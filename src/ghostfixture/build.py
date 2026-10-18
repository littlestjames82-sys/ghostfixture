"""Fixture build + check.

Build: seed with the files a GhostSlice bundle references, extend by
static local import closure, copy ORIGINALS from the project into a
brand-new output tree, and record every decision in a fixture
manifest. The source project is only ever read.

Safety rules enforced here, in order, for every candidate file:
1. The path must resolve inside the project root. Symlinks are never
   followed out of the root: a referenced path whose real location is
   outside the root is left out, with the reason recorded.
2. Secret-shaped content is excluded by default and named in the
   manifest as excluded-flagged (path + pattern types only).
3. The total copied size is capped; the cap is stated in the report
   and in CLI output. Bundle-referenced files are served first, in
   manifest order; closure files after, in BFS order.
4. Guard findings the bundle itself recorded (per-file
   ``redactions``/``redaction_kinds``, written by GhostSlice when a
   bundle is exported with redaction) are propagated, never dropped:
   where this tool's shape scan confirms the flag, the file is
   excluded under rule 2 and the record names both verdicts; where
   it does not confirm, the file is copied and the disagreement is
   recorded in the manifest and in FIXTURE.md. The two scanners
   disagree by design (Slice's guard is name-based, this scan is
   shape-based); the seam this rule closes is the silence between
   them.
"""
from __future__ import annotations

import hashlib
import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from .bundle import BundleError, load_bundle
from .closure import closure_note, closure_supported, imports_of, language_of
from .secrets import scan_bytes

DEFAULT_MAX_BYTES = 2 * 1024 * 1024  # 2 MiB of copied content
FIXTURE_MANIFEST = "fixture-manifest.json"
FIXTURE_SUMMARY = "FIXTURE.md"
_OWN_FILES = {FIXTURE_MANIFEST, FIXTURE_SUMMARY}


class FixtureError(ValueError):
    """The fixture cannot be built (callers map this to exit 2)."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inside(root_real: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root_real)
        return True
    except (ValueError, RuntimeError, OSError):
        return False


def _validate_locations(project: Path, out: Path) -> tuple:
    """Return (project_real, out_abs) or raise FixtureError."""
    if not project.is_dir():
        raise FixtureError(f"project is not a directory: {project}")
    project_real = project.resolve()
    out_abs = out if out.is_absolute() else (Path.cwd() / out)
    out_abs = Path(*out_abs.parts)  # normalise without resolving symlinks in the tail
    out_real_parent = out_abs.parent.resolve() if out_abs.parent.exists() else None
    if out_real_parent is None:
        raise FixtureError(f"output parent does not exist: {out_abs.parent}")
    out_real = out_real_parent / out_abs.name
    if out_real == project_real or project_real in out_real.parents:
        raise FixtureError("output directory must not be inside the project (the source project is never written to)")
    if out_real in project_real.parents:
        raise FixtureError("project must not be inside the output directory")
    if out_abs.exists() and any(out_abs.iterdir()):
        raise FixtureError(f"output directory exists and is not empty: {out}")
    return project_real, out_abs


def build_fixture(project, bundle_path, out_dir, task: str = "",
                  max_bytes: int = DEFAULT_MAX_BYTES,
                  include_flagged: bool = False) -> dict:
    """Build a fixture tree. Returns the fixture manifest dict.

    Raises FixtureError (or BundleError) when no fixture can be built.
    """
    project = Path(project)
    out = Path(out_dir)
    if max_bytes <= 0:
        raise FixtureError("--max-bytes must be a positive number of bytes")
    project_real, out_abs = _validate_locations(project, out)
    bundle = load_bundle(bundle_path)

    included: list = []          # manifest entries, in copy order
    excluded_flagged: list = []  # {path, types}
    left_out: list = []          # {path, reason, detail}
    external_refs: list = []     # {from, specifier}
    drift: list = []             # {path, bundle_sha256, copied_sha256}
    upstream_disagreements: list = []  # {path, upstream_kinds, upstream_redactions, fixture_types}
    upstream_scanned: set = set()  # paths with bundle-recorded findings that reached the scan
    pending_disagreement: dict = {}  # rel -> disagreement record, until the copy decision lands
    comparable = 0               # full-mode files byte-compared to the bundle
    ext_seen: set = set()
    languages: dict = {}         # language -> closure note
    copied_bytes = 0
    queue: deque = deque()
    queued: set = set()
    decided: set = set()

    modes = {e.path: e.mode for e in bundle.entries}
    bundle_shas = {e.path: e.sha256 for e in bundle.entries}
    bundle_excluded = set(bundle.excluded)
    upstream = {e.path: e.upstream_findings for e in bundle.entries
                if e.upstream_findings}

    def _left_out(rel: str, reason: str, detail: str) -> None:
        """Record a left-out file; a bundle-recorded guard finding
        for it stays attached to the record, so no outcome path can
        drop the upstream flag silently."""
        record = {"path": rel, "reason": reason, "detail": detail}
        up = upstream.get(rel)
        if up:
            record["upstream_kinds"] = up["kinds"]
            record["upstream_redactions"] = up["redactions"]
        left_out.append(record)
    for entry in bundle.entries:
        queue.append((entry.path, "bundle-referenced", ""))
        queued.add(entry.path)

    def consider(rel: str) -> bytes | None:
        """Apply the safety rules to one candidate. Returns its bytes
        if it may be copied (subject to the caller's cap check)."""
        src = project / rel
        if not src.is_file():
            _left_out(rel, "missing-in-project",
                      "referenced but not present in the project tree")
            return None
        if src.is_symlink() and not _inside(project_real, src):
            _left_out(rel, "symlink-escapes-root",
                      "symlink target resolves outside the project root; links are not followed out of the root")
            return None
        if not _inside(project_real, src):
            _left_out(rel, "outside-root",
                      "path resolves outside the project root")
            return None
        try:
            data = src.read_bytes()
        except OSError as exc:
            _left_out(rel, "unreadable", str(exc))
            return None
        types = scan_bytes(data)
        up = upstream.get(rel)
        if up:
            upstream_scanned.add(rel)
        if types:
            record = {"path": rel, "types": types}
            if include_flagged:
                # Included by explicit override; the flag stays on record.
                record["included_by_override"] = True
            if up:
                # The bundle's guard flagged this file too: the
                # record names both verdicts (agreement, not silence).
                record["upstream_kinds"] = up["kinds"]
                record["upstream_redactions"] = up["redactions"]
                record["upstream_confirmed"] = True
            excluded_flagged.append(record)
            return data if include_flagged else None
        if up:
            # Upstream flagged it; this scan does not confirm. Hold
            # the disagreement until the caller decides the copy: it
            # becomes a record only if the file is actually copied.
            pending_disagreement[rel] = {
                "path": rel,
                "upstream_kinds": up["kinds"],
                "upstream_redactions": up["redactions"],
                "fixture_types": [],
            }
        return data

    while queue:
        rel, reason, via = queue.popleft()
        if rel in decided:
            continue
        decided.add(rel)
        if rel in bundle_excluded:
            _left_out(rel, "bundle-excluded",
                      "listed in the bundle manifest with mode exclude; "
                      "import closure never overrides a bundle exclusion")
            continue
        data = consider(rel)
        if data is None:
            continue
        if copied_bytes + len(data) > max_bytes:
            pending_disagreement.pop(rel, None)
            _left_out(rel, "size-cap",
                      f"would exceed the total size cap of {max_bytes} bytes "
                      f"({copied_bytes} already copied)")
            continue
        dest = out_abs / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        copied_bytes += len(data)
        entry = {"path": rel, "reason": reason, "bytes": len(data),
                 "sha256": _sha256(data)}
        if via:
            entry["via"] = via
        if rel in modes:
            entry["bundle_mode"] = modes[rel]
        if rel in pending_disagreement:
            # The copy lands: the upstream flag and this scan's
            # disagreement with it go on the record, on the entry
            # itself and in the manifest's disagreement list.
            disagreement = pending_disagreement.pop(rel)
            upstream_disagreements.append(disagreement)
            entry["upstream_kinds"] = disagreement["upstream_kinds"]
            entry["upstream_redactions"] = disagreement["upstream_redactions"]
        # Drift: for a bundle-referenced file at mode "full", the
        # bundle manifest's sha256 is taken over the file itself as
        # exported, so a byte comparison against what was just
        # copied is exact. Other modes store sliced text (not the
        # file) and are not byte-comparable; non-UTF-8 content is
        # not comparable either, because Slice hashed decoded text.
        if rel in modes and bundle_shas.get(rel):
            entry["bundle_sha256"] = bundle_shas[rel]
            if modes[rel] == "full":
                try:
                    data.decode("utf-8")
                except UnicodeDecodeError:
                    pass
                else:
                    comparable += 1
                    matches = entry["sha256"] == bundle_shas[rel]
                    entry["matches_bundle_content"] = matches
                    if not matches:
                        drift.append({
                            "path": rel,
                            "bundle_sha256": bundle_shas[rel],
                            "copied_sha256": entry["sha256"],
                        })
        included.append(entry)
        # Closure over what was actually copied.
        lang = language_of(rel)
        if closure_supported(rel):
            languages.setdefault(lang, closure_note(rel))
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = ""
            if text:
                locals_found, externals = imports_of(project, rel, text)
                for cand in locals_found:
                    if cand not in queued and cand not in decided:
                        queued.add(cand)
                        queue.append((cand, "import-closure", rel))
                for spec in externals:
                    key = (rel, spec)
                    if key not in ext_seen:
                        ext_seen.add(key)
                        external_refs.append({"from": rel, "specifier": spec})
        else:
            languages.setdefault(lang, closure_note(rel))

    manifest = {
        "tool": "ghostfixture",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "task": task,
        "source_project": str(project_real),
        "source_bundle": str(Path(bundle_path)),
        "source_bundle_manifest_sha256": bundle.manifest_sha256,
        "max_bytes": max_bytes,
        "include_flagged": include_flagged,
        "totals": {
            "files_considered": len(decided),
            "files_included": len(included),
            "files_excluded_flagged": len([e for e in excluded_flagged if not e.get("included_by_override")]),
            "files_left_out": len(left_out),
            "files_drifted": len(drift),
            "files_upstream_flagged": len(upstream_scanned),
            "files_upstream_disagreements": len(upstream_disagreements),
            "bytes_copied": copied_bytes,
        },
        "included": included,
        "drift": drift,
        "upstream_disagreements": upstream_disagreements,
        "drift_check": {
            "comparable_files": comparable,
            "drifted_files": len(drift),
            "note": "Byte comparison is exact only for bundle entries at "
                    "mode 'full' with a recorded sha256 and UTF-8 content: "
                    "the bundle manifest sha256 is taken over the text the "
                    "bundle stored, which for mode 'full' is the file "
                    "itself at export time. A mismatch means the copied "
                    "bytes are not the bytes the bundle captured (the "
                    "project changed after export, or the bundle text was "
                    "transformed). Other modes are not byte-comparable.",
        },
        "excluded_flagged": excluded_flagged,
        "left_out": left_out,
        "external_references": external_refs,
        "closure_by_language": languages,
        "limits": [
            "Copies are the original project files at full fidelity; sliced text stays in the bundle.",
            "Import closure is static and parse-level: dynamic imports and string-built module paths are not traced.",
            "Secret shapes are a conservative net: 'not flagged' means no known shape matched, never 'secret-free'.",
            "If the project changed after the bundle was exported, copied files may be newer than the bundle. The bundle manifest hash above pins the pairing, and copied files at bundle mode 'full' whose bytes differ from the bundle's recorded content are listed under 'drift' in this manifest and in FIXTURE.md.",
            "Guard findings recorded in the bundle manifest (per-file 'redactions'/'redaction_kinds', written by GhostSlice when a bundle is exported with redaction) are propagated: where the shape scan confirms the flag, the exclusion record names both verdicts; where it does not, the file is copied and the disagreement is listed under 'upstream_disagreements' in this manifest and in FIXTURE.md. The two scanners differ by design (the guard is name-based, this scan is shape-based), so a disagreement is information, not an error. A bundle whose manifest records no findings (a plain export records none in the manifest) gives this tool nothing to propagate.",
        ],
    }
    out_abs.mkdir(parents=True, exist_ok=True)
    (out_abs / FIXTURE_MANIFEST).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    from .reports import render_fixture_md
    (out_abs / FIXTURE_SUMMARY).write_text(render_fixture_md(manifest), encoding="utf-8")
    return manifest


# ---------------- check ----------------

class CheckError(ValueError):
    """The fixture cannot be checked (callers map this to exit 2)."""


def check_fixture(fixture_dir) -> dict:
    """Re-verify a fixture tree against its fixture-manifest.json."""
    root = Path(fixture_dir)
    mpath = root / FIXTURE_MANIFEST
    if not mpath.is_file():
        raise CheckError(f"no {FIXTURE_MANIFEST} in {fixture_dir}")
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise CheckError(f"{FIXTURE_MANIFEST}: invalid ({exc})") from exc
    problems: list = []
    expected: set = set()
    for entry in manifest.get("included", []):
        rel = entry.get("path", "")
        expected.add(rel)
        f = root / rel
        if not f.is_file():
            problems.append(f"{rel}: missing from fixture tree")
            continue
        actual = _sha256(f.read_bytes())
        if actual != entry.get("sha256"):
            problems.append(f"{rel}: sha256 mismatch (file changed after build)")
    for entry in manifest.get("excluded_flagged", []):
        if entry.get("included_by_override"):
            continue
        rel = entry.get("path", "")
        if (root / rel).exists():
            problems.append(f"{rel}: excluded-flagged file is present in the fixture tree")
    ignored: list = []
    for f in sorted(root.rglob("*")):
        if f.is_file():
            rel = f.relative_to(root).as_posix()
            if rel in expected or rel in _OWN_FILES:
                continue
            # Runtime byproducts of actually running a fixture (the
            # point of a fixture) are noted, not treated as tampering.
            if "__pycache__" in Path(rel).parts or f.suffix in (".pyc", ".pyo"):
                ignored.append(rel)
                continue
            problems.append(f"{rel}: present but not recorded in the fixture manifest")
    return {
        "ok": not problems,
        "problems": problems,
        "ignored_runtime_byproducts": ignored,
        "files_checked": len(expected),
        "fixture": str(root),
    }
