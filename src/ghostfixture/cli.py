"""GhostFixture CLI.

  ghostfixture build <project> <bundle> -o <out-dir>
                     [--task "..." | --task-file f]
                     [--max-bytes N] [--include-flagged] [--json]
  ghostfixture check <fixture-dir> [--json]
  ghostfixture mcp

Exit codes: build 0 = fixture built, 1 = fixture would be empty,
2 = could not build. check 0 = clean, 1 = mismatch, 2 = could not
check. The source project is only ever read, never written.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .build import (DEFAULT_MAX_BYTES, CheckError, FixtureError,
                    build_fixture, check_fixture)
from .bundle import BundleError


def _task_from(args) -> str:
    if getattr(args, "task_file", None):
        return Path(args.task_file).read_text(encoding="utf-8", errors="replace")
    return getattr(args, "task", "") or ""


def _cmd_build(args) -> int:
    try:
        manifest = build_fixture(
            args.project, args.bundle, args.out,
            task=_task_from(args),
            max_bytes=args.max_bytes,
            include_flagged=args.include_flagged,
        )
    except (FixtureError, BundleError, OSError) as exc:
        print(f"ghostfixture: could not build: {exc}", file=sys.stderr)
        return 2
    t = manifest["totals"]
    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        print(f"GhostFixture built: {args.out}")
        print(f"  Size cap: {manifest['max_bytes']} bytes (total copied content)")
        print(f"  Included: {t['files_included']} files, {t['bytes_copied']} bytes "
              f"(bundle-referenced first, then static import closure)")
        if t.get("files_drifted"):
            print(f"  drift warning: {t['files_drifted']} copied file(s) differ from the "
                  "bundle's recorded content (project changed after export? see FIXTURE.md)")
        if t.get("files_upstream_disagreements"):
            print(f"  upstream disagreement: {t['files_upstream_disagreements']} copied "
                  "file(s) were flagged by the bundle's guard but not confirmed by the "
                  "shape scan (the flag and the disagreement are recorded; see FIXTURE.md)")
        for e in manifest["excluded_flagged"]:
            note = " (included by --include-flagged override)" if e.get("included_by_override") else ""
            print(f"  excluded-flagged: {e['path']} [{', '.join(e['types'])}]{note}")
        for e in manifest["left_out"]:
            print(f"  left out: {e['path']} ({e['reason']})")
        print(f"  Record: fixture-manifest.json + FIXTURE.md in {args.out}")
    if t["files_included"] == 0:
        print("ghostfixture: fixture is empty (nothing could be copied)", file=sys.stderr)
        return 1
    return 0


def _cmd_check(args) -> int:
    try:
        result = check_fixture(args.fixture)
    except CheckError as exc:
        print(f"ghostfixture: could not check: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    elif result["ok"]:
        extra = ""
        if result.get("ignored_runtime_byproducts"):
            extra = f", {len(result['ignored_runtime_byproducts'])} runtime byproducts ignored (__pycache__)"
        print(f"GhostFixture check: OK ({result['files_checked']} files verified{extra})")
    else:
        print("GhostFixture check: MISMATCH")
        for p in result["problems"]:
            print(f"  {p}")
    return 0 if result["ok"] else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ghostfixture",
                                     description="Minimal repro project generator for GhostSlice bundles")
    parser.add_argument("--version", action="version", version=f"ghostfixture {__version__}")
    sub = parser.add_subparsers(dest="command")

    b = sub.add_parser("build", help="build a fixture tree from a project + GhostSlice bundle")
    b.add_argument("project")
    b.add_argument("bundle")
    b.add_argument("-o", "--out", required=True)
    b.add_argument("--task", default="")
    b.add_argument("--task-file", default=None)
    b.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    b.add_argument("--include-flagged", action="store_true",
                   help="include secret-flagged files anyway (flags stay on record)")
    b.add_argument("--json", action="store_true")
    b.set_defaults(func=_cmd_build)

    c = sub.add_parser("check", help="re-verify a fixture tree against its manifest")
    c.add_argument("fixture")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=_cmd_check)

    sub.add_parser("mcp", help="run the stdio MCP server")

    args = parser.parse_args(argv)
    if args.command == "mcp":
        from .mcp_server import serve
        serve()
        return 0
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
