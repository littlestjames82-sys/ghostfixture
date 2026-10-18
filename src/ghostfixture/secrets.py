"""Secret shape scan, applied before any file is copied.

Deliberately conservative, same family as GhostSlice's secret guard:
known provider token shapes are flagged on sight, generic assignments
only when the name looks sensitive AND the value is long, varied, and
not an obvious placeholder.

Findings NEVER carry the secret value. A finding is a pattern type
string only; the fixture manifest records path + types, nothing else.
A file with no flagged shapes is "not flagged", never "secret-free":
the shapes are a known net, not a proof.
"""
from __future__ import annotations

import math
import re

_KNOWN_PATTERNS: list = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("openai-or-anthropic-key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("url-password", re.compile(r"://[^\s/@:'\"]+:[^\s/@'\"]{3,}@")),
]

_PLACEHOLDER_MARKERS = (
    "example", "xxx", "your-", "your_", "yourkey", "placeholder",
    "changeme", "change-me", "change_me", "dummy", "sample", "fixture",
    "redacted", "insert-", "insert_", "todo", "fake", "test-key",
    "test_key", "not-a-real", "not_real", "mock",
)

_SENSITIVE_NAME_RE = re.compile(
    r"(key|token|secret|password|passwd|pwd|credential|auth|private)", re.IGNORECASE)
_ASSIGN_RE = re.compile(
    r"""^\s*(?:export\s+|const\s+|let\s+|var\s+)?["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*["']([^\s"']{16,})["']""")

# Byte-level shapes catchable without decoding (binary files, undecodable text).
_BYTES_PATTERNS: list = [
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
]


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'").strip().lower()
    if not v:
        return True
    if any(m in v for m in _PLACEHOLDER_MARKERS):
        return True
    if v.startswith("${") or v.startswith("<") or set(v) <= {"*"}:
        return True
    return False


def _varied(value: str) -> bool:
    """Rough entropy gate so 'aaaa...' or a single repeated token is not flagged."""
    if len(set(value)) < 8:
        return False
    counts: dict = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return entropy >= 3.0


def scan_bytes(data: bytes) -> list:
    """Return the sorted list of pattern types found in raw bytes.

    Decodable text gets the full pattern family; undecodable data gets
    the byte-level shapes only. Never returns any part of a value.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        found = {name for name, pat in _BYTES_PATTERNS if pat.search(data)}
        return sorted(found)
    found: set = set()
    for name, pat in _KNOWN_PATTERNS:
        if pat.search(text):
            found.add(name)
    for line in text.splitlines():
        m = _ASSIGN_RE.match(line)
        if not m:
            continue
        name, value = m.group(1), m.group(2)
        if not _SENSITIVE_NAME_RE.search(name):
            continue
        if _is_placeholder(value) or not _varied(value):
            continue
        found.add("sensitive-assignment")
    return sorted(found)
