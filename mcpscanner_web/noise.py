"""Noise-suppression patterns for triaging scan results.

`NOISE_PATTERNS` is the single source of truth, served to the frontend via
`/api/config` so client-side filtering uses the exact same list. Suppression
only *hides* by default — nothing is ever dropped from the underlying data.

To extend: add a glob to NOISE_PATTERNS. Patterns use `**` to match any number
of path segments and `*` to match within a segment. Matching is
case-insensitive and operates on `/`-normalized paths.
"""

from __future__ import annotations

import re

# Well-known false-positive paths. Grouped by category for easy extension.
NOISE_PATTERNS: list[str] = [
    # test files
    "**/*_test.*", "**/*.test.*", "**/test/**", "**/tests/**",
    "**/__tests__/**", "**/*.spec.*", "**/__toolsnaps__/**", "**/*.snap",
    # lock / manifest noise
    "**/yarn.lock", "**/package-lock.json", "**/go.sum", "**/uv.lock", "**/*.lock",
    # VCS internals
    "**/.git/**",
    # generated code
    "**/generated/**", "**/*.gen.*", "**/dist/**", "**/build/**",
    # docs & CI
    "**/docs/**", "**/*.md", "**/.github/workflows/**",
    # build scripts
    "**/script/**", "**/*.sh",
]


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Translate a `**`-aware glob into a compiled, anchored regex.

    `**/` matches zero or more leading path segments; `**` matches across
    separators; `*` matches within a single segment; `?` matches one char.
    """
    i = 0
    out = ["^"]
    while i < len(pattern):
        c = pattern[i]
        if pattern[i : i + 3] == "**/":
            out.append("(?:.*/)?")
            i += 3
        elif pattern[i : i + 2] == "**":
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    out.append("$")
    return re.compile("".join(out), re.IGNORECASE)


_COMPILED = [_glob_to_regex(p) for p in NOISE_PATTERNS]


def is_noise(path: str) -> bool:
    """Return True if `path` matches any noise pattern."""
    normalized = path.replace("\\", "/").removeprefix("./")
    return any(rx.match(normalized) for rx in _COMPILED)
