"""Glob patterns for excludes and owner rules, matched against a path relative to a root (always with '/').

`*` matches within one path segment, `?` one character, `**` any number of whole segments (including none).
`**/x` matches x at any depth, `dir/**` everything below dir.
"""

import re


def _segment(seg):
    out = []
    for ch in seg:
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def translate(pattern):
    parts = pattern.strip("/").split("/")
    rx = ""
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if part == "**":
            rx += ".*" if last else "(?:[^/]+/)*"
        else:
            rx += _segment(part) + ("" if last else "/")
    return re.compile(rx + r"\Z")


class Matcher:
    def __init__(self, patterns):
        self.patterns = list(patterns)
        self._rx = [translate(p) for p in self.patterns]

    def __call__(self, relpath):
        return any(rx.match(relpath) for rx in self._rx)

    def __bool__(self):
        return bool(self._rx)
