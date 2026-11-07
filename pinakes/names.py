"""Normalizing file names for lineage: strip copy markers, dates and version marks (patterns/names.toml)."""

import os
import re

from .config import tomllib

_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patterns", "names.toml")


def load_patterns(extra_file=None):
    pats = []
    for path in [_DEFAULT] + ([extra_file] if extra_file else []):
        with open(path, "rb") as f:
            pats.extend(tomllib.load(f).get("patterns", []))
    return [re.compile(p, re.IGNORECASE) for p in pats]


def split_ext(name):
    """('report', '.pdf'); '.tar.gz' and similar double extensions kept whole."""
    lower = name.lower()
    for double in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(double):
            return name[: -len(double)], lower[-len(double):]
    stem, ext = os.path.splitext(name)
    return stem, ext.lower()


def normalize(name, patterns):
    """A comparison key for a file name: (stem without markers, folded; extension)."""
    stem, ext = split_ext(name)
    for _ in range(10):  # markers can stack: "report - Copy (2) final"
        before = stem
        for p in patterns:
            stem = p.sub("", stem)
        if stem == before:
            break
    # a minus sign before a number, at the start or after a separator, is part of the name: r.-1.1 is not r.1.1
    stem = re.sub(r"(?<![^\s_.])-(?=\d)", "\0", stem)
    stem = re.sub(r"[\s_.-]+", " ", stem).strip().casefold().replace("\0", "-")
    return stem, ext
