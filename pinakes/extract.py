"""Running the schemas' extractors (METADATA.md, ROADMAP 13), and checking the values they give.

The agent runs extractors, on the machine that has the file, never on a protected root nor on a hard link of a
protected file. An extractor is a module with `extract(f)`: f is the file opened read-only by the agent (O_NOFOLLOW,
O_NOATIME where permitted), and it returns {field: value} in the schema's types. A schema's extractor whose `requires`
aren't installed is off, and says why; the scan goes on without it.

Each extractor's outcome for a file is sent too (ROADMAP 44), to a server of protocol 4: values found, nothing found,
refused with one of REFUSALS, or skipped with one of SKIPS (the extractor is off here). A reason code, never an
error's text, which can quote the file. An older server gets the error's text, as before (it keeps none of it).

check_vals() is shared: the agent checks what an extractor gives before sending it, and the ingester checks again
what a batch says, so an agent can only write values of a schema's own fields and types into the catalog.
Standard library only.
"""

import importlib
import importlib.metadata
import json
import math
import mimetypes
import os
import re

MAX_TEXT = 1000          # characters in one text value
MAX_LIST = 200           # items in one list
MAX_VALS = 16 * 1024     # bytes of one schema's values as JSON
MAX_ERROR = 300          # characters of an extractor's error, as sent to a server before protocol 4
OUTCOMES_PROTOCOL = 4    # the first server protocol that keeps outcomes (compat.py)

# why an extractor refused a file (ROADMAP 44): an extractor's exception names one by its `reason` (a Refusal's);
# the others are the agent's own
REFUSALS = ("truncated",    # the file ends inside what the extractor reads
            "wrong_type",   # not the format its name says
            "malformed",    # the format, broken or out of bounds
            "bad_values",   # the values aren't the schema's own fields and types (check_vals)
            "unreadable",   # a read error
            "failed")       # anything else: an extractor's bug
# why an extractor that applies didn't run here
SKIPS = ("dependency",      # a package its `requires` names isn't installed
         "broken")          # its module can't be imported, or has no extract()

# ISO 8601 as the registry stores dates: as precise as known; a time in UTC ends with Z, a time with no zone (a
# camera's local time, its offset unknown) has none
_DATE = re.compile(r"\d{4}(-\d{2}(-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?Z?)?)?)?\Z")
_REQ = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(.*)\Z")


class Refusal(ValueError):
    """What an extractor raises for a file it won't read; `reason` is one of REFUSALS."""
    reason = "malformed"


def refusal(e):
    """The reason code for an extractor's exception."""
    r = getattr(e, "reason", None)
    if isinstance(e, Refusal) and r in REFUSALS:
        return r
    if isinstance(e, OSError):
        return "unreadable"
    if isinstance(e, EOFError):
        return "truncated"
    return "failed"


def waits(cfg, state):
    """Why outcomes can't be sent to this agent's server yet, or None (as manifests.waits)."""
    if cfg.transport["kind"] != "ssh":
        return None
    p = state.get_meta("server_protocol")
    if p is not None and int(p) >= OUTCOMES_PROTOCOL:
        return None
    return ("the server %s; extraction outcomes wait for one of protocol %d or later"
            % ("hasn't checked in yet" if p is None else "is at protocol %s" % p, OUTCOMES_PROTOCOL))


def _number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _item(kind, v):
    """None if v is a fine value of this kind, else what's wrong."""
    if kind == "text":
        if not isinstance(v, str):
            return "not text"
        return "longer than %d characters" % MAX_TEXT if len(v) > MAX_TEXT else None
    if kind in ("number", "duration"):
        return None if _number(v) else "not a number"
    if kind == "date":
        return None if isinstance(v, str) and _DATE.match(v) else "not an ISO 8601 date"
    if kind == "point":
        if (not isinstance(v, dict) or set(v) != {"lat", "lon"} or not _number(v["lat"]) or not _number(v["lon"])
                or not -90 <= v["lat"] <= 90 or not -180 <= v["lon"] <= 180):
            return "not a point {lat, lon}"
        return None
    if kind in ("person", "file"):
        return "a %s is named by the catalog, not by an extractor" % kind
    return "unknown type %s" % kind


def check_vals(schema, vals):
    """(the values to keep, [what's wrong]). None values are left out. Sensitive fields are kept: the ingester stores
    them apart, for the owners only (sensitive_visible() in schema.sql)."""
    if not isinstance(vals, dict):
        return {}, ["values are not a table"]
    keep, problems = {}, []
    for name, v in vals.items():
        f = schema.fields.get(name) if isinstance(name, str) else None
        if f is None:
            problems.append("%s: not a field of %s" % (name, schema.name))
            continue
        if v is None:
            continue
        if f.type == "list":
            if not isinstance(v, list):
                bad = "not a list"
            elif len(v) > MAX_LIST:
                bad = "more than %d items" % MAX_LIST
            else:
                bad = next((b for b in (_item(f.of, i) for i in v) if b), None)
        else:
            bad = _item(f.type, v)
        if bad:
            problems.append("%s: %s" % (name, bad))
        else:
            keep[name] = v
    if len(json.dumps(keep)) > MAX_VALS:
        problems.append("values over %d bytes" % MAX_VALS)
    return keep, problems


def _version(text):
    return tuple(int(p) for p in re.findall(r"\d+", text)[:4])


def missing(requires):
    """The first requirement not met, or None. A requirement is a distribution's name, optionally with >= and a
    version; any other specifier can't be checked here and counts as not met."""
    for r in requires:
        m = _REQ.match(r)
        name, spec = m.group(1), m.group(2)
        try:
            have = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            return r
        for clause in filter(None, spec.split(",")):
            if not clause.startswith(">=") or _version(have) < _version(clause[2:]):
                return "%s (%s installed)" % (r, have)
    return None


_MIMES = mimetypes.MimeTypes(filenames=())


def mime_of(relpath):
    """A file's MIME type by its name, from the standard library's own table of types by suffix, not this machine's
    /etc/mime.types: the same extractors run for the same names everywhere. None if unknown."""
    return _MIMES.guess_type(relpath.rsplit("/", 1)[-1], strict=False)[0]


def _mime_fits(patterns, mime):
    return any(p == "*/*" or p == mime or (p.endswith("/*") and mime.startswith(p[:-1])) for p in patterns)


# Image files by their suffix (ROADMAP 71), for saying what a schema read from some image types only can't see: the
# common still-image formats and the cameras' raw ones, which the standard library's table doesn't know. A fixed
# list, not this Python's table, so every server counts the same files.
IMAGE_EXTS = (".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".gif", ".tif", ".tiff", ".bmp", ".webp", ".heic", ".heif",
              ".avif", ".jxl", ".jp2",
              ".dng", ".cr2", ".cr3", ".crw", ".nef", ".nrw", ".arw", ".srf", ".sr2", ".orf", ".rw2", ".raf", ".pef",
              ".srw", ".x3f", ".rwl", ".3fr", ".iiq", ".mos", ".erf", ".kdc", ".dcr", ".mrw")


def unread_images(patterns):
    """For a schema read from some image types only (`patterns`, its `mime`, every one image/... and none image/*):
    (the types it reads, as "JPEG" or "JPEG and PNG"; the IMAGE_EXTS it doesn't read). None for any other schema."""
    if not patterns or not all(p.startswith("image/") and p != "image/*" for p in patterns):
        return None
    left = tuple(e for e in IMAGE_EXTS if not _mime_fits(patterns, mime_of("x" + e) or "image/x-raw"))
    return " and ".join(p.split("/", 1)[1].upper() for p in patterns), left


def _open_readonly(path):
    from .scan import _open_readonly as opener   # one definition of how the agent opens a file
    return os.fdopen(opener(path), "rb")


class _BadValues(Refusal):
    reason = "bad_values"


class Extractors:
    """The registry's extractors that can run here: on, {name: (schema, extract)}; off, {name: why}, and
    skipped, {name: (schema, one of SKIPS)} for the same."""

    def __init__(self, reg, opener=_open_readonly):
        self.on, self.off, self.skipped = {}, {}, {}
        self.known = set()
        self.opener = opener
        for s in reg:
            if not s.extractor:
                continue
            self.known.add(s.name)
            need = missing(s.extractor["requires"])
            if need:
                self.off[s.name] = "needs %s" % need
                self.skipped[s.name] = (s, "dependency")
                continue
            try:
                fn = importlib.import_module(s.extractor["module"]).extract
            except Exception as e:                  # ImportError, or a module with no extract()
                self.off[s.name] = "%s: %s" % (type(e).__name__, e)
                self.skipped[s.name] = (s, "broken")
                continue
            self.on[s.name] = (s, fn)

    def wanted(self, select, relpath, skipped=False):
        """{schema: version} of the extractors on here that apply to this name; select: a root's `metadata` (None:
        all). With skipped, also those that apply and are off here, as {schema: 0}."""
        mime = mime_of(relpath)
        if not mime:
            return {}
        out = {n: s.version for n, (s, _) in self.on.items()
               if (select is None or n in select) and _mime_fits(s.mime, mime)}
        if skipped:
            out.update({n: 0 for n, (s, _) in self.skipped.items()
                        if (select is None or n in select) and _mime_fits(s.mime, mime)})
        return out

    def run(self, path, wanted, outcomes=False):
        """{schema: {"v": version, "vals": {...}}} ({} for nothing found) or, where one refused the file,
        {"v": version, "refused": one of REFUSALS}, and {"v": version, "skipped": one of SKIPS} for one off here
        (version 0 in wanted). Without outcomes (a server before protocol 4), a refusal is {"v": version,
        "error": "..."} as before, and nothing is said of one skipped. A refusal is kept too, so the file isn't
        tried again until the schema's version changes."""
        out = {}
        for name in sorted(wanted):
            if wanted[name] == 0:
                s, why = self.skipped[name]
                if outcomes:
                    out[name] = {"v": s.version, "skipped": why}
                continue
            s, fn = self.on[name]
            try:
                with self.opener(path) as f:
                    vals, problems = check_vals(s, fn(f))
                if problems:
                    raise _BadValues("; ".join(problems))
                out[name] = {"v": s.version, "vals": vals}
            except Exception as e:
                if outcomes:
                    out[name] = {"v": s.version, "refused": refusal(e)}
                else:
                    out[name] = {"v": s.version, "error": ("%s: %s" % (type(e).__name__, e))[:MAX_ERROR]}
        return out
