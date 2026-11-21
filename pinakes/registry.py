"""The schema registry (METADATA.md "Schemas"): the project's schemas/*.toml, and a site's in the same form.

Standard library only: the agent will read it too, for its extractors. A schema that doesn't validate is refused
with a message naming its file and the key at fault; nothing of a registry with a bad schema is used.
"""

import os
import re

from .config import ConfigError, tomllib

BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schemas")
COMMON = "dc"   # the schema every other maps onto, so one search covers every type

TYPES = ("text", "number", "date", "point", "duration", "list", "person", "file")
LIST_OF = ("text", "number", "date", "person", "file")
# which index each type takes, and the index's kind: the kind names the index's expression in the database
# (enroll_metadata_indexes() in schema.sql), so a field whose type or index changes gets a new index
INDEXES = {
    "text": {"exact": "eq", "trigram": "trgm"},
    "number": {"exact": "num", "range": "num"},
    "duration": {"exact": "num", "range": "num"},
    "date": {"exact": "date", "range": "date"},
    "point": {"spatial": "geo"},
    "list": {"exact": "list", "trigram": "trgm"},   # trigram on a list: of text only, over its JSON text
    "person": {"exact": "ref"},
    "file": {"exact": "ref"},
}

_SCHEMA_NAME = re.compile(r"[a-z][a-z0-9]{0,19}\Z")      # also an index name's part: no underscore, 20 at most
_FIELD_NAME = re.compile(r"[a-z][a-z0-9_]{0,29}\Z")
_MIME = re.compile(r"(\*/\*|[a-z0-9][a-z0-9!#$&^_.+-]*/(\*|[a-z0-9][a-z0-9!#$&^_.+-]*))\Z")
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_REQUIREMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*([<>=!~]=?[A-Za-z0-9.*+!-]+(,[<>=!~]=?[A-Za-z0-9.*+!-]+)*)?\Z")

_TOP_KEYS = {"name", "version", "title", "mime", "extractor", "common", "fields"}
_FIELD_KEYS = {"type", "of", "index", "sensitive", "identity", "parent", "description"}
_EXTRACTOR_KEYS = {"module", "requires"}


class Field:
    def __init__(self, name, type, of=None, index=None, sensitive=False, identity=False, description="",
                 parent=None):
        self.name, self.type, self.of, self.index = name, type, of, index
        self.sensitive, self.identity, self.description = sensitive, identity, description
        # an identity field (METADATA.md "Identity fields"): two files sharing its value are versions of one
        # document; with parent, its value is another file's `parent` field instead: that file is the parent
        self.parent = parent

    @property
    def index_kind(self):
        return INDEXES[self.type][self.index] if self.index else None


class Schema:
    def __init__(self, name, version, title, mime, fields, common, extractor, path):
        self.name, self.version, self.title, self.mime = name, version, title, mime
        self.fields, self.common, self.extractor, self.path = fields, common, extractor, path

    def identity_rules(self):
        """How lineage reads this schema's identity fields: (field, the other file's field, how), how being
        'shared' (versions of one document), 'parent' (the other file is this one's parent) or 'child' (the other
        is this one's child: the same rule from the parent's side). Parents first: the more particular."""
        fs = [f for f in self.fields.values() if f.identity]
        return ([(f.name, f.parent, "parent") for f in fs if f.parent]
                + [(f.parent, f.name, "child") for f in fs if f.parent]
                + [(f.name, f.name, "shared") for f in fs if not f.parent])

    def indexes(self):
        """(schema, field, kind) for every indexed field."""
        return [(self.name, f.name, f.index_kind) for f in self.fields.values() if f.index]


def index_name(schema, field, kind):
    return "md_%s_%s_%s" % (schema, field, kind)


def _refuse(where, msg):
    raise ConfigError("%s: %s" % (where, msg))


def _unknown(where, d, allowed):
    extra = sorted(set(d) - allowed)
    if extra:
        _refuse(where, "unknown key%s %s (allowed: %s)" % ("s" if len(extra) > 1 else "", ", ".join(extra),
                                                          ", ".join(sorted(allowed))))


def _field(where, name, d):
    if not isinstance(d, dict):
        _refuse(where, "a field is a table: [fields.%s]" % name)
    _unknown(where, d, _FIELD_KEYS)
    t = d.get("type")
    if t not in TYPES:
        _refuse(where, "type must be one of %s, not %r" % (", ".join(TYPES), t))
    of = d.get("of")
    if t == "list":
        of = "text" if of is None else of
        if of not in LIST_OF:
            _refuse(where, "of must be one of %s, not %r" % (", ".join(LIST_OF), of))
    elif of is not None:
        _refuse(where, "of is for a list only")
    index = d.get("index")
    if index is not None:
        if index not in INDEXES[t]:
            _refuse(where, "index %r doesn't apply to %s (use %s)" % (index, t, " or ".join(INDEXES[t])))
        if t == "list" and index == "trigram" and of != "text":
            _refuse(where, "a trigram index needs a list of text, not of %s" % of)
    for flag in ("sensitive", "identity"):
        if not isinstance(d.get(flag, False), bool):
            _refuse(where, "%s is true or false" % flag)
    desc = d.get("description", "")
    if not isinstance(desc, str):
        _refuse(where, "description is text")
    identity, parent = d.get("identity", False), d.get("parent")
    if identity and (t != "text" or index != "exact" or d.get("sensitive", False)):
        # lineage looks the value up in other files' metadata: by its index, and never in what only owners see
        _refuse(where, "an identity field is text with index = \"exact\", not sensitive")
    if parent is not None and (not identity or not isinstance(parent, str)):
        _refuse(where, "parent names another identity field of this schema, on an identity field")
    return Field(name, t, of, index, d.get("sensitive", False), identity, desc, parent)


def parse(d, path, common=None):
    """A Schema from a parsed TOML table. `common` is the common schema, which every other's mapping must name."""
    where = path
    if not isinstance(d, dict):
        _refuse(where, "not a table")
    _unknown(where, d, _TOP_KEYS)
    name = d.get("name")
    stem = os.path.splitext(os.path.basename(path))[0]
    if not isinstance(name, str) or not _SCHEMA_NAME.match(name):
        _refuse(where, "name must be a lowercase letter then up to 19 lowercase letters or digits, not %r" % (name,))
    if name != stem:
        _refuse(where, "name %r must match the file's name (%s.toml)" % (name, name))
    version = d.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        _refuse(where, "version must be a whole number from 1, not %r" % (version,))
    title = d.get("title", name)
    if not isinstance(title, str):
        _refuse(where, "title is text")
    mime = d.get("mime")
    if not isinstance(mime, list) or not mime:
        _refuse(where, "mime must list the MIME types it applies to (\"*/*\" for all)")
    for m in mime:
        if not isinstance(m, str) or not _MIME.match(m):
            _refuse(where, "not a MIME type: %r (use e.g. image/jpeg, image/*, */*)" % (m,))

    fields_d = d.get("fields")
    if not isinstance(fields_d, dict) or not fields_d:
        _refuse(where, "a schema needs [fields.NAME] tables")
    fields = {}
    for fname, fd in fields_d.items():
        if not _FIELD_NAME.match(fname):
            _refuse(where, "field name %r: a lowercase letter, then up to 29 lowercase letters, digits or _" % fname)
        fields[fname] = _field("%s: field %s" % (where, fname), fname, fd)
    for f in fields.values():
        p = fields.get(f.parent) if f.parent is not None else None
        if f.parent is not None and (p is None or not p.identity or p.parent is not None):
            _refuse("%s: field %s" % (where, f.name), "parent %r is not an identity field of this schema without "
                    "a parent of its own" % f.parent)

    extractor = d.get("extractor")
    if extractor is not None:
        w = where + ": [extractor]"
        if not isinstance(extractor, dict):
            _refuse(w, "a table with module and requires")
        _unknown(w, extractor, _EXTRACTOR_KEYS)
        mod = extractor.get("module")
        if not isinstance(mod, str) or not _MODULE.match(mod):
            _refuse(w, "module must be a Python module's dotted name, not %r" % (mod,))
        req = extractor.get("requires", [])
        if not isinstance(req, list) or not all(isinstance(r, str) and _REQUIREMENT.match(r) for r in req):
            _refuse(w, "requires lists packages, e.g. [\"Pillow>=10\"], not %r" % (req,))
        extractor = {"module": mod, "requires": list(req)}

    mapping = d.get("common", {})
    if not isinstance(mapping, dict):
        _refuse(where, "[common] maps common fields to this schema's: creator = \"artist\"")
    if name == COMMON:
        if mapping:
            _refuse(where, "the common schema maps onto nothing: no [common]")
    else:
        if common is None:
            _refuse(where, "the common schema (%s) must load first" % COMMON)
        for target, source in mapping.items():
            w = "%s: [common] %s" % (where, target)
            if target not in common.fields:
                _refuse(w, "not a field of %s (%s)" % (COMMON, ", ".join(common.fields)))
            if not isinstance(source, str) or source not in fields:
                _refuse(w, "names %r, not a field of this schema" % (source,))
            t, s = common.fields[target], fields[source]
            if not _fits(s, t):
                _refuse(w, "%s is %s, which doesn't fit %s.%s (%s)" % (source, _kind(s), COMMON, target, _kind(t)))
    return Schema(name, version, title, list(mime), fields, dict(mapping), extractor, path)


def _kind(f):
    return "a list of %s" % f.of if f.type == "list" else f.type


def _fits(source, target):
    """A value of `source` can stand as one of `target`: the same type, or one item of a list of that type."""
    if source.type == target.type:
        return source.type != "list" or source.of == target.of
    return target.type == "list" and source.type == target.of


def _read(path, common=None):
    try:
        with open(path, "rb") as f:
            d = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError("%s: not valid TOML: %s" % (path, e))
    except OSError as e:
        raise ConfigError("%s: can't read: %s" % (path, e.strerror))
    return parse(d, path, common)


def _files(directory):
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(".toml"))
    except OSError as e:
        raise ConfigError("schemas folder %s: %s" % (directory, e.strerror))
    return [os.path.join(directory, n) for n in names]


class Registry:
    def __init__(self, schemas):
        self.schemas = schemas          # name -> Schema, the common one first

    def __getitem__(self, name):
        return self.schemas[name]

    def __iter__(self):
        return iter(self.schemas.values())

    def indexes(self):
        return [i for s in self for i in s.indexes()]


def load(site_dir=None, builtin_dir=BUILTIN_DIR):
    """The project's schemas, then the site's (a folder of NAME.toml, [metadata] schemas in server.toml). A site
    schema can't take a project schema's name."""
    paths = _files(builtin_dir)
    common_path = os.path.join(builtin_dir, COMMON + ".toml")
    if common_path not in paths:
        raise ConfigError("%s: missing: the common schema" % common_path)
    common = _read(common_path)
    schemas = {COMMON: common}
    builtin = {os.path.splitext(os.path.basename(p))[0] for p in paths}
    for p in [p for p in paths if p != common_path] + (_files(site_dir) if site_dir else []):
        stem = os.path.splitext(os.path.basename(p))[0]
        if stem in schemas:
            raise ConfigError("%s: schema %r is already enrolled%s" % (
                p, stem, " by the project; give the site's another name" if stem in builtin else ""))
        schemas[stem] = _read(p, common)
    return Registry(schemas)
