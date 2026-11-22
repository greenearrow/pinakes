"""The server's configuration (server.example.toml): database, people, hosts, ownership seeds, lineage."""

import os
import re

from .config import ConfigError, tomllib

_INTERVAL = re.compile(r"(\d+)\s*([smhdw])\Z")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def interval(value):
    """'1d', '12h', 'never' -> a PostgreSQL interval string, or None for never."""
    if value in (None, "", "never"):
        return None
    m = _INTERVAL.match(str(value).strip())
    if not m:
        raise ConfigError("not an interval: %r (use e.g. 1d, 36h, never)" % value)
    return "%s %s" % (m.group(1), _UNITS[m.group(2)])


_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def seconds(value):
    """'90s', '1h', 'never' -> seconds, or None for never."""
    if value in (None, "", "never"):
        return None
    m = _INTERVAL.match(str(value).strip())
    if not m or int(m.group(1)) == 0:
        raise ConfigError("not a duration: %r (use e.g. 30m, 1h, never)" % value)
    return int(m.group(1)) * _SECONDS[m.group(2)]


class ServerConfig:
    def __init__(self, d, base_dir="."):
        db = d.get("database", {})
        self.dsn = db.get("dsn", "")
        self.password_file = db.get("password_file")
        self.people = d.get("people", {})
        self.groups = {name: g.get("members", []) for name, g in d.get("groups", {}).items()}
        own = d.get("ownership", {})
        self.default_owner = own.get("default_owner")
        if self.default_owner and self.default_owner not in self.people and self.default_owner not in self.groups:
            raise ConfigError("ownership.default_owner %r is not a person or group" % self.default_owner)
        self.rules = own.get("rule", [])
        self.enrollments = own.get("enrollment", [])
        for r in self.rules:
            if "root" not in r or "folder" not in r or "owner" not in r:
                raise ConfigError("an [[ownership.rule]] needs root, folder and owner")
        for e in self.enrollments:
            if e.get("as") not in ("co-owner", "reader", "annotator"):
                raise ConfigError("an enrollment's as must be co-owner, reader or annotator")
        self.hosts = {}
        for name, h in d.get("hosts", {}).items():
            self.hosts[name] = {"roots": list(h.get("roots", [])),
                                "expected_every": interval(h.get("expected_every", "1d")),
                                "uid_map": {int(k): v for k, v in h.get("uid_map", {}).items()},
                                "key": h.get("key")}
            for who in self.hosts[name]["uid_map"].values():
                if who not in self.people and who not in self.groups:
                    raise ConfigError("hosts.%s.uid_map: %r is not a person or group" % (name, who))
        for r in self.rules:
            # owner = "uid": the file's uid, through the uid_map of the host that reports the root
            if r["owner"] == "uid" and not any(r["root"] in h["roots"] and h["uid_map"]
                                               for h in self.hosts.values()):
                raise ConfigError('an ownership rule with owner = "uid" needs a uid_map on a host that reports '
                                  "root %s" % r["root"])
        lin = d.get("lineage", {})
        self.chunk_overlap = float(lin.get("chunk_overlap", 0.6))
        self.name_patterns_file = lin.get("name_patterns")
        # a name match alone is not evidence: it also needs sizes within this share of each other, the same parent
        # folder name (if at most name_folder_max folders have it), the other file changing or going within this many days, or a drop root on either side
        self.name_size_within = float(lin.get("name_size_within", 0.05))
        self.name_window_days = int(lin.get("name_window_days", 7))
        self.name_folder_max = int(lin.get("name_folder_max", 5))   # "the same folder name" only if this few have it
        self.name_size_namesakes = int(lin.get("name_size_namesakes", 5))  # "similar size" only if this few files
        # one batch may run this long before it is stopped and rolled back (a backstop: a sender that hangs up
        # stops it sooner)
        self.max_batch_time = seconds(d.get("ingest", {}).get("max_batch_time", "1h"))
        self._placeholders(d.get("placeholders", {}))
        self.web = d.get("web", {})
        # a folder of the site's own schemas (NAME.toml), enrolled after the project's (METADATA.md "Schemas")
        self.schemas_dir = d.get("metadata", {}).get("schemas")
        self.base_dir = base_dir

    def _placeholders(self, p):
        """[placeholders] (ROADMAP 69): what `pinakes placeholders` offers as candidates (a content of at most
        max_size bytes held under at least min_names names outside backup roots), how near in size a likely sibling
        is, and the site's rules: a content a rule matches is a placeholder without a person's mark."""
        def count(v, what, least):
            if isinstance(v, bool) or not isinstance(v, int) or v < least:
                raise ConfigError("%s must be a whole number of at least %d" % (what, least))
            return v
        self.placeholder_min_names = count(p.get("min_names", 3), "placeholders.min_names", 2)
        self.placeholder_max_size = count(p.get("max_size", 65536), "placeholders.max_size", 1)
        within = p.get("siblings_within", 0.2)
        if isinstance(within, bool) or not isinstance(within, (int, float)) or not 0 <= within < 1:
            raise ConfigError("placeholders.siblings_within is a share of the size, from 0 to under 1")
        self.placeholder_siblings_within = float(within)
        self.placeholder_rules = []
        for r in p.get("rule", []):
            name = r.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ConfigError("a [[placeholders.rule]] needs a name")
            if set(r) - {"name", "ext", "max_size", "min_names", "min_folders"}:
                raise ConfigError("[[placeholders.rule]] %s: only name, ext, max_size, min_names and min_folders"
                                  % name)
            if "max_size" not in r:
                raise ConfigError("[[placeholders.rule]] %s needs max_size (bytes)" % name)
            ext = r.get("ext")
            if ext is not None:
                if not isinstance(ext, str) or not ext.strip(". ") or "/" in ext:
                    raise ConfigError("[[placeholders.rule]] %s: ext is an extension, e.g. \"dat\"" % name)
                ext = "." + ext.strip().lstrip(".").lower()
            self.placeholder_rules.append({
                "name": name.strip(), "ext": ext,
                "max_size": count(r["max_size"], "[[placeholders.rule]] %s max_size" % name, 1),
                "min_names": count(r.get("min_names", 3), "[[placeholders.rule]] %s min_names" % name, 2),
                "min_folders": count(r.get("min_folders", 1), "[[placeholders.rule]] %s min_folders" % name, 1)})
        if len({r["name"] for r in self.placeholder_rules}) < len(self.placeholder_rules):
            raise ConfigError("two [[placeholders.rule]] have the same name")

    def connect_kwargs(self):
        kw = {"conninfo": self.dsn}
        if self.password_file and os.path.exists(self.password_file):
            with open(self.password_file) as f:
                kw["password"] = f.read().strip()
        return kw

    def host_allows(self, host, root_label):
        h = self.hosts.get(host)
        return h is not None and root_label in h["roots"]


def load(path):
    with open(path, "rb") as f:
        return ServerConfig(tomllib.load(f), os.path.dirname(os.path.abspath(path)))


def loads(text):
    return ServerConfig(tomllib.loads(text))
