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
        lin = d.get("lineage", {})
        self.chunk_overlap = float(lin.get("chunk_overlap", 0.6))
        self.name_patterns_file = lin.get("name_patterns")
        self.web = d.get("web", {})
        self.base_dir = base_dir

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
