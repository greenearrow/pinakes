"""The agent's configuration (config.example.toml)."""

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: the distribution's python3-tomli
    import tomli as tomllib

import os

from .globs import Matcher

KINDS = ("primary", "drop", "backup")
OPERATIONS = ("move", "rename", "write-sidecar", "trash")
_SIZE_UNITS = {"": 1, "B": 1, "KIB": 1024, "MIB": 1024 ** 2, "GIB": 1024 ** 3, "TIB": 1024 ** 4,
               "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3, "TB": 1000 ** 4}


class ConfigError(ValueError):
    pass


def parse_size(value):
    if isinstance(value, int):
        return value
    s = str(value).strip().upper().replace(" ", "")
    num = s.rstrip("KMGTIB")
    unit = s[len(num):]
    if not num or unit not in _SIZE_UNITS:
        raise ConfigError("not a size: %r" % value)
    return int(float(num) * _SIZE_UNITS[unit])


class Root:
    def __init__(self, d):
        try:
            self.label = d["label"]
            self.path = d["path"].rstrip("/") or "/"
        except KeyError as e:
            raise ConfigError("a [[root]] needs %s" % e)
        self.kind = d.get("kind", "primary")
        if self.kind not in KINDS:
            raise ConfigError("root %s: kind must be one of %s" % (self.label, ", ".join(KINDS)))
        self.protected = bool(d.get("protected", False))
        # stay on the root's own filesystem unless told otherwise: a mount inside a root (a USB disk, a network share,
        # an opened encrypted folder) is not walked
        self.cross_mounts = bool(d.get("cross_mounts", False))
        self.archives = bool(d.get("archives", False))
        if self.protected and self.archives:
            raise ConfigError("root %s: a protected root can't list archives" % self.label)
        self.exclude = Matcher(d.get("exclude", []))
        self.hash = d.get("hash", "sha256")
        if self.hash not in ("sha256", "none"):
            raise ConfigError("root %s: hash must be sha256 or none" % self.label)
        c = d.get("chunks") or {}
        self.chunks = bool(c.get("enabled", False))
        if self.chunks and self.hash == "none":
            raise ConfigError("root %s: chunks need hash = sha256" % self.label)
        self.chunk_min_size = parse_size(c.get("min_size", "64KiB"))
        self.chunk_max_size = parse_size(c.get("max_size", "2GiB"))
        self.chunk_average = parse_size(c.get("average", "256KiB"))
        self.managed = list(d.get("managed", []))
        bad = [m for m in self.managed if m not in OPERATIONS]
        if bad:
            raise ConfigError("root %s: unknown operations %s" % (self.label, bad))
        self.mirrors = d.get("mirrors")
        if self.kind == "backup" and not self.mirrors:
            raise ConfigError("root %s: a backup root needs mirrors" % self.label)
        # which schemas' extractors run here (METADATA.md): true or left out, every one that applies; false or [],
        # none; or a list of schema names
        m = d.get("metadata", True)
        if self.protected and m not in (False, [], None) and "metadata" in d:
            raise ConfigError("root %s: a protected root can't extract metadata" % self.label)
        if m is True:
            self.metadata = None
        elif m is False:
            self.metadata = []
        elif isinstance(m, list) and all(isinstance(n, str) for n in m):
            self.metadata = list(m)
        else:
            raise ConfigError("root %s: metadata is true, false or a list of schema names" % self.label)
        if self.protected:
            self.metadata = []

    def wants_chunks(self, size):
        return self.chunks and self.chunk_min_size <= size <= self.chunk_max_size


class AgentConfig:
    def __init__(self, d):
        a = d.get("agent", {})
        try:
            self.host = a["host"]
            self.state = a["state"]
            self.outbox = a["outbox"]
        except KeyError as e:
            raise ConfigError("[agent] needs %s" % e)
        # the scrub file (DESIGN.md "Scrub"): written by the agent, its numbers edited by the person
        self.scrub = a.get("scrub")
        if self.scrub is not None and not isinstance(self.scrub, str):
            raise ConfigError("[agent] scrub is the scrub file's path")
        m = a.get("scrub_max_minutes")
        if m is not None and (isinstance(m, bool) or not isinstance(m, int) or m <= 0):
            raise ConfigError("[agent] scrub_max_minutes must be a whole number of minutes above 0")
        self.scrub_max_minutes = m
        s = d.get("schedule", {})
        self.only_on_ac = bool(s.get("only_on_ac", False))
        self.busy_command = s.get("busy_command", "")
        self.batch_records = int(s.get("batch_records", 5000))
        self.transport = d.get("transport", {"kind": "directory", "path": self.outbox + "/../inbox"})
        if self.transport.get("kind") not in ("ssh", "directory"):
            raise ConfigError("[transport] kind must be ssh or directory")
        t = self.transport.get("timeout", 600)
        if isinstance(t, bool) or not isinstance(t, int) or t <= 0:
            raise ConfigError("[transport] timeout must be a whole number of seconds above 0")
        self.roots = [Root(r) for r in d.get("root", [])]
        labels = [r.label for r in self.roots]
        if len(set(labels)) != len(labels):
            raise ConfigError("root labels must be unique")

    def root(self, label):
        for r in self.roots:
            if r.label == label:
                return r
        raise ConfigError("no root %r" % label)


def load(path):
    with open(path, "rb") as f:
        cfg = AgentConfig(tomllib.load(f))
    if cfg.scrub is None:                       # beside agent.toml
        cfg.scrub = os.path.join(os.path.dirname(os.path.abspath(path)), "scrub.toml")
    return cfg


def loads(text):
    cfg = AgentConfig(tomllib.loads(text))
    if cfg.scrub is None:                       # no file to sit beside: beside the state
        cfg.scrub = os.path.join(os.path.dirname(os.path.abspath(cfg.state)), "scrub.toml")
    return cfg
