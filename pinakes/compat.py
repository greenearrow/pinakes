"""Which release this is, and which agents and servers it works with (RELEASES.toml has every release).

PROTOCOL numbers the batch format, the agent's state and the catalog's schema together: a change to any of them
raises it (tests/test_releases.py fails otherwise). An agent and a server compare at check-in (`pinakes-ingest hello`):
each side names the oldest protocol of the other that it works with. An agent or server from before check-in declares
nothing and counts as protocol 0.
"""

RELEASE = 11                # the newest entry in RELEASES.toml
PROTOCOL = 1                # 1: check-in, and the protocol in each batch's header
MIN_AGENT_PROTOCOL = 0      # the server accepts batches from agents of this protocol or later (0: before check-in)
MIN_SERVER_PROTOCOL = 0     # the agent sends to servers of this protocol or later (0: one that can't answer hello)

# What a batch may carry, by the protocol above: a field outside these fails the tests, so adding one raises it.
BATCH_FIELDS = {
    "header": ("t", "format", "host", "root", "scan", "started", "root_def", "seq", "complete", "records",
               "release", "protocol", "min_server_protocol"),
    "root_def": ("path", "kind", "protected", "mirrors"),
    "file": ("t", "path", "size", "mtime_ns", "ctime_ns", "btime_ns", "dev", "ino", "nlink", "uid", "sha256",
             "chunk_params", "chunks", "members", "members_error", "unstable", "protected_link", "hidden", "meta",
             "resend", "target", "link_root", "link_path", "dangling"),
    "error": ("t", "path", "error"),
    "gone": ("t", "path"),
}

# Each upgrades/*.sql and a query that is true once it has run (readable by any role: catalog lookups only).
UPGRADE_PROBES = {
    "review-marks.sql": "to_regclass('pinakes.review_marks') IS NOT NULL",
    "protected-links.sql": "EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pinakes.files') "
                           "AND attname = 'protected_link' AND NOT attisdropped)",
    "symlink-targets.sql": "EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pinakes.files') "
                           "AND attname = 'link_dangling' AND NOT attisdropped)",
    "metadata-indexes.sql": "to_regprocedure('pinakes.enroll_metadata_indexes(jsonb)') IS NOT NULL",
    "metadata-extracted.sql": "EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pinakes.metadata') "
                              "AND attname = 'sent_by' AND NOT attisdropped)",
    "metadata-sensitive.sql": "to_regprocedure('pinakes.sensitive_visible(bigint, bigint)') IS NOT NULL",
    "hidden-files.sql": "EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pinakes.files') "
                        "AND attname = 'hidden' AND NOT attisdropped)",
    "checkins.sql": "to_regclass('pinakes.checkins') IS NOT NULL",
}

LOCKED_EXIT = 4             # pinakes-agent's exit status while it holds its batches for want of a compatible server


def verdict(agent_protocol, agent_min_server, server_protocol, server_min_agent):
    """None if this agent and server work together, else (side that must update, why)."""
    if server_protocol < agent_min_server:
        return "server", "the agent (protocol %d) needs a server of protocol %d or later; the server is at %d" % (
            agent_protocol, agent_min_server, server_protocol)
    if agent_protocol < server_min_agent:
        return "agent", "the server (protocol %d) accepts agents of protocol %d or later; the agent is at %d" % (
            server_protocol, server_min_agent, agent_protocol)
    return None


def as_int(v, default=0):
    """A protocol or release number from the other side: a small non-negative int, else default."""
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << 31 else default
