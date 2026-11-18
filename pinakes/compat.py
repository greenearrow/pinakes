"""Which release this is, and which agents and servers it works with (RELEASES.toml has every release).

PROTOCOL numbers the batch format, the agent's state and the catalog's schema together: a change to any of them
raises it (tests/test_releases.py fails otherwise). An agent and a server compare at check-in (`pinakes-ingest hello`):
each side names the oldest protocol of the other that it works with. An agent or server from before check-in declares
nothing and counts as protocol 0.
"""

RELEASE = 7                 # the newest entry in RELEASES.toml (cut or being prepared)
PROTOCOL = 4                # 1: check-in, and the protocol in each batch's header; 2: sequence follows the
                            # server at check-in, a complete full scan retires what it didn't send; 3: scrub
                            # batches (DESIGN.md "Scrub"), and every batch names the agent's roots (ROADMAP 46);
                            # 4: checksum manifests' hint and manifest records (DESIGN.md "Checksum manifests")
MIN_AGENT_PROTOCOL = 0      # the server accepts batches from agents of this protocol or later (0: before check-in)
MIN_SERVER_PROTOCOL = 0     # the agent sends to servers of this protocol or later (0: one that can't answer hello)

# What a batch may carry, by the protocol above: a field outside these fails the tests, so adding one raises it.
BATCH_FIELDS = {
    "header": ("t", "format", "host", "root", "scan", "started", "root_def", "seq", "complete", "records",
               "release", "protocol", "min_server_protocol", "full", "accept_gone", "scrub", "roots"),
    # a scrub batch (DESIGN.md "Scrub"): its header's "scrub" in place of "scan", and only these records
    "scrub": ("on", "days", "oldest", "never", "mismatches", "unreadable"),
    "mismatch": ("t", "path", "size", "mtime_ns", "dev", "ino", "sha256", "verified", "chunk_params", "chunks"),
    "unreadable": ("t", "path", "error"),
    "readable": ("t", "path"),
    "root_def": ("path", "kind", "protected", "mirrors"),
    "file": ("t", "path", "size", "mtime_ns", "ctime_ns", "btime_ns", "dev", "ino", "nlink", "uid", "sha256",
             "chunk_params", "chunks", "members", "members_error", "unstable", "protected_link", "hidden", "meta",
             "resend", "target", "link_root", "link_path", "dangling"),
    "error": ("t", "path", "error"),
    "gone": ("t", "path"),
    # checksum manifests (DESIGN.md "Checksum manifests"), in a complete scan batch only: a listed file's verdict
    # (verdict null: none now), and a manifest's counts (none: no longer checked)
    "hint": ("t", "path", "verdict", "manifest"),
    "manifest": ("t", "path", "lines", "confirmed", "wrong", "missing", "unchecked", "bad", "outside"),
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
    "takeovers.sql": "EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pinakes.checkins') "
                     "AND attname = 'seq_reset' AND NOT attisdropped)",
    "api-tokens.sql": "to_regclass('pinakes.tokens') IS NOT NULL",
    "scrub.sql": "EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pinakes.files') "
                 "AND attname = 'unreadable_on' AND NOT attisdropped)",
    "files-policy.sql": "EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = to_regclass('pinakes.files') "
                        "AND polname = 'files_visible' "
                        "AND pg_get_expr(polqual, polrelid) ~ 'SELECT (pinakes\\.)?visible_acls\\(\\)')",
    "owner-by-uid.sql": "EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pinakes.owner_rules') "
                        "AND attname = 'by_uid' AND NOT attisdropped)",
    "unreported-roots.sql": "EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pinakes.roots') "
                            "AND attname = 'retired_on' AND NOT attisdropped)",
    "manifests.sql": "EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pinakes.files') "
                     "AND attname = 'manifest_verdict' AND NOT attisdropped)",
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
