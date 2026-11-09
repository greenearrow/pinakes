# pinakes

A catalog of every file on every machine in a home lab, and of who owns it: path, size, times, SHA-256 and metadata,
kept current by cheap incremental scans, with a web UI. Questions like "where are all copies of this", "what exists
only on this laptop", "is this folder backed up" and "is it safe to delete" become one indexed query instead of a
one-off hashing script.

The name is the *Pinakes*, the catalogue Callimachus compiled of the Library of Alexandria's holdings:
who wrote what, how long it was, where it was shelved. It held none of the scrolls; this holds none of the files.

**Status: early.** The agent, ingester, queries, CLI and a read-only web UI with sign-in are built and tested;
metadata, file operations and more are not (ROADMAP.md).

- [DESIGN.md](DESIGN.md): the parts, what is recorded, roots and policies, backup servers, move and change matching,
  the web UI, managing files, queries.
- [SECURITY.md](SECURITY.md): people, roles and ownership; administrators see others' records only by stepping up,
  audited and visible to the people affected; row-level security; agents; the web UI.
- [METADATA.md](METADATA.md): metadata on content and on files, enrolled standard schemas (Dublin Core, EXIF, XMP,
  audio tags, OPF and more), bundles of files that belong together, storage and indexes.
- [QUERIES.md](QUERIES.md): every query in SQL.
- [ROADMAP.md](ROADMAP.md): what is built, what is left, and what "done" means for each piece.
- [DECISIONS.md](DECISIONS.md): every choice made while building, and why.
- [config.example.toml](config.example.toml) (an agent) and [server.example.toml](server.example.toml) (the server).

In short:

- One agent per machine scans its own disks, read-only, rehashes only what changed, and sends batches when it can
  reach the server. Machines that are often off, or that sleep on demand, are fine.
- Backup servers are first-class: hard-linked snapshots are hashed once per inode, and each backup copy is tied back
  to its source.
- Moves and edits are tracked by hash, inode and content-defined chunk overlap, with the evidence recorded.
- PostgreSQL with row-level security; agents hold no database credentials.
- Never a way to reach a file: no download, upload or editing. The catalog says where a file is; the machine that
  holds it, through its own shares and logins, gives access.
- File operations (move, rename, write a sidecar, trash) only by approved request, carried out and verified by the
  agent; nothing is ever deleted.

- Owners per folder, changeable in the web UI, with others enrolled as co-owners, readers or annotators.
- A wish: an MCP server over the read-only queries, acting as one person.

Target: Debian-family Linux with systemd, Python 3.10+ (tested on 3.10 to 3.15; 3.10 needs `tomli`, the
`agent310` extra), PostgreSQL 15+ (tested on 15 to 18); the web UI on Flask and waitress.

Licence: GPL-3.0 ([LICENSE](LICENSE)).

## Installing

A machine running pinakes needs only the package: `pip install pinakes` for an agent (`pinakes[agent310]` on Python
3.10), `pinakes[server]` for the catalog server and web UI. No tests, test tools or extra PostgreSQL versions; the
wheel holds the package alone, and `tools/test --wheel` fails if anything else gets in.

## Contributing

Development needs more: `pip install -e '.[dev]'` (the server's packages, `build`, `uv`), and a PostgreSQL for the
tests. When to run what:

- Every commit: the hooks run `tools/leak-scan`, and, when the commit touches code or tests, the agent's tests
  (`tools/test --agent-only`, about 3 s; `PINAKES_SKIP_TESTS=1` skips them once). Run the full `tools/test` yourself
  (about 75 s).
- A change to the schema, an upgrade file, packaging or what runs on old machines: `tools/test --matrix`.
- Before a release: `tools/test --matrix full` and `tools/test --wheel`.

The matrix needs each PostgreSQL major version side by side (PGDG's apt packages, with `create_main_cluster =
false` so none starts a cluster of its own) and `tools/test --setup` once.

Tests: `tools/test` starts a throwaway PostgreSQL (from `/usr/lib/postgresql/N/bin`; `--pg N` picks one), runs
every test with `.venv`'s Python, removes the cluster, and fails if anything was skipped for lack of a database or a
dependency; `tools/test --agent-only` needs neither. Its last line says what it ran on. Across versions:
`tools/test --setup` makes an environment per Python under `.matrix/` (with [uv](https://docs.astral.sh/uv/)),
then `tools/test --matrix [full] --jobs 4` runs them against every PostgreSQL installed (PGDG's packages put several
side by side). `tools/test --wheel` tests what a release would ship: the wheel, built from a clean copy and
installed in a new environment.

Run `git config core.hooksPath githooks` once. The hooks run `tools/leak-scan`, which blocks addresses, MACs, LAN
host names, email addresses, keys and your own private terms (`leak-patterns.example`) from being committed.
