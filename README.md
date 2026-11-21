# pinakes

A catalog of every file on every machine in a home lab, and of who owns it: path, size, times, SHA-256 and metadata,
kept current by cheap incremental scans, with a web UI. Questions like "where are all copies of this", "what exists
only on this laptop", "is this folder backed up" and "is it safe to delete" become one indexed query instead of a
one-off hashing script.

The name is the *Pinakes*, the catalogue Callimachus compiled of the Library of Alexandria's holdings:
who wrote what, how long it was, where it was shelved. It held none of the scrolls; this holds none of the files.

**Status: early.** The agent, ingester, queries, CLI, a read-only web UI with sign-in, and a JSON API with
per-person tokens are built and tested; so are the metadata schemas, EXIF and XMP from JPEGs (sensitive fields for
owners only) and hidden files. Other extractors, person-entered metadata, file operations and more are not
(REARVIEW.md, ROADMAP.md).

- [DESIGN.md](DESIGN.md): the parts, what is recorded, roots and policies, backup servers, move and change matching,
  the web UI, managing files, queries.
- [SECURITY.md](SECURITY.md): people, roles and ownership; administrators see others' records only by stepping up,
  audited and visible to the people affected; row-level security; agents; the web UI.
- [METADATA.md](METADATA.md): metadata on content and on files, enrolled standard schemas (Dublin Core, EXIF, XMP,
  audio tags, OPF and more), bundles of files that belong together, storage and indexes.
- [QUERIES.md](QUERIES.md): every query in SQL.
- [ROADMAP.md](ROADMAP.md): what is left, and what "done" means for each piece.
- [HORIZON.md](HORIZON.md): over the horizon: not planned, kept only for the day a catalog's size asks for it.
- [REARVIEW.md](REARVIEW.md): what is built, and how each piece was tested.
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
- A wish: an MCP server over the queries, review marks and tags, acting as one person, every write undoable.

Target: Debian-family Linux with systemd, Python 3.10+ (tested on 3.10 to 3.15; 3.10 needs `tomli`, the
`agent310` extra), PostgreSQL 15+ (tested on 15 to 18); the web UI on Flask and waitress.

Licence: GPL-3.0 ([LICENSE](LICENSE)).

## Installing

A machine running pinakes needs only the package: `pip install pinakes` for an agent or the `pinakes` command
(`pinakes[agent310]` on Python 3.10), `pinakes[server]` for the catalog server and web UI. The command needs the
catalog's address (`client.example.toml`) and a token from the web UI's account page in `~/.config/pinakes/token`
(mode 600). No tests, test tools or extra PostgreSQL versions; the
wheel holds the package alone, and `tools/test --wheel` fails if anything else gets in.

## Contributing

Development needs more: `pip install -e '.[dev]'` (the server's packages, `build`, `uv`), and a PostgreSQL for the
tests. When to run what:

- Every commit: the hooks run `tools/leak-scan`, and, when the commit touches code or tests, the agent's tests
  (`tools/test --agent-only`, about 3 s; `PINAKES_SKIP_TESTS=1` skips them once). Run the full `tools/test` yourself
  (about 75 s).
- A change to the schema, an upgrade file, packaging or what runs on old machines: `tools/test --matrix`.
- A change to a query, a policy or an API list call: `tools/bench-pages` (about 5 minutes), which builds a catalog of
  500,000 files by real scans in a throwaway PostgreSQL and times each read call's first page, failing one over 2 s.
- Before a release: `tools/test --matrix` and `tools/test --wheel` ("Cutting a release" below).
- Preparing a release: its entry in `RELEASES.toml` (what it affects, its protocol, the `upgrades/*.sql` it needs)
  and the same numbers in `pinakes/compat.py`. Cutting it is a deliberate step, never implied by a commit: tag the
  commit `release-N` when the owner says so; until then nothing counts it. A change to the batch fields, the
  agent's state or the schema raises the protocol (`tests/test_releases.py` fails otherwise). `tools/latest-release
  ROLE` prints the newest cut release that changes `server`, `agent` or `cli`, from the tags only, never HEAD;
  `--upgrades-after N` the upgrade files of the cut releases after N.

The matrix needs each PostgreSQL major version side by side (PGDG's apt packages, with `create_main_cluster =
false` so none starts a cluster of its own) and `tools/test --setup` once.

Tests: `tools/test` starts a throwaway PostgreSQL (from `/usr/lib/postgresql/N/bin`; `--pg N` picks one), runs
every test with `.venv`'s Python, removes the cluster, and fails if anything was skipped for lack of a database or a
dependency; `tools/test --agent-only` needs neither. Its last line says what it ran on. Across versions:
`tools/test --setup` makes an environment per Python under `.matrix/` (with [uv](https://docs.astral.sh/uv/)),
then `tools/test --matrix --jobs 4` runs each Python and each PostgreSQL installed once, paired oldest with oldest
(PGDG's packages put several side by side; `--matrix full` runs every pair). `tools/test --wheel` tests what a release would ship: the wheel, built from a clean copy and
installed in a new environment.

Run `git config core.hooksPath githooks` once. The hooks run `tools/leak-scan`, which blocks addresses, MACs, LAN
host names, email addresses, keys and your own private terms (`leak-patterns.example`) from being committed.

### Cutting a release

Only when the owner says to cut it. In order:

1. **Ready:** its `RELEASES.toml` entry (what it affects, protocol, upgrade files, fingerprint, a note) and
   `pinakes/compat.py` agree, and `tests/test_releases.py` passes. `affects` names every role whose code changed
   since the last cut (`git diff release-N-1 --stat`): the CLI counts. A release that affects `cli` must reach
   every machine with the `pinakes` command, not only the catalog server: one where it is installed with an agent
   is updated by `agent` and `cli` together, so *Before you update* says so whenever `cli` is in and `agent` isn't.
2. **Tested:** `tools/test --matrix` and `tools/test --wheel`, both on the commit to be cut, both OK. A run that
   wasn't made is said to be not run, in step 3 and in the commits.
3. **What's new:** a `## Release N` section at the top of `WHATSNEW.md`: a first line that begins `Not cut.`, then
   what it affects, its protocol and which side may be updated first; *Before you update* (upgrade files in order,
   `tools/latest-release --upgrades-after N-1`, and the order of server, agents and CLI); one heading per change;
   *Not yet*, with what was tested (tests, Pythons, PostgreSQL, OS) and what wasn't (the wheel, other PostgreSQL, a
   real catalog, a deployment). Commit: `Release N: What's new (ROLES; protocol P; UPGRADES; not cut, not
   deployed)`, its body the test runs and the commit they ran on.
4. **Cut:** `Not cut.` becomes "Cut DATE (tag `release-N`)."; any "not cut" about release N in `REARVIEW.md` goes.
   Commit: `Release N: cut (WHATSNEW says so)`, the same test lines. Then `git tag release-N` on that commit.
5. **Check:** `tools/latest-release server`, `agent` and `cli` each print what they now should. No push, no
   deployment: that is the site's.
