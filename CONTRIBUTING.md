# Contributing

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

## Cutting a release

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
