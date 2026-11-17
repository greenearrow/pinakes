# What's new in pinakes

Newest first. Each release's full entry is in `RELEASES.toml`; the reasons are in `DECISIONS.md`.

## Release 6

Cut 2026-11-17 (tag `release-6`). Affects the server, the agents and the CLI. Protocol 3; agents and servers of protocol 0 to 2 still work with it, and
either side may be updated first.

### Before you update

1. As the schema's owner, run in order: `upgrades/scrub.sql`, `upgrades/files-policy.sql`,
   `upgrades/owner-by-uid.sql`, then `upgrades/unreported-roots.sql` (`tools/latest-release --upgrades-after 5` lists
   them). Then update the server, then the agents.
2. **The agents start scrubbing.** After their scans, they re-read every file over 30 days per local filesystem
   (network filesystems off). Each night reads about a thirtieth of the disk. Set `days` in the `scrub.toml` the
   agent writes, or `[agent] scrub_max_minutes`, before the first night if that is too much.
3. **`/health` has two new reasons for 503:** `"roots unreported"` and `"scrub behind"`. A monitor that alerts on
   any 503 will fire on them, which is the intent.

### The scrub

- After the scans, each filesystem's files are read again over `days` (`scrub.toml`, written by the agent; you
  change only the numbers), least recently verified first. A changed hash under an unchanged size and mtime is
  reported as a **mismatch**, and a read error as **unreadable**. Both are reviewable and on the restore list, and an
  unreadable file counts as no copy until it reads again.
- `pinakes-agent scrub` runs it alone, and `pinakes-agent scrub status` shows each filesystem's rotation.
- `/health` says per host when the oldest check was made and whether the scrub is behind.
- An agent scrubs only once its server answers protocol 3, so an agent updated before its server just waits.

### A machine replaced under the same name

- Every batch now names all of the agent's roots. A root of that host that the batches leave out (new hardware
  with fewer disks, or a root dropped from the config) is flagged: its files would otherwise go on counting as
  copies.
- `/health` gives a count per host (`roots_unreported`, no labels) and answers 503 "roots unreported";
  `pinakes releases` says the same. **On the server, `pinakes-ingest totals` names the roots**, with the
  `pinakes-ingest retire-root LABEL` to run.
- A batch that names the root again clears the flag, and so does retiring it. Agents before release 6 name no roots,
  so nothing is flagged for them.

### Ownership and speed

- **Owner rules by uid:** `owner = "uid"` in an `[[ownership.rule]]` gives each file to whoever its uid maps to in
  the host's `uid_map` (`server.example.toml`). A chown moves the file, and a uid the map doesn't name falls to the
  next rule.
- **The home page is fast on a large catalog:** the files policy is evaluated once per query, and every root is
  counted in one pass. On generated catalogs this took 2M files from 1.3 s to 0.18 s and 10M from 79 s to 1.3 s.
- **Token forms on the account page** can be filled by a password manager, and show their result next to the form.

### Not yet

Tested: 370 tests on each of Python 3.10 to 3.15 with PostgreSQL 16.15, and the installed wheel on Python 3.12
(Linux x86-64); PostgreSQL 15, 17 and 18 not run. Not run against a real catalog or on real disks; not deployed. The
scrub's load on a real disk, and a password manager on the token forms, not tried.

## Release 5

Affects the server, the agents and the CLI. Protocol 2; agents and servers of protocol 0 and 1 still work with it.

### Before you update

1. As the schema's owner, run in order: `upgrades/takeovers.sql`, then `upgrades/api-tokens.sql`
   (`tools/latest-release --upgrades-after 4` lists them). Then update the server, then the agents.
2. **`pinakes --versions` is gone.** It now exits 1 and says to use `pinakes releases`. Change any deploy check or
   script that calls it (below).
3. **`pinakes --backups` is now `pinakes backups`.**
4. **`pinakes` is now a client of the web service.** It needs a client config with the catalog's address
   (`client.example.toml`: https, or http only to this machine) and a token in `~/.config/pinakes/token`, mode 600
   and the user's own; a token file anyone else can read is refused. The web service must be running.

### A JSON API and tokens

- `/api/v1/` in `pinakes-web` answers the CLI's queries (`find`, `where`, `only-here`, `safe-to-delete`,
  `backed-up`, `dupes`, `history`, `versions`, `lineage`, `changes`, `meta`, `stale`, ...) by bearer token.
- **Person tokens**, made and revoked on the account page: scopes `read`, `review`, `tag`; every root but the
  protected ones, or only the roots ticked; a lifetime or none. Shown once, stored as a hash, every call on the
  person's access page. A token never steps up, and row-level security holds it to its roots.
- **Group tokens** act as a group and no member: they see what the group owns or is enrolled in, mark only where the
  group owns or co-owns, and stop working when their maker leaves the group. Any member can list and revoke them.
- **Ops tokens**, made by an operator, act as no person and see no file: they answer only `releases`, `stale` and
  `whoami`. Use one for monitoring and deploy checks.

### The `pinakes` command

- Works on any machine with Python 3.10+ and nothing else installed: it talks to the API, never to the database.
- **From inside a folder:** commands take a path here, `ROOT:PATH`, or nothing for the current folder. Bare
  `pinakes` sums up the folder you're in (files, without a backup, without a copy on another disk, changed in the
  last 7 days).
- `only-here`, `safe-to-delete` and `backed-up` given a file answer for that file, on the web too. Before, a file
  matched nothing under it, which read as "safe".
- `pinakes --as NAME` runs one command as another person, after their password and second factor (or a token of
  theirs): read only, 10 minutes at most, revoked when the command ends, audited for them.
- `pinakes review intended|restore [PATH]` shows the unreviewed gone files and moves under a folder, asks, and marks
  exactly those (`--yes` to skip the question). Needs a token with the `review` scope.
- `pinakes releases` (with an ops token) prints what `pinakes --versions` did: the server's release and each agent's
  last check-in.

### Agents and the ingester

- **A machine that takes over a host no longer loses its batches.** A batch number already applied is accepted only
  if it is the same batch; another is refused and recorded, and the agent renumbers to follow the server at check-in
  (`pinakes-agent renumber --after N` by hand).
- **`scan --full` from start to end retires what it didn't send**, except under paths it reported errors for; most of
  a root only with `--accept-gone`.
- `pinakes-ingest retire-root LABEL` retires a root a host no longer reports.
- Refusals and the last renumbering show in `pinakes releases` and `/health` (503 "refused" while a host's batches
  are held).

### Not yet

Tested: 324 tests on each of Python 3.10 to 3.15 with PostgreSQL 16.15, and the installed wheel on Python 3.12
(Linux x86-64); PostgreSQL 15, 17 and 18 not run. Not run against a real catalog; not deployed. Tags (the `tag` scope) wait for person-entered metadata.
