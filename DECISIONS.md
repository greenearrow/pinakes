# Decisions

What was decided, by whom, and why, newest last. "Owner" decisions came from the project's owner; "build" decisions
were made while building, to keep going, and are open to change.

## Design (owner)

- Design as in DESIGN.md, SECURITY.md, METADATA.md and QUERIES.md: approved.
- Python, standard library first; where a dependency is needed, Flask and waitress for the web.
- The database identity: one unprivileged application role, with the signed-in person set per transaction for
  row-level security. Not a PostgreSQL role per person.
- The ingester and the web UI run on the database server.
- Dates, not times, are the unit of history: it is for finding which backup holds a version, not for tracking people.
- Chunk hashes are allowed on protected roots: they say nothing readable. Protected records never go to an outside
  service that would use them (MCP tokens leave protected roots out unless added).
- No deletion, ever: `trash` only.
- Never a way to reach a file: no download, upload, opening or editing, by any route (web UI, MCP, API, a proxy to a
  share). Working on a file through a portal makes stray copies, and a breached index exposes far less than a
  breached file portal. Access stays with each machine's own shares and logins. Previews stay as designed (optional
  per root, never on a protected root).

## Build

- **Layout:** one Python package, `pinakes/`, with the agent, ingester, CLI and web as modules; console entry points
  in `pyproject.toml`. Tests use `unittest` (standard library), so the agent's tests need nothing installed.
- **Python 3.10 floor for the agent.** Some machines that will run it are on 3.10 until their next reinstall. The agent
  code avoids 3.11-only syntax and reads TOML with `tomllib`, falling back to `tomli` (packaged by the distribution) on
  3.10. The server parts may use 3.11+.
- **The agent is simple; the server matches.** The agent reports what it sees (paths, sizes, times, device and inode,
  link count, hashes) and what disappeared. Moves, changes, copies and lineage are all worked out by the ingester,
  which sees every host. This keeps one implementation of the matching rules and lets late reports from a laptop link
  up.
- **Resuming a scan:** each scan has an id; every file seen is marked with it. An interrupted scan re-walks (metadata
  only) and skips files already marked; files never marked by the time the walk completes are reported gone. Gone
  reports therefore come only from a completed walk.
- **Walk order** is sorted by name, so batches are deterministic and tests are stable.
- **Hard links:** a file with more than one link is hashed once per (device, inode) in a scan, and its hash is reused
  while size, mtime and ctime are unchanged.
- **Niceness, I/O class and the sleep inhibitor** are set by the systemd unit (`Nice=`, `IOSchedulingClass=`,
  `systemd-inhibit`), not by the agent, which only checks `only_on_ac` and `busy_command`.
- **Batches** are gzip-compressed JSON lines with a header line (host, sequence number, root, scan id, whether the scan
  completed). The agent deletes a batch only after the ingester acknowledges its sequence number.
- **Batch sequence numbers** are reserved and committed before a batch is written, so a crash leaves a gap, never a
  reused number. The ingester applies a host's batches in increasing order and ignores numbers it has seen.
- **Only changes are sent.** A completed scan tells the ingester that everything it didn't report gone is still
  there. `pinakes-agent scan --full` resends every record, for after the database is restored from a backup.
- **Chunks belong to content**, so a second link to an inode, or a copy elsewhere, doesn't resend them.
- **Mass-gone guard:** if a completed walk finds more than half of a root's files missing (and at least 100), it
  reports nothing gone and stops: a mount that didn't come up looks exactly like that. `--accept-gone` confirms a real
  deletion. Files under a folder that couldn't be listed are never reported gone.
- **Telling a dismount from a deletion:** when the guard trips, it names the likely cause: the root is on another
  device than its files were recorded on ("not mounted"), or the same one ("deleted?"). And every walk checks the
  root's device at its start and end: if it changed (unmounted or remounted mid-scan), nothing is reported gone,
  however few files were missed and even with `--accept-gone`; the next run resumes. Without that, an unmount late
  in a walk left fewer missing than the guard's threshold and they were reported gone.
- **A file that changes while it's read** is sent with no hash and `unstable`; the next scan hashes it.
- **Symlinks** are recorded (with their target) and never followed. Sockets, fifos and devices are skipped.
- **Chunk digests** are the first 128 bits of SHA-256: enough to tell chunks apart, half the space.
- **Chunking speed:** pure Python, about 16 MB/s on a 12th-gen desktop core (measured). Fine for drop folders and
  documents; a media root should leave chunks off.
- **Owner rules are folders**, not globs: a rule covers a folder and everything below it, and the longest matching
  folder wins. That is what "change it per folder" needs, and it keeps the most-specific rule obvious.
- **Visibility through ACLs.** Each distinct combination of owner and enrollments is one ACL; a file points at one,
  and `acl_members` is it expanded to people (groups included). Row-level security is then one array test per row
  (`acl_id = ANY (visible_acls())`), computed once per statement. Changing a rule recomputes the root's files
  (`recompute_root`), with no rescan.
- **The `present` view is `security_invoker`.** A plain view reads its table as the view's owner, so row-level
  security wouldn't apply through it. Found while writing the schema; a test checks the view shows exactly what the
  table does.
- **Moves are matched only within one root and one scan:** a gone path and a new path in the same completed scan.
  A move between two roots of the same machine shows as a copy (a certain lineage edge) and a gone file.
- **Direction of a copy** comes from the files' mtimes: the earlier holder of the content is the source. A plain copy
  gets a new mtime; an edit's mtime is when it was written. So a laptop reporting late still links the right way.
- **Weaker lineage evidence** (chunks, names) is used only for a file with no line yet: a changed file keeps its own,
  and a certain edge isn't joined by a guess.
- **A name match** links to the most recent earlier file with the same normalized name and extension: the likeliest
  immediate parent.
- **pg_trgm** is installed in `public`: the database is the catalog's own.
- **Past versions stay visible to their owner.** Running QUERIES.md as a test found that `versions` lost every version
  no file holds any more: the contents policy only allowed content a visible file holds now. Contents referenced by a
  visible file's history are now visible too (still nobody else's).
- **Two database roles, two DSNs:** `[database]` is the ingester's (`pinakes_ingest`, bypasses row-level security);
  `[web]` is the web UI's and CLI's (`pinakes_app`, under it). The CLI takes `--as NAME` and never steps up.
- **Passwords are scrypt** (`hashlib.scrypt`, standard library; N=2^15, r=8, about 32 MB), not argon2id, which would
  be a dependency. A sign-in for an unknown name checks a dummy hash, so both take the same time.
- **TOTP is implemented in the standard library** (RFC 6238, checked against its test vector), with one step of
  clock drift either side. WebAuthn and OpenID Connect are later.
- **Sign-in limits** are in memory: five failures per address in 15 minutes. They reset when the service restarts.
- **The first password** is set on the server with `pinakes-ingest passwd NAME` at a hidden prompt; after that,
  people change their own in the UI.
- **No htmx yet:** every page is plain server-rendered HTML; htmx comes when something needs a partial update.
- **A file you can't see answers 404**, the same as one that doesn't exist.
- **Lineage walks never revisit a file.** A file keeps its id through versions, so a copy out and back makes a
  cycle between two files; found when the demo's walk came back 50 levels deep.
- **`pinakes-ingest setup` doesn't create the schema.** The schema belongs to a role that can't log in, so a
  superuser applies it once; setup says how and stops (exit 2).
- **Measured on a desktop (12th-gen Intel, ext4, warm cache), a 3.0 GB tree of 383,985 entries:** first scan 44 s
  (67 MB of memory); a rescan with nothing changed 4.2 s; ingesting it 187 s (about 2,000 records a second, 352 MB);
  database 584 MB (about 1.5 KB a file, indexes included). The ingester does a few round trips per record; batching
  them is the first optimization if a large first pass is too slow on a small server.
- **Behind a reverse proxy** (`[web] behind_proxy = true`), the visitor comes from `X-Forwarded-For`, trusting exactly
  one hop; otherwise every visitor is the proxy and the sign-in limit is one limit for everybody. The plain-http name
  should redirect to https: the session cookie is `Secure` and wouldn't stick over http.
- **A root is one filesystem** (unless `cross_mounts = true`): a mount inside a root is reported, not walked, so a
  plugged-in disk or an opened encrypted folder under a root is never scanned by accident; what was under the mount
  point isn't reported gone. Bind mounts of the same filesystem aren't detected (same device number).
- **Copies are physical:** distinct (host, device, inode). Hard links are paths of one copy: they reclaim nothing in
  `dupes`, count once in `backed-up` (which also shows how many snapshots hold the version) and once in folder sizes.
- **Linking same-disk duplicates** is designed (DESIGN.md "Planned"), not built: opt-in per root, settled content
  only, same owner, verified and atomic, the replaced inode to trash by default.
