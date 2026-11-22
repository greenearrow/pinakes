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
- **The CLI and the API** (2026-11-13). One API, in `pinakes-web`, in front of every person-facing function, and
  one way to authenticate; `pinakes` becomes its client and runs on any machine. Agents' batches stay on their forced
  SSH keys and server maintenance stays a local command: the ingest role bypasses row-level security and doesn't
  belong in the web process. "No secrets on the clients" meant database credentials: a client may hold a revocable
  token, at home in `~/.config/pinakes/token` or in a folder for that folder. `--as` stays, but asks for the other
  person's secret and never adds their access to the caller's. Group tokens act as a group: groups own much of a
  shared store's content. Ops tokens are their own kind, scoped to the operator role; admin tokens get every function
  but still step up for other people's records. Reviewing and tagging work from inside a folder, so the API writes from
  the start. Every action is a subcommand, flags only modify: `pinakes releases` replaces `pinakes --versions`, and
  a site's deploy checks change with it.

- **The scrub** (2026-11-16). Every file is read again and its hash checked over a period, in rotation, not by
  random sampling, so each file has a known longest time unchecked. The budget is per filesystem, as one number,
  `days` for a full pass, default 30 (about 3.3 % a night). The agent writes the file of numbers itself from the
  filesystems under its roots and the person edits it; a published pinakes has to work for sites that never open
  it. A changed hash with an unchanged mtime is its own kind of change, not an edit.
- **The MCP server** (2026-11-21). The assistant is meant to be the main way to use pinakes; the command line and
  the web UI show what was done. So its tokens may have the review and tag scopes, not read alone: the catalog isn't
  the file store, and with every write kept with the value before and undoable (ROADMAP 62), a wrong one is
  recoverable. Writes ask first, a preview then an apply, since a local model makes more mistakes with tools.
  Streamable HTTP behind the proxy, chosen for visibility over ease: one place where it runs, and a token per
  connection, so a chat app shared by a household acts as each person; the audit is the API's either way. Answers
  are paged with counts, and making them fast is the server's job (ROADMAP 61). Once the operation queue exists, an
  assistant may request a change on disk only to a file a backup holds.

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
- **Niceness, I/O class and staying awake** are the systemd unit's and the site's (`Nice=`, `IOSchedulingClass=`;
  `systemd-inhibit`, or a busy check that whatever suspends the machine asks first), not the agent's, which only
  checks `only_on_ac` and `busy_command`.
- **Batches** are gzip-compressed JSON lines with a header line (host, sequence number, root, scan id, whether the scan
  completed). The agent deletes a batch only after the ingester acknowledges its sequence number.
- **Batch sequence numbers** are reserved and committed before a batch is written, so a crash leaves a gap, never a
  reused number. The ingester applies a host's batches in increasing order. A number it has seen is acknowledged
  only if it is the same batch sent again (the same header, kept with each number applied); another batch of that
  number is refused, never swallowed: the agent's state is new or restored (a new machine taking over a host).
  Check-in answers the last number applied and the agent renumbers what it holds to follow it, saying so; the
  server keeps when it happened (`pinakes --versions`, `/health`). `pinakes-agent renumber --after N` does the same
  by hand, for an agent that doesn't check in.
- **Only changes are sent.** A completed scan tells the ingester that everything it didn't report gone is still
  there. `pinakes-agent scan --full` resends every record, for after the database is restored from a backup or a
  new machine takes over a host. A scan full from start to end says so, and the ingester retires every file of the
  root it has that the scan didn't send (last seen before the scan's first batch), except under a path the scan
  reported an error for; most of a root only with `--accept-gone`, as the agent's own guard. A root the host no
  longer reports at all is retired by `pinakes-ingest retire-root LABEL`.
- **A root the host no longer reports is noticed from its batches (ROADMAP 46).** Every batch names all the agent's
  roots, so the server learns the root set on either transport (check-in runs only over ssh) and from a scrub as
  from a scan; a root left out is marked, not retired, because a disk that was only unmounted for a while comes back
  named, and retiring is a decision. Root labels stay out of `/health` (no sign-in) and `pinakes releases` (ops
  tokens name no root): both give a count, and `pinakes-ingest totals` on the server names the roots. No machine id
  is compared: a new machine with the same roots needs nothing that `scan --full` doesn't already do, and one with
  fewer is caught by its roots. One agent per host name is assumed, as the sequence numbers already assume it.
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
  `[web]` is the web UI's (`pinakes_app`, under it); the CLI used it too, with `--as NAME`, until it became the
  API's client (ROADMAP 35).
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
  database 584 MB (about 1.5 KB a file, indexes included). The ingester did a few round trips per record then;
  completing a scan and matching moves have since gone to bulk (below).
- **Completing a scan works in bulk, and moves are matched by an index** (ROADMAP 1). On the board, the batch
  completing a first scan of ~340k files ran past the agent's 10-minute send timeout: completing worked per file (a
  history row and 5-7 lineage queries each, about 2M round trips). Now the new files' history is one statement, and
  lineage runs in rounds of 2000 files with a handful of queries each (chunk sharing still per chunked file);
  `TestLineageRounds` proves rounds of 3 and 2000 give the same catalog as rounds of 1. Matching a scan's gone paths
  against its new ones was one pass over the new files per gone path, so a reorganisation (42k gone, 37k new) never
  finished; `TestMovesSameAsBefore` finds the same moves as the old code on 12 random trees. On a desktop
  (i7-12700KF, PostgreSQL 16 on a local socket, synthetic 300k files): that batch 68.7 s before, 18.7 s after; an
  ordinary batch of 5000 files 1.3 s; 40k gone and 37k new matched in about 5 s.
- **Measured on a 4+4-core ARM board (Cortex-A76 and A55, 8 GB, PostgreSQL 18), real batches:** over 140 batches a
  5000-record batch took about 6-10 s from one to the next, transfer included (430-820 records a second over
  back-to-back stretches; the longest gap 35.7 s), far inside the agent's send timeout. Over 202 batches from the
  backup server's first ingest the ingester's peak RSS was 65 MB, mean 52 MB, none failed. So the per-record queries
  of ordinary batches stay per record.
- **`/health` answers 503 for a stale host, not only for a database that's down.** Most monitors check the status
  code alone, and a host that stopped reporting is what it is for; the body says which. Its newest batch comes from
  `ingested`, which `pinakes_app` may now read (host, sequence, time, record count: no names): an agent that keeps
  sending but never completes a scan, as the first large scan did, shows a recent batch and an old scan.
  A catalog built before this needs `GRANT SELECT ON pinakes.ingested TO pinakes_app;` once, as the schema's owner.
- **A review marks a history row** (ROADMAP 32), so a later change to the same file is a new row, unreviewed. Only
  gone files and moves are marked: new and changed files need no restoring. The web role can't write the table;
  `mark_changes()` (SECURITY DEFINER) skips what the person may not mark (not an owner or co-owner of the file, and
  no step-up) and returns how many it marked, and an administrator's marks of other people's changes are audited for
  their owners. A bulk mark takes only unreviewed changes, so a *restore* already set isn't overwritten; marks are
  cleared only row by row. A restore is *back*, and leaves the list, once its last content is present again
  anywhere in the file's root (a move: at its old path), whenever that happened, and whoever put it there: the
  content is what was missing. "Still elsewhere" for a gone file counts copies in primary and drop roots (a disk move
  or a copy kept somewhere); backups are counted apart, as they are what a restore comes from. A catalog built
  before this needs `pinakes/upgrades/review-marks.sql` once, as the schema's owner; a test checks it creates what
  `schema.sql` does.
- **"Today" is the UTC date** (`queries.today()`), in the changes windows, the bulk form's "seen up to" and `tidy`:
  a scan's `seen_on` is the UTC date of its start (the agent writes `started` in UTC). With the server's local date,
  a server west of UTC marked nothing in bulk in its evenings, as the form's date was the day before the scan's, and
  the last-N-days window was a day off. The tests check it under UTC-12 and UTC+14, so a run at any hour sees it.
- **The walk check reports what changed since the scan.** On a live disk a plain count can't tell "changed since
  the scan" from "the scan missed it": the first server's check by hand came out higher than the catalog on two
  roots, and only counting files whose mtime or ctime is after the last complete scan's *start* (a file changed
  mid-scan, after its folder was walked, is missed too) showed that was all. So `pinakes-agent check` prints that
  count and a verdict beside the disk's and the state's totals. It compares with the agent's state, not the
  catalog, which the agent can't read; `pinakes-ingest totals` (the ingest role, every owner's files, totals only)
  is the other half, and the state and the catalog should agree exactly when no scan is unfinished.
- **A batch whose sender gave up is stopped.** The forced ingester reads its whole batch before applying it, so a
  closed stdin says nothing; a watchdog thread instead watches stdout, which reports an error once sshd closes it
  (the agent's ssh exited, as it does when its send times out). It then cancels the running statement and exits 3;
  the connection closing rolls the transaction back, whether a statement was running or the session sat idle in
  it. `[ingest] max_batch_time` (default 1h, also for `inbox`) is the backstop for a sender sshd hasn't noticed is
  gone (a dropped network, until its `ClientAliveInterval` fires). A batch committed just before the hang-up is
  applied and not acknowledged: the agent sends it again and it is acknowledged as a duplicate.
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
- **Only another disk makes a file safe** (ROADMAP 5): `only-here` and `safe-to-delete` count a copy only on another
  host or another device of the same host, and show the copies on the file's own disk apart (`same_disk`); a hard
  link of the file is no copy. The first deployment had its backup roots on the same disk as their source. A device
  is the filesystem's number (`st_dev`), not the physical disk: two partitions of one disk, or two btrfs subvolumes,
  look like two disks, and so count as safe. A device the catalog doesn't know counts as the same disk.
- **The test matrix runs each version once** (ROADMAP 27): each Python and each PostgreSQL in one run, paired oldest
  with oldest, the shorter list repeated (6 Pythons and 4 PostgreSQL: 6 runs). Python and PostgreSQL meet only
  through psycopg's protocol, so pairs add little; the 24-pair `--matrix full` is kept but no longer run routinely,
  not even before a release. Each run has its own cluster on a Unix socket in its own folder, so runs go side by side
  (`--jobs`); 8 at once take under two minutes on the desktop. A test that compared the bulk move matching with the
  old per-file one built its tree twice: a freed inode reused by a file written just after made a gone and a new
  path "the same inode" in one build only, under load. It now scans once and replays the same batches into both.
- **`--wheel` builds from a clean copy of the tree** (what git tracks, or would): an editable install leaves
  `pinakes.egg-info`, whose file list setuptools trusts, and with it a wheel shipped the upgrade files even with
  them taken out of the package data. The tests run from a copy of `tests/` and find the upgrade files through the
  installed package, so a file missing from a release fails a test.
- **Protection follows the inode** (ROADMAP 6): a file in any root whose inode has another link under one of the
  same agent's protected roots is protected there too. The agent finds such links by walking its protected roots
  (names and inodes only, excludes ignored, since an excluded file is still under the root) once per scan, and only
  when the scan meets a file with more than one link. Its record says `protected_link`: no archive listing, and chunks
  only if both roots make them; the catalog drops a listing it kept from before the link, and the file's page says
  so. A folder in a protected root the agent can't list makes every multi-link file on that filesystem protected,
  as the agent can't tell. A link made or removed changes the record, so the next scan sends it, in a backup root
  too. A plain copy is not covered: it is a new file, under its own root's rules. Older catalogs:
  `upgrades/protected-links.sql`, which also marks the links the catalog already knows.
- **A symlink is tied to where it leads** (ROADMAP 7): the agent resolves its target one name at a time, like the
  kernel (`..` after a link is the link's target's parent), with `lstat` only inside its own roots and on their own
  filesystem: a target outside every root (or reached only through one) is stored as text, not looked up, so a
  link to an automount or a hung network share costs nothing. Dangling is true when a name is missing, under a
  file, or the chain passes 40 links; unknown when a lookup is refused or reaches a mount the root doesn't cross.
  Kept in the agent's state with the target text, so a target appearing or going resends the link, and `--full`
  sends a symlink as one. Moves: a symlink is small, so a freed inode is soon another link's; the same inode counts
  only if it still leads to the same place. Otherwise the same resolved target (or the same absolute text, outside
  the roots) and the same name is strong, a single candidate likely, several not guessed. A relative link outside the
  roots reads differently from another folder, so it isn't matched by text. `only-here` and `safe-to-delete` leave
  symlinks out (they listed every one as having no copy); the links into a folder are listed beside the answer
  (the web shows the first 200 and the total; the CLI's `--json` gives `not_safe` and `links_into`). Only links
  the person may see, and only from the same agent: a link on another machine to an NFS mount of the folder isn't
  known as one. Older catalogs: `upgrades/symlink-targets.sql`, after `protected-links.sql`.
- **Paging:** every list in the web UI is paged (50, 100, 250 or 500 a page, 100 by default); a query selects its
  total with a window count, so a page says "41-80 of 312" without a second query. Page links keep the page's other
  arguments; a bad page or size falls back to the first page at the default size. The API and the CLI page too
  (ROADMAP 61, below).
- **Sorting is in SQL, not in the browser:** a page holds only part of a list, so a script (DataTables and the like)
  would sort that part. Each column header has a ▲ and a ▼ link (`sort`, `dir`; `copies_sort` and the like for
  the lists on a file's page), so either direction is one click and one query, not a toggle; the current one is
  marked. Each query maps the column names it allows to SQL, a name outside that list is the default order,
  and the default order follows the chosen column, ending in a unique key, so pages neither overlap nor skip. NULLs
  sort last both ways. A new sort starts at page 1; the pager keeps it. Row-level security is untouched: the sort
  only orders the rows a person already sees. No JavaScript; one, if ever needed, goes in `static/`, no CDN.
- **Backup roots record the present only** (ROADMAP 28): a gone path's row is deleted, no history rows, no move
  matching; the agent ignores link-count and ctime changes there (a uid or mtime change is still sent). Versions and
  `backed-up` come from the source's history and the copies' content. A backup root's own "what was in snapshot X
  last month" is the backup tool's question, not the catalog's.
- **A similar name needs a second signal** (ROADMAP 29), any one of: sizes within `name_size_within` (5%) of each
  other, the same parent folder name (compared case-insensitively; a file at the top of a root has none), the other
  file changed, moved or went within `name_window_days` (7) of this one first appearing, or a drop root on either
  side. The edge's evidence names the signal ("similar name, same folder name").
- **The folder name counts only when it is rare:** held by at most `name_folder_max` (5) folders (distinct root and
  parent path, present files, backup roots left out since every snapshot repeats them). Found by sampling the first
  deployment's 39,832 "same folder name" edges: names held by under about five folders (a trip's photos) were real
  copies, names held by fifty or more (a game's `region/`, `data/`, `html/`) were structure. The counts are one
  statement once a lineage pass (1.6 s on 450k files, desktop). A camera's `100CANON/` on two cards is still rare
  enough to link; a person rejects that.
- **A similar size counts only for a rare name:** at most `name_size_namesakes` (5) present files outside backup
  roots have the name. After the folder rule was tightened, "similar size" held 33,288 edges and a sample of 30 was
  18 unrelated: fixed names inside software packages (`DESCRIPTION`, `NAMESPACE`, `.meta`), per-folder files and
  camera counters; 10,454 of them on names more than 100 files have. Camera counters in two folders of similar size
  still link; telling those apart needs dates from the files' metadata (METADATA.md).
- **An AppleDouble `._` prefix stays in the name key:** `._photo.jpg` holds `photo.jpg`'s attributes and is not a
  version of it.
- **A minus sign before a number is kept in a name key** (at the start of a stem or after a separator): it folded to
  a separator, so a game's region `r.-1.1` matched `r.1.1`; 8 of 12 unrelated edges in that sample. `tidy` recomputes
  every stored name key by the current patterns.
- **`pinakes-ingest tidy`** brings a catalog built by an older release in line: backup roots' history rows, gone rows
  and lineage edges go; name keys are recomputed; every undecided edge by name is worked out again (kept with the signal named, moved to
  another source, or removed). Decided edges stay. `--dry-run` counts and changes nothing. It is idempotent.
- **Empty files are not duplicates and have no lineage:** every empty file has the same hash, takes no space and
  reclaims nothing, so `dupes` leaves them out (the first deployment's top row by copies was 4,467 empty game data
  files), and lineage neither starts nor ends at one. `tidy` removes undecided edges to or from an empty file. A file's
  own page still lists where else its content is, empty or not.
- **The schema registry's indexes are made by a function, not by hand** (ROADMAP 12). The ingester owns no table, so
  it can't make an index on `metadata`; `enroll_metadata_indexes()` is the schema owner's (SECURITY DEFINER) and
  executable by `pinakes_ingest` only. It takes `[schema, field, kind]` names, checks them against the same patterns
  the registry does, and builds each index from one of seven fixed expressions, so no SQL passes through it; it
  touches only `md_*` indexes on `metadata`. Setup can then keep the indexes in step with the schemas, a site's
  included, with no superuser step for each new schema. Building an index locks the table against writes while it
  runs: setup, not a batch, does it. Older catalogs: `upgrades/metadata-indexes.sql`, once, as the owner.
- **An index is named by what it indexes** (`md_SCHEMA_FIELD_KIND`, the kind standing for the expression: `eq`,
  `trgm`, `num`, `date`, `list`, `ref`, `geo`), so a field whose type or index changes gets a new index and the
  old one is dropped. Schema names have no underscore and are at most 20 characters, field names at most 30, so names
  stay unique and within PostgreSQL's 63.
- **Dates are ISO 8601 text**, indexed as text: a cast to `timestamptz` isn't immutable (it depends on the session's
  time zone), so it can't be indexed, and partial dates ("2019") are common in tags. Times are stored in UTC with
  `Z`, so text order is time order. A trigram index on a list of text covers its JSON text, which is enough for
  "creator contains". Places use PostgreSQL's own `point` and GiST: no PostGIS.
- **Only what the registry needs now is in the form:** sidecar patterns and pairing rules come with ROADMAP 14 and
  are refused as unknown keys until then; `[extractor]` is checked (a dotted module name, a list of packages) and
  imported by the agent (ROADMAP 13).
- **Extracted metadata rides on the file record** (batch format 2): `"meta": {"exif": {"v": 1, "vals": {...}}}`, or
  `{"v": 1, "error": "..."}` when the extractor failed, so a broken file isn't read again until the schema's version
  changes. Extraction reads the file when the record is built, and the ingester already has the content there; a
  record of its own would only add sending metadata without the file, which a resent file record covers. The agent
  doesn't send `source`: the ingester sets `embedded`. Format 1 is still accepted; an older ingester refuses 2, so the
  server is upgraded first.
- **The agent keeps what it extracted, not the values:** `meta_v` in its state is the schemas and versions read for
  a file. An unchanged file whose versions differ from the registry's (a schema's version went up, a root's
  `metadata` changed) is sent again with only `meta` new, without rehashing; one content is read once per agent (a
  hard link, a copy in another folder or root); `--full` reads everything again, as the server lost it.
- **What the ingester says about an applied batch reaches the agent's journal.** Over ssh the agent kept the
  forced command's stderr only for a refused batch, so a warning about metadata left out was lost on success. Now
  each line is logged after its batch (`batch N: ingest said: ...`), the last 4,000 characters of it, where a
  summary is. The directory transport's ingester logs to its own journal.
- **The ingester trusts no agent's metadata:** every value is checked against the registry by the same function the
  agent uses (`extract.check_vals`: the schema's own fields and types, a schema with an extractor, at most the
  catalog's version, text, list and size caps; no `person` or `file` values, which only the catalog names). What
  fails is left out and reported on stderr, not refused: a batch that can never apply would stop the host's queue.
  `meta` on a protected root or a protected link is refused, as the agent never sends it there; a protected link
  also removes what was extracted from that content before. Values replace a content's only from a newer version,
  so the same bytes on another machine rewrite nothing and a later agent can't overwrite what is known. Each row
  records the version and the host that sent it (`sent_by`: not `host_id`, which queries join `hosts` by).
- **Sensitive fields are kept in rows of their own, for owners only** (ROADMAP 16, its first part). Row-level
  security works on rows, not on keys inside a JSON value, so the ingester splits each schema's values: the fields
  in one row, the sensitive ones (`metadata.sensitive`) in another. That row is visible only through
  `sensitive_visible()`: to the owner or a co-owner of a file with that content, or to an administrator in a
  step-up; readers and annotators of a shared folder see the rest of a photo's metadata, not where it was taken or
  who is in it. Someone who owns a copy of the same bytes sees them too: they hold the file. The schemas' indexes
  cover both rows, so a search by place returns only what the person may see. Sharing sensitive fields with a
  reader, and person-entered metadata, came with 16's last part (below). Until this, the agent kept them (exif and xmp
  version 1); version 2 sends them, so every photo is read once more. Older catalogs:
  `upgrades/metadata-sensitive.sql`, after `metadata-extracted.sql`.
- **EXIF is read with the standard library** (`pinakes/exif.py`), not Pillow or exifread: the agent stays dependency
  free, and a file's bytes are parsed by bounded Python (offsets and counts checked against the segment, at most
  1 MiB of markers read, no image decoded), not by a C imaging library. JPEG only so far. `taken` is UTC with `Z`
  when the camera recorded its offset (EXIF 2.31's `OffsetTimeOriginal`), else the camera's local time without a
  zone, which keeps text order within one camera's photos but not across zones.
- **XMP is read with expat directly, and refuses what XML can ask for** (`pinakes/xmp.py`): a DOCTYPE, an entity
  declaration or an external entity refuses the packet before anything is built (billion laughs, external
  entities), elements nest at most 32 deep, and a packet is at most one APP1 segment (64 KiB). Every RDF form is
  read (attributes or elements, Bag/Seq/Alt, a language alternative's x-default, structures in all three spellings),
  as software writes all of them. Extended XMP (a packet over several segments) isn't read yet. Pillow 10.2 confirmed
  the generated segments' framing but can't write XMP, so the RDF reading is tested on packets written from the
  spec, not from another program.
- **People shown and place names are sensitive in XMP**, like GPS in EXIF: a city or a person's name tells as much
  as a position. They are kept with GPS, for owners only.
- **A new extractor reads every photo once more:** a file's `meta_v` lists the schemas read, so adding one makes
  every file it applies to differ; the file is sent again with all its schemas, without rehashing.
- **MIME types by name, from the standard library's own table** (`mimetypes.MimeTypes(filenames=())`), not the
  machine's `/etc/mime.types`, so the same files get the same extractors on every machine. An extractor checks the
  bytes itself (a `.jpg` that isn't a JPEG is an error entry).
- **What each extractor made of a file is kept, as a reason code (ROADMAP 44).** The first real run left 717 JPEGs
  with no EXIF row and no way to tell why: the agent sent a failure's text and the ingester dropped it. Now the
  agent sends, to a server of protocol 4, one of four outcomes per schema (found, nothing, refused, skipped) and, for
  the last two, a code from a fixed list (`extract.REFUSALS`, `extract.SKIPS`, checked again by the ingester and by
  the table's CHECK), never the text: an exception's message can quote the file's bytes. The catalog keeps the
  latest report per content and schema (`extractions`) at the newest version reported, except that a skip never
  replaces a run (another machine without the package says nothing about the bytes); a refusal leaves the values
  already known in place, as a failure always did. An older agent's `error` is not taken as an outcome.
- **A JPEG that ends before its image data is refused as truncated,** where the reader used to keep what it had
  read: a cut-short file returning its first segments' values, or nothing, looked like a photo without EXIF, which
  is the question 44 is there to answer. Its values from an earlier reading stay, at the same version.
- **Outcomes hide sensitive-only values as metadata does.** "Found" on a photo whose only values are its GPS would
  tell a reader there is a position they can't see. Such an outcome is two rows, as its values are: a sensitive
  one, "found", for those `sensitive_visible()` lets see it, and the other, "nothing"; `extraction_outcomes`
  shows each person one, so a reader sees what they would of a photo without any. The operator's counts take the
  true one, without names.
- **Every photo is read once more when outcomes start.** The agent's `meta_v` takes another form once its server
  is at protocol 4 (`[2, {"exif": 2}]`), so what was read before is read again, headers only and without rehashing,
  and its outcomes sent; until then nothing changes, so either side may be updated first. The alternative,
  outcomes only for files read from now on, would never answer for the 717.
- **A requirement is checked by its installed distribution's version** (`importlib.metadata`), `>=` only; any other
  specifier counts as not met. A missing one turns that extractor off (`Extractors.off` says why), not the scan.
- **Metadata on a file's page, and find by common fields** (ROADMAP 16, showing it). The page lists each schema's
  fields in the schema's order, each value with its source, version and date; when sources disagree all are shown,
  person first, then sidecar, embedded, derived. A sensitive field is tagged as such. Someone who may not see a
  file's sensitive fields gets a note naming the shown schemas' sensitive fields, the same whether this file has
  any or not, so the note gives nothing away. An administrator's step-up that showed sensitive rows is audited as
  `file N, with sensitive metadata`, so the owner sees that the place or people were shown too. Find takes a name,
  "made by" (a substring of `creator`) and "dated" from and to (a year, a month or a day, both ends inclusive).
  The common fields are not stored as rows of their own: a search reads every schema's mapped field at query time,
  one condition per schema, its names written as literals from the registry so that each part uses that schema's
  partial index. A file matches by its content's metadata or its own. The search runs under the same row-level
  security, so a sensitive field (if a site maps one onto a common field) finds nothing for a reader.
- **Entering metadata, and sharing a file's sensitive fields** (ROADMAP 16, its last part). A person's values are
  the file's own (`metadata.file_id`, source `person`, `author`), so they follow it through moves and not to other
  copies, and are their author's: each author has their own row per file and schema (and a second for its sensitive
  fields, kept apart as extracted ones are), replaced whole by `set_file_metadata()`, and nobody else's are touched.
  The owner, a co-owner or an annotator (the role that exists for it) enters; a reader can't, and a step-up gives no
  right to, as entering is not looking. The application checks the values against the registry with the same
  `extract.check_vals` the ingester uses (a person or a file reference is not typed in), the database checks who,
  the schema's name and a size cap; the web role still has no write on the table. Entering on another person's
  file is audited for its owners and co-owners, as a lineage decision is. The author sees their own sensitive
  values even where they may not see the file's other sensitive fields. Sharing is per file: its owner or a
  co-owner shares its sensitive fields with one of its readers or annotators (`share_sensitive()`), who then sees
  the file's sensitive values and its content's, as an owner does; another file in the same shared folder keeps
  its own. It shares no file: only with a person the file's enrollments already let see it, and a share counts only
  while they still do. Who has them is shown to the owners only (`sensitive_sharing()`; the table is read through
  that function and written through the other), and each share and its end is audited for the person and the other
  owners. Per file, not per folder, because enrollments are still seeded from the server's config (ROADMAP 8); a
  folder's share can come with enrolling. Sharing is web only, refused under every token; entering opened to a
  person's token with the `tag` scope with `pinakes tag` (ROADMAP 37, below). Which schemas a file's form offers follows its name's MIME type, as the agent picks extractors
  (`extract.mime_of`), and the common schema fits every file. Older catalogs: `upgrades/person-metadata.sql`.
- **Hidden files** are those with a dot at the start of their name or of a folder's above them, or with the
  Windows hidden attribute, set on them or on a folder above, which Samba keeps in the `user.DOSATTRIB` extended
  attribute (`pinakes/hidden.py` reads every form Samba writes: the old hex text, and the NDR-encoded versions 1 to
  5 with their 0xFFFF compat form; an attribute not marked valid counts as none). Reading it is one extended
  attribute per file and per folder, as stat is: no content, so protected roots get it too. The agent sends
  `"hidden": true` on the file record (still batch format 2: an ingester that doesn't know it ignores it) and keeps
  it in its state, so a change of attribute alone resends the record without rehashing; an older agent's state
  sends its hidden files once more. The ingester also marks a dot-name itself, from an agent that doesn't say. On
  the web, browse and find leave hidden files out until a person shows them, a choice kept for the session; browse
  says how many it left out (of those the person may see). Reports (only here, safe to delete, duplicates, changes)
  always count them: deleting a folder deletes its hidden files too. Older catalogs: `upgrades/hidden-files.sql`,
  after `symlink-targets.sql`; it marks the dot-names, and the agents' next scans send the attribute.
- **A state from before the agent kept a file's type is read as files** (found by the first deployment's first
  metadata pass: most photos weren't read). Extraction asks for a regular file, and rows saved before `27650a5` have
  no type, so an unchanged photo was never extracted, even with `--full`. Opening such a state now sets `t =
  'file'` once on every row with a hash (a symlink then had none). A row without one is an old symlink, which is
  sent again anyway as its type now differs, or a file not hashed, from which nothing is read. The other columns
  added later (`protected_link`, `dangling`, `meta_v`, `hidden`) read NULL as false or "not extracted", which is
  right for an old row. Checked on a state written by the agent from before `27650a5`.
- **Releases are numbered, and agents check in** (`RELEASES.toml`, `pinakes/compat.py`). A release is the commit
  tagged `release-N`, cut deliberately when the owner says so, never implied by a commit: an entry without its tag
  is being prepared, and `tools/latest-release` reads only tagged ones, never HEAD. Its entry says which roles it changes (`server`, `agent`, `cli`), its protocol, the oldest
  agent and server it works with, and the upgrade files it needs. A tag, not a `commit` field, because the entry and
  the numbers in `compat.py` land in the commit being cut, which can't name its own hash. One protocol number covers
  the batch fields, the agent's state and the schema together: each side needs only the other's oldest number, and
  a server-only schema change doesn't stop agents, since their `MIN_SERVER_PROTOCOL` stays. The newest release
  records a fingerprint of all three; the tests fail when the code no longer matches it and the protocol is the
  same, and when two releases of one protocol disagree, so a cut release's protocol can't be reused for a new
  format. The batch fields are declared in `compat.BATCH_FIELDS` and a scan of a generated tree may write no other,
  so a new field changes the fingerprint. Releases 1 and 2 are the two live when releases began (the first
  deployment's server at `3522719`, its agents at `d753d9f`), so the first check shows no drift; both are protocol 0:
  nothing was declared. Release 1's `upgrade_sql` is every upgrade before it, for an older catalog. Release 3 is this
  check-in, cut 2026-11-12. An agent checks in at the
  start of `run` and `send` through its forced key (`ssh ... hello`, which sshd hands the ingester as
  `SSH_ORIGINAL_COMMAND`: no change to `authorized_keys`). An ingester from before check-in reads the request as a
  batch and refuses it as "not gzip": that answer means a server of protocol 0, which release 3's agents accept.
  Locked (the server too old, the agent too old, or the catalog missing an upgrade this server needs), the agent
  scans and keeps its batches, sends nothing, writes one line naming both sides and which must update, and exits 4;
  the next run checks again. A server it can't reach is held for as before (exit 1). The ingester refuses a batch
  outside its range on its own too, so an agent that skips the check-in still can't send; the refusal goes to the
  agent, the system log and `checkins`, which `pinakes --versions` reads with each agent's last check-in and the
  protocol its last batch declared (0: an agent before check-in). The directory transport doesn't check in: it is
  an agent on the server, from the same install.
- **A release also has a semantic version** (from release 13, 0.13.0). The id stays the number agents, servers and
  `tools/latest-release` compare (an int in check-in, in each batch's header and in `checkins`), so adding the
  version changes no protocol; the version is for people and packages: `RELEASES.toml`'s `version`, which
  `pinakes.__version__` and the package's version (read from it by `pyproject.toml`) follow, and a `vVERSION` tag
  beside `release-N`. MAJOR when something that worked stops working until a person does more than update (an
  oldest protocol raised, a command, call, page or setting changed or removed); MINOR when anything is added;
  PATCH for fixes only. Before 1.0.0, while publishing isn't decided, what would raise MAJOR raises MINOR. Release
  13 is 0.13.0 so the first version reads next to the release it is; after that the two move apart (a release of
  fixes only is the next PATCH). Releases 1 to 12 have none: a version given afterwards would claim a rule they
  weren't cut under.
- **The API and person tokens (ROADMAP 34).** A token's secret is 32 random bytes, kept as its SHA-256: a slow hash
  like the passwords' guards a guessable secret, and this one isn't. Making one asks for the current password again,
  so a borrowed web session can't mint itself a lasting key. The database ties a call to its token
  (`begin_token_call()`) and records every call as an `api` audit entry, which the person sees on their access page;
  a refused token isn't recorded (it names nobody) but counts toward the address's limit, like a failed sign-in.
  The root limit is in the files policy, evaluated once per query, so every query and report follows it without
  change; a token with no list sees every root but the protected ones, those added later included. The API is GET
  only until review and tag commands need writing (37). Its schema went into release 5, which wasn't cut yet, rather
  than a new protocol.
- **`pinakes` as the API's client (ROADMAP 35).** Standard library only, so the bare package is the CLI on any
  machine, Python 3.10 included. A token file is refused, not skipped, when it isn't a plain file of the user's own
  readable by them alone: falling through to another token would answer as someone else without saying so, and a
  token file planted by someone else in a folder would make the CLI answer as them. The address must be https, or
  http to this machine only, so the token never crosses the network in the clear. `--as` goes until 36 makes it
  ask for a secret. `pinakes --versions` stays a server-local command (no person, no token, the database through
  `server.toml`) until ops tokens (39), so a site's deploy checks change once, when `pinakes releases` replaces it.
  `backups` asks the API for the host's roots with their paths there and works out the folder's place locally.
- **Commands from inside a folder (ROADMAP 33).** One rule for every command: a path that exists here is local,
  anything else is `ROOT:PATH`, none is the current folder. File commands refuse a folder; folder reports take a
  file and answer for it, because a file matched as a folder has nothing under it, and an empty answer from
  `safe-to-delete` means safe: the web report did that too, and now doesn't. `changes` with no folder outside
  every root keeps its old meaning, everything, and says so in its first line; `--host` stays its filter there, so
  a folder is found by this machine's configured name. Bare `pinakes` outside a root, or before a token is set up,
  prints usage and the reason, and exits 1.
- **`--as` (ROADMAP 36).** One prompt takes either a token of the person's (it begins `pinakes_`) or their
  password; a password then asks for the second-factor code, which the server checks only if the person has one,
  so the answer never tells a guesser that the password alone was right. The session is a token like any other
  (`cli_session`), so row-level security, the token's roots, no step-up and the call log all hold without new code;
  it is read only, for every root but the protected ones, because a person signing in for someone else's view at a
  shell shouldn't carry their protected roots along. It lasts 10 minutes and the command revokes it at its end; if
  the command dies first, the minutes run out. The sign-in is a POST; the queries stay GET.
- **Reviewing from a folder (ROADMAP 37).** `pinakes review` shows what it would mark and marks exactly those, by
  their ids, once the person says yes: new changes arriving between the two aren't swept in, and nothing is marked
  unseen. Without a terminal it marks only with `--yes`. `mark_changes()` checks the token's scope and roots itself,
  because it reads history and files as the schema's owner, where the files policy doesn't apply; the test was
  checked to fail without it (two changes outside the token's roots were marked). Its new body ships in
  `api-tokens.sql` with the rest of release 5.
- **Tagging from a folder (ROADMAP 37).** A tag is an item of the person's own `dc.subject` and a note is their
  `dc.description`: the common schema's keywords and description, the same values the file page enters, so the CLI
  and the web never disagree about what a file's tags are, and `meta dc.subject=X` finds them. `pinakes tag` adds and
  removes single tags rather than setting the list, so tagging a folder keeps what each file had; a tag has no comma,
  as the web form takes a list's items separated by commas. Like `pinakes review` it shows the files, asks, and sends
  exactly the ids it showed; a file named alone is tagged at once, as there is nothing to sweep in. It sends only the
  files the person owns, co-owns or annotates, says how many it leaves alone, and the API skips the rest again;
  `set_file_metadata()` checks the token's `tag` scope itself, and its roots through `my_file_role()`, so a call that
  forgot either is still refused. A group token doesn't tag: an entered value has a person as its author and is
  theirs alone to change, and a group has no person to be. Values other than tags and notes stay on the file page.
- **Ops tokens and `pinakes releases` (ROADMAP 39).** An ops token is a token of its own kind (`tokens.kind`), made
  by an operator, scope `ops` alone: the database sets no person for its calls, so even a call that forgot its
  scope check would see no file, and it answers only `releases`, `stale` and `whoami` (a test calls every route).
  Its calls go on its maker's record, so the operator sees what their deploy asked. `pinakes --versions` no longer
  reads the database: it says to use `pinakes releases`, so a deploy check that wasn't updated fails loudly, not
  quietly. On the catalog server the client config can name `http://127.0.0.1`. `releases` needs the web service
  running and the catalog upgraded first (`api-tokens.sql`), which the release order already asks.
- **Group tokens (ROADMAP 38).** "Made and revoked by the group's co-owners": groups have no co-owners of their own
  (a group is a list of members in `server.toml`), and a group that owns a folder makes every member an owner of it,
  so a group token is made by any member, seen by every member and revocable by any of them. It stops working when its
  maker leaves the group, so a departing member can't keep the group's view; another member's tokens go on. It acts
  as no person: the database finds the group from the token itself (`current_group()`), and `visible_acls()` reads
  `acl_groups`, the groups each ACL names with the group's own role, so a group token sees a folder the household
  owns or reads and never a member's own, and its view doesn't change when members come and go. A mark is the
  group's (`review_marks.marked_by_group`), only where the group is the owner or a co-owner; the audit entry names
  the token and its maker and goes to every member, as do its calls. Its sensitive metadata follows the owner's rule,
  by the group's role. It doesn't tag (ROADMAP 37): an entered value is a person's.
- **The operator page and a disk's loss (ROADMAP 10, 42).** A disk is a device of a host as the agent saw it
  (`st_dev`): a root never crosses a filesystem, so a disk is one or more roots. Losing it loses the files with no
  readable copy on another host or another device of that host, counted as only-here counts them; the same per host is
  "if this machine burned". The operator gets totals per disk and per host only, not per owner or top folder, which
  the roadmap left open: a folder's name is a path, and per-owner sizes are more than SECURITY.md's "per root" grants.
  Both are database functions an operator may call only from the web (a token, ops or not, is refused), so the web
  role's row-level security stays as it is. A person's report runs the same function under row-level security: copies
  only someone else can see don't count, so it errs toward "at risk". No API call or CLI yet.
- **Lineage decisions (ROADMAP 9).** A decision is on two files, not on one edge: "these aren't related" must hold
  when a later heuristic points the other way, or finds the same pair by other evidence (identity fields, 15, will).
  So the ingester skips a rejected pair either way round, and `decide_lineage()` covers every edge between the two.
  The person who decides is the owner or a co-owner of the later file (an edge's `to_file`): an edge says where that
  file came from, and the earlier file's owner sees the decision in their audit, not a power over it. Both files must
  be visible, since the function reads as the schema's owner, where row-level security doesn't apply. A certain edge
  (the same content) can't be decided: the hash is the fact, and rejecting it would only hide a copy. A group token
  can't decide: an edge's later file has a person or a group as owner, and keeping it to people keeps the audit
  simple; a group's files are decided from a person's token or the web. `decided_at` was added for the file page and
  the export; clearing a decision clears who and when.
- **Identity fields in lineage (ROADMAP 15).** A schema says which of its fields are identity fields and, with
  `parent`, which name another file's field: the rules are the registry's, not the ingester's, so a site's schema
  (or PDF's, later) needs no code. An identity field must be exact-indexed text and not sensitive: the lookup uses
  its index, and a link made from what only owners see would show it to others. Identity evidence ranks after the
  same content and before chunks, and like them only for a file with no line yet: a file changed in place keeps its
  own. Scan order doesn't matter: a file of an earlier scan whose parent (or earlier version) arrives now gets it as
  its source at the end of the pass, the best one of the pass, so the result doesn't depend on which file came first
  or on the rounds; a file of the same pass works it out itself. The edges are certain, so a person can't reject one
  (`decide_lineage()` decides every edge but the certain ones): software that copies one template's DocumentID into
  unrelated files would chain them with no way out. Not seen yet; if it is, either identity edges become decidable
  or a value shared by too many contents stops being evidence. Files ingested before this release are linked by
  `pinakes-ingest tidy`: each with identity metadata, never changed, whose only source is an undecided name edge or
  none, is worked out as a scan would now, and a name edge it had goes (identity outranks names; a decided edge
  stays and keeps the file out). Chunk edges aren't redone, so a file whose source is chunks keeps it.
- **Paged answers with counts (ROADMAP 61).** Every list call of the API answers one page unless asked otherwise:
  100 rows, at most 10,000 with `limit=`, and the whole list's total beside it, read from the window count each
  query already selects; a page past the end asks once more for the total alone. A total is always given, never
  only "there is more": on a generated catalog of 500,000 files every first page with its total took at most 0.9 s
  (duplicates; only-here of a whole root of 400,000 files 0.7 s), so counting was not the slow part, and a person (or an
  assistant) needs the number to know what they are looking at. What was slow had other causes, fixed where they
  were: PostgreSQL's JIT compiled short queries whose costs row-level security makes look high, and compiling took
  longer than running them (folder copies 1.5 s of 1.6 s), so the web turns JIT off on its connections; `meta`
  asked `sensitive_visible()` of every sensitive row of the schema before its own test of the value, which the
  policy's order puts last, so it now tests `m.sensitive` first (a field's values are in a row of its own
  sensitivity, and the registry knows which); folder copies built every folder of the catalog to answer for one,
  and now builds only the scope's and looks the other folders' files up by path (a scope of most of the catalog
  takes as long as before). Under row-level security only a
  leakproof comparison becomes an index condition, so a path is made before it is compared (`||` isn't leakproof;
  `=` and `~>=~` are). The CLI shows a page and says "N of TOTAL" and the next `--offset`; `--json` is the API's
  answer, rows and total. Commands that act on a whole list (review, tag, export) ask a page at a time until the
  last. Offsets, not keysets: the web already pages by them, and a person reads the first pages; an export of
  hundreds of thousands of rows asks 10,000 at a time. roots, stale, host-roots, lineage and relatives aren't paged:
  a site's roots and hosts, and one file's relatives, are short.
- **The catalog's own writes (ROADMAP 62).** An edit is one write call: everything one of `mark_changes()`,
  `decide_lineage()` or `set_file_metadata()` changed in one transaction, by one person, group and token. So a
  `pinakes review` of a folder is one edit to undo, not hundreds; `pinakes tag` of more than 1,000 files is one edit per
  1,000 (one API call each). Its items are only the values that changed, each with the value before and after: a
  mark or decision written again unchanged, or the same tags sent twice, leave nothing to undo. The functions record
  it themselves, as they already check who may write: triggers would have seen a metadata write as a delete and an
  insert, and a call's grouping only with more machinery. Nothing changes an edit after: the application only reads
  the tables, and the ingester may add but never update or delete; the items keep no foreign key, so a file's row
  going (tidy, a backup's gone files) leaves them, out of sight. An undo is an edit too, naming the one it undoes,
  and can be undone in turn. It is refused, whole, when a value it would put back over has changed since (it
  compares the value now with the edit's own, times aside) and names the newest later edit of that value; with
  `pinakes undo NEW OLD`, the newest goes first, so a run of edits undoes in one command. It puts back exactly the
  value before, another person's mark (and its time) too, and only where the person may write now, by the write's
  own rules and the token's scope of that kind: the right to undo is the right to write, not a right of its own. A
  person sees their own edits, on the web and by every token of theirs (a token limited to some roots shows only
  those roots' values), and their groups'; an undo of a group's edit by a member is the group's too, so the other
  members see it was undone. No one else, an administrator in a step-up neither: the audit already tells an owner
  who changed their records. Writes before the upgrade have no history.
- **Backup copies folded (ROADMAP 68).** `find`, `where` and `meta` in the API and `pinakes` list the copies in primary
  and drop roots first, each with `backups`, the backup copies of its content in the whole answer; a content found only
  in backup roots is listed once, as its newest snapshot, `backups` counting the others. `total` is the rows listed, so
  paging and "N of TOTAL" stay one rule, and `folded` beside it is the backup copies left out: the two add up to every
  copy, as `backups=all` (`--backups`) lists them, primary and drop rows still first. A copy is a file, not an inode:
  hard-linked snapshots of one file are each counted, since a person asking "in how many snapshots" means that. Counted
  under row-level security, so only copies the person can see. The web's find and a file's copies fold the same way,
  with a link to every copy that paging and sorting keep. A broad find costs more: a name in 378,500 files on the
  generated catalog, 0.36 s before, 0.88 s folded (windows over the whole answer), within 61's 2 s.
