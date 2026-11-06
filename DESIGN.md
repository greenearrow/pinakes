# Design

Status: design only. Nothing here is built or tested yet. Security: [SECURITY.md](SECURITY.md). Metadata:
[METADATA.md](METADATA.md).

## The problem

Files land on many machines: a storage server, a backup server, a desktop, a laptop that is mostly off, the
`Downloads` and `Pictures` folders where things get dropped "for now". Questions that come up again and again:

- Does this file exist anywhere else? Where are all the copies, and is any of them a backup?
- What on this disk or folder exists **only** here?
- Is this folder safe to delete (does every file in it have a copy somewhere that is kept)?
- What changed since last week? Where did that file go?
- Which photos were taken at this place, which books are by this author, wherever the files are?

Each answer usually means a one-off script that hashes a tree, compares, prints, and throws the result away. This
project keeps the result: a catalog of every file's path, size, times, SHA-256 and metadata across machines and the
people who own them, kept current by cheap incremental scans, with indexed queries and a web UI.

The operating system doesn't do this. Name indexes (`plocate`, GNOME localsearch, KDE Baloo) store names and sometimes
text, never hashes. Filesystem checksums (btrfs, ZFS) are per block, for integrity, and can't be queried. Backup tools
(restic, borg) hash content into chunks but answer "what was in snapshot X", not "where are all copies of this".

## Principles

- **Read-only on the files by default.** The agent opens files read-only and never writes to a scanned tree: no
  xattrs, no sidecar files, no touching of times (`O_NOATIME` where permitted). Changing files (moving, renaming,
  writing sidecars) is a separate, opt-in capability per root ("Managing files").
- **Each machine scans its own disks.** Local reads, not over a network share. A machine that is often off, or sleeps
  on demand, scans when it's awake and sends later.
- **Every file has an owner, and people see only their own** unless they share it or an administrator deliberately
  steps up, which is logged where the owner can see it ([SECURITY.md](SECURITY.md)).
- **No secrets on the clients.** Agents never hold database credentials. They write batches to a local spool and send
  them through a transport (an SSH command restricted to "accept a batch", or a shared directory).
- **Incremental.** A file is rehashed only when its size, mtime or inode changes. After the first pass a nightly scan
  is metadata-only for nearly everything.
- **Never guess silently.** A rename that can't be proven is reported with its evidence and a confidence, or as
  "gone" plus "new".
- **Everything specific to one site is in config.** No host names, paths, addresses or people in code.

## Parts

```
 machine (agent)                          catalog server
 ┌───────────────────────────┐            ┌──────────────────────────────┐
 │ pinakes-agent scan      │            │ pinakes-ingest            │
 │  walks roots from config   │  batches   │  checks and applies batches  │
 │  extracts metadata         │ ─────────► │ PostgreSQL (row-level        │
 │  local SQLite: state +     │ transport  │  security per owner)         │
 │  outbox of batches         │            │ pinakes-web (web UI, API) │
 │  (optional) runs approved  │ ◄───────── │ pinakes (CLI)             │
 │  file operations           │  requests  └──────────────────────────────┘
 └───────────────────────────┘
```

- **`pinakes-agent`**: runs on each machine from a timer. Walks the configured roots, compares with its local
  state (SQLite), hashes what changed, extracts metadata (METADATA.md), writes a batch of observations to its outbox,
  and sends the outbox when the transport is reachable. Resumable: a scan interrupted by sleep or shutdown continues
  where it stopped. On a root that allows it, also fetches and carries out approved file operations.
- **`pinakes-ingest`**: on the catalog server. Accepts batches (idempotent, by agent and sequence number), checks
  that every path lies inside a root that agent is enrolled for, assigns owners, applies the batch, and runs the move
  and change matching.
- **`pinakes-web`**: the web UI and its JSON API (below). Each request runs with the signed-in person's identity
  set for the database, so row-level security, not the application code, decides what they can see.
- **`pinakes`**: the command-line client, using the same API as the web UI.

Python 3.11+ throughout. The standard library first; where a dependency earns its place, the preferred ones are
**Flask** (web) and **waitress** (its WSGI server). The agent's core is standard library only (`hashlib`, `sqlite3`,
`tomllib`); metadata extractors may need packages and are optional per type. On 3.8-3.10 the agent needs `tomli`.
The server needs PostgreSQL 15+ and `psycopg`. A single-machine mode with SQLite (no users, no row-level security)
is possible later.

## What is recorded

| Table | Holds |
|---|---|
| `people`, `groups` | Who can sign in, and groups for sharing (a household). |
| `hosts` | One row per agent: name, enrolled roots, last batch, last full scan, schedule. |
| `roots` | A scanned folder: host, path, label, kind (`primary`, `drop`, `backup`), policies (below). |
| `owner_rules`, `enrollments` | Who owns which folder, and who else is enrolled in it ("Ownership and enrollments"). |
| `contents` | One row per distinct content: SHA-256, size, MIME type, extracted metadata. Copies share it. |
| `files` | One row per path present now: root, relative path, content, mtime, ctime and birth time (ns; birth time where the filesystem has it, through `statx`), device and inode, owner, first seen, last seen, hashed at. A stable `file_id` follows the file through moves and edits. |
| `links` | For hard-linked trees (snapshot backups): one inode, many paths. The inode is hashed once. |
| `history` | Every change: new, changed, moved, moved and changed, gone; old and new path and hash; the file's mtime, ctime and birth time before and after; the window it happened in (the dates of the scan before and the scan that saw it); evidence; confidence. |
| `members` | Files inside archives (zip, tar), when a root asks for it: archive content, entry path, size, SHA-256. |
| `chunks` | Optional, per root: content-defined chunk hashes (FastCDC). Used only to recognise an edited and renamed file. |
| `metadata` | Typed metadata on a content or on one file, by schema (METADATA.md): extracted, imported from a sidecar, or entered by a person. |
| `bundles` | Files that belong together (a photo and its XMP sidecar, a book's folder): METADATA.md "Pairing". |
| `shares` | Who else may see a file, folder or bundle. |
| `operations` | Requested file operations: who asked, who approved, state, result (SHA-256 before and after). |
| `audit` | Every administrator access to someone else's records and every operation, readable by the people affected. |

Indexes on SHA-256, size, relative path and file name (trigram for substring search), and per-schema indexes on
metadata fields.

## Roots and their policies

Set in config, per root:

- `kind`:
  - `primary`: where files are kept.
  - `drop`: a folder where things are left for later (`Downloads`, `Desktop`).
  - `backup`: a copy of another root. Needs `mirrors`: which root it copies, and how a backup path maps back to a
    source path (for example `snapshots/*/`, then the source's relative path). That answers "is this backed up, how
    many times, how old is the newest copy" for a source file, and gives backup copies their source's owner.
- Owners are not set here: see "Ownership and enrollments" below. The agent reports paths and uids; the server
  decides who owns them.
- `hash`: `sha256` (default) or `none` (names and sizes only).
- `chunks`: off (default) or on, with a size range.
- `archives`: list members of zip and tar files.
- `metadata`: which extractors run (METADATA.md); default all that apply.
- `exclude`: glob patterns (caches, build output, VM images).
- `protected`: hash only. No chunks, no archive listing, no metadata extraction, no previews, nothing derived from
  content; the UI never shows more than path, size and hash.
- `managed`: off (default) or the operations allowed here (`move`, `rename`, `write-sidecar`, `trash`).

### Ownership and enrollments

Every file has exactly one owner, worked out on the server, so a change of ownership never needs a rescan or a change
on the machine:

1. **A site default owner** owns everything no rule claims.
2. **Folder rules** give a folder and everything below it to a person or a group (`people/user-2/**` to `user-2`).
   The most specific rule wins. A rule can also use the file's uid on one host, through that host's uid map; servers
   that map every client to one account, as NFS exports often do, need path rules, because the uid says nothing there.
3. **Enrollments** add people to a folder without changing its owner: as co-owners (same rights as the owner), or as
   readers or annotators. An enrollment is a standing share of a folder, inherited by everything below it, including
   files that arrive later.

Rules and enrollments are seeded from the server's config and live in the database after that, so they are changed in
the web UI per folder: by the folder's owner (give it away, enroll others), or by an administrator in a step-up
session. Every change is audited and shown to the people it affects (SECURITY.md). Backup copies follow their source
file's owner and enrollments.

### Backup servers

Snapshot backups made with hard links (`rsync --link-dest`, `cp -al`) hold the same inode under many snapshot paths.
The agent hashes each inode once and records the other paths as links, so 22 snapshots of a 400 GB tree cost one
pass, not 22. A snapshot root is scanned newest first; older snapshots are mostly links already known. Tools that
store content in their own format (restic, borg) are not walked; their repositories can be added later as a
`backup` source read through the tool (`restic ls --json`), giving paths and times but not whole-file hashes.

A machine that sleeps on demand must not sleep mid-scan: the agent holds a sleep inhibitor while it runs, and runs
inside the machine's scheduled wake window.

## Matching moves and changes

Per root, on each scan, for every path:

1. Same path, same size, mtime and inode: unchanged. Not hashed.
2. Same path, anything changed: hashed. Same hash: metadata change only. New hash: **changed**.
3. A path that disappeared and a new path that appeared, same host:
   - same SHA-256: **moved** (certain);
   - same device and inode, similar size: **moved and changed** (strong; `mv` then edit);
   - chunk overlap at or above a threshold (default 60 %): **moved and changed** (likely; the evidence records the
     overlap). Catches "save as" and editors that replace the file, which get a new inode;
   - its bundle moved with it (a photo and its sidecar to the same new folder): raises the confidence of the above;
   - otherwise: **gone** and **new**.
4. Across hosts nothing is a move: the same SHA-256 on two hosts is a **copy**. A file that vanished from a laptop and
   appeared on the storage server in the same window is reported as "copied there, then removed here".

A move keeps the `file_id`, so metadata entered by a person, shares and history follow the file.

### When a change happened

History exists to answer "which backup holds the version I want", not to track what people do, so its unit is the
**date**. Each change carries:

- the **window**: the date of the last scan that saw the old state and of the scan that saw the new one. A nightly
  scan gives one day; a laptop that is often off, a wider window;
- the file's own times, before and after: **mtime** (content last written), **ctime** (last rename or change of
  permissions; on Linux a rename updates it, so a move can usually be dated, not only bracketed), **birth time**
  (created on this filesystem, where the filesystem records it). Python's `os.stat` has no birth time on Linux
  (no `st_birthtime`, no `os.statx` in 3.12), so the agent calls `statx(2)` through `ctypes`, still standard library.
  Its result struct is 256 bytes and must be declared in full: a short one is overrun by the kernel. A probe on ext4
  (Python 3.12, kernel 7.0) matched `stat %W`, and its mtime and inode matched `os.stat`.

Edits between two scans collapse into one change: the catalog sees the hash before and the hash after, never the
versions in between, and it never holds old content. Finding an old version is a matter of matching its hash and
dates against backup roots, which the catalog does (`versions` below); restoring it is the backup tool's job.

History starts when a root is first scanned. Earlier states are not reconstructed.

Not covered: content changed so much that no chunks survive, and inode reuse by an unrelated file (hence the size
check). A live watcher (fanotify/inotify) could be added later on a busy server; the nightly scan stays the source of
truth because a watcher misses whatever happens while it isn't running.

## Web UI

Served by `pinakes-web` behind the site's HTTPS reverse proxy. Stack: Flask with Jinja templates, served by
waitress; server-rendered pages, with htmx (one vendored file) for partial updates; no JavaScript build step.

- **Browse** by host and root, or by person, or as one merged tree per source with its copies and backups folded in.
- **Search** by name, path, hash, size, date, and metadata fields (author, place, camera, date taken); saved searches.
- **A file's page**: every copy and backup, with ages; history (moves, edits); its bundle; metadata by schema, with
  where each value came from (extracted, sidecar, a person); shares.
- **Reports**: only here, safe to delete, duplicates, not backed up, stale hosts, a root's growth.
- **Managing**: edit metadata; tag; share; change a folder's owner or enroll people (above); mark "keep" or "drop";
  request file operations (below).
- **Administration**: people, groups, hosts and roots; the audit log. Administrator views of other people's records
  only after stepping up (SECURITY.md).

No file content is served by default. Previews (thumbnails, text) are an optional per-root feature, never on a
protected root, and produced by the agent, not the server.

## Managing files

The catalog is the place to decide; the agent on the machine is the only thing that touches files.

1. A person requests an operation in the UI (move this folder to that root, rename, write metadata to a sidecar,
   send to trash), on files they own.
2. Moves within one root are applied when the agent next runs. Operations that leave a root, or are on someone else's
   files, need approval: by the owner, or by an administrator (logged).
3. The agent re-checks each file's SHA-256 before acting, refuses if it changed, copies and verifies by SHA-256
   before removing a source, never overwrites, and reports the result.
4. **No deletion.** `trash` moves into a per-root trash folder with a retention period; emptying it is a person's act
   outside the catalog, or a later, separately enabled feature.

## Queries

```
pinakes find NAME-OR-GLOB              where files with this name are
pinakes where PATH|SHA256              every copy and backup of this file
pinakes only-here HOST:PATH            files under PATH with no copy anywhere else
pinakes safe-to-delete HOST:PATH       every file has a copy in a primary or backup root? (lists the ones that don't)
pinakes backed-up HOST:PATH            per file: backup copies, newest age
pinakes dupes [HOST:PATH]              duplicates, largest first
pinakes history HOST:PATH              what happened to a file or folder
pinakes versions HOST:PATH             each known version (hash, dates) and which backup copies hold it
pinakes changes --since DATE [--host]  what changed
pinakes meta SCHEMA.FIELD=VALUE        files by metadata
pinakes stale                          hosts whose last scan is older than their schedule allows
```

Read-only, scoped to what the caller may see. Output as text or JSON.

## Wish: an MCP server

Not a requirement. The same read-only queries, offered as Model Context Protocol tools (`find`, `where`,
`only_here`, `safe_to_delete`, `backed_up`, `history`, `search_metadata`), so an assistant can answer "is this
folder safe to delete" or "where are the photos from that trip" from the catalog instead of walking disks.

- `pinakes-mcp`, a thin layer over the API (the official Python MCP SDK as its one dependency), over stdio for a
  local client or streamable HTTP behind the proxy.
- It acts as one person, with a token that person creates in the web UI and can revoke. Row-level security applies
  exactly as for the web UI.
- Read-only. No step-up: an administrator session is never available to an assistant. No file operations, no
  metadata edits, at least at first.
- Protected roots show path, size and hash only, as everywhere.
- What leaves the house is the person's choice: a local model (through a local runner with tool calling) keeps
  everything on the LAN; a hosted assistant receives whatever file names and metadata its queries return. The token
  can be limited to some roots for that reason.

## Running on machines that are often off

- Timer with `Persistent=true`, so a missed run happens soon after boot or wake.
- Optional conditions: on AC power only; on a named network only (the transport's host answers); not while a
  configured "busy" command succeeds (a game running, a backup in progress).
- Low priority: `nice` 19 and `ionice -c3`.
- Home folders that are only readable while the user is logged in (encrypted homes) need a user service started in
  the login session, not a system timer.
- The outbox keeps batches until the ingester acknowledges them, so a laptop away from home just queues.

## Cost

The first pass reads every byte once: for a large spinning disk that is many hours, so it runs at idle priority and is
resumable. After that, a scan is a directory walk plus hashing of what changed. The local state is a few hundred bytes
per file; the database the same plus history and metadata.

## Out of scope

Deleting anything, content search inside documents, and Windows (possible later with the same batch format).
