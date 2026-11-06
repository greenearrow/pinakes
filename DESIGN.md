# Design

Status: design only. Nothing here is built or tested yet.

## The problem

Files land on many machines: a storage server, a desktop, a laptop that is mostly off, the `Downloads` and `Pictures`
folders where things get dropped "for now". Questions that come up again and again:

- Does this file exist anywhere else? Where are all the copies?
- What on this disk or folder exists **only** here?
- Is this folder safe to delete (does every file in it have a copy somewhere that is kept)?
- What changed since last week? Where did that file go?

Each answer usually means a one-off script that hashes a tree, compares, prints, and throws the result away. This
project keeps the result: a catalog of every file's path, size, times and SHA-256 across machines, kept current by
cheap incremental scans, with indexed queries.

The operating system doesn't do this. Name indexes (`plocate`, GNOME localsearch, KDE Baloo) store names and sometimes
text, never hashes. Filesystem checksums (btrfs, ZFS) are per block, for integrity, and can't be queried. Backup tools
(restic, borg) hash content into chunks but answer "what was in snapshot X", not "where are all copies of this".

## Principles

- **Read-only on the files.** The agent opens files read-only and never writes to a scanned tree: no xattrs, no
  sidecar files, no touching of times (`O_NOATIME` where permitted).
- **Each machine scans its own disks.** Local reads, not over a network share. A machine that is often off scans when
  it's on and sends later.
- **No secrets on the clients.** Agents never hold database credentials. They write batches to a local spool and send
  them through a transport (an SSH command restricted to "accept a batch", or a shared directory).
- **Incremental.** A file is rehashed only when its size, mtime or inode changes. After the first pass a nightly scan
  is metadata-only for nearly everything.
- **Never guess silently.** A rename that can't be proven is reported with its evidence and a confidence, or as
  "gone" plus "new".
- **Everything specific to one site is in config.** No host names, paths, addresses or users in code.

## Parts

```
 machine (agent)                         catalog host
 ┌──────────────────────────┐            ┌─────────────────────────────┐
 │ catalog-agent scan        │            │ catalog-ingest              │
 │  walks roots from config  │  batches   │  applies batches in order   │
 │  local SQLite: state +    │ ─────────► │  to the database            │
 │  outbox of batches        │ transport  │ PostgreSQL (or SQLite)      │
 └──────────────────────────┘            │ catalog (CLI queries)       │
                                          └─────────────────────────────┘
```

- **`catalog-agent`**: runs on each machine from a timer. Walks the configured roots, compares with its local state
  (SQLite), hashes what changed, writes a batch of observations to its outbox, and sends the outbox when the transport
  is reachable. Resumable: a scan interrupted by sleep or shutdown continues where it stopped.
- **`catalog-ingest`**: on the catalog host. Accepts batches (idempotent, by agent and sequence number), applies them,
  and runs the move and change matching across all hosts.
- **`catalog`**: the query CLI. Reads the database; never touches files.

Python 3.11+ (standard library only for the agent: `hashlib`, `sqlite3`, `tomllib`). On 3.8-3.10 the agent needs
`tomli`. The ingester uses `psycopg` for PostgreSQL, or nothing for SQLite.

## What is recorded

| Table | Holds |
|---|---|
| `hosts` | One row per agent: name, last batch, last full scan. |
| `roots` | A scanned folder: host, path, label, policy (below). |
| `files` | One row per file present now: root, relative path, size, mtime (ns), inode and device, SHA-256, first seen, last seen, hashed at. |
| `history` | Every change: new, changed, moved, moved and changed, gone; old and new path and hash; evidence; confidence; when. |
| `members` | Files inside archives (zip, tar), when a root asks for it: archive SHA-256, entry path, size, SHA-256. Lets "is this unpacked folder a copy of that zip" be one query. |
| `chunks` | Optional, per root: content-defined chunk hashes of each file (FastCDC, average 64 KiB-1 MiB by config). Used only to recognise an edited and renamed file. |
| `extra_hashes` | Optional: other digests for matching outside systems, such as SHA-1 for a photo library that stores SHA-1. |

Indexes on SHA-256, size, relative path and file name (trigram for substring search under PostgreSQL).

## Policies per root

Set in config, per root:

- `hash`: `sha256` (default) or `none` (names and sizes only).
- `chunks`: off (default) or on, with a size range.
- `archives`: list members of zip and tar files, on or off.
- `exclude`: glob patterns (caches, build output, VM images).
- `kept`: whether this root counts as a place copies are kept (an archive or the storage server) or a drop folder.
  "Safe to delete" means every file has a copy in a `kept` root.
- `protected`: the agent never opens files here except to hash them; no chunking, no fuzzy hashing, no archive
  listing, no content-derived fields of any kind, and the query tool never prints more than path, size and hash.

## Matching moves and changes

Per root, on each scan, for every path:

1. Same path, same size, mtime and inode: unchanged. Not hashed.
2. Same path, anything changed: hashed. Same hash: metadata change only. New hash: **changed**.
3. A path that disappeared and a new path that appeared, same host:
   - same SHA-256: **moved** (certain);
   - same device and inode: **moved and changed** (strong; `mv` then edit);
   - chunk overlap at or above a threshold (default 60 %): **moved and changed** (likely; the evidence records the
     overlap). Catches "save as" and editors that replace the file, which get a new inode.
   - otherwise: **gone** and **new**.
4. Across hosts nothing is a move: the same SHA-256 on two hosts is a **copy**. A file that vanished from a laptop and
   appeared on the storage server in the same window is reported as "copied there, then removed here".

Not covered: content changed so much that no chunks survive, and moves between scans on a machine where the old copy
was deleted and a different file took its inode (the inode match then also requires a similar size).

A live watcher (fanotify/inotify) could be added later on a busy server; the nightly scan stays the source of truth
because a watcher misses whatever happens while it isn't running.

## Queries

```
catalog find NAME-OR-GLOB              where files with this name are
catalog where PATH|SHA256              every copy of this file, on every host
catalog only-here HOST:PATH            files under PATH with no copy anywhere else
catalog safe-to-delete HOST:PATH       every file has a copy in a kept root? (lists the ones that don't)
catalog dupes [HOST:PATH]              duplicates, largest first
catalog history HOST:PATH              what happened to a file or folder
catalog changes --since DATE [--host]  what changed
catalog stale                          hosts whose last scan is older than their schedule allows
```

All read-only. Output as text or JSON.

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
per file; the database the same plus history.

## Out of scope

Deduplicating or deleting anything (the catalog only reports), content search inside files, and Windows (possible
later with the same batch format).
