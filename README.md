# pinakes

**Know where every file in the house is, how many copies it has, and whose it is, without hashing a disk again.**

A home lab ends up with files everywhere: a storage server, a backup server, a desktop, a laptop that is mostly off,
and the `Downloads` folders where things get dropped "for now". The same questions keep coming back. Is this folder
safe to delete? What exists only on this laptop? Is any of this backed up? Where did that file go? Each answer
usually means a one-off script that hashes a tree, compares, prints, and throws the result away.

Pinakes keeps the result. A small agent on each machine scans its own disks, read-only, and rehashes only what
changed; a catalog server keeps every file's path, size, times, SHA-256, metadata and owner in PostgreSQL. Those
questions become one indexed query, from a web page, a shell on any machine, or SQL, and each person sees only their
own files.

It is a catalog, never a way to reach a file: it holds none of the files, serves no downloads and opens nothing. The
machine that holds a file, through its own shares and logins, gives access. The name is the *Pinakes*, the catalogue
Callimachus compiled of the Library of Alexandria's holdings: who wrote what, how long it was, where it was shelved.
It held none of the scrolls either.

**Status: early; running on its first deployment.** Release 10 is being prepared. What is built, and how each piece was
tested, is in [REARVIEW.md](REARVIEW.md); what is left in [ROADMAP.md](ROADMAP.md). Licence: GPL-3.0
([LICENSE](LICENSE)).

## What it does

Built and tested:

- **Copies and safety.** Every copy and backup of a file, on every machine. What exists only here (no copy on
  another disk). Whether a folder is safe to delete, and which symlinks elsewhere lead into it. What losing one disk
  or one machine would cost each person. Duplicates, and whole folders that are copies of another.
- **Backups as first-class.** Backup servers are scanned like any machine; hard-linked snapshots are hashed once per
  inode, and each backup copy is tied back to its source, so "is this backed up, and how recently" is a query.
- **Changes and moves.** What changed, per folder or as a tree. Moves and edits are matched by hash, inode and
  content-defined chunk overlap, with the evidence and a confidence recorded; a rename that can't be proven is shown
  as gone plus new, never guessed silently. Gone files and moves can be reviewed (intended, or to restore), with a
  list of which backup holds each one to restore.
- **History and lineage.** A file's history (new, changed, moved, gone) and each version it had, with the backups
  that hold it. Where a file came from and what came from it, across machines, with likely relatives you confirm or
  reject once.
- **Metadata.** EXIF and embedded XMP from JPEGs (location and people fields for their owners only), enrolled schemas
  (Dublin Core, EXIF, XMP: [METADATA.md](METADATA.md)), tags and notes you enter, and search by any field.
  `SHA256SUMS` files are checked against the agents' own hashes.
- **People and privacy.** Every file has an owner; folders are given to people or groups by rules. Each person sees
  their own files and what is shared with them, enforced by PostgreSQL row-level security, not by the application.
  An administrator sees someone else's records only by stepping up (password, second factor, a reason, a time
  limit), and the people affected see that it happened on their *Access to your records* page.
- **Honest scanning.** Agents never write to a scanned tree. Each root is one filesystem; a USB disk or a share
  mounted inside it is reported, not walked, and nothing under it is reported gone. Hidden files are left out of
  browsing until shown. Protected roots get hashes only. A scrub reads unchanged files again on a schedule to catch
  silent corruption.
- **Machines that are often off.** Agents scan when awake, keep an outbox, and send when the server is reachable;
  laptops can scan only on mains power. Agents hold no database credentials: batches travel by an SSH key forced to
  one command, or a shared directory.
- **Every write is undoable** (from release 10). Review marks, lineage decisions, tags and notes are each kept with
  who made them, by which token, and the value before; `pinakes edits` lists yours and `pinakes undo` puts the old values back.

Not yet (ROADMAP.md): extractors beyond JPEG (audio tags, PDF, office, video, XMP sidecars), bundles (RAW with JPEG,
a photo with its sidecar), changing owners in the web UI, file operations by approved request (move, rename, trash;
nothing is ever deleted), WebAuthn and OpenID Connect sign-in, and the MCP server below.

## How you use it

Three ways in, one catalog. The web UI and the command line go through the same API, as one person at a time, under
the same rules. SQL is underneath both.

The examples use placeholder machines (`server-1`, `laptop-1`), people (`user-1`, `user-2`) and roots (`store`,
`downloads`).

### The web UI

`pinakes-web` serves it behind the site's HTTPS reverse proxy. Sign in with your password and, if you set one, a
second factor (TOTP).

- **Find** by name (with `*` and `?`), by who made a file (author, artist, photographer) and by date, and
  **browse** each root as a folder tree.
- **A file's page:** every copy and backup with its age, its history and versions, its lineage and direct
  relatives (confirm, reject or clear a suggested link), and its metadata by schema with where each value came from.
  Enter your own values (tags, notes, any field of a schema that fits), and share its sensitive fields with one of
  its readers.
- **Reports**, along the top: *Changes* (with the review: mark gone files and moves intended or to restore),
  *Duplicates*, *Safe to delete?*, *Only here*, *Folder copies*, *If a disk failed*, *Growth* and *Manifests*.
- **Access to your records:** who saw them (an administrator's step-up, with its reason) and every call made with
  your tokens.
- **Your account:** password, second factor, and tokens for the command line and assistants: each one named, with
  its scopes (`read`, `review`, `tag`), optionally limited to some roots, its last use shown, revocable.
- An administrator's **Step up**, and an operator's **Operator** page (per-root totals, never file names).

The web UI never serves a file's content.

### The command line

`pinakes` runs on any machine and answers as the person whose token it holds. Inside a scanned folder it works on
where you are: no root to name.

```bash
cd /mnt/store/projects
pinakes                              # this folder in numbers: files, backups, copies, changes
pinakes safe-to-delete old-drafts    # files with no kept copy on another disk (none listed: safe)
pinakes where report.pdf             # every copy and backup of it
pinakes changes --days 7 --tree      # what changed this week, per folder
pinakes tag trip-photos --add trip   # tag every file under the folder: shown first, then asked
```

| To know | Ask |
|---|---|
| Where files with this name are | `pinakes find NAME-OR-GLOB` |
| Every copy and backup of a file | `pinakes where FILE` |
| What exists only here | `pinakes only-here [PATH]` |
| Whether a folder is safe to delete | `pinakes safe-to-delete [PATH]` |
| How well a folder is backed up | `pinakes backed-up [PATH]`, `pinakes backups [FOLDER]` |
| What losing a disk or machine would cost | `pinakes at-risk` |
| Duplicates, and folders that copy others | `pinakes dupes`, `pinakes folder-copies [FOLDER]` |
| What changed | `pinakes changes [PATH] [--days N] [--what KIND] [--tree]` |
| A file's history, versions, origins | `pinakes history FILE`, `versions FILE`, `lineage FILE [--down]` |
| What to restore, from which backup | `pinakes restores [PATH]` |
| Growth per folder and week | `pinakes growth [FOLDER] [--weeks N]` |
| Files by metadata | `pinakes meta SCHEMA.FIELD=VALUE` |
| What `SHA256SUMS` files say that the hashes don't | `pinakes manifests [PATH]` |
| Machines that haven't scanned on time; the roots | `pinakes stale`, `pinakes roots` |
| Who saw your records; what your tokens did | `pinakes access`, `pinakes edits` |
| Your own records, to keep | `pinakes export [PART] [--csv]` |

And to act: `pinakes review intended|restore [PATH]` marks gone files and moves reviewed, `pinakes tag` adds or
removes tags and a note, `pinakes relatives FILE --confirm|--reject OTHER` decides a link, and `pinakes undo EDIT`
takes any of them back. `review` and `tag` on a folder show what they would change and ask first (`--yes` skips the
question). Review marks and decisions change only what you own or co-own, tags also what you annotate; each needs
the token's `review` or `tag` scope.

FILE and PATH are a path on this machine (none: the current folder) or `ROOT:PATH`. Lists come a page at a time (100
rows, `--limit` and `--offset`) with the total; `--json` for scripts; `--as NAME` to ask as another person, with their
password at a prompt. `pinakes --help` has the rest.

Setting it up on a machine: `~/.config/pinakes/client.toml` names the catalog
([client.example.toml](client.example.toml)), and a token made on the web UI's account page goes in
`~/.config/pinakes/token` (mode 600).

### The SQL database

The catalog is a PostgreSQL schema, `pinakes`: `hosts`, `roots`, `contents` (one row per SHA-256), `files` (every
file ever seen, with `present` as the view of what exists now), `history`, `lineage` and `metadata` (JSON per
schema). [QUERIES.md](QUERIES.md) shows every `pinakes` command as the one SQL statement it is, with the columns it
assumes, and every block there runs as a test against a catalog built by real scans. It is the place to start a
query of your own, or a report the command line doesn't have:

```sql
-- the 20 biggest files that exist on one machine only (search_path = pinakes)
SELECT h.name AS host, r.label AS root, f.relpath, f.size
FROM present f JOIN roots r USING (root_id) JOIN hosts h USING (host_id)
WHERE r.kind <> 'backup'
  AND NOT EXISTS (SELECT 1 FROM present o JOIN roots ro USING (root_id)
                  WHERE o.content_id = f.content_id AND ro.host_id <> r.host_id)
ORDER BY f.size DESC LIMIT 20;
```

Who may run SQL, and as whom: row-level security, not the query, decides what a session sees. The web UI's role,
`pinakes_app`, is under it and sees only the person a session names (`set_config('pinakes.person', ...)`, as the
tests do); the ingester's role bypasses it. Both trust whoever connects, so direct SQL is for whoever already runs
the catalog server, never a way to give a person access: people reach the catalog through the web UI, the API and
`pinakes`, which the database ties to their own sign-in or token and records. [SECURITY.md](SECURITY.md) has the
policies.

### An assistant (planned: the MCP server)

The way pinakes is meant to be used most, once built (ROADMAP 24): you ask an assistant "is this folder safe to
delete?" or "where are the photos from that trip?", and it answers from the catalog instead of walking disks.
`pinakes-mcp` will offer the queries above, and review marks, tags and lineage decisions, as Model Context Protocol
tools, over the same API and a token you make for it. It acts as you and never as anyone else, can't step up, fetch a
file or make tokens, asks before each write, and every call shows in `pinakes access` and every write in `pinakes
edits`, undoable. A local model keeps everything on the LAN; a hosted assistant receives whatever names and
metadata its answers return, so the token can be limited to some roots. Design: DESIGN.md "Wish: an MCP server".

## Installing

Target: Debian-family Linux with systemd, Python 3.10+ (tested on 3.10 to 3.15; 3.10 needs `tomli`, the `agent310`
extra), PostgreSQL 15+ (tested on 15 to 18); the web UI on Flask and waitress.

Pinakes is not on PyPI; install it from a clone or a wheel built from one (`python -m build`). An agent machine, or
one that only runs the `pinakes` command, needs the package alone, standard library only: `pip install .`
(`'.[agent310]'` on Python 3.10). The catalog server needs `pip install '.[server]'`. The wheel holds the package
alone (`tools/test --wheel` fails if anything else gets in).

Configuration, all of it site-specific and none in the code:

- [config.example.toml](config.example.toml): an agent, its roots and how it sends batches.
- [server.example.toml](server.example.toml): the catalog server: database, web, people, groups, hosts and
  ownership rules.
- [client.example.toml](client.example.toml): the `pinakes` command.

On the server, `pinakes-ingest --config FILE setup` seeds people, hosts and schemas once the schema is applied, and
`pinakes-ingest --config FILE passwd NAME` sets a person's first password. A step-by-step install guide is not
written yet.

## Documentation

- [DESIGN.md](DESIGN.md): the parts, what is recorded, roots and policies, backup servers, move and change matching,
  the web UI, managing files, queries, the MCP server.
- [SECURITY.md](SECURITY.md): people, roles and ownership; stepping up; row-level security; agents; tokens.
- [METADATA.md](METADATA.md): metadata on content and on files, the enrolled schemas, bundles, storage and indexes.
- [QUERIES.md](QUERIES.md): every query in SQL.
- [WHATSNEW.md](WHATSNEW.md): each release, and what to do before updating to it.
- [ROADMAP.md](ROADMAP.md): what is left, and what "done" means for each piece. [HORIZON.md](HORIZON.md): not
  planned, kept for the day a catalog's size asks for it.
- [REARVIEW.md](REARVIEW.md): what is built, and how each piece was tested.
- [DECISIONS.md](DECISIONS.md): every choice made while building, and why.
- [CONTRIBUTING.md](CONTRIBUTING.md): tests, hooks, and cutting a release.
