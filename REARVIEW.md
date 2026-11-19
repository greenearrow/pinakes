# Rearview

What is built, and how each piece was tested. What is left is in ROADMAP.md, and what is only for later, if scale ever asks for it, in HORIZON.md; the reasons are in DECISIONS.md; what a
release changes for a site is in WHATSNEW.md.

Item numbers are one series across ROADMAP.md and this file, and are never reused: "ROADMAP N" in code, tests and
commits means item N, here once built. An item built in parts has its built part here and the rest in ROADMAP.md (or, if it
is not planned, HORIZON.md) under the same number. The first pieces, built before items were numbered, come first and have no number. Each item has
**Built** (what it does) and **State** (what was run, where, and what was not).

Platforms so far: every test on each of Python 3.10 to 3.15 and PostgreSQL 15 to 18, each once (`tools/test --matrix`,
x86-64 desktop; every pair up to ROADMAP 12); Python 3.10 (ARM64 single-board server, kernel 5.10) for the agent, run
for real; PostgreSQL 18 for the first deployment (schema, setup, upgrades and real batches, metadata extracted by its
agents).

## Index

- Agent
- Schema
- Ingester
- Queries
- CLI
- Web UI
- Hidden files
- Releases and check-in
- 1. Ingester at scale
- 2. Owner rules by uid
- 4. A health endpoint
- 5. Copies only on another disk
- 6. Protection by inode
- 7. Symlinks tied to their targets
- 10. The operator page
- 12. The metadata schema registry
- 13. Extractors, first part: EXIF and embedded XMP from JPEGs
- 16. Sensitive metadata for owners only (first part)
- 16. Metadata on a file's page and in find (showing it)
- 19. Checksum manifests
- 27. Packaging and a test matrix
- 28, 29. Backup roots without churn; name lineage with a second signal
- 30. A walk check for comparing the catalog with the disk
- 31. An ingester stopping when its agent gives up
- 32. Reviewing changes
- 33. Commands from inside a folder
- 34. The JSON API and person tokens
- 35. `pinakes` as a client of the API
- 36. `--as NAME`
- 37. Reviewing from a folder (first part)
- 38. Group tokens
- 39. Ops tokens and `pinakes releases`
- 41. The scrub
- 42. What a disk's loss would cost
- 43. Folders that are copies of each other
- 44. Extraction outcomes kept
- 45. A person's export of their own records
- 46. A machine replaced under the same name
- 47. Growth by folder over time
- 48. A fast home page on a large catalog, (a) and (b)
- 49. Token forms a password manager can fill
- 50. A web page for folder copies
- 51. The agent reports its runs to a push monitor

## Dropped

- 3. `inhibit_sleep`: gone, as the unit or the site keeps the machine awake.

## Agent

**Built:** Walk, state, hashing, birth time (statx), chunks, archive members, protected roots, resumable scans,
mass-gone guard, one filesystem per root, progress lines, batches, ssh and directory transports.

**State:** Tested (3.12, 3.10); run for real on one server.

## Schema

**Built:** People, groups, ACLs, step-ups, append-only audit, hosts, roots, scans, contents, files, chunks, members,
history, lineage, metadata (table only).

**State:** Tested on 16; applied on 18.

## Ingester

**Built:** Sequence and duplicate handling, owners by folder rules and enrollments, backup copies tied to their source
(with prefix), moves by hash, inode and chunks, lineage by identical content, chunks and names, recompute after a rule
change.

**State:** Tested on 16; run on 18 with real batches (a first deployment, two scans).

## Queries

**Built:** Queries (QUERIES.md), physical copies by host, device and inode.

**State:** Tested on 16.

## CLI

**Built:** CLI.

**State:** Run by hand on a demo catalog.

## Web UI

**Built:** Sign-in (scrypt), TOTP enrollment, step-up with reason and code, audit of what a step-up showed, "Access to
your records", browse, find, a file's page (copies, versions and the backups holding them, history, lineage), reports
(only here, safe to delete, backed up, duplicates, changes with a folder tree of new, changed, moved in, moved out and
gone, filtered by kind and folder), paging, sorting by column (in SQL), behind a proxy.

**State:** Tested with the test client on 16; served for real behind a proxy, no sign-in yet.

## Hidden files

**Built:** The agent marks a file hidden by a dot in its path or by Samba's hidden attribute (`user.DOSATTRIB`, every
version Samba writes) on it or a folder above, read once per folder per scan; a change of attribute alone resends the
record without rehashing; the ingester also marks a dot-name from an agent that doesn't say, and a moved file takes its
new path's; browse and find leave them out until a person shows them for the session (browse says how many it left out),
reports count them; `upgrades/hidden-files.sql`.

**State:** Tested on each of Python 3.10 to 3.15 and PostgreSQL 15 to 18 once (x86-64 desktop, ext4): the attribute set
with real xattrs on generated files, its parser on values from Samba 4.19.5's own encoder (no smbd: never written by a
Windows client); the ingester, the upgrade and the web toggle with the test client. Deployed,
`upgrades/hidden-files.sql` applied: dot-names marked on every root, a protected root's from names alone; no file there
has Samba's hidden attribute, so the attribute is still tested only on generated files; not tried in a browser.

## Releases and check-in

**Built:** `RELEASES.toml` (releases 1 and 2 backfilled: the server and agents live when releases began, protocol 0; 3,
the first with a protocol, cut 2026-11-12, not deployed; a release is cut only by its tag, when the owner says),
`pinakes/compat.py` (release, protocol, the oldest agent and server each side works with), `tools/latest-release ROLE`;
a test fails if the batch fields, the agent's state or the schema change and the protocol doesn't; `pinakes-ingest
hello` through the agent's forced key; the agent locks (scans on, sends nothing, one line, exit 4) and unlocks by
itself; the ingester refuses a batch outside its range, and takes one with no protocol as 0; `pinakes --versions`;
`upgrades/checkins.sql`.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (the only one installed there; 15, 17 and 18 not
run), and from the wheel (x86-64 desktop), the fingerprints the same on each: the agent against a stand-in ssh (too far
ahead, ahead but compatible, behind, a server from before check-in, unreachable, unlock with the held batches), the
ingester and its refusals, the upgrade against the schema, and one run through a stand-in forced key into the real
ingester. Not deployed; not run against a real sshd.

## 1. Ingester at scale

**Built:** Completing a scan in bulk (the new files' history in one statement, lineage in rounds of 2000 files), a
scan's gone paths matched to its new ones by an index; ordinary batches still per record, as the board's time and memory
don't ask for more.

**State:** Tested on 16 (`TestLineageRounds`, `TestMovesSameAsBefore`); run on 18 on a 4+4-core ARM board
(DECISIONS.md): 5000-record batches every 6-10 s, peak RSS 65 MB over 202 batches, none failed.

## 2. Owner rules by uid

**Built:** An `[[ownership.rule]]` with `owner = "uid"` gives each file under its folder to whoever the file's uid maps
to in the `uid_map` of the host that reports the root (a person or a group). A uid the map doesn't name leaves the file
to the next rule, then the default owner; a more specific folder rule outranks it. The rule is seeded as
`owner_rules.by_uid` (`upgrades/owner-by-uid.sql`, in release 6); a rescan that sees a file chowned moves it, and
`recompute_root` uses each file's uid. The config refuses a uid rule on a root no host with a `uid_map` reports, and a
`uid_map` naming someone unknown. A server whose clients are all one account keeps working by folder rules.

**State:** Tested on Python 3.12 with PostgreSQL 16.15 (x86-64 desktop; `TestOwnerByUid`: two uids to two people,
unmapped uid, folder rule outranking, row-level visibility per person, chown, recompute, config refusals, upgrade file
against schema.sql). Not run on a real catalog; not deployed.

## 4. A health endpoint

**Built:** `/health` without sign-in for monitoring (database reachable; per host its newest batch, last complete scan
and staleness; 200 or 503; host names only), also alone on `[web] health_listen`.

**State:** Tested with the test client on 16; served by waitress on both listeners on the desktop.

## 5. Copies only on another disk

**Built:** Only-here and safe-to-delete count a copy only on another disk (another host, or another device of the host);
copies on the file's own disk shown apart; a hard link no copy (5).

**State:** Tested on 16, under row-level security; web and CLI wording.

## 6. Protection by inode

**Built:** A hard link of a protected file in another root of the same agent is protected there too (no archive listing,
chunks only if the protected root makes them, a listing made before the link dropped, the file's page says so); the
agent walks its protected roots for links only when a scan meets a file with more than one link;
`upgrades/protected-links.sql` for older catalogs.

**State:** Tested (agent on 3.12; ingester, row-level security, upgrade and web on 16).

## 7. Symlinks tied to their targets

**Built:** The agent resolves each link's target name by name, looking names up only inside its own roots (root and
path, dangling or not, a loop dangling); a target appearing or going resends the link; moved links matched by inode only
when they still lead to the same place, else by target and name; `only-here` and `safe-to-delete` leave links out, and
safe-to-delete lists the links elsewhere that lead into the folder; a link's page links to its target where the person
may see it; `upgrades/symlink-targets.sql`.

**State:** Tested (agent on 3.12; ingester, row-level security, upgrade, CLI query and web on 16).

## 10. The operator page

**Built:** `/operator`, linked for operators only: per root its host, kind, every person's present files and bytes
(an inode once), last complete scan, oldest scrub check, whether its host stopped reporting it or it was retired, and
its scan errors' count and newest date; then 42's totals. From `operator_roots()`, a database function that refuses
anyone but an operator signed in on the web (a token, ops or not, too): counts, sizes and dates, never a path, a file's
name or a person. `upgrades/operator.sql` (release 8, protocol 5, not cut).

**State:** Tested on Python 3.12.3 with PostgreSQL 16.15 (x86-64 desktop, `tools/test`, 406 tests, all pass):
`tests/test_server.py` `TestAtRisk` (another person's root counted, an inode once, scan errors counted without their
path, refused to a person, an operator under a token and no person; the upgrade against the schema) and
`tests/test_web.py` `TestWeb` (the page and its link for an operator only, no path, file or other person on it). Not
run against a real catalog or in a browser; not deployed.

## 12. The metadata schema registry

**Built:** `pinakes/schemas/*.toml` (Dublin Core, the common fields, first) and a site's in `[metadata] schemas`,
validated with a message naming the file and key; `pinakes-ingest setup` makes a partial index per indexed field through
`enroll_metadata_indexes()` and drops those no schema wants; `upgrades/metadata-indexes.sql` for older catalogs.

**State:** Tested on Python 3.10 to 3.15 and PostgreSQL 15 to 18 (the lean matrix, x86-64 desktop; the wheel, installed,
on 18.6): loading and refusals, the indexes serving searches, the function's refusals and grants, the upgrade; applied
on the first deployment (PostgreSQL 18) with its indexes.

## 13. Extractors, first part: EXIF and embedded XMP from JPEGs

Open part: ROADMAP.md 13.

**Built:** EXIF and embedded XMP from JPEGs on the agent, standard library only (`pinakes/exif.py`, `pinakes/xmp.py`,
`schemas/exif.toml`, `schemas/xmp.toml`; XMP's ids declared as identity fields for 15, its people and places sensitive;
XML with a DOCTYPE or entities refused); extracted metadata in batch format 2 (`meta` on a file record), read once per
content per agent and again when a schema's version changes, never on a protected root or link; the ingester checks it
against the registry, keeps it on the content with its version and host, and refuses it from protected roots and links;
sensitive fields (GPS, people, places) kept apart for owners only (16's first part); `upgrades/metadata-extracted.sql`.

**State:** Tested on each of Python 3.10.22 to 3.15.2 and PostgreSQL 15.19 to 18.6 once (`tools/test --matrix`, x86-64
desktop), on generated JPEGs. Its first run on a real tree skipped photos whose agent state predated the file type
(`27650a5`): fixed in `d753d9f`, tested on a state written by that older agent. Run for real with the fix on the first
deployment's agents: 86,608 of 87,325 JPEGs have EXIF (717 without, not looked into yet); 83,176 exif and 40,546 xmp
rows; nothing from a protected root or link; no metadata left out; five photos' camera and date taken read correctly
(not compared with a photo viewer).

## 16. Sensitive metadata for owners only (first part)

Open part: ROADMAP.md 16.

**Built:** GPS, people shown and place names in rows of their own (`metadata.sensitive`), visible through
`sensitive_visible()` to the owners and co-owners of a copy or an administrator in a step-up, not to readers; exif and
xmp at version 2 send them; `upgrades/metadata-sensitive.sql`.

**State:** Tested on each of Python 3.10 to 3.15 and PostgreSQL 15 to 18 once (x86-64 desktop): owner, co-owner, reader,
a copy of one's own, step-up, a search by place, the upgrade; the tests checked to fail without the policy. Deployed:
12,695 sensitive exif rows (GPS) and 2 xmp; a second person sees exactly the sensitive rows of the photos they own or
co-own (2,889 of 2,889).

## 16. Metadata on a file's page and in find (showing it)

**Built:** Each schema's fields with source, version and date, all sources when they disagree, sensitive ones tagged and
shown only where `sensitive_visible()` allows (a note otherwise, the same with or without them); a step-up that showed
them audited as such; find by name, "made by" (`creator`) and "dated" (`date`) over every schema's mapping, each through
its own index, under row-level security.

**State:** Tested on each of Python 3.10 to 3.15 and PostgreSQL 15 to 18 once (x86-64 desktop), with the test client on
generated JPEGs: owner, reader, step-up and its audit, find under row-level security, the indexes used, markup in a
value; the reader tests checked to fail without the policy; deployed on the first deployment; not tried in a browser.

## 19. Checksum manifests

Design: DESIGN.md "Checksum manifests".

**Built:** `pinakes/manifests.py`: at the end of each scan, every `SHA256SUMS`, `SHA256SUMS.txt` and `*.sha256` in the
root (sha256sum's text, binary and escaped lines, and the BSD format) is read when its content is new and only if
the bytes read have the scan's hash, and each line is checked against the agent's own hash: confirmed, wrong,
missing, unchecked; bad lines and names outside the root counted. The agent's state keeps the lines and what was last
sent (`manifests`, `manifest_lines`, `hints`). `hint` and `manifest` records go with the scan's complete batch, only
when they change (all again with `--full`), and only to a server of protocol 4 (release 7). Never on a
protected root or link, nor with `hash = "none"`; `[[root]] manifests = false` turns it off and clears what was sent.
The ingester applies them after the scan's moves (a move carries them), refuses them outside a complete batch, from a
protected root or through a protected link, and keeps them on the files (`manifest_verdict`, `manifest_file_id`,
`manifest_on`, `manifest_counts`; `upgrades/manifests.sql`). Shown on the file page, in the Manifests report,
`/api/v1/manifests`, `pinakes manifests [PATH]`, and QUERIES.md "manifests".

**State:** Tested on Python 3.12.3 with PostgreSQL 16.15 (x86-64 desktop, ext4; `tools/test`, 383 tests): the
agent's `tests/test_agent.py` `TestManifests` and `TestManifestsProtected` on generated trees (a wrong line reported
and a right one confirmed, the hash sent the agent's own, nothing sent again when nothing changed, the formats, a file
put back and a listed file gone, the manifest gone, two manifests disagreeing, `--full`, read once per content and
not believed when it changed after hashing, a symlink unchecked, waiting for protocol 4, turned off, the config, a
protected root never read, checked to fail without its guard); `tests/test_server.py` `TestManifests` (in the catalog
the wrong line reported and the right one confirmed, the hash the agent's, the report and file page queries, another
person seeing none of it, a folder moved with its manifest, the manifest gone, refusals outside a complete batch,
of a bad verdict and from a protected root, the upgrade against the schema); `tests/test_queries.py` with the new
QUERIES.md block; `tests/test_releases.py` with a manifest in its tree. One failure in the run, not from this change:
`TestUnreportedRoots.test_a_machine_replaced_with_fewer_roots` fails the same on the commit before (`totals` prints
`unreported_since` in the server's time zone, the test expects UTC's date, so it fails while they differ). Only this
Python and PostgreSQL; not run on a real tree; not deployed.

## 27. Packaging and a test matrix

**Built:** `tools/test` starts and removes its own PostgreSQL and fails a run that skipped tests for want of a database
or a dependency; `--matrix` (each Python on the newest PostgreSQL, each PostgreSQL on one Python; `full`: every pair,
side by side with `--jobs`); `--wheel` builds the sdist and wheel from a clean copy of the tree, installs the wheel in a
new environment and runs every test against it. No release is published (not decided) and the version is still
0.1.0.dev0.

**State:** Every pair of Python 3.10.22, 3.11.18, 3.12.3, 3.13.18, 3.14.9, 3.15.2 and PostgreSQL 15.19, 16.15, 17.11,
18.6: 148 tests OK (x86-64 desktop); the wheel, installed, on 18.6.

## 28, 29. Backup roots without churn; name lineage with a second signal

**Built:** Backup roots without churn (no history, gone rows deleted, link-count and ctime changes not sent); name
lineage only with a second signal (a folder name only when rare; signs kept in names); `pinakes-ingest tidy` for
catalogs built before them.

**State:** Tested on 16 (agent part on 3.12); run for real on 18: a hard-linked snapshot root of ~100k files sent about
100k records a night before, and after it only each new snapshot's files plus one gone per pruned file (two nights:
3,688 and 14,753), matching the snapshots made and pruned.

## 30. A walk check for comparing the catalog with the disk

**Built:** `pinakes-agent check` counts each root with the scan's own walk and the running process's rights, beside the
last scan, with what changed since it started and errors by kind; `pinakes-ingest totals` gives the catalog's per root,
every owner's; no file names in either.

**State:** Tested (3.12; the comparison on 16); done by hand on one server before it was built: every root matched its
last scan.

## 31. An ingester stopping when its agent gives up

**Built:** Ingester stopping a batch whose sender hung up (its stdout closed) or that runs past `[ingest]
max_batch_time`: the running statement cancelled, the transaction rolled back, exit 3.

**State:** Tested on 16 (the forced ingester as a subprocess, blocked on a lock).

## 32. Reviewing changes

**Built:** Gone files and moves marked *intended* or *restore*, by row or in bulk (the changes filters, seen up to a
date, optionally only gone files still in another root, not a backup); unreviewed counts in the tree, a reviewed /
unreviewed filter; a gone file's other copies and backups, or "may be lost"; a restore list naming the backup and
snapshot, cleared when the content is back in the root (a move: at its old path); marks only through `mark_changes()`,
by owners and co-owners, or an administrator in a step-up (audited); `upgrades/review-marks.sql` for older catalogs.

**State:** Tested on 16 (queries under row-level security, the web forms with the test client); tried in a browser on
the demo catalog (waitress); deployed on 18 (`upgrades/review-marks.sql` applied to the first deployment), no mark made
there yet.

## 33. Commands from inside a folder

**Built:** `where`, `history`, `versions` and `lineage` take a file, `only-here`, `safe-to-delete` and `backed-up` a
folder or a file, `changes` and `backups` a folder: a path here (none: the current folder) or `ROOT:PATH`, a path that
exists here taken as one; found among the roots this machine reports (`--host`, else `[client] host`, else `[agent]
host`, else its hostname), a file's own name kept as it is (a symlink is itself); `changes` with no folder outside every
root shows everything, and says which; bare `pinakes` sums up the current folder (files, with no backup, with no copy on
another disk, changes in 7 days) and prints usage outside a root; the folder reports, given a file, answer for the file
(before, a file matched nothing under it, which read as safe), on the web too; `--backups` became `backups` (35).

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py`
`TestCliHere`, the CLI against a real HTTP server on 127.0.0.1): each command from inside a folder and given one, by
path and as `ROOT:PATH`, a file for a folder report, a folder for a file command, outside every root, another person's
files, the summary and usage; the web's file-for-a-folder answer in `tests/test_web.py`. Not run on a real catalog; not
deployed.

## 34. The JSON API and person tokens

**Built:** `/api/v1/` in `pinakes-web` over the CLI's queries (`whoami`, `roots`, `find`, `where`, `only-here`,
`safe-to-delete`, `backed-up`, `dupes`, `history`, `versions`, `lineage`, `changes`, `meta`, `stale`), GET only, by
bearer token, never the session cookie; tokens made on the account page (the current password again, a client name,
scopes `read`, `review`, `tag`, every root but the protected ones or the roots ticked, a lifetime or none), shown once,
kept as SHA-256, revoked there, last use shown; `begin_token_call()` sets the person and records every call for them
(their access page); row-level security holds files to the token's roots; a token never steps up (`stepped_up()` false,
`begin_step_up()`, `make_token()` and `revoke_token()` refused under one); refused tokens limited per address;
`upgrades/api-tokens.sql`.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15, the only one installed (x86-64 desktop;
`tests/test_api.py` within the full run; the root test checked to fail without the policy); 15, 17 and 18 not run. Not
tried in a browser or against a real catalog; not deployed.

## 35. `pinakes` as a client of the API

**Built:** Standard library only (`urllib`), no database driver or server config; the catalog's address from `[client]
url` (`~/.config/pinakes/client.toml`, `$PINAKES_CLIENT_CONFIG` or `/etc/pinakes/client.toml`) or `--url`, https or http
to this machine only, `[client] ca_file` for a site's CA; the token from the first of a `.pinakes-token` in the current
folder or one above it and `~/.config/pinakes/token`, a token file not the user's own, not a plain file or readable by
anyone else refused, not skipped; every action a subcommand (`backups`); `--as` gone until 36; `--versions` stays on the
server, from `server.toml` and the database with no person, until 39; API calls `host-roots` and `backups` for the
folder commands.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py` `TestCli`
and the moved CLI tests in `tests/test_server.py`, against a real HTTP server on 127.0.0.1 in the test; once with
psycopg made unimportable), and from the wheel on 3.12. Not run against a real catalog or over https; not deployed.

## 36. `--as NAME`

**Built:** One hidden prompt for NAME's password or a token of theirs (checked to be theirs by `whoami`), and for a
password their second-factor code (empty if they have none); the password through `POST /api/v1/session`, checked as the
web sign-in checks it plus the second factor when the person has one, a failure counted in the web sign-in's own
per-address limit; the answer a `read` token of 10 minutes (`begin_cli_session()`), every root but the protected ones,
kept in memory only, revoked by `POST session/end` when the command ends, never listed among the person's tokens; the
caller's own token not read; audited for the person as a sign-in from the CLI with its address, and each call as theirs.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py` `TestCliAs`,
the CLI against a real HTTP server on 127.0.0.1, the prompts answered by the test): the named person's files and not the
caller's, nothing written, the session revoked and unlisted, the second factor, wrong secrets and the shared limit (the
web sign-in held too), a token of theirs and one not, no step-up, the entries on their page. Not run against a real
catalog; not deployed.

## 37. Reviewing from a folder (first part)

Open part (tagging): ROADMAP.md 37.

**Built:** `pinakes review intended|restore [PATH]` lists the unreviewed gone files and moves under the folder (or of
the file, `ROOT:PATH` for one already gone) in the last `--days`, asks, and marks them through `POST /api/v1/review` (by
the ids it showed, scope `review`); `--yes` without asking, and without a terminal only with it; says how many of how
many were marked; `mark_changes()` refuses a token without the scope and skips changes outside the token's roots (it
reads files as the schema's owner, so the policy didn't reach it); the API's `changes` takes `review` and `what`, and
`changes` a file's own path.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py`
`TestCliReview`, the CLI against a real HTTP server on 127.0.0.1): the owner from inside the folder, asked and
declining, then marking; one gone file by `ROOT:PATH`; `--yes`; a co-owner marking, a reader's skipped; a token without
the scope refused by the API and by the database; a token limited to another root marking nothing of the store, even by
ids (checked to fail without the check); the marks on the web's Changes and restore pages. Not run against a real
catalog; not deployed.

## 38. Group tokens

**Built:** A token of kind `group` acts as its group and no member: `begin_token_call()` sets no person,
`current_group()` names the group, and `visible_acls()` gives the ACLs the group owns or is enrolled in (`acl_groups`,
written by the ingester beside `acl_members`), never a member's own; scopes and roots as a person's token; made on the
account page by a member of the group ("Asks as"), listed for every member, revocable by any, and it stops working once
its maker leaves the group; its calls, making and revoking are on every member's record; it marks only where the group
is the owner or a co-owner, the mark the group's (`review_marks.marked_by_group`), audited with the token for every
member; sensitive metadata where the group is the owner or a co-owner; `api-tokens.sql` fills `acl_groups` from each
ACL's key. Tags wait for 37.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py`
`TestGroupToken`): the group's files and no member's own, by the API and in the database; a non-member refused making,
seeing and revoking one, by the page and the database; a former member's token refused and theirs no more to list or
revoke; its marks the group's, refused where it only reads or a member owns, shown as the group's on the web and the
API; its calls on every member's access page; sensitive metadata; the upgrade against the schema, with a group's ACLs.
The membership and mark checks checked to fail without them. Not run against a real catalog; not deployed.

## 39. Ops tokens and `pinakes releases`

**Built:** An ops token is made by an operator on the account page (the current password again, a client name, a
lifetime), scope `ops` alone, no root list; it acts as no person (`begin_token_call()` sets none, so row-level security
shows it no file), answers `releases`, `stale` and `whoami`, and every other call refuses it; its calls are its maker's
record; `GET /api/v1/releases` gives what `pinakes --versions` read from the database; `pinakes releases` prints it as
before, and `pinakes --versions` now only says where it went; a site's deploy checks change with this release.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop), and from the wheel on 3.12:
`tests/test_api.py` `TestOpsToken` (made by an operator and refused to anyone else, by the page and the database; ops
alone and no roots; `releases` and `stale` answered and every other route refused, a person's token refused `releases`;
no person in the database, no file seen, `mark_changes()` refused; its calls on its maker's record) and the check-in and
takeover reports in `tests/test_server.py` through `pinakes releases`. Not run against a real catalog; not deployed, and
the first deployment's checks still call `pinakes --versions`.

## 41. The scrub

Design: DESIGN.md "Scrub".

**Built:** After the scans, each filesystem under the agent's roots has its least recently verified files read again and
their hashes checked, up to its share (its bytes × time since its last scrub ÷ `days`, at most seven nights'; `[agent]
scrub_max_minutes`); `scrub.toml` written by the agent (filesystems by UUID through `/proc/self/mountinfo` and
`/dev/disk/by-uuid`, else the mount source; `days = 30`, 0 for network filesystems), new ones appended, never rewritten;
a hard-linked inode read once; `verified` and `scrub_error` in the agent's state; a scrub batch per root (its summary,
`mismatch`, `unreadable`, `readable`), sent only to a server of protocol 3 (release 6); the ingester gives a
mismatch its new content and a history row of its own (none in a backup root), marks an unreadable file, which no copy
query counts until it reads; both reviewable (`mark_changes()`, the changes page and tree, `pinakes review`, the restore
list); `/health` per host the oldest check and whether the scrub is behind (503); `pinakes-agent scrub [status]`;
`upgrades/scrub.sql`.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15, the only one installed (x86-64 desktop, ext4;
`tests/test_scrub.py` on generated trees with a mount table and by-uuid folder made by the test, `tests/test_server.py`
`TestScrub`): a flipped byte under a kept mtime a mismatch and not an edit, an edit left to the scan, a read error sent
once and its clearing, days 0, the budget and the cap, the time limit, a hard link, an interrupted run, a protected
root, chunks, the file written, appended and a changed number kept, unwritable; in the catalog the history row, copies
no longer counted, review and restore, another person not seeing it, a reader not marking it, /health, the upgrade
against the schema. The copy and hash checks checked to fail without them. Not run on a real tree or against real disks;
not deployed.

## 42. What a disk's loss would cost

**Built:** `at_risk()`: every present file but a symlink with no readable copy on another host, and whether it has none
on another device of its host either, copies counted as only-here counts them (a hard link no copy, an unreadable file
none, a device not known never another disk), under the caller's row-level security. "If a disk failed"
(`/reports/at-risk`) shows a person, of the files they can see, the files and bytes lost per disk (a device of a host,
named by its roots) and per machine, and by disk, root, top folder and owner, the largest first (200 shown, each
opening Only here for its folder); in a step-up it is audited for the owners shown. The operator page has every
person's totals per disk and per host, without names (`operator_at_risk()`). Not per owner for the operator, no API
call or CLI (DECISIONS.md).

**State:** Tested on Python 3.12.3 with PostgreSQL 16.15 (x86-64 desktop, `tools/test`, 406 tests, all pass):
`tests/test_server.py` `TestAtRisk` on generated trees, two devices of one host (made by changing a device number in
the catalog) and a backup root on another: the sizes per disk and per host for the operator, without a path; each
person's own, a copy only another person can see not counted; an unreadable copy and an unknown device;
`tests/test_web.py` `TestWeb`: the page for two people, and a step-up's view on the other person's access page,
checked to fail without the audit; the QUERIES.md block in `tests/test_queries.py`. Not measured on a large catalog
(it groups every file by content per call); not run on a real catalog or in a browser; not deployed.

## 43. Folders that are copies of each other

Design: ROADMAP.md item 43 (built, so no longer listed); no DECISIONS.md entry.

**Built:** `pinakes folder-copies [FOLDER]` and the API call `folder-copies?loc=ROOT:PATH` (`queries.folder_copies`):
the folders under the given one (or the root) that are copies of another folder anywhere the person can see. A
folder is the set of its files' (path inside it, content); backup roots, symlinks and empty files are left out. A
pair is `same` (equal sets), `inside` (everything the folder holds is in the other, which holds more) or `nearly`
(every path of the folder is in the other, at most `NEAR_PERCENT` (10) of them, at least one, with other content:
those paths are listed in `differing`). A subfolder whose parent has the same relation to the same other folder is
left out, and a pair of folders inside the scope is one row. Each row says how many files are only on either side.
Biggest first.

**Not as the roadmap said:** it is computed on each call, not at scan completion. A stored digest would be built from
every file, so it could not follow row-level security; a query over `present` can. The cost is a pass over the
catalog's present files per call, so a very large root should be asked about a folder at a time. Not measured on a
large catalog; if it is too slow, the way out is per-owner digests kept at scan completion. The web page is item 50.

**State:** Tested on Python 3.12.3 with PostgreSQL 16.15 (x86-64 desktop; `tools/test`, 396 tests, all pass):
`tests/test_server.py` `TestFolderCopies` on generated trees (same with a subfolder, inside, nearly with the edited
file named, empty files and same-name-other-content ignored, one row per pair, no row for a subfolder of a pair, a
smaller scope; another person's identical folder gives no row, checked against the unrestricted connection that does
find the pair). The CLI command (given ROOT:PATH, and a path here with `--host`, `--json`) and the API call it makes are in
`test_cli_and_api`. Not run on a real tree; not deployed.

## 44. Extraction outcomes kept

Design: METADATA.md "Extraction"; DECISIONS.md "What each extractor made of a file is kept".

**Built:** the agent sends, per file and schema, what the extractor made of it: values (none: nothing found),
`refused` with a reason code (`extract.REFUSALS`: `truncated`, `wrong_type`, `malformed`, `bad_values`,
`unreadable`, `failed`), or `skipped` for one that applies and is off there (`extract.SKIPS`: `dependency`,
`broken`); codes only, never an error's text, and only to a server of protocol 4 (release 7): to an older
one, the text as before. The EXIF reader refuses a JPEG that ends before its image data as truncated (`CutShort`),
where it used to return what it had read, and a file that isn't a JPEG as `wrong_type` (`NotJpeg`). Once the server
is at protocol 4, the agent's `meta_v` takes the form `[2, {...}]`, so every file read before is read once more
(headers, no rehash) and its outcomes sent. The ingester checks the codes, keeps the latest report per content and
schema at the newest version (a skip never replaces a run; a refusal leaves known values), drops them with the rest
of a protected link's, and keeps found values that are all sensitive as a sensitive row "found" and another
"nothing" (`extractions`, `extraction_outcomes`; `upgrades/extractions.sql`). Shown on the file page ("Read by"),
in QUERIES.md "extraction outcomes", and counted for the operator, every owner's and without names, by
`pinakes-ingest extractions`. The operator page (10) will show the same counts when it exists.

**State:** Tested on Python 3.12.3 with PostgreSQL 16.15 (x86-64 desktop, ext4; `tools/test`, 393 tests, all pass):
`tests/test_extract.py` (a truncated JPEG refused wherever it ends, a non-JPEG `wrong_type`, codes and no text sent,
the text to a protocol 3 server and every photo read once more at 4 without rehashing, an extractor missing its
package said skipped); `tests/test_server.py` `TestExtractionOutcomes` (on real scans of generated JPEGs: truncated
refused, one with no metadata "nothing", a non-JPEG `wrong_type`, the counts per content and per file, the command's
output without names; another person sees only the shared files' outcomes, and a reader of a GPS-only photo
"nothing" while its owner sees "found", checked to fail without the split; which report is kept; codes outside the
lists left out; a protected link takes them; the upgrade against the schema); `tests/test_web.py` (the file page's
line, a reader's identical for a GPS-only photo and one with none); `tests/test_queries.py` with the new block;
`tests/test_releases.py` (the meta entry's fields declared in `compat.BATCH_FIELDS`). Only this Python and
PostgreSQL; not run on a real tree; not deployed.

## 45. A person's export of their own records

Design: ROADMAP.md item 45 (built, so no longer listed; with it the "Reports and exports" section, all built); no
DECISIONS.md entry.

**Built:** `GET /api/v1/export`, with a person's token and the `read` scope (`queries.export`, QUERIES.md "export"):
the files the person owns and what the catalog holds about them, in five parts: `files` (host, root, path, size,
SHA-256, MIME, times, gone, hidden, symlink, backup, scrub and manifest state), `history` (every change, with both
hashes), `reviews` (their marks, and by whom), `metadata` (a content's rows once per file of theirs that holds it, and
the file's own), `lineage` (links with either end theirs). JSON: every part, or one with `part=`; `format=csv`: one
part, with a header even when empty, metadata values as JSON text. `limit=` and `offset=` page each part, in a unique
order. It is a query, not a dump: it runs as the person under row-level security, so a token's roots limit it (the
protected ones left out unless named) and sensitive metadata comes only where `sensitive_visible()` allows. The call
is recorded like every API call, on the person's access page. A group token is refused (its files have no person
owner), an ops token too (no `read`).

**Not as the roadmap said:** "my files" is the files the person owns (`files.owner_id`): a folder shared with them,
co-owned or a group's is in its owner's export, not theirs. Metadata of a past content no file holds any more isn't
in it (row-level security shows none). Built in memory as the other calls are, not streamed. No CLI command or web
page yet.

**State:** Tested on Python 3.12.3 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py` `TestApi`): two
people's exports, each with only their own files, history, marks and metadata and nothing of the other's (by id, path
and hash), the reader of a shared folder getting none of it, sensitive metadata present and each row allowed by
`sensitive_visible()` under the token, a token limited to a protected root, a page, CSV with and without rows, bad
arguments, group and review-only tokens refused, and every call in the audit and on the access page (checked to fail
without the owner filter); all 411 tests pass. Other Pythons and PostgreSQL versions not run; not run on a real
catalog; not deployed.

## 46. A machine replaced under the same name

**Built:** Every batch, scan or scrub, names all the roots the agent has (`roots` in its header, protocol 3); the
ingester marks the host's other roots `unreported_since` (the first batch that left them out) and clears the mark when
a batch names a root again; `pinakes-ingest retire-root` sets `retired_on`, which ends it until the root is named
again. `/health` gives per host `roots_unreported`, a count, and answers 503 "roots unreported" (after "refused" and
"stale", before "scrub behind"); `pinakes releases` says the count and where to look; `pinakes-ingest totals`, on the
server, names each such root with the date and the `retire-root` to run. A batch with no `roots` (an agent before
release 6) changes nothing; a `roots` that isn't a list of labels holding the batch's own root is refused.
`upgrades/unreported-roots.sql`, after `owner-by-uid.sql`. Not built: noticing a different machine id (a replaced
machine with the same roots is already handled by `scan --full`), and the line on the operator page, which waits for
10.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15, the only one installed, and the installed wheel
on Python 3.12 (x86-64 desktop; `tests/test_server.py` `TestUnreportedRoots`
on generated trees: a two-root machine replaced by a one-root one under the same name, its left-out root's file still
counted until retired, `/health`, `pinakes releases`' query and `totals`, a batch without `roots`, a root named again,
retire-root and its dry run, a malformed list refused, no root label in `/health` or `releases`, the upgrade against
the schema). Not run on a real tree; not deployed. Fixed after release 6: `totals` printed `unreported_since` as the
session's local date, a day off from UTC's for part of every day; it prints the UTC date now, as the catalog's other
dates are (a test with the session in New York, 02:00 UTC; Python 3.12, PostgreSQL 16.15).

## 47. Growth by folder over time

Design: ROADMAP.md item 47 (built, so no longer listed); no DECISIONS.md entry.

**Built:** `/reports/growth?loc=ROOT:PATH&weeks=N`, with "Growth" in the header (`queries.growth`, QUERIES.md
"growth by folder"): per root and folder one level under the chosen one (no folder: each root's top folders), per week
from its Monday, the files and bytes that came and went in the last N weeks (8 by default), from history, under
row-level security. Each change takes its old size from its old path and gives its new size to its new path, added up
per folder: a change of content counts its difference in size, a move between folders leaves one and comes to the
other, a move inside one counts nothing. A root's first scan is the catalog starting and isn't counted; an unreadable
file isn't a change of size. Each folder links to its own growth. In a step-up it is audited for the owners of the
files counted. At most 2000 rows, said on the page when cut.

**Not as the roadmap said:** "per root and top folder" is the default; a folder can be chosen, as on the changes page.
Bytes are per path, so a new hard link counts again (history has no inode). No API call or CLI command yet.

**State:** Tested on Python 3.12.3 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_web.py` `TestWeb`): the first
scan, then three scans dated two weeks ago, last week and this week (new files, a change, a move between folders, a
delete), with the exact weekly rows for two people under a folder and at the root's top, the other person's files
absent, a shorter window, the page, and a step-up view in the other person's access list (checked to fail without the
first-scan rule and without the audit); all 410 tests pass. Other Pythons and PostgreSQL versions not run; not tried in
a browser; not run on a real catalog; not deployed.

## 48. A fast home page on a large catalog, (a) and (b)

The open part (c) is not planned: HORIZON.md 48.

**Measured** on 2026-11-16 (generated catalogs, 8 roots on 3 hosts, 40 ACLs, 10% gone, 5% hidden; PostgreSQL 16.15
with default settings and fsync off, warm cache; x86-64 desktop, 24 threads; Python 3.12; the first deployment's size
and hardware not checked), home page queries, median:

| Files | Before | (a) policy wrapped | (a) + (b) one pass, as built |
| --- | --- | --- | --- |
| 200k | 68 ms | not run | not run |
| 2M | 1.3 s | 1.2 s | 0.18 s |
| 10M | 79 s (user-1), 39 s (user-2) | 12.6 s | 1.3 s |

At 10M the planner had switched to the `files_acl` index with `visible_acls()` as its condition, reading every file the
person may see, in every root, for each of the 16 counts; JIT made no difference.

**Built:** The `files` policy evaluates `visible_acls()` once per query, wrapped in `(SELECT ...)` as `token_roots()`
was (bare, a large catalog's plan called it per row); `queries.roots()` counts every root in one grouped pass instead of
two counts per root; `upgrades/files-policy.sql`, after `scrub.sql`, which check-in and `pinakes releases` list as
missing until it has run.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py`
`TestGroupToken`): every root's counts equal a count per root, and the numbers stated, for two people, a person with
none, a person's token, a group token and a token for one root, hidden shown and not; the upgrade against the schema,
alone and after `api-tokens.sql`. Home page queries on generated catalogs (8 roots, 40 ACLs, warm cache), median: 2M
files 1.3 s to 0.18 s, 10M files 79 s to 1.3 s, the counts unchanged. Not run on a real catalog; not deployed.

## 49. Token forms a password manager can fill

Found at the first deployment.

**Built:** On the account page, both token forms have a hidden `autocomplete="username"` field with the person's name
before the password (not sent), and `autocomplete="off"` on the client and days fields; a token form's message and new
token are shown next to that form, which jumps there (other messages, and a forged ops-token post from someone who has
no ops form, stay at the top); a days field that isn't a number is now said to be one.

**State:** Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15, the only one installed (x86-64 desktop;
`tests/test_api.py` `TestOpsToken`, checked to fail without the change). Not tried in a browser with a password manager;
not deployed.

## 50. A web page for folder copies

Design: ROADMAP.md item 50 (built, so no longer listed); no DECISIONS.md entry.

**Built:** `/reports/folder-copies?loc=ROOT:PATH`, with "Folder copies" in the header: the query of
`pinakes folder-copies` (`queries.folder_copies`) as a table beside Duplicates and Only here, one row per folder with
its relation (same, inside, nearly), the folder it is a copy of (both link to their listing), file counts, the files
only on either side, the size, and the edited files named. Sortable by folder, relation, files and size, and paged,
as the other reports are (`queries.FOLDER_COPIES_SORT`); a location that isn't ROOT:PATH is said, as there. In a
step-up it is audited for the owners of the folders shown (`queries.folder_owners`). Like the query, it reads the
whole catalog per call; the page says to ask about a folder, not a large root.

**State:** Tested on Python 3.12.3 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_web.py` `TestWeb`): the three
relations with the edited file named, 58 rows over pages of 50 with none twice and none missing, every sort column
both ways, another person's folders absent until a step-up and then listed with the access shown to them (checked to
fail without the audit); all 408 tests pass. Other Pythons and PostgreSQL versions not run; not tried in a browser; not
run on a real catalog; not deployed.

## 51. The agent reports its runs to a push monitor

Design: ROADMAP.md item 51 (built, so no longer listed); SECURITY.md "Agents".

**Built:** An optional `[monitor] url_file` in `agent.toml`, the path of a file whose first line that isn't empty or a
comment is a push monitor's URL; a config with `url` itself, or a relative path, is refused. Every `pinakes-agent run`,
by timer or by hand, ends by calling it (`pinakes/monitor.py`, standard library, 10 s): `status=up` with
`N root(s) scanned, N files seen, N error(s); N batch(es) sent, N waiting` (or the skip, "on battery" or "busy"; "the
server didn't answer" added when check-in failed), `status=down` with `exit N:` and the reasons (a root not found, most
of a root missing, the scrub's file, locked with both sides' protocols, sending stopped) or `crashed:` and the
exception's kind, which is still raised. The URL's own `status`, `msg` and `ping` are replaced, the rest kept (the
push form with the state in the query). No path, file name or error text is sent. A missing file, a file without an
http(s) URL, an HTTP error, a timeout or a refused connection is one line on stderr naming the status code or the
error's kind, without the URL, and the exit status stays the run's. Only `run` reports, not `scan` or `send`.

**State:** Tested on Python 3.12.3 (x86-64 desktop; `tests/test_agent.py` `TestMonitor`, against a local HTTP server
on generated trees): up after a good run with the counts, down with the reason after a missing root, after most of a
root gone, and after a crash; up for a skipped run; nothing sent with no setting, no file or no URL in it; HTTP 500,
a 0.3 s timeout, a closed port and a failing call each one line with exit 0; the URL absent from stdout, stderr and
the argv of the processes started (checked to fail with an error's text printed), and refused in the config. All 419
tests pass (tools/test, PostgreSQL 16.15). Other Pythons not run; not run on a real tree against a real push monitor;
not deployed.
