# Roadmap

What is built, what is left to build, and what "done" means for each piece. The design is in DESIGN.md, SECURITY.md,
METADATA.md and QUERIES.md; choices made while building are in DECISIONS.md. Deployment belongs to each site, not to
this repo.

Each open item starts with its category in brackets: *feature* (something new to do), *security* (who sees or does
what), *correctness* (a wrong answer without a crash), *stability* (staying up), *scalability* (bigger trees, busier
machines) or *operability* (installing and running it); "also" names a second.

## How things are tested

- **Agent:** `unittest` on generated trees in a temporary directory; standard library only, so it runs anywhere the
  agent does. Never a real tree in a test.
- **Server:** the same tests against a throwaway PostgreSQL (`PINAKES_TEST_PGHOST`), a fresh database per test class,
  through the real roles (`pinakes_ingest`, `pinakes_app`) so row-level security is exercised, not bypassed.
- **Queries:** every SQL block in QUERIES.md runs as a test (`tests/test_queries.py`), as a person under row-level
  security, on a catalog built by real scans.
- **Web:** Flask's test client against the same throwaway database.
- **`tools/test`** starts that throwaway PostgreSQL itself (a Unix socket in a temporary folder, removed after),
  runs everything, and fails a run that skipped tests for want of a database or a dependency.
- **"Tested" means run, on the stated Python, PostgreSQL, OS and hardware.** Each change says which. A feature that
  touches files on disk also gets a run on a real tree (read-only) before it is called done.
- **Security-relevant changes** (anything that names or shows a file, any new role or function, any new way in) add
  a test that a second person can't see or do it, and that a step-up is audited.

Platforms so far: every test on each of Python 3.10 to 3.15 and PostgreSQL 15 to 18, each once (`tools/test
--matrix`, x86-64 desktop; every pair up to ROADMAP 12); Python 3.10 (ARM64 single-board server, kernel 5.10) for the agent, run for real; PostgreSQL
18 for the first deployment (schema, setup, upgrades and real batches, metadata extracted by its agents).

## Built

| Part | State |
|---|---|
| Agent: walk, state, hashing, birth time (statx), chunks, archive members, protected roots, resumable scans, mass-gone guard, one filesystem per root, progress lines, batches, ssh and directory transports | Tested (3.12, 3.10); run for real on one server |
| Schema: people, groups, ACLs, step-ups, append-only audit, hosts, roots, scans, contents, files, chunks, members, history, lineage, metadata (table only) | Tested on 16; applied on 18 |
| Ingester: sequence and duplicate handling, owners by folder rules and enrollments, backup copies tied to their source (with prefix), moves by hash, inode and chunks, lineage by identical content, chunks and names, recompute after a rule change | Tested on 16; run on 18 with real batches (a first deployment, two scans) |
| Ingester stopping a batch whose sender hung up (its stdout closed) or that runs past `[ingest] max_batch_time`: the running statement cancelled, the transaction rolled back, exit 3 | Tested on 16 (the forced ingester as a subprocess, blocked on a lock) |
| Ingester at scale (1): completing a scan in bulk (the new files' history in one statement, lineage in rounds of 2000 files), a scan's gone paths matched to its new ones by an index; ordinary batches still per record, as the board's time and memory don't ask for more | Tested on 16 (`TestLineageRounds`, `TestMovesSameAsBefore`); run on 18 on a 4+4-core ARM board (DECISIONS.md): 5000-record batches every 6-10 s, peak RSS 65 MB over 202 batches, none failed |
| A walk check for comparing the catalog with the disk: `pinakes-agent check` counts each root with the scan's own walk and the running process's rights, beside the last scan, with what changed since it started and errors by kind; `pinakes-ingest totals` gives the catalog's per root, every owner's; no file names in either | Tested (3.12; the comparison on 16); done by hand on one server before it was built: every root matched its last scan |
| `/health` without sign-in for monitoring (database reachable; per host its newest batch, last complete scan and staleness; 200 or 503; host names only), also alone on `[web] health_listen` | Tested with the test client on 16; served by waitress on both listeners on the desktop |
| Queries (QUERIES.md), physical copies by host, device and inode | Tested on 16 |
| Reviewing changes (32): gone files and moves marked *intended* or *restore*, by row or in bulk (the changes filters, seen up to a date, optionally only gone files still in another root, not a backup); unreviewed counts in the tree, a reviewed / unreviewed filter; a gone file's other copies and backups, or "may be lost"; a restore list naming the backup and snapshot, cleared when the content is back in the root (a move: at its old path); marks only through `mark_changes()`, by owners and co-owners, or an administrator in a step-up (audited); `upgrades/review-marks.sql` for older catalogs | Tested on 16 (queries under row-level security, the web forms with the test client); tried in a browser on the demo catalog (waitress); deployed on 18 (`upgrades/review-marks.sql` applied to the first deployment), no mark made there yet |
| Only-here and safe-to-delete count a copy only on another disk (another host, or another device of the host); copies on the file's own disk shown apart; a hard link no copy (5) | Tested on 16, under row-level security; web and CLI wording |
| Protection by inode (6): a hard link of a protected file in another root of the same agent is protected there too (no archive listing, chunks only if the protected root makes them, a listing made before the link dropped, the file's page says so); the agent walks its protected roots for links only when a scan meets a file with more than one link; `upgrades/protected-links.sql` for older catalogs | Tested (agent on 3.12; ingester, row-level security, upgrade and web on 16) |
| Symlinks tied to their targets (7): the agent resolves each link's target name by name, looking names up only inside its own roots (root and path, dangling or not, a loop dangling); a target appearing or going resends the link; moved links matched by inode only when they still lead to the same place, else by target and name; `only-here` and `safe-to-delete` leave links out, and safe-to-delete lists the links elsewhere that lead into the folder; a link's page links to its target where the person may see it; `upgrades/symlink-targets.sql` | Tested (agent on 3.12; ingester, row-level security, upgrade, CLI query and web on 16) |
| Packaging and a test matrix (27): `tools/test` starts and removes its own PostgreSQL and fails a run that skipped tests for want of a database or a dependency; `--matrix` (each Python on the newest PostgreSQL, each PostgreSQL on one Python; `full`: every pair, side by side with `--jobs`); `--wheel` builds the sdist and wheel from a clean copy of the tree, installs the wheel in a new environment and runs every test against it. No release is published (not decided) and the version is still 0.1.0.dev0 | Every pair of Python 3.10.22, 3.11.18, 3.12.3, 3.13.18, 3.14.9, 3.15.2 and PostgreSQL 15.19, 16.15, 17.11, 18.6: 148 tests OK (x86-64 desktop); the wheel, installed, on 18.6 |
| The metadata schema registry (12): `pinakes/schemas/*.toml` (Dublin Core, the common fields, first) and a site's in `[metadata] schemas`, validated with a message naming the file and key; `pinakes-ingest setup` makes a partial index per indexed field through `enroll_metadata_indexes()` and drops those no schema wants; `upgrades/metadata-indexes.sql` for older catalogs | Tested on Python 3.10 to 3.15 and PostgreSQL 15 to 18 (the lean matrix, x86-64 desktop; the wheel, installed, on 18.6): loading and refusals, the indexes serving searches, the function's refusals and grants, the upgrade; applied on the first deployment (PostgreSQL 18) with its indexes |
| Extractors (13), first part: EXIF and embedded XMP from JPEGs on the agent, standard library only (`pinakes/exif.py`, `pinakes/xmp.py`, `schemas/exif.toml`, `schemas/xmp.toml`; XMP's ids declared as identity fields for 15, its people and places sensitive; XML with a DOCTYPE or entities refused); extracted metadata in batch format 2 (`meta` on a file record), read once per content per agent and again when a schema's version changes, never on a protected root or link; the ingester checks it against the registry, keeps it on the content with its version and host, and refuses it from protected roots and links; sensitive fields (GPS, people, places) kept apart for owners only (16's first part); `upgrades/metadata-extracted.sql` | Tested on each of Python 3.10.22 to 3.15.2 and PostgreSQL 15.19 to 18.6 once (`tools/test --matrix`, x86-64 desktop), on generated JPEGs. Its first run on a real tree skipped photos whose agent state predated the file type (`27650a5`): fixed in `d753d9f`, tested on a state written by that older agent. Run for real with the fix on the first deployment's agents: 86,608 of 87,325 JPEGs have EXIF (717 without, not looked into yet); 83,176 exif and 40,546 xmp rows; nothing from a protected root or link; no metadata left out; five photos' camera and date taken read correctly (not compared with a photo viewer) |
| Sensitive metadata for owners only (16, first part): GPS, people shown and place names in rows of their own (`metadata.sensitive`), visible through `sensitive_visible()` to the owners and co-owners of a copy or an administrator in a step-up, not to readers; exif and xmp at version 2 send them; `upgrades/metadata-sensitive.sql` | Tested on each of Python 3.10 to 3.15 and PostgreSQL 15 to 18 once (x86-64 desktop): owner, co-owner, reader, a copy of one's own, step-up, a search by place, the upgrade; the tests checked to fail without the policy. Deployed: 12,695 sensitive exif rows (GPS) and 2 xmp; a second person sees exactly the sensitive rows of the photos they own or co-own (2,889 of 2,889) |
| Metadata on a file's page and in find (16, showing it): each schema's fields with source, version and date, all sources when they disagree, sensitive ones tagged and shown only where `sensitive_visible()` allows (a note otherwise, the same with or without them); a step-up that showed them audited as such; find by name, "made by" (`creator`) and "dated" (`date`) over every schema's mapping, each through its own index, under row-level security | Tested on each of Python 3.10 to 3.15 and PostgreSQL 15 to 18 once (x86-64 desktop), with the test client on generated JPEGs: owner, reader, step-up and its audit, find under row-level security, the indexes used, markup in a value; the reader tests checked to fail without the policy; deployed on the first deployment; not tried in a browser |
| Hidden files: the agent marks a file hidden by a dot in its path or by Samba's hidden attribute (`user.DOSATTRIB`, every version Samba writes) on it or a folder above, read once per folder per scan; a change of attribute alone resends the record without rehashing; the ingester also marks a dot-name from an agent that doesn't say, and a moved file takes its new path's; browse and find leave them out until a person shows them for the session (browse says how many it left out), reports count them; `upgrades/hidden-files.sql` | Tested on each of Python 3.10 to 3.15 and PostgreSQL 15 to 18 once (x86-64 desktop, ext4): the attribute set with real xattrs on generated files, its parser on values from Samba 4.19.5's own encoder (no smbd: never written by a Windows client); the ingester, the upgrade and the web toggle with the test client. Deployed, `upgrades/hidden-files.sql` applied: dot-names marked on every root, a protected root's from names alone; no file there has Samba's hidden attribute, so the attribute is still tested only on generated files; not tried in a browser |
| CLI | Run by hand on a demo catalog |
| Releases and check-in: `RELEASES.toml` (releases 1 and 2 backfilled: the server and agents live when releases began, protocol 0; 3, the first with a protocol, cut 2026-11-12, not deployed; a release is cut only by its tag, when the owner says), `pinakes/compat.py` (release, protocol, the oldest agent and server each side works with), `tools/latest-release ROLE`; a test fails if the batch fields, the agent's state or the schema change and the protocol doesn't; `pinakes-ingest hello` through the agent's forced key; the agent locks (scans on, sends nothing, one line, exit 4) and unlocks by itself; the ingester refuses a batch outside its range, and takes one with no protocol as 0; `pinakes --versions`; `upgrades/checkins.sql` | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (the only one installed there; 15, 17 and 18 not run), and from the wheel (x86-64 desktop), the fingerprints the same on each: the agent against a stand-in ssh (too far ahead, ahead but compatible, behind, a server from before check-in, unreachable, unlock with the held batches), the ingester and its refusals, the upgrade against the schema, and one run through a stand-in forced key into the real ingester. Not deployed; not run against a real sshd |
| Commands from inside a folder (33): `where`, `history`, `versions` and `lineage` take a file, `only-here`, `safe-to-delete` and `backed-up` a folder or a file, `changes` and `backups` a folder: a path here (none: the current folder) or `ROOT:PATH`, a path that exists here taken as one; found among the roots this machine reports (`--host`, else `[client] host`, else `[agent] host`, else its hostname), a file's own name kept as it is (a symlink is itself); `changes` with no folder outside every root shows everything, and says which; bare `pinakes` sums up the current folder (files, with no backup, with no copy on another disk, changes in 7 days) and prints usage outside a root; the folder reports, given a file, answer for the file (before, a file matched nothing under it, which read as safe), on the web too; `--backups` became `backups` (35) | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py` `TestCliHere`, the CLI against a real HTTP server on 127.0.0.1): each command from inside a folder and given one, by path and as `ROOT:PATH`, a file for a folder report, a folder for a file command, outside every root, another person's files, the summary and usage; the web's file-for-a-folder answer in `tests/test_web.py`. Not run on a real catalog; not deployed |
| `--as NAME` (36): one hidden prompt for NAME's password or a token of theirs (checked to be theirs by `whoami`), and for a password their second-factor code (empty if they have none); the password through `POST /api/v1/session`, checked as the web sign-in checks it plus the second factor when the person has one, a failure counted in the web sign-in's own per-address limit; the answer a `read` token of 10 minutes (`begin_cli_session()`), every root but the protected ones, kept in memory only, revoked by `POST session/end` when the command ends, never listed among the person's tokens; the caller's own token not read; audited for the person as a sign-in from the CLI with its address, and each call as theirs | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py` `TestCliAs`, the CLI against a real HTTP server on 127.0.0.1, the prompts answered by the test): the named person's files and not the caller's, nothing written, the session revoked and unlisted, the second factor, wrong secrets and the shared limit (the web sign-in held too), a token of theirs and one not, no step-up, the entries on their page. Not run against a real catalog; not deployed |
| Reviewing from a folder (37, first part): `pinakes review intended|restore [PATH]` lists the unreviewed gone files and moves under the folder (or of the file, `ROOT:PATH` for one already gone) in the last `--days`, asks, and marks them through `POST /api/v1/review` (by the ids it showed, scope `review`); `--yes` without asking, and without a terminal only with it; says how many of how many were marked; `mark_changes()` refuses a token without the scope and skips changes outside the token's roots (it reads files as the schema's owner, so the policy didn't reach it); the API's `changes` takes `review` and `what`, and `changes` a file's own path | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py` `TestCliReview`, the CLI against a real HTTP server on 127.0.0.1): the owner from inside the folder, asked and declining, then marking; one gone file by `ROOT:PATH`; `--yes`; a co-owner marking, a reader's skipped; a token without the scope refused by the API and by the database; a token limited to another root marking nothing of the store, even by ids (checked to fail without the check); the marks on the web's Changes and restore pages. Not run against a real catalog; not deployed |
| Ops tokens and `pinakes releases` (39): an ops token is made by an operator on the account page (the current password again, a client name, a lifetime), scope `ops` alone, no root list; it acts as no person (`begin_token_call()` sets none, so row-level security shows it no file), answers `releases`, `stale` and `whoami`, and every other call refuses it; its calls are its maker's record; `GET /api/v1/releases` gives what `pinakes --versions` read from the database; `pinakes releases` prints it as before, and `pinakes --versions` now only says where it went; a site's deploy checks change with this release | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop), and from the wheel on 3.12: `tests/test_api.py` `TestOpsToken` (made by an operator and refused to anyone else, by the page and the database; ops alone and no roots; `releases` and `stale` answered and every other route refused, a person's token refused `releases`; no person in the database, no file seen, `mark_changes()` refused; its calls on its maker's record) and the check-in and takeover reports in `tests/test_server.py` through `pinakes releases`. Not run against a real catalog; not deployed, and the first deployment's checks still call `pinakes --versions` |
| Group tokens (38): a token of kind `group` acts as its group and no member: `begin_token_call()` sets no person, `current_group()` names the group, and `visible_acls()` gives the ACLs the group owns or is enrolled in (`acl_groups`, written by the ingester beside `acl_members`), never a member's own; scopes and roots as a person's token; made on the account page by a member of the group ("Asks as"), listed for every member, revocable by any, and it stops working once its maker leaves the group; its calls, making and revoking are on every member's record; it marks only where the group is the owner or a co-owner, the mark the group's (`review_marks.marked_by_group`), audited with the token for every member; sensitive metadata where the group is the owner or a co-owner; `api-tokens.sql` fills `acl_groups` from each ACL's key. Tags wait for 37 | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py` `TestGroupToken`): the group's files and no member's own, by the API and in the database; a non-member refused making, seeing and revoking one, by the page and the database; a former member's token refused and theirs no more to list or revoke; its marks the group's, refused where it only reads or a member owns, shown as the group's on the web and the API; its calls on every member's access page; sensitive metadata; the upgrade against the schema, with a group's ACLs. The membership and mark checks checked to fail without them. Not run against a real catalog; not deployed |
| The JSON API and person tokens (34): `/api/v1/` in `pinakes-web` over the CLI's queries (`whoami`, `roots`, `find`, `where`, `only-here`, `safe-to-delete`, `backed-up`, `dupes`, `history`, `versions`, `lineage`, `changes`, `meta`, `stale`), GET only, by bearer token, never the session cookie; tokens made on the account page (the current password again, a client name, scopes `read`, `review`, `tag`, every root but the protected ones or the roots ticked, a lifetime or none), shown once, kept as SHA-256, revoked there, last use shown; `begin_token_call()` sets the person and records every call for them (their access page); row-level security holds files to the token's roots; a token never steps up (`stepped_up()` false, `begin_step_up()`, `make_token()` and `revoke_token()` refused under one); refused tokens limited per address; `upgrades/api-tokens.sql` | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15, the only one installed (x86-64 desktop; `tests/test_api.py` within the full run; the root test checked to fail without the policy); 15, 17 and 18 not run. Not tried in a browser or against a real catalog; not deployed |
| `pinakes` as a client of the API (35): standard library only (`urllib`), no database driver or server config; the catalog's address from `[client] url` (`~/.config/pinakes/client.toml`, `$PINAKES_CLIENT_CONFIG` or `/etc/pinakes/client.toml`) or `--url`, https or http to this machine only, `[client] ca_file` for a site's CA; the token from the first of a `.pinakes-token` in the current folder or one above it and `~/.config/pinakes/token`, a token file not the user's own, not a plain file or readable by anyone else refused, not skipped; every action a subcommand (`backups`); `--as` gone until 36; `--versions` stays on the server, from `server.toml` and the database with no person, until 39; API calls `host-roots` and `backups` for the folder commands | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (x86-64 desktop; `tests/test_api.py` `TestCli` and the moved CLI tests in `tests/test_server.py`, against a real HTTP server on 127.0.0.1 in the test; once with psycopg made unimportable), and from the wheel on 3.12. Not run against a real catalog or over https; not deployed |
| Backup roots without churn (no history, gone rows deleted, link-count and ctime changes not sent); name lineage only with a second signal (a folder name only when rare; signs kept in names); `pinakes-ingest tidy` for catalogs built before them | Tested on 16 (agent part on 3.12); run for real on 18: a hard-linked snapshot root of ~100k files sent about 100k records a night before, and after it only each new snapshot's files plus one gone per pruned file (two nights: 3,688 and 14,753), matching the snapshots made and pruned |
| The scrub (41; DESIGN.md "Scrub"): after the scans, each filesystem under the agent's roots has its least recently verified files read again and their hashes checked, up to its share (its bytes × time since its last scrub ÷ `days`, at most seven nights'; `[agent] scrub_max_minutes`); `scrub.toml` written by the agent (filesystems by UUID through `/proc/self/mountinfo` and `/dev/disk/by-uuid`, else the mount source; `days = 30`, 0 for network filesystems), new ones appended, never rewritten; a hard-linked inode read once; `verified` and `scrub_error` in the agent's state; a scrub batch per root (its summary, `mismatch`, `unreadable`, `readable`), sent only to a server of protocol 3 (release 6, not cut); the ingester gives a mismatch its new content and a history row of its own (none in a backup root), marks an unreadable file, which no copy query counts until it reads; both reviewable (`mark_changes()`, the changes page and tree, `pinakes review`, the restore list); `/health` per host the oldest check and whether the scrub is behind (503); `pinakes-agent scrub [status]`; `upgrades/scrub.sql` | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15, the only one installed (x86-64 desktop, ext4; `tests/test_scrub.py` on generated trees with a mount table and by-uuid folder made by the test, `tests/test_server.py` `TestScrub`): a flipped byte under a kept mtime a mismatch and not an edit, an edit left to the scan, a read error sent once and its clearing, days 0, the budget and the cap, the time limit, a hard link, an interrupted run, a protected root, chunks, the file written, appended and a changed number kept, unwritable; in the catalog the history row, copies no longer counted, review and restore, another person not seeing it, a reader not marking it, /health, the upgrade against the schema. The copy and hash checks checked to fail without them. Not run on a real tree or against real disks; not deployed |
| Web UI: sign-in (scrypt), TOTP enrollment, step-up with reason and code, audit of what a step-up showed, "Access to your records", browse, find, a file's page (copies, versions and the backups holding them, history, lineage), reports (only here, safe to delete, backed up, duplicates, changes with a folder tree of new, changed, moved in, moved out and gone, filtered by kind and folder), paging, sorting by column (in SQL), behind a proxy | Tested with the test client on 16; served for real behind a proxy, no sign-in yet |

## Next: before more machines join

Found by the first deployment (one storage server, 445k files, two nights), and needed before a backup server joins
(1, the ingester on a small server, 28, backup roots without churn, 29, name lineage with a second signal, 30, a
walk check with the agent's rights, 31, an ingester stopping when its agent gives up, and 4, a health endpoint, are
built; see the table above; 3, `inhibit_sleep`, is gone, as the unit or the site keeps the machine awake; 5, same-disk
copies, found when the first deployment's backup roots turned out to share their source's disk, is built):

2. [Security; also correctness] **Owner rules by uid.** `uid_map` is read but no rule uses it. Either rules gain an
   `owner = "uid"` form that maps the file's uid through the host's map, or the option goes. *Done when:* a test gives
   two files of two uids on one host to two people through the map, and a server whose clients are all one account still
   works by folder rules. The first deployment's shares all write as one account, so uids decide nothing there yet; they
   will once people write as themselves (per-person Samba accounts, no `force user`). Keep `uid_map`; build this then.

## The web UI, read-write

8. [Feature; also security] **Owners and enrollments per folder:** give a folder away, enroll people as co-owners,
   readers or annotators, a preview of how many files change hands before saving, audited and shown to the people
   affected. *Done when:* tests cover a person giving their own folder away, being refused someone else's, an
   administrator taking one only in a step-up, and the preview's count matching the result.
9. [Feature; also correctness] **Lineage decisions:** confirm or reject a likely or possible relative; a decision
   outranks every heuristic. *Done when:* a rejected edge disappears from walks and is never re-added by a later scan,
   and a confirmed one survives a recompute.
10. [Operability] **Operator page:** counts, sizes, ages and errors per root, no file names. *Done when:* a test shows
    an operator sees totals for another person's root and no path from it.
11. [Security] **Notifications** when an administrator saw someone's records: a pluggable command (an e-mail, a push
    service), off by default. *Done when:* a test with a stand-in command gets one message per step-up per person, with
    the reason and no file names.

## Metadata (METADATA.md)

13. [Feature; also security] **Extractors, one schema at a time:** EXIF and embedded XMP (JPEG) are built (table
    above); then XMP sidecars (with 14) and extended XMP, audio tags, OPF, PDF and office properties, video. Each optional by its dependency. *Done when, for each:* tests on generated
    files (made by the test, never real ones) extract the declared fields; a missing dependency turns the extractor off,
    not the scan; nothing runs on a protected root (a test proves it). Left from the first real run: 717 JPEGs without
    EXIF, not looked into. They may hold none, or a form the reader refuses; the catalog keeps no extraction error,
    so it can't tell which.
14. [Feature; also correctness] **Bundles and pairing**, per schema's rules. *Done when:* tests cover a photo with each
    sidecar form, RAW with JPEG, a book folder, and a bundle moved together counting as one move.
15. [Correctness] **Identity fields for lineage** (PDF `/ID`, XMP `DocumentID`/`InstanceID`/`DerivedFrom`, EPUB
    identifier). *Done when:* two renamed, edited files sharing an identity field are linked with certainty in a test.
16. [Feature; also security] **Person-entered metadata and sensitive fields** in the UI. Sensitive fields are kept
    for owners and co-owners only, and shown on a file's page and in find (built, table above); left: entering
    metadata, and an owner sharing sensitive fields with a reader. *Done when:* a shared file shows its non-sensitive fields to the
    other person and hides the sensitive ones unless shared too.

## Managing files (DESIGN.md "Managing files")

17. [Feature; also stability] **The operation queue:** request, approval, the agent fetching approved operations for its
    roots, carrying them out within its local `managed` policy, reporting results. Move and rename first, then trash.
    *Done when:* tests cover every refusal (file changed since the request, outside the local policy, someone else's
    file without approval, a would-be overwrite) and a crash mid-operation leaving either the old state or the new,
    never neither.
18. [Feature] **Linking same-disk duplicates** (DESIGN.md "Planned"), after 17. *Done when:* the same refusals plus:
    different owners, unsettled content, a protected or drop or backup root; the replaced inode reaches the trash; undo
    by copy is documented and tested.

## Sources and imports

19. [Feature; also correctness] **Checksum manifests** (`SHA256SUMS` files) as hints, checked on the next scan, never
    trusted. *Done when:* a test finds a wrong line reported and a right one confirmed.
20. [Feature] **Another catalog's checksums** (a photo library's SHA-1s), for files the agent doesn't see. Needs SHA-1
    as an extra hash on the roots that hold the library's originals. *Done when:* a test matches by SHA-1 and reports
    the library's files that no root holds.
21. [Feature] **A restic repository as a backup source** (`restic ls --json`: paths, sizes, times; no whole-file hashes,
    so matches are by path, size and mtime, marked lower confidence). *Done when:* a test with a stand-in `restic`
    answers "which snapshot holds this version" for a primary file.

## Accounts and hardening

22. [Security] **WebAuthn** as a second factor; **OpenID Connect** sign-in. *Done when:* each has its own tests, and
    step-up accepts each factor it is configured for.
23. [Security] **Rate limits on search, audit retention, removing a person** (their records, shares and sessions go;
    audit entries about them kept for the retention period). *Done when:* tests cover each.

## The command line, through an API

Today `pinakes` connects to the database with the web role's password and acts as whoever `--as` names, so it runs
only on the catalog server. The plan (DECISIONS.md "The CLI and the API"): every person-facing function goes through
one API in `pinakes-web`, with one way to authenticate, and `pinakes` becomes a client of it that runs on any machine
and works where you are. Agents' batches stay on their forced SSH keys, and server maintenance stays a local command
(`pinakes-ingest`). 34, the API and person tokens, 35, `pinakes` as its client, 33, its commands from inside a
folder, 36, `--as`, reviewing from a folder (37's first part), 38, group tokens, and 39, ops tokens and
`pinakes releases`, are built (table above). In order:

37. [Feature; also security] **Tagging from a folder.** Reviewing from a folder is built (table above); left:
    `pinakes tag` and notes, once person-entered metadata exists (16), with the token's `tag` scope. *Done when:* tests
    cover an owner tagging from inside a folder, a reader refused, a token without the scope refused, a root outside
    the token's limit refused, and the tags shown in the web UI.
40. [Security] **A protected admin API** (later): admin tokens with every function (`*`), each call audited; another
    person's records still only in a step-up, logged where they can see it, as on the web. Until then administration
    is the server's local CLI. *Done when:* tests show an admin token refused another person's records without an
    active step-up, and every call in the audit.

## Proposed (from a review of the whole project; not yet agreed)

Things a catalog's users would expect that nothing above lists. Each fits next to something built; none is started
(41, the scrub, was agreed and is built: table above).
Ranked by value over cost (cost: S half a day or less, M a day or two, L more).

42. [Feature; also operability] **What a disk's loss would cost.** `only-here` answers for a folder; nobody asks
    folder by folder before a disk fails. One report per device: how much has no copy on another disk, by owner and
    by top folder, with the largest folders first, and the same per host ("if this machine burned"). On the operator
    page as totals without names (10), and for a person, their own files with names. Sits next to: only-here and
    safe-to-delete counting a copy only on another disk (5); the operator page (10). Value: high. Cost: S (the
    queries exist; this is aggregation). Risk: none. *Done when:* a test with two devices and one backup root gives
    the sizes at risk per device, an operator sees totals and no path, and a person sees only their own.
43. [Feature] **Folders that are copies of each other.** `dupes` works file by file; when tidying, the question is
    "is this folder the same as that one, or contained in it". From content hashes already stored: pairs of folders
    whose file sets are equal, or where one holds everything the other does, with what differs. Sits next to:
    `dupes`, lineage by identical content, linking same-disk duplicates (18). Value: high for a store that grew by
    copying. Cost: M (a set comparison that must not be quadratic: compare folder digests built bottom-up). Risk: a
    slow query on a large root; compute it at scan completion, as lineage rounds are. *Done when:* tests cover equal
    folders, a subset, a folder with one edited file (reported with the difference), and empty folders ignored.
44. [Operability; also correctness] **Extraction outcomes kept.** The first real run left several hundred images
    with no EXIF and no way to tell "has none" from "the reader refused it" (13). Record per file and extractor:
    ran, found nothing, refused with a reason code, or skipped for a missing dependency; counts on the operator
    page. Sits next to: extractors (13), the schema registry (12). Value: medium. Cost: S. Risk: none; reason codes,
    never file content. *Done when:* a test with a truncated image records a refusal, one without metadata records
    "nothing", and the counts match.
45. [Feature; also security] **A person's export of their own records.** Everything the catalog holds about my
    files (paths, hashes, history, metadata, reviews), as CSV or JSON, through the API with the token's `read`
    scope. A catalog that describes people's files should hand them their description. Sits next to: the JSON API
    and person tokens (34), removing a person (23). Value: medium. Cost: S. Risk: row-level security must apply
    exactly as for a query: the export is a query, not a dump. *Done when:* a test exports one person's records and
    finds none of a second person's, sensitive fields only where `sensitive_visible()` allows, and the export in the
    audit.
46. [Operability] **A machine replaced under the same name.** When new hardware takes over a host's name with fewer
    roots, the old machine's files in roots the new one doesn't have stay "present" until someone retires each root
    by hand, and until then they count as copies. `retire-root` exists (DECISIONS.md); missing is noticing: a host
    whose agent reports a different machine id or root set gets a line on the operator page and in `/health`, with
    the command to run. Sits next to: check-in and releases, `/health`'s staleness, `retire-root`. Value: medium
    (a wrong "there is another copy" is the catalog's worst answer). Cost: S. Risk: none (it reports; retiring stays
    a command). *Done when:* a test with a host whose second scan lacks a root it had shows the warning, and
    retiring the root clears it.
47. [Feature] **Growth by folder over time.** History is kept to the day; "what grew this month, and where" is one
    query away and listed in DESIGN.md's reports ("a root's growth") without an item here. Per root and top folder,
    bytes and files added and gone per week. Sits next to: history, the changes page, the operator page. Value:
    medium. Cost: S. Risk: none. *Done when:* a test with three dated scans gives the right weekly deltas, per
    person under row-level security.
48. [Scalability; also security] **A fast home page after sign-in.** Signing in is one scrypt check (a few tenths
    of a second, by design); the page it lands on counts every present file of every root twice, all and hidden,
    under row-level security, on every visit (`queries.roots()`). In two steps, measuring first:
    (a) EXPLAIN ANALYZE the home page's queries on a generated catalog the size of the first deployment's. The
    `files` policy calls `visible_acls()` bare while `token_roots()` is wrapped as `(SELECT ...)`; if the function
    runs per row, wrapping it too runs it once per query, for every page and not only this one. Stop here if that
    is enough.
    (b) Otherwise keep the counts: present files and bytes per root, ACL and hidden flag, rewritten for a root when
    its scan completes (where `last_complete_on` is set) and for the roots a batch, a retire-root or an ACL change
    touched; under the same policy as `files`, so the home page sums the few rows a person may see and gets exactly
    today's numbers, for a person, a group token or a token held to some roots. Keyed by ACL, a change of group
    membership needs no rewrite. Not one total per root: totals differ by person, and a shared number would tell a
    person how many files others have. `upgrades/root-counts.sql` fills it once. Sits next to: hidden files (the
    count left out), the operator page (10), growth (47), which could read the same table. Value: high (every
    sign-in). Cost: S for (a), M for (b). Risk: counts going stale when a write path forgets them. *Done when:* the
    home page's numbers equal a live count for two people, a group token and a token held to some roots, hidden
    shown and not, after a full scan, a partial batch, a retire-root and an ACL change; and the page's time on the
    generated catalog is stated before and after.

## Later, or a wish

24. [Feature; also security] **MCP server** over the read-only queries (DESIGN.md "Wish"), on the API and tokens of
    34, `read` scope only. *Done when:* tests show a
    token acting as one person under row-level security, never stepping up, leaving protected roots out unless added,
    and every query logged.
25. [Scalability] **A live watcher** (fanotify) on a busy server, beside the nightly scan.
26. [Feature] **Single-machine mode** (SQLite, no people).
