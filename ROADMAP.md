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
| Releases and check-in: `RELEASES.toml` (releases 1 and 2 backfilled: the server and agents live when releases began, protocol 0; 3, the first with a protocol, prepared and not cut; a release is cut only by its tag, when the owner says), `pinakes/compat.py` (release, protocol, the oldest agent and server each side works with), `tools/latest-release ROLE`; a test fails if the batch fields, the agent's state or the schema change and the protocol doesn't; `pinakes-ingest hello` through the agent's forced key; the agent locks (scans on, sends nothing, one line, exit 4) and unlocks by itself; the ingester refuses a batch outside its range, and takes one with no protocol as 0; `pinakes --versions`; `upgrades/checkins.sql` | Tested on each of Python 3.10 to 3.15 with PostgreSQL 16.15 (the only one installed there; 15, 17 and 18 not run), and from the wheel (x86-64 desktop), the fingerprints the same on each: the agent against a stand-in ssh (too far ahead, ahead but compatible, behind, a server from before check-in, unreachable, unlock with the held batches), the ingester and its refusals, the upgrade against the schema, and one run through a stand-in forced key into the real ingester. Not deployed; not run against a real sshd |
| CLI from inside a folder (33, first part): `pinakes --backups [FOLDER]` finds the root holding the current folder from this machine's name (`--host`, else `[agent] host`, else its hostname) and the roots the catalog says it reports, then lists the folder's files, least backed up first (50 shown, the rest counted; `--json`); `--as` defaults to `$PINAKES_PERSON`, then the login name | Tested on Python 3.12.3 and PostgreSQL 16.15 (x86-64 desktop; `TestHardLinks.test_cli_backups_from_inside_a_folder`, within the full run): from inside the folder and given it, the whole root, another person's files left out, outside any root, inside a backup root. Not run on a real catalog or a second Python or PostgreSQL |
| Backup roots without churn (no history, gone rows deleted, link-count and ctime changes not sent); name lineage only with a second signal (a folder name only when rare; signs kept in names); `pinakes-ingest tidy` for catalogs built before them | Tested on 16 (agent part on 3.12); run for real on 18: a hard-linked snapshot root of ~100k files sent about 100k records a night before, and after it only each new snapshot's files plus one gone per pruned file (two nights: 3,688 and 14,753), matching the snapshots made and pruned |
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

## The command line

33. [Feature] **The other commands from inside a folder.** `--backups` is built (table above); the rest take
    `ROOT:PATH` and should default to the current folder the same way: `where` (every copy of a file), `only-here`,
    `safe-to-delete`, `history`, `versions`, `lineage`, `changes`, and a short summary with no command. Needs a choice
    of flag or subcommand form (`pinakes --backups` today). *Done when:* each has a test run from inside a folder and
    given one, a folder outside every root refused, and another person's files left out.

## Later, or a wish

24. [Feature; also security] **MCP server** over the read-only queries (DESIGN.md "Wish"). *Done when:* tests show a
    token acting as one person under row-level security, never stepping up, leaving protected roots out unless added,
    and every query logged.
25. [Scalability] **A live watcher** (fanotify) on a busy server, beside the nightly scan.
26. [Feature] **Single-machine mode** (SQLite, no people).
