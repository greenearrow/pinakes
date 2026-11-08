# Roadmap

What is built, what is left to build, and what "done" means for each piece. The design is in DESIGN.md, SECURITY.md,
METADATA.md and QUERIES.md; choices made while building are in DECISIONS.md. Deployment belongs to each site, not to
this repo.

## How things are tested

- **Agent:** `unittest` on generated trees in a temporary directory; standard library only, so it runs anywhere the
  agent does. Never a real tree in a test.
- **Server:** the same tests against a throwaway PostgreSQL (`PINAKES_TEST_PGHOST`), a fresh database per test class,
  through the real roles (`pinakes_ingest`, `pinakes_app`) so row-level security is exercised, not bypassed.
- **Queries:** every SQL block in QUERIES.md runs as a test (`tests/test_queries.py`), as a person under row-level
  security, on a catalog built by real scans.
- **Web:** Flask's test client against the same throwaway database.
- **"Tested" means run, on the stated Python, PostgreSQL, OS and hardware.** Each change says which. A feature that
  touches files on disk also gets a run on a real tree (read-only) before it is called done.
- **Security-relevant changes** (anything that names or shows a file, any new role or function, any new way in) add
  a test that a second person can't see or do it, and that a step-up is audited.

Platforms so far: Python 3.12 (x86-64 desktop) for everything; Python 3.10 (ARM64 single-board server, kernel 5.10)
for the agent; PostgreSQL 16 for the tests, PostgreSQL 18 for the first deployment (schema, setup and real batches).

## Built

| Part | State |
|---|---|
| Agent: walk, state, hashing, birth time (statx), chunks, archive members, protected roots, resumable scans, mass-gone guard, one filesystem per root, progress lines, batches, ssh and directory transports | Tested (3.12, 3.10); run for real on one server |
| Schema: people, groups, ACLs, step-ups, append-only audit, hosts, roots, scans, contents, files, chunks, members, history, lineage, metadata (table only) | Tested on 16; applied on 18 |
| Ingester: sequence and duplicate handling, owners by folder rules and enrollments, backup copies tied to their source (with prefix), moves by hash, inode and chunks, lineage by identical content, chunks and names, recompute after a rule change | Tested on 16; run on 18 with real batches (a first deployment, two scans) |
| Queries (QUERIES.md), physical copies by host, device and inode | Tested on 16 |
| CLI | Run by hand on a demo catalog |
| Backup roots without churn (no history, gone rows deleted, link-count and ctime changes not sent); name lineage only with a second signal (a folder name only when rare; signs kept in names); `pinakes-ingest tidy` for catalogs built before them | Tested on 16 (agent part on 3.12) |
| Web UI: sign-in (scrypt), TOTP enrollment, step-up with reason and code, audit of what a step-up showed, "Access to your records", browse, find, a file's page (copies, versions and the backups holding them, history, lineage), reports (only here, safe to delete, backed up, duplicates, changes with a folder tree of new, changed, moved in, moved out and gone, filtered by kind and folder), paging, sorting by column (in SQL), behind a proxy | Tested with the test client on 16; served for real behind a proxy, no sign-in yet |

## Next: before more machines join

Found by the first deployment (one storage server, 445k files, two nights), and needed before a backup server joins
(28, backup roots without churn, and 29, name lineage with a second signal, are built; see the table above):

30. **A walk check with the agent's own rights,** for comparing the catalog with the disk: run under the same unit
    settings (`CAP_DAC_READ_SEARCH`), print per-root counts and sizes, so a mismatch means a bug, not missing rights.
    *Done when:* a test runs the check on a generated tree and its counts and sizes match the catalog's for that root.

31. **An ingester outliving its agent.** When a send times out the agent closes SSH, but the forced ingester went on
    (three hours, old code, its transaction holding locks), and the next ingest and `setup` waited behind it. The
    ingester should stop when its stdin/stdout closes, or the server should cap one batch's run time.
    *Done when:* a test kills the agent's side mid-batch and sees the ingester exit and its transaction roll back.

1. **The ingester on a small server.** Measure a first ingest of a large tree on a 4+4-core ARM board; if it is far
   slower than the scan, batch the per-record queries (one round trip per batch for contents, files and members).
   *Done when:* a 300k-file ingest's time and peak memory are recorded for the board, and a test proves batched and
   unbatched ingest give the same catalog.
   - *Done:* completing a scan works in bulk. On the board, the batch completing a first scan of ~340k files ran past
     the agent's 10-minute send timeout, because completing worked per file (a history row and 5-7 lineage queries
     each, about 2M round trips). Now the new files' history is one statement, and lineage runs in rounds of 2000
     files with a handful of queries each (chunk sharing still per chunked file). `TestLineageRounds` proves rounds
     of 3 and 2000 give the same catalog as rounds of 1 (the per-file order). On a desktop (i7-12700KF, PostgreSQL 16
     on a local socket, synthetic 300k files): that batch 68.7 s before, 18.7 s after; an ordinary batch of 5000
     files 1.3 s.
   - *Done:* matching a scan's gone paths against its new ones is indexed. It was one pass over the new files per
     gone path, so a reorganisation (42k gone, 37k new) never finished. `TestMovesSameAsBefore` finds the same moves
     as the old code on 12 random trees; 40k gone and 37k new complete in about 5 s on that desktop.
   - *Left:* the board's time and peak memory for a 300k-file first ingest; batching the per-record queries of
     ordinary batches, with the test that batched and unbatched give the same catalog.
2. **Owner rules by uid.** `uid_map` is read but no rule uses it. Either rules gain an `owner = "uid"` form that maps
   the file's uid through the host's map, or the option goes. *Done when:* a test gives two files of two uids on one
   host to two people through the map, and a server whose clients are all one account still works by folder rules.
3. **`inhibit_sleep`:** listed in the example config, read by nothing. The sleep inhibitor belongs to the systemd
   unit, not the agent (DECISIONS.md, "Niceness, I/O class and the sleep inhibitor"), so the option goes.
   *Done when:* it is gone from the example config and nothing in the repo mentions it.
4. **A health endpoint** (`/health`: database reachable, newest batch per host, stale hosts) for monitoring that can't
   resolve the site's names or reach its loopback. *Done when:* the web tests cover healthy, database down and a
   stale host, and it reveals no file names.

## Correctness gaps found while building

5. **Same-disk copies.** `safe-to-delete` and `only-here` accept any other copy; show separately how many copies are on
   other disks (other host or device), so "safe" can't rest on a copy that dies with the same disk. *Done when:*
   tests cover a copy on the same disk, one on another disk, and a hard link (not a copy at all).
6. **Protection by inode.** A file under a protected root that is hard-linked elsewhere is protected at every path.
   *Done when:* a test links a protected file into a normal root and finds no archive listing, no metadata, no chunks
   policy override, and the UI shows only names, sizes, times and hashes there.
7. **Symlinks tied to their targets.** Resolve a target inside a known root to that file's id, flag dangling links,
   match a moved symlink by its target, and list in `safe-to-delete` the links elsewhere that point into the folder.
   *Done when:* tests cover a link inside a root, one to another root, a dangling one, a moved one, and a folder with
   links pointing into it.

## The web UI, read-write

8. **Owners and enrollments per folder:** give a folder away, enroll people as co-owners, readers or annotators, a
   preview of how many files change hands before saving, audited and shown to the people affected. *Done when:*
   tests cover a person giving their own folder away, being refused someone else's, an administrator taking one only
   in a step-up, and the preview's count matching the result.
9. **Lineage decisions:** confirm or reject a likely or possible relative; a decision outranks every heuristic.
   *Done when:* a rejected edge disappears from walks and is never re-added by a later scan, and a confirmed one
   survives a recompute.
10. **Operator page:** counts, sizes, ages and errors per root, no file names. *Done when:* a test shows an operator
    sees totals for another person's root and no path from it.
11. **Notifications** when an administrator saw someone's records: a pluggable command (an e-mail, a push service),
    off by default. *Done when:* a test with a stand-in command gets one message per step-up per person, with the
    reason and no file names.
32. **Reviewing changes, and what needs restoring.** After a clean-up, the changes tree (built) shows what went; a
    review records which of it was checked. Gone first, then moves (a move between roots or disks is a gone plus a
    new copy elsewhere, so the two mix):
    - a mark per history row: *intended*, or *restore*; by row or for everything shown under a folder (the tree's
      filters) up to a date, so a clean-up of thousands is a few clicks; a later change is unreviewed again;
    - the tree and list show unreviewed counts, and filter reviewed / unreviewed;
    - a gone file whose last content still exists in another root you can see (the copy lineage of a disk move) says
      so, with where, and can be marked intended in bulk; one with no other copy is flagged, as it may be lost;
    - *restore* lists, per file, which backup copy and snapshot holds its last content (the `versions` query), or
      none; it clears itself when a scan sees that content back at the path or nearby. Pinakes points at the copy
      and never restores it (DESIGN.md "Principles");
    - marks are records about files: under row-level security, made by the file's owner or co-owners, by an
      administrator only in a step-up (audited); who marked and when is kept.
    *Done when:* tests cover a folder marked intended in bulk, a later gone under it showing unreviewed, a disk move
    recognised by its copy, a restore mark naming the snapshot that holds the content and clearing when it comes
    back, and another person neither seeing nor making marks on files they can't see. Could live with other
    file-management extras rather than in the core.

## Metadata (METADATA.md)

12. **The schema registry** (`schemas/*.toml`), with Dublin Core's common fields first. *Done when:* schemas load and
    validate, a bad one is refused with a clear message, and every enrolled field's index exists.
13. **Extractors, one schema at a time:** EXIF, then XMP (embedded and sidecar), audio tags, OPF, PDF and office
    properties, video. Each optional by its dependency. *Done when, for each:* tests on generated files (made by the
    test, never real ones) extract the declared fields; a missing dependency turns the extractor off, not the scan;
    nothing runs on a protected root (a test proves it).
14. **Bundles and pairing**, per schema's rules. *Done when:* tests cover a photo with each sidecar form, RAW with JPEG,
    a book folder, and a bundle moved together counting as one move.
15. **Identity fields for lineage** (PDF `/ID`, XMP `DocumentID`/`InstanceID`/`DerivedFrom`, EPUB identifier).
    *Done when:* two renamed, edited files sharing an identity field are linked with certainty in a test.
16. **Person-entered metadata and sensitive fields** in the UI. *Done when:* a shared file shows its non-sensitive
    fields to the other person and hides the sensitive ones unless shared too.

## Managing files (DESIGN.md "Managing files")

17. **The operation queue:** request, approval, the agent fetching approved operations for its roots, carrying them
    out within its local `managed` policy, reporting results. Move and rename first, then trash. *Done when:* tests
    cover every refusal (file changed since the request, outside the local policy, someone else's file without
    approval, a would-be overwrite) and a crash mid-operation leaving either the old state or the new, never neither.
18. **Linking same-disk duplicates** (DESIGN.md "Planned"), after 17. *Done when:* the same refusals plus: different
    owners, unsettled content, a protected or drop or backup root; the replaced inode reaches the trash; undo by copy
    is documented and tested.

## Sources and imports

19. **Checksum manifests** (`SHA256SUMS` files) as hints, checked on the next scan, never trusted. *Done when:* a test
    finds a wrong line reported and a right one confirmed.
20. **Another catalog's checksums** (a photo library's SHA-1s), for files the agent doesn't see. Needs SHA-1 as an
    extra hash on the roots that hold the library's originals. *Done when:* a test matches by SHA-1 and reports the
    library's files that no root holds.
21. **A restic repository as a backup source** (`restic ls --json`: paths, sizes, times; no whole-file hashes, so
    matches are by path, size and mtime, marked lower confidence). *Done when:* a test with a stand-in `restic`
    answers "which snapshot holds this version" for a primary file.

## Accounts and hardening

22. **WebAuthn** as a second factor; **OpenID Connect** sign-in. *Done when:* each has its own tests, and step-up
    accepts each factor it is configured for.
23. **Rate limits on search, audit retention, removing a person** (their records, shares and sessions go; audit
    entries about them kept for the retention period). *Done when:* tests cover each.

## Later, or a wish

24. **MCP server** over the read-only queries (DESIGN.md "Wish"). *Done when:* tests show a token acting as one person
    under row-level security, never stepping up, leaving protected roots out unless added, and every query logged.
25. **A live watcher** (fanotify) on a busy server, beside the nightly scan.
26. **Single-machine mode** (SQLite, no people).
27. **Packaging:** an installable release (`pyproject` build), a test runner that starts its own throwaway PostgreSQL,
    and a test matrix (Python 3.10 to 3.13, PostgreSQL 15 to 18).
