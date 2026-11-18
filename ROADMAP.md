# Roadmap

What is left to build, and what "done" means for each piece. What is built, and how it was tested, is in REARVIEW.md;
item numbers are one series across both files and never reused. The design is in DESIGN.md, SECURITY.md, METADATA.md
and QUERIES.md; choices made while building are in DECISIONS.md. Deployment belongs to each site, not to this repo. What is not planned, and only
for a day scale asks for it, is in HORIZON.md.

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

## Next: before more machines join

Found by the first deployment (one storage server, 445k files, two nights), and needed before a backup server joins
(1, 2, 4, 5 and 28 to 31 are built and 3 dropped: REARVIEW.md):

No known item blocks adding a machine. New ones from a deployment go in this section. Left:

51. [Operability; also stability] **The agent reports its own runs to a push monitor.** A site that watches its
    machines with a push-style uptime monitor (a URL the job calls when it finishes) has to wrap the agent's unit
    in a drop-in and a small script that calls it, one copy per kind of host (a system unit, a user unit). Built
    into the agent instead: an optional `[monitor]` setting in `agent.toml` (a file holding the push URL, never the
    URL itself in the config), the agent calling it at the end of every `run` (up with a short summary: files seen,
    batches sent, the outbox left; down with the failure), a run started by hand reporting too, and a failed report
    never failing the scan or reaching a log with the URL in it. Sits next to: the agent's `status` and `check`
    commands (what it already knows at the end of a run); `/health` on the server (it sees a stale host only after
    its `expected_every`, and never a host set to `never`). Value: medium (a failed run alerts at once, desktops
    included). Cost: S. Risk: none beyond a new outbound call, off unless configured. *Done when:* tests with a
    local test server show an up call after a good run and a down call with the reason after a failed one, nothing
    sent with no setting or no file, a dead server leaving the exit status at 0, and the URL absent from the log,
    argv and the config; and a run on a real tree (read-only) reaches a real push monitor.

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

13. [Feature; also security] **Extractors, one schema at a time:** EXIF and embedded XMP (JPEG) are built (REARVIEW.md);
    then XMP sidecars (with 14) and extended XMP, audio tags, OPF, PDF and office properties, video. Each optional by
    its dependency. *Done when, for each:* tests on generated files (made by the test, never real ones) extract the
    declared fields; a missing dependency turns the extractor off, not the scan; nothing runs on a protected root (a
    test proves it). Left from the first real run: 717 JPEGs without EXIF, not looked into; once release 7's
    outcomes (44) are in, `pinakes-ingest extractions` says which of them hold none and which the reader refused.
14. [Feature; also correctness] **Bundles and pairing**, per schema's rules. *Done when:* tests cover a photo with each
    sidecar form, RAW with JPEG, a book folder, and a bundle moved together counting as one move.
15. [Correctness] **Identity fields for lineage** (PDF `/ID`, XMP `DocumentID`/`InstanceID`/`DerivedFrom`, EPUB
    identifier). *Done when:* two renamed, edited files sharing an identity field are linked with certainty in a test.
16. [Feature; also security] **Person-entered metadata and sensitive fields** in the UI. Sensitive fields are kept
    for owners and co-owners only, and shown on a file's page and in find (built: REARVIEW.md); left: entering
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
(`pinakes-ingest`). 33 to 36, 38, 39 and 37's first part are built (REARVIEW.md). Left, in order:

37. [Feature; also security] **Tagging from a folder.** Reviewing from a folder is built (REARVIEW.md); left:
    `pinakes tag` and notes, once person-entered metadata exists (16), with the token's `tag` scope. *Done when:* tests
    cover an owner tagging from inside a folder, a reader refused, a token without the scope refused, a root outside
    the token's limit refused, and the tags shown in the web UI.
40. [Security] **A protected admin API** (later): admin tokens with every function (`*`), each call audited; another
    person's records still only in a step-up, logged where they can see it, as on the web. Until then administration
    is the server's local CLI. *Done when:* tests show an admin token refused another person's records without an
    active step-up, and every call in the audit.

## Proposed (from a review of the whole project; not yet agreed)

Things a catalog's users would expect that nothing above lists. Each fits next to something built; none is started
(41, the scrub, 46, a machine replaced under the same name, 44, extraction outcomes, and 43, folders that are copies of
each other, were agreed and are built: REARVIEW.md).
Ranked by value over cost (cost: S half a day or less, M a day or two, L more).

42. [Feature; also operability] **What a disk's loss would cost.** `only-here` answers for a folder; nobody asks
    folder by folder before a disk fails. One report per device: how much has no copy on another disk, by owner and
    by top folder, with the largest folders first, and the same per host ("if this machine burned"). On the operator
    page as totals without names (10), and for a person, their own files with names. Sits next to: only-here and
    safe-to-delete counting a copy only on another disk (5); the operator page (10). Value: high. Cost: S (the
    queries exist; this is aggregation). Risk: none. *Done when:* a test with two devices and one backup root gives
    the sizes at risk per device, an operator sees totals and no path, and a person sees only their own.
45. [Feature; also security] **A person's export of their own records.** Everything the catalog holds about my
    files (paths, hashes, history, metadata, reviews), as CSV or JSON, through the API with the token's `read`
    scope. A catalog that describes people's files should hand them their description. Sits next to: the JSON API
    and person tokens (34), removing a person (23). Value: medium. Cost: S. Risk: row-level security must apply
    exactly as for a query: the export is a query, not a dump. *Done when:* a test exports one person's records and
    finds none of a second person's, sensitive fields only where `sensitive_visible()` allows, and the export in the
    audit.
47. [Feature] **Growth by folder over time.** History is kept to the day; "what grew this month, and where" is one
    query away and listed in DESIGN.md's reports ("a root's growth") without an item here. Per root and top folder,
    bytes and files added and gone per week. Sits next to: history, the changes page, the operator page. Value:
    medium. Cost: S. Risk: none. *Done when:* a test with three dated scans gives the right weekly deltas, per
    person under row-level security.
50. [Feature] **A web page for folder copies** (43 is built as the CLI and API only). The same query as
    `pinakes folder-copies`, on the web beside Duplicates and Only here: a folder or root asked about, rows with the
    relation (same, inside, nearly), file counts and what differs, sortable and paged as those are. Sits next to:
    the Duplicates page, 43. Value: medium. Cost: S. Risk: none beyond 43's (the query reads the whole catalog per
    call; paging doesn't cheapen it). *Done when:* a web test shows the page for a folder with the three relations,
    another person's folders absent, and the sort and paging working.

## Soon: add-on modules

Optional pieces that sit on the API and tokens, not in the core: a site that doesn't install one loses nothing.

24. [Feature; also security] **MCP server**, an add-on module, over the read-only queries (DESIGN.md "Wish"), on the
    API and tokens of 34, `read` scope only; no new powers in the core, and the core runs without it. *Done when:* tests show a
    token acting as one person under row-level security, never stepping up, leaving protected roots out unless added,
    and every query logged.
