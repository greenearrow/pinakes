# Roadmap

What is left to build, and what "done" means for each piece. What is built, and how it was tested, is in REARVIEW.md;
item numbers are one series across both files and never reused. The design is in DESIGN.md, SECURITY.md, METADATA.md
and QUERIES.md; choices made while building are in DECISIONS.md. Deployment belongs to each site, not to this repo. What is not planned, and only
for a day scale asks for it, is in HORIZON.md.

Each open item starts with its category in brackets: *feature* (something new to do), *security* (who sees or does
what), *correctness* (a wrong answer without a crash), *stability* (staying up), *scalability* (bigger trees, busier
machines) or *operability* (installing and running it); "also" names a second.

An item added from here on that gives a person something to ask or do (a report, a query, a review, a mark) names
the `pinakes` command in its *done when*: the command, its `--json`, and a test of it through the API. A web page or
API call alone doesn't finish it. Only an item with nothing a person asks or does (the agent's scanning, an install
step, the operator's own tools) leaves it out, and says why.

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

No known item blocks adding a machine; new ones from a deployment go in this section. Left, not a blocker but next:

51. [Operability; also stability] **The agent reports its own runs to a push monitor:** built and tested on generated
    trees (REARVIEW.md 51). Left: *done when* a run on a real tree (read-only) reaches a real push monitor, up and
    down.

## The web UI, read-write

8. [Feature; also security] **Owners and enrollments per folder:** give a folder away, enroll people as co-owners,
   readers or annotators, a preview of how many files change hands before saving, audited and shown to the people
   affected. *Done when:* tests cover a person giving their own folder away, being refused someone else's, an
   administrator taking one only in a step-up, and the preview's count matching the result.
11. [Security] **Notifications** when an administrator saw someone's records: a pluggable command (an e-mail, a push
    service), off by default. *Done when:* a test with a stand-in command gets one message per step-up per person, with
    the reason and no file names.

## Metadata (METADATA.md)

13. [Feature; also security] **Extractors, one schema at a time:** EXIF and embedded XMP (JPEG) are built (REARVIEW.md);
    then XMP sidecars (with 14) and extended XMP, audio tags, OPF, PDF and office properties, video; the PDF's `/ID`
    and the EPUB's `dc:identifier` as identity fields of their schemas (lineage reads them as it does XMP's: 15).
    Each optional by its dependency. *Done when, for each:* tests on generated files (made by the test, never real ones) extract the
    declared fields; a missing dependency turns the extractor off, not the scan; nothing runs on a protected root (a
    test proves it). Left from the first real run: 717 JPEGs without EXIF, not looked into; extraction outcomes
    (44) are built and in release 7, so once it is deployed, `pinakes-ingest extractions` says which of them hold none
    and which the reader refused.
14. [Feature; also correctness] **Bundles and pairing**, per schema's rules. *Done when:* tests cover a photo with each
    sidecar form, RAW with JPEG, a book folder, and a bundle moved together counting as one move.

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

Every person-facing function goes through one API in `pinakes-web`, with one way to authenticate (DECISIONS.md "The
CLI and the API"), and `pinakes` is a client of it that runs on any machine and works where you are. Agents' batches
stay on their forced SSH keys, and server maintenance stays a local command (`pinakes-ingest`). 33 to 39 are built
(REARVIEW.md). Left:

40. [Security] **A protected admin API** (later): admin tokens with every function (`*`), each call audited; another
    person's records still only in a step-up, logged where they can see it, as on the web. Until then administration
    is the server's local CLI. *Done when:* tests show an admin token refused another person's records without an
    active step-up, and every call in the audit.

### What the server answers that `pinakes` doesn't ask yet

Built on the server (an API call, or a web page only) before the rule above, with no command. Each *done when*
names the command, its `--json`, and a test of it through the API. 53 to 59 are built (REARVIEW.md). Left:

60. [Security; also operability] **The operator's totals through the API** (10, 42; the operator page only), as
    `pinakes operator` with an ops token. The database refuses its functions to every token, ops tokens too
    (`require_operator()`); opening them to ops tokens is the owner's decision first, and an upgrade. *Done when:*
    decided; then `pinakes operator` and `--json` are tested through the API with an ops token, a person's token
    refused, and no path or person in the answer.

## Before the MCP server

The assistant is meant to be the main way in (DESIGN.md "Wish: an MCP server"); this came first, and helps the
command line and the web UI as much. 61 and 62 are built (REARVIEW.md); nothing is left here.

## Soon: add-on modules

Optional pieces that sit on the API and tokens, not in the core: a site that doesn't install one loses nothing.

24. [Feature; also security] **MCP server**, an add-on module (DESIGN.md "Wish: an MCP server"), on the API and tokens
    of 34, after 61 and 62: the read-only queries, and review marks, tags and notes and lineage decisions with the
    review and tag scopes, each write a preview and then an apply; streamable HTTP behind the proxy, each connection
    with its own person's token. No new powers in the core, and the core runs without it (the token form's note on what
    an assistant receives is built: REARVIEW.md "Before 24"). A person asks through their assistant; what it did they
    see with `pinakes access` and `pinakes edits`. *Done when:* tests show a token acting as one person under row-level
    security, two connections with two people's tokens each seeing only their own, never stepping up, leaving protected
    roots out unless added, every call logged, a write changing nothing before its apply, and that write listed by
    `pinakes edits` and undone by `pinakes undo`.
