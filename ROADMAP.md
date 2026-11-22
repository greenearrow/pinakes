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
18. [Feature; also correctness] **Linking same-disk duplicates** (DESIGN.md "Planned"), after 17 and 69. Placeholders
    are never linked, and the rule fails safe instead of trusting 69's thresholds: a size floor (`link_min_size`,
    default 1 MiB); never a placeholder candidate, marked or not, or a content marked or matched by a site rule; never
    a content held under more than one name in one folder; a reflink where the filesystem has one. *Done when:* the
    same refusals plus: different owners, unsettled content, a protected or drop or backup root, a file under the size
    floor, an unmarked candidate, identical files under several names in one folder (generated default files of a
    game world, one large enough to pass the floor); the replaced inode reaches the trash; a reflink used where the
    test filesystem has one; undo by copy is documented and tested.

## Exclusions and routine churn

Today every exclusion is an `exclude` glob in one root of one agent's config (DESIGN.md "Roots"): a backup root
restates its source's globs by hand with its layout prefix, the same junk globs are repeated per root and per machine,
a new exclude turns the files already catalogued under it into unreviewed gone files (the agent prunes them in its
walk; the server knows nothing of excludes), and files that rotate out on a schedule (nightly dumps kept N days,
snapshot pruning, log rotation) are marked `intended` by hand every day. In order:

63. [Feature; also security] **Expected rules for rotation:** a glob under a root (`ROOT:app/backups/*.sql.gz`) whose
    gone files are marked `intended` by the rule as they arrive; the files stay catalogued, so whether one was ever
    backed up stays answerable. A rule marks only what its maker could mark by hand, checked each time it applies,
    not only when made; each mark is the rule's, shown in `pinakes edits` and undone by `pinakes undo`. Server only,
    no protocol change. *Done when:* `pinakes expected add|remove ROOT:GLOB` and `pinakes expected` (the rules, with
    what each marked) and their `--json` are tested through the API: a rotated file marked as it arrives, a file
    outside the glob left unreviewed, a second person's rule refused files they can't mark, the marks in `edits` and
    undone by `undo`; and the web page.
64. [Correctness; also feature] **A preview of an exclusion, and "excluded", not "gone":** before an exclude takes
    effect, "this would drop N files (B bytes) from ROOTS, M with no copy elsewhere", from the catalog; after it, the
    files that left because they were excluded are recorded as excluded and need no review. Needs the agent to tell
    the server why files left (a protocol change). Decided first: whether the agent sends its patterns (which can name
    what never left the machine) or only the fact that a path is now excluded. *Done when:* `pinakes exclude-preview
    ROOT:GLOB` and `--json` are tested through the API, under row-level security (a person counts only what they
    see); a scan after the exclude records exactly the files the preview counted as excluded, none of them gone or
    unreviewed (`pinakes changes --what excluded`); and the web page.
65. [Operability; also security] **One site-wide exclude list,** in `server.toml`, applying to every root beside the
    per-root `exclude`. It must reach the agents, since privacy excludes have to stop the walk on the machine: either
    sent with the batch acknowledgement and applied from the next scan (a protocol change), or the agent's
    `exclude_from = FILE` with the site distributing one file; decided first. The server's list only adds excludes: it
    can never make an agent read what its local config leaves out or a protected root hides (SECURITY.md). No person
    command: the list is the operator's config, and its patterns may name private things. *Done when:* tests show an
    agent applying the site list from its next scan, a site list unable to remove a local exclude, the preview of 64
    for a change to it, and `pinakes-ingest excludes` showing the list and which agents have applied it.
66. [Operability] **A backup root inherits its source's excludes through `mirrors`:** the agent applies the source
    root's globs (its own and the site's) to each backup path mapped back through `layout`; the backup's own `exclude`
    is only for what is its own (partial transfers). Agent and config only, after 65 (the source's list must reach the
    backup's machine); no person command, since nothing new is asked. *Done when:* tests on generated trees show a
    backup root leaving out exactly what its source leaves out, through a prefixed layout, and a glob added to the
    source reaching the backup without editing its config.
67. [Feature] **Candidates for a rule:** a report of the folders whose gone files are always marked intended, or that
    lose files on a schedule (about one per interval, the same name pattern), each offered as an exclude (64) or an
    expected rule (63). `changes --tree` counts the noise per folder but doesn't say "the same thing every day". *Done
    when:* `pinakes candidates [PATH]` and `--json` are tested through the API on a generated rotating tree and a
    folder marked by hand, under row-level security; and the web page.

## Copies, metadata and plain answers

Found walking a photographer's questions against a live catalog (a primary photo root, an app's upload folder of
UUID names with `.xmp` sidecars, nightly hard-linked snapshots of both on a backup root):

72. [Feature] **One file's metadata from the command line:** `pinakes meta FILE` with each schema's fields, their
    sources and the extraction outcome ("refused: truncated", "nothing found"), today on the web page only. *Done
    when:* it and its `--json` are tested through the API, sensitive fields left out under a token, a second person's
    file refused as by `where`.
73. [Correctness] **Plain `relatives` and `lineage` show what matters:** gone copies marked (the JSON has `gone_on`,
    the table doesn't), and long paths cut in the middle so the name and its extension stay (`.../IMG_1881.CR2`, not
    `.../IMG_1881`); the same cut in every table that shortens paths. *Done when:* `pinakes relatives` and `pinakes
    lineage` are tested through the API with a gone relative and a long path, and `--json` unchanged.

## A household's answers

Found walking a family admin's questions on the demo household (`tools/demo.py`), each person signed in as
themself, on the web and with the command against a running `pinakes-web`:

76. [Correctness] **One rule for dates and times:** today some pages and commands give UTC dates (Changes "Seen",
    history, a file's "gone", the roots' last complete scan) and others local ones ("In the catalog", marks, edits,
    access, restores), so one file page reads "in the catalog 2026-11-21 to 2026-11-21" beside "gone 2026-11-22", a
    root's last scan and `stale` disagree by a day, and `pinakes undo`'s refusal gives UTC for an edit `edits` lists in
    local time. Wanted: one zone everywhere a person reads (the site's, from `server.toml`, unless decided otherwise),
    UTC with its offset only in `--json`. *Done when:* `pinakes changes`, `history`, `roots`, `stale`, `edits`,
    `undo`, `access` and `restores` and their `--json` are tested through the API with the clock just past midnight
    UTC and the site's zone behind it: each date the site's, the same on the web pages that show them, `--json` in UTC.
78. [Feature] **Edits and undo on the web, each edit naming its folder:** `/edits` is a 404 and the account page only
    mentions `pinakes undo`; an edit that marked a folder is listed by its first file. Wanted: an Edits page with
    undo (a preview, then the undo, refused as the command refuses), and each edit named by its folder ("N files
    under FOLDER"). *Done when:* `pinakes edits` and `--json` name the folder, tested through the API; the web page's
    undo is tested for an edit undone, one refused for a later edit, and another person's edit not shown.
80. [Security] **Every step-up entry names its folders:** a person seen in a step-up gets an entry per page, as
    SECURITY.md asks ("which records (by folder, with counts)"), but a find's entry says only "page: find; records:
    1". Also: the web's detail shows Python values (`until: None`, `scopes: ['read']`), and a sensitive-share entry
    says "file: 4", not the path. With 75 (the reason). Grouping the entries under their step-up is a wish, not part of
    this. *Done when:* `pinakes access` and `--json` are tested through the API: after a step-up's find, browse and
    file page, the person seen gets each with its folders and counts and no other person's folder; the share entry
    names the file's path to its owner and to the person shared with; and the web page shows the values as words.
81. [Correctness] **The command and the web say the same things:** the report is `restores` in the command and
    `/reports/restore` on the web; a file page's owner reads "a group", not its name, to a member; `pinakes changes`
    is a column dump (history_id, reviewable, elsewhere_at) and a gone row says `backups 1` without naming it, where
    the web says "only in 1 backup copy: restore it, or mark it intended"; columns are cut mid-value (`restores`
    held_in, `access` detail, `meta` vals; 73 cuts paths in the middle). *Done when:* `pinakes changes`, `restores`,
    `access` and `meta` are tested through the API: plain output in the web's words, the backup named, no value cut
    but a path's middle; `--json` unchanged; one name for the restores report on both; the group's name shown to its
    members.

## Graduated privacy, and what the catalog can't see

Found walking a family admin's and a lab's questions (a child, a teenager and a partner in a household; a principal
investigator, students and a collaborator on a lab's storage). Today everyone has an adult's privacy: another person's
records are reached by a share or enrollment their owner can remove, or in a step-up. What is planned is the
catalog's promise, not the disk's: whoever can read the files on the machine still can (SECURITY.md). Every choice in
82 to 86 is a default, set per site within limits no site can loosen, and the site's policy is shown to everyone in it
(87).

82. [Security; also feature] **Standing views: one person sees another's records within a reach** (SECURITY.md "Standing
    views"). Of kind *guardian*, at level *child* (everything the person owns but their private folders) or *teenager*
    (only the folders named in it). Built as a member of the ACLs it reaches, with its own role, so row-level security
    stays one array test (`visible_acls()`) and every report follows; a private folder gets ACLs of its own the view
    doesn't reach, and its backup copies follow it as they follow their source's owner. A reader's view: no marks, tags
    or lineage decisions. Sensitive fields (GPS, people; METADATA.md) by level: at *child* included, a safety value; at
    *teenager* not, a step-up reaches them; at *supervisor* never (83). Who may be viewed so is site config
    (`[people.NAME] standing = {kind, by}`); the database refuses anyone else, so an adult or a collaborator can never
    be given one through the web or the API, and a config entry appears, audited, on the person's page at the next
    `setup`. Its level and folders are changed by an administrator in a step-up with a reason and a preview equal to the
    result ("you'll see 2,140 of user-3's files in 1 folder; 6,902 stay private"); narrowing (teenager back to child) is
    shown to the person with the reason (and sent, with 11); ending it needs no step-up, can't be undone, and keeps the
    access entries. The person marks their own folders private, without the viewer agreeing (an administrator can always
    step up: restraint, not a lock), and sees their view: who sees what, since when. What the viewer sees of the private
    part depends on the level: at *child* one line that a private folder exists, with no name, count or size; at
    *teenager* nothing at all, not that line, and no opaque container (85) in it named, since making something private
    is itself private. Each look is on the person's "Access to your records" as its own kind, by folder with counts (as
    80), never as a step-up; the private part is reached only by an ordinary step-up (75, 80). A token leaves standing
    views out unless its maker adds them, with the note on what an assistant receives (24); a group token never has one;
    no token sets, changes or ends one. After 8 (the per-folder pages it changes) and 80. Owner decisions 2026-11-22
    (private marks, sensitive fields by level). *Done when:* `pinakes views` (the arrangements a person is in, either
    side), `pinakes private FOLDER` (mark, unmark) and `pinakes access` and their `--json` are tested through the API on
    the demo household (`tools/demo.py`, which builds both levels): user-1 outside a step-up finds user-4's files and
    their GPS but nothing in the private folder, and only the one line, no name or count, hints at it in `find`,
    `changes`, `at-risk`, `only-here`, `backed-up`, `safe-to-delete`, `meta` or `--json`, its snapshot copies included;
    user-1 finds only user-3's agreed folder, without its sensitive fields and with no line about a private folder or an
    opaque container, and a file moved out of it is gone from that view after the next scan; user-3's `access` lists
    user-1's looks as guardian views; a view on user-2 refused by the database, under every token and in a step-up; a
    token without the view added sees none of user-4's files; ending user-3's view leaves user-1 nothing outside a
    step-up and the earlier entries kept; the operator page's per-person totals unchanged; and the web pages say the
    same.
83. [Security; also feature] **A supervisor's standing view, for a lab:** 82's mechanism of kind *supervisor*, its words
    on the pages ("independent" for private; "supervised by"): everything a student owns but the folders they mark
    independent, or only named project folders. Two things the household doesn't have: a file of the lab's (one the
    supervisor sees, by hash or confirmed lineage) put into an independent folder, or a folder of them marked
    independent, is shown to the student ("this came from project-y") before the mark takes effect or at the next scan
    that brings it in, and the supervisor is told the file's name and its source (it is lab data), so a move from the
    lab's view into a private one is never silent and the supervisor knows which backup copies hold the exposed version;
    the independent folder's name and its other files stay out of it. Sensitive fields are never in a supervisor's view
    (a lab's GPS is participants' data). Owner decision 2026-11-22. And a student who leaves: the view ends as in 82,
    and their independent folders are theirs to take with them by 8's giving. The institution's right to the independent
    part is an ordinary step-up, shown at once, or an auditor's held view (86). *Done when:* `pinakes private` and
    `pinakes views` and their `--json` are tested through the API on a generated lab: user-3's independent folder hidden
    from user-1 in every report 82 lists and in `export`; a lab file copied into it listed for user-3 with its source,
    and for user-1 by its name and source only, the folder's name and its other files absent; no sensitive field of
    user-3's in user-1's answers; a view of kind supervisor refused on user-2 (a collaborator, not named in config); the
    web page says the same.
84. [Security; also correctness] **Unclaimed until claimed:** an owner rule may give a folder (a root's top included) to
    nobody (`owner = "unclaimed"`), so a file under it that no deeper rule claims has no owner, instead of falling to
    the site's one `default_owner`. On a lab's storage that is how a collaborator's new folder beside their rule stops
    becoming the default owner's, silently. An unclaimed file is in no person's view and no person's copy reasoning (so
    only-here or safe-to-delete err toward "not safe"), its backup copies follow it, administrators see it in a step-up
    (as now: a step-up sees every ACL), and operators see counts per root. Nobody is told "there's something beside your
    folder" (that would name another person's folder); claiming is an administrator's, in a step-up with a reason,
    audited, by 8's per-folder giving, and the new owner is told (11). No `pinakes` command: claiming needs a step-up,
    which no token opens (SECURITY.md), until an admin token (40); the operator's counts are `pinakes-ingest unclaimed`.
    *Done when:* tests on a root with an unclaimed rule: a new folder beside a person's rule is owned by nobody, in no
    person's `find` or `--json` through the API, counted in `pinakes-ingest unclaimed` and on the operator page with no
    path, listed in a step-up and claimed there with the preview equal to the result; a uid rule (2) still claims what
    it maps; a root without the rule unchanged.
85. [Correctness; also security] **Opaque containers:** what the catalog can't see inside, shown as one thing. An opened
    encrypted volume is a mount and already not walked (DESIGN.md "Roots"), and a container file is already one file
    with a size, times and a hash; what's missing is saying so, and folding a backup tool's repository (restic, borg),
    which today is walked as thousands of pack files: its prune turns them into gone files to review, and its parts show
    in `find`, `only-here` and `changes`. Wanted: a folder or file marked `opaque` in the root's config, or recognised
    by the agent (a restic or borg repository's layout; a LUKS header in the first block it already reads to hash;
    VeraCrypt can only be marked, its volumes look random by design), recorded as one thing: size, file count, newest
    change and a digest over its files' names, sizes and hashes, so two copies of one repository are copies of each
    other as a whole. Its parts are never duplicates, folder copies, relatives, safe to delete or review items; the
    whole is, as one. Its page and `--json` say "opaque: the catalog checks its bytes, not what's inside" (a scrub still
    finds rot; `restic check` is the tool's). A repository read with its owner's key (21) is not opaque to them. Where
    it folds is the machine's own agent config, per root like `managed`, so the machine's owner decides (a parent on a
    child's laptop, a student on their own, the PI on the lab's server): on the agent (one record, a protocol change;
    the parts and their prune churn never leave the machine) or on the server (every part sent, folded in queries). The
    server can't change it; the agent reports each root's setting at its check-in (its label and one word, a small
    protocol addition), and 87's page shows it with that date. Owner decisions 2026-11-22. *Done when:* `pinakes find`,
    `dupes`, `safe-to-delete`, `only-here`, `folder-copies` and `changes` and their `--json` are tested through the API
    on a generated restic-shaped and borg-shaped folder and a LUKS-headed file, folded on the agent and on the server:
    each root's setting reported at check-in and recorded with its date; each appears as one opaque thing, the
    agent-folded one with no part in the catalog, none of its parts in `dupes` or `safe-to-delete`, a pruned pack no
    review item, two copies of the repository one copy of the other; and the web page says the same.
86. [Security] **An auditor, whose views can be held** (SECURITY.md "Auditors"): for an inquiry (a lab's
    research-integrity case) an administrator's step-up is never held, it shows at once; instead a separate role, named
    in the site config (`[people.NAME] roles = ["auditor"]`) and held by every administrator unless the config takes it
    from one (`auditor = false`, so a site can keep an administrator to step-ups only), the database refusing anyone
    else; a site whose administrators all have it taken away and that names no auditor can hold nothing. Web only, with
    a second factor; no token, no `--as`, no assistant. Each audit has three different people, enforced by the database:
    a requester (an auditor; in a household of two administrators, either parent), an approver (another auditor or an
    administrator), and the subjects, neither of the first two among them (in a lab the subject may be the PI, who
    administers the site, so an administrator is never the auditor's only check). Its scope is set before it opens
    (named people, folders and a time window), reaches only that, and widening it needs a new audit; sensitive fields
    (GPS, people's names) are in it only when its scope names them before it opens, as the child safety case needs; it
    is read-only (no marks, tags, shares, ownership changes or sensitive-field sharing) and an export is recorded as
    part of it. A hold is capped (90 days by default, site config); a renewal needs the approver again and is logged; at
    the cap the entries show on each subject's "Access to your records" with nobody releasing them, complete: requester,
    approver, reason, scope (saying whether it held sensitive fields), each folder seen with its counts, and how long it
    was held. A **solo hold**, without an approver, only once exactly one person on the site has been an administrator
    or an auditor for a waiting period (30 days by default, site config, never below the floor in SECURITY.md "What no
    site can change"; the clock restarts whenever a second one is added), so taking the role from the other parent
    doesn't open one at once, and a step-up is always there meanwhile (a single parent who runs the server and could
    read the disks anyway, where an approver brought in would cost the subject more privacy, not less): a shorter cap
    (14 days by default), no renewal, released by itself, and its entry says "held by user-1 alone, with no approver,
    for 14 days" with the reason and every folder seen. It is for cases where a warning is dangerous (grooming,
    self-harm, someone else involved); for ordinary behaviour a step-up, shown at once, is the path, and the pages say
    so. Every page shows everyone on the site how many audits are held, solo ones included, and the latest date one
    ends, with no names. The database superuser and whoever runs the disks stay outside all of this (SECURITY.md). Owner
    decisions 2026-11-22 (the role and administrators holding it, the approver, sensitive fields, solo holds and their
    waiting period). After 80 (entries by folder). *Done when:* `pinakes access` and its `--json` are tested through the
    API: an audit with requester and approver the same, or either a subject, or an approver who is neither auditor nor
    administrator, or a requester whose auditor role the config took away, refused by the database; a solo hold refused
    on a site with a second administrator or auditor, and within the waiting period after the second one's role was
    taken away, and one allowed shown at its 14 days, with no action, saying it was held alone, and refused a renewal; a
    held entry absent from the subject's `access` and present, complete, after the cap with no action; a renewal without
    the approver refused; the held count, solo holds included, right for a person who isn't the subject and shown on the
    web; an auditor's call outside the scope finding nothing; sensitive fields absent from an audit whose scope doesn't
    name them, present in one that does, and the shown entry saying which; a token refused every auditor function; and a
    site with no auditor configured refusing an audit.
87. [Security; also operability] **The site's policy, in words, from the config it runs:** 82 to 86 are the default
    contract, and each household or lab sets its own within limits (whether administrators are auditors, the caps, solo
    holds, the private line at *child*, sensitive fields by level, supervisors told of moves into independent folders,
    the held count), so the policy has to be visible to everyone who trusts their data to the site. A page every person
    can read and `pinakes policy`, generated from the settings the server is running, never a document written beside
    them: what the administrators, auditors, guardians and supervisors here may see, of whom (by name to the people it
    concerns, by role to everyone else), and how each look is recorded; and each root's opaque folding as its agent last
    reported it at check-in, with that date (85; the agent's config decides, the server only reports). Beside it, the
    guarantees no site configures away, each enforced in the database or the agent, not by the page (SECURITY.md "What
    no site can change"): a setting can make a site stricter than the default and looser only within them, and `setup`
    refuses a config that goes past one. A person sees the policy when their account is made and again at their next
    sign-in after it changes, until they have opened it (seeing it is required; agreeing isn't asked). Every change is
    on record and on the page: what changed, in words, and when; who changed it, as the person `setup` names (`--by`),
    shown as the operator's word: whoever can edit the config is root on the server, already outside the guarantees, so
    a required sign-in would add ceremony, not protection (owner decision 2026-11-22). *Done when:* `pinakes policy` and
    its `--json` are tested through the API on the demo household and a generated lab: the words match the running
    settings (a cap or a level changed in config changes them after `setup`, and nothing else does); a person not
    concerned by a guardian view sees it by role and not by name; each fixed guarantee listed, and a config that loosens
    one refused by `setup`; a policy change recorded with its time and the `--by` name shown as the operator's word; a
    root's folding shown with the date its agent reported it; and shown to every person at their next sign-in until
    opened; the web page says the same.

## Sources and imports

20. [Feature] **Another catalog's checksums** (a photo library's SHA-1s), for files the agent doesn't see. Needs SHA-1
    as an extra hash on the roots that hold the library's originals. *Done when:* a test matches by SHA-1 and reports
    the library's files that no root holds.
21. [Feature] **A restic repository as a backup source** (`restic ls --json`: paths, sizes, times; no whole-file hashes,
    so matches are by path, size and mtime, marked lower confidence). *Done when:* a test with a stand-in `restic`
    answers "which snapshot holds this version" for a primary file. A repository not read so is opaque (85).

## Accounts and hardening

22. [Security] **WebAuthn** as a second factor; **OpenID Connect** sign-in. *Done when:* each has its own tests, and
    step-up accepts each factor it is configured for.
23. [Security] **Rate limits on search, audit retention, removing a person** (their records, shares and sessions go;
    audit entries about them kept for the retention period). *Done when:* tests cover each.
75. [Security] **The step-up's reason on the record of the people it saw:** SECURITY.md ("People and roles", step 3)
    says each record seen in a step-up is logged with the reason, but `audit_view` writes only the page and a count; the
    reason is in the `step_up` entry, which the people seen can't read. So their "Access to your records" shows that an
    administrator looked, not why. Found by the demo household's test (`tests/test_web.py` TestDemo). Needs a schema
    change and an upgrade file; entries already written keep no reason. *Done when:* `pinakes access` and `--json` are
    tested through the API: the person seen gets each view with the step-up's reason, a person not seen gets nothing,
    the reason the same as the `step_up` entry's; the web page says the same, and TestDemo asserts it.

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

The assistant is meant to be the main way in (DESIGN.md "Wish: an MCP server"); this came first, and helps the command
line and the web UI as much. 61, 62, 68, 69 and 70 are built (REARVIEW.md). Left: the items below, moved here from the
persona reviews ("Copies, metadata and plain answers", "A household's answers") because each changes what the API tells
a model, which repeats an answer where a person would doubt it. Also before 24, the part of two items left where they
are: 76's rule for `--json` (UTC with its offset) and 78's edits named by their folder in `pinakes edits` and `--json`
(an MCP write's preview names its files the same way); their web halves can follow.

71. [Correctness] **Say what a metadata answer can't see:** EXIF is read from JPEG only (`schemas/exif.toml`), so
    `meta exif.make=...` leaves the RAWs out and says nothing. Under a `meta` answer: "EXIF is read from
    JPEG only; N other image files under your roots aren't searched", N counted under row-level security. *Done
    when:* `pinakes meta` and its `--json` (the count as a field) are tested through the API on generated JPEGs and
    RAWs, and the web page says the same.
74. [Correctness] **`only-here` with nothing to list says why:** "none: all N files have a copy on another disk", with
    the folder's last scan date, not "(none)", which reads the same as an empty folder. *Done when:* `pinakes
    only-here` is tested through the API on a folder fully copied and an empty one, and `--json` carries N and the
    scan date.
77. [Feature] **Find by a folder's name too:** `find beach`, where only a folder is named so, answers "no file
    matches", and the person looking for "the beach photos" is told there are none. Wanted: folders matched as well,
    or "no file is named so; N files are under folders named so", counted under row-level security. *Done when:*
    `pinakes find` and its `--json` are tested through the API on a generated tree with a matching folder and no
    matching file, a second person's folder of that name not counted; and the web page says the same.
79. [Security; also correctness] **A person's home page shows what concerns them:** a child's home page lists every
    root and host, a sibling's laptop with 0 files among them, and a "Not heard from" box saying that laptop is off,
    in raw values (`2026-11-17 19:47:14.251293-05:00`, `1 day, 0:00:00`; `pinakes stale` prints the same). Wanted:
    roots holding nothing the person can see left off their home page and `pinakes roots`; "Not heard from" for
    operators and for the people with files on that host; ages in words ("4 days ago"). *Done when:* `pinakes roots`
    and `pinakes stale` and their `--json` are tested through the API: a person with nothing on a root doesn't get it,
    `stale` answers a person only for hosts holding their files and an operator for all, and the plain output says
    the age in words; and the home page says the same.

## Soon: add-on modules

Optional pieces that sit on the API and tokens, not in the core: a site that doesn't install one loses nothing.

24. [Feature; also security] **MCP server**, an add-on module (DESIGN.md "Wish: an MCP server"), on the API and tokens
    of 34, after 61 and 62 and the items under "Before the MCP server": the read-only queries, and review marks, tags
    and notes and lineage decisions with the review and tag scopes, each write a preview and then an apply; streamable
    HTTP behind the proxy, each connection with its own person's token. No new powers in the core, and the core runs
    without it (the token form's note on what an assistant receives is built: REARVIEW.md "Before 24"). A person asks
    through their assistant; what it did they see with `pinakes access` and `pinakes edits`. *Done when:* tests show a
    token acting as one person under row-level security, two connections with two people's tokens each seeing only their
    own, never stepping up, leaving protected roots out unless added, every call logged, a write changing nothing before
    its apply, and that write listed by `pinakes edits` and undone by `pinakes undo`.
