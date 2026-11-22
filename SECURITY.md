# Security design

Status: design only. Several people share one catalog. Each sees their own files; an administrator sees other
people's only by deliberately stepping up, and the people affected can see that it happened.

## What the catalog protects, and what it doesn't

The catalog holds the names, places, sizes, hashes and metadata of everyone's files. That is sensitive in itself:
file names and photo locations say a lot about a person. The catalog must not make anything **less** private than it
is on the disks.

It cannot make anything **more** private than the disks. Whoever can read a folder on the machine can read the files,
whatever the catalog shows them. Whoever has root on the catalog server, or is a database superuser, can read the
whole catalog. The guarantees below are about access through the catalog (its web UI, API and CLI), enforced in the
database, with an audit trail. They are not cryptographic.

## People and roles

| Role | Can |
|---|---|
| **person** | See and manage their own files and what is shared with them. Everyone who signs in is a person. |
| **operator** | Run the system: hosts, roots, agents, health, schedules. Sees counts, sizes, ages and errors per root, never file names or metadata of other people. |
| **administrator** | Everything, but only during a **step-up session**. Outside one, an administrator is just a person. |
| **auditor** (planned, ROADMAP 86) | Read, in one approved audit of named people and folders, entries that may be held for a capped time. Every administrator has it unless the site's config takes it away; others only if the config names them. "Auditors" below. |

The site's administrator normally works as a person. To see someone else's records they step up:

1. Re-authenticate (password plus a second factor) and give a reason.
2. The session is time-limited (default 15 minutes) and shown with a banner on every page.
3. Every record viewed or changed in it is written to the `audit` table: who, when, reason, which records (by folder,
   with counts, so the log stays readable).
4. The people whose records were seen get an entry on their own "Access to your records" page, and optionally a
   notification.

The audit table is append-only for every role the application uses (no `UPDATE` or `DELETE` granted); only the
database superuser could change it.

A **standing view** (planned, ROADMAP 82 and 83; "Standing views" below) is not a role: it lets one named person see
another's records within a reach, without a step-up, and only for a person the site's config names as viewable so.

## Ownership

Every file row has one owner, set by the ingester from the site default owner and the folder rules (DESIGN.md
"Ownership and enrollments"). Backup copies inherit the owner of the source file they mirror. A file no rule claims
goes to the site default owner, never to "everyone"; or (planned, ROADMAP 84), under a rule that holds its folder
unclaimed, to nobody: in no person's view, seen by administrators in a step-up and by operators as counts, until an
administrator gives it to someone in a step-up.

Owners can share a file, folder or bundle with a person or a group (read, or read and annotate), and enroll people in
a folder as co-owners, readers or annotators. A household can have folders owned by a group.

Who may change ownership:

- A folder's owner (or co-owner) may give it to someone else and enroll or remove others.
- Nobody takes ownership of someone else's folder as a person. An administrator can, in a step-up session, with a
  reason; the previous owner is told.
- Every change of a rule or an enrollment is in the audit log, shown to the people it affects.
- A new rule applies at once to every file it covers, with no rescan, so its effect is previewed first ("this moves
  1,204 files from user-1 to user-2") before it is saved.

## Enforcement: row-level security

Visibility is enforced by PostgreSQL row-level security on every table that names or describes a file (`files`,
`links`, `history`, `members`, `chunks`, `metadata`, `bundles`, `shares`, `operations`), not by `WHERE` clauses in
application code. A policy allows a row when:

- its owner is the current person, or
- it is shared with the current person or one of their groups, or
- the current session is an active administrator step-up (checked against a `step_ups` table with an expiry; the
  check also writes the audit row), or
- (planned, ROADMAP 82) the current person holds a standing view of its owner that reaches it: a member of the row's
  ACL with the view's own role, so it is the same array test, and a private folder's ACLs leave the view out, or
- (planned, ROADMAP 86) the current session is an auditor's open, approved audit whose scope (people, folders, time
  window) holds the row.

The history of the catalog's own writes (`edits`, `edit_items`, ROADMAP 62) is narrower: a person sees only their own
edits and their groups', never another person's, not in a step-up either; and of an edit only the values on files
they can still see (under a token, in its roots).

The web service connects as one unprivileged role that is subject to these policies, and sets the signed-in person
for each transaction. This guards against bugs (a forgotten filter, a crafted query parameter). It does not guard
against a compromised web service, which could claim to be anyone: that is the line where "root on the catalog
server" begins.

`contents` (hash, size, type) is shared by all copies. A person reaches a content row only through a file they can
see; there is no query by hash outside one's own files.

## Standing views (planned: ROADMAP 82, 83)

One person sees another's records within a reach, minus folders the person marks private, as an arrangement both can
see. Kinds: *guardian* (a household: level *child*, everything but private folders; level *teenager*, only named
folders) and *supervisor* (a lab: everything but folders the student marks *independent*, or only named project
folders).

- Who may be viewed so, and by whom, is site config (`[people.NAME] standing`), the same trust as `[people]` roles:
  the database refuses a view of anyone else, so an adult or a collaborator never gets one through the web, the API
  or a step-up. A view seeded from config is audited and shown on the person's page at the next `setup`.
- An administrator sets its level and folders in a step-up with a reason, after a preview equal to the result.
  Narrowing it is shown to the person with the reason. Ending it needs no step-up and can't be undone; entries
  already written stay.
- It is a reader's view: no review marks, tags, lineage decisions or shares. Sensitive fields (GPS, people) by
  level: *child*, included (a safety value); *teenager*, not (a step-up reaches them); *supervisor*, never (a lab's
  locations are participants' data).
- A private folder is the person's own to mark, without the viewer agreeing: the viewer is an administrator who can
  always step up, so what holds them back is restraint, made visible, not a lock. Its backup copies follow it. The
  viewer gets nothing of it: no row, count or copy in any report or export, and not in copy reasoning ("safe to
  delete" for the viewer can't count a copy there). At *child* they see one line that a private folder exists, with
  no name, count or size; at *teenager* not even that, and no opaque container in it is named, since making something
  private is itself private. Reaching it is an ordinary step-up, audited and shown as one.
- Lab files (ones the supervisor sees) put into an independent folder are shown to the student first, and the
  supervisor is told their names and sources, never the folder's name or its other files: data leaving the lab's view
  is never silent, and the supervisor knows which backup copies hold it.
- Every look is on the person's "Access to your records" as its own kind, by folder with counts, never as a step-up.
- Under a token: left out unless its maker adds it, with the warning that the records go to whoever runs the
  assistant; never in a group token; no token sets, changes or ends one.
- The operator page's per-person totals are unchanged by it.

An administrator's step-up is never held, an inquiry's included: it shows on the person's page at once (owner's
decision, 2026-11-22). An inquiry that must not alert its subject uses an auditor.

## Auditors (planned: ROADMAP 86)

An auditor sees records in one audit whose entries may be held from their subjects for a capped time. A held audit is
for cases where warning its subject is dangerous (grooming, self-harm, someone else involved, an inquiry); for
anything else a step-up, shown at once, is the normal path. These are the defaults; each site sets its own within the
limits in "What no site can change" below, and shows its policy to everyone in it.

- Every administrator has the role unless the site's config takes it from them, so a site can keep an administrator
  to step-ups only; anyone else has it only if the config names them, and the database refuses it to everyone else. A
  site with no one holding it can hold nothing. Web only, with a second factor: no token, no `--as`, no assistant.
- Three different people: a requester (an auditor), an approver (another auditor or an administrator), and the subjects;
  the requester and approver are never the same person nor among the subjects, enforced by the database. A subject may
  be the site's administrator, so an administrator is never an audit's only check.
- The scope (people, folders, a time window) is set before it opens; the audit reaches only that, and widening it
  needs a new audit. Sensitive fields (GPS, people's names) are in it only when the scope names them before it opens
  (a child's safety can need them). Read-only: no marks, tags, shares, ownership changes or sensitive-field sharing;
  an export is recorded as part of it.
- A hold is capped (default 90 days); a renewal needs the approver again and is logged. At the cap the entries show on
  each subject's "Access to your records" by themselves, complete: requester, approver, reason, scope (with whether it
  held sensitive fields), each folder seen with counts, and how long they were held.
- A **solo hold** has no approver, and is allowed only while exactly one person on the site is an administrator or
  an auditor (a single parent running the server, who could read the disks anyway; an approver brought in from
  outside would cost the subject more privacy, not less). Its cap is shorter (default 14 days), it can't be renewed,
  it shows by itself at the cap, and its entry says it was held alone with no approver, with the reason and every
  folder seen. Making a site solo is a policy change, shown to everyone at once.
- Every page shows everyone on the site how many audits are held (solo ones included) and the latest date one ends,
  without names: a hold hides who is looked at, not that someone is. Collusion of requester and approver is the risk
  left; the count and the cap limit it. On a site of few people the count itself narrows who it could be.
- The limit, as for step-ups: the database superuser, root on the catalog server and whoever runs the disks are
  outside all of this.

## What no site can change (planned: ROADMAP 87)

The rules in "Standing views" and "Auditors", and the caps, levels and flags behind them, are defaults: a household
or a lab sets its own in the site's config. What a site has set is shown to everyone in it, in words, generated from
the settings the server runs (a page and `pinakes policy`): at account creation, and again after every change until
the person has opened it. Each change is recorded with what changed, when, and the person `setup` names (the
operator's word: a config file has no signed-in author).

A setting can make a site stricter than the default, and looser only within these, each enforced in the database or
the agent, not by the page; `setup` refuses a config that goes past one:

- Visibility is row-level security in the database, never a filter in the application.
- The audit table is append-only for every role the application uses.
- Every step-up shows on the people's page at once; only an auditor's audit is ever held, and every hold shows by
  itself at its cap, which no setting removes.
- Requester, approver and subject of an audit are three different people, except in a solo hold, which is allowed
  only while one person on the site is an administrator or an auditor.
- A standing view only of a person the config names as viewable so, never extending to step-up powers, and every look
  on the person's page.
- No token or assistant steps up, audits, or sets, changes or ends a standing view.
- Pinakes never gives access to a file (DESIGN.md "Principles").
- The server can't widen an agent's local config: `managed`, protected roots and opaque folding are the machine's own.
- The policy page itself, and the record of its changes, can't be turned off.
- And the limit no setting changes: the database superuser, root on the catalog server and whoever runs the disks are
  outside all of this.

## Copies across owners

Deduplication can leak: "where are all copies of this file" would reveal that another person holds the same file.

- A person's queries only consider copies they can see. Copies in someone else's space are not shown or counted.
- So "safe to delete" for a person means "you can see another kept copy". If the only other copy is someone else's,
  the answer is no, which is the safe answer.
- Backups of a person's own files are theirs (inherited owner), so "is this backed up" works without seeing anyone
  else's records.
- Cross-owner duplicate reports are administrator-only.

## Agents

- Each host's agent has its own SSH key, forced on the catalog server to `pinakes-ingest --host NAME`. The host
  name comes from the key, never from the batch.
- The same key reaches one more thing, the check-in: when the agent asks for `hello` (sshd's
  `SSH_ORIGINAL_COMMAND`), the ingester reads the agent's release and protocol (numbers only, at most 4 KiB),
  records them for the key's host, and answers this server's release and protocol, whether its schema is
  applied, and the last batch number applied for that host (with its header's digest). No root, file or person is
  named either way; anything else asked for is still read as a batch.
- A batch from an agent whose protocol this server doesn't work with (`pinakes/compat.py`) is refused before
  anything is applied; the reason goes to the agent and to the server's system log.
- The ingester rejects any path outside the roots enrolled for that host, and any batch that doesn't continue the
  host's sequence (other than the same batch sent again). A complete full scan retires files only of its own root,
  as its gone records could already.
- An agent can't read the catalog. It can fetch only approved operations for its own roots. It never sends a file
  to the server, only records (and previews, where a root enables them).
- Operations are limited by the agent's **local** config (`managed` per root). The server can't widen them: a
  compromised server could at worst ask for moves and renames the machine's owner already allowed, never a deletion.
  The agent re-checks hashes before acting and never overwrites.
- Protected roots send names, sizes, times and hashes (SHA-256 and chunk hashes) only. Nothing readable derived from
  their content leaves the machine, by any path: a hard link of a protected file in another root is protected there
  too (the agent walks its protected roots for links; a folder there it can't list protects every multi-link file
  on its filesystem). A plain copy is a new file, under its own root's rules.
- Checksum manifests (DESIGN.md "Checksum manifests") are read like any file the scan hashes, never on a
  protected root or through a protected link. What leaves the machine is a verdict per listed file it already
  reports (confirmed or wrong, and which manifest) and counts per manifest: no name, hash or line of a manifest. The
  verdicts are columns of the files, under the files policy. A manifest's counts are seen by whoever sees the
  manifest, even when some of the files it lists are someone else's: counts only, of a list its reader can open
  where it lies. The ingester refuses manifest records from a protected root, or for a manifest behind a protected
  link.
- A push monitor (`[monitor]`, off unless configured) is the agent's one outbound call besides the server: at the
  end of each run, up or down with counts and reasons from a fixed set (a root's label, a protocol, a number of
  batches), never a path, a file's name or an error's text. Its URL is a secret, kept only in the file
  `url_file` names: a config with the URL itself is refused, and no message, log line or command line carries it;
  a report that fails says why as a status code or an error's kind. It never changes the run's exit status.
- Resolving a symlink's target looks names up (`lstat`, never reading a file) only inside the agent's own roots,
  as configured: a link pointing elsewhere gets no access the scan didn't already have. On the web, a link shows its
  target's page only to someone who may see that file.

## Web UI

- Accounts: local accounts (scrypt passwords, TOTP second factor; WebAuthn later), or sign-in through an OpenID
  Connect provider the site already runs (later). The second factor is required for step-up.
- HTTPS only; session cookies `Secure`, `HttpOnly`, `SameSite=Strict`; CSRF tokens on every change; short idle
  timeout.
- Reachable on the LAN or a VPN by default. Exposing it to the internet is out of scope.
- Never a file: no download, upload, opening or editing, by any route (DESIGN.md "Principles"). The only thing
  shown that is rendered from content is a preview, where a root enables it; never for a protected root.
- Rate limits on sign-in and search.
- Review marks (a gone file or a move marked intended or restore) are records about files: seen only with the file
  (row-level security), written only through `mark_changes()`, which lets the file's owner and co-owners mark it, an
  administrator only in a step-up (audited for the owners), and nobody else; readers and annotators can't. The web
  role has no write on the table itself. Under a token (`pinakes review`), `mark_changes()` also needs the token's
  `review` scope and skips changes outside its roots.
- Person-entered metadata is written only through `set_file_metadata()`: by the owner, a co-owner or an annotator
  of the file, each their own values only, never in a step-up; under a token (`pinakes tag`, ROADMAP 37) only a
  person's with its `tag` scope, in its roots, never a group's; entering on another person's file is audited for its
  owners. A file's sensitive fields are shared only through
  `share_sensitive()`, by its owner or a co-owner, with a reader or annotator the file is already shared with; it
  shares no file, lapses when that person no longer sees it, is audited for them and the other owners, and the list
  of who has them (`sensitive_sharing()`) is the owners' only. The web role reads and writes neither table directly.
- Lineage decisions (a relative confirmed or rejected) are written only through `decide_lineage()`: by the owner or a
  co-owner of the later file, with both files visible to them, or an administrator in a step-up; a decision that
  touches another person's file is audited for them. Under a token it needs the `review` scope and stays in its roots;
  a group token never decides. The web role has no write on `lineage`.
- Placeholder marks (ROADMAP 69) are written only through `mark_placeholder()`. A mark is on a content, so it changes
  what every holder of those bytes is told: only a person who owns or co-owns every present file holding them marks
  or unmarks, or an administrator in a step-up, audited for those files' owners and co-owners. Under a token it needs
  the `review` scope and every holder in its roots; a group token never marks. A placeholder is seen by whoever sees
  a file holding it, and its candidates are counted from the files the person sees. The site's rules are server
  configuration, applied by the ingester. The web role has no write on `placeholders`.
- The operator page (`/operator`) shows every person's totals per root and what a disk's loss would cost per disk
  and per host: counts, sizes and dates, never a path, a folder, a file's name or a person. The database gives them
  (`operator_roots()`, `operator_at_risk()`) only to an operator signed in on the web, never under a token. "If a
  disk failed" shows a person their own at-risk files by folder, under row-level security, counting only the copies
  they can see; an administrator sees everyone's only in a step-up, audited for the owners.
- `/health` is the one page without sign-in, for monitoring: whether the database answers, and per host its newest
  batch, last complete scan, whether it is stale, its scrub's dates, and how many of its roots its batches no longer
  name. It names hosts and nothing else (no root, person or file, no
  error text), through `pinakes_app` with no person set, so row-level security would hide any file it touched. A
  site that doesn't want host names reachable this way blocks the path at its proxy, or serves it only on
  `[web] health_listen`, an address of its choosing that serves nothing else.

## Tokens and the CLI (person tokens built; the rest planned)

ROADMAP 34 to 40; person tokens (34, 36, 37), group tokens (38) and ops tokens (39) are built, admin tokens not. Every
person-facing function goes through the API in `pinakes-web`, and every client authenticates there; no client holds
a database credential, not even on the catalog server.

| Token | Acts as | Can |
|---|---|---|
| **person** | one person | their own files, what is shared with them and their groups'; scoped `read`, `review`, `tag` |
| **group** | one group, no member | what the group owns or has shared with it, never a member's own; made, seen and revoked by the group's members, and dead once its maker leaves; marks only where the group owns or co-owns, as the group; never tags; scoped `read`, `review`, `tag` |
| **ops** | no person (made by an operator) | `releases`, `stale` and `whoami`; never a person, root or file: the database sets no person for it, so row-level security shows it nothing |
| **admin** | an administrator (later) | every function (`*`); another person's records still only in a step-up |

- One token per person (or group) per client, stored hashed, revocable in the web UI, its last use shown, optionally
  limited to some roots; protected roots are left out unless added. Every call is logged with its token.
- A client uses one identity per command, never the sum of two. The CLI takes it from `--as`, else a token file in
  the current folder or one above it, else `~/.config/pinakes/token`; it refuses a token file others can read. A
  token in a folder is readable by whoever can read the folder, and travels with its backups: revoking it is the
  remedy.
- `--as NAME` signs in as that person, at a hidden prompt: a token of theirs, or their password and, if they have
  one, their second factor (more than the web sign-in asks: a password typed into a script is easier to take than
  one typed into a browser). Failures count in the web sign-in's own per-address limit. The answer is a `read`
  token of 10 minutes for every root but the protected ones, held in memory, revoked when the command ends and never
  listed among the person's tokens; the caller's own token isn't read. It never steps up, and the person sees the
  sign-in, its address and each call on their "Access to your records" page.
- Under a token, row-level security also holds files to the token's roots, and what depends on files (contents,
  history, lineage, metadata) follows. So does a copy: a token that can't see a root doesn't count the copies there,
  and `only-here` or `safe-to-delete` through it can only err toward "not safe".
- The database, not the application, ties a call to its token: `begin_token_call()` finds the token by its hash,
  sets the person for the transaction and records the call; `stepped_up()` is false under a token, and
  `begin_step_up()`, `make_token()` and `revoke_token()` refuse one. As with the web session, a compromised web
  service could still claim to be anyone.
- No token steps up by itself. An admin token sees another person's records only inside a step-up the
  administrator opens with password and second factor, audited as on the web.

## The MCP server (a wish)

DESIGN.md "Wish: an MCP server". Its rules:

- One token per person and client, created and revoked in the web UI, optionally limited to some roots; stored
  hashed on the server. A chat app that serves more than one person passes each person's token on their own
  connection; `pinakes-mcp` holds no token of its own.
- The token acts as that person under row-level security, with the scopes they gave it: `read`, and `review` and
  `tag` if they choose. It can never open a step-up session, fetch a file, share sensitive fields or make tokens.
- Writes ask first: a call that says what would change and changes nothing, then one that applies it. Every write
  is kept with its token and the value before, and the person sees and undoes their tokens' writes (ROADMAP 62).
- Every MCP query is logged with its token, so a person can see what their assistants asked.
- A hosted assistant receives the names and metadata its answers contain. The UI says so when the token is made.
- Protected roots are not in a token unless the person adds them, after a warning that the records go to whoever
  runs the assistant.
- Later, with the operation queue (ROADMAP 17): an assistant may request a change on disk only to a file the catalog
  says a backup holds; the request waits for approval and the agent's local `managed` policy like any other.

## The database and its backups

- Its dumps hold everything: back them up like the most private data in the catalog (encrypted at rest offsite).
- Removing a person removes their files' catalog records, metadata, shares and sessions; the audit entries about them
  are kept for a set period, then removed.
- Person-entered metadata could later be encrypted per person (client-side), at the cost of server-side search on it.
  Not in the first version.

## Threats considered

| Threat | Answer |
|---|---|
| A person tries to see another's files through the UI or API | Row-level security; no hash lookups outside own files. |
| The administrator browses others' files casually | Step-up with reason and second factor, time-limited, audited, visible to the people affected. |
| A bug in a query forgets the owner filter | Row-level security still applies. |
| A laptop's agent is stolen or tampered with | Its key can only submit batches for its own roots; revoke the key. It holds no database credentials. |
| A forged batch claims another host's files | Host from the SSH key; paths checked against enrolled roots. |
| The catalog is breached through the web UI or a stolen session | It holds no files and can reach none: the intruder gets what that person can see (names, hashes, metadata, previews), not file content, and no path to the disks. |
| The catalog server is compromised | Out of scope for the guarantees above. Agents still refuse deletions and anything outside their local `managed` policy. |
| Dedupe reveals someone holds a file | Copies outside one's view are neither shown nor counted. |
| A parent or supervisor browses a child's or student's records casually | Only within a standing view the site's config allows for that person, never an adult's or a collaborator's; private folders out of it, at *teenager* without a trace; sensitive fields by level; every look on the person's page; beyond it a step-up. (Planned, ROADMAP 82, 83.) |
| An inquiry has to look without alerting its subject | An auditor (administrators by default), three different people (or a solo hold, shorter and unrenewable, only on a site with one administrator or auditor), a scope set first, read-only, a capped hold that ends by itself, a held count on every page. A step-up is never held. (Planned, ROADMAP 86.) |
| A site quietly loosens its own rules | Its policy is shown to everyone, from the running config, after every change, with each change recorded; a few guarantees no setting removes. (Planned, ROADMAP 87.) |
| A new folder no rule claims becomes the default owner's, silently | A rule can hold a folder unclaimed: nobody's until an administrator gives it in a step-up. (Planned, ROADMAP 84.) |
| A folder is quietly given away or taken over | Owners give, administrators take only in step-up; audited; the affected people are told. |
| An assistant with an MCP token oversteps | The person's own view and the scopes they gave, no step-up, writes asked first, kept with the value before and undoable, revocable, logged. |
| Protected work's records reach an outside service that would use them | Protected roots: hashes only, never extracted; left out of MCP tokens unless added deliberately. Encrypted offsite backups of the database are storage, not use. |
| Photo locations or people's names leak through sharing | Metadata fields marked sensitive stay with the owner unless shared explicitly (METADATA.md). |
