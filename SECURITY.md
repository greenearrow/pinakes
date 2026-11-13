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

The site's administrator normally works as a person. To see someone else's records they step up:

1. Re-authenticate (password plus a second factor) and give a reason.
2. The session is time-limited (default 15 minutes) and shown with a banner on every page.
3. Every record viewed or changed in it is written to the `audit` table: who, when, reason, which records (by folder,
   with counts, so the log stays readable).
4. The people whose records were seen get an entry on their own "Access to your records" page, and optionally a
   notification.

The audit table is append-only for every role the application uses (no `UPDATE` or `DELETE` granted); only the
database superuser could change it.

## Ownership

Every file row has one owner, set by the ingester from the site default owner and the folder rules (DESIGN.md
"Ownership and enrollments"). Backup copies inherit the owner of the source file they mirror. A file no rule claims
goes to the site default owner, never to "everyone".

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
  check also writes the audit row).

The web service (and today the CLI, until it uses the API) connect as one unprivileged role that is subject to these
policies, and set the signed-in person for each transaction. This guards against bugs (a forgotten filter, a crafted
query parameter). It does not guard against a compromised web service, which could claim to be anyone: that is the
line where "root on the catalog server" begins.

`contents` (hash, size, type) is shared by all copies. A person reaches a content row only through a file they can
see; there is no query by hash outside one's own files.

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
  role has no write on the table itself.
- `/health` is the one page without sign-in, for monitoring: whether the database answers, and per host its newest
  batch, last complete scan and whether it is stale. It names hosts and nothing else (no root, person or file, no
  error text), through `pinakes_app` with no person set, so row-level security would hide any file it touched. A
  site that doesn't want host names reachable this way blocks the path at its proxy, or serves it only on
  `[web] health_listen`, an address of its choosing that serves nothing else.

## Tokens and the CLI (person tokens built; the rest planned)

ROADMAP 34 to 40; 34, the API and person tokens, is built. Every person-facing function goes through the API in
`pinakes-web`, and every client authenticates there; once the CLI uses it (35), no client holds a database
credential.

| Token | Acts as | Can |
|---|---|---|
| **person** | one person | their own files, what is shared with them and their groups'; scoped `read`, `review`, `tag` |
| **group** | one group, no member | what the group owns or has shared with it; made by the group's co-owners |
| **ops** | the operator role | hosts, check-ins, releases, staleness; never a person, root or file |
| **admin** | an administrator (later) | every function (`*`); another person's records still only in a step-up |

- One token per person (or group) per client, stored hashed, revocable in the web UI, its last use shown, optionally
  limited to some roots; protected roots are left out unless added. Every call is logged with its token.
- A client uses one identity per command, never the sum of two. The CLI takes it from `--as`, else a token file in
  the current folder or one above it, else `~/.config/pinakes/token`; it refuses a token file others can read. A
  token in a folder is readable by whoever can read the folder, and travels with its backups: revoking it is the
  remedy.
- `--as NAME` signs in as that person (their token, or their password and second factor, rate-limited like the web
  sign-in). The session is only theirs, is never written to disk, never steps up, and shows on their "Access to
  your records" page.
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
  hashed on the server.
- The token acts as that person under row-level security. It can never open a step-up session, fetch a file, request
  operations or edit metadata.
- Every MCP query is logged with its token, so a person can see what their assistants asked.
- A hosted assistant receives the names and metadata its answers contain. The UI says so when the token is made.
- Protected roots are not in a token unless the person adds them, after a warning that the records go to whoever
  runs the assistant.

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
| A folder is quietly given away or taken over | Owners give, administrators take only in step-up; audited; the affected people are told. |
| An assistant with an MCP token oversteps | Read-only, the person's own view, no step-up, revocable, logged. |
| Protected work's records reach an outside service that would use them | Protected roots: hashes only, never extracted; left out of MCP tokens unless added deliberately. Encrypted offsite backups of the database are storage, not use. |
| Photo locations or people's names leak through sharing | Metadata fields marked sensitive stay with the owner unless shared explicitly (METADATA.md). |
