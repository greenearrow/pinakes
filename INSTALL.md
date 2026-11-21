# Installing pinakes

One catalog server, an agent on each machine whose files are catalogued, and the `pinakes` command wherever people
want it. This guide sets up a site from nothing: the server first, then each machine, then the people.

The examples use placeholders: the catalog server `server-1` (reachable as `server-1.example.net`), a storage machine
`workstation-1`, a laptop `laptop-1`, people `user-1` and `user-2`, and the web UI at
`https://pinakes.example.net`. Put your own in their place. Every command that needs root is shown with `sudo`.

What this guide was checked on, and what it wasn't, is at the end ("How this guide was checked").

## What you need

- **The catalog server:** Debian-family Linux with systemd, Python 3.10+ with `venv`, PostgreSQL 15+ (on the same
  machine, or reachable from it), OpenSSH's server, and an HTTPS reverse proxy you already run (any that sets
  `X-Forwarded-For`, `-Proto` and `-Host`).
- **Each machine with files:** Linux with systemd, Python 3.10+ (3.10 needs `tomli`), OpenSSH's client, and the
  ability to reach the catalog server's SSH now and then. It needs no database and no open port.
- **A clone of this repository** on each machine, or a wheel built from it (`python -m build` in a clone, then copy
  `dist/pinakes-*.whl`). Pinakes is not on PyPI.

## 1. The catalog server

### The service user and the code

One system user, `pinakes`, runs the ingester (through agents' SSH keys) and the web UI, and owns its state:

```bash
sudo useradd --system --home-dir /var/lib/pinakes --shell /bin/sh pinakes
sudo install -d -m 700 -o pinakes -g pinakes /var/lib/pinakes /var/lib/pinakes/.ssh
sudo python3 -m venv /opt/pinakes/venv
sudo /opt/pinakes/venv/bin/pip install '/path/to/pinakes[server]'
```

Its shell must be a real one (`/bin/sh`): sshd runs the agents' forced command through it.

### The database

Three roles: `pinakes_owner` owns the schema and can't log in; `pinakes_ingest` is the ingester and bypasses
row-level security; `pinakes_app` is the web UI and API, under it. As PostgreSQL's superuser (`sudo -u postgres psql
-v ON_ERROR_STOP=1`):

```sql
CREATE ROLE pinakes_owner NOLOGIN;
CREATE ROLE pinakes_ingest LOGIN BYPASSRLS;
CREATE ROLE pinakes_app LOGIN;
CREATE DATABASE pinakes OWNER pinakes_owner ENCODING UTF8;
REVOKE ALL ON DATABASE pinakes FROM PUBLIC;
GRANT CONNECT ON DATABASE pinakes TO pinakes_ingest, pinakes_app;
\password pinakes_ingest
\password pinakes_app
```

`\password` asks for each password at a hidden prompt and sends only its hash. Keep both for the next step.

Then apply the schema, as its owner:

```bash
sudo -u postgres psql -v ON_ERROR_STOP=1 -d pinakes -c 'SET ROLE pinakes_owner' \
    -f - < /opt/pinakes/venv/lib/python3*/site-packages/pinakes/schema.sql
```

### Secrets and configuration

Secrets live each in its own file, readable by `pinakes` alone, never in a config file:

```bash
sudo install -d -m 750 -o root -g pinakes /etc/pinakes/secrets
sudo sh -c 'umask 027; head -c 32 /dev/urandom | base64 > /etc/pinakes/secrets/session-key'
sudo sh -c 'umask 027; cat > /etc/pinakes/secrets/ingest-db-password'   # paste pinakes_ingest's, then Ctrl-D
sudo sh -c 'umask 027; cat > /etc/pinakes/secrets/app-db-password'      # paste pinakes_app's, then Ctrl-D
sudo chgrp pinakes /etc/pinakes/secrets/*
```

Copy [server.example.toml](server.example.toml) to `/etc/pinakes/server.toml` (mode 644: it holds no secret) and
edit it:

- `[database]` and `[web]`: the two DSNs and the secret files above. `[web] listen` is where waitress listens
  (`127.0.0.1:8080`: only the proxy reaches it); `public_url` is the address people use; keep
  `behind_proxy = true`.
- `[people.NAME]`: everyone who signs in, with their roles (`person`; `operator` to run the system;
  `administrator`, which takes effect only in a step-up). No passwords here.
- `[groups.NAME]`: a household's shared owner, with its members.
- `[ownership]`: who owns what. `default_owner` gets every file no rule claims; each `[[ownership.rule]]` gives a
  folder of a root to a person or group (or `owner = "uid"`, by the files' owners on disk), and each
  `[[ownership.enrollment]]` adds a co-owner, reader or annotator. They are copied into the catalog when a root first
  reports, and editing them later changes nothing for that root: get them right before each root's first scan.
  Changing owners in the web UI is not built yet (ROADMAP 8).
- `[hosts.NAME]`: every machine that sends batches, and the root labels it may report. A batch naming any other root
  is refused. `expected_every = "never"` for a laptop that is often off, so it never counts as stale.

Then seed the catalog, and set each person's first password:

```bash
sudo -u pinakes /opt/pinakes/venv/bin/pinakes-ingest --config /etc/pinakes/server.toml setup
sudo -u pinakes /opt/pinakes/venv/bin/pinakes-ingest --config /etc/pinakes/server.toml passwd user-1
```

`passwd` asks twice, at a hidden prompt, for at least 12 characters. `setup` is safe to run again, and is run
again whenever `[people]`, `[groups]` or `[hosts]` change. If it says there is no schema yet, the step before was
skipped.

### The web UI

`/etc/systemd/system/pinakes-web.service`:

```ini
[Unit]
Description=pinakes web UI
After=network-online.target
Wants=network-online.target

[Service]
User=pinakes
Group=pinakes
ExecStart=/opt/pinakes/venv/bin/pinakes-web --config /etc/pinakes/server.toml
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pinakes-web
curl -sS http://127.0.0.1:8080/health
```

`/health` answers JSON: `"database": "ok"` once the web UI reaches PostgreSQL with its role, and per host when it
last scanned. Until every host in `[hosts]` has sent its first scan the status is `stale` (HTTP 503); that is
expected on a new site, and turns to 200 as the machines report.

Point the reverse proxy's `public_url` host at `[web] listen`, over HTTPS only (session cookies are marked secure),
as the one hop in front: the web UI reads the visitor's address from `X-Forwarded-For`, and its sign-in limit counts
per address. A monitor that can't reach the proxy or the loopback can have `/health` alone on `[web] health_listen`.

## 2. Each machine with files

An agent scans the machine's own disks, read-only, keeps its state and an outbox of batches in `/var/lib/pinakes`,
and sends them to the catalog server over SSH, through a key that can do nothing but hand in a batch. Do this on
every machine, the catalog server too if it holds files ("An agent on the catalog server", below).

### The code, the user, the key

On the catalog server itself the `pinakes` user and the venv exist already: skip the first four lines.

```bash
sudo useradd --system --home-dir /var/lib/pinakes --shell /usr/sbin/nologin pinakes
sudo install -d -m 700 -o pinakes -g pinakes /var/lib/pinakes /var/lib/pinakes/.ssh
sudo python3 -m venv /opt/pinakes/venv
sudo /opt/pinakes/venv/bin/pip install /path/to/pinakes        # '/path/to/pinakes[agent310]' on Python 3.10
sudo -u pinakes ssh-keygen -q -t ed25519 -N '' -C "pinakes-agent@workstation-1" -f /var/lib/pinakes/id_ed25519
```

The agent sends with `BatchMode=yes`, so it never asks about an unknown host key: give it the server's now, and
check its fingerprint against the server's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` there):

```bash
ssh-keyscan -t ed25519 server-1.example.net | sudo -u pinakes tee /var/lib/pinakes/.ssh/known_hosts
ssh-keygen -lf /var/lib/pinakes/.ssh/known_hosts
```

### Its configuration

Copy [config.example.toml](config.example.toml) to `/etc/pinakes/agent.toml` and keep only this machine's own:

- `[agent] host`: its name in the catalog, as in the server's `[hosts]`.
- `[transport]`: `kind = "ssh"`, `target = "pinakes@server-1.example.net"`, `identity =
  "/var/lib/pinakes/id_ed25519"`.
- One `[[root]]` per scanned folder: a `label` unique across the site (and listed under this host on the server),
  the `path`, and its `kind`: `primary` (where files live), `drop` (`Downloads` and the like, where things land), or
  `backup`, with `mirrors` saying which root its snapshots copy. `protected = true` sends hashes only for a root
  whose names or content must not be read. `exclude` takes globs.

A root is one filesystem: a disk mounted inside it is reported, not walked.

### Its key on the server

On the catalog server, add one line per agent to `/var/lib/pinakes/.ssh/authorized_keys` (owned by `pinakes`, mode
600), the agent's public key after a forced command naming its host:

```
command="/opt/pinakes/venv/bin/pinakes-ingest --config /etc/pinakes/server.toml --host workstation-1",restrict ssh-ed25519 AAAA... pinakes-agent@workstation-1
```

The host comes from the key, never from the batch, so a key can only report its own host's roots. `restrict` turns
off forwarding, a terminal and everything else. Whatever the agent asks for, this command runs.

### The nightly run

`/etc/systemd/system/pinakes-agent.service`: the agent reads every file of its roots through
`CAP_DAC_READ_SEARCH` and nothing more, and writes only its own state.

```ini
[Unit]
Description=pinakes agent: scan this machine's roots and send what changed
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=pinakes
Group=pinakes
ExecStart=/opt/pinakes/venv/bin/pinakes-agent --config /etc/pinakes/agent.toml run
StateDirectory=pinakes
StateDirectoryMode=0700
AmbientCapabilities=CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
Nice=19
IOSchedulingClass=idle
CPUSchedulingPolicy=batch
TimeoutStartSec=infinity
```

A root on a disk that is mounted late wants `RequiresMountsFor=/mnt/store` in a drop-in
(`pinakes-agent.service.d/`). `/etc/systemd/system/pinakes-agent.timer`:

```ini
[Unit]
Description=pinakes agent, nightly

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pinakes-agent.timer
sudo systemctl start --no-block pinakes-agent        # the first scan, now
journalctl -fu pinakes-agent
```

The first scan hashes everything and can take hours; every one after it rehashes only what changed. Pick a time when
the machine is on and the disks are quiet (away from backup jobs). A machine that sleeps on demand can use
`[schedule] busy_command` to skip a run while something else needs it.

### A laptop or desktop: a user agent

On a machine where one person's own files are scanned (their `Downloads`, `Pictures`), the agent can run as that
person instead, with no system user: the config in `~/.config/pinakes/agent.toml` (`state` and `outbox` and the key
under `~/.local/state/pinakes`), and a user timer that runs while they are logged in. As that person:

```bash
python3 -m venv ~/.local/lib/pinakes/venv
~/.local/lib/pinakes/venv/bin/pip install /path/to/pinakes
install -d ~/.config/pinakes ~/.local/state/pinakes
ssh-keygen -q -t ed25519 -N '' -C "pinakes-agent@laptop-1" -f ~/.local/state/pinakes/id_ed25519
ssh-keyscan -t ed25519 server-1.example.net >> ~/.ssh/known_hosts     # and check its fingerprint, as above
```

Its public key goes on the server as any agent's does, with `--host laptop-1`.

```ini
# ~/.config/systemd/user/pinakes-agent.service
[Unit]
Description=pinakes agent: scan the drop folders and send what changed
ConditionACPower=true

[Service]
Type=oneshot
ExecStart=%h/.local/lib/pinakes/venv/bin/pinakes-agent --config %h/.config/pinakes/agent.toml run
Nice=19
IOSchedulingClass=idle
CPUSchedulingPolicy=batch
```

```ini
# ~/.config/systemd/user/pinakes-agent.timer
[Unit]
Description=pinakes agent (user)

[Timer]
OnStartupSec=15min
OnCalendar=*-*-* 12,20:00:00
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now pinakes-agent.timer
```

`ConditionACPower` (or `[schedule] only_on_ac = true`) keeps it off the battery. A run missed while the laptop was
off or asleep happens at the next login; its batches wait in the outbox until the server is reachable.

### An agent on the catalog server

The catalog server's own files need no SSH: `[transport] kind = "directory"` and `path = "/var/lib/pinakes/inbox"`
in its agent's config, and the ingester applies what is in that folder:

```bash
sudo -u pinakes /opt/pinakes/venv/bin/pinakes-ingest --config /etc/pinakes/server.toml inbox /var/lib/pinakes/inbox
```

To do it after every run, a drop-in, `/etc/systemd/system/pinakes-agent.service.d/inbox.conf`:

```ini
[Service]
ExecStartPost=/opt/pinakes/venv/bin/pinakes-ingest --config /etc/pinakes/server.toml inbox /var/lib/pinakes/inbox
```

### Checking a machine

```bash
sudo -u pinakes /opt/pinakes/venv/bin/pinakes-agent --config /etc/pinakes/agent.toml status   # the agent's side
sudo -u pinakes /opt/pinakes/venv/bin/pinakes-ingest --config /etc/pinakes/server.toml totals  # on the server
```

`status` says what is waiting to be sent and when each root was last scanned. `totals` gives files and bytes per
root, to compare with `pinakes-agent check`, which counts each root as a scan sees it. A root a host no longer reports
is marked there, with the command that retires it.

## 3. People

Each person signs in at `public_url` with the password set by `passwd`, then, on their account page:

- **sets a second factor** (TOTP, in any authenticator app). An administrator needs one to step up;
- **changes their password**;
- **makes a token** for each machine where they want the `pinakes` command, and later for an assistant: a name, its
  scopes (`read`; `review` and `tag` to let it mark and tag), and optionally only some roots. The token is shown once.

On that machine, the `pinakes` command needs the package (`pip install /path/to/pinakes`, in a venv of their own or
the machine's), [client.example.toml](client.example.toml) as `~/.config/pinakes/client.toml` with `url` set to
`public_url`, and the token alone in `~/.config/pinakes/token`:

```bash
install -m 600 /dev/null ~/.config/pinakes/token && nano ~/.config/pinakes/token   # paste the token
pinakes whoami
```

The token is refused if anyone else can read its file. A site with its own CA names it in `[client] ca_file`.

An operator makes an **ops token** on their account page for the server's own checks, which see no person, root or
file: `pinakes releases` (this server's release, its schema, and each agent's last check-in) and `pinakes stale`. On
the catalog server, `[client] url` can be `http://127.0.0.1:8080`.

## 4. Updating

Read the release's entry in [WHATSNEW.md](WHATSNEW.md) first: its *Before you update* says which side goes first and
which upgrade files to apply. `tools/latest-release --upgrades-after N` in a clone lists them for a site on release
N. Each runs as the schema's owner, as the schema did:

```bash
sudo -u postgres psql -v ON_ERROR_STOP=1 -d pinakes -c 'SET ROLE pinakes_owner' -f - < upgrades/NAME.sql
```

Then install the new package into each venv (`pip install --upgrade '/path/to/pinakes[server]'` on the server,
without `[server]` elsewhere) and restart the web UI (`sudo systemctl restart pinakes-web`). Agents pick up the new
code at their next run. An agent and a server that don't work together say so: the agent keeps scanning, holds its
batches, and names which side must update.

## 5. Backing up the catalog

The database holds every person's file names, places and metadata: back it up like the most private data on the site
(SECURITY.md "The database and its backups"): `pg_dump -Fc pinakes` as the superuser, kept encrypted offsite.
After restoring an older dump, `pinakes-agent scan --full` on each machine resends its records. Restoring is not
covered further here, and was not tried.

## How this guide was checked

Run as written on Linux x86-64 (Ubuntu 24.04), Python 3.12 and PostgreSQL 16.15, in a throwaway cluster that asks
the two login roles for their passwords, with paths under a temporary folder in place of `/etc`, `/opt` and
`/var/lib`, and `psql` as the cluster's superuser in place of `sudo -u postgres`:

- `pip install '.[server]'` into a new venv; the roles, the database and its grants; the schema applied as
  `pinakes_owner`; `setup` twice (the second made nothing new); `passwd`.
- `pinakes-web`: `/health` stale (503) before the first scans, 200 after; the sign-in page; `pinakes --as user-1
  whoami` signing in through the API.
- An agent's `run` sent through the forced command exactly as the `authorized_keys` line above names it, check-in
  included, with a stand-in for `ssh` that runs that command as sshd would (not a real sshd); the directory
  transport and `inbox`; `status`, `check` and `totals` agreeing.
- The five systemd units checked with `systemd-analyze verify` (not the `inbox` drop-in); they are those of a
  working deployment, with this guide's paths. None was run under systemd here.

Not checked: a real sshd, a reverse proxy, a token file (only `--as`), an ops token and `pinakes releases`, the
`inbox` drop-in, a user agent's setup and timer, the update steps, a backup and restore, and Debian itself.
