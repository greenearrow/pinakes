# pinakes

A cross-machine file catalog for a home lab, with owners, metadata and a web UI: see `README.md`, `DESIGN.md`,
`SECURITY.md` and `METADATA.md`. Status: design only.

Decided: Python 3.11+; the standard library first, and where a dependency is needed, Flask and waitress for the
web. Publishing: the source is public on GitHub (owner, 2026-11-22); no package is published yet. A wish, not a requirement: an MCP server over the queries, review marks and tags.

## Rules for Claude in this repo

- Nothing here is about one person's lab. No real addresses, MACs, host names, user names, people, domains, paths or
  folder names from a real site, in code, config examples, tests, fixtures or commit messages. Use placeholders:
  machines `server-1`, `workstation-1`, `laptop-1`; people `user-1`, `user-2`, group `household`; LAN
  `192.0.2.0/24`; domains `example.net`; paths `/mnt/store`, `/mnt/backup`, `/home/user`.
- Everything site-specific is configuration. If code needs a name, path or address, it reads it from config.
- Pinakes never gives access to a file: no download, upload, opening or editing, by any route (DESIGN.md
  "Principles"). Don't build toward it.
- Security is part of every change: anything that names or describes a file is under row-level security; agents get
  no new powers the machine's local config hasn't granted (SECURITY.md).
- A new ROADMAP item that gives a person something to ask or do names the `pinakes` command in its *done when*
  (ROADMAP.md, above the items).
- Tests use generated trees in a temporary directory, never a real one.
- Run `tools/leak-scan --all` before every commit and show the result. Fix findings; don't allowlist them without
  asking.
- Verify, never assume: read back and checksum every file written. Say what was run and what was not; code is
  "tested" only if it ran on the stated OS, Python version and hardware.
- No remote and no push unless the owner says so. Stage only the files you changed.
- Be concise, lead with the result, don't build ahead of what was asked.
