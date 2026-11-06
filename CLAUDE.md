# file-catalog

A cross-machine file catalog for a home lab: see `README.md` and `DESIGN.md`. Status: design only.

Not decided yet: the name, publishing.

## Rules for Claude in this repo

- Nothing here is about one person's lab. No real addresses, MACs, host names, user names, domains, paths or folder
  names from a real site, in code, config examples, tests, fixtures or commit messages. Use placeholders: machines
  `server-1`, `workstation-1`, `laptop-1`; users `admin`, `user`; LAN `192.0.2.0/24`; domains `example.net`; paths
  `/mnt/store`, `/home/user`.
- Everything site-specific is configuration. If code needs a name, path or address, it reads it from config.
- Tests use generated trees in a temporary directory, never a real one.
- Run `tools/leak-scan --all` before every commit and show the result. Fix findings; don't allowlist them without
  asking.
- Verify, never assume: read back and checksum every file written. Say what was run and what was not; code is
  "tested" only if it ran on the stated OS, Python version and hardware.
- No remote and no push unless the owner says so. Stage only the files you changed.
- Be concise, lead with the result, don't build ahead of what was asked.
