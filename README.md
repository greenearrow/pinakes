# file-catalog

A catalog of every file on every machine in a home lab: path, size, times and SHA-256, kept current by cheap
incremental scans, so questions like "where are all copies of this", "what exists only on this laptop" and "is this
folder safe to delete" are one indexed query instead of a one-off hashing script.

**Status: design only.** Nothing is built or tested. Read [DESIGN.md](DESIGN.md); the configuration format is in
[config.example.toml](config.example.toml).

- One agent per machine scans its own disks, read-only, and rehashes only what changed.
- Batches go to a central ingester (PostgreSQL, or SQLite for a single machine). Agents hold no database credentials.
- Machines that are often off scan when they're on and send later.
- Renames are detected by hash, inode and (optionally) content-defined chunk overlap, with the evidence recorded.

Target: Debian-family Linux with systemd, Python 3.11+.

Licence: GPL-3.0 ([LICENSE](LICENSE)).

## Contributing

Run `git config core.hooksPath githooks` once. The hooks run `tools/leak-scan`, which blocks addresses, MACs, LAN
host names, email addresses, keys and your own private terms (`leak-patterns.example`) from being committed.
