"""Sending batches to the ingester.

ssh: each batch goes on stdin to `ssh -i KEY TARGET`; the server's authorized_keys forces the key to
`pinakes-ingest --host NAME`, which answers `ack SEQ` on success. directory: the batch is copied into a folder the
ingester reads (for an agent on the catalog server itself).
"""

import os
import shutil
import subprocess

from . import outbox


class SendError(Exception):
    pass


def send_ssh(path, seq, transport):
    timeout = transport.get("timeout", 600)
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if transport.get("identity"):
        cmd += ["-i", transport["identity"], "-o", "IdentitiesOnly=yes"]
    cmd += [transport["target"], "ingest"]  # the forced command ignores what is asked for
    with open(path, "rb") as f:
        try:
            p = subprocess.run(cmd, stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            last = (e.stderr or b"").decode(errors="replace").strip().splitlines()[-1:]
            raise SendError("timed out after %ds%s" % (timeout, " (%s)" % last[0] if last else ""))
    out = p.stdout.decode(errors="replace").strip().splitlines()
    if p.returncode != 0 or not out or out[-1] != "ack %d" % seq:
        raise SendError("ingest refused batch %d (exit %d): %s" % (
            seq, p.returncode, (p.stderr.decode(errors="replace") or "\n".join(out)).strip()[-500:]))


def send_directory(path, seq, transport):
    inbox = transport["path"]
    os.makedirs(inbox, exist_ok=True)
    final = os.path.join(inbox, os.path.basename(path))
    tmp = final + ".tmp"
    shutil.copyfile(path, tmp)
    with open(tmp, "rb") as f:
        os.fsync(f.fileno())
    os.replace(tmp, final)


def send_pending(cfg):
    """Send every waiting batch in order; stop at the first failure. Returns (sent, error or None)."""
    sent = 0
    for seq, path in outbox.pending(cfg.outbox):
        try:
            if cfg.transport["kind"] == "ssh":
                send_ssh(path, seq, cfg.transport)
            else:
                send_directory(path, seq, cfg.transport)
        except (OSError, SendError) as e:
            return sent, "batch %d: %s" % (seq, e)
        outbox.ack(cfg.outbox, seq)
        sent += 1
    return sent, None
