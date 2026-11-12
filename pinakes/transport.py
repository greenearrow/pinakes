"""Sending batches to the ingester.

ssh: each batch goes on stdin to `ssh -i KEY TARGET`; the server's authorized_keys forces the key to
`pinakes-ingest --host NAME`, which answers `ack SEQ` on success. What the ingester writes to stderr (metadata it
left out, progress while a scan completes) is passed on to the agent's own stderr, the journal under systemd, after
every batch, not only a refused one. directory: the batch is copied into a folder the ingester reads (for an agent on
the catalog server itself; the ingester's messages go to its own journal).

Check-in (ssh only): `ssh -i KEY TARGET hello` reaches `pinakes-ingest hello` through the same forced key (sshd
passes what was asked for as SSH_ORIGINAL_COMMAND). An ingester from before check-in reads the request as a batch and
refuses it as one; that answer means a server of protocol 0.
"""

SAID_MAX = 4000   # characters of the ingester's stderr passed on per batch: its end, where the summary is

import json
import os
import shutil
import subprocess
import sys

from . import compat, outbox


class SendError(Exception):
    pass


def send_ssh(path, seq, transport):
    """Send one batch; returns what the ingester wrote to stderr (stripped, possibly empty)."""
    timeout = transport.get("timeout", 600)
    cmd = _ssh(transport) + ["ingest"]  # the forced command runs the ingester whatever is asked for
    with open(path, "rb") as f:
        try:
            p = subprocess.run(cmd, stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            last = (e.stderr or b"").decode(errors="replace").strip().splitlines()[-1:]
            raise SendError("timed out after %ds%s" % (timeout, " (%s)" % last[0] if last else ""))
    out = p.stdout.decode(errors="replace").strip().splitlines()
    said = p.stderr.decode(errors="replace").strip()
    if p.returncode != 0 or not out or out[-1] != "ack %d" % seq:
        raise SendError("ingest refused batch %d (exit %d): %s" % (
            seq, p.returncode, (said or "\n".join(out)).strip()[-500:]))
    return said


def _ssh(transport):
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if transport.get("identity"):
        cmd += ["-i", transport["identity"], "-o", "IdentitiesOnly=yes"]
    return cmd + [transport["target"]]


# what an ingester from before check-in says to a hello, which it reads as a batch
BEFORE_CHECKIN = ("refused: not gzip", "refused: empty batch")


def hello(transport):
    """Check in with the server: its answer as a dict (release, protocol, min_agent_protocol, schema_applied,
    upgrades_missing). Raises SendError if the server can't be reached or doesn't answer."""
    req = json.dumps({"release": compat.RELEASE, "protocol": compat.PROTOCOL,
                      "min_server_protocol": compat.MIN_SERVER_PROTOCOL}).encode()
    timeout = min(transport.get("timeout", 600), 120)
    try:
        p = subprocess.run(_ssh(transport) + ["hello"], input=req, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        raise SendError("check-in timed out after %ds" % timeout)
    said = p.stderr.decode(errors="replace").strip()
    if p.returncode == 1 and said.splitlines()[-1:] and said.splitlines()[-1].strip() in BEFORE_CHECKIN:
        return {"release": None, "protocol": 0, "min_agent_protocol": 0, "schema_applied": None,
                "upgrades_missing": [], "before_checkin": True}
    if p.returncode != 0:
        raise SendError("check-in failed (exit %d): %s" % (p.returncode, said[-500:] or "no answer"))
    try:
        answer = json.loads(p.stdout.decode(errors="replace").strip().splitlines()[-1])
    except (ValueError, IndexError):
        answer = None
    if not isinstance(answer, dict):
        raise SendError("check-in: no answer the agent can read: %r" % p.stdout[-200:])
    return answer


def send_directory(path, seq, transport):
    inbox = transport["path"]
    os.makedirs(inbox, exist_ok=True)
    final = os.path.join(inbox, os.path.basename(path))
    tmp = final + ".tmp"
    shutil.copyfile(path, tmp)
    with open(tmp, "rb") as f:
        os.fsync(f.fileno())
    os.replace(tmp, final)


def _say(text):
    print(text, file=sys.stderr, flush=True)


def send_pending(cfg, say=_say):
    """Send every waiting batch in order; stop at the first failure. Returns (sent, error or None). What the
    ingester said about a batch it applied goes to say(), one line each, marked with the batch."""
    sent = 0
    for seq, path in outbox.pending(cfg.outbox):
        try:
            if cfg.transport["kind"] == "ssh":
                said = send_ssh(path, seq, cfg.transport)
            else:
                said = send_directory(path, seq, cfg.transport)
        except (OSError, SendError) as e:
            return sent, "batch %d: %s" % (seq, e)
        if said:
            cut = len(said) > SAID_MAX
            for line in said[-SAID_MAX:].splitlines()[1 if cut else 0:]:
                say("batch %d: ingest said: %s" % (seq, line))
        outbox.ack(cfg.outbox, seq)
        sent += 1
    return sent, None
