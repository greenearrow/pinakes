"""Batches waiting to be sent: gzip-compressed JSON lines, one header line first.

A batch file is written to a temporary name, flushed to disk and renamed into place; only then is the local state
committed. A crash between the two leaves a batch whose records are sent again by the next scan: the ingester treats
a repeated record as no change.
"""

import gzip
import json
import os
import re

from . import BATCH_FORMAT

_NAME = re.compile(r"(\d{9})\.jsonl\.gz\Z")


def batch_name(seq):
    return "%09d.jsonl.gz" % seq


class BatchWriter:
    def __init__(self, outbox, header):
        os.makedirs(outbox, exist_ok=True)
        self.outbox = outbox
        self.header = dict(header, t="batch", format=BATCH_FORMAT)
        self.records = []

    def add(self, rec):
        self.records.append(rec)

    def __len__(self):
        return len(self.records)

    def write(self, seq, complete):
        """Write the batch durably as sequence number seq; returns its path."""
        header = dict(self.header, seq=seq, complete=complete, records=len(self.records))
        final = os.path.join(self.outbox, batch_name(seq))
        tmp = final + ".tmp"
        with open(tmp, "wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                gz.write((json.dumps(header, sort_keys=True) + "\n").encode())
                for rec in self.records:
                    gz.write((json.dumps(rec, sort_keys=True) + "\n").encode())
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(tmp, final)
        dfd = os.open(self.outbox, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return final


def pending(outbox):
    """(seq, path) of every batch waiting, oldest first."""
    if not os.path.isdir(outbox):
        return []
    out = []
    for name in os.listdir(outbox):
        m = _NAME.match(name)
        if m:
            out.append((int(m.group(1)), os.path.join(outbox, name)))
    return sorted(out)


def read(path):
    """The header and records of a batch file."""
    with gzip.open(path, "rt") as f:
        lines = [json.loads(line) for line in f]
    if not lines or lines[0].get("t") != "batch":
        raise ValueError("%s: no batch header" % path)
    return lines[0], lines[1:]


def ack(outbox, seq):
    path = os.path.join(outbox, batch_name(seq))
    if os.path.exists(path):
        os.remove(path)
