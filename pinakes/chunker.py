"""Content-defined chunking (FastCDC-style gear hash with normalized chunking), standard library only.

Boundaries depend only on content and the parameters, so an edit in the middle of a file changes the chunks around
it and leaves the rest identical, on every machine. The gear table is derived from SHA-256 so it is the same
everywhere and in every version; changing it, or the cut rule, changes every chunk (bump CHUNKER_ID if so).

Pure Python: about one to ten megabytes a second, so chunking is meant for the roots that need lineage (drop
folders, documents, writing), not for a whole media disk.
"""

import hashlib

CHUNKER_ID = "fastcdc-gear64-v1"
_M64 = (1 << 64) - 1
_GEAR = [int.from_bytes(hashlib.sha256(b"pinakes-gear-" + bytes([i])).digest()[:8], "big") for i in range(256)]


def _mask(bits):
    bits = max(1, min(bits, 63))
    return ((1 << bits) - 1) << (64 - bits)


class Params:
    def __init__(self, average=256 * 1024, minimum=None, maximum=None):
        if average & (average - 1):
            raise ValueError("average chunk size must be a power of two")
        self.average = average
        self.minimum = minimum or average // 4
        self.maximum = maximum or average * 8
        bits = average.bit_length() - 1
        self.mask_small = _mask(bits + 1)   # harder to cut before the average: fewer tiny chunks
        self.mask_large = _mask(bits - 1)   # easier after it: fewer huge chunks

    def ident(self):
        return "%s:%d:%d:%d" % (CHUNKER_ID, self.minimum, self.average, self.maximum)


class Chunker:
    """Feed bytes with update(); collect (offset, length, digest) tuples from chunks; call finish() at the end."""

    def __init__(self, params, digest_len=16):
        self.p = params
        self.digest_len = digest_len
        self.chunks = []
        self._buf = bytearray()
        self._offset = 0   # file offset of _buf[0]

    def _cut(self, data, start):
        """Index (exclusive) of the next boundary at or after start in data, or None if more data is needed."""
        p = self.p
        n = len(data) - start
        if n <= p.minimum:
            return None
        end = start + min(n, p.maximum)
        normal = start + p.average
        h = 0
        i = start + p.minimum
        gear = _GEAR
        mask_s, mask_l = p.mask_small, p.mask_large
        while i < end:
            h = ((h << 1) + gear[data[i]]) & _M64
            if i < normal:
                if not h & mask_s:
                    return i + 1
            elif not h & mask_l:
                return i + 1
            i += 1
        return end if n >= p.maximum else None

    def _emit(self, start, stop):
        piece = bytes(self._buf[start:stop])
        self.chunks.append((self._offset + start, stop - start,
                            hashlib.sha256(piece).hexdigest()[: self.digest_len * 2]))

    def update(self, data):
        self._buf += data
        start = 0
        while True:
            cut = self._cut(self._buf, start)
            if cut is None:
                break
            self._emit(start, cut)
            start = cut
        if start:
            del self._buf[:start]
            self._offset += start

    def finish(self):
        if self._buf:
            self._emit(0, len(self._buf))
            self._offset += len(self._buf)
            self._buf = bytearray()
        return self.chunks


def chunk_bytes(data, params):
    c = Chunker(params)
    c.update(data)
    return c.finish()
