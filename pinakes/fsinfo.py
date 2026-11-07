"""File metadata through statx(2), for birth time, with a plain lstat fallback.

Python's os.stat has no birth time on Linux (no st_birthtime, no os.statx up to 3.13), so this calls statx through
ctypes. The kernel fills a 256-byte struct: it must be declared in full, or the kernel writes past the buffer.
"""

import ctypes
import ctypes.util
import os
from collections import namedtuple

Info = namedtuple("Info", "size mtime_ns ctime_ns btime_ns dev ino nlink uid mode")

_AT_FDCWD = -100
_AT_SYMLINK_NOFOLLOW = 0x100
_STATX_BASIC_STATS = 0x7FF
_STATX_BTIME = 0x800


class _Ts(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_int64), ("nsec", ctypes.c_uint32), ("_reserved", ctypes.c_int32)]


class _Statx(ctypes.Structure):
    _fields_ = [
        ("mask", ctypes.c_uint32), ("blksize", ctypes.c_uint32), ("attributes", ctypes.c_uint64),
        ("nlink", ctypes.c_uint32), ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32), ("mode", ctypes.c_uint16),
        ("_spare0", ctypes.c_uint16), ("ino", ctypes.c_uint64), ("size", ctypes.c_uint64),
        ("blocks", ctypes.c_uint64), ("attributes_mask", ctypes.c_uint64),
        ("atime", _Ts), ("btime", _Ts), ("ctime", _Ts), ("mtime", _Ts),
        ("rdev_major", ctypes.c_uint32), ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32), ("dev_minor", ctypes.c_uint32),
        ("mnt_id", ctypes.c_uint64), ("dio_mem_align", ctypes.c_uint32), ("dio_offset_align", ctypes.c_uint32),
        ("_spare3", ctypes.c_uint64 * 12),
    ]


assert ctypes.sizeof(_Statx) == 256, ctypes.sizeof(_Statx)


def _load_statx():
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
        fn = libc.statx
    except (OSError, AttributeError):
        return None
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(_Statx)]
    fn.restype = ctypes.c_int
    return fn


_statx = _load_statx()


_NS_MIN, _NS_MAX = -2**63, 2**63 - 1  # what the catalog can hold (SQLite and PostgreSQL integers): 1677 to 2262


def _fit(ns):
    """ns, or None (unknown) if it is outside what the catalog can hold: a clock or filesystem gone wrong."""
    return ns if ns is not None and _NS_MIN <= ns <= _NS_MAX else None


def _ns(ts):
    return _fit(ts.sec * 1_000_000_000 + ts.nsec)


def info(path):
    """Metadata of path without following a final symlink. btime_ns is None where the filesystem has none; any time
    is None where it is outside 1677 to 2262."""
    if _statx is not None:
        buf = _Statx()
        if _statx(_AT_FDCWD, os.fsencode(path), _AT_SYMLINK_NOFOLLOW, _STATX_BASIC_STATS | _STATX_BTIME,
                  ctypes.byref(buf)) == 0:
            return Info(buf.size, _ns(buf.mtime), _ns(buf.ctime),
                        _ns(buf.btime) if buf.mask & _STATX_BTIME else None,
                        os.makedev(buf.dev_major, buf.dev_minor), buf.ino, buf.nlink, buf.uid, buf.mode)
        err = ctypes.get_errno()
        if err not in (38,):  # ENOSYS: the kernel has no statx; fall back
            raise OSError(err, os.strerror(err), path)
    st = os.lstat(path)
    return Info(st.st_size, _fit(st.st_mtime_ns), _fit(st.st_ctime_ns), None, st.st_dev, st.st_ino, st.st_nlink,
                st.st_uid, st.st_mode)


def has_statx():
    return _statx is not None
