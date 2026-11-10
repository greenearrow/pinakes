"""Hidden files: by name (a dot at the start of the file's name or of a folder's above it) or by the Windows hidden
attribute, which Samba keeps in the `user.DOSATTRIB` extended attribute. Standard library only.

A file is hidden when it, or any folder above it inside its root, is hidden either way. Only the attribute is read
from the disk (an extended attribute, as stat is: no file content), and only where the platform has os.getxattr.
"""

import os
import struct

XATTR = "user.DOSATTRIB"
FILE_ATTRIBUTE_HIDDEN = 0x2
_DOSINFO_ATTRIB = 0x1        # valid_flags bit of info 3 to 5: the attributes are set
_getxattr = getattr(os, "getxattr", None)


def by_name(relpath):
    """Whether a path inside a root has a part that starts with a dot."""
    return any(p.startswith(".") for p in relpath.split("/") if p)


def dos_attrib(blob):
    """The DOS attributes from a user.DOSATTRIB value, or None if it can't be read. Samba writes xattr_DosAttrib
    (librpc/idl/xattr.idl), NDR, little-endian: a NUL-terminated `attrib_hex` ("0x22", or empty), a uint16 version
    (at an even offset), the union's uint16 switch (the version again), then, at a multiple of 4: version 1 and
    0xFFFF, uint32 attrib; versions 2 to 5, uint32 flags (valid_flags from 3) and uint32 attrib. Old Samba wrote
    only the text. The text, when there, is the attributes in hex, the same as the binary part."""
    text, nul, _ = blob.partition(b"\0")
    if text[:2] in (b"0x", b"0X"):
        try:
            return int(text[2:].decode("ascii"), 16)
        except ValueError:
            return None
    if not nul or text:
        return None
    off = len(text) + 1
    off += off % 2
    if len(blob) < off + 4:
        return None
    version, switch = struct.unpack_from("<HH", blob, off)
    off += 4
    off += -off % 4
    if version != switch:
        return None
    if version in (1, 0xFFFF) and len(blob) >= off + 4:
        return struct.unpack_from("<I", blob, off)[0]
    if version in (2, 3, 4, 5) and len(blob) >= off + 8:
        flags, attrib = struct.unpack_from("<II", blob, off)
        return attrib if version == 2 or flags & _DOSINFO_ATTRIB else None
    return None


def by_attribute(abspath):
    """Whether this path (not a symlink's target) has the DOS hidden attribute. No attribute, no xattr support or no
    right to read it: not hidden."""
    if _getxattr is None:
        return False
    try:
        blob = _getxattr(abspath, XATTR, follow_symlinks=False)
    except OSError:
        return False
    attrib = dos_attrib(blob)
    return bool(attrib is not None and attrib & FILE_ATTRIBUTE_HIDDEN)


class Hidden:
    """Whether files of one root are hidden, each folder's attribute read once per scan."""

    def __init__(self, top):
        self.top = top
        self.folders = {"": False}          # relpath of a folder -> hidden, it or any folder above it

    def folder(self, rel_dir):
        h = self.folders.get(rel_dir)
        if h is None:
            parent = rel_dir.rsplit("/", 1)[0] if "/" in rel_dir else ""
            h = self.folder(parent) or by_attribute(os.path.join(self.top, rel_dir))
            self.folders[rel_dir] = h
        return h

    def __call__(self, relpath, abspath):
        if by_name(relpath):
            return True
        rel_dir = relpath.rsplit("/", 1)[0] if "/" in relpath else ""
        return self.folder(rel_dir) or by_attribute(abspath)
