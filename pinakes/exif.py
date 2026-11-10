"""EXIF from a JPEG (schemas/exif.toml): the standard library only, no dependency to install.

Reads the JPEG's markers up to the image data (at most MAX_HEADER bytes), takes the size from the frame header and
the fields below from the APP1 Exif segment's TIFF structure. A file is someone else's bytes: every offset and count
is checked against the segment before it is used, nothing is followed outside it, and a segment that doesn't add up
is refused, never guessed at.
"""

import datetime
import struct

MAX_HEADER = 1024 * 1024        # bytes of markers read before the image data, at most
MAX_ENTRIES = 1000              # entries in one IFD
MAX_VALUE = 64 * 1024           # bytes of one tag's value

_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}   # frame headers
# TIFF field types: (bytes per item, struct code)
_TYPES = {1: (1, "B"), 2: (1, "c"), 3: (2, "H"), 4: (4, "L"), 5: (8, "LL"), 7: (1, "B"), 9: (4, "l"), 10: (8, "ll")}

# IFD0
MAKE, MODEL, EXIF_IFD, GPS_IFD = 0x010F, 0x0110, 0x8769, 0x8825
# the Exif IFD
EXPOSURE, FNUMBER, ISO, TAKEN, TAKEN_OFFSET, FOCAL, LENS = 0x829A, 0x829D, 0x8827, 0x9003, 0x9011, 0x920A, 0xA434
# the GPS IFD
LAT_REF, LAT, LON_REF, LON = 1, 2, 3, 4


class BadExif(ValueError):
    pass


def segments(f):
    """(marker, body) of each segment before the image data."""
    if f.read(2) != b"\xff\xd8":
        raise BadExif("not a JPEG")
    read = 2
    while read < MAX_HEADER:
        b = f.read(1)
        if not b:
            return
        if b != b"\xff":
            raise BadExif("no marker at byte %d" % read)
        m = f.read(1)
        read += 2
        while m == b"\xff":                         # fill bytes
            m = f.read(1)
            read += 1
        if not m:
            return
        code = m[0]
        if code in (0xD9, 0xDA):                    # end of image, start of scan: no headers after
            return
        if 0xD0 <= code <= 0xD7 or code == 0x01:    # markers without a body
            continue
        n = f.read(2)
        if len(n) < 2:
            return
        n = struct.unpack(">H", n)[0]
        if n < 2:
            raise BadExif("segment length %d at byte %d" % (n, read))
        body = f.read(n - 2)
        read += n
        if len(body) < n - 2:
            return                                  # cut short: what came before still counts
        yield code, body


def _ifd(data, off, bo):
    """{tag: value} of the IFD at off: text as str, numbers as a tuple, rationals as a tuple of (num, den)."""
    if off < 8 or off + 2 > len(data):
        raise BadExif("IFD at %d outside the segment" % off)
    n = struct.unpack(bo + "H", data[off:off + 2])[0]
    if n > MAX_ENTRIES:
        raise BadExif("IFD of %d entries" % n)
    tags = {}
    for i in range(n):
        e = off + 2 + 12 * i
        if e + 12 > len(data):
            raise BadExif("IFD entry outside the segment")
        tag, typ, count = struct.unpack(bo + "HHL", data[e:e + 8])
        if typ not in _TYPES:
            continue
        size, code = _TYPES[typ]
        total = size * count
        if total > MAX_VALUE:
            continue
        if total <= 4:
            raw = data[e + 8:e + 8 + total]
        else:
            p = struct.unpack(bo + "L", data[e + 8:e + 12])[0]
            if p + total > len(data):
                continue                            # points outside the segment: not read
            raw = data[p:p + total]
        if typ == 2:
            tags[tag] = raw.split(b"\0", 1)[0].decode("utf-8", "replace").strip()
        elif typ == 7:
            tags[tag] = raw
        else:
            items = struct.unpack(bo + code * count, raw)
            if typ in (5, 10):                      # rationals: (numerator, denominator) pairs
                items = tuple((items[i], items[i + 1]) for i in range(0, len(items), 2))
            tags[tag] = items
    return tags


def tiff(data):
    """The TIFF structure of an Exif segment: (IFD0, Exif IFD, GPS IFD), each {tag: value}."""
    if data[:4] == b"II*\0":
        bo = "<"
    elif data[:4] == b"MM\0*":
        bo = ">"
    else:
        raise BadExif("not a TIFF header")
    ifd0 = _ifd(data, struct.unpack(bo + "L", data[4:8])[0], bo)
    sub = {}
    for tag in (EXIF_IFD, GPS_IFD):
        p = ifd0.get(tag)
        sub[tag] = _ifd(data, p[0], bo) if isinstance(p, tuple) and p else {}
    return ifd0, sub[EXIF_IFD], sub[GPS_IFD]


def _ratio(v):
    if isinstance(v, tuple) and v and isinstance(v[0], tuple) and v[0][1]:
        return round(v[0][0] / v[0][1], 6)
    return None


def _text(v):
    return v if isinstance(v, str) and v else None


def taken(when, offset=None):
    """EXIF's "YYYY:MM:DD HH:MM:SS", in UTC with Z when its offset ("+02:00") is known, else as the camera's local
    time with no zone. None for the blank or impossible dates cameras write."""
    try:
        t = datetime.datetime.strptime(when, "%Y:%m:%d %H:%M:%S")
    except (TypeError, ValueError):
        return None
    if isinstance(offset, str) and len(offset) == 6 and offset[0] in "+-" and offset[3] == ":":
        try:
            sign = 1 if offset[0] == "+" else -1
            delta = datetime.timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
        except ValueError:
            delta = None
        if delta is not None:
            return (t - sign * delta).strftime("%Y-%m-%dT%H:%M:%SZ")
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def _degrees(v, ref, pos, neg):
    if not (isinstance(v, tuple) and len(v) == 3 and all(d for _, d in v)) or ref not in (pos, neg):
        return None
    deg = v[0][0] / v[0][1] + v[1][0] / v[1][1] / 60 + v[2][0] / v[2][1] / 3600
    return round(deg if ref == pos else -deg, 7)


def extract(f):
    vals = {}
    exif = None
    for code, body in segments(f):
        if code == 0xE1 and exif is None and body.startswith(b"Exif\0\0"):
            exif = body[6:]
        elif code in _SOF and "width" not in vals and len(body) >= 5:
            height, width = struct.unpack(">HH", body[1:5])
            if width and height:
                vals["width"], vals["height"] = width, height
    if exif is None:
        return vals
    ifd0, ex, gps = tiff(exif)
    vals.update(make=_text(ifd0.get(MAKE)), model=_text(ifd0.get(MODEL)), lens=_text(ex.get(LENS)),
                taken=taken(ex.get(TAKEN), ex.get(TAKEN_OFFSET)), exposure_time=_ratio(ex.get(EXPOSURE)),
                f_number=_ratio(ex.get(FNUMBER)), focal_length=_ratio(ex.get(FOCAL)))
    iso = ex.get(ISO)
    if isinstance(iso, tuple) and iso:
        vals["iso"] = iso[0]
    lat = _degrees(gps.get(LAT), gps.get(LAT_REF), "N", "S")
    lon = _degrees(gps.get(LON), gps.get(LON_REF), "E", "W")
    if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180:
        vals["gps"] = {"lat": lat, "lon": lon}
    return {k: v for k, v in vals.items() if v is not None}
