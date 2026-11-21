"""Generated JPEGs with an EXIF header, written from the TIFF 6.0 and EXIF 2.32 layouts: no real photo, no imaging
library. The image data is a stub: nothing here decodes pixels, only the headers before them."""

import struct

ASCII, SHORT, LONG, RATIONAL, UNDEFINED = 2, 3, 4, 5, 7


def _enc(typ, value, bo):
    if typ == ASCII:
        raw = value.encode() + b"\0"
        return len(raw), raw
    if typ == UNDEFINED:
        return len(value), bytes(value)
    if typ == RATIONAL:
        flat = [x for pair in value for x in pair]
        return len(value), struct.pack(bo + "L" * len(flat), *flat)
    code = {SHORT: "H", LONG: "L"}[typ]
    return len(value), struct.pack(bo + code * len(value), *value)


def ifd(entries, start, bo):
    """An IFD at offset start: [(tag, type, value)], its values longer than 4 bytes after it, word-aligned."""
    entries = sorted(entries)
    data_at = start + 2 + 12 * len(entries) + 4
    head, data = b"", b""
    for tag, typ, value in entries:
        count, raw = _enc(typ, value, bo)
        if len(raw) <= 4:
            field = raw.ljust(4, b"\0")
        else:
            field = struct.pack(bo + "L", data_at + len(data))
            data += raw + (b"\0" if len(raw) % 2 else b"")
        head += struct.pack(bo + "HHL", tag, typ, count) + field
    return struct.pack(bo + "H", len(entries)) + head + struct.pack(bo + "L", 0) + data


def tiff(ifd0, exif=(), gps=(), bo="<"):
    """The TIFF structure of an Exif segment: IFD0, then the Exif IFD and the GPS IFD it points to."""
    def first(e_at, g_at):
        return list(ifd0) + [(0x8769, LONG, (e_at,))] + ([(0x8825, LONG, (g_at,))] if gps else [])
    e_at = 8 + len(ifd(first(0, 0), 8, bo))
    g_at = e_at + len(ifd(exif, e_at, bo))
    out = (b"II*\0" if bo == "<" else b"MM\0*") + struct.pack(bo + "L", 8)
    out += ifd(first(e_at, g_at), 8, bo) + ifd(exif, e_at, bo)
    return out + (ifd(gps, g_at, bo) if gps else b"")


def segment(marker, body):
    return bytes([0xFF, marker]) + struct.pack(">H", len(body) + 2) + body


def jpeg(exif_tiff=None, width=64, height=48, extra=b"", xmp=None):
    """SOI, an APP1 Exif segment (if any), an APP1 XMP segment (if any), a baseline frame header, then a stub scan
    and EOI."""
    out = b"\xff\xd8" + segment(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0")
    if exif_tiff is not None:
        out += segment(0xE1, b"Exif\0\0" + exif_tiff)
    if xmp is not None:
        out += segment(0xE1, b"http://ns.adobe.com/xap/1.0/\0" + (xmp.encode() if isinstance(xmp, str) else xmp))
    out += segment(0xC0, bytes([8]) + struct.pack(">HH", height, width) + bytes([1, 1, 0x11, 0]))
    return out + extra + segment(0xDA, bytes([1, 1, 0, 0, 63, 0])) + b"\x00" * 16 + b"\xff\xd9"


def camera(bo="<", offset="+02:00", gps=True, make="Maker-1", when="2019:06:01 12:30:00"):
    """A photo's EXIF: the fields schemas/exif.toml declares, GPS included."""
    exif = [(0x829A, RATIONAL, [(1, 250)]), (0x829D, RATIONAL, [(28, 10)]), (0x8827, SHORT, (400,)),
            (0x9003, ASCII, when), (0x920A, RATIONAL, [(35, 1)]), (0xA434, ASCII, "Lens-1 35mm")]
    if offset:
        exif.append((0x9011, ASCII, offset))
    g = [(1, ASCII, "N"), (2, RATIONAL, [(47, 1), (30, 1), (0, 1)]),
         (3, ASCII, "W"), (4, RATIONAL, [(8, 1), (15, 1), (36, 1)])] if gps else []
    return jpeg(tiff([(0x010F, ASCII, make), (0x0110, ASCII, "Model-1")], exif, g, bo), width=640, height=480)


EXPECTED = {"make": "Maker-1", "model": "Model-1", "lens": "Lens-1 35mm", "taken": "2019-06-01T10:30:00Z",
            "exposure_time": 0.004, "f_number": 2.8, "iso": 400, "focal_length": 35.0, "width": 640, "height": 480}
GPS = {"lat": 47.5, "lon": -8.26}
SENT = dict(EXPECTED, gps=GPS)          # what the agent sends: GPS too, which the catalog keeps for owners only


# XMP packets as photo software writes them (XMP 2012 spec, Part 1, 7.9: RDF/XML), placeholders only.
_NS = ('xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/" '
       'xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" '
       'xmlns:stRef="http://ns.adobe.com/xap/1.0/sType/ResourceRef#" '
       'xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" '
       'xmlns:Iptc4xmpCore="http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/" '
       'xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/"')

# simple properties as attributes, DerivedFrom as attributes on its element
XMP_ATTRIBUTES = """<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF %s>
 <rdf:Description rdf:about="" xmp:Rating="4" xmp:CreateDate="2019-06-01T12:30:00+02:00"
   xmpMM:DocumentID="xmp.did:doc-1" xmpMM:InstanceID="xmp.iid:inst-2"
   photoshop:City="City-1" photoshop:Country="Country-1" Iptc4xmpCore:Location="Place-1">
  <xmpMM:DerivedFrom stRef:documentID="xmp.did:doc-0" stRef:instanceID="xmp.iid:inst-1"/>
  <dc:title><rdf:Alt><rdf:li xml:lang="de">Titel-1</rdf:li><rdf:li xml:lang="x-default">Title-1</rdf:li></rdf:Alt>
  </dc:title>
  <dc:description><rdf:Alt><rdf:li xml:lang="x-default">Description-1</rdf:li></rdf:Alt></dc:description>
  <dc:creator><rdf:Seq><rdf:li>User One</rdf:li></rdf:Seq></dc:creator>
  <dc:subject><rdf:Bag><rdf:li>walk</rdf:li><rdf:li>lake</rdf:li></rdf:Bag></dc:subject>
  <dc:rights><rdf:Alt><rdf:li xml:lang="x-default">Rights-1</rdf:li></rdf:Alt></dc:rights>
  <Iptc4xmpExt:PersonInImage><rdf:Bag><rdf:li>User Two</rdf:li></rdf:Bag></Iptc4xmpExt:PersonInImage>
 </rdf:Description>
</rdf:RDF></x:xmpmeta>
<?xpacket end="w"?>""" % _NS

# the same as elements, over two rdf:Description, DerivedFrom as rdf:parseType="Resource"
XMP_ELEMENTS = """<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF %s>
 <rdf:Description rdf:about="">
  <xmp:Rating>4</xmp:Rating><xmp:CreateDate>2019-06-01T12:30:00+02:00</xmp:CreateDate>
  <xmpMM:DocumentID>xmp.did:doc-1</xmpMM:DocumentID><xmpMM:InstanceID>xmp.iid:inst-2</xmpMM:InstanceID>
  <xmpMM:DerivedFrom rdf:parseType="Resource"><stRef:documentID>xmp.did:doc-0</stRef:documentID>
   <stRef:instanceID>xmp.iid:inst-1</stRef:instanceID></xmpMM:DerivedFrom>
  <photoshop:City>City-1</photoshop:City><photoshop:Country>Country-1</photoshop:Country>
  <Iptc4xmpCore:Location>Place-1</Iptc4xmpCore:Location>
 </rdf:Description>
 <rdf:Description rdf:about="">
  <dc:title><rdf:Alt><rdf:li xml:lang="x-default">Title-1</rdf:li></rdf:Alt></dc:title>
  <dc:description><rdf:Alt><rdf:li xml:lang="x-default">Description-1</rdf:li></rdf:Alt></dc:description>
  <dc:creator><rdf:Seq><rdf:li>User One</rdf:li></rdf:Seq></dc:creator>
  <dc:subject><rdf:Bag><rdf:li>walk</rdf:li><rdf:li>lake</rdf:li></rdf:Bag></dc:subject>
  <dc:rights><rdf:Alt><rdf:li xml:lang="x-default">Rights-1</rdf:li></rdf:Alt></dc:rights>
  <Iptc4xmpExt:PersonInImage><rdf:Bag><rdf:li>User Two</rdf:li></rdf:Bag></Iptc4xmpExt:PersonInImage>
 </rdf:Description>
</rdf:RDF></x:xmpmeta>""" % _NS

XMP_SENSITIVE = {"people": ["User Two"], "city": "City-1", "country": "Country-1", "location": "Place-1"}
XMP_EXPECTED = {"title": "Title-1", "description": "Description-1", "creator": ["User One"],
                "keywords": ["walk", "lake"], "rights": "Rights-1", "rating": 4, "created": "2019-06-01T10:30:00Z",
                "document_id": "xmp.did:doc-1", "instance_id": "xmp.iid:inst-2",
                "derived_document_id": "xmp.did:doc-0", "derived_instance_id": "xmp.iid:inst-1"}


def tagged(xmp=XMP_ATTRIBUTES):
    """A photo with both EXIF and XMP."""
    return jpeg(tiff([(0x010F, ASCII, "Maker-1")]), xmp=xmp)


GPS_IFD = [(1, ASCII, "N"), (2, RATIONAL, [(47, 1), (30, 1), (0, 1)]),
           (3, ASCII, "W"), (4, RATIONAL, [(8, 1), (15, 1), (36, 1)])]


def bare(exif_tiff=None):
    """A JPEG with no frame header, and no EXIF unless given: nothing for the EXIF reader but what exif_tiff holds."""
    out = b"\xff\xd8" + segment(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0")
    if exif_tiff is not None:
        out += segment(0xE1, b"Exif\0\0" + exif_tiff)
    return out + segment(0xDA, bytes([1, 1, 0, 0, 63, 0])) + b"\x00" * 16 + b"\xff\xd9"


def gps_only():
    """A JPEG whose only EXIF is its GPS position: every value found a sensitive one."""
    return bare(tiff([], [], GPS_IFD))


def version(doc, inst, parent_doc=None, parent_inst=None, width=64):
    """A saved version of a document: its XMP ids (DocumentID, InstanceID) and, if given, the DerivedFrom ids of
    the version it was made from. Each InstanceID gives other bytes; width gives other bytes for the same ids."""
    derived = ('<xmpMM:DerivedFrom stRef:documentID="%s" stRef:instanceID="%s"/>' % (parent_doc, parent_inst)
               if parent_doc else "")
    packet = ('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF %s><rdf:Description rdf:about="" '
              'xmpMM:DocumentID="%s" xmpMM:InstanceID="%s">%s</rdf:Description></rdf:RDF></x:xmpmeta>'
              % (_NS, doc, inst, derived))
    return jpeg(width=width, xmp=packet)
