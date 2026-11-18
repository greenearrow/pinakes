"""XMP embedded in a JPEG (schemas/xmp.toml): the standard library only, no dependency to install.

The packet is the APP1 segment that starts with the XMP namespace (exif.segments reads the markers, at most
exif.MAX_HEADER bytes). It is XML from someone else's file, so it is parsed with expat directly and nothing XML can
ask for is granted: a DOCTYPE, an entity declaration or a reference to an external entity refuses the packet, before
anything is built; elements nest at most MAX_DEPTH deep. Extended XMP (a packet split over several segments) is not
read yet.

RDF says one thing in several ways, and all of them are read: a property as an attribute of rdf:Description or as
an element; an array as rdf:Bag, rdf:Seq or rdf:Alt (a language alternative gives its x-default, else its first);
a structure as rdf:parseType="Resource", a nested rdf:Description, or attributes on the property's element.
"""

import datetime
import re
import xml.parsers.expat

from . import exif
from .extract import Refusal

HEADER = b"http://ns.adobe.com/xap/1.0/\0"
MAX_DEPTH = 32

RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
XML = "http://www.w3.org/XML/1998/namespace"
DC = "http://purl.org/dc/elements/1.1/"
XMP = "http://ns.adobe.com/xap/1.0/"
XMPMM = "http://ns.adobe.com/xap/1.0/mm/"
STREF = "http://ns.adobe.com/xap/1.0/sType/ResourceRef#"
PHOTOSHOP = "http://ns.adobe.com/photoshop/1.0/"
IPTC_CORE = "http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/"
IPTC_EXT = "http://iptc.org/std/Iptc4xmpExt/2008-02-29/"


class BadXmp(Refusal):
    pass


class _Node:
    __slots__ = ("tag", "attrs", "children", "text")

    def __init__(self, tag, attrs):
        self.tag, self.attrs, self.children, self.text = tag, attrs, [], ""


def _refuse(what):
    def handler(*args):
        raise BadXmp("XMP with %s: refused" % what)
    return handler


def _name(n):
    """expat's "uri local" as (uri, local); a name in no namespace as ("", local)."""
    uri, _, local = n.rpartition(" ")
    return uri, local


def parse(data):
    """The packet's element tree: the root _Node."""
    p = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    p.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    p.StartDoctypeDeclHandler = _refuse("a DOCTYPE")
    p.EntityDeclHandler = _refuse("an entity declaration")
    p.UnparsedEntityDeclHandler = _refuse("an entity declaration")
    p.ExternalEntityRefHandler = _refuse("an external entity")
    p.SkippedEntityHandler = _refuse("an undeclared entity")
    stack, top = [], []

    def start(tag, attrs):
        if len(stack) >= MAX_DEPTH:
            raise BadXmp("XMP nested more than %d deep" % MAX_DEPTH)
        node = _Node(_name(tag), {_name(k): v for k, v in attrs.items()})
        (stack[-1].children if stack else top).append(node)
        stack.append(node)

    def end(tag):
        stack.pop()

    def text(t):
        if stack:
            stack[-1].text += t

    p.StartElementHandler, p.EndElementHandler, p.CharacterDataHandler = start, end, text
    try:
        p.Parse(data, True)
    except xml.parsers.expat.ExpatError as e:
        raise BadXmp("not well-formed XML: %s" % e)
    if not top:
        raise BadXmp("no XML element")
    return top[0]


def _find(node, tag):
    if node.tag == tag:
        return node
    for c in node.children:
        found = _find(c, tag)
        if found is not None:
            return found
    return None


def _struct(node):
    """A structure's fields: {(uri, local): value}."""
    fields = {k: v for k, v in node.attrs.items() if k[0] not in (RDF, XML, "")}
    for c in node.children:
        if c.tag == (RDF, "Description"):
            fields.update(_struct(c))
        else:
            fields[c.tag] = _value(c)
    return fields


def _value(el):
    """A property element's value: text, a list (an array), or a dict (a structure)."""
    if el.attrs.get((RDF, "parseType")) == "Resource":
        return _struct(el)
    for c in el.children:
        if c.tag in ((RDF, "Bag"), (RDF, "Seq")):
            return [_value(li) for li in c.children if li.tag == (RDF, "li")]
        if c.tag == (RDF, "Alt"):
            items = [li for li in c.children if li.tag == (RDF, "li")]
            pick = next((li for li in items if li.attrs.get((XML, "lang")) == "x-default"), items[0] if items else None)
            return _value(pick) if pick is not None else None
        if c.tag == (RDF, "Description"):
            return _struct(c)
    if (RDF, "resource") in el.attrs:
        return el.attrs[(RDF, "resource")]
    if any(k[0] not in (RDF, XML, "") for k in el.attrs):
        return _struct(el)
    return el.text.strip()


def properties(root):
    """Every top-level property of every rdf:Description: {(uri, local): value}."""
    rdf = _find(root, (RDF, "RDF"))
    if rdf is None:
        raise BadXmp("no rdf:RDF")
    props = {}
    for d in rdf.children:
        if d.tag == (RDF, "Description"):
            props.update(_struct(d))
    return props


_DATE = re.compile(r"(\d{4}(?:-\d{2}(?:-\d{2})?)?)(?:T(\d{2}:\d{2}(?::\d{2})?)(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})?)?\Z")
_FORMS = {1: "%Y", 2: "%Y-%m", 3: "%Y-%m-%d"}


def date(text):
    """An XMP date (ISO 8601, as precise as known) in the registry's form: UTC with Z when a zone is given, as
    written (the camera's or the person's local time) without one; None if it isn't a real date."""
    m = _DATE.match(text.strip()) if isinstance(text, str) else None
    if not m:
        return None
    day, clock, frac, zone = m.group(1), m.group(2), m.group(3) or "", m.group(4)
    try:
        datetime.datetime.strptime(day, _FORMS[day.count("-") + 1])
        if clock is None:
            return day
        form = "%Y-%m-%dT%H:%M:%S" if clock.count(":") == 2 else "%Y-%m-%dT%H:%M"
        t = datetime.datetime.strptime(day + "T" + clock, form)
    except ValueError:
        return None
    if zone is None:
        return day + "T" + clock + frac
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        t -= sign * datetime.timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
    return t.strftime(form) + frac + "Z"


def _text(v):
    return v if isinstance(v, str) and v else None


def _texts(v):
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return None
    out = [x for x in v if isinstance(x, str) and x]
    return out or None


def _rating(v):
    try:
        r = float(v)
    except (TypeError, ValueError):
        return None
    return (int(r) if r == int(r) else r) if -1 <= r <= 5 else None


def values(props):
    """schemas/xmp.toml's fields from the properties."""
    derived = props.get((XMPMM, "DerivedFrom"))
    derived = derived if isinstance(derived, dict) else {}
    vals = {
        "title": _text(props.get((DC, "title"))),
        "description": _text(props.get((DC, "description"))),
        "creator": _texts(props.get((DC, "creator"))),
        "keywords": _texts(props.get((DC, "subject"))),
        "rights": _text(props.get((DC, "rights"))),
        "rating": _rating(props.get((XMP, "Rating"))),
        "created": date(props.get((XMP, "CreateDate"))) or date(props.get((PHOTOSHOP, "DateCreated"))),
        "document_id": _text(props.get((XMPMM, "DocumentID"))),
        "instance_id": _text(props.get((XMPMM, "InstanceID"))),
        "derived_document_id": _text(derived.get((STREF, "documentID"))),
        "derived_instance_id": _text(derived.get((STREF, "instanceID"))),
        "people": _texts(props.get((IPTC_EXT, "PersonInImage"))),
        "location": _text(props.get((IPTC_CORE, "Location"))),
        "city": _text(props.get((PHOTOSHOP, "City"))),
        "state": _text(props.get((PHOTOSHOP, "State"))),
        "country": _text(props.get((PHOTOSHOP, "Country"))),
    }
    return {k: v for k, v in vals.items() if v is not None}


def extract(f):
    for code, body in exif.segments(f):
        if code == 0xE1 and body.startswith(HEADER):
            return values(properties(parse(body[len(HEADER):])))
    return {}
