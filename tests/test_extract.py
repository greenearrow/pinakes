"""Extraction on the agent (ROADMAP 13): the EXIF reader, the values' checks, and extraction during a scan, on
generated JPEGs (tests/jpegs.py) in a temporary directory. Standard library only."""

import io
import os
import shutil
import sqlite3
import struct
import tempfile
import unittest
import unittest.mock

import jpegs
from pinakes import config, exif, extract, outbox, registry, xmp
from pinakes.scan import Scanner
from pinakes.state import State


def site_schema(folder, name, text):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name + ".toml"), "w") as f:
        f.write(text)


class TestExifReader(unittest.TestCase):
    def read(self, data):
        return exif.extract(io.BytesIO(data))

    def test_every_declared_field_both_byte_orders(self):
        for bo in "<>":
            with self.subTest(bo=bo):
                self.assertEqual(self.read(jpegs.camera(bo)), dict(jpegs.EXPECTED, gps=jpegs.GPS))

    def test_taken_without_an_offset_is_local_time(self):
        self.assertEqual(self.read(jpegs.camera(offset=None))["taken"], "2019-06-01T12:30:00")
        self.assertEqual(exif.taken("2019:06:01 00:10:00", "-05:00"), "2019-06-01T05:10:00Z")
        self.assertIsNone(exif.taken("    :  :     :  :  "))
        self.assertIsNone(exif.taken("2019:13:01 00:00:00"))

    def test_no_exif_gives_the_size_only(self):
        self.assertEqual(self.read(jpegs.jpeg(width=10, height=20)), {"width": 10, "height": 20})

    def test_not_a_jpeg(self):
        with self.assertRaises(exif.BadExif):
            self.read(b"GIF89a" + b"\0" * 100)

    def test_offsets_outside_the_segment_are_refused_not_followed(self):
        t = bytearray(jpegs.tiff([(0x010F, jpegs.ASCII, "Maker-1")]))
        t[4:8] = struct.pack("<L", 60000)                       # IFD0 far past the segment
        with self.assertRaises(exif.BadExif):
            self.read(jpegs.jpeg(bytes(t)))
        t = jpegs.tiff([(0x010F, jpegs.ASCII, "a long maker's name"), (0x0110, jpegs.ASCII, "Model-1")])
        cut = bytearray(t)
        value_at = struct.unpack("<L", cut[8 + 2 + 8:8 + 2 + 12])[0]
        cut[8 + 2 + 8:8 + 2 + 12] = struct.pack("<L", value_at + 5000)   # the make's text points outside
        got = self.read(jpegs.jpeg(bytes(cut)))
        self.assertNotIn("make", got)
        self.assertEqual(got["model"], "Model-1")
        many = bytearray(t)
        many[8:10] = struct.pack("<H", 5000)                   # more entries than an IFD holds
        with self.assertRaises(exif.BadExif):
            self.read(jpegs.jpeg(bytes(many)))

    def test_cut_short_and_no_marker(self):
        # a file that ends before its image data is refused as truncated (ROADMAP 44), wherever it ends: it is
        # told apart from a photo with no EXIF
        whole = jpegs.camera()
        sos = whole.index(b"\xff\xda")
        for cut in (2, 3, 4, 5, 40, sos):
            with self.subTest(cut=cut), self.assertRaises(exif.CutShort) as e:
                self.read(whole[:cut])
            self.assertEqual(extract.refusal(e.exception), "truncated")
        self.assertEqual(self.read(whole[:sos + 6]), jpegs.EXPECTED | {"gps": jpegs.GPS})   # in the image data
        with self.assertRaises(exif.BadExif) as e:
            self.read(b"\xff\xd8" + b"\x00" * 50)
        self.assertEqual(extract.refusal(e.exception), "malformed")

    def test_reads_no_further_than_the_headers(self):
        f = io.BytesIO(jpegs.camera() + b"\x00" * (4 * exif.MAX_HEADER))
        self.read(f.getvalue())
        f.seek(0)
        exif.extract(f)
        self.assertLess(f.tell(), 4096)


class TestXmpReader(unittest.TestCase):
    ALL = dict(jpegs.XMP_EXPECTED, **jpegs.XMP_SENSITIVE)

    def read(self, data):
        return xmp.extract(io.BytesIO(data))

    def packet(self, body):
        return jpegs.jpeg(xmp=body)

    def test_attributes_and_elements_read_alike(self):
        for name in ("XMP_ATTRIBUTES", "XMP_ELEMENTS"):
            with self.subTest(form=name):
                self.assertEqual(self.read(jpegs.tagged(getattr(jpegs, name))), self.ALL)

    def test_no_xmp_and_exif_alone(self):
        self.assertEqual(self.read(jpegs.camera()), {})
        self.assertEqual(exif.extract(io.BytesIO(jpegs.tagged()))["make"], "Maker-1")   # each reads its own segment

    def test_what_xml_can_ask_for_is_refused(self):
        laughs = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">'
                  '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><x:xmpmeta xmlns:x="adobe:ns:meta/">&c;</x:xmpmeta>')
        external = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]>'
                    '<x:xmpmeta xmlns:x="adobe:ns:meta/">&e;</x:xmpmeta>')
        doctype = '<!DOCTYPE x SYSTEM "http://example.net/x.dtd"><x:xmpmeta xmlns:x="adobe:ns:meta/"/>'
        for body, why in ((laughs, "a DOCTYPE"), (external, "a DOCTYPE"), (doctype, "a DOCTYPE"),
                          ('<x:xmpmeta xmlns:x="adobe:ns:meta/">&nosuch;</x:xmpmeta>', "not well-formed"),
                          ("<a><b></a>", "not well-formed"), ("", "not well-formed"),
                          ("<a>" * (xmp.MAX_DEPTH + 1) + "</a>" * (xmp.MAX_DEPTH + 1), "nested more than"),
                          ('<x:xmpmeta xmlns:x="adobe:ns:meta/"/>', "no rdf:RDF")):
            with self.subTest(why=why, body=body[:40]), self.assertRaisesRegex(xmp.BadXmp, why):
                self.read(self.packet(body))

    def test_odd_values_left_out(self):
        body = jpegs.XMP_ATTRIBUTES.replace('xmp:Rating="4"', 'xmp:Rating="9"').replace(
            "2019-06-01T12:30:00+02:00", "2019-13-01T00:00:00Z").replace(
            '<rdf:li xml:lang="de">Titel-1</rdf:li><rdf:li xml:lang="x-default">Title-1</rdf:li>',
            '<rdf:li xml:lang="de">Titel-1</rdf:li><rdf:li xml:lang="fr">Titre-1</rdf:li>')
        got = self.read(self.packet(body))
        self.assertNotIn("rating", got)
        self.assertNotIn("created", got)
        self.assertEqual(got["title"], "Titel-1")               # no x-default: the first

    def test_dates(self):
        for given, want in (("2019", "2019"), ("2019-06", "2019-06"), ("2019-06-01", "2019-06-01"),
                            ("2019-06-01T12:30:00+02:00", "2019-06-01T10:30:00Z"),
                            ("2019-06-01T12:30+02:00", "2019-06-01T10:30Z"),
                            ("2019-06-01T12:30:00.5-05:00", "2019-06-01T17:30:00.5Z"),
                            ("2019-06-01T12:30:00", "2019-06-01T12:30:00"),
                            ("2019-13", None), ("2019-02-30T00:00:00Z", None), ("2019-06-01T25:00", None),
                            ("June 2019", None), (None, None)):
            self.assertEqual(xmp.date(given), want, given)
            if want:
                self.assertEqual(extract.check_vals(registry.load()["xmp"], {"created": want})[1], [], want)


class TestCheckVals(unittest.TestCase):
    def setUp(self):
        self.schema = registry.load()["exif"]

    def test_good_values_kept_sensitive_too(self):
        keep, problems = extract.check_vals(self.schema, dict(jpegs.EXPECTED, gps=jpegs.GPS, lens=None))
        self.assertEqual(problems, [])
        self.assertEqual(keep["gps"], jpegs.GPS)                # sensitive: sent, kept apart for owners only
        self.assertNotIn("lens", keep)
        self.assertEqual(keep["make"], "Maker-1")

    def test_wrong_values(self):
        bad = {"nosuch": 1, "make": 3, "iso": True, "taken": "June 2019", "width": float("nan"),
               "model": "x" * (extract.MAX_TEXT + 1)}
        keep, problems = extract.check_vals(self.schema, bad)
        self.assertEqual(keep, {})
        self.assertEqual(len(problems), 6)
        self.assertEqual(extract.check_vals(self.schema, ["not", "a", "table"])[1], ["values are not a table"])

    def test_dates_people_and_lists(self):
        dc = registry.load()["dc"]
        for d in ("2019", "2019-06", "2019-06-01", "2019-06-01T10:30", "2019-06-01T10:30:00Z", "2019-06-01T10:30:00"):
            self.assertEqual(extract.check_vals(dc, {"date": d})[1], [], d)
        self.assertTrue(extract.check_vals(dc, {"date": "2019-06-01 10:30"})[1])
        self.assertTrue(extract.check_vals(dc, {"creator": ["a"] * (extract.MAX_LIST + 1)})[1])
        self.assertTrue(extract.check_vals(dc, {"creator": ["a", 2]})[1])
        self.assertEqual(extract.check_vals(dc, {"creator": ["user-1"]})[0], {"creator": ["user-1"]})

    def test_size_cap(self):
        dc = registry.load()["dc"]
        many = {"subject": ["x" * 900] * 30}
        self.assertIn("values over %d bytes" % extract.MAX_VALS, extract.check_vals(dc, many)[1])


class TestRequirements(unittest.TestCase):
    def test_missing_and_versions(self):
        self.assertEqual(extract.missing(["pinakes-no-such-package"]), "pinakes-no-such-package")
        self.assertIsNone(extract.missing([]))
        with unittest.mock.patch("importlib.metadata.version", return_value="10.2.0"):
            self.assertIsNone(extract.missing(["Pillow>=10"]))
            self.assertEqual(extract.missing(["Pillow>=11"]), "Pillow>=11 (10.2.0 installed)")
            self.assertEqual(extract.missing(["Pillow==10.2.0"]), "Pillow==10.2.0 (10.2.0 installed)")

    def test_missing_dependency_turns_the_extractor_off_not_the_scan(self):
        tmp = tempfile.mkdtemp(prefix="pinakes-test-")
        self.addCleanup(shutil.rmtree, tmp)
        site_schema(os.path.join(tmp, "schemas"), "photo", '''
name = "photo"
version = 1
mime = ["image/jpeg"]
[extractor]
module = "pinakes.exif"
requires = ["pinakes-no-such-package"]
[fields.make]
type = "text"
''')
        site_schema(os.path.join(tmp, "schemas"), "broken", '''
name = "broken"
version = 1
mime = ["image/*"]
[extractor]
module = "pinakes.no_such_module"
[fields.x]
type = "text"
''')
        ex = extract.Extractors(registry.load(os.path.join(tmp, "schemas")))
        self.assertEqual(ex.off["photo"], "needs pinakes-no-such-package")
        self.assertIn("ModuleNotFoundError", ex.off["broken"])
        self.assertEqual(set(ex.on), {"exif", "xmp"})
        self.assertEqual(ex.wanted(None, "a/IMG_0001.JPG"), {"exif": 2, "xmp": 2})
        self.assertEqual(ex.wanted(None, "a/notes.txt"), {})
        self.assertEqual(ex.wanted([], "a/IMG_0001.jpg"), {})


class ScanCase(unittest.TestCase):
    """A primary root and a protected one, on one agent."""

    store_extra = ""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pinakes-test-")
        self.store = os.path.join(self.tmp, "store")
        self.writing = os.path.join(self.tmp, "writing")
        os.makedirs(self.store)
        os.makedirs(self.writing)
        self.cfg = config.loads("""
[agent]
host = "test-1"
state = "%(t)s/state.sqlite"
outbox = "%(t)s/outbox"
[[root]]
label = "store"
path = "%(store)s"
%(x)s
[[root]]
label = "writing"
path = "%(writing)s"
protected = true
""" % {"t": self.tmp, "store": self.store, "writing": self.writing, "x": self.store_extra})
        self.state = State(self.cfg.state)

    def tearDown(self):
        self.state.close()
        shutil.rmtree(self.tmp)

    def put(self, top, rel, data):
        p = os.path.join(top, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def scan(self, label="store", extractors=None, **kw):
        sc = Scanner(self.cfg, self.state, extractors=extractors)
        sc.scan(self.cfg.root(label), **kw)
        self.counter = sc.counter
        return self.collect()

    def collect(self):
        recs = []
        for seq, path in outbox.pending(self.cfg.outbox):
            header, r = outbox.read(path)
            self.assertEqual(header["format"], 2)
            recs.extend(r)
            outbox.ack(self.cfg.outbox, seq)
        return {r["path"]: r for r in recs if r["t"] in ("file", "symlink")}


class TestScanExtracts(ScanCase):
    def test_declared_fields_sent_gps_not_others_untouched(self):
        self.put(self.store, "photos/IMG_0001.JPG", jpegs.camera())
        self.put(self.store, "notes.txt", b"text")
        recs = self.scan()
        self.assertEqual(recs["photos/IMG_0001.JPG"]["meta"], {"exif": {"v": 2, "vals": jpegs.SENT},
                                                               "xmp": {"v": 2, "vals": {}}})     # read, none there
        self.assertNotIn("meta", recs["notes.txt"])
        self.assertEqual(self.scan(), {})                       # unchanged: nothing sent, nothing read again
        self.assertNotIn("extracted", self.counter)

    def test_a_state_from_before_file_types_still_extracts(self):
        # rows saved before the agent kept a file's type (27650a5) and before it extracted: t and meta_v NULL. A row
        # with a SHA-256 was a regular file then (symlinks had none); it must be read like any other photo, by a
        # plain scan or a --full one
        self.put(self.store, "photos/IMG_0001.JPG", jpegs.camera())
        os.symlink("photos/IMG_0001.JPG", os.path.join(self.store, "latest.jpg"))
        for full in (False, True):
            with self.subTest(full=full):
                self.scan()
                self.state.close()
                db = sqlite3.connect(self.cfg.state)
                db.execute("UPDATE files SET t = NULL, target = NULL, link_root = NULL, link_path = NULL, "
                           "dangling = NULL, meta_v = NULL")
                db.execute("UPDATE files SET sha256 = NULL WHERE relpath = 'latest.jpg'")     # as it was then
                db.execute("DELETE FROM meta WHERE key = 'types_filled'")                     # an older release's
                db.commit()
                db.close()
                self.state = State(self.cfg.state)
                recs = self.scan(full=full)
                self.assertEqual(recs["photos/IMG_0001.JPG"]["meta"]["exif"]["vals"], jpegs.SENT)
                self.assertNotIn("hashed", self.counter)                 # only the metadata is new: no rehash
                self.assertEqual(recs["latest.jpg"]["t"], "symlink")     # a link of then is sent as one, not read
                self.assertNotIn("meta", recs["latest.jpg"])
                self.assertEqual(self.state.get("store", "photos/IMG_0001.JPG")["t"], "file")
                self.assertEqual(self.scan(), {})                        # and then it is like any other

    def test_a_broken_photo_is_a_refusal_and_not_tried_again(self):
        self.put(self.store, "bad.jpg", b"not a jpeg at all")
        self.put(self.store, "cut.jpg", jpegs.camera()[:100])
        self.put(self.store, "good.jpg", jpegs.camera())
        recs = self.scan()
        self.assertEqual(recs["bad.jpg"]["meta"], {"exif": {"v": 2, "refused": "wrong_type"},
                                                   "xmp": {"v": 2, "refused": "wrong_type"}})   # a code, no text
        self.assertEqual(recs["cut.jpg"]["meta"]["exif"], {"v": 2, "refused": "truncated"})
        self.assertEqual(recs["good.jpg"]["meta"]["exif"]["vals"], jpegs.SENT)
        self.assertEqual(self.scan(), {})

    def test_to_a_server_before_protocol_4_the_text_as_before_and_outcomes_once_it_is(self):
        self.put(self.store, "bad.jpg", b"not a jpeg at all")
        self.put(self.store, "good.jpg", jpegs.camera())
        self.cfg.transport["kind"] = "ssh"
        self.state.set_meta("server_protocol", "3")
        sc = Scanner(self.cfg, self.state)
        summary = sc.scan(self.cfg.root("store"))
        self.assertIn("is at protocol 3", summary["outcomes_wait"])
        recs = self.collect()
        self.assertIn("NotJpeg: not a JPEG", recs["bad.jpg"]["meta"]["exif"]["error"])
        self.assertEqual(self.scan(), {})
        self.state.set_meta("server_protocol", "4")                # the server updated: every photo read once more
        recs = self.scan()
        self.assertEqual(recs["bad.jpg"]["meta"]["exif"], {"v": 2, "refused": "wrong_type"})
        self.assertEqual(recs["good.jpg"]["meta"]["exif"]["vals"], jpegs.SENT)
        self.assertNotIn("hashed", self.counter)
        self.assertEqual(self.scan(), {})

    def test_an_extractor_off_here_is_said_skipped(self):
        tmp = os.path.join(self.tmp, "schemas")
        site_schema(tmp, "photo", '''
name = "photo"
version = 1
mime = ["image/jpeg"]
[extractor]
module = "pinakes.exif"
requires = ["pinakes-no-such-package"]
[fields.make]
type = "text"
''')
        ex = extract.Extractors(registry.load(tmp))
        self.put(self.store, "a.jpg", jpegs.camera())
        recs = self.scan(extractors=ex)
        self.assertEqual(recs["a.jpg"]["meta"]["photo"], {"v": 1, "skipped": "dependency"})
        self.assertEqual(recs["a.jpg"]["meta"]["exif"]["vals"], jpegs.SENT)
        self.assertEqual(self.scan(extractors=ex), {})

    def test_a_new_schema_version_reads_unchanged_photos_again_without_rehashing(self):
        self.put(self.store, "a.jpg", jpegs.camera())
        self.scan()
        reg = registry.load()
        reg["exif"].version = 3
        recs = self.scan(extractors=extract.Extractors(reg))
        self.assertEqual(recs["a.jpg"]["meta"]["exif"], {"v": 3, "vals": jpegs.SENT})
        self.assertNotIn("hashed", self.counter)
        self.assertEqual(self.scan(extractors=extract.Extractors(reg)), {})

    def test_one_content_read_once_here_unless_full(self):
        self.put(self.store, "a/one.jpg", jpegs.camera())
        self.put(self.store, "b/two.jpg", jpegs.camera())
        os.makedirs(os.path.join(self.store, "c"))
        os.link(os.path.join(self.store, "a/one.jpg"), os.path.join(self.store, "c/three.jpg"))
        recs = self.scan()
        with_meta = [p for p, r in recs.items() if "meta" in r]
        self.assertEqual(len(with_meta), 1)                     # the same bytes: one reading, sent once
        self.assertEqual(self.counter["extracted"], 1)
        again = self.scan(full=True)                            # the server lost it: every copy read and sent
        self.assertEqual({p for p, r in again.items() if "meta" in r}, set(recs))

    def test_changed_photo_read_again(self):
        p = self.put(self.store, "a.jpg", jpegs.camera())
        self.scan()
        self.put(self.store, "a.jpg", jpegs.camera(make="Maker-2"))
        os.utime(p, ns=(1, 1))
        self.assertEqual(self.scan()["a.jpg"]["meta"]["exif"]["vals"]["make"], "Maker-2")

    def test_nothing_from_a_protected_root_or_a_link_into_one(self):
        self.put(self.writing, "scan.jpg", jpegs.camera())
        recs = self.scan("writing")
        self.assertNotIn("meta", recs["scan.jpg"])
        os.link(os.path.join(self.writing, "scan.jpg"), os.path.join(self.store, "copy.jpg"))
        self.put(self.store, "own.jpg", jpegs.camera(make="Maker-2"))
        recs = self.scan()
        self.assertTrue(recs["copy.jpg"]["protected_link"])
        self.assertNotIn("meta", recs["copy.jpg"])
        self.assertIn("meta", recs["own.jpg"])
        read = []
        real = extract.Extractors.run
        with unittest.mock.patch.object(extract.Extractors, "run", autospec=True,
                                        side_effect=lambda ex, path, w, **kw: read.append(path) or real(ex, path, w, **kw)):
            self.scan("writing", full=True)
            self.scan(full=True)
        self.assertEqual(read, [os.path.join(self.store, "own.jpg")])   # the others not even opened

    def test_exif_and_xmp_from_one_photo_sensitive_fields_too(self):
        self.put(self.store, "a.jpg", jpegs.tagged())
        meta = self.scan()["a.jpg"]["meta"]
        self.assertEqual(meta["xmp"], {"v": 2, "vals": dict(jpegs.XMP_EXPECTED, **jpegs.XMP_SENSITIVE)})
        self.assertEqual(meta["exif"]["vals"]["make"], "Maker-1")

    def test_xmp_never_read_on_a_protected_root_or_link(self):
        self.put(self.writing, "a.jpg", jpegs.tagged())
        self.assertNotIn("meta", self.scan("writing")["a.jpg"])
        os.link(os.path.join(self.writing, "a.jpg"), os.path.join(self.store, "a.jpg"))
        self.assertNotIn("meta", self.scan()["a.jpg"])

    def test_a_new_extractor_reads_known_photos_once(self):
        self.put(self.store, "a.jpg", jpegs.tagged())
        reg = registry.load()
        del reg.schemas["xmp"]
        self.assertEqual(set(self.scan(extractors=extract.Extractors(reg))["a.jpg"]["meta"]), {"exif"})
        again = self.scan()                                     # xmp enrolled since: read, without rehashing
        self.assertEqual(set(again["a.jpg"]["meta"]), {"exif", "xmp"})
        self.assertNotIn("hashed", self.counter)
        self.assertEqual(self.scan(), {})

    def test_unknown_metadata_names_refused(self):
        self.cfg.root("store").metadata = ["dc"]                # a schema, but no extractor
        with self.assertRaises(config.ConfigError):
            self.scan()

    def test_protected_root_refuses_metadata_in_config(self):
        with self.assertRaises(config.ConfigError):
            config.loads('[agent]\nhost="h"\nstate="s"\noutbox="o"\n[[root]]\nlabel="w"\npath="/mnt/store"\n'
                         'protected=true\nmetadata=["exif"]\n')
        cfg = config.loads('[agent]\nhost="h"\nstate="s"\noutbox="o"\n[[root]]\nlabel="w"\npath="/mnt/store"\n'
                           'protected=true\nmetadata=false\n')
        self.assertEqual(cfg.roots[0].metadata, [])


class TestRootOff(ScanCase):
    store_extra = "metadata = false"

    def test_off(self):
        self.put(self.store, "a.jpg", jpegs.camera())
        self.assertNotIn("meta", self.scan()["a.jpg"])
        self.cfg.root("store").metadata = None                  # turned on: the next scan reads it
        self.assertIn("meta", self.scan()["a.jpg"])


if __name__ == "__main__":
    unittest.main()
