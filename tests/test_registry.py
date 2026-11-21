"""The schema registry (ROADMAP 12): the project's schemas load, a site's join them, a bad one is refused with a
message naming its file and what is wrong. Standard library only; schemas written to a temporary folder."""

import os
import shutil
import tempfile
import unittest

from pinakes import registry
from pinakes.config import ConfigError

PHOTO = """
name = "photo"
version = 2
title = "A site's photos"
mime = ["image/*"]

[extractor]
module = "site_extractors.photo"
requires = ["Pillow>=10"]

[common]
creator = "photographer"
date = "taken"

[fields.photographer]
type = "text"
index = "trigram"

[fields.taken]
type = "date"
index = "range"

[fields.place]
type = "point"
index = "spatial"
sensitive = true

[fields.iso]
type = "number"
index = "range"

[fields.length]
type = "duration"
index = "exact"

[fields.shown]
type = "list"
of = "person"
index = "exact"
sensitive = true

[fields.album]
type = "file"
index = "exact"

[fields.document_id]
type = "text"
index = "exact"
identity = true

[fields.note]
type = "text"
"""


class RegistryCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pinakes-reg-")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def site(self, name, text):
        d = os.path.join(self.tmp, "site")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name + ".toml"), "w") as f:
            f.write(text)
        return d

    def refused(self, text, *words, name="photo"):
        d = self.site(name, text)
        with self.assertRaises(ConfigError) as cm:
            registry.load(d)
        msg = str(cm.exception)
        self.assertIn(os.path.join(d, name + ".toml"), msg)
        for w in words:
            self.assertIn(w, msg)
        return msg


class TestProjectSchemas(RegistryCase):
    def test_dublin_core_loads_first_with_its_fields(self):
        reg = registry.load()
        self.assertEqual([s.name for s in reg][0], "dc")
        dc = reg["dc"]
        self.assertEqual(sorted(dc.fields), sorted(["title", "creator", "subject", "description", "date", "type",
                                                    "format", "language", "rights"]))
        self.assertEqual(dc.mime, ["*/*"])
        self.assertEqual(dc.fields["date"].index_kind, "date")
        self.assertEqual(dc.fields["creator"].of, "text")
        self.assertIsNone(dc.fields["rights"].index)
        self.assertIn(("dc", "title", "trgm"), reg.indexes())

    def test_every_project_schema_file_is_enrolled(self):
        on_disk = sorted(n[:-5] for n in os.listdir(registry.BUILTIN_DIR) if n.endswith(".toml"))
        self.assertEqual(sorted(s.name for s in registry.load()), on_disk)

    def test_the_common_schema_is_required(self):
        d = os.path.join(self.tmp, "builtin")
        os.makedirs(d)
        with self.assertRaises(ConfigError) as cm:
            registry.load(builtin_dir=d)
        self.assertIn("dc.toml: missing", str(cm.exception))


class TestSiteSchemas(RegistryCase):
    def test_a_site_schema_loads_with_every_type_and_index(self):
        reg = registry.load(self.site("photo", PHOTO))
        p = reg["photo"]
        self.assertEqual((p.version, p.title, p.mime), (2, "A site's photos", ["image/*"]))
        self.assertEqual(p.extractor, {"module": "site_extractors.photo", "requires": ["Pillow>=10"]})
        self.assertEqual(p.common, {"creator": "photographer", "date": "taken"})
        self.assertTrue(p.fields["place"].sensitive)
        self.assertTrue(p.fields["document_id"].identity)
        self.assertEqual(sorted(p.indexes()), sorted([
            ("photo", "photographer", "trgm"), ("photo", "taken", "date"), ("photo", "place", "geo"),
            ("photo", "iso", "num"), ("photo", "length", "num"), ("photo", "shown", "list"),
            ("photo", "album", "ref"), ("photo", "document_id", "eq")]))

    def test_index_names_fit_postgresql(self):
        name, field = "a" * 20, "b" * 30
        text = 'name = "%s"\nversion = 1\nmime = ["*/*"]\n[fields.%s]\ntype = "text"\nindex = "trigram"\n' % (
            name, field)
        reg = registry.load(self.site(name, text))
        (idx,) = reg[name].indexes()
        self.assertLessEqual(len(registry.index_name(*idx)), 63)

    def test_no_site_folder_is_no_site_schemas(self):
        self.assertEqual([s.name for s in registry.load(None)], [s.name for s in registry.load()])

    def test_a_missing_site_folder_is_refused(self):
        with self.assertRaises(ConfigError) as cm:
            registry.load(os.path.join(self.tmp, "nowhere"))
        self.assertIn("schemas folder", str(cm.exception))


class TestIdentityRules(RegistryCase):
    def test_xmp_parents_first_then_shared_values(self):
        self.assertEqual(registry.load()["xmp"].identity_rules(), [
            ("derived_instance_id", "instance_id", "parent"), ("derived_document_id", "document_id", "parent"),
            ("instance_id", "derived_instance_id", "child"), ("document_id", "derived_document_id", "child"),
            ("instance_id", "instance_id", "shared"), ("document_id", "document_id", "shared")])

    def test_a_schema_without_identity_fields_has_none(self):
        self.assertEqual(registry.load()["exif"].identity_rules(), [])

    def test_identity_fields_refused(self):
        ident = '[fields.document_id]\ntype = "text"\nindex = "exact"\nidentity = true\n'
        for bad in ('[fields.document_id]\ntype = "number"\nindex = "exact"\nidentity = true\n',
                    '[fields.document_id]\ntype = "text"\nindex = "trigram"\nidentity = true\n',
                    '[fields.document_id]\ntype = "text"\nidentity = true\n',
                    ident + "sensitive = true\n"):
            self.refused(PHOTO.replace(ident, bad), "field document_id", "an identity field is text")
        parent = ident + '[fields.parent_id]\ntype = "text"\nindex = "exact"\nidentity = true\n'
        for target, words in (("nothing", "parent 'nothing' is not an identity field"),
                              ("note", "parent 'note' is not an identity field"),
                              ("parent_id", "without a parent of its own")):
            self.refused(PHOTO.replace(ident, parent + 'parent = "%s"\n' % target), "field parent_id", words)
        self.refused(PHOTO.replace(ident, ident.replace("identity = true\n", 'parent = "x"\n')),
                     "field document_id", "parent names another identity field")

    def test_a_site_parent_field_loads(self):
        ident = '[fields.document_id]\ntype = "text"\nindex = "exact"\nidentity = true\n'
        text = PHOTO.replace(ident, ident + '[fields.parent_id]\ntype = "text"\nindex = "exact"\nidentity = true\n'
                             'parent = "document_id"\n')
        p = registry.load(self.site("photo", text))["photo"]
        self.assertEqual(p.identity_rules(), [("parent_id", "document_id", "parent"),
                                              ("document_id", "parent_id", "child"),
                                              ("document_id", "document_id", "shared")])


class TestRefused(RegistryCase):
    def test_not_toml(self):
        self.refused("name = ", "not valid TOML")

    def test_unknown_keys(self):
        self.refused(PHOTO + '\nsidecars = ["{name}.xmp"]\n', "unknown key sidecars")
        self.refused(PHOTO.replace('type = "point"', 'type = "point"\nprecision = 3'), "field place",
                     "unknown key precision")

    def test_name(self):
        self.refused(PHOTO.replace('name = "photo"', 'name = "Photo"'), "name must be")
        self.refused(PHOTO.replace('name = "photo"', 'name = "my_photo"'), "name must be")
        self.refused(PHOTO.replace('name = "photo"', 'name = "pictures"'), "must match the file's name")

    def test_version(self):
        for v in ('"2"', "0", "true", "1.5"):
            self.refused(PHOTO.replace("version = 2", "version = %s" % v), "version must be")
        self.refused(PHOTO.replace("version = 2\n", ""), "version must be")

    def test_mime(self):
        self.refused(PHOTO.replace('mime = ["image/*"]', "mime = []"), "mime must list")
        self.refused(PHOTO.replace('mime = ["image/*"]', 'mime = ["jpeg"]'), "not a MIME type")
        self.refused(PHOTO.replace('mime = ["image/*"]', 'mime = ["*/jpeg"]'), "not a MIME type")

    def test_fields(self):
        self.refused('name = "photo"\nversion = 1\nmime = ["*/*"]\n', "needs [fields.NAME]")
        self.refused(PHOTO.replace("[fields.iso]", "[fields.ISO]"), "field name 'ISO'")
        self.refused(PHOTO.replace('type = "number"', 'type = "integer"'), "field iso", "type must be one of")
        self.refused(PHOTO.replace("[fields.note]\ntype = \"text\"", "[fields.note]"), "field note",
                     "type must be one of")

    def test_an_index_that_doesnt_fit_its_type(self):
        msg = self.refused(PHOTO.replace('type = "date"\nindex = "range"', 'type = "date"\nindex = "trigram"'),
                           "field taken", "index 'trigram' doesn't apply to date")
        self.assertIn("use exact or range", msg)
        self.refused(PHOTO.replace('index = "spatial"', 'index = "range"'), "doesn't apply to point")
        self.refused(PHOTO.replace('of = "person"\nindex = "exact"', 'of = "person"\nindex = "trigram"'),
                     "field shown", "a trigram index needs a list of text, not of person")

    def test_of(self):
        self.refused(PHOTO.replace('of = "person"', 'of = "point"'), "field shown", "of must be one of")
        self.refused(PHOTO.replace('type = "number"', 'type = "number"\nof = "text"'), "field iso",
                     "of is for a list only")

    def test_flags(self):
        self.refused(PHOTO.replace("sensitive = true", 'sensitive = "yes"', 1), "field place",
                     "sensitive is true or false")

    def test_extractor(self):
        self.refused(PHOTO.replace('module = "site_extractors.photo"', 'module = "site extractors"'),
                     "[extractor]", "module must be")
        self.refused(PHOTO.replace('requires = ["Pillow>=10"]', 'requires = "Pillow"'), "requires lists packages")
        self.refused(PHOTO.replace('requires = ["Pillow>=10"]', 'requires = ["Pillow; rm -rf"]'),
                     "requires lists packages")

    def test_common_mapping(self):
        self.refused(PHOTO.replace('creator = "photographer"', 'author = "photographer"'), "[common] author",
                     "not a field of dc")
        self.refused(PHOTO.replace('creator = "photographer"', 'creator = "artist"'), "[common] creator",
                     "'artist', not a field of this schema")
        self.refused(PHOTO.replace('date = "taken"', 'date = "iso"'), "[common] date",
                     "iso is number, which doesn't fit dc.date (date)")
        self.refused(PHOTO.replace('creator = "photographer"', 'creator = "shown"'),
                     "shown is a list of person, which doesn't fit dc.creator (a list of text)")

    def test_a_site_schema_cant_take_a_project_schemas_name(self):
        self.refused(PHOTO.replace('name = "photo"', 'name = "dc"'), "already enrolled by the project", name="dc")


if __name__ == "__main__":
    unittest.main()
