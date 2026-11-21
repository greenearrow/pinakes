# Metadata

Status: partly built (schemas, EXIF and embedded XMP from JPEGs, sensitive fields, a file's page and find, entering
metadata and sharing sensitive fields: REARVIEW.md 12 to 16); the rest is design. Files carry metadata of their own (a photo's camera and place, a song's artist, a
book's author) and people add more (tags, notes, "this is the master copy"). The catalog stores both, typed by
enrolled schemas, indexed, and attached so that it follows files through copies and moves.

## Two places metadata attaches

- **On content** (by SHA-256): facts about the bytes, true of every copy. A photo's date taken, a song's artist.
  Extracted once; every copy anywhere has it at once, with no re-reading.
- **On a file** (by `file_id`): facts about one copy, or a person's view of it. Tags, notes, keep or drop, "master
  copy". The `file_id` survives moves and edits (DESIGN.md "Matching moves and changes"), so this metadata follows
  the file.

Person-entered metadata belongs to its author. Extracted metadata is visible to anyone who can see a file with that
content (SECURITY.md).

## Schemas

A schema is enrolled in the project as a versioned file, `schemas/<name>.toml`. It declares:

- its fields and their types: text, number, date and time, geographic point, duration, list, reference to a person
  or another file;
- which fields are indexed and how (exact, trigram for substring, range for dates and numbers, spatial for places);
- which fields are **sensitive** (GPS position, people's names, phone numbers): visible to the owner only, even when
  the file is shared, unless they share those fields too;
- which MIME types it applies to;
- its extractor: a Python module, with its optional dependency (for example `Pillow` or `exifread` for EXIF,
  `mutagen` for audio tags, `ffprobe` for video). A missing dependency turns the extractor off, not the scan;
- its sidecar patterns (below);
- a mapping onto common fields, so one search covers every type: `creator` is a photo's photographer, a song's artist
  and a book's author; `date` is a photo's date taken, a song's release date, a document's creation date.

To be enrolled first, all standards:

| Schema | From | Holds |
|---|---|---|
| `dc` | Dublin Core | title, creator, subject, description, date, type, format, language, rights: the common fields |
| `exif` | EXIF | camera, lens, exposure, date taken, GPS (sensitive) |
| `xmp` | XMP, IPTC Core | keywords, people shown (sensitive), place names, ratings, description; also read from `.xmp` sidecars |
| `audio` | ID3, Vorbis comments, MP4 tags | artist, album, track, disc, year, genre, duration |
| `video` | container metadata | duration, codecs, resolution, date recorded, GPS (sensitive) |
| `ebook` | OPF (EPUB, a Calibre `metadata.opf`) | title, authors, series and index, identifiers (ISBN), language, publisher |
| `document` | PDF info, Office core properties | title, author, created, modified, page count |

A site can enroll its own schemas in config (a collection's catalogue numbers, a family's own tags) in the same form:
a folder of `NAME.toml` files named by `[metadata] schemas` in `server.toml`, which can't reuse a project schema's
name. Export maps onto schema.org types where they exist.

### The file's form (built: ROADMAP 12)

`pinakes/schemas/dc.toml` is the example. Top-level keys: `name` (as the file's name: a lowercase letter, then up to
19 lowercase letters or digits), `version` (a whole number from 1), `title`, `mime` (a list; `image/*`, `*/*`),
`[extractor]` (`module`, a dotted Python name, and `requires`, a list of packages), `[common]` (common field =
this schema's field, of the same type, or one item of a common list) and one `[fields.NAME]` table per field
(`type`, `of` for a list's items, `index`, `sensitive`, `identity`, `parent`, `description`). Anything else is refused,
as is a type an index doesn't fit:

| Type | Stored as | Index |
|---|---|---|
| `text` | a string | `exact` (B-tree), `trigram` |
| `number`, `duration` | a number (a duration in seconds) | `exact`, `range` (B-tree on the number) |
| `date` | ISO 8601 text, as precise as known, times in UTC with `Z`, so text order is time order | `exact`, `range` |
| `point` | `{"lat": ..., "lon": ...}` | `spatial` (GiST, PostgreSQL's own `point`; no PostGIS) |
| `list` | an array, `of` text (the default), number, date, person or file | `exact` (GIN: has this item), `trigram` (of text) |
| `person`, `file` | an id | `exact` |

`pinakes-ingest setup` loads every schema first, and a bad one stops it, naming the file and the key, before anything
changes; it then makes one partial index per indexed field (`md_SCHEMA_FIELD_KIND`, `WHERE schema = 'SCHEMA'`) and
drops the `md_*` indexes no schema wants any more. Sidecar patterns and pairing rules join the form with ROADMAP 14.

## Identity fields

Some formats keep an id that survives edits and saves; a schema marks such fields as **identity fields**, and lineage
(DESIGN.md "Lineage across machines") links any two files that share one, wherever they are:

- PDF: the first part of the trailer's `/ID`, meant to stay for the document's life (the second part changes with each
  revision);
- XMP: `xmpMM:DocumentID` (stays), `xmpMM:InstanceID` (one per saved version), `xmpMM:DerivedFrom` (the parent);
- EPUB: `dc:identifier`;
- office documents: to be checked per format before relying on it (some word processors write a document id that
  survives saves; not verified here).

Identity fields need extraction, so they are never read on a protected root.

Built for XMP (ROADMAP 15). An identity field is text with `index = "exact"`, never sensitive: two files whose
values match are versions of one document. With `parent = "FIELD"` its value is another file's FIELD instead
(`derived_instance_id` names a parent's `instance_id`), and that file is the parent. Lineage tries a schema's parent
fields first, then the shared ones, each in the schema's order: for XMP the parent's version, the parent document,
the same version, the same document. A match is certain (`derived_from`, evidence such as `same xmp document_id`),
and is looked for only where nothing stronger gave the file a source, as chunks and names are.

## Where values come from

Each value records its source and time: **person** (entered in the UI), **sidecar** (read from a paired file),
**embedded** (read from the file itself), **derived** (computed, such as a duration). When sources disagree, the UI
shows all of them and searches use the first of person, sidecar, embedded, derived.

Extraction reads file content, so it never runs on a protected root, nor on a hard link of a protected file in
another root (its record says `protected_link`), and it runs on the agent, on the machine that has the file, never on
the server.

### Extraction (built for EXIF and embedded XMP in JPEGs: ROADMAP 13)

An extractor is a module with `extract(f)`, given the file opened read-only by the agent; it returns the schema's
fields. The agent sends them on the file's record (batch format 2):

```json
{"t": "file", "path": "photos/IMG_0001.JPG", "sha256": "...",
 "meta": {"exif": {"v": 1, "vals": {"make": "Maker-1", "taken": "2019-06-01T10:30:00Z"}}}}
```

or, sent to a server of protocol 4 or later (release 7), what else the extractor made of it: `{"v": 1, "vals": {}}`
when it found nothing, `{"v": 1, "refused": "truncated"}` when it refused the file, with a reason code
(`truncated`, `wrong_type`, `malformed`, `bad_values`, `unreadable`, `failed`), and `{"v": 1, "skipped":
"dependency"}` (or `"broken"`) for an extractor that applies but is off on that machine. A code, never the error's
text, which can quote the file; an older server gets `{"v": 1, "error": "..."}` as before and keeps none of it. The
catalog keeps one outcome per content and schema (`extractions`, ROADMAP 44), so "has no EXIF" is told from "the
reader refused it": the file's page says what each extractor made of it, and `pinakes-ingest extractions` counts
them, every owner's, without names. A root's `metadata` (agent config) is `true` (the default: every
extractor that applies), `false`, or a list of schema names. The agent remembers which versions it read for each
file and reads a file again only when its content or a schema's version changes. The ingester checks every value
against the registry and keeps it on the content, the sensitive fields in a row of their own that only the owners
and co-owners of a copy see (or an administrator in a step-up); DECISIONS.md has the rules.

### On a file's page and in find (built: ROADMAP 16, showing it)

A file's page lists its metadata per schema: every field the person may see, each value with its source, version
and date, and sensitive fields tagged as such. Someone who may not see them gets the same note whether the file has
any or not. Find searches by name, by "made by" (`creator`) and by "dated" (`date`, from and to, a year, a month or
a day), over every schema that maps onto the common field, each through its own index.

### Entering it, and sharing sensitive fields (built: ROADMAP 16)

On a file's page, its owner, a co-owner or an annotator sets or removes one field at a time of any schema that fits
the file (by its name's MIME type; Dublin Core fits every file): a list's items separated by commas, a place as
`LAT, LON`, a duration in seconds or `H:MM:SS`, a date in ISO 8601. The values are checked as extracted ones are,
kept on the file with their author, and shown with "person" and the author's name; nobody else changes them. The
schema's sensitive fields stay apart, as extracted ones do. The owner or a co-owner shares the file's sensitive
fields with any of its readers and annotators, and stops; the page lists who has them, for the owners only. Both
are audited where they touch someone else's file or records.

From a shell, `pinakes tag` sets a person's tags (their `dc.subject`) and note (their `dc.description`) on a file or
on every file under a folder, by a person's token with the `tag` scope (ROADMAP 37); other fields stay on the page.

## Pairing: bundles

Some files only make sense together. A **bundle** is a set of files with a lead file; each schema declares its
pairing rules:

- a photo and its sidecar: `IMG_0001.JPG` with `IMG_0001.JPG.xmp` or `IMG_0001.xmp`;
- RAW and JPEG of the same shot (same base name, same folder);
- a video and its subtitles (`.srt`, `.vtt`) and chapters;
- a disc image and its cue sheet (`.cue` with `.bin`);
- a book folder: the book files, `metadata.opf` and `cover.jpg`;
- an export's JSON sidecars (`photo.jpg.json`).

What pairing gives:

- **Searches** return the bundle once, with the sidecar's metadata applied to the lead file.
- **Move matching** treats the bundle as a unit: a photo and its sidecar that appear together in a new folder are one
  move, with higher confidence.
- **Managed moves** move the whole bundle, so a sidecar is never left behind.
- **Write-back**: metadata entered in the catalog can be written to the bundle's sidecar (the `write-sidecar`
  operation), so it survives outside the catalog and other programs can read it. The catalog never writes metadata
  into a file itself, which would change its hash.

## Storage and speed

- One row per subject and schema, with the values as JSONB, plus a typed index for every field the schema marks
  indexed (B-tree for exact and range, trigram for text, GiST for places). A search on metadata is an index lookup;
  no file is read.
- Content metadata is extracted once per content. When a copy of known content turns up on another machine, its
  metadata is already there.
- Re-extraction happens when a file's content changes, when its sidecar changes, or when a schema's version goes up.
