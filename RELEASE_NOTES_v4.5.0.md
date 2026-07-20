# Dayı Stego Solver 4.5.0

Release candidate prepared on 2026-07-20. These notes do not assert that a tag,
GitHub release, package publication, or production merge has occurred.

## Overview

Dayı Stego Solver 4.5.0 is the candidate for a reliability and
defensive-analysis release. It adds bounded text and document steganography,
advanced local OCR and passive QR analysis, recursive artifact propagation, and
a local-only regression harness. It also tightens extraction verification,
timeout enforcement, process cleanup, Unicode safety, and per-flag reporting
attribution.

Repository: https://github.com/MacallanTheRoot/DayiStegoSolver

The core installation remains dependency-free. Optional Python libraries and
external tools enable format-specific capabilities and degrade cleanly when
they are unavailable.

## Highlights

### Verified extraction and brute-force control

- OutGuess output is no longer accepted from a successful return code or an
  output path alone.
- Candidate extraction is compared with one bounded, usable known-invalid
  baseline and must have verified evidence such as a flag, known file magic,
  or meaningful structured content.
- Missing, failed, timed-out, unreadable, oversized, or otherwise unusable
  baselines fail closed and do not suppress StegSeek or fallback phases.
- Wordlists resolve only through the requested local path, current directory,
  or the standard Kali `rockyou.txt` and streamed `rockyou.txt.gz` locations.
  `--require-wordlist` provides an explicit strict mode.

### Bounded text steganography

The core-only `text_stego_scanner` detects text from bytes rather than file
extensions and supports bounded analysis of:

- UTF-8/ASCII, BOM-marked UTF, UTF-16/UTF-32, and conservative Latin-1 input;
- Bacon A/B and binary variants;
- spaces, tabs, line structure, trailing whitespace, and CRLF/LF channels;
- zero-width and other explicitly recognized invisible Unicode characters;
- conservative Latin/Cyrillic and selected visual homoglyph channels;
- acrostics, structural/every-N extraction, capitalization anomalies, and
  ghost-text/control-character reconstruction;
- bounded nested reverse, ROT, Atbash, Hex, binary/octal/decimal ASCII,
  Base16/32/64/85, URL/HTML/Unicode escapes, Morse, gzip/zlib, and limited XOR
  transformations.

Direct active-regex flags are retained independently of bounded previews and
the expensive decoder window. Candidate count, output size, aggregate bytes,
and recursion depth remain fixed.

### Word, spreadsheet, presentation, OpenDocument, and RTF analysis

The core-only `document_stego_scanner` uses content-based detection for:

- DOCX and DOCM;
- XLSX and XLSM;
- PPTX and PPTM;
- ODT, ODS, and ODP;
- bounded RTF and document-container classification.

It inspects hidden text and styles, revisions, comments, notes, headers and
footers, metadata, alt text, field instructions, relationships, hidden
sheets/slides/pages, spreadsheet names and passive formulas, media, objects,
and conservative two-class style channels. OpenXML and OpenDocument members are
read explicitly with path, count, compression, expanded-size, XML, media,
object, and recursion limits. RTF processing bounds input, group depth, group
and control counts, decoded text, pictures, objects, and binary data.

Macros, formulas, fields, OLE content, embedded executables, and decoded
commands are never executed. External relationships are reported but never
fetched.

### Advanced OCR and passive QR analysis

- OCR uses deterministic, lazily generated preprocessing variants, selected
  Tesseract page-segmentation modes, structured word confidence, consensus,
  conservative flag-context repair, and `--ocr-lang` validation.
- `--ocr-exhaustive` expands the fixed processing schedule without removing
  image, pixel, invocation, byte, memory-work, or timeout limits.
- `qr_scanner` prefers OpenCV, then pyzbar, then the byte-preserving zbarimg
  fallback. Native backends run in killable workers and zbarimg is bounded by
  the remaining plugin deadline.
- QR payloads are classified passively and may enter bounded local text or
  image recursion only after recognized encoding and image magic checks.
- Decoded URLs, Wi-Fi records, contacts, OTP URIs, and command-like payloads are
  never opened, joined, imported, or executed.

OCR is heuristic, and damaged QR symbols or stylized text are not guaranteed to
decode. Missing optional backends produce a degraded capability rather than a
core failure.

### Recursive artifact propagation

Content-extracted images and text from binwalk, Word, spreadsheets,
presentations, OpenDocument packages, RTF, nested documents, and QR image
payloads can reach compatible downstream scanners within shared limits.
Package-specific extraction namespaces prevent member-name collisions, while
content hashes, depth, object-count, and aggregate-byte budgets prevent cycles
and recursive runner explosions.

### Process, timeout, and memory hardening

- Timeout-sensitive text/document parsers and native QR decoders use spawned,
  killable workers with bounded serialized responses and child reaping.
- OCR recomputes the absolute remaining deadline before each pass and keeps
  per-call and total invocation limits.
- QR and OCR preprocessing variants are generated and released incrementally
  under aggregate generated-pixel and estimated-byte budgets.
- Image dimensions, frame counts, source bytes, and decoded pixels are checked
  before native QR decoding.
- Urllib notification fallback work runs behind a killable total deadline;
  redirects and response bodies remain bounded.
- ANSI, bidi, terminal controls, RTF surrogate pairs, and malformed Unicode are
  normalized or escaped before terminal, JSON, and Markdown reporting.

These controls reduce exposure to hostile challenge inputs. They are not a
complete sandbox and cannot guarantee the safety of every third-party parser,
native library, or external executable.

### Reporting and attribution

- Flags retain canonical source, member, image variant, page-segmentation mode,
  and decoder-chain attribution where applicable.
- Per-flag OCR chains remain distinct even when one OCR pass yields multiple
  direct and decoded flags.
- Confirmed document flags are retained when bounded finding capacity is
  reached, while lower-confidence output remains limited.
- Nested document and RTF artifacts preserve package/member provenance through
  downstream OCR, QR, metadata, strings, LSB, and compatible stego analysis.
- Terminal, JSON, Markdown writeups, and optional ctfshit exporter input use
  bounded, escaped representations.

### Local private regression harness

`scripts/run_private_regression.py` scans a user-selected corpus one file at a
time in child processes. Corpus, manifest, and output paths must remain outside
the repository; source files are not modified or uploaded. The harness supports
bounded timeouts and file counts, deterministic anonymization, default full-flag
redaction, optional local expectations, and JSON/Markdown aggregate summaries.
The expectation manifest itself is excluded from corpus discovery.

Private results depend entirely on the user's local corpus. No private corpus,
manifest, basename, flag, extracted payload, or report is shipped with Dayı.

## Installation

From a trusted checkout:

```bash
python -m pip install .
```

Optional capabilities can be installed independently, for example:

```bash
python -m pip install '.[ocr]'
python -m pip install '.[qr]'
python -m pip install '.[pdf,ole,pcap,integration,ui]'
```

The package supports CPython 3.10 through 3.13. The core package declares no
mandatory runtime dependency.

## Verification commands

```bash
dayi --version
dayi doctor
dayi plugins list
```

Expected release-candidate version output is `dayi 4.5.0`. The deterministic
registry contains 22 plugins; availability varies with optional libraries and
external tools.

## Known limitations

- Detection is bounded and heuristic; Dayı does not solve every CTF challenge.
- The document scanner does not provide rendering-equivalent Microsoft Office
  or LibreOffice behavior and does not claim complete legacy Office support.
- OCR quality depends on the local Tesseract installation, language packs, and
  source image quality.
- QR backend support and damaged-code recovery vary by installed optional
  backend.
- External steganography tools and optional native libraries remain outside a
  complete sandbox and should be treated as format-specific local dependencies.
- Extracted artifacts remain untrusted data even when their paths and sizes have
  been validated.
