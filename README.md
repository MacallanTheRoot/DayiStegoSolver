<div align="center">

# 🕵️ Dayı Stego Solver

### *"Hallederiz yeğenim." — The Uncle who always finds the flag.*

[![Python 3.10–3.13](https://img.shields.io/badge/Python-3.10%E2%80%933.13-3776AB?logo=python&logoColor=white)](https://python.org)
[![CI](https://github.com/MacallanTheRoot/DayiStegoSolver/actions/workflows/ci.yml/badge.svg)](https://github.com/MacallanTheRoot/DayiStegoSolver/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/Version-4.5.0-success)](https://github.com/MacallanTheRoot/DayiStegoSolver)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Core%20Deps-Zero%20%28stdlib%29-brightgreen)](pyproject.toml)
[![Async](https://img.shields.io/badge/asyncio-gather-blue)](dayi/runner.py)

**English** | [Türkçe](#-türkçe-dokümantasyon)

> **Current release candidate:** 4.5.0. See the
> [changelog](CHANGELOG.md) and [4.5.0 release notes](RELEASE_NOTES_v4.5.0.md).
> Tagging and publication are separate release steps and are not asserted here.

> Developed with ☕ and CTF tears by [MacallanTheRoot](https://github.com/MacallanTheRoot)

> *"Dayı"* means Uncle in Turkish — the kind who knows how everything works, fixes things without asking twice, and never panics under pressure. Give him a stego challenge. He'll sort it.

</div>

---

## 🌐 English Documentation

### What is Dayı?

Throw a suspicious file at Dayı and walk away. It coordinates a deterministic
22-plugin phased pipeline, extracts useful content, matches your flag regex,
and — if you configured it — pings CTFd and Discord before you've opened a
second terminal.

It logs at you like a wise, sarcastic Turkish uncle. The code itself is clean and boring, as it should be.

---

### 🆕 Latest upgrades

| Upgrade | Current behavior |
|---|---|
| **Multi-stage artifact scanner** | Passively reports HTTP/HTTPS URLs, validated IP addresses, conservative domains, credential hints, decimal/DMS coordinates, and printable Base64 hints. It never fetches, resolves, or follows an artifact. |
| **Bounded text steganography** | Detects text from bytes, then scores Bacon, whitespace, zero-width Unicode, homoglyph, acrostic/structural, ghost-text, and nested encoding candidates without network access or optional dependencies. |
| **Bounded document steganography** | Detects DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, ODT/ODS/ODP, and RTF content regardless of extension; inspects explicit concealment, comments/notes, metadata, alt text, relationships, media, objects, and conservative style channels without rendering or active content. |
| **Intelligent mini-wordlist decoder** | Quietly adds printable Hex and strict Base64 decodings alongside their original tokens, with deterministic deduplication and bounded candidate limits. |
| **ZIP carving and cracking** | `binwalk` explicitly carves raw ZIP bytes even when external extraction fails. Extensionless ZIPs are detected by content, then safely extracted or tried with the mini-wordlist before the streamed main wordlist. |
| **Pure-Python chi-square analysis** | Reconstructs bounded PNG scanlines and uncompressed BMP pixels without Pillow/NumPy/SciPy, then reports an LSB Pair-of-Values uniformity heuristic. |
| **Dynamic plugin registry** | Discovers validated `PLUGIN_SPECS` automatically, orders them by phase and priority, and skips malformed plugins without crashing the scan. |
| **Optional Rich terminal UI** | Provides one coordinated live display, plugin status, progress, artifact panels, and flag tables when Rich and an interactive TTY are available. |
| **Optional advanced OCR** | Runs a bounded deterministic multi-pass pipeline over content-detected PNG/JPEG/BMP/GIF/TIFF/WebP/PNM targets and extracted images. OCR text enters flag, artifact, and nested text decoding. |
| **Optional passive QR** | `qr_scanner` prefers OpenCV, then pyzbar, then zbarimg; decoded payloads are classified locally but URLs and commands are never opened or executed. |
| **Optional PDF forensics** | Uses pypdf to inspect PDF metadata and page text, handles empty-password encryption, and sends discovered flags and passive artifacts through the normal report/UI pipeline. |
| **Optional OLE/macro forensics** | Uses `oletools.olevba` to identify OLE/OpenXML Office containers, extract bounded VBA source modules, and scan macros for flags, URLs, credentials, and encoded hints. |
| **Optional PCAP forensics** | Streams PCAP/PCAPNG packets with Scapy `PcapReader`; extracts bounded Raw/ICMP payloads, DNS queries/TXT-style resource data, HTTP paths/cookies/authorization, flags, and passive artifacts without loading the capture into RAM. Recognized PNG/JPEG/ZIP/PDF payloads are carved into the managed workspace. |

Security hardening also rejects noisy short-domain/IPv6 artifacts, ZIP path traversal, symlink escapes, oversized archive members, decompression bombs, oversized OCR/PDF/Office/PCAP inputs, excessive PDF pages/text, VBA modules/source, packets/cleartext, and duplicate workspace images. Text stego inspects at most 8 MiB, analyzes at most 4 million decoded characters, stores at most 512 candidates with 64 KiB output each, limits recursion to depth 3 and aggregate decoded data to 16 MiB, and escapes ANSI/bidi/control data before display. OpenXML and OpenDocument analysis caps packages at 128 MiB, members at 5,000, one expanded member at 32 MiB, total expansion at 256 MiB, XML members at 16 MiB with 200,000 nodes and depth 256, media at 100, embedded objects at 50, and recursive depth at 3. RTF analysis caps input at 16 MiB, group depth at 256, groups at 100,000, control words at 200,000, decoded text at 4 MiB, binary data at 32 MiB, pictures at 100, and objects at 50. No macro, formula, field, embedded executable, or external relationship is executed or fetched. PCAP processing is capped at 128 MiB, 50,000 streamed packets, 4 MiB retained text, 50 carved files, and 10 MiB per carved payload.

Direct active-regex flags are retained separately from the 64 KiB candidate
preview, with 64-match and 64 KiB aggregate flag-text limits.

Image analysis caps each source at 64 MiB, 50 million pixels, 20,000 pixels
per dimension, and five frames. A scan considers at most 20 unique images, 20
OCR variants per image, 30 OCR calls per image, 200 OCR calls total, and 15
seconds per OCR call under one absolute 90-second OCR plugin deadline. Image
dimensions are validated before OpenCV decoding. QR analysis uses at most 16
variants and 20 symbols per image, 1 MiB per payload, recursion depth 2, and 32
MiB of recursively decoded image data. QR transformations are generated and
released one at a time under aggregate limits of 150 million generated pixels
and 256 MiB of estimated transformation work. The zbarimg fallback preserves
one raw binary payload per image;
multi-symbol binary decoding uses OpenCV or pyzbar because zbarimg raw newline
framing is ambiguous. QR payloads remain passive and all OCR/QR control data is
escaped. Timeout-sensitive document and text parsers run in killable spawned
workers and are reaped when their deadline expires.

#### Optional Auto-Forensics modules

| Module | Plugin | Phase | Optional runtime | Coverage |
|---|---|---:|---|---|
| **Module 7 — OCR** | `ocr_scanner` | Archive, priority 20 | `Pillow`, `pytesseract`, system Tesseract | Bounded preprocessing/PSM passes, language selection, consensus, and nested text decoding. |
| **Module 8 — PDF** | `pdf_scanner` | Concurrent, priority 45 | `pypdf>=4.0.0` | Scans PDF metadata and bounded page text, including empty-password documents. |
| **Module 9 — OLE/Macro** | `ole_scanner` | Concurrent, priority 46 | `oletools>=0.60.1` | Extracts bounded VBA source from supported OLE/OpenXML Office containers. |
| **Module 10 — PCAP** | `pcap_scanner` | Concurrent, priority 47 | `scapy>=2.5.0` | Streams PCAP/PCAPNG, analyzes Raw/ICMP/DNS/HTTP data, and safely carves embedded PNG/JPEG/ZIP/PDF payloads. |
| **Module 11 — Documents** | `document_stego_scanner` | Archive, priority 5 | Core Python | Inspects bounded Word, spreadsheet, presentation, OpenDocument, and RTF structure and exposes safe media/objects to local scanners; optional `oletools` enriches DOCM/XLSM/PPTM macro analysis. |
| **Module 12 — QR** | `qr_scanner` | Archive, priority 15 | Optional OpenCV, pyzbar/zbar, or zbarimg | Passively decodes and classifies bounded QR payloads before OCR. |

The optional modules skip cleanly when their runtime is absent; the document
core remains available with the default zero-dependency installation.

---

### ✨ Features

| | Feature | What it actually does |
|---|---|---|
| ⚡ | **Concurrent execution** | `asyncio.gather()` runs the 12 `CONCURRENT`-phase plugin operations together within the 22-plugin registered pipeline. ~75% faster than the old sequential loop. |
| 🔌 | **Drop-in plugins** | Public modules under `dayi/tools/` self-register with `PLUGIN_SPECS`; the runner needs no edits. |
| 🎨 | **Optional Rich UI** | `.[ui]` adds one coordinated live display, progress bars, warning panels, and flag tables; non-TTY and zero-dependency installs stay plain. |
| 👁️ | **Optional OCR** | `.[ocr]` reads visible text from the target and images unpacked into the workspace; the core remains dependency-free. |
| ▣ | **Passive QR analysis** | `.[qr]` supplies the preferred OpenCV backend; pyzbar/zbar or zbarimg are alternatives and missing backends degrade cleanly. |
| 📄 | **Optional PDF forensics** | `.[pdf]` extracts bounded metadata/page text and checks empty-password encrypted PDFs; non-PDF targets skip immediately. |
| 📎 | **Optional OLE/macro forensics** | `.[ole]` extracts bounded VBA source from legacy OLE and ZIP-based OpenXML Office documents. |
| 🌐 | **Optional PCAP forensics** | `.[pcap]` streams PCAP/PCAPNG packets, inspects Raw/ICMP/DNS/HTTP data, and safely carves recognized PNG/JPEG/ZIP/PDF payloads. |
| 🔤 | **Core text steganography** | `text_stego_scanner` recognizes byte-detected UTF/ASCII text and bounded Bacon, whitespace, invisible Unicode, homoglyph, structural, ghost-text, and nested encodings. |
| 📚 | **Core document steganography** | `document_stego_scanner` inspects supported Office OpenXML, OpenDocument, and RTF content under fixed local limits. |
| 🧭 | **Passive artifact detection** | Reports links, IPs, domains, credential hints, coordinates, and validated Base64 previews without network access. |
| 🔐 | **Safe archive recovery** | Carves extensionless ZIPs, tries contextual passwords first, and enforces traversal and extraction-size limits. |
| 🔓 | **Intelligent token decoding** | Adds printable Hex and strict Base64 decodings to the bounded contextual password pool. |
| 📊 | **Chi-square LSB test** | Measures PNG/BMP Pair-of-Values distributions with a pure-stdlib p-value heuristic. |
| 🧠 | **Smart routing** | Reads the first 16 bytes. JPEG → no zsteg. PNG → no steghide. No wasted forks. |
| 🔔 | **Early notification** | Flag found by exiftool while binwalk is still running? CTFd gets it immediately. |
| 🔍 | **Mini-wordlist BF** | Pulls candidate passwords from metadata output and tries them before touching rockyou. |
| 📝 | **Auto write-up** | Generates a Markdown writeup. Uses ctfshit's exporter if available, falls back to its own. |
| 🧹 | **Zombie-safe subprocess** | SIGTERM → 2s grace → SIGKILL → `wait_for(5s)`. Stuck processes don't linger. |
| 🔒 | **OOM-safe wordlists** | rockyou.txt is streamed line-by-line. 134MB never hits RAM as a whole. |
| 🛡️ | **Token sanitization** | Strips null bytes and control chars before handing tokens to steghide subprocess args. |
| 🧩 | **ctfshit writeup integration** | Optionally uses the `csl-ctfshitcli` exporter for rich Markdown; the built-in Markdown fallback is always available. |
| 🔄 | **Native notification transport** | Selects usable aiohttp once, otherwise stdlib urllib; CTFd and Discord delivery remain independent. |
| 🗂️ | **Flag attribution** | Report says `CTF{flag} ← found by: exiftool, binwalk`. Useful. |
| ⌨️ | **Ctrl+C safe** | Hit interrupt anytime. Partial results are written. Nothing is lost. |

---

### 🗂️ Format → Tool Matrix

| Format | Magic bytes | exiftool | exiv2 | strings | binwalk | zsteg | lsb_py | chi_square | steghide | outguess | stegseek | ocr | pdf | ole | pcap |
|:------:|:-----------:|:--------:|:-----:|:-------:|:-------:|:-----:|:------:|:----------:|:--------:|:--------:|:--------:|:---:|:---:|:---:|:----:|
| **JPEG** | `FF D8 FF` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **PNG** | `89 50 4E 47` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **BMP** | `42 4D` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **WAV** | `52 49 46 46` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **ZIP** | `50 4B 03 04` | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **PDF** | `25 50 44 46 2D` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **OLE Office** | `D0 CF 11 E0 A1 B1 1A E1` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **OpenXML Office** | `50 4B 03 04` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **PCAP** | `D4 C3 B2 A1` / `A1 B2 C3 D4` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **PCAPNG** | `0A 0D 0D 0A` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Unknown** | — | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

> Routing is header-based. Rename a JPEG to `.png` — Dayı still knows what it is.

#### Tool reference

| Tool | Type | What it does | Install |
|------|------|-------------|---------|
| `exiftool` | External | EXIF/metadata dump | `sudo apt install libimage-exiftool-perl` |
| `exiv2` | External | EXIF/IPTC/XMP metadata | `sudo apt install exiv2` |
| `strings` | External | Printable string extraction | `sudo apt install binutils` |
| `text_stego_scanner` | **Built-in** | Bounded confidence-scored text steganography and decoder chains | nothing |
| `document_stego_scanner` | **Built-in** | Bounded Word, spreadsheet, presentation, OpenDocument, and RTF concealment plus embedded content | nothing; `.[ole]` optionally enriches DOCM/XLSM/PPTM macro strings |
| `binwalk` | External | Embedded extraction + raw ZIP carving fallback | `sudo apt install binwalk` |
| `zip_cracker` | **Built-in** | Safe extensionless/ZipCrypto recovery and recursive flag scan | nothing |
| `zsteg` | External | PNG/BMP LSB analysis | `sudo gem install zsteg` |
| `lsb_py` | **Built-in** | PNG/BMP LSB (pure Python, no Ruby needed) | nothing |
| `chi_square` | **Built-in** | PNG/BMP PoV chi-square LSB heuristic | nothing |
| `qr_scanner` | Optional-backend plugin | Passive QR decoding on content-detected target/workspace/document images | `pip install -e ".[qr]"`, pyzbar/zbar, or zbarimg |
| `ocr_scanner` | Optional plugin | Bounded multi-pass OCR on PNG/JPEG/BMP/GIF/TIFF/WebP/PNM images | `pip install -e ".[ocr]"` + Tesseract |
| `pdf_scanner` | Optional plugin | Bounded PDF metadata/text, empty-password, flag, and artifact scan | `pip install -e ".[pdf]"` |
| `ole_scanner` | Optional plugin | Bounded OLE/OpenXML VBA source, flag, and artifact scan | `pip install -e ".[ole]"` |
| `pcap_scanner` | Optional plugin | Streaming Raw/ICMP/DNS/HTTP analysis plus bounded PNG/JPEG/ZIP/PDF carving | `pip install -e ".[pcap]"` |
| `steghide` | External | JPEG/BMP/WAV steghide | `sudo apt install steghide` |
| `outguess` | External | JPEG outguess | `sudo apt install outguess` |
| `stegseek` | External | Native-speed steghide BF | [github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek) |

---

### 📦 Installation

For users with access to the repository:

```bash
git clone https://github.com/MacallanTheRoot/DayiStegoSolver.git
cd DayiStegoSolver

python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Rich spinner, progress bars, panels, and result tables (optional)
pip install -e ".[ui]"

# Visible-text OCR for target and extracted images (optional)
pip install -e ".[ocr]"

# Preferred passive QR backend (optional; pyzbar/zbarimg are alternatives)
pip install -e ".[qr]"

# PDF metadata and page-text forensics (optional)
pip install -e ".[pdf]"

# OLE/OpenXML VBA macro forensics (optional)
pip install -e ".[ole]"

# Streaming PCAP/PCAPNG network forensics (optional)
pip install -e ".[pcap]"

# Preferred native Discord/CTFd transport (stdlib urllib remains available)
pip install -e ".[integration]"

dayi --help
dayi doctor
```

`dayi doctor` checks core Python/package health, known external executables,
and optional Python capabilities without scanning a target or making network
requests. External tools are format-specific and optional; missing ones do not
prevent basic use. Exit code `0` means the core CLI remains usable, including a
degraded result with optional components missing. Exit code `1` means the core
installation is unhealthy. Use `dayi doctor --json` for deterministic CI or
script output. Native notification diagnostics report the locally selected
aiohttp/urllib transport and safe CTFd/Discord configuration states. Doctor does
not contact endpoints or test credentials and never prints their values. It
also reports local OCR/Tesseract language capability and the selected passive
QR backend without opening or scanning an image.

**System tools (Kali/Debian/Ubuntu):**

```bash
sudo apt install -y libimage-exiftool-perl exiv2 binutils binwalk steghide outguess
sudo gem install zsteg

# Required only when the optional OCR extra is used
sudo apt install -y tesseract-ocr

# stegseek — worth it, trust me
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_linux.deb
sudo dpkg -i stegseek_linux.deb
```

**ctfshit rich writeup export (optional):**

```bash
# Use a validated local ctfshitcli checkout without installing it
export DAYI_CTFSHIT_PATH=../ctfshitcli

# Or install the csl-ctfshitcli distribution from that checkout
python -m pip install -e ../ctfshitcli
```

The resolver prefers an explicit `--ctfshit-path` or `DAYI_CTFSHIT_PATH`, then
an installed `csl-ctfshitcli` distribution, then validated immediate
`ctfshitcli`/legacy `ctfshit` sibling or child checkouts. It is used only for
rich Markdown writeups; Discord and CTFd do not depend on it. If unavailable,
Dayı still writes its built-in Markdown format.

---

### 🚀 Usage

```bash
# Preferred: built-in common flag patterns
dayi scan photo.jpg

# Known challenge format: use only this custom pattern
dayi scan photo.jpg --flag "CTF{.*?}"

# Extension-independent text stego with a challenge-specific prefix
dayi scan hidden.data --flag 'SiberVatan\{.*?\}' -v

# With rockyou (streamed, safe)
dayi scan stego.jpg --flag "picoCTF{.*?}" --wordlist /usr/share/wordlists/rockyou.txt

# Require a usable wordlist instead of continuing in degraded mode
dayi scan stego.jpg --wordlist rockyou.txt --require-wordlist

# JSON report, verbose
dayi scan mystery.png -v --output report --format json

# Put the unique scan workspace under a chosen parent
dayi scan mystery.png --workspace-dir /safe/workspaces
```

Without `--flag`, the conservative built-in matcher recognizes only `CTF`,
`FLAG`, `HTB`, `picoCTF`, and `THM` brace forms. Custom challenge prefixes may
not be detected, so `--flag` remains recommended when the expected format is
known. Run `dayi scan --help` for scan options. The legacy forms
`dayi FILE` and `dayi FILE --flag REGEX` remain supported and use the same scan
path. To scan a target literally named `scan`, use `dayi scan -- scan` (or an
unambiguous path such as `./scan`).

For the plain name `--wordlist rockyou.txt`, Dayı checks only the supplied
path, the current directory, `/usr/share/wordlists/rockyou.txt`, and
`/usr/share/wordlists/rockyou.txt.gz`, in that order. Gzip wordlists are
streamed without being expanded to disk. If no candidate exists, scanning
continues in degraded mode and reports the disabled main Steghide and OutGuess
brute-force phases. Add `--require-wordlist` to fail before scanning instead.
Other names are never replaced with an unrelated wordlist.

OutGuess output counts as a recovered password only after bounded content
validation. A zero return code or output-file creation alone cannot make the
mini brute-force phase successful or suppress later fallback plugins.
Domain-like artifacts are confidence-classified without DNS or network access:
confirmed and probable findings appear normally, possible findings require
`--verbose`, and noise remains hidden.

Installation diagnostics require no target:

```bash
dayi doctor
dayi doctor --json
```

Doctor makes no network requests. Missing external tools or optional Python
modules produce a degraded report but still exit `0` while the core is usable.
It also reports the built-in text- and document-steganography capabilities
without opening or scanning a target. The document capability is local and
network-free; `oletools` availability is reported separately for optional DOCM
macro-source analysis.

Inspect the real dynamic registry without running a scan:

```bash
dayi plugins list
dayi plugins list --json
```

`available` means declared static runtime dependencies are present;
`unavailable` means a declared executable or Python module is missing;
`conditional` means scan-time input or phase/plugin outcomes are required.
Listing imports only trusted modules shipped inside `dayi.tools`. It never loads
arbitrary plugin directories, executes plugin runners or external binaries, or
uses the network. Discovery issues and missing optional tools remain reportable
with exit code `0`; JSON output is suitable for scripts and CI.
The registry contains 22 plugins in this release candidate. Archive processing
runs `document_stego_scanner` at priority 5, ZIP recovery at 10, the core-only
`text_stego_scanner` at 12, `qr_scanner` at 15, and `ocr_scanner` at 20. This
lets bounded carved and document-extracted text reach text-stego analysis before
image analysis, without adding another plugin.

OCR remains heuristic. Choose installed Tesseract languages with `--ocr-lang`
and request the slower full bounded processing schedule with
`--ocr-exhaustive`:

```bash
dayi scan image.bin --ocr-lang eng+tur --flag 'SiberVatan\{.*?\}'
dayi scan image.bin --ocr-exhaustive --writeup image-analysis.md
```

QR decoding is passive: URL, Wi-Fi, contact, OTP, JSON, encoded text, binary,
compressed, and image payloads are reported or decoded within limits, but are
never opened, joined, imported, fetched, or executed. Damaged QR codes and
stylized or low-quality OCR text are not guaranteed to decode.

Document scans are selected from signatures, package declarations, and members
rather than the filename. Extensionless or renamed DOCX, XLSX, PPTX, ODT, and
RTF inputs are still inspected. Use the active flag pattern normally:

```bash
dayi scan renamed-document.jpg --flag 'SiberVatan\{.*?\}' --writeup document.md
```

Document findings retain the package member and mechanism in terminal, JSON,
and Markdown attribution. Extracted local media can reach compatible metadata,
strings, image, OCR, and text-stego analysis. External relationships are only
reported; macros, field codes, embedded executables, and scripts are never run.
Word coverage retains hidden styles, comments, revisions, headers/footers, alt
text, metadata, media, and embedded objects from the earlier document core.
XLSX formulas and names, PowerPoint notes and hidden slides, ODF annotations and
hidden elements, and RTF hidden text/fields are inspected only as passive data.
The implementation is not rendering-equivalent and does not claim complete
Microsoft Office, LibreOffice, or legacy DOC/XLS/PPT compatibility.

| Document family | Content-based types | Bounded mechanisms |
|---|---|---|
| Word | DOCX, DOCM | Hidden runs/styles, revisions, comments, notes, properties, fields, media/objects |
| Spreadsheet | XLSX, XLSM | Hidden sheets/rows/columns, cells, comments, names, passive formulas, explicit styles, media/objects |
| Presentation | PPTX, PPTM | Hidden slides, notes/comments, off-slide/transparent text, alt text, explicit styles, media/objects |
| OpenDocument | ODT, ODS, ODP | Hidden elements/tables/pages, annotations, tracked text, metadata, explicit styles, media/objects |
| Rich Text | RTF | Hidden/color/size text, annotations, fields, escaped Unicode/code pages, pictures/objects |

```bash
dayi scan renamed-workbook.bin --flag 'SiberVatan\{.*?\}'
dayi scan extensionless-slides --verbose
dayi scan local-document.odt --writeup document.md
dayi scan suspicious.rtf --json report.json
```

**Full pipeline — everything at once:**

```bash
dayi scan challenge.jpg \
    --flag "CTF{.*?}" \
    --wordlist rockyou.txt \
    --timeout 120 \
    --threads 16 \
    --bf-limit 50000 \
    --writeup writeup.md \
    --ctfd-url https://ctf.example.com \
    --ctfd-token REDACTED_TOKEN \
    --challenge-id 42 \
    --webhook "https://discord.example.invalid/webhook-placeholder" \
    --output report \
    --format json \
    --log-file dayi.log \
    -v
```

**Argument order doesn't matter** — `parse_intermixed_args()` handles it:

```bash
dayi scan --flag "CTF{.*?}" --output rapor image.png   # file last — fine
dayi --flag "FLAG{.*?}" mystery.bmp --wordlist words.txt  # legacy — still fine
```

**All flags:**

```
Core:
  DOSYA                   Target file
  --flag/-f REGEX         Flag pattern. E.g. "CTF{.*?}"
  --wordlist/-w FILE      BF wordlist
  --require-wordlist      Fail before scanning if the wordlist cannot resolve
  --output/-o PATH        Report name (no extension). Default: dayi_rapor
  --format {txt,json}     Default: txt
  --timeout/-t N          Per-tool timeout in seconds. Default: 60
  --threads N             BF worker count. Default: 8
  --bf-limit N            Max BF attempts (0=unlimited). Default: 1000
  --workspace-dir PATH    Parent for the unique per-scan workspace
  --log-file FILE         Also write logs here
  -v/--verbose            Debug output

Integration (v2.0):
  --webhook URL           Discord webhook
  --ctfd-url URL          CTFd base URL
  --ctfd-token REDACTED_TOKEN
                           CTFd API token
  --challenge-id ID       Challenge ID for auto-submit
  --challenge-name NAME   Challenge name in Discord embed

Write-up (v3.0):
  --writeup FILE.md       Generate Markdown writeup after scan
  --ctfshit-path PATH     Explicit validated ctfshitcli checkout
```

By default, each scan gets a unique workspace under the operating system's
temporary directory. `--workspace-dir` changes only the parent; Dayı still
creates a unique `dayi_runner_*` child and never treats the parent itself as
managed output. Empty workspaces are removed. Workspaces containing useful
extractions are retained and their exact child path is recorded in TXT/JSON
reports. Treat every retained artifact as untrusted input.

---

### ⚙️ How it runs

```
┌──────────────────────────────────────────────────┐
│  Phases 1–4  (asyncio.gather — all at once)      │
│                                                  │
│  exiftool  exiv2  strings  binwalk                 │
│  pdf_scanner                                        │
│  ole_scanner  pcap_scanner  zsteg  lsb_py         │
│  chi_square                                      │
│  steghide  outguess                               │
│                                                  │
│  → flag found mid-gather? notify() fires now.    │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  Phase 4.5 — Archive post-processing             │
│  Office/ODF/RTF: bounded document + local objects │
│  ZIP: mini-list → streamed main list → safe scan │
│  Text stego: target + bounded extracted text      │
│  QR: target + extracted images (when available)   │
│  OCR: target + extracted images (when installed) │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  Phase 4.6 — Mini-wordlist BF                    │
│  Pulls tokens from phases 1+2 output             │
│  → Tries them against steghide + outguess        │
│  → Verified extraction skips Phase 5             │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  Phase 5 — Main wordlist BF                      │
│  stegseek first (C++, fast)                      │
│  → if stegseek fails: steghide_bf, outguess_bf   │
└──────────────────────────────────────────────────┘
                       ↓
              TXT / JSON / Markdown
```

---

### 🔗 Integration

Notifications are native Dayı functionality. At manager initialization Dayı
selects usable aiohttp when present, otherwise the stdlib urllib transport. The
selection is fixed for the scan: a failed request is never retried through the
other transport. CTFd and Discord are dispatched independently, so failure in
one channel neither repeats nor suppresses the other and never invalidates a
completed scan.

```
flag found
  │
  ▼
notify(flag, tool)   ← asyncio.create_task, returns immediately
  │
  ├─ usable aiohttp?  → native asynchronous HTTPS/HTTP POST
  └─ otherwise       → native urllib POST in a killable deadline worker
       ├─ CTFd result
       └─ Discord result (independent)
```

Configuration is selected field by field: explicit CLI value, then nonblank
environment value, then the default/disabled state.

| CLI option | Environment variable |
|---|---|
| `--ctfd-url` | `DAYI_CTFD_URL` |
| `--ctfd-token` | `DAYI_CTFD_TOKEN` |
| `--challenge-id` | `DAYI_CTFD_CHALLENGE_ID` |
| `--webhook` | `DAYI_DISCORD_WEBHOOK_URL` |
| `--challenge-name` | `DAYI_CHALLENGE_NAME` |
| `--ctfshit-path` | `DAYI_CTFSHIT_PATH` |

Use environment variables for tokens and webhook URLs where practical. CLI
arguments can be visible in process listings, shell history, and terminal logs.
The examples below use placeholders, not working credentials.

```bash
# 1. CTFd from environment only
export DAYI_CTFD_URL=https://ctf.example.com
export DAYI_CTFD_TOKEN=REDACTED_TOKEN
export DAYI_CTFD_CHALLENGE_ID=42
dayi scan challenge.jpg

# 2. Discord from environment only
export DAYI_DISCORD_WEBHOOK_URL=https://discord.example.invalid/webhook-placeholder
dayi scan challenge.jpg

# 3. Both channels together (uses the variables above)
dayi scan challenge.jpg --challenge-name "Example challenge"

# 4. One CLI value overrides only its corresponding environment value
dayi scan challenge.jpg --challenge-id 43

# 5. Rich writeup exporter from an explicit local checkout
export DAYI_CTFSHIT_PATH=../ctfshitcli
dayi scan challenge.jpg --writeup writeup.md

# 6. Network-free diagnostics in plain or schema-version-1 JSON
dayi doctor
dayi doctor --json
```

Discord webhook URLs require HTTPS. CTFd HTTP remains accepted for backward
compatibility, but HTTPS is recommended. URL userinfo, query strings, and
fragments are rejected; redirects are blocked; requests use bounded timeouts;
and CTFd response reads are bounded. The urllib fallback enforces its total
deadline in an isolated worker and reaps it on timeout. Doctor validates local configuration only:
it does not test endpoints, credentials, or reachability. Notification secrets
are not added to TXT, JSON, or Markdown reports.

**Write-up export:**

```python
# ctfshit present: creates a temp workspace, drops .challenge.json + notes.txt,
# calls export_writeups(), cleans up.
export_markdown_writeup(report, Path("writeup.md"))

# ctfshit absent: built-in fallback, same output path, zero deps.
```

---

### 🏗️ Project layout

```
DayiStegoSolver/
├── dayi/
│   ├── cli.py              # argparse entry point
│   ├── runner.py           # generic phase-aware plugin orchestrator
│   ├── scanner.py          # regex flag scanner
│   ├── reporter.py         # TXT + JSON + Markdown writeup
│   ├── persona.py          # Dayı voice, colors, banners
│   ├── integrations.py     # CTFd/Discord fire-and-forget
│   ├── text_stego.py       # bounded text detection and decoder engine
│   ├── image_analysis.py   # image magic, safety limits, OCR/QR finding models
│   ├── document/            # bounded Office/ODF/RTF detection and analysis
│   └── tools/
│       ├── _base.py        # subprocess wrapper, SIGTERM/SIGKILL, sanitizer
│       ├── _plugin.py      # plugin contract, validation, dynamic discovery
│       ├── text_stego_scanner.py # bounded core text-stego adapter
│       ├── document_stego_scanner.py # bounded document adapter
│       ├── lsb.py          # pure-Python PNG/BMP LSB (no zsteg dependency)
│       ├── chi_square.py   # bounded PNG/BMP PoV statistical analyzer
│       ├── ocr_scanner.py  # optional OCR for target and workspace images
│       ├── qr_scanner.py   # passive bounded QR backends and recursion
│       ├── pdf_scanner.py  # optional bounded PDF metadata/text forensics
│       ├── ole_scanner.py  # optional OLE/OpenXML VBA source forensics
│       ├── pcap_scanner.py # optional streaming PCAP/PCAPNG forensics
│       ├── zip_cracker.py  # safe stdlib ZipCrypto cracking
│       ├── steghide.py     # empty-pass + streaming BF
│       ├── outguess.py     # empty-pass + streaming BF
│       ├── binwalk.py      # extraction + protected-ZIP carving fallback
│       └── …               # exiftool, exiv2, strings, zsteg, stegseek
├── scripts/
│   └── run_private_regression.py # external-corpus, redacted local harness
├── ctfshitcli/             # optional validated child checkout for writeups
├── pyproject.toml
└── .gitignore
```

---

### 🧪 Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v

# Full local CI parity: tests, static checks, build, and archive validation
./scripts/check.sh

# No pytest? Quick sanity:
python -c "from dayi.cli import build_arg_parser; print('OK')"
dayi --help
```

#### Local private regression

The optional harness scans a user-selected corpus locally, one file at a time.
The corpus, manifest, and output must use absolute paths outside this repository;
inputs are never uploaded or copied into Git. Write summaries outside the corpus
and repository. Anonymization hides source basenames, and complete flags are
redacted by default:

```bash
export DAYI_PRIVATE_CORPUS=/absolute/path/outside/DayiStegoSolver
python scripts/run_private_regression.py \
  --input "$DAYI_PRIVATE_CORPUS" \
  --output /tmp/dayi-private-regression \
  --manifest /absolute/path/to/local-expectations.json \
  --timeout 180 --max-files 500 --anonymize --redact-flags
```

Use `--show-flags` only for an explicitly local report that may contain complete
challenge results. The harness disables notification configuration, discards
each full transient scan report, bounds report/summary sizes, and classifies
timeouts, parser failures, unsupported inputs, and missing tools separately.
Its exit code reports harness/configuration failure rather than the number of
unsolved files. Regression results depend entirely on the supplied corpus;
synthetic tests are required for code fixes and private challenge data must never
become a fixture. The Dayı 4.5.0 release candidate is prepared, but tagging and
publication remain separate steps.

---

### 🤝 Contributing

PRs welcome. A few rules:

1. New tool? Copy `dayi/tools/exiftool.py` as a template.
2. Export a non-empty `PLUGIN_SPECS` tuple containing validated `ToolPlugin` operations. The registry discovers public modules automatically; `runner.py` changes are not needed.
3. Choose the correct `PluginPhase`, priority, declared executable/Python requirements, and skip dependencies. Add a format guard with `get_file_type()` + `make_skipped_result()` where applicable.
4. Treat drop-in plugins as trusted local code: discovery imports each public module. Malformed plugins are skipped with a warning.
5. Code/comments/docstrings → English. `logger.info()` messages → Turkish, Dayı tone.

---

### 📄 License

MIT — do whatever you want with it.

---

---

## 🇹🇷 Türkçe Dokümantasyon

> **Güncel sürüm adayı:** 4.5.0. Ayrıntılar
> [değişiklik günlüğünde](CHANGELOG.md) ve
> [4.5.0 sürüm notlarında](RELEASE_NOTES_v4.5.0.md) yer alır. Etiketleme ve
> yayımlama ayrı sürüm adımlarıdır; burada tamamlandıkları iddia edilmez.

<div align="center">

### *"Hallederiz yeğenim." — CTF Steganografisinin Bilge Dayısı*

> [MacallanTheRoot](https://github.com/MacallanTheRoot) tarafından ☕ ve CTF gözyaşlarıyla geliştirildi.

</div>

---

### Dayı Nedir?

Şüpheli dosyayı Dayı'ya ver, geri adım at. Deterministik ve aşamalı 22 eklentili
pipeline'ı yönetir, yararlı içeriği regex'le tarar; flag bulursa — eğer
yapılandırdıysan — ikinci terminali açmadan CTFd'ye ve Discord'a haber uçurur.

Seninle bilge, nükteli bir Türk dayısı ağzıyla konuşur. Kodun kendisi sıkıcı derecede temiz.

---

### 🆕 Son yükseltmeler

| Yükseltme | Güncel davranış |
|---|---|
| **Çok aşamalı artifact tarayıcı** | HTTP/HTTPS bağlantılarını, doğrulanmış IP adreslerini, temkinli domain eşleşmelerini, kimlik bilgisi ipuçlarını, decimal/DMS koordinatlarını ve yazdırılabilir Base64 ipuçlarını pasif biçimde raporlar. Hiçbir bağlantıyı çekmez, çözümlemez veya takip etmez. |
| **Sınırlandırılmış metin steganografisi** | Metni uzantıdan değil baytlardan tanır; Bacon, whitespace, zero-width Unicode, homoglyph, akrostiş/yapısal, ghost-text ve iç içe kodlama adaylarını ağsız ve ek bağımlılıksız puanlar. |
| **Sınırlandırılmış belge steganografisi** | DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, ODT/ODS/ODP ve RTF içeriğini uzantıdan bağımsız tanır; açık gizleme işaretlerini, yorum/notları, metadata'yı, alt text'i, ilişkileri, medya/nesneleri ve temkinli stil kanallarını render etmeden inceler. |
| **Akıllı mini-wordlist decoder** | Yazdırılabilir Hex ve katı Base64 çözümlerini özgün token'larla birlikte sessizce ekler; adayları deterministik biçimde tekilleştirir ve sınırlar. |
| **ZIP carving ve şifre çözme** | Harici çıkarma başarısız olsa bile `binwalk` ham ZIP baytlarını ayrıca carve eder. Uzantısız ZIP'ler içerikten tanınır; önce mini-wordlist, sonra stream edilen ana wordlist denenir. |
| **Saf Python chi-square analizi** | Pillow/NumPy/SciPy olmadan sınırlandırılmış PNG scanline'larını ve sıkıştırılmamış BMP piksellerini çözer; LSB Pair-of-Values uniformity heuristic'ini raporlar. |
| **Dinamik eklenti registry'si** | `PLUGIN_SPECS` tanımlarını otomatik keşfeder, faz ve önceliğe göre sıralar; bozuk eklentileri taramayı çökertmeden atlar. |
| **İsteğe bağlı Rich terminal UI** | Rich ve interaktif TTY varsa tek bir canlı ekran üzerinden eklenti durumu, ilerleme, artifact panelleri ve flag tabloları gösterir. |
| **İsteğe bağlı gelişmiş OCR** | İçerikten tanınan PNG/JPEG/BMP/GIF/TIFF/WebP/PNM hedeflerinde ve çıkarılmış görsellerde sınırlandırılmış, deterministik çok geçişli OCR çalıştırır. |
| **İsteğe bağlı pasif QR** | `qr_scanner` sırasıyla OpenCV, pyzbar ve zbarimg kullanır; payload'ları yerelde sınıflandırır fakat URL veya komut açmaz/çalıştırmaz. |
| **İsteğe bağlı PDF forensics** | PDF metadata ve sayfa metnini pypdf ile inceler, boş parola ile açılan şifrelemeyi işler; flag ve pasif artifact'ları normal rapor/UI hattına aktarır. |
| **İsteğe bağlı OLE/makro forensics** | `oletools.olevba` ile OLE/OpenXML Office kaplarını tanır, sınırlandırılmış VBA kaynak modüllerini çıkarır; makroları flag, URL, credential ve kodlanmış ipucu için tarar. |
| **İsteğe bağlı PCAP forensics** | Scapy `PcapReader` ile PCAP/PCAPNG paketlerini RAM'e yığmadan stream eder; sınırlandırılmış Raw/ICMP payload'larını, DNS sorgularını ve TXT-benzeri resource data'yı, HTTP path/cookie/authorization alanlarını, flag ve pasif artifact'ları çıkarır. Tanınan PNG/JPEG/ZIP/PDF payload'larını yönetilen çalışma alanına carve eder. |

Güvenlik sıkılaştırmaları; kısa domain/IPv6 gürültüsünü, ZIP path traversal girişimlerini, symlink kaçışlarını, aşırı büyük arşiv üyelerini, decompression bomb'larını, büyük OCR/PDF/Office/PCAP girdilerini, aşırı PDF sayfa/metnini, VBA modül/kaynağını, paket/cleartext miktarını ve yinelenen çalışma alanı görsellerini de engeller. Metin stego en fazla 8 MiB inceler, 4 milyon decoded karakter işler, 64 KiB'lık en fazla 512 aday tutar, recursion'ı 3 derinlikle ve toplam decoded veriyi 16 MiB ile sınırlar; ANSI/bidi/kontrol verisini göstermeden önce escape eder. OpenXML/OpenDocument analizi paketleri 128 MiB, üye sayısını 5.000, tek açılmış üyeyi 32 MiB, toplam açılmış veriyi 256 MiB, XML üyelerini 16 MiB/200.000 node/256 derinlik, medyayı 100, gömülü nesneyi 50 ve recursion'ı 3 derinlikle sınırlar. RTF analizi 16 MiB girdi, 256 grup derinliği, 100.000 grup, 200.000 kontrol sözcüğü, 4 MiB metin, 32 MiB binary, 100 resim ve 50 nesne ile sınırlıdır. Makro, formül, field, gömülü executable ve harici ilişki çalıştırılmaz veya çekilmez. PCAP işlemi 128 MiB dosya, 50.000 stream edilen paket, 4 MiB tutulan metin, 50 carve edilen dosya ve carve başına 10 MiB ile sınırlıdır.

Doğrudan aktif regex ile bulunan flag'ler 64 KiB aday önizlemesinden ayrı,
64 eşleşme ve toplam 64 KiB flag metni sınırıyla korunur.

Görsel analizi kaynak başına 64 MiB, 50 milyon piksel, boyut başına 20.000
piksel ve beş frame ile sınırlıdır. Tarama en fazla 20 eşsiz görsel, görsel
başına 20 OCR varyantı/30 OCR çağrısı, toplam 200 OCR çağrısı ve çağrı başına 15
saniyeyi tek bir mutlak 90 saniyelik OCR eklenti süresi içinde kullanır. Görsel
boyutları OpenCV decode işleminden önce doğrulanır. QR analizi görsel başına 16
varyant/20 sembol, payload başına 1 MiB, recursion derinliği 2 ve toplam 32 MiB
recursive görsel verisi sınırını uygular. QR dönüşümleri tek tek üretilip
bırakılır; toplam üretim 150 milyon piksel ve tahmini 256 MiB dönüşüm işiyle
sınırlıdır. zbarimg fallback'i görsel başına bir ham binary payload'ı byte olarak
korur; ham newline çerçevesi çoklu binary sembollerde belirsiz olduğundan bu
durumda OpenCV veya pyzbar kullanılır. QR payload'ları pasiftir; OCR/QR kontrol
verileri escape edilir. Timeout'a duyarlı belge ve metin parser'ları
sonlandırılabilir spawn worker'larda çalışır ve süre dolduğunda reap edilir.

#### İsteğe bağlı Auto-Forensics modülleri

| Modül | Eklenti | Faz | İsteğe bağlı runtime | Kapsam |
|---|---|---:|---|---|
| **Modül 7 — OCR** | `ocr_scanner` | Arşiv, öncelik 20 | `Pillow`, `pytesseract`, sistem Tesseract | Sınırlandırılmış preprocessing/PSM, dil seçimi, consensus ve iç içe metin çözme. |
| **Modül 8 — PDF** | `pdf_scanner` | Eşzamanlı, öncelik 45 | `pypdf>=4.0.0` | PDF metadata ve sınırlandırılmış sayfa metnini, boş parola ile açılan belgeler dahil tarar. |
| **Modül 9 — OLE/Makro** | `ole_scanner` | Eşzamanlı, öncelik 46 | `oletools>=0.60.1` | Desteklenen OLE/OpenXML Office kaplarından sınırlandırılmış VBA kaynağı çıkarır. |
| **Modül 10 — PCAP** | `pcap_scanner` | Eşzamanlı, öncelik 47 | `scapy>=2.5.0` | PCAP/PCAPNG stream eder, Raw/ICMP/DNS/HTTP verisini inceler ve gömülü PNG/JPEG/ZIP/PDF payload'larını güvenle carve eder. |
| **Modül 11 — Belgeler** | `document_stego_scanner` | Arşiv, öncelik 5 | Çekirdek Python | Word, elektronik tablo, sunum, OpenDocument ve RTF yapısını sınırlar içinde inceler; isteğe bağlı `oletools` DOCM/XLSM/PPTM makro incelemesini zenginleştirir. |
| **Modül 12 — QR** | `qr_scanner` | Arşiv, öncelik 15 | İsteğe bağlı OpenCV, pyzbar/zbar veya zbarimg | OCR'dan önce QR payload'larını pasif ve sınırlandırılmış biçimde çözer. |

İsteğe bağlı modüller runtime bulunmadığında temizce atlanır; belge çekirdeği
sıfır-bağımlılıklı varsayılan kurulumda kullanılabilir kalır.

---

### ✨ Özellikler

| | Özellik | Ne yapar |
|---|---|---|
| ⚡ | **Eşzamanlı çalışma** | `asyncio.gather()` toplam 22 kayıtlı eklentili pipeline'ın `CONCURRENT` aşamasındaki 12 eklenti işlemini birlikte çalıştırır. Eski sıralı yapıya göre ~%75 hız kazancı. |
| 🔌 | **Drop-in eklentiler** | `dayi/tools/` altındaki açık modüller `PLUGIN_SPECS` ile kendini kaydeder; runner değişmez. |
| 🎨 | **İsteğe bağlı Rich UI** | `.[ui]` tek bir canlı ekran, ilerleme çubukları, uyarı panelleri ve flag tabloları ekler; TTY dışı ve sıfır-bağımlılık kurulumu düz kalır. |
| 👁️ | **İsteğe bağlı OCR** | `.[ocr]` hedefteki ve çalışma alanına çıkarılmış görsellerdeki görünür yazıları okur; çekirdek bağımlılıksız kalır. |
| ▣ | **Pasif QR analizi** | `.[qr]` tercih edilen OpenCV backend'ini kurar; pyzbar/zbar ve zbarimg alternatifleri de algılanır. |
| 📄 | **İsteğe bağlı PDF forensics** | `.[pdf]` sınırlandırılmış metadata/sayfa metni çıkarır ve boş parola ile açılan PDF'leri dener; PDF olmayan hedefi hemen atlar. |
| 📎 | **İsteğe bağlı OLE/makro forensics** | `.[ole]` eski OLE ve ZIP tabanlı OpenXML Office belgelerinden sınırlandırılmış VBA kaynağı çıkarır. |
| 🌐 | **İsteğe bağlı PCAP forensics** | `.[pcap]` PCAP/PCAPNG paketlerini stream eder; Raw/ICMP/DNS/HTTP verisini inceler ve tanınan PNG/JPEG/ZIP/PDF payload'larını güvenle carve eder. |
| 🔤 | **Çekirdek metin steganografisi** | `text_stego_scanner` bayttan tanınan UTF/ASCII metinde sınırlandırılmış Bacon, whitespace, görünmez Unicode, homoglyph, yapısal, ghost-text ve iç içe kodlamaları inceler. |
| 📚 | **Çekirdek belge steganografisi** | `document_stego_scanner` desteklenen Office OpenXML, OpenDocument ve RTF içeriğini sabit yerel sınırlar altında inceler. |
| 🧭 | **Pasif artifact tespiti** | Bağlantı, IP, domain, kimlik bilgisi ipucu, koordinat ve doğrulanmış Base64 önizlemelerini ağa çıkmadan raporlar. |
| 🔐 | **Güvenli arşiv kurtarma** | Uzantısız ZIP'leri carve eder, önce bağlamsal şifreleri dener; traversal ve çıkarma boyutu sınırlarını uygular. |
| 🔓 | **Akıllı token çözme** | Yazdırılabilir Hex ve katı Base64 çözümlerini sınırlandırılmış bağlamsal şifre havuzuna ekler. |
| 🧠 | **Akıllı yönlendirme** | İlk 16 byte'ı okur. JPEG → zsteg yok. PNG → steghide yok. Boşuna fork yok. |
| 🔔 | **Erken bildirim** | exiftool flag buldu, binwalk hâlâ çalışıyor? CTFd anında haberdar olur. |
| 🔍 | **Mini-wordlist BF** | Metadata çıktısından aday şifreler toplar, rockyou'ya girmeden önce dener. |
| 📊 | **Chi-square LSB testi** | PNG/BMP renk kanallarında PoV dağılımını ölçer; p-value tabanlı skor bir heuristic'tir, kesin stego kanıtı değildir. |
| 📝 | **Otomatik write-up** | Markdown çözüm belgesi üretir. ctfshit varsa onun exporter'ını kullanır, yoksa kendisi yapar. |
| 🧹 | **Zombie-safe subprocess** | SIGTERM → 2s → SIGKILL → `wait_for(5s)`. Takılı process bırakmaz. |
| 🔒 | **OOM koruması** | rockyou.txt satır satır stream edilir. 134MB RAM'e hiç yüklenmez. |
| 🛡️ | **Token temizleme** | Null-byte ve kontrol karakterlerini steghide argümanlarına gitmeden önce siler. |
| 🧩 | **ctfshit writeup entegrasyonu** | Zengin Markdown için isteğe bağlı `csl-ctfshitcli` exporter'ını kullanır; yerleşik Markdown fallback her zaman hazırdır. |
| 🔄 | **Yerel bildirim transport'u** | Kullanılabilir aiohttp'yu bir kez seçer, yoksa stdlib urllib kullanır; CTFd ve Discord bağımsızdır. |
| 🗂️ | **Flag attribution** | Raporda `CTF{flag} ← bulan: exiftool, binwalk` yazar. |
| ⌨️ | **Ctrl+C güvenli** | İstediğin zaman dur. Kısmi sonuçlar yazılır. Veri kaybolmaz. |

---

### 📦 Kurulum

Depoya erişimi olan kullanıcılar için:

```bash
git clone https://github.com/MacallanTheRoot/DayiStegoSolver.git
cd DayiStegoSolver

python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Rich spinner, progress bar, panel ve sonuç tabloları (isteğe bağlı)
pip install -e ".[ui]"

# Hedef ve çıkarılmış görsellerde görünür yazı OCR'ı (isteğe bağlı)
pip install -e ".[ocr]"

# Tercih edilen pasif QR backend'i (isteğe bağlı)
pip install -e ".[qr]"

# PDF metadata ve sayfa metni forensics (isteğe bağlı)
pip install -e ".[pdf]"

# OLE/OpenXML VBA makro forensics (isteğe bağlı)
pip install -e ".[ole]"

# Stream edilen PCAP/PCAPNG ağ forensics (isteğe bağlı)
pip install -e ".[pcap]"

# Tercih edilen yerel CTFd/Discord transport'u (stdlib urllib her zaman hazır)
pip install -e ".[integration]"

dayi doctor
```

`dayi doctor`, hedef taramadan veya ağ isteği yapmadan çekirdek Python/paket
sağlığını, bilinen harici araçları ve isteğe bağlı Python kabiliyetlerini
denetler. Harici araçlar format-özel ve isteğe bağlıdır; eksik olmaları temel
kullanımı engellemez. Çekirdek CLI kullanılabiliyorsa isteğe bağlı eksiklerde
bile çıkış kodu `0`, çekirdek kurulum sağlıksızsa `1` olur. CI ve scriptler için
`dayi doctor --json` kullanın. Yerel bildirim tanısı seçilecek aiohttp/urllib
transport'unu ve güvenli CTFd/Discord yapılandırma durumlarını gösterir; endpoint
veya credential testi yapmaz ve değerleri yazdırmaz. Ayrıca hedef görseli
açmadan yerel OCR/Tesseract dil kabiliyetini ve seçilen pasif QR backend'ini
raporlar.

**Sistem araçları (Kali / Debian / Ubuntu):**

```bash
sudo apt install -y libimage-exiftool-perl exiv2 binutils binwalk steghide outguess
sudo gem install zsteg

# Yalnızca isteğe bağlı OCR extra'sı kullanılırken gerekir
sudo apt install -y tesseract-ocr
# stegseek: https://github.com/RickdeJager/stegseek/releases
```

**ctfshit zengin writeup export'u (isteğe bağlı):**

```bash
export DAYI_CTFSHIT_PATH=../ctfshitcli
# Alternatif: python -m pip install -e ../ctfshitcli
```

Resolver önce `--ctfshit-path` veya `DAYI_CTFSHIT_PATH`, sonra kurulu
`csl-ctfshitcli` dağıtımı, ardından doğrulanmış doğrudan kardeş/çocuk
`ctfshitcli` (ve eski `ctfshit`) checkout'larını dener. Bu entegrasyon yalnızca
zengin Markdown writeup içindir; CTFd ve Discord bundan bağımsızdır. Bulunamazsa
yerleşik Markdown fallback yine çıktı üretir.

---

### 🚀 Kullanım

```bash
# Tercih edilen: yerleşik yaygın flag desenleri
dayi scan foto.jpg

# Challenge formatı biliniyorsa yalnızca bu özel deseni kullan
dayi scan foto.jpg --flag "CTF{.*?}"

# Uzantıdan bağımsız metin stego ve challenge'a özel prefix
dayi scan gizli.data --flag 'SiberVatan\{.*?\}' -v

# Wordlist ile (stream edilir, OOM yok)
dayi scan stego.jpg --flag "picoCTF{.*?}" --wordlist /usr/share/wordlists/rockyou.txt

# Kullanılabilir wordlist yoksa taramadan önce hata ver
dayi scan stego.jpg --wordlist rockyou.txt --require-wordlist

# JSON rapor, detaylı
dayi scan mystery.png -v --output rapor --format json

# Benzersiz tarama çalışma alanını seçilen üst dizinde oluştur
dayi scan mystery.png --workspace-dir /guvenli/calisma-alanlari
```

`--flag` verilmezse muhafazakâr yerleşik eşleştirici yalnızca `CTF`, `FLAG`,
`HTB`, `picoCTF` ve `THM` süslü parantez biçimlerini tanır. Özel challenge
öneklerini kaçırabileceği için beklenen format biliniyorsa `--flag` kullanmak
önerilir. Tarama seçenekleri için `dayi scan --help` çalıştırın. Eski
`dayi DOSYA` ve `dayi DOSYA --flag REGEX` biçimleri aynı tarama yoluyla
desteklenmeye devam eder. Adı doğrudan `scan` olan hedef için
`dayi scan -- scan` veya `./scan` gibi açık bir yol kullanın.

`--wordlist rockyou.txt` düz adı için Dayı yalnızca verilen yolu, mevcut
dizini, `/usr/share/wordlists/rockyou.txt` ve
`/usr/share/wordlists/rockyou.txt.gz` yollarını bu sırayla dener. Gzip wordlist
diske açılmadan stream edilir. Hiçbiri bulunamazsa tarama degraded modda sürer
ve devre dışı kalan ana Steghide/OutGuess brute-force fazlarını bildirir.
Taramadan önce hata vermek için `--require-wordlist` ekleyin. Başka bir ad
verildiğinde ilgisiz bir wordlist sessizce kullanılmaz.

OutGuess çıktısı ancak sınırlı içerik doğrulamasından sonra bulunan şifre
sayılır. Tek başına sıfır dönüş kodu veya çıktı dosyasının oluşması mini
brute-force fazını başarılı yapamaz ve sonraki fallback eklentilerini
engelleyemez. Domain benzeri artifact'lar DNS veya ağ erişimi olmadan güven
seviyesine ayrılır: normal çıktıda confirmed ve probable, `--verbose` modunda
possible sonuçlar gösterilir; noise gizli kalır.

Hedef gerektirmeyen kurulum tanısı:

```bash
dayi doctor
dayi doctor --json
```

Doctor ağ isteği yapmaz. Eksik harici araçlar veya isteğe bağlı Python
modülleri çekirdek kullanılabildiği sürece degraded sonuç verir ve `0` ile
çıkar.
Yerleşik metin ve belge steganografi kabiliyetlerini de hedef dosyayı
açmadan veya taramadan raporlar. Belge kabiliyeti yerel ve ağsızdır; isteğe
bağlı DOCM makro-kaynak incelemesi için `oletools` ayrıca raporlanır.

Gerçek dinamik registry'yi tarama çalıştırmadan inceleyin:

```bash
dayi plugins list
dayi plugins list --json
```

`available`, bildirilen statik runtime bağımlılıklarının hazır olduğunu;
`unavailable`, bildirilen executable veya Python modülünün eksik olduğunu;
`conditional` ise tarama girdisi ya da faz/eklenti sonucunun gerektiğini
gösterir. Listeleme yalnızca `dayi.tools` içindeki güvenilir paket modüllerini
import eder; rastgele eklenti dizini yüklemez, runner veya harici binary
çalıştırmaz ve ağa çıkmaz. Keşif sorunları ile isteğe bağlı araç eksikleri çıkış
kodu `0` ile raporlanabilir; JSON çıktısı script ve CI kullanımı içindir.
Bu sürüm adayındaki registry 22 eklenti içerir. Arşiv işlemleri sırasıyla
önceliği 5 olan `document_stego_scanner`, 10 olan ZIP kurtarma, 12 olan çekirdek
`text_stego_scanner`, 15 olan `qr_scanner` ve 20 olan `ocr_scanner` ile ilerler.
Böylece sınırlandırılmış carve/belge metinleri görsel taramalarından önce
text-stego decoder'ına ulaşır; yeni bir eklenti eklenmez.

OCR heuristic bir analizdir. Kurulu Tesseract dillerini `--ocr-lang eng+tur`
ile seçebilir, daha yavaş fakat yine sınırlandırılmış işleme turunu
`--ocr-exhaustive` ile açabilirsiniz. QR analizi URL, Wi-Fi, kişi, OTP, JSON,
kodlanmış metin, binary, sıkıştırılmış ve görsel payload'ları yalnızca pasif
olarak raporlar veya çözer; hiçbir URL'yi açmaz, ağa bağlanmaz ve komut
çalıştırmaz. Hasarlı QR veya stilize/düşük kaliteli OCR metninin çözüleceği
garanti edilmez.

Belge taraması dosya adına değil imza, paket bildirimi ve üyelere göre seçilir.
Uzantısız veya yeniden adlandırılmış DOCX, XLSX, PPTX, ODT ve RTF girdileri yine
incelenir. Etkin flag desenini normal biçimde kullanın:

```bash
dayi scan yeniden-adlandirilmis-belge.jpg --flag 'SiberVatan\{.*?\}' --writeup belge.md
```

Belge bulguları terminal, JSON ve Markdown'da paket üyesi ile gizleme
mekanizmasını korur. Çıkarılmış yerel medya; uyumlu metadata, strings, görsel,
OCR ve text-stego analizine ulaşabilir. Harici ilişkiler yalnızca raporlanır;
makrolar, field code'lar, gömülü executable'lar ve scriptler çalıştırılmaz.
Önceki belge çekirdeğinin Word gizli stilleri, yorumları, revizyonları,
header/footer, alt text, metadata, medya ve gömülü nesne kapsamı korunur.
XLSX formül/adları, PowerPoint notları ve gizli slaytları, ODF annotation/gizli
öğeleri ile RTF gizli metin/field içerikleri yalnızca pasif veri olarak
incelenir. Uygulama render ile eşdeğer değildir; eksiksiz Microsoft Office,
LibreOffice veya eski DOC/XLS/PPT uyumluluğu iddia etmez.

| Belge ailesi | İçerikten tanınan türler | Sınırlandırılmış mekanizmalar |
|---|---|---|
| Word | DOCX, DOCM | Gizli run/stiller, revizyon, yorum, not, özellik, field, medya/nesne |
| Elektronik tablo | XLSX, XLSM | Gizli sheet/satır/sütun, hücre, yorum, ad, pasif formül, açık stil, medya/nesne |
| Sunum | PPTX, PPTM | Gizli slayt, not/yorum, slayt dışı/transparan metin, alt text, açık stil, medya/nesne |
| OpenDocument | ODT, ODS, ODP | Gizli öğe/tablo/sayfa, annotation, değişiklik, metadata, açık stil, medya/nesne |
| Zengin metin | RTF | Gizli/renk/boyut metni, annotation, field, Unicode/code page escape, resim/nesne |

```bash
dayi scan yeniden-adlandirilmis-calisma-kitabi.bin --flag 'SiberVatan\{.*?\}'
dayi scan uzantisiz-sunum --verbose
dayi scan yerel-belge.odt --writeup belge.md
dayi scan supheli.rtf --json rapor.json
```

**Tam pipeline:**

```bash
dayi scan challenge.jpg \
    --flag "CTF{.*?}" \
    --wordlist rockyou.txt \
    --timeout 120 \
    --threads 16 \
    --bf-limit 50000 \
    --writeup cozum.md \
    --ctfd-url https://ctf.example.com \
    --ctfd-token REDACTED_TOKEN \
    --challenge-id 42 \
    --webhook "https://discord.example.invalid/webhook-placeholder" \
    --output rapor \
    --format json \
    -v
```

Varsayılan olarak her tarama için işletim sisteminin geçici dizini altında
benzersiz bir çalışma alanı oluşturulur. `--workspace-dir` yalnızca üst dizini
değiştirir; Dayı yine benzersiz bir `dayi_runner_*` alt dizini oluşturur ve üst
dizini yönetilen çıktı saymaz. Boş çalışma alanları temizlenir. Faydalı çıkarım
içerenler korunur ve tam alt dizin yolu TXT/JSON raporuna yazılır. Korunan tüm
artifact'ları güvenilmeyen girdi olarak değerlendirin.

---

### ⚙️ Çalışma sırası

```
Faz 1–4 (asyncio.gather — hepsi aynı anda):
  exiftool  exiv2  strings  binwalk  pdf_scanner
  ole_scanner  pcap_scanner
  zsteg     lsb_py  chi_square
  steghide_empty    outguess_empty
  → Flag bulunur bulunmaz notify() tetiklenir.

Faz 4.5 — Arşiv son işlemleri:
  Office/ODF/RTF: sınırlı belge + yerel medya/nesne incelemesi
  ZIP: mini-wordlist → stream edilen ana wordlist → güvenli tarama
  Text stego: hedef + sınırlandırılmış çıkarılmış metinler
  QR: hedef + çıkarılmış görseller (backend varsa)
  OCR: hedef + çıkarılmış görseller (kuruluysa)

Faz 4.6 — Mini-wordlist BF:
  Metadata çıktısından token topla → steghide/outguess'e ver
  → Doğrulanmış çıkarım bulunursa Faz 5 atlanır.

Faz 5 — Ana wordlist BF:
  stegseek (C++, hızlı) → başarısız olursa → steghide_bf, outguess_bf

Son: TXT / JSON rapor + --writeup verilmişse Markdown
```

---

### 🔗 Entegrasyon — CTFd & Discord

Bildirimler Dayı'nın yerel özelliğidir. Manager oluşturulurken kullanılabilir
aiohttp varsa bir kez seçilir; yoksa stdlib urllib kullanılır. Tarama boyunca
transport değişmez ve başarısız istek diğer transport ile tekrar gönderilmez.
CTFd ile Discord bağımsız çalışır: birinin hatası diğerini tekrarlamaz veya
engellemez ve tamamlanmış taramanın çıkış kodunu değiştirmez.

Her alan için öncelik ayrı uygulanır: açık CLI değeri → boş olmayan ortam
değişkeni → varsayılan/devre dışı durum.

| CLI seçeneği | Ortam değişkeni |
|---|---|
| `--ctfd-url` | `DAYI_CTFD_URL` |
| `--ctfd-token` | `DAYI_CTFD_TOKEN` |
| `--challenge-id` | `DAYI_CTFD_CHALLENGE_ID` |
| `--webhook` | `DAYI_DISCORD_WEBHOOK_URL` |
| `--challenge-name` | `DAYI_CHALLENGE_NAME` |
| `--ctfshit-path` | `DAYI_CTFSHIT_PATH` |

Token ve webhook URL'leri için mümkün olduğunda ortam değişkenlerini kullanın.
CLI argümanları process listelerinde, shell history'de ve terminal loglarında
görünebilir. Aşağıdaki değerler çalışan credential değil, yer tutucudur.

```bash
# 1. Yalnızca ortam değişkenleriyle CTFd
export DAYI_CTFD_URL=https://ctf.example.com
export DAYI_CTFD_TOKEN=REDACTED_TOKEN
export DAYI_CTFD_CHALLENGE_ID=42
dayi scan challenge.jpg

# 2. Yalnızca ortam değişkeniyle Discord
export DAYI_DISCORD_WEBHOOK_URL=https://discord.example.invalid/webhook-placeholder
dayi scan challenge.jpg

# 3. Yukarıdaki değerlerle iki kanal birlikte
dayi scan challenge.jpg --challenge-name "Örnek challenge"

# 4. CLI yalnızca ilgili ortam alanını ezer
dayi scan challenge.jpg --challenge-id 43

# 5. Yerel checkout ile zengin writeup exporter
export DAYI_CTFSHIT_PATH=../ctfshitcli
dayi scan challenge.jpg --writeup cozum.md

# 6. Ağsız düz ve schema-version-1 JSON tanısı
dayi doctor
dayi doctor --json
```

Discord webhook URL'si HTTPS gerektirir. CTFd HTTP yalnızca geriye uyumluluk
için kabul edilir; HTTPS önerilir. URL userinfo, query string ve fragment
alanları reddedilir; redirect'ler engellenir; istek timeout'ları ve CTFd cevap
okumaları sınırlıdır. Urllib fallback'i toplam deadline'ı izole bir worker'da
uygular ve timeout'ta worker'ı sonlandırıp reap eder. Doctor yalnızca yerel yapılandırmayı doğrular; endpoint,
credential veya erişilebilirlik testi yapmaz. Bildirim sırları TXT, JSON veya
Markdown raporlarına eklenmez.

---

### 📝 Otomatik write-up

```bash
dayi stego.png --flag "CTF{.*?}" --writeup cozum.md
# ctfshit varsa: kategori gruplu, timestamp'li zengin Markdown
# ctfshit yoksa: yerleşik fallback, sıfır bağımlılık — yine de dosya üretilir
```

### Yerel özel regresyon

İsteğe bağlı harness, kullanıcının seçtiği corpus'u tamamen yerelde ve dosya
dosya tarar. Corpus, manifest ve çıktı mutlak yolları bu repository'nin dışında
olmalıdır; girdiler yüklenmez veya Git'e kopyalanmaz. Özetleri corpus ve
repository dışında yazın. `--anonymize` kaynak dosya adlarını gizler; tam flag
değerleri varsayılan olarak redacted tutulur:

```bash
export DAYI_PRIVATE_CORPUS=/repository/disinda/mutlak/corpus/yolu
python scripts/run_private_regression.py \
  --input "$DAYI_PRIVATE_CORPUS" \
  --output /tmp/dayi-private-regression \
  --manifest /repository/disinda/yerel-beklenti.json \
  --timeout 180 --max-files 500 --anonymize --redact-flags
```

Tam flag'ler yalnızca açıkça yerel bir rapor için `--show-flags` ile gösterilir.
Harness bildirim yapılandırmasını devre dışı bırakır, her tam geçici tarama
raporunu siler, rapor/özet boyutlarını sınırlar ve timeout, parser hatası,
unsupported girdi ile eksik aracı ayrı sınıflandırır. Çıkış kodu çözülmeyen dosya
sayısını değil harness/yapılandırma hatasını gösterir. Sonuçlar tamamen sağlanan
corpus'a bağlıdır; kod düzeltmeleri sentetik testlerle yeniden üretilmeli ve özel
challenge verisi fixture yapılmamalıdır. Dayı 4.5.0 sürüm adayı hazırlanmıştır;
etiketleme ve yayımlama ayrı adımlardır.

---

### 🤝 Katkı

CI ile aynı test, statik kontrol, paket build ve arşiv doğrulama zincirini yerelde
çalıştırmak için geliştirme extra'sını kurup `./scripts/check.sh` komutunu kullanın.

PR'lar bekliyorum. Kurallar basit:

1. Yeni araç → `dayi/tools/exiftool.py`'yi template al.
2. Doğrulanabilir `ToolPlugin` işlemlerinden oluşan boş olmayan bir `PLUGIN_SPECS` tuple'ı dışa aktar. Registry modülü otomatik keşfeder; `runner.py` değişmez.
3. Doğru `PluginPhase`, öncelik, bildirilen executable/Python gereksinimleri ve atlama bağımlılıklarını seç. Uygun araçlarda `get_file_type()` ile format kontrolü ekle.
4. Drop-in eklentileri güvenilir yerel kod kabul et: keşif sırasında modüller import edilir. Bozuk eklenti uyarıyla atlanır.
5. Kod/yorum → İngilizce. `logger.info()` mesajları → Türkçe, Dayı tonu.

---

### 📄 Lisans

MIT — istediğin gibi kullan.

---

<div align="center">

*"Nasıl mı yaptım? Dayı halleder yeğenim, sormaya gerek yok."*

**⭐ Beğendiysen yıldızla. Dayı mutlu olur.**

</div>
