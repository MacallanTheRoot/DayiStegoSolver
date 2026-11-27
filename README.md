<div align="center">

# 🕵️ Dayı Stego Solver

### Automated steganography and file-forensics triage for CTFs

**Give Dayı a suspicious file. It identifies the format, routes it through a bounded 22-plugin pipeline, extracts artifacts, looks for flags, and writes a report.**

[![Python 3.10–3.13](https://img.shields.io/badge/Python-3.10%E2%80%933.13-3776AB?logo=python&logoColor=white)](https://python.org)
[![CI](https://github.com/MacallanTheRoot/DayiStegoSolver/actions/workflows/ci.yml/badge.svg)](https://github.com/MacallanTheRoot/DayiStegoSolver/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MacallanTheRoot/DayiStegoSolver)](https://github.com/MacallanTheRoot/DayiStegoSolver/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Core Dependencies](https://img.shields.io/badge/Core%20Dependencies-stdlib-brightgreen)](pyproject.toml)

**English** · [Türkçe](#-türkçe-dokümantasyon)

[Latest release](https://github.com/MacallanTheRoot/DayiStegoSolver/releases/latest) ·
[Installation](#installation) ·
[Quick start](#quick-start) ·
[Supported analysis](#what-it-analyzes) ·
[Security model](#security-model)

*"Hallederiz yeğenim."*

</div>

---

## English Documentation

## Why Dayı?

Steganography challenges often require manually trying several unrelated tools:

```text
file → exiftool → strings → binwalk → zsteg → steghide → stegseek → OCR → custom scripts
```

Dayı coordinates that workflow from one CLI while keeping analysis local, bounded, and deterministic.

```bash
dayi scan challenge.png
```

It can:

- detect the real file type from content instead of trusting the extension;
- run only relevant tools and built-in analyzers;
- inspect image, text, archive, document, PDF, OLE/macro, QR, and PCAP evidence;
- decode nested text and collect contextual password candidates;
- attribute discovered flags to the plugin that found them;
- write a Markdown report;
- optionally notify CTFd or Discord.

> Dayı is a triage and automation tool, not a guarantee that every challenge will be solved automatically.

---

## Installation

### Core installation

```bash
git clone https://github.com/MacallanTheRoot/DayiStegoSolver.git
cd DayiStegoSolver

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .

dayi --version
dayi doctor
```

The core package uses the Python standard library and remains usable when optional tools are missing.

### Recommended optional Python features

```bash
python -m pip install -e ".[ui,ocr,qr,pdf,ole,pcap,integration]"
```

### Recommended system tools on Kali, Debian, or Ubuntu

```bash
sudo apt update
sudo apt install -y \
  libimage-exiftool-perl \
  exiv2 \
  binutils \
  binwalk \
  steghide \
  outguess \
  tesseract-ocr

sudo gem install zsteg
```

Install StegSeek from its official releases:

```bash
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_linux.deb
sudo dpkg -i stegseek_linux.deb
```

Check the environment:

```bash
dayi doctor
dayi plugins list
```

---

## Quick start

```bash
# Built-in common flag patterns
dayi scan challenge.png

# Challenge-specific flag expression
dayi scan challenge.jpg --flag 'CTF\{.*?\}'

# Extensionless or misleading file
dayi scan hidden.data --flag 'SiberVatan\{.*?\}' -v

# Keep scanning after the first flag (unreleased, see "Early stop and full scan")
dayi scan challenge.png --full-scan

# Health and plugin diagnostics
dayi doctor
dayi plugins list
```

---

## What it analyzes

| Area | Coverage |
|---|---|
| **Images** | JPEG, PNG, BMP, GIF, TIFF, WebP, PNM; metadata, strings, embedded files, LSB-oriented analysis, OCR, and QR |
| **Text steganography** | Bacon, whitespace, zero-width Unicode, homoglyphs, acrostic and structural channels, ghost text, Hex/Base64 nesting |
| **Documents** | DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, ODT/ODS/ODP, and RTF concealment, metadata, comments, relationships, media, and embedded objects |
| **Archives** | ZIP discovery, bounded extraction, extensionless ZIP carving, contextual password attempts, streamed wordlists |
| **PDF** | Metadata, bounded page text, empty-password encrypted documents, flags, and passive artifacts |
| **OLE and macros** | Bounded VBA source extraction from supported OLE and OpenXML containers |
| **PCAP/PCAPNG** | Streamed Raw, ICMP, DNS, HTTP, flags, passive artifacts, and bounded carving of recognized payloads |
| **Passive artifacts** | URLs, IP addresses, conservative domains, credential hints, coordinates, and printable encoded hints |

### Registered pipeline

Dayı 4.5.2 ships with:

- **22 registered plugins**
- **12 concurrent-phase operations**
- dynamic plugin discovery and validation
- clean degradation when optional runtimes are unavailable

Common integrations:

```text
exiftool · exiv2 · strings · binwalk · zsteg · steghide
stegseek · outguess · Tesseract · OpenCV/pyzbar/zbarimg
pypdf · oletools · Scapy
```

### Advanced local analysis

The core `text_stego_scanner` works from detected text rather than filename
extensions. It scores zero-width Unicode, letter-case binary ASCII,
whitespace/SNOW, Bacon-style, homoglyph, acrostic/structural, ghost-text, and
nested Hex/Base64 candidates. Findings keep their plugin and decoder-chain
attribution. Analysis runs without network access; decoded content is data and
is never executed. ANSI/bidi/control characters are escaped before display.

Text analysis accepts at most **8 MiB** of source data, examines at most **4
million** decoded characters, retains at most **512 candidates**, limits each
candidate output to **64 KiB**, follows nested decoding to **depth 3**, and caps
aggregate decoded data at **16 MiB**.

Document analysis covers PDF, OpenXML/Office packages (DOCX/DOCM, XLSX/XLSM,
PPTX/PPTM), OLE/legacy documents when the optional parser supports them,
OpenDocument (ODT/ODS/ODP), RTF, and plain text routed to the appropriate local
analyzer. The `document_stego_scanner` inspects hidden styles, comments,
revisions, headers/footers, alt text, metadata, relationships, media, and
embedded objects. External relationships are reported only; macros, formulas,
fields, scripts, and embedded executables are never run or fetched.

OpenXML processing caps packages at **128 MiB**, members at **5,000**, each
member at **32 MiB**, aggregate uncompressed data at **256 MiB**, and each XML
member at **16 MiB**. Extraction caps media at **100**, embedded objects at
**50**, and recursive document traversal at **depth 3**. Results retain package
member and mechanism attribution. These analyzers are heuristic and
format/corpus dependent; they do not claim complete rendering or legacy-format
compatibility.

### OCR and QR controls

Use `--ocr-lang` to select installed Tesseract languages and
`--ocr-exhaustive` for the slower bounded preprocessing schedule. OCR remains
heuristic: stylized, damaged, or low-contrast text may not decode. The schedule
accepts at most 20 source images, 20 variants and 30 invocations per image, and
**200 OCR invocations** overall. Each invocation is limited to **15 seconds**
and 1 MiB of text; aggregate OCR text is capped at 8 MiB. A source image is
limited to 64 MiB and 50 million decoded pixels. Large exhaustive inputs may
need a plugin timeout of 60 seconds or more, for example `--timeout 60`.

The passive `qr_scanner` uses OpenCV, pyzbar, and zbarimg backends when
available. Decoded QR URLs, commands, archives, and embedded data are reported
or analyzed within existing limits but are never opened, fetched, or executed.
The registered pipeline remains **22 registered plugins**, including **12
concurrent plugins**.

---

## Example workflow

```text
[+] Target type: PNG
[+] Running relevant metadata, archive, LSB, QR, and OCR analysis
[+] Extracted printable Base64 candidate
[+] Decoded nested text
[FLAG] CTF{example_flag}
[+] Found by: strings, text_stego_scanner
[+] Markdown report written
```

Actual output depends on installed optional tools and the analyzed challenge.

---

## Design principles

- **Content-based routing:** file signatures are preferred over filename extensions.
- **Bounded execution:** parsers, archives, OCR, documents, packets, recursion, and subprocesses have explicit limits.
- **Passive by default:** discovered URLs and commands are reported, not opened or executed.
- **No active document content:** macros, formulas, fields, embedded executables, and external relationships are never executed or fetched.
- **Deterministic reporting:** plugin order, attribution, and JSON-capable diagnostics support repeatable runs.
- **Graceful degradation:** missing optional tools reduce coverage without breaking the core CLI.

---

## Security model

Dayı processes untrusted CTF files, so analysis is deliberately constrained. It rejects or limits path traversal, symlink escapes, decompression bombs, oversized archive members, excessive image dimensions, oversized OCR/PDF/Office/RTF/PCAP inputs, recursive decoding, unsafe terminal control data, and lingering subprocesses after timeouts.

No local forensic tool can provide a complete sandbox guarantee. Use a disposable VM or container for unknown files and keep third-party tools updated.

### Custom flag patterns (`--flag`)

*Unreleased: not part of the published v4.5.2 package.*

A custom pattern is a Python `re` regular expression. Python cannot interrupt
a running match, and a pattern that looks harmless, such as `F.*L.*A.*G.*\}`,
can run for minutes or longer on long, almost-matching text. Custom patterns
are therefore limited in two ways:

- **Validation** (unchanged from 4.5.2): patterns longer than 512 characters,
  back-references, lookaround and nested ambiguous repeats such as `(a+)+` are
  rejected before the scan starts (exit code 1). This check is a heuristic;
  passing it does not mean a pattern is fast.
- **Bounded execution**: every match of a custom pattern in Dayı's main
  process runs in a separate worker process, one per scan. A match gets at
  most 5 seconds, or less when the scan budget is almost used up; then the
  worker is killed and the next input gets a fresh one. All custom-pattern
  work in a scan (worker start-up, matching, communication and stopping a
  worker) shares a time budget of `--timeout` seconds; when it is used up, the
  remaining inputs are not searched with the pattern. The budget is capped at
  one hour: a larger or non-finite `--timeout` (`inf`, `nan`) gives
  custom-pattern matching a one-hour budget, while the tools keep their usual
  `--timeout`. Every wait for the worker during a match, including sending it
  an input and reading its results, ends at the per-match limit, and waiting
  for a worker to start ends after 30 seconds; a worker that stops responding
  is killed. A single input longer than 16 Mi characters is not
  searched (no current input source produces one).

Matching behaviour is unchanged: the same pattern and flags, the full matched
text, unique values in first-occurrence order, at most 1,024 per input. Flags
found before a match was stopped are kept, and early stop and `--full-scan`
work as before. The built-in pattern used without `--flag` is not affected.

A stopped or skipped match is not a "no flag" result. It is listed under
`analysis_limits` (see [Analysis limits](#analysis-limits)); the scan still
ends as `completed` or `early_stopped`, and the tool result is not marked as
timed out.

Limitations:

- The worker adds a short start-up per scan and some inter-process overhead
  to every match of a custom pattern. The start-up counts against the budget,
  so a `--timeout` shorter than the worker start-up (a fraction of a second,
  longer on a loaded machine) leaves no time for custom-pattern matching in the
  main process; the skipped inputs are reported as
  `flag_regex_budget_exhausted`.
- A match made from the asyncio event loop blocks the loop until it ends. It
  can also first wait for another match in progress or for a worker start, so
  the wait is bounded by the time left in the scan budget rather than by the
  5-second per-match limit, and Ctrl+C can take that long to act. The scan
  budget itself can be exceeded once, by at most one worker start-up (up to
  30 seconds) plus stopping a worker (about one second). Starting the worker
  process and waiting for a killed worker to exit are bounded by the operating
  system rather than by these deadlines.
- Programs that use `build_flag_pattern_config(...).compiled` outside
  `DayiRunner` get a 60-second budget for that object until they call
  `start_scan()`; `close()` stops the worker. The object provides only
  `pattern`, `flags` and `finditer` (full-match `group(0)`), not `search`,
  `match`, `findall` or `sub`.
- Text-steganography, document and pytesseract OCR analysis already run in
  isolated child processes. There the pattern is matched inside that child and
  is bounded only by that plugin's own timeout, not by the regex budget.
- Programs that pass their own `re.Pattern` to `DayiRunner`, or use
  `compile_pattern` directly, are not bounded; use
  `build_flag_pattern_config`.
- Bounded execution needs POSIX `poll()` (Linux is the supported platform).
  Without it, custom-pattern matching in the main process is turned off and
  reported as `flag_regex_worker_failure`.
- This bounds the time spent on custom-pattern matching. It is not a deadline
  for the whole scan (each tool keeps its own `--timeout`) and not a complete
  protection against denial of service.

---

## Reports and integrations

Dayı writes a built-in Markdown report. It can optionally:

- use a validated `csl-ctfshitcli` installation for richer writeups;
- submit discovered flags to a configured CTFd instance;
- send independent Discord notifications.

Configuration is selected independently for each field: an explicit CLI value
wins over a nonblank environment value, followed by the default or disabled
state.

| Purpose | CLI option | Environment variable |
|---|---|---|
| CTFd base URL | `--ctfd-url` | `DAYI_CTFD_URL` |
| CTFd API token | `--ctfd-token` | `DAYI_CTFD_TOKEN` |
| CTFd challenge ID | `--challenge-id` | `DAYI_CTFD_CHALLENGE_ID` |
| Discord webhook | `--webhook` | `DAYI_DISCORD_WEBHOOK_URL` |
| Notification challenge name | `--challenge-name` | `DAYI_CHALLENGE_NAME` |
| Optional writeup checkout | `--ctfshit-path` | `DAYI_CTFSHIT_PATH` |

Prefer environment variables for secrets. Real tokens and webhook URLs must not
be placed in process listings, shell history, terminal logs, screenshots, or
committed files. The following values are deliberately non-secret placeholders:

```bash
export DAYI_CTFD_URL=https://ctfd.example
export DAYI_CTFD_TOKEN=TOKEN_REDACTED
export DAYI_CTFD_CHALLENGE_ID=42
export DAYI_DISCORD_WEBHOOK_URL=https://discord.example/webhook
export DAYI_CHALLENGE_NAME="Example challenge"
dayi scan challenge.jpg

# A CLI value overrides only its corresponding environment field.
dayi scan challenge.jpg --challenge-id 43

# Optional rich writeup checkout; built-in Markdown remains the fallback.
export DAYI_CTFSHIT_PATH=/path/to/local/ctfshitcli
dayi scan challenge.jpg --writeup writeup.md

# Network-free diagnostics
dayi doctor
dayi doctor --json
```

At manager creation Dayı selects usable aiohttp, otherwise stdlib urllib; that
transport selection is fixed for the scan. CTFd and Discord are dispatched
independently, and an integration failure never invalidates a completed scan.
`csl-ctfshitcli` is used only for rich Markdown writeups; Discord and CTFd do
not depend on it, and built-in Markdown is the writeup fallback.

Discord webhook URLs require HTTPS. CTFd HTTP remains accepted for backward
compatibility, although HTTPS is recommended. URL userinfo, query strings, and
fragments are rejected, redirects are blocked, requests use bounded timeouts,
and CTFd response reads are bounded. `dayi doctor` validates local configuration
only; it does not test endpoints, credentials, or reachability. Notification
secrets are not added to TXT, JSON, or Markdown reports.

### Early stop and full scan

By default the scan stops after the first confirmed flag: still-running
concurrent plugins are cancelled and later archive, mini-wordlist and
main-wordlist phases are not started. This keeps the common single-flag case
fast.

`--full-scan` turns off only that flag-triggered stop. It is useful when a
challenge hides several flags, when the first hit may be a decoy, or when you
want every eligible plugin's output for deeper analysis. It was added after
the v4.5.2 release and is not available in published v4.5.2 packages.

```bash
dayi scan challenge.png --full-scan
```

Everything else stays in force: plugins still skip when they need a missing
`--wordlist` or an empty mini-wordlist, declared skip-after-success rules still
apply, unsupported formats and missing optional dependencies still produce
skipped results, and per-plugin timeouts, extraction limits and output limits
are unchanged. A full scan can take considerably longer because later phases,
including wordlist brute force, also run. Flags are still de-duplicated and
attributed to every tool that found them. With CTFd or Discord configured,
each distinct flag is dispatched at most once, so a full scan can submit more
than one flag (including decoys) where the default scan would have stopped.
Automatic CTFd submission continues after CTFd accepts a flag as correct, and
each rejected decoy is a wrong submission that, depending on the CTF's rules,
can use up a limited number of attempts or incur penalties. Do not combine
`--full-scan` with automatic CTFd submission (`--ctfd-url` or `DAYI_CTFD_URL`)
on challenges with limited attempts.

A full scan that reaches the end of the pipeline reports
`scan_status: completed` and never lists `*_early_stop` reasons. `completed`
means every eligible plugin was evaluated under the existing limits; it does
not guarantee that every hidden flag was found. Ctrl+C and fatal errors are
still reported as `cancelled` and `failed`.

### Scan status

Finding a flag and finishing the analysis are reported separately. JSON
reports carry two additional top-level fields; TXT and Markdown reports show
the same information as a `Tarama Durumu` line and a list of plugins that did
not run.

`scan_status`:

| Value | Meaning |
|---|---|
| `completed` | The pipeline reached its normal end. It does not mean every tool succeeded; a flag may or may not have been found. |
| `early_stopped` | A confirmed flag stopped the scan and at least one plugin that would otherwise have been evaluated did not run or had its result discarded. |
| `cancelled` | The scan task was cancelled, normally by the user pressing Ctrl+C. Results may be partial; `plugins_not_run` shows what did not run. |
| `failed` | The runner stopped on a fatal error. Results may be partial. |

If several apply, `cancelled` wins over `failed`, and both win over
`early_stopped`. As before, the `dayi` CLI writes no report file when the
runner re-raises anything other than task cancellation, so `failed`, and
`cancelled` caused by a `KeyboardInterrupt` inside the pipeline, are currently
visible only to programmatic callers of the runner.

`plugins_not_run` lists, in registry order, every registered plugin without an
entry in `tool_results`, as `{"plugin_id": ..., "reason": ...}`. Plugins that
returned a skipped, timed-out or error result stay in `tool_results`. Entries
use registry plugin IDs as shown by `dayi plugins list`, which can differ from
the tool name in `tool_results`. Reasons:

| Reason | Meaning |
|---|---|
| `wordlist_missing` | The plugin requires `--wordlist` and none was given. |
| `mini_wordlist_missing` | The metadata-derived mini-wordlist was empty. |
| `redundant_after_success` | A declared prerequisite phase or plugin already succeeded. |
| `not_started_early_stop` / `cancelled_early_stop` | Not started, or started and cancelled, after a confirmed flag. |
| `not_started_user_cancel` / `cancelled_user_cancel` | Not started, or started and cancelled, because the user cancelled the scan. |
| `not_started_runner_failure` / `interrupted_runner_failure` | Not started, or started and not finished, because of a fatal runner error. |
| `result_discarded` | The plugin finished, but the scan was already stopping and its result was not recorded. |

A plugin that was never reached is reported with a skip reason only when that
rule would certainly have applied; otherwise it carries the `not_started_*`
reason. Both fields are `null` for reports that were not produced by a scan.

### Analysis limits

*Unreleased: not part of the published v4.5.2 package.*

Every parser and extractor works within fixed size, count and time budgets so
that a hostile or huge file cannot exhaust memory, CPU or disk. When one of
the recorded budgets listed below changes what was analysed, the report says
so; not every budget is recorded yet. A pipeline that
`completed` can still have incomplete coverage: `scan_status` describes how the
scan ended, analysis limits describe what each tool could not fully examine.

JSON reports gain a top-level `analysis_limits` list (empty when no recorded
limit was reached). TXT reports, the built-in Markdown writeup and the notes
passed to the optional writeup exporter show the same entries under
`KAYNAK SINIRLARI`. Each entry is:

```json
{"tool": "binwalk", "source": "scan_file", "reason": "extracted_file_size_limit",
 "action": "skipped", "limit": 8388608, "unit": "bytes", "observed": 20971520, "count": 1}
```

`tool` is the `tool_results[].tool` name of the result that hit the limit;
`source` is the component that made the decision. `action` is `skipped` (input
not analysed), `partial` (only a prefix was analysed) or `stopped` (a
cumulative budget ended processing). `limit` and `observed` use `unit`;
`observed` is `null` when the exact quantity is not known without extra reads.
Repeated identical events are merged and counted in `count`; at most 32
distinct entries are kept per tool result. Entries follow `tool_results`
order and are sorted within each tool.

| Reason | Source | Action | Meaning |
|---|---|---|---|
| `extracted_file_size_limit` | `scan_file` | skipped | An extracted file (steghide, stegseek, binwalk, zip_cracker) is larger than 8 MiB and was not scanned for flags. |
| `directory_file_limit` | `scan_directory` | stopped | Flag scanning of an extraction directory stopped after 4,096 files; the number of remaining files is not counted. |
| `directory_byte_budget` | `scan_directory` | stopped | Flag scanning of an extraction directory stopped at the 128 MiB aggregate budget. |
| `artifact_input_limit` | `artifact_scan/stdout`, `artifact_scan/stderr` | partial | Only the first 4 Mi characters of tool output were searched for next-stage artifacts. |
| `artifact_finding_limit` | `artifact_scan`, `artifact_scan/<stream>` | stopped | A new artifact was dropped because the 512-artifact budget of one tool result was used up; artifacts repeated in tool output also count against that budget. Without a stream, `artifact_scan` means the plugin itself returned more than 512 artifacts and the rest were dropped; those may include repeats. |
| `subprocess_output_limit` | `subprocess_stdout`, `subprocess_stderr` | partial | The tool printed more than 10 MiB. Flags are still searched in the complete stream (within the streaming flag-match caps); artifacts, the mini-wordlist and the report use the retained prefix. |
| `text_source_byte_limit` | `text_stego` | partial | Only the first 8 MiB of a text input were read. |
| `text_decoded_char_limit` | `text_stego` | partial | Only the first 4,000,000 decoded characters were kept. |
| `text_analysis_char_limit` | `text_stego` | partial | Text-steganography methods examined the first 1 Mi characters; the direct flag search covered all decoded text. |
| `flag_regex_timeout` | `flag_regex` | partial | A custom `--flag` match was stopped at the 5-second per-match limit (`limit`, in milliseconds); flags found in that input before the stop are kept. |
| `flag_regex_budget_exhausted` | `flag_regex` | skipped, partial | The scan's custom-pattern time budget (`--timeout`, shown in milliseconds) was used up: `skipped` means the input was not searched with the pattern, `partial` means a match was stopped because the budget ran out (flags found before the stop are kept). |
| `flag_regex_input_limit` | `flag_regex` | skipped | An input longer than 16 Mi characters was not searched with the custom pattern. |
| `flag_match_limit` | `flag_regex` | partial | A custom pattern found more than 1,024 distinct matches in one input; only the first 1,024 were kept. |
| `flag_regex_worker_failure` | `flag_regex` | skipped | The custom-pattern worker could not start or stopped unexpectedly; custom-pattern matching stays off for the rest of the scan (`limit` 0, unit `none`). |

The `flag_regex` entries are explained in [Custom flag patterns](#custom-flag-patterns---flag).

Report display shortening is separate and is never listed as an analysis
limit: JSON and TXT shorten stored stdout/stderr with an inline
`[TRUNCATED — N chars omitted]` marker, and TXT/Markdown views that show only
the first findings or lines add a `(+N … yalnızca bu rapor görünümünde
gösterilmedi)` line. JSON keeps the full finding lists.

`--full-scan` does not lift any limit. Not every limit is recorded yet: limits
that were already visible as text (for example PDF page, PCAP packet, OLE
macro and document parser limits, and oversized-input skip reasons) keep their
existing `skip_reason`/stderr/stdout wording, and some budgets, such as the
1,024-match cap of the built-in flag pattern, the streaming flag-match caps, the artifact budgets of
plugin-internal artifact scans (PDF, OLE, document, QR, OCR, text-stego),
workspace discovery caps of the text-stego, OCR and QR plugins and the 1 MiB
extracted-payload check of outguess, are not reported. Text-stego truncation
is also not reported for an input that was then skipped as non-text. An empty
`analysis_limits` list therefore does not prove complete coverage.

---

## Release status

**Latest published release: [GitHub Releases](https://github.com/MacallanTheRoot/DayiStegoSolver/releases/latest)**

Version in this source tree: 4.5.2 (see [CHANGELOG.md](CHANGELOG.md) and
[RELEASE_NOTES_v4.5.2.md](RELEASE_NOTES_v4.5.2.md)).

- Python: 3.10–3.13
- CI: passing across all supported Python versions
- Distribution: verified wheel and source archive
- License: MIT

Release checksums are included with the GitHub Release assets.

---

## Roadmap

- public CTF challenge benchmark;
- reproducible demonstration corpus;
- installation and Docker experience;
- shorter visual documentation;
- community feedback and external contributions.

---

## Contributing

Issues and focused pull requests are welcome. Useful contributions include reproducible public challenge samples, false-positive or missed-detection reports, new bounded analyzers, portability fixes, installation documentation, and benchmark results.

Do not submit private challenge data, credentials, or copyrighted corpora without redistribution permission.

### Local private regression

Private corpora, manifests, and reports must stay outside this repository.
Never commit challenge samples or exact flags, and redact filenames, paths,
payloads, and flag values from public reports. Real private regressions remain
read-only and local; deterministic synthetic fixtures are required for code
changes committed to the repository.

The local harness is explicitly bounded, uses no network access, and keeps
networking configuration disabled:

```bash
export DAYI_PRIVATE_CORPUS=/path/outside/repository/corpus
python scripts/run_private_regression.py \
  --input "$DAYI_PRIVATE_CORPUS" \
  --output /tmp/dayi-private-regression \
  --manifest /path/outside/repository/expectations.json \
  --timeout 180 --max-files 500 --anonymize --redact-flags
```

Use `--show-flags` only for an explicitly local report. The harness classifies
timeouts, parser failures, unsupported inputs, and missing tools separately;
its exit status reports harness/configuration failure rather than how many
challenges were solved. It does not execute decoded payloads. Synthetic tests
are required for fixes; private challenge data must never become a fixture.

---

## License

Released under the [MIT License](LICENSE).

---

## Türkçe Dokümantasyon

## Dayı nedir?

Steganografi challenge'larında çoğu zaman birbirinden bağımsız birçok aracı elle denemek gerekir:

```text
dosya → exiftool → strings → binwalk → zsteg → steghide → stegseek → OCR → özel scriptler
```

Dayı bu akışı tek bir CLI altında koordine eder. Analizi yerel, sınırlı ve deterministik tutar.

```bash
dayi scan challenge.png
```

Dayı şunları yapabilir:

- dosya uzantısına güvenmek yerine gerçek dosya türünü içerikten algılar;
- yalnız ilgili araçları ve dahili analiz modüllerini çalıştırır;
- görsel, metin, arşiv, doküman, PDF, OLE/makro, QR ve PCAP kanıtlarını inceler;
- iç içe kodlanmış metinleri çözer ve bağlamsal parola adayları toplar;
- bulunan flag'i hangi pluginin bulduğunu raporlar;
- Markdown raporu oluşturur;
- isteğe bağlı olarak CTFd veya Discord bildirimi gönderir.

> Dayı bir triage ve otomasyon aracıdır; her challenge'ı otomatik çözeceği garanti edilmez.

---

## Kurulum

### Core kurulum

```bash
git clone https://github.com/MacallanTheRoot/DayiStegoSolver.git
cd DayiStegoSolver

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .

dayi --version
dayi doctor
```

Core paket Python standart kütüphanesiyle çalışır. Optional araçlar eksik olsa bile temel CLI kullanılabilir.

### Önerilen optional Python özellikleri

```bash
python -m pip install -e ".[ui,ocr,qr,pdf,ole,pcap,integration]"
```

### Kali, Debian veya Ubuntu için önerilen sistem araçları

```bash
sudo apt update
sudo apt install -y \
  libimage-exiftool-perl \
  exiv2 \
  binutils \
  binwalk \
  steghide \
  outguess \
  tesseract-ocr

sudo gem install zsteg
```

StegSeek'i resmi release üzerinden kur:

```bash
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_linux.deb
sudo dpkg -i stegseek_linux.deb
```

Ortamı kontrol et:

```bash
dayi doctor
dayi plugins list
```

---

## Hızlı başlangıç

```bash
# Dahili genel flag patternleri
dayi scan challenge.png

# Challenge'a özel flag ifadesi
dayi scan challenge.jpg --flag 'CTF\{.*?\}'

# Uzantısız veya yanıltıcı uzantılı dosya
dayi scan hidden.data --flag 'SiberVatan\{.*?\}' -v

# İlk flag'den sonra taramaya devam et (yayımlanmadı, bkz. "Erken durma ve tam tarama")
dayi scan challenge.png --full-scan

# Sağlık ve plugin kontrolleri
dayi doctor
dayi plugins list
```

---

## Neleri analiz eder?

| Alan | Kapsam |
|---|---|
| **Görseller** | JPEG, PNG, BMP, GIF, TIFF, WebP, PNM; metadata, strings, embedded dosyalar, LSB odaklı analiz, OCR ve QR |
| **Metin steganografisi** | Bacon, whitespace, zero-width Unicode, homoglyph, acrostic ve yapısal kanallar, ghost text, iç içe Hex/Base64 |
| **Dokümanlar** | DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, ODT/ODS/ODP ve RTF gizleme yöntemleri, metadata, yorumlar, ilişkiler, medya ve embedded objeler |
| **Arşivler** | ZIP keşfi, sınırlı extraction, uzantısız ZIP carving, bağlamsal parola denemeleri, streamed wordlist |
| **PDF** | Metadata, sınırlı sayfa metni, boş parolalı şifreli belgeler, flag ve pasif artifact taraması |
| **OLE ve makrolar** | Desteklenen OLE ve OpenXML container'lardan sınırlı VBA source extraction |
| **PCAP/PCAPNG** | Streamed Raw, ICMP, DNS, HTTP, flag, pasif artifact ve tanınan payload carving |
| **Pasif artifact'ler** | URL, IP, kontrollü domain, credential hint, koordinat ve yazdırılabilir encoded hint |

### Kayıtlı pipeline

Dayı 4.5.2:

- **22 kayıtlı plugin**
- **12 CONCURRENT aşama işlemi**
- dinamik plugin keşfi ve doğrulama
- optional runtime eksik olduğunda temiz degradation

Yaygın entegrasyonlar:

```text
exiftool · exiv2 · strings · binwalk · zsteg · steghide
stegseek · outguess · Tesseract · OpenCV/pyzbar/zbarimg
pypdf · oletools · Scapy
```

### Gelişmiş yerel analiz

Çekirdek `text_stego_scanner`, dosya uzantısı yerine algılanan metin üzerinde
çalışır. Zero-width Unicode, harf büyüklüğüne dayalı binary ASCII,
whitespace/SNOW, Bacon-style, homoglyph, akrostiş/yapısal, ghost-text ve iç içe
Hex/Base64 adaylarını puanlar. Bulgular plugin ve decoder-chain attribution
bilgisini korur. Analiz ağ erişimi olmadan çalışır; çözülen içerik veri olarak
kalır ve çalıştırılmaz. ANSI/bidi/control karakterleri gösterimden önce escape
edilir.

Metin analizi en fazla **8 MiB** kaynak, **4 milyon** decoded karakter ve **512
aday** işler; aday çıktısını **64 KiB**, iç içe çözmeyi **depth 3** ve toplam
decoded veriyi **16 MiB** ile sınırlar.

Belge analizi PDF, OpenXML/Office paketleri (DOCX/DOCM, XLSX/XLSM, PPTX/PPTM),
optional parser desteklediğinde OLE/eski belgeler, OpenDocument (ODT/ODS/ODP),
RTF ve uygun yerel analizöre yönlendirilen düz metni kapsar.
`document_stego_scanner`; gizli stiller, yorumlar, revizyonlar, header/footer,
alt text, metadata, ilişkiler, medya ve gömülü nesneleri inceler. Harici
ilişkiler yalnızca raporlanır; makrolar, formüller, field'lar, scriptler ve
gömülü executable'lar çalıştırılmaz veya fetch edilmez.

OpenXML işlemleri paketleri **128 MiB**, üyeleri **5.000**, her üyeyi **32 MiB**,
toplam açılmış veriyi **256 MiB** ve her XML üyesini **16 MiB** ile sınırlar.
Extraction sırasında medya sayısı **100**, gömülü nesne sayısı **50** ve recursive
belge geçişi **depth 3** ile sınırlıdır. Bulgular paket üyesi ve mekanizma
attribution bilgisini korur. Bu analizler heuristic ve format/corpus bağımlıdır;
eksiksiz render veya eski-format uyumluluğu iddia etmez.

### OCR ve QR kontrolleri

Kurulu Tesseract dillerini `--ocr-lang` ile seçin; daha yavaş fakat sınırlı
preprocessing planını `--ocr-exhaustive` ile açın. OCR heuristic bir analizdir;
stilize, hasarlı veya düşük kontrastlı metin çözülemeyebilir. Plan en fazla 20
kaynak görsel, görsel başına 20 variant ve 30 invocation, toplamda **200 OCR
invocation** çalıştırır. Her invocation **15 saniye** ve 1 MiB metinle, toplam
OCR metni 8 MiB ile sınırlıdır. Kaynak görsel sınırı 64 MiB ve 50 milyon decoded
pikseldir. Büyük exhaustive girdiler için `--timeout 60` gibi 60 saniye veya
daha uzun plugin timeout gerekebilir.

Pasif `qr_scanner`, hazır olduğunda OpenCV, pyzbar ve zbarimg backend'lerini
kullanır. QR'dan çözülen URL, komut, arşiv ve gömülü veriler mevcut sınırlar
içinde raporlanır veya incelenir; asla açılmaz, fetch edilmez veya çalıştırılmaz.
Kayıtlı pipeline **22 kayıtlı plugin** ve bunların **12 concurrent plugin**
işlemini korur.

---

## Örnek çalışma akışı

```text
[+] Hedef türü: PNG
[+] İlgili metadata, arşiv, LSB, QR ve OCR analizleri başlatıldı
[+] Yazdırılabilir Base64 adayı çıkarıldı
[+] İç içe metin çözüldü
[FLAG] CTF{example_flag}
[+] Bulan pluginler: strings, text_stego_scanner
[+] Markdown raporu yazıldı
```

Gerçek çıktı, kurulu optional araçlara ve analiz edilen challenge'a göre değişir.

---

## Tasarım ilkeleri

- **İçerik tabanlı yönlendirme:** dosya imzaları, dosya uzantısından önce gelir.
- **Sınırlı çalışma:** parser, arşiv, OCR, doküman, paket, recursion ve subprocess işlemleri açık limitlere sahiptir.
- **Varsayılan olarak pasif:** bulunan URL ve komutlar raporlanır; açılmaz veya çalıştırılmaz.
- **Aktif doküman içeriği yok:** makro, formül, field, embedded executable ve external relationship çalıştırılmaz veya fetch edilmez.
- **Deterministik raporlama:** plugin sırası, attribution ve JSON diagnostic çıktıları tekrarlanabilir çalışmayı destekler.
- **Temiz degradation:** optional araçların eksikliği core CLI'yi bozmaz.

---

## Güvenlik modeli

Dayı güvenilmeyen CTF dosyalarını işler. Bu nedenle path traversal, symlink escape, decompression bomb, büyük arşiv üyeleri, aşırı görsel boyutları, büyük OCR/PDF/Office/RTF/PCAP girdileri, kontrolsüz recursive decoding, terminal control karakterleri ve timeout sonrası kalan subprocess'ler sınırlandırılır veya reddedilir.

Hiçbir yerel forensics aracı tam sandbox garantisi vermez. Bilinmeyen dosyaları disposable VM veya container içinde analiz et ve üçüncü taraf araçları güncel tut.

### Özel flag desenleri (`--flag`)

*Yayımlanmadı: yayımlanmış v4.5.2 paketinin parçası değildir.*

Özel desen bir Python `re` düzenli ifadesidir. Python çalışmakta olan bir
eşleştirmeyi kesemez; `F.*L.*A.*G.*\}` gibi zararsız görünen bir desen, uzun ve
neredeyse eşleşen bir metinde dakikalarca veya daha uzun sürebilir. Bu yüzden
özel desenler iki şekilde sınırlandırılır:

- **Doğrulama** (4.5.2 ile aynı): 512 karakterden uzun desenler, geri
  referanslar, lookaround ve `(a+)+` gibi iç içe belirsiz tekrarlar tarama
  başlamadan reddedilir (çıkış kodu 1). Bu kontrol sezgiseldir; kontrolden
  geçmek desenin hızlı olduğu anlamına gelmez.
- **Sınırlı çalıştırma**: özel desenin Dayı ana sürecindeki her eşleştirmesi,
  tarama başına bir tane olan ayrı bir işçi süreçte çalışır. Bir eşleştirmeye
  en fazla 5 saniye, tarama bütçesi bitmek üzereyse daha az süre verilir;
  ardından işçi öldürülür ve sonraki girdi için yeni bir işçi başlatılır. Bir
  taramadaki tüm özel desen işleri (işçi başlatma, eşleştirme, süreçler arası
  iletişim ve işçiyi durdurma) `--timeout` saniyelik ortak bir süre bütçesini
  paylaşır; bütçe bitince kalan girdiler bu desenle aranmaz. Bütçe en fazla
  bir saattir: daha büyük veya sonlu olmayan bir `--timeout` (`inf`, `nan`)
  özel desen eşleştirmesine bir saatlik bütçe verir; araçlar `--timeout`
  değerini her zamanki gibi kullanır. Bir eşleştirme sırasında işçiye girdi
  gönderme ve sonuçlarını okuma dahil işçiyi her bekleyiş eşleştirme başına
  sınırda, bir işçinin başlamasını bekleme 30 saniyede biter; yanıt vermeyen
  bir işçi öldürülür. 16 Mi karakterden uzun tek bir girdi aranmaz
  (mevcut girdi kaynaklarının hiçbiri böyle bir girdi üretmez).

Eşleştirme davranışı değişmedi: aynı desen ve bayraklar, eşleşen metnin
tamamı, ilk görülme sırasına göre tekil değerler, girdi başına en fazla 1.024.
Bir eşleştirme durdurulmadan önce bulunan flag'ler korunur; erken durma ve
`--full-scan` eskisi gibi çalışır. `--flag` verilmeden kullanılan yerleşik
desen bundan etkilenmez.

Durdurulan veya atlanan bir eşleştirme "flag yok" sonucu değildir.
`analysis_limits` altında listelenir (bkz. [Analiz sınırları](#analiz-sınırları));
tarama yine `completed` veya `early_stopped` olarak biter ve araç sonucu
zaman aşımına uğramış olarak işaretlenmez.

Sınırlamalar:

- İşçi, tarama başına kısa bir başlatma süresi ve özel desenin her
  eşleştirmesine bir miktar süreçler arası iletişim maliyeti ekler. Başlatma
  süresi bütçeden düşer; bu yüzden işçinin başlama süresinden (saniyenin bir
  kısmı, yüklü bir makinede daha uzun) kısa bir `--timeout`, ana süreçte özel
  desen eşleştirmesine süre bırakmaz; atlanan girdiler
  `flag_regex_budget_exhausted` olarak raporlanır.
- asyncio olay döngüsünden yapılan bir eşleştirme bitene kadar döngüyü
  bekletir. Önce sürmekte olan başka bir eşleştirmeyi veya bir işçinin
  başlamasını da bekleyebileceği için bu bekleme 5 saniyelik eşleştirme
  sınırıyla değil, tarama bütçesinde kalan süreyle sınırlıdır; Ctrl+C'nin
  etkisi bu kadar gecikebilir. Tarama bütçesi bir kez, en fazla bir işçi
  başlatması (en fazla 30 saniye) ile bir işçiyi durdurma (yaklaşık bir
  saniye) kadar aşılabilir. İşçi sürecinin başlatılması ve öldürülen bir
  işçinin çıkışının beklenmesi bu sürelerle değil, işletim sistemiyle
  sınırlıdır.
- `build_flag_pattern_config(...).compiled` nesnesini `DayiRunner` dışında
  kullanan programlar, `start_scan()` çağırana kadar o nesne için 60 saniyelik
  bir bütçe alır; `close()` işçiyi durdurur. Nesne yalnız `pattern`, `flags` ve
  `finditer` (tam eşleşme, `group(0)`) sağlar; `search`, `match`, `findall`
  veya `sub` sağlamaz.
- Metin steganografisi, belge ve pytesseract OCR analizi zaten yalıtılmış
  alt süreçlerde çalışır. Orada desen o alt süreçte eşleştirilir ve yalnız o
  eklentinin kendi zaman aşımıyla sınırlanır, regex bütçesiyle değil.
- `DayiRunner`'a kendi `re.Pattern` nesnesini veren veya `compile_pattern`'ı
  doğrudan kullanan programlar sınırlanmaz; `build_flag_pattern_config`
  kullanılmalıdır.
- Sınırlı çalıştırma POSIX `poll()` gerektirir (desteklenen platform
  Linux'tur). Bu olmadan ana süreçte özel desen eşleştirmesi kapatılır ve
  `flag_regex_worker_failure` olarak raporlanır.
- Bu, özel desen eşleştirmesine harcanan süreyi sınırlar. Taramanın tamamı
  için bir süre sınırı değildir (her araç kendi `--timeout` değerini kullanır)
  ve hizmet engellemeye karşı tam bir koruma değildir.

---

## Raporlar ve entegrasyonlar

Dayı yerleşik Markdown raporu üretir. İsteğe bağlı olarak:

- daha zengin writeup için doğrulanmış `csl-ctfshitcli` kurulumu kullanabilir;
- bulunan flag'leri yapılandırılmış CTFd sunucusuna gönderebilir;
- bağımsız Discord bildirimi gönderebilir.

Yapılandırma her alan için ayrı seçilir: açık CLI değeri boş olmayan ortam
değişkeninden, ortam değeri de varsayılan veya devre dışı durumdan önceliklidir.

| Amaç | CLI seçeneği | Ortam değişkeni |
|---|---|---|
| CTFd temel URL | `--ctfd-url` | `DAYI_CTFD_URL` |
| CTFd API token | `--ctfd-token` | `DAYI_CTFD_TOKEN` |
| CTFd challenge ID | `--challenge-id` | `DAYI_CTFD_CHALLENGE_ID` |
| Discord webhook | `--webhook` | `DAYI_DISCORD_WEBHOOK_URL` |
| Bildirim challenge adı | `--challenge-name` | `DAYI_CHALLENGE_NAME` |
| Optional writeup checkout | `--ctfshit-path` | `DAYI_CTFSHIT_PATH` |

Secret değerler için ortam değişkenlerini tercih edin. Gerçek token ve webhook
URL'lerini process listesi, shell history, terminal logu, ekran görüntüsü veya
commit edilmiş dosyalara koymayın. Yukarıdaki İngilizce örneklerdeki
`https://ctfd.example`, `https://discord.example/webhook` ve `TOKEN_REDACTED`
değerleri yalnızca güvenli placeholder'dır.

Manager oluşturulurken kullanılabilir aiohttp seçilir, yoksa stdlib urllib
kullanılır; transport seçimi tarama boyunca sabittir. CTFd ve Discord bağımsız
gönderilir ve entegrasyon hatası tamamlanmış taramayı geçersiz kılmaz.
`csl-ctfshitcli` yalnız zengin Markdown writeup için kullanılır; Discord ve CTFd
ona bağlı değildir ve yerleşik Markdown fallback olarak kalır.

Discord webhook URL'leri HTTPS gerektirir. CTFd HTTP geriye uyumluluk için kabul
edilir, fakat HTTPS önerilir. URL userinfo, query string ve fragment alanları
reddedilir; redirect engellenir, istek timeout'ları ve CTFd cevap okumaları
sınırlıdır. `dayi doctor` yalnızca yerel yapılandırmayı doğrular; endpoint,
credential veya erişilebilirlik testi yapmaz. Bildirim secret'ları TXT, JSON
veya Markdown raporlarına eklenmez.

### Erken durma ve tam tarama

Varsayılan olarak tarama ilk doğrulanmış flag'den sonra durur: hâlâ çalışan
concurrent eklentiler iptal edilir; sonraki arşiv, mini-wordlist ve ana
wordlist fazları başlatılmaz. Böylece tek flag'li yaygın durum hızlı kalır.

`--full-scan` yalnızca flag kaynaklı bu durmayı kapatır. Challenge birden fazla
flag sakladığında, ilk eşleşme bir yem olabileceğinde veya daha derin analiz
için uygun her eklentinin çıktısını görmek istediğinizde işe yarar. Bu seçenek
v4.5.2 sürümünden sonra eklendi ve yayımlanmış v4.5.2 paketlerinde bulunmaz.

```bash
dayi scan challenge.png --full-scan
```

Diğer her şey geçerli kalır: eksik `--wordlist` veya boş mini-wordlist isteyen
eklentiler yine atlanır, tanımlı başarı sonrası atlama kuralları uygulanır,
desteklenmeyen formatlar ve eksik optional bağımlılıklar yine atlandı sonucu
üretir; eklenti başına timeout, çıkarma ve çıktı sınırları değişmez. Sonraki
fazlar, wordlist brute force dahil, de çalıştığı için tam tarama belirgin
biçimde uzun sürebilir. Flag'ler yine tekilleştirilir ve onları bulan her araca
atfedilir. CTFd veya Discord yapılandırılmışsa bulunan her farklı flag en
fazla bir kez gönderilir; bu yüzden tam tarama, varsayılan taramanın duracağı
yerde birden fazla flag (yemler dahil) gönderebilir. Otomatik CTFd gönderimi,
CTFd bir flag'i doğru kabul ettikten sonra da sürer; reddedilen her yem flag
yanlış bir gönderimdir ve CTF kurallarına göre sınırlı deneme hakkını
tüketebilir veya ceza getirebilir. Deneme hakkı sınırlı challenge'larda
`--full-scan` seçeneğini otomatik CTFd gönderimiyle (`--ctfd-url` veya
`DAYI_CTFD_URL`) birlikte kullanmayın.

Analiz hattının sonuna ulaşan tam tarama `scan_status: completed` raporlar ve
hiçbir zaman `*_early_stop` nedeni listelemez. `completed`, uygun her eklentinin
mevcut sınırlar içinde değerlendirildiği anlamına gelir; saklı her flag'in
bulunduğunu garanti etmez. Ctrl+C ve ölümcül hatalar yine `cancelled` ve
`failed` olarak raporlanır.

### Tarama durumu

Flag bulunması ile analizin tamamlanması ayrı raporlanır. JSON raporlarında iki
yeni üst seviye alan bulunur; TXT ve Markdown raporları aynı bilgiyi
`Tarama Durumu` satırı ve çalıştırılmayan eklenti listesiyle gösterir.

`scan_status`:

| Değer | Anlamı |
|---|---|
| `completed` | Analiz hattı normal sonuna ulaştı. Her aracın başarılı olduğu anlamına gelmez; flag bulunmuş da olabilir, bulunmamış da. |
| `early_stopped` | Doğrulanmış bir flag taramayı durdurdu ve aksi halde değerlendirilecek en az bir eklenti çalışmadı ya da sonucu kaydedilmedi. |
| `cancelled` | Tarama görevi iptal edildi; genellikle kullanıcı Ctrl+C'ye basmıştır. Sonuçlar kısmi olabilir; `plugins_not_run` neyin çalışmadığını gösterir. |
| `failed` | Çalıştırıcı ölümcül bir hatayla durdu. Sonuçlar kısmi olabilir. |

Birden fazlası geçerliyse `cancelled`, `failed`'dan; ikisi de `early_stopped`'dan
önceliklidir. `dayi` CLI, çalıştırıcı görev iptali dışında bir hatayı yeniden
yükselttiğinde eskisi gibi rapor dosyası yazmaz; bu yüzden `failed` ve analiz
hattı içindeki `KeyboardInterrupt` kaynaklı `cancelled` şu an yalnız
çalıştırıcıyı programatik olarak kullananlara görünür.

`plugins_not_run`, `tool_results` içinde kaydı olmayan her kayıtlı eklentiyi
registry sırasıyla `{"plugin_id": ..., "reason": ...}` olarak listeler. Atlandı,
timeout veya hata sonucu döndüren eklentiler `tool_results` içinde kalır.
Kayıtlar `dayi plugins list` çıktısındaki registry eklenti kimliklerini
kullanır; bunlar `tool_results` içindeki araç adından farklı olabilir.
Nedenler:

| Neden | Anlamı |
|---|---|
| `wordlist_missing` | Eklenti `--wordlist` ister ve verilmedi. |
| `mini_wordlist_missing` | Metadata'dan türetilen mini-wordlist boş kaldı. |
| `redundant_after_success` | Tanımlı ön koşul faz veya eklenti zaten başarılı oldu. |
| `not_started_early_stop` / `cancelled_early_stop` | Doğrulanmış flag sonrası başlatılmadı ya da başladı ve iptal edildi. |
| `not_started_user_cancel` / `cancelled_user_cancel` | Kullanıcı taramayı durdurduğu için başlatılmadı ya da başladı ve iptal edildi. |
| `not_started_runner_failure` / `interrupted_runner_failure` | Ölümcül çalıştırıcı hatası yüzünden başlatılmadı ya da başladı ve bitmedi. |
| `result_discarded` | Eklenti bitti, fakat tarama zaten duruyordu ve sonucu kaydedilmedi. |

Hiç ulaşılmayan bir eklenti, yalnızca ilgili atlama kuralı kesin olarak
geçerliyse atlama nedeniyle raporlanır; aksi halde `not_started_*` nedenini
taşır. Tarama tarafından üretilmeyen raporlarda iki alan da `null` olur.

### Analiz sınırları

*Yayımlanmadı: yayımlanan v4.5.2 paketinin parçası değildir.*

Her ayrıştırıcı ve çıkarıcı sabit boyut, sayı ve süre bütçeleriyle çalışır;
böylece kötü niyetli veya çok büyük bir dosya belleği, işlemciyi ya da diski
tüketemez. Aşağıda listelenen kayıtlı bütçelerden biri analiz edilen kapsamı
değiştirdiğinde rapor bunu belirtir; henüz her bütçe kaydedilmiyor.
`completed` olarak biten bir analiz hattının kapsamı yine eksik olabilir:
`scan_status` taramanın nasıl bittiğini, analiz sınırları ise her aracın
neyi tam inceleyemediğini anlatır.

JSON raporlarına üst seviye `analysis_limits` listesi eklenir (kayıtlı bir
sınıra ulaşılmadıysa boştur). TXT raporları, yerleşik Markdown writeup ve
opsiyonel writeup exporter'a verilen notlar aynı kayıtları `KAYNAK SINIRLARI`
başlığı altında gösterir. Her kayıt şöyledir:

```json
{"tool": "binwalk", "source": "scan_file", "reason": "extracted_file_size_limit",
 "action": "skipped", "limit": 8388608, "unit": "bytes", "observed": 20971520, "count": 1}
```

`tool`, sınıra takılan sonucun `tool_results[].tool` adıdır; `source` kararı
veren bileşendir. `action` değeri `skipped` (girdi analiz edilmedi), `partial`
(yalnız baştaki kısım analiz edildi) veya `stopped` (toplam bütçe işlemi
durdurdu) olur. `limit` ve `observed` `unit` birimindedir; kesin miktar ek okuma
yapmadan bilinmiyorsa `observed` `null` olur. Aynı olaylar birleştirilir ve
`count` ile sayılır; her araç sonucu için en fazla 32 farklı kayıt tutulur.
Kayıtlar `tool_results` sırasını izler ve her araç içinde sıralanır.

| Neden | Kaynak | Eylem | Anlamı |
|---|---|---|---|
| `extracted_file_size_limit` | `scan_file` | skipped | Çıkarılan bir dosya (steghide, stegseek, binwalk, zip_cracker) 8 MiB'tan büyük ve flag için taranmadı. |
| `directory_file_limit` | `scan_directory` | stopped | Çıkarım klasörünün flag taraması 4.096 dosyadan sonra durdu; kalan dosya sayısı sayılmaz. |
| `directory_byte_budget` | `scan_directory` | stopped | Çıkarım klasörünün flag taraması 128 MiB toplam bütçede durdu. |
| `artifact_input_limit` | `artifact_scan/stdout`, `artifact_scan/stderr` | partial | Araç çıktısının yalnız ilk 4 Mi karakterinde sonraki aşama artifact'ı arandı. |
| `artifact_finding_limit` | `artifact_scan`, `artifact_scan/<akış>` | stopped | Bir araç sonucunun 512 artifact bütçesi dolduğu için yeni bir artifact bırakıldı; araç çıktısında tekrar eden artifact'lar da bu bütçeden düşer. Akış belirtilmeyen `artifact_scan`, eklentinin kendisinin 512'den fazla artifact döndürdüğü ve fazlasının bırakıldığı anlamına gelir; bırakılanlar tekrar içerebilir. |
| `subprocess_output_limit` | `subprocess_stdout`, `subprocess_stderr` | partial | Araç 10 MiB'tan fazla çıktı verdi. Flag araması akışın tamamında yapılır (akış flag eşleşme sınırları içinde); artifact, mini-wordlist ve rapor saklanan baş kısmı kullanır. |
| `text_source_byte_limit` | `text_stego` | partial | Metin girdisinin yalnız ilk 8 MiB'ı okundu. |
| `text_decoded_char_limit` | `text_stego` | partial | Çözülen metnin yalnız ilk 4.000.000 karakteri tutuldu. |
| `text_analysis_char_limit` | `text_stego` | partial | Metin steganografi yöntemleri ilk 1 Mi karakteri inceledi; doğrudan flag araması çözülen metnin tamamını kapsadı. |
| `flag_regex_timeout` | `flag_regex` | partial | Özel `--flag` eşleştirmesi 5 saniyelik eşleştirme başına sınırda (`limit`, milisaniye) durduruldu; durmadan önce o girdide bulunan flag'ler korunur. |
| `flag_regex_budget_exhausted` | `flag_regex` | skipped, partial | Taramanın özel desen süre bütçesi (`--timeout`, milisaniye olarak gösterilir) bitti: `skipped` girdinin desenle aranmadığı, `partial` bir eşleştirmenin bütçe bittiği için durdurulduğu anlamına gelir (durmadan önce bulunan flag'ler korunur). |
| `flag_regex_input_limit` | `flag_regex` | skipped | 16 Mi karakterden uzun bir girdi özel desenle aranmadı. |
| `flag_match_limit` | `flag_regex` | partial | Özel desen tek bir girdide 1.024'ten fazla farklı eşleşme buldu; yalnız ilk 1.024'ü tutuldu. |
| `flag_regex_worker_failure` | `flag_regex` | skipped | Özel desen işçisi başlatılamadı veya beklenmedik şekilde durdu; taramanın geri kalanında özel desen eşleştirmesi kapalı kalır (`limit` 0, birim `none`). |

`flag_regex` kayıtları [Özel flag desenleri](#özel-flag-desenleri---flag) bölümünde açıklanır.

Rapor görünümünün kısaltılması ayrıdır ve hiçbir zaman analiz sınırı olarak
listelenmez: JSON ve TXT, saklanan stdout/stderr'i satır içi
`[TRUNCATED — N chars omitted]` işaretiyle kısaltır; yalnız ilk bulguları veya
satırları gösteren TXT/Markdown görünümleri `(+N … yalnızca bu rapor
görünümünde gösterilmedi)` satırı ekler. JSON bulgu listelerinin tamamını
tutar.

`--full-scan` hiçbir sınırı kaldırmaz. Henüz her sınır kaydedilmiyor: zaten
metin olarak görünen sınırlar (örneğin PDF sayfa, PCAP paket, OLE makro ve
belge ayrıştırıcı sınırları ile büyük girdi atlama nedenleri) mevcut
`skip_reason`/stderr/stdout ifadelerini korur; yerleşik flag deseninin 1.024 eşleşmelik sınırı,
akış flag eşleşme sınırları, eklenti içi artifact taramalarının (PDF, OLE,
belge, QR, OCR, text-stego) artifact bütçeleri, text-stego, OCR ve QR
eklentilerinin çalışma alanı keşif sınırları ve outguess'in 1 MiB'lık
çıkarılan veri kontrolü gibi bazı bütçeler raporlanmaz. Metin olmadığı için
atlanan bir girdide text-stego kırpması da raporlanmaz. Bu yüzden boş bir
`analysis_limits` listesi kapsamın tam olduğunu kanıtlamaz.

---

## Sürüm durumu

**Son yayımlanan sürüm: [GitHub Releases](https://github.com/MacallanTheRoot/DayiStegoSolver/releases/latest)**

Bu kaynak ağacındaki sürüm: 4.5.2 (bkz. [CHANGELOG.md](CHANGELOG.md) ve
[RELEASE_NOTES_v4.5.2.md](RELEASE_NOTES_v4.5.2.md)).

- Python: 3.10–3.13
- CI: desteklenen tüm Python sürümlerinde başarılı
- Dağıtım: doğrulanmış wheel ve source archive
- Lisans: MIT

Release checksum dosyaları GitHub Release asset'leri içinde bulunur.

---

## Yol haritası

- kamuya açık CTF challenge benchmark'ı;
- tekrar üretilebilir demo corpus'u;
- kurulum ve Docker deneyimi;
- daha kısa ve görsel dokümantasyon;
- topluluk geri bildirimi ve dış katkılar.

---

## Katkıda bulunma

Issue ve odaklı pull request'ler kabul edilir. Özellikle tekrar üretilebilir kamuya açık challenge örnekleri, false-positive veya missed-detection raporları, yeni bounded analyzer'lar, portability düzeltmeleri, kurulum dokümanı ve benchmark sonuçları değerlidir.

Dağıtım izni olmayan özel challenge verisi, credential veya copyrighted corpus eklemeyin.

### Yerel özel regresyon

Özel corpus, manifest ve raporlar bu repository'nin dışında kalmalıdır.
Challenge örneklerini veya tam flag değerlerini commit etmeyin; public
raporlarda dosya adı, yol, payload ve flag değerlerini redact edin. Gerçek özel
regresyonlar read-only ve yerel kalır; repository'ye yalnız deterministik
sentetik fixture ve testler eklenir.

Yerel harness ağ erişimini kapatır ve sınırları korur. İngilizce bölümdeki
`DAYI_PRIVATE_CORPUS`, `--timeout 180 --max-files 500`, `--anonymize`,
`--redact-flags` ve yerel kullanım için `--show-flags` seçenekleri geçerlidir.
Harness timeout, parser hatası, unsupported girdi ve eksik araçları ayrı
sınıflandırır. Çıkış durumu çözülen challenge sayısını değil harness veya
yapılandırma hatasını bildirir. Decoded payload çalıştırılmaz. Düzeltmeler
sentetik testlerle doğrulanmalı; özel challenge verisi fixture olmamalıdır.

---

## Lisans

Proje [MIT License](LICENSE) altında yayımlanır.

---

<div align="center">

Developed by [MacallanTheRoot](https://github.com/MacallanTheRoot)

**Dayı finds the evidence. You solve the challenge.**

</div>
