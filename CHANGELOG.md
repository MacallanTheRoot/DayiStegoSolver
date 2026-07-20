# Changelog

All notable changes to Dayı Stego Solver are documented here.

## [Unreleased]

## [4.5.0] - 2026-07-20

Release candidate prepared on 2026-07-20. Tagging and publication remain
separate release steps.

### Added

- Added bounded extraction-evidence validation for OutGuess output, including a
  single known-invalid baseline per target.
- Added controlled `rockyou.txt` resolution, streamed `.gz` wordlists, and the
  optional `--require-wordlist` strict mode.
- Added confidence-aware domain classification with verbose-only possible
  findings and deterministic synthetic regressions.
- Added the core-only `text_stego_scanner` plugin with byte-based UTF/ASCII
  detection, immutable confidence-scored candidates, and decoder-chain flag
  attribution.
- Added bounded Bacon, whitespace, zero-width/invisible Unicode, homoglyph,
  acrostic/structural, ghost-text, and common nested text decoders.
- Added the core-only `document_stego_scanner` for content-detected DOCX and
  DOCM packages, with bounded OpenXML text, hidden-style, revision, comment,
  note, header/footer, metadata, alt-text, field, and relationship analysis.
- Added bounded local extraction and recursive inspection for Word media and
  embedded objects, including handoff to compatible metadata, strings, image,
  OCR, artifact, and text-steganography scanners.
- Extended the same core document plugin to content-detected XLSX/XLSM,
  PPTX/PPTM, ODT/ODS/ODP, and bounded RTF, including hidden sheets/slides,
  comments, notes, annotations, metadata, style channels, media, and objects.
- Added passive spreadsheet formula/name, presentation drawing/alt-text,
  OpenDocument concealment, and RTF group/control-word analysis.
- Added bounded multi-pass OCR with deterministic preprocessing, structured
  confidence data, variant consensus, nested text decoding, `--ocr-lang`, and
  the optional bounded `--ocr-exhaustive` mode.
- Added the passive `qr_scanner` with OpenCV, pyzbar, and zbarimg backend
  priority, payload classification, nested decoding, and bounded image
  recursion for target, carved, and document-extracted media.
- Added a local-only private regression harness with external-path validation,
  optional manifests, deterministic anonymization, default flag redaction,
  bounded child-process scans, and JSON/Markdown aggregate summaries.

### Changed

- Mini brute-force success now requires verified extracted content instead of a
  tool return code or output-file existence alone.
- Wordlist lookup is limited to the requested path, the current directory, and
  the standard Kali `rockyou.txt`/`rockyou.txt.gz` locations.
- Default artifact output now includes confirmed and probable domain findings;
  possible findings require verbose mode and noise remains suppressed.
- Registered text steganography as the twentieth deterministic plugin and as a
  network-free core capability in `dayi doctor`.
- Registered Word/OpenXML document steganography as the twenty-first
  deterministic plugin and a separate network-free core doctor capability.
- Kept the plugin count at 21 by extending `document_stego_scanner` through the
  shared bounded package and recursive-artifact pipeline.
- Expanded content-based image discovery to PNG, JPEG, BMP, GIF, TIFF, WebP,
  and PNM and registered passive QR analysis as the twenty-second plugin.
- Moved the existing text-stego adapter to archive priority 12 so target text
  and bounded text artifacts extracted by document, binwalk, and ZIP stages are
  analyzed through the same decoder without adding another plugin.

### Fixed

- Prevented OutGuess false-positive output from reporting a recovered password
  or suppressing later StegSeek, Steghide, and OutGuess fallback attempts.
- Suppressed random short JPEG/compressed-data tokens that resembled domains
  while preserving contextual domains and full HTTP/HTTPS URLs.
- Fixed carved text payloads being created after the text-stego plugin had
  already finished, and preserved plugin error/extraction state in JSON for
  deterministic regression classification.
- Rejected unsafe image dimensions before OpenCV QR decoding, enforced the
  absolute OCR deadline before every pass, and preserved raw binary zbarimg
  payload bytes without UTF-8 replacement.
- Moved document and text parsers to killable spawned workers, isolated nested
  document extraction namespaces, and resolved ODF media references before
  orphan classification.
- Accepted both headless and desktop OpenCV distribution metadata in doctor
  while still validating the `QRCodeDetector` API.
- Made QR preprocessing lazy under aggregate pixel/byte budgets and moved
  urllib notifications behind a killable total-deadline worker.
- Preserved bounded direct flags beyond text candidate previews, corrected
  Word paragraph/run style precedence, normalized root-relative spreadsheet
  and presentation relationships, and consumed complete RTF Unicode fallback
  tokens.
- Normalized RTF surrogate pairs, read hidden PowerPoint state from slide XML,
  and propagated nested RTF/document artifacts into downstream image analysis.
- Moved native OpenCV and pyzbar decoding into killable workers, made OCR
  preprocessing lazy under aggregate budgets, and bounded zbarimg by the
  remaining QR deadline.
- Required a usable known-invalid OutGuess baseline, scanned direct flags across
  the complete retained text window, and preserved per-flag OCR decoder chains.
- Excluded private expectation manifests from corpus discovery, preserved
  confirmed document flags at the finding limit, and retained exact OCR
  attribution beyond the displayed-finding cap.

### Security

- Bounded text inspection to 8 MiB, analysis to 4 million decoded characters,
  candidate outputs to 64 KiB, recursion to depth 3, and aggregate decoded data
  to 16 MiB.
- Escaped ANSI, bidi, format, carriage-return, and control characters before
  terminal or report output; text decoding remains local and network-free.
- Added traversal, symlink, collision, compression-ratio, member-count,
  expanded-size, XML node/text, media/object, recursive-byte, and recursion-depth
  limits for OpenXML analysis. External relationships and macros are inspected
  only as passive data and are never fetched or executed.
- Added bounded RTF group, control-word, decoded-text, picture, and object
  parsing. Spreadsheet formulas and Office/ODF active content remain passive;
  no relationship is resolved or fetched.
- Bounded image files, pixels, dimensions, frames, discovered images, OCR/QR
  variants, OCR invocations and timeouts, payload bytes, and recursive decoded
  images. QR URLs and command-like payloads are classified only and are never
  opened or executed; ANSI/bidi/control data is escaped before reporting.
- Parser timeouts terminate and reap their isolated child process; OpenCV image
  decode begins only after bounded metadata validation. The zbarimg fallback
  uses a one-symbol raw-byte mode because newline framing is ambiguous for
  multiple binary symbols.
- QR transformations are decoded and released one at a time under a 150-million
  generated-pixel and 256 MiB estimated-work budget. Urllib notification
  connection and response work is terminated at the total notification
  deadline rather than relying only on per-socket timeouts.
- Private regression runs reject repository-local corpora and outputs, symlinked
  roots, manifest traversal, malformed expectations, oversized reports, and
  existing summary destinations. Full flags are redacted unless explicitly
  requested and transient full reports are deleted after each local scan.

## [4.1.0] - 2026-07-19

### Added

- Added a safe optional resolver for the `csl-ctfshitcli` rich Markdown
  exporter, including `--ctfshit-path` and `DAYI_CTFSHIT_PATH` selection.
- Added native CTFd and Discord delivery with field-specific notification
  environment variables.
- Added network-free doctor diagnostics for native notification transport and
  local channel configuration.
- Added `python -m dayi` as a package entry point.
- Added deterministic resolver, notification, doctor, security,
  documentation, and distribution tests.

### Changed

- Changed StegSeek eligibility to use detected JPEG/BMP/WAV carrier content
  instead of filename extensions.
- Limited ctfshit integration to rich writeup export; notification delivery is
  now entirely native.
- Made CTFd and Discord delivery independent so one channel cannot retry or
  suppress the other.
- Applied CLI-over-environment precedence independently to each notification
  setting.
- Corrected the English and Turkish README integration documentation.
- Separated ctfshit writeup and native notification capabilities in doctor
  output.

### Security

- Blocked redirects and added bounded total, connection, and read timeouts for
  notification requests.
- Bounded CTFd response reads and rejected malformed, oversized, or structurally
  invalid responses.
- Added strict network-free URL validation for schemes, hostnames, userinfo,
  query strings, fragments, and duplicated CTFd submission paths.
- Kept credentials, endpoint details, response bodies, and delivery exceptions
  out of logs, reports, doctor output, and `DeliveryResult` values.
- Added resolver checks for checkout boundaries, distribution ownership,
  symlinks, and isolated module loading.
- Limited StegSeek's project-URL suppression to artifact-scanning copies of its
  stdout and stderr.

### Fixed

- Removed invalid legacy ctfshit notification imports.
- Prevented an HTTP 200 CTFd response with an incorrect submission status from
  being treated as success.
- Fixed the missing module entry point for `python -m dayi`.
- Prevented renamed unsupported files from invoking StegSeek.
- Contained ordinary notification failures so completed scans and their exit
  codes remain valid.

## [4.0.0] - 2026-07-18

Version 4.0.0 was released on 2026-07-18. This release follows the earlier
v3-era production history and brings the fully audited maintenance line into
the production repository.

### Added

- Added the explicit `dayi scan` command while preserving legacy flat scan
  invocation.
- Added a conservative built-in matcher for common CTF flag prefixes, with an
  optional custom `--flag` override.
- Added `dayi --version` using the package's authoritative runtime version.
- Added dependency-free `dayi doctor` diagnostics with isolated JSON output.
- Added `dayi plugins list` registry inspection with deterministic JSON output.
- Added configurable workspace parents through `--workspace-dir`.
- Added structured dynamic-plugin discovery diagnostics and static availability
  reporting.
- Added retained-workspace reporting for useful extracted artifacts.
- Added GitHub Actions CI for Python 3.10, 3.11, 3.12, and 3.13.
- Added wheel and source-distribution content validation, clean-install smoke
  tests, and installed-command JSON integrity checks.

### Changed

- Moved default per-scan workspaces from the current directory to operating
  system temporary storage.
- Corrected the distribution identity, author, repository URLs, and runtime
  version consistency while setting the production release to version 4.0.0.
- Changed the development classifier from Production/Stable to Beta.
- Modernized MIT license metadata and included the license in distributions.
- Made executable and Python-module plugin requirements declarative.
- Added flag-pattern display and source metadata to reports.
- Organized the CLI around `scan`, `doctor`, and `plugins` top-level commands.
- Kept the core and installed diagnostic commands usable with zero mandatory
  runtime dependencies.

### Fixed

- Prevented redundant main brute-force work after genuine mini-wordlist success.
- Prevented a zero tool return code alone from being treated as successful
  extraction.
- Preserved full regex matches when custom patterns contain capture groups.
- Corrected temporary-workspace cleanup and retention on completion, failure,
  and cancellation.
- Prevented outside-workspace or symlinked paths from being treated as managed
  retained output.
- Corrected package URL and version drift across metadata and runtime output.
- Kept doctor and plugin JSON output free from normal banners and log prose.
- Retained structured plugin discovery and validation issues for inspection.
- Closed distribution validation gaps involving traversal entries, duplicate or
  forbidden members, missing metadata, and stale archives.

### Security

- Bounded retained subprocess output and strengthened process-group termination
  and reaping after timeout.
- Enforced archive path validation, extraction limits, and workspace boundary
  checks without following extraction symlinks.
- Added regular-expression safety checks for user-supplied flag patterns.
- Bounded file reads and optional OCR, PDF, OLE, and PCAP parser workloads.
- Preserved partial reporting and managed-workspace cleanup during cancellation.

These measures reduce exposure to hostile CTF inputs; they are not a guarantee
that every file, parser, optional dependency, or external executable is safe.

[Unreleased]: https://github.com/MacallanTheRoot/DayiStegoSolver/compare/v4.5.0...HEAD
[4.5.0]: https://github.com/MacallanTheRoot/DayiStegoSolver/compare/v4.1.0...v4.5.0
[4.1.0]: https://github.com/MacallanTheRoot/DayiStegoSolver/compare/v4.0.0...v4.1.0
[4.0.0]: https://github.com/MacallanTheRoot/DayiStegoSolver/releases/tag/v4.0.0
