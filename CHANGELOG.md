# Changelog

All notable changes to Dayı Stego Solver are documented here.

## [Unreleased]

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

[Unreleased]: https://github.com/MacallanTheRoot/DayiStegoSolver/compare/v4.1.0...HEAD
[4.1.0]: https://github.com/MacallanTheRoot/DayiStegoSolver/compare/v4.0.0...v4.1.0
[4.0.0]: https://github.com/MacallanTheRoot/DayiStegoSolver/releases/tag/v4.0.0
