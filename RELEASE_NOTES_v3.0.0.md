# Dayı Stego Solver 3.0.0

Release status: prepared for a future tag and GitHub release. Version 3.0.0 has
not been marked as released by this document, and no release date is assigned.

## Overview

Dayı Stego Solver 3.0.0 is a major internal and CLI reliability release focused
on deterministic plugin execution, safer workspace and extraction handling,
inspectable installation and plugin state, maintainable commands, and verifiable
package artifacts. It retains a standard-library-only core and keeps optional
forensic runtimes and external steganography tools optional.

## Highlights

The preferred scan command now works with either conservative built-in flag
patterns or an exact user-supplied expression:

```bash
dayi scan challenge.png
dayi scan challenge.png --flag 'CUSTOM\{[^}]+\}'
```

Installation and registry state can be inspected without scanning a target:

```bash
dayi doctor
dayi doctor --json
dayi plugins list
dayi plugins list --json
```

Additional highlights include dynamic plugin discovery diagnostics, explicit
workspace-parent configuration, retained-artifact reporting, Python 3.10–3.13
CI configuration, archive-content validation, and clean wheel/sdist smoke tests.

## Installation

For users who have access to the Git repository:

```bash
git clone https://github.com/MacallanTheRoot/testrepo.git
cd testrepo
python -m pip install .
```

For an editable development installation:

```bash
python -m pip install -e '.[dev]'
```

For a wheel obtained from a trusted future release or successful CI artifact:

```bash
python -m pip install --no-deps dayi_stego_solver-3.0.0-py3-none-any.whl
```

No PyPI publication is asserted by these notes.

## Upgrade notes

- Prefer `dayi scan FILE`; legacy `dayi FILE` invocation remains supported and
  follows the same scan execution path.
- `--flag` is optional. Without it, Dayı matches only the documented built-in
  common prefixes. A custom regex replaces, rather than extends, that matcher.
- Default workspaces now live under the operating system temporary directory.
  Retained extraction paths therefore differ from older current-directory
  behavior.
- If automation expects workspaces beneath a particular parent, pass
  `--workspace-dir PATH`. Dayı creates a unique child rather than writing
  directly into that parent.
- Optional Python extras and external executables remain optional. Use
  `dayi doctor` and `dayi plugins list` to identify statically unavailable or
  scan-time-conditional capabilities.
- Retained extracted artifacts are untrusted and should be handled accordingly.

## New commands

```bash
dayi --version
dayi scan --help
dayi doctor
dayi doctor --json
dayi plugins list
dayi plugins list --json
```

`doctor` reports core and optional capability health. `plugins list` imports the
trusted package-local plugin modules to inspect the actual registry, but does
not execute plugin runners or external binaries.

## Security and reliability

Version 3.0.0 adds bounded subprocess-output retention, process-group timeout
termination, archive path and extraction limits, workspace boundary and symlink
protections, user-regex safety checks, bounded optional-parser processing, and
cancellation-safe partial reporting. These controls reduce risk when processing
hostile challenge files; they do not make extracted files, third-party parsers,
or external tools inherently trustworthy.

The release also fixes brute-force phase suppression, extraction-success false
positives based only on return codes, capture-group truncation, workspace
lifecycle errors, JSON output contamination, plugin discovery issue loss, and
distribution archive validation gaps.

## Compatibility

- Python requirement: `>=3.10`.
- Configured CI matrix: Python 3.10, 3.11, 3.12, and 3.13.
- Linux is the primary tested environment; the current workflow uses Linux
  runners and does not claim full Windows or macOS support.
- External tools are optional, format-specific, and platform-dependent.
- The core package has zero mandatory runtime dependencies.
- Doctor schema version: 1.
- Plugin inspection schema version: 1.

## Known limitations

- The built-in flag matcher recognizes only `CTF`, `FLAG`, `HTB`, `picoCTF`,
  and `THM` brace forms. Custom challenge formats require `--flag`.
- OCR, PDF, OLE/macro, PCAP, terminal UI, and integration capabilities depend on
  optional Python extras and, where applicable, external runtimes.
- Plugin discovery imports trusted modules shipped inside `dayi.tools`; it does
  not provide an untrusted third-party plugin sandbox.
- Retained extracted artifacts remain untrusted input.
- Doctor performs static availability and bounded version checks; it cannot
  prove that every tool works correctly for every target file.
- CI does not install or exercise external steganography binaries or optional
  Python forensic extras.

## Verification

Release-preparation baseline verified locally:

- 183 passed, 1 skipped.
- Pyflakes, compileall, and `git diff --check` completed successfully.
- Wheel and source distribution built and passed content/metadata validation.
- Clean wheel and source-distribution installations passed CLI smoke checks.
- Doctor and plugin-inspection JSON outputs passed syntax and invariant checks.
- The GitHub Actions workflow passed local `actionlint` validation.

The GitHub Actions Python 3.10–3.13 workflow is configured. These notes do not
claim that a remote GitHub Actions run has completed successfully.
