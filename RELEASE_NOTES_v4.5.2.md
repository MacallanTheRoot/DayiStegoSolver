# Dayı Stego Solver 4.5.2

Prepared on 2026-11-26.

Dayı Stego Solver 4.5.2 is a stability patch for
https://github.com/MacallanTheRoot/DayiStegoSolver. It ships the fixes merged
since 4.5.1 together with two small corrections found during release review.

## Behavior change: stop after the first confirmed flag

Once any plugin reports a confirmed flag (in its output or in extracted
files), Dayı stops the scan:

- still-running `CONCURRENT` plugins are cancelled and their subprocesses and
  temporary files are cleaned up;
- the archive, mini-wordlist and main-wordlist phases are not started;
- the TXT/JSON/Markdown reports, CTFd/Discord integrations and retained
  workspace artifacts are still produced from the results collected so far.

What this means for you:

- Scans that find a flag usually finish sooner and run fewer brute-force
  attempts.
- A report may list fewer tools. Plugins that were cancelled or never started
  do not appear in it.
- If a challenge hides more than one flag, or the first match is a decoy,
  later findings are not collected. 4.5.2 has no full-scan mode and no
  option to turn the early stop off.

## Fixed

- Flags in external-tool output (strings, exiftool, exiv2, binwalk, steghide,
  stegseek, zsteg, OutGuess) are found while the output is drained. Flags past
  the retained 10 MiB prefix and flags printed before a timeout are kept. The
  stream each flag came from is shown in a new `stream_flags` report field.
- A plugin that raises a timeout error is reported as timed out, not as an
  unexpected error.
- QR and OCR reliability: QR checks for supported images before choosing a
  backend; OpenCV worker threads are limited in one shared helper; OCR adds a
  bounded high-zoom band variant for large images and a small, regex-gated
  repair set for common misreads (`!` for `i`, punctuation for `_`, flag
  prefix case).
- Text steganography: case-as-bit binary ASCII, SNOW-style trailing
  whitespace and more whitespace-binary layouts, all behind a strict printable
  filter and per-stream candidate cap.
- File-type detection reads a bounded 4 KiB prefix and recognizes UTF-8 text,
  so image-only tools skip text files.
- `dayi doctor` reports Python 3.14 and newer as unsupported, matching the
  package's declared range, and its text output shows the maximum supported
  version. On those versions it now exits 1 instead of 0.

## Security

- `--flag` patterns are also checked on the parsed regex. Variable-count
  repeats or alternations nested inside a variable-count repeat are rejected,
  as are fixed-count repeats whose nested choices multiply past 256. This
  closes bypasses such as `(a{1,})+b`, `(?:a{1,40}){1,40}b`, `((a+))+b` and
  `(?:a?){30}b`. Patterns such as `(?:\d{1,3}\.){3}\d{1,3}` and
  `CTF\{(?:[0-9a-f]{2}){16}\}` are still accepted.
  Rejected patterns produce the existing invalid-pattern error and exit 1.
- A `--flag` pattern with an oversized repeat count now produces the same
  invalid-pattern error instead of a Python traceback.
- This check is a heuristic. It does not make arbitrary user regexes safe:
  some super-linear patterns are still accepted, and matching runs in-process
  without a time limit. Accepted examples include adjacent unbounded repeats
  such as `\d+\d+\d+x` and optional items written out one after another
  (`a?a?a?…aaa…`); 4.5.1 accepted them too. Prefer simple patterns with a
  literal prefix, such as `CTF\{[^}]+\}`.

## Compatibility

- Python support remains CPython 3.10 through 3.13.
- The core has no mandatory runtime dependencies; optional dependencies keep
  degrading cleanly when unavailable.
- The deterministic registry remains at 22 plugins, including 12 operations in
  the `CONCURRENT` phase.
- CLI options, the `dayi` entry point and the doctor and plugin JSON schemas
  (`schema_version` 1) are unchanged. Scan exit codes keep their meaning
  (0, 1, 130), but a `--flag` pattern that 4.5.1 accepted may now be rejected
  and exit 1 (see Security). The scan JSON report gains the additive
  `stream_flags` field.

## Known limitations

- No full-scan mode: the scan always stops after the first confirmed flag.
- Thread-based work (binwalk post-processing, QR and OCR decoding) cannot be
  interrupted, so the early stop and Ctrl+C may wait for it to finish.
- Files and outputs above the documented size limits are still skipped or
  truncated without a note in the report.

Detection remains bounded and heuristic. This patch does not claim perfect
detection, complete sandboxing, or universal CTF challenge coverage.
