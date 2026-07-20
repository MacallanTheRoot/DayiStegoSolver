# Dayı Stego Solver 4.5.1

Release candidate prepared on 2026-07-20. Tagging and publication remain
separate release steps.

Dayı Stego Solver 4.5.1 is a minimal compatibility patch for
https://github.com/MacallanTheRoot/DayiStegoSolver.

## Fixed

- Restored Python 3.10 and 3.11 test-suite parsing compatibility by moving an
  escaped WordprocessingML literal out of an f-string expression.
- Preserved the exact synthetic DOCX fixture bytes and test intent.

## Compatibility and behavior

- Steganography detection and runtime scanning behavior are unchanged.
- The deterministic registry remains at 22 plugins, including 12 operations in
  the `CONCURRENT` phase.
- Python support remains CPython 3.10 through 3.13.
- Optional dependencies continue to degrade cleanly when unavailable.
- Version 4.5.1 supersedes 4.5.0 for source and CI validation; the 4.5.0 tag,
  release notes, and release history remain intact.

Detection remains bounded and heuristic. This patch does not claim perfect
detection, complete sandboxing, or universal CTF challenge coverage.
