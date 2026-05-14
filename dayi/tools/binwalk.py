"""
dayi/tools/binwalk.py
~~~~~~~~~~~~~~~~~~~~~~
Async runner for `binwalk`: firmware/file analysis and embedded file extraction.

Binwalk extracts embedded files to a directory named '_<filename>.extracted'.
This module also scans that directory for flags after extraction.

FIXES applied in this version:
  1. findall() → finditer()+group(0) in stdout/stderr scanning to correctly
     handle user-supplied capture-group regex patterns.
  2. Extraction directory discovery is now robust: checks the standard
     binwalk naming convention first, then falls back to any subdirectory
     created during the run (not just the first one found).
  3. The temporary directory is cleaned up with shutil.rmtree() in a
     finally block to prevent disk space leaks on long-running sessions.
     The extracted_dir path is captured before cleanup and stored in the
     ToolResult for reporting purposes.
"""
import logging
import re
import shutil
import tempfile
from pathlib import Path

from dayi.reporter import ToolResult
from dayi.scanner import scan_directory
from dayi.tools._base import async_run_command, is_tool_available, make_skipped_result
from dayi.persona import TOOL_INTROS, TOOL_SKIP_MESSAGES, TOOL_SUCCESS_MESSAGES

logger = logging.getLogger("dayi")

TOOL_NAME = "binwalk"
BINARY    = "binwalk"


async def run_binwalk(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float = 120.0,
) -> ToolResult:
    """
    Run binwalk with extraction mode against the target file.

    Extracted files land in an isolated temporary directory. After extraction,
    that directory is recursively scanned for flag matches. The temporary
    directory is always cleaned up in a finally block regardless of outcome.

    Args:
        target:       Path to the target file.
        flag_pattern: Compiled regex pattern to search for flags.
        timeout:      Subprocess timeout in seconds.

    Returns:
        Populated ToolResult with extracted_dir (path before cleanup) and
        extracted_flags populated.
    """
    if not is_tool_available(BINARY):
        logger.warning(TOOL_SKIP_MESSAGES[TOOL_NAME])
        return make_skipped_result(
            TOOL_NAME,
            f"{BINARY} not found on PATH (sudo apt install binwalk)",
            [BINARY],
        )

    # Use mkdtemp so we control the cleanup timing ourselves
    tmpdir = Path(tempfile.mkdtemp(prefix="dayi_binwalk_"))

    try:
        # Copy target into tmpdir so binwalk writes all extractions relative to it
        target_copy = tmpdir / target.name
        shutil.copy2(target, target_copy)

        # -e: extract, -M: recursively matryoshka-extract, -q: quiet, -C: output dir
        cmd = [BINARY, "-e", "-M", "-q", "-C", str(tmpdir), str(target_copy)]

        logger.info(TOOL_INTROS[TOOL_NAME])
        rc, stdout, stderr, elapsed, timed_out = await async_run_command(
            cmd, TOOL_NAME, timeout, cwd=tmpdir
        )

        flags_from_output: list[str] = []
        extracted_flags:   dict[str, list[str]] = {}
        extracted_dir_str: str | None = None

        if not timed_out:
            logger.info(TOOL_SUCCESS_MESSAGES.get(TOOL_NAME, TOOL_SUCCESS_MESSAGES["default"]))

            # Fix: use finditer+group(0) to correctly handle capture-group patterns
            flags_from_output = list(dict.fromkeys(
                [m.group(0) for m in flag_pattern.finditer(stdout)] +
                [m.group(0) for m in flag_pattern.finditer(stderr)]
            ))

            # ── Robust extraction directory discovery ─────────────────────────
            # Binwalk's standard naming: _<filename>.extracted
            standard_extract = tmpdir / f"_{target_copy.name}.extracted"

            if standard_extract.exists() and standard_extract.is_dir():
                extract_dir = standard_extract
            else:
                # Fallback: collect ALL subdirectories created by binwalk
                # (it may use different names depending on version/content)
                subdirs = sorted(
                    [p for p in tmpdir.rglob("*") if p.is_dir() and p != tmpdir],
                    key=lambda p: len(p.parts),   # shortest path first = top-level dir
                )
                extract_dir = subdirs[0] if subdirs else tmpdir

            extracted_dir_str = str(extract_dir)
            logger.debug(f"[binwalk] Scanning extraction directory: {extract_dir}")

            extracted_flags = scan_directory(extract_dir, flag_pattern)

            if extracted_flags:
                total_flags = sum(len(v) for v in extracted_flags.values())
                logger.info(
                    f"[binwalk] Çıkarılan dosyalarda {total_flags} flag bulundu! "
                    f"Yeğenim içinden bir şeyler çıktı!"
                )
            else:
                logger.debug("[binwalk] No flags found in extracted directory.")

        all_flags = list(dict.fromkeys(
            flags_from_output + [f for hits in extracted_flags.values() for f in hits]
        ))

        return ToolResult(
            tool_name=TOOL_NAME,
            command=cmd,
            return_code=rc,
            stdout=stdout,
            stderr=stderr,
            flags_found=all_flags,
            elapsed_seconds=elapsed,
            timed_out=timed_out,
            extracted_dir=extracted_dir_str,
            extracted_flags=extracted_flags,
        )

    finally:
        # Always clean up the temporary directory to prevent disk leaks
        shutil.rmtree(tmpdir, ignore_errors=True)
        logger.debug(f"[binwalk] Cleaned up temporary directory: {tmpdir}")
