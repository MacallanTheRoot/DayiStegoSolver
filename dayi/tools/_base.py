"""
dayi/tools/_base.py
~~~~~~~~~~~~~~~~~~~~
Shared subprocess execution primitives used by all tool modules.

Provides:
  - FileType: enum of supported container formats detected via magic bytes
  - get_file_type(): header-based (not extension-based) format detection
  - async_run_command(): async subprocess with 10MB pipe buffer + robust zombie kill
  - is_tool_available(): shutil.which check for graceful skip
  - iter_wordlist_lines(): memory-efficient streaming line iterator
  - sanitize_token(): strip non-printable/control chars from mini-wordlist tokens
  - make_skipped_result(): factory for skipped ToolResult instances

ROBUSTNESS (Zombie Process Fix):
    After timeout, the subprocess kill sequence is:
      1. SIGTERM → give the process 2 seconds to clean up gracefully
      2. SIGKILL  → forcibly terminate if still alive after grace period
      3. proc.wait() wrapped in asyncio.wait_for(timeout=5s) → prevents
         wait() itself from blocking indefinitely on a zombified process.

ROBUSTNESS (Token Sanitization):
    sanitize_token() strips null bytes, control characters, and any
    non-printable bytes from mini-wordlist candidate strings before they
    are passed as subprocess arguments to steghide/outguess. This prevents
    binary garbage from strings/binwalk output from crashing those tools.
"""
import asyncio
import logging
import os
import shutil
import signal
import time
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional

from dayi.reporter import ToolResult

logger = logging.getLogger("dayi")

# 10 MB asyncio StreamReader buffer — prevents pipe deadlock on large outputs
PIPE_BUFFER_LIMIT: int = 10 * 1024 * 1024

# Number of bytes to read for magic byte detection
_MAGIC_READ_BYTES: int = 16

# Grace period between SIGTERM and SIGKILL during zombie-process cleanup
_KILL_GRACE_SECONDS: float = 2.0

# Timeout for proc.wait() after kill — guards against kernel-level zombie stalls
_WAIT_AFTER_KILL_SECONDS: float = 5.0


# ---------------------------------------------------------------------------
# File format detection via magic bytes (never trust extensions or MIME types)
# ---------------------------------------------------------------------------

class FileType(str, Enum):
    """
    Container format identified from the file's magic bytes.
    Tool compatibility is determined against this enum, not file extensions.
    """
    JPEG    = "JPEG"
    PNG     = "PNG"
    BMP     = "BMP"
    WAV     = "WAV"
    ZIP     = "ZIP"
    UNKNOWN = "UNKNOWN"


def get_file_type(path: Path) -> FileType:
    """
    Identify a file's format by reading its leading magic bytes.

    Never relies on file extensions or MIME type headers — those are trivially
    spoofed in CTF challenges. Reads up to 16 bytes from the file header and
    matches against known signatures.

    Supported signatures:
      - JPEG : FF D8 FF              (offset 0)
      - PNG  : 89 50 4E 47 0D 0A 1A 0A  (offset 0)
      - BMP  : 42 4D                 (offset 0, "BM")
      - WAV  : 52 49 46 46 ... 57 41 56 45  (RIFF at 0, WAVE at 8)
      - ZIP  : 50 4B 03 04           (offset 0, PK\\x03\\x04)

    Args:
        path: Path to the file to inspect.

    Returns:
        Detected FileType; FileType.UNKNOWN if no signature matches or file
        is unreadable.
    """
    try:
        header: bytes = path.read_bytes()[:_MAGIC_READ_BYTES]
    except OSError as exc:
        logger.debug(f"[get_file_type] Cannot read {path}: {exc}")
        return FileType.UNKNOWN

    if header[:3] == b"\xff\xd8\xff":
        return FileType.JPEG

    if header[:8] == b"\x89PNG\r\n\x1a\n":
        return FileType.PNG

    if header[:2] == b"BM":
        return FileType.BMP

    # WAV: RIFF at byte 0, WAVE at byte 8 (bytes 4–7 are file size, variable)
    if header[:4] == b"RIFF" and header[8:12] == b"WAVE":
        return FileType.WAV

    if header[:4] == b"PK\x03\x04":
        return FileType.ZIP

    return FileType.UNKNOWN


def describe_file_type(ft: FileType) -> str:
    """Return a human-readable Turkish label for use in Dayı persona log messages."""
    labels: dict[FileType, str] = {
        FileType.JPEG:    "JPEG",
        FileType.PNG:     "PNG",
        FileType.BMP:     "BMP",
        FileType.WAV:     "WAV",
        FileType.ZIP:     "ZIP",
        FileType.UNKNOWN: "bilinmeyen formatta",
    }
    return labels.get(ft, "bilinmeyen")


# ---------------------------------------------------------------------------
# Token sanitization for mini-wordlist entries
# ---------------------------------------------------------------------------

def sanitize_token(token: str) -> str | None:
    """
    Sanitize a candidate password token extracted from tool output.

    Removes or rejects strings that would corrupt subprocess argument lists:
      - Null bytes (\\x00) → terminate C strings inside subprocess exec
      - Control characters (\\x01–\\x1F, \\x7F) → can corrupt terminal/pipes
      - Non-printable Unicode → likely binary garbage from strings/binwalk output

    Args:
        token: Raw token string from mini-wordlist extraction.

    Returns:
        Sanitized token if it passes all checks, None if it should be discarded.
    """
    if not token:
        return None

    # Hard reject: null bytes are never valid in subprocess argument strings.
    # They terminate C strings and would silently truncate the password.
    if "\x00" in token:
        logger.debug(f"[sanitize_token] Discarded null-byte token: {token[:20]!r}")
        return None

    # Strip C0 control characters (0x01–0x1F) and DEL (0x7F).
    # Keep printable ASCII (0x20–0x7E) only.
    cleaned = "".join(
        ch for ch in token
        if 0x20 <= ord(ch) <= 0x7E
    )

    # Discard if more than 20% of the original characters were stripped —
    # indicates binary garbage mixed into a text field.
    if not cleaned:
        return None

    original_len = len(token)
    if len(cleaned) < original_len * 0.8:
        logger.debug(
            f"[sanitize_token] Discarded high-entropy token "
            f"(original={original_len}, cleaned={len(cleaned)}): {token[:20]!r}"
        )
        return None

    # Minimum length guard (5 chars — same floor as mini-WL token regex)
    if len(cleaned) < 5:
        return None

    return cleaned


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

def is_tool_available(binary_name: str) -> bool:
    """
    Check whether a binary is present on the system PATH.

    Args:
        binary_name: Executable name (e.g. 'exiftool', 'zsteg').

    Returns:
        True if found, False otherwise.
    """
    return shutil.which(binary_name) is not None


async def _kill_process_robustly(proc: asyncio.subprocess.Process, tool_name: str) -> None:
    """
    Terminate a subprocess using a SIGTERM → SIGKILL escalation sequence.

    This two-step approach gives well-behaved processes a chance to perform
    cleanup before being forcibly killed. The subsequent proc.wait() call is
    wrapped in its own timeout to prevent blocking on kernel-level zombies.

    Args:
        proc:      The asyncio subprocess to terminate.
        tool_name: Tool name for log context.
    """
    pid = proc.pid

    # Step 1: SIGTERM — polite request to terminate
    try:
        os.kill(pid, signal.SIGTERM)
        logger.debug(f"[{tool_name}] SIGTERM sent to PID {pid}")
    except (ProcessLookupError, OSError):
        pass  # Process already exited

    # Step 2: Wait briefly for graceful shutdown
    try:
        await asyncio.wait_for(proc.wait(), timeout=_KILL_GRACE_SECONDS)
        logger.debug(f"[{tool_name}] Process {pid} exited after SIGTERM")
        return
    except asyncio.TimeoutError:
        pass  # Did not exit gracefully; escalate to SIGKILL

    # Step 3: SIGKILL — forcible termination
    try:
        proc.kill()
        logger.debug(f"[{tool_name}] SIGKILL sent to PID {pid}")
    except (ProcessLookupError, OSError):
        pass

    # Step 4: Reap the process with a hard timeout to avoid zombie accumulation
    try:
        await asyncio.wait_for(proc.wait(), timeout=_WAIT_AFTER_KILL_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(
            f"[{tool_name}] PID {pid} nem SIGTERM'e ne SIGKILL'e uymadı. "
            f"Zombi süreç olabilir, işletim sistemi halleder onu..."
        )


async def async_run_command(
    cmd: list[str],
    tool_name: str,
    timeout: float = 60.0,
    cwd: Optional[Path] = None,
    stdin_data: Optional[bytes] = None,
) -> tuple[int | None, str, str, float, bool]:
    """
    Execute a subprocess asynchronously, capturing stdout and stderr.

    The StreamReader limit is set to PIPE_BUFFER_LIMIT (10 MB) to prevent
    deadlocks on tools that produce very large outputs.

    On timeout, a robust SIGTERM → SIGKILL → wait sequence is used instead
    of a bare kill() call to prevent zombie process accumulation.

    Args:
        cmd:        Command list to execute.
        tool_name:  Human-readable tool name for logging.
        timeout:    Maximum seconds to wait before killing the process.
        cwd:        Optional working directory for the subprocess.
        stdin_data: Optional bytes to pipe into stdin.

    Returns:
        Tuple of (return_code, stdout, stderr, elapsed_seconds, timed_out).
        return_code is None if the process timed out or failed to start.
    """
    start = time.monotonic()
    timed_out = False
    rc: int | None = None
    stdout_str = ""
    stderr_str = ""

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            limit=PIPE_BUFFER_LIMIT,
        )

        try:
            raw_stdout, raw_stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data),
                timeout=timeout,
            )
            rc = proc.returncode
            stdout_str = raw_stdout.decode("utf-8", errors="replace")
            stderr_str = raw_stderr.decode("utf-8", errors="replace")

        except asyncio.TimeoutError:
            timed_out = True
            logger.warning(
                f"[{tool_name}] Süre doldu! ({timeout}s) — "
                f"prosesi kademeli olarak öldürüyorum yeğenim..."
            )
            await _kill_process_robustly(proc, tool_name)

    except FileNotFoundError:
        # Defensive guard; should not occur after is_tool_available() check.
        logger.debug(f"[{tool_name}] FileNotFoundError: binary not on PATH.")

    elapsed = time.monotonic() - start
    return rc, stdout_str, stderr_str, elapsed, timed_out


# ---------------------------------------------------------------------------
# Memory-efficient wordlist streaming
# ---------------------------------------------------------------------------

def iter_wordlist_lines(wordlist_path: Path, limit: int = 0) -> Iterator[str]:
    """
    Memory-efficient streaming line iterator over a wordlist file.

    Reads one line at a time — never loads the entire file into RAM.
    Critical for large wordlists like rockyou.txt (~134 MB).

    Args:
        wordlist_path: Path to the plaintext wordlist file.
        limit:         Maximum number of lines to yield. 0 = unlimited.

    Yields:
        Stripped, non-empty password strings.
    """
    count = 0
    try:
        with open(wordlist_path, encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                word = raw_line.rstrip("\n\r")
                if not word:
                    continue
                yield word
                count += 1
                if limit and count >= limit:
                    break
    except OSError as exc:
        logger.error(f"[wordlist] Could not open {wordlist_path}: {exc}")


# ---------------------------------------------------------------------------
# ToolResult factory helpers
# ---------------------------------------------------------------------------

def make_skipped_result(tool_name: str, reason: str, cmd: list[str] | None = None) -> ToolResult:
    """
    Construct a ToolResult representing a skipped tool run.

    Args:
        tool_name: Name of the tool that was skipped.
        reason:    Human-readable explanation for the skip.
        cmd:       The command that would have been run.

    Returns:
        A ToolResult with skipped=True.
    """
    return ToolResult(
        tool_name=tool_name,
        command=cmd or [],
        return_code=None,
        stdout="",
        stderr="",
        flags_found=[],
        elapsed_seconds=0.0,
        skipped=True,
        skip_reason=reason,
    )
