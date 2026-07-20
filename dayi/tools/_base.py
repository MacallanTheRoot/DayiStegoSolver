"""
dayi/tools/_base.py
~~~~~~~~~~~~~~~~~~~~
Shared subprocess execution primitives used by all tool modules.

Provides:
  - FileType: enum of supported container formats detected via magic bytes
  - get_file_type(): header-based (not extension-based) format detection
  - async_run_command(): async subprocess with bounded output + robust tree cleanup
  - is_tool_available(): shutil.which check for graceful skip
  - iter_wordlist_lines(): memory-efficient streaming line iterator
  - sanitize_token(): strip non-printable/control chars from mini-wordlist tokens
  - make_skipped_result(): factory for skipped ToolResult instances

ROBUSTNESS (Zombie Process Fix):
    Each POSIX tool starts in a new session. Timeout or cancellation signals
    the entire process group, escalates from SIGTERM to SIGKILL, and always
    awaits the direct child so descendants and zombies cannot leak.

ROBUSTNESS (Token Sanitization):
    sanitize_token() strips null bytes, control characters, and any
    non-printable bytes from mini-wordlist candidate strings before they
    are passed as subprocess arguments to steghide/outguess. This prevents
    binary garbage from strings/binwalk output from crashing those tools.
"""
import asyncio
import gzip
import logging
import multiprocessing
import os
import pickle
import shutil
import signal
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, TypeVar

from dayi.reporter import ToolResult

logger = logging.getLogger("dayi")

# Retain at most 10 MiB from each subprocess stream while continuing to drain it.
PIPE_OUTPUT_LIMIT: int = 10 * 1024 * 1024
PIPE_BUFFER_LIMIT: int = 64 * 1024
MAX_WORDLIST_LINE_CHARS: int = 1_024

# Number of bytes to read for magic byte detection
_MAGIC_READ_BYTES: int = 16

# Grace period between SIGTERM and SIGKILL during zombie-process cleanup
_KILL_GRACE_SECONDS: float = 2.0

# Timeout for proc.wait() after kill — guards against kernel-level zombie stalls
_ISOLATED_MEMORY_BYTES = 768 * 1024 * 1024
_ISOLATED_REQUEST_BYTES = 1024 * 1024
_ISOLATED_RESPONSE_BYTES = 64 * 1024 * 1024
_ISOLATED_POLL_SECONDS = 0.01
_ISOLATED_KILL_GRACE_SECONDS = 0.25
_T = TypeVar("_T")


def _isolated_worker_entry(
    connection: Any,
    worker: Callable[..., Any],
    args: tuple[Any, ...],
    memory_bytes: int,
    cpu_seconds: int,
    max_response_bytes: int,
) -> None:
    """Execute a parser worker under resource limits and bounded IPC."""
    sink = None
    try:
        if os.name == "posix":
            os.setsid()
            try:
                import resource

                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
                resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024 * 1024,) * 2)
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            except (ImportError, OSError, ValueError):
                pass
        sink = open(os.devnull, "w", encoding="utf-8")
        sys.stdout = sink
        sys.stderr = sink
        message: tuple[bool, Any] = (True, worker(*args))
    except BaseException as exc:
        message = (False, exc)
    try:
        payload = pickle.dumps(message, protocol=pickle.HIGHEST_PROTOCOL)
        if len(payload) > max_response_bytes:
            payload = pickle.dumps(
                (False, RuntimeError("isolated worker response exceeded limit")),
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        connection.send_bytes(payload)
    except Exception:
        pass
    finally:
        connection.close()
        if sink is not None:
            sink.close()


def _stop_isolated_process(process: multiprocessing.Process) -> None:
    """Terminate, kill, and reap one isolated worker without leaving children."""
    if not process.is_alive():
        process.join(timeout=_ISOLATED_KILL_GRACE_SECONDS)
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            process.terminate()
    else:
        process.terminate()
    process.join(timeout=_ISOLATED_KILL_GRACE_SECONDS)
    if process.is_alive():
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
        else:
            process.kill()
        process.join(timeout=1.0)


async def async_run_isolated(
    worker: Callable[..., _T],
    *args: Any,
    timeout: float,
    memory_bytes: int = _ISOLATED_MEMORY_BYTES,
    max_response_bytes: int = _ISOLATED_RESPONSE_BYTES,
) -> _T:
    """Run one parser in a spawn-compatible, killable bounded process."""
    bounded_timeout = max(0.01, timeout)
    bounded_response = max(1024, max_response_bytes)
    try:
        request_size = len(
            pickle.dumps((worker, args), protocol=pickle.HIGHEST_PROTOCOL)
        )
    except (pickle.PickleError, TypeError, AttributeError) as exc:
        raise TypeError("isolated worker request is not serializable") from exc
    if request_size > _ISOLATED_REQUEST_BYTES:
        raise ValueError("isolated worker request exceeded limit")
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_isolated_worker_entry,
        args=(
            child,
            worker,
            args,
            memory_bytes,
            max(1, int(bounded_timeout) + 1),
            bounded_response,
        ),
        daemon=True,
    )
    try:
        process.start()
        child.close()
        deadline = time.monotonic() + bounded_timeout
        while not parent.poll():
            if not process.is_alive():
                if parent.poll():
                    break
                raise RuntimeError("isolated worker exited without a response")
            if time.monotonic() >= deadline:
                raise asyncio.TimeoutError
            await asyncio.sleep(
                min(_ISOLATED_POLL_SECONDS, max(0.0, deadline - time.monotonic()))
            )
        payload = parent.recv_bytes(bounded_response)
        message = pickle.loads(payload)
    except BaseException:
        if process.pid is not None:
            _stop_isolated_process(process)
        raise
    finally:
        parent.close()
        child.close()
    process.join(timeout=_ISOLATED_KILL_GRACE_SECONDS)
    if process.is_alive():
        _stop_isolated_process(process)
    if not message[0]:
        exception = message[1]
        if isinstance(exception, BaseException):
            raise exception
        raise RuntimeError("isolated worker failed without an exception")
    return message[1]


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
        with path.open("rb") as source:
            header = source.read(_MAGIC_READ_BYTES)
    except OSError as exc:
        logger.debug(f"[get_file_type] Dosyanın başı okunamadı yeğenim ({path}): {exc}")
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
        logger.debug(f"[sanitize_token] NUL içeren adayı eledim yeğenim: {token[:20]!r}")
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
            f"[sanitize_token] Fazla gürültülü adayı eledim yeğenim "
            f"(asıl={original_len}, temiz={len(cleaned)}): {token[:20]!r}"
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


def _signal_process_tree(
    proc: asyncio.subprocess.Process,
    sig: signal.Signals,
) -> None:
    """Signal a subprocess group on POSIX or the direct child elsewhere."""
    if os.name == "posix":
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass
        return

    try:
        if sig == signal.SIGTERM:
            proc.terminate()
        else:
            proc.kill()
    except (ProcessLookupError, OSError):
        pass


async def _kill_process_robustly(
    proc: asyncio.subprocess.Process,
    tool_name: str,
) -> None:
    """
    Terminate a subprocess using a SIGTERM → SIGKILL escalation sequence.

    This two-step approach gives well-behaved processes a chance to perform
    cleanup before being forcibly killed. The direct child is always awaited
    after escalation so it cannot remain as a zombie.

    Args:
        proc:      The asyncio subprocess to terminate.
        tool_name: Tool name for log context.
    """
    pid = proc.pid

    # Signal the complete process group. Tools such as binwalk may leave child
    # extractors behind when only the immediate PID is terminated.
    _signal_process_tree(proc, signal.SIGTERM)
    logger.debug(f"[{tool_name}] PID {pid} süreç grubuna SIGTERM gönderildi.")

    # Step 2: Wait briefly for graceful shutdown
    try:
        await asyncio.wait_for(asyncio.shield(proc.wait()), timeout=_KILL_GRACE_SECONDS)
    except asyncio.TimeoutError:
        pass

    # Even when the direct child exited, descendants may still own the group.
    _signal_process_tree(proc, signal.SIGKILL)
    logger.debug(f"[{tool_name}] PID {pid} süreç grubuna SIGKILL gönderildi.")

    # A killed direct child must always be reaped. Shielding prevents a second
    # cancellation from interrupting zombie cleanup.
    await asyncio.shield(proc.wait())


async def _read_stream_bounded(
    stream: asyncio.StreamReader | None,
    retained_limit: int,
) -> tuple[bytes, bool]:
    """Drain one subprocess stream while retaining only a bounded prefix."""
    if stream is None:
        return b"", False
    retained = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(PIPE_BUFFER_LIMIT)
        if not chunk:
            break
        remaining = retained_limit - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0):
            truncated = True
    return bytes(retained), truncated


async def _write_stdin(
    stream: asyncio.StreamWriter | None,
    data: bytes | None,
) -> None:
    """Write optional subprocess input and close its pipe safely."""
    if stream is None:
        return
    try:
        if data:
            stream.write(data)
            await stream.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        stream.close()
        try:
            await stream.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def async_run_command_bytes(
    cmd: list[str],
    tool_name: str,
    timeout: float = 60.0,
    cwd: Optional[Path] = None,
    stdin_data: Optional[bytes] = None,
    *,
    stdout_limit: int | None = None,
    stderr_limit: int | None = None,
) -> tuple[int | None, bytes, bytes, float, bool, bool, bool]:
    """
    Execute a subprocess while preserving bounded stdout and stderr bytes.

    Both pipes are continuously drained in small chunks while only a bounded
    prefix is retained, preventing deadlocks and unbounded output growth.

    On timeout, a robust SIGTERM → SIGKILL → wait sequence is used instead
    of a bare kill() call to prevent zombie process accumulation.

    Args:
        cmd:        Command list to execute.
        tool_name:  Human-readable tool name for logging.
        timeout:    Maximum seconds to wait before killing the process.
        cwd:        Optional working directory for the subprocess.
        stdin_data: Optional bytes to pipe into stdin.

    The final booleans report stdout and stderr truncation. Callers handling
    binary protocols must reject truncated records rather than decode a prefix.
    """
    start = time.monotonic()
    stdout_limit = PIPE_OUTPUT_LIMIT if stdout_limit is None else stdout_limit
    stderr_limit = PIPE_OUTPUT_LIMIT if stderr_limit is None else stderr_limit
    timed_out = False
    rc: int | None = None
    raw_stdout = b""
    raw_stderr = b""
    stdout_truncated = False
    stderr_truncated = False

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=(
                asyncio.subprocess.PIPE
                if stdin_data is not None
                else asyncio.subprocess.DEVNULL
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            limit=PIPE_BUFFER_LIMIT,
            start_new_session=os.name == "posix",
        )

        stdout_task = asyncio.create_task(
            _read_stream_bounded(proc.stdout, max(0, stdout_limit))
        )
        stderr_task = asyncio.create_task(
            _read_stream_bounded(proc.stderr, max(0, stderr_limit))
        )
        stdin_task = asyncio.create_task(_write_stdin(proc.stdin, stdin_data))

        try:
            await asyncio.wait_for(
                asyncio.shield(proc.wait()),
                timeout=timeout,
            )
            rc = proc.returncode

        except asyncio.TimeoutError:
            timed_out = True
            logger.warning(
                f"[{tool_name}] Süre doldu! ({timeout}s) — "
                f"prosesi kademeli olarak öldürüyorum yeğenim..."
            )
            await _kill_process_robustly(proc, tool_name)
        except asyncio.CancelledError:
            await _kill_process_robustly(proc, tool_name)
            raise
        finally:
            await asyncio.shield(stdin_task)
            raw_stdout, stdout_truncated = await asyncio.shield(stdout_task)
            raw_stderr, stderr_truncated = await asyncio.shield(stderr_task)

    except FileNotFoundError:
        # Defensive guard; should not occur after is_tool_available() check.
        logger.debug(f"[{tool_name}] Çalıştırılacak program PATH üzerinde bulunamadı.")

    elapsed = time.monotonic() - start
    return (
        rc,
        raw_stdout,
        raw_stderr,
        elapsed,
        timed_out,
        stdout_truncated,
        stderr_truncated,
    )


async def async_run_command(
    cmd: list[str],
    tool_name: str,
    timeout: float = 60.0,
    cwd: Optional[Path] = None,
    stdin_data: Optional[bytes] = None,
) -> tuple[int | None, str, str, float, bool]:
    """Run a subprocess and decode its bounded diagnostic text as UTF-8."""
    (
        rc,
        raw_stdout,
        raw_stderr,
        elapsed,
        timed_out,
        stdout_truncated,
        stderr_truncated,
    ) = await async_run_command_bytes(
        cmd,
        tool_name,
        timeout=timeout,
        cwd=cwd,
        stdin_data=stdin_data,
    )
    stdout = raw_stdout.decode("utf-8", errors="replace")
    stderr = raw_stderr.decode("utf-8", errors="replace")
    if stdout_truncated:
        stdout += f"\n... [subprocess stdout truncated at {PIPE_OUTPUT_LIMIT} bytes] ..."
    if stderr_truncated:
        stderr += f"\n... [subprocess stderr truncated at {PIPE_OUTPUT_LIMIT} bytes] ..."
    return rc, stdout, stderr, elapsed, timed_out


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
        opener = gzip.open if wordlist_path.suffix.lower() == ".gz" else open
        with opener(
            wordlist_path,
            mode="rt",
            encoding="utf-8",
            errors="replace",
        ) as fh:
            while True:
                raw_line = fh.readline(MAX_WORDLIST_LINE_CHARS + 1)
                if not raw_line:
                    break
                if len(raw_line) > MAX_WORDLIST_LINE_CHARS and not raw_line.endswith(("\n", "\r")):
                    while raw_line and not raw_line.endswith(("\n", "\r")):
                        raw_line = fh.readline(MAX_WORDLIST_LINE_CHARS + 1)
                    continue
                word = raw_line.rstrip("\n\r")
                if not word:
                    continue
                yield word
                count += 1
                if limit and count >= limit:
                    break
    except OSError as exc:
        logger.error(f"[wordlist] Wordlist açılamadı yeğenim ({wordlist_path}): {exc}")


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
