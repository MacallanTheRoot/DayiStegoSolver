"""
Scanning utilities for flags and passive next-stage artifacts.

Artifact detection is deliberately passive: matches are reported from text
that the existing tools already produced. URLs are never fetched, hostnames
are never resolved, and artifact matches never trigger file traversal.
"""
from __future__ import annotations

import base64
import binascii
import bisect
import codecs
import ipaddress
import logging
import math
import multiprocessing
import os
import re
import select
import struct
import threading
import time
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, replace
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Literal, Optional, Protocol

from dayi.text_stego import (
    MAX_DIRECT_FLAG_CHARACTERS,
    MAX_DIRECT_FLAG_LENGTH,
    MAX_DIRECT_FLAGS,
)

try:
    from re import _parser as _regex_parser
except ImportError:  # pragma: no cover - Python 3.10 compatibility
    import sre_parse as _regex_parser

logger = logging.getLogger("dayi")

_REGEX_REPEAT_OPCODES = tuple(
    opcode
    for opcode in (
        getattr(_regex_parser, name, None)
        for name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT")
    )
    if opcode is not None
)
_REGEX_NESTED_CHOICE_LIMIT = 256

_PREVIEW_LIMIT = 180
MAX_ARTIFACT_INPUT_CHARS = 4 * 1024 * 1024
MAX_ARTIFACT_FINDINGS = 512
MAX_SCAN_FILE_BYTES = 8 * 1024 * 1024
MAX_SCAN_FILES = 4_096
MAX_SCAN_DIRECTORY_BYTES = 128 * 1024 * 1024
MAX_FLAG_REGEX_CHARS = 512
MAX_FLAG_MATCHES = 1_024
MAX_BUILTIN_FLAG_CONTENT_CHARS = 256
MAX_ANALYSIS_LIMIT_EVENTS = 32
# User flag patterns run in a killable worker process (T3.3). Each call stops
# at this wall-clock deadline; all calls of one scan share a time budget
# (the runner passes ``--timeout``; this default applies outside a runner).
MAX_FLAG_REGEX_CALL_SECONDS = 5.0
DEFAULT_FLAG_REGEX_BUDGET_SECONDS = 60.0
# The budget is clamped to [0, this]: NaN, infinite or huge values never
# remove the cumulative cap (unrelated tool timeouts keep their own meaning).
MAX_FLAG_REGEX_BUDGET_SECONDS = 3600.0
MAX_FLAG_REGEX_INPUT_CHARS = 16 * 1024 * 1024
_FLAG_REGEX_START_SECONDS = 30.0
_FLAG_REGEX_MEMORY_BYTES = 768 * 1024 * 1024
_FLAG_REGEX_KILL_GRACE_SECONDS = 1.0
# Worker IPC: length-prefixed frames on the pipe's file descriptor. The parent
# end is non-blocking and every wait is a poll() bounded by the call deadline.
_FRAME_HEADER = struct.Struct("!Q")
_FLAG_REGEX_MAX_REQUEST_BYTES = MAX_FLAG_REGEX_INPUT_CHARS * 4
_DEADLINE_IPC_SUPPORTED = os.name == "posix" and hasattr(select, "poll")
BUILTIN_FLAG_PATTERN_DISPLAY = "built-in common CTF patterns"

_BUILTIN_FLAG_REGEX = (
    r"(?<![A-Za-z0-9_])"
    r"(?:CTF|FLAG|HTB|picoCTF|THM)"
    r"\{[^\r\n{}\x00-\x1f\x7f-\x9f]{1,"
    + str(MAX_BUILTIN_FLAG_CONTENT_CHARS)
    + r"}\}"
)
_BUILTIN_FLAG_PATTERN = re.compile(_BUILTIN_FLAG_REGEX)

_URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']{1,2048}", re.IGNORECASE)
_IPV4_CANDIDATE_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)
_IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9A-Za-z:.])\[?[0-9A-Fa-f:.]{2,45}\]?(?![0-9A-Za-z:.])"
)
_DOMAIN_PATTERN = re.compile(
    r"(?<![\w.-])(?=[\w.-]{1,253}(?![\w.-]))"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![\w.-])",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERN = re.compile(
    r"\b(?:password|passwd|pwd|secret|api[_-]?key|key)\s*[:=]\s*"
    r"(?:\"[^\"\r\n]{1,128}\"|'[^'\r\n]{1,128}'|[^\s,;]{1,128})",
    re.IGNORECASE,
)
_BASE64_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,4096}={0,2}"
    r"(?![A-Za-z0-9+/=])"
)
_DECIMAL_COORDINATE_PATTERN = re.compile(
    r"(?<![\d.])"
    r"([+-]?(?:90(?:\.0{1,12})?|[0-8]?\d(?:\.\d{1,12})?))"
    r"\s*[,;]\s*"
    r"([+-]?(?:180(?:\.0{1,12})?|1[0-7]\d(?:\.\d{1,12})?|[0-9]?\d(?:\.\d{1,12})?))"
    r"(?![\d.])"
)
_DMS_COORDINATE_PATTERN = re.compile(
    r"(?<!\w)"
    r"(\d{1,2})\s*[°º]\s*(\d{1,2})\s*['′]\s*"
    r"(\d{1,2}(?:\.\d+)?)\s*(?:[\"″]\s*)?([NS])"
    r"\s*[,;]?\s*"
    r"(\d{1,3})\s*[°º]\s*(\d{1,2})\s*['′]\s*"
    r"(\d{1,2}(?:\.\d+)?)\s*(?:[\"″]\s*)?([EW])"
    r"(?!\w)",
    re.IGNORECASE,
)
_COMMON_FILE_SUFFIXES = frozenset({
    "bmp", "csv", "gif", "jpeg", "jpg", "json", "log", "md", "pdf",
    "png", "py", "rar", "tar", "tif", "tiff", "txt", "wav", "xml", "zip",
})
_COMMON_DOMAIN_TLDS = frozenset({
    "ai", "app", "au", "biz", "ca", "cc", "ch", "cloud", "cn", "co",
    "com", "de", "dev", "edu", "fr", "gg", "gov", "in", "info", "io",
    "it", "jp", "me", "mil", "net", "nl", "online", "org", "ru", "site",
    "tech", "tr", "tv", "uk", "us", "xyz",
})
_CTF_DOMAIN_LABELS = frozenset({
    "admin", "challenge", "ctf", "flag", "hint", "paste", "stage",
})
_BINARY_ARTIFACT_SOURCES = (
    "binwalk/", "document/embedded/", "outguess/", "steghide/", "stegseek/",
    "strings/", "zsteg/",
)
_RELIABLE_ARTIFACT_SOURCES = (
    "metadata", "ocr", "ole", "pcap", "pdf", "target",
)

ArtifactConfidence = Literal["confirmed", "probable", "possible", "noise"]


@dataclass(frozen=True)
class ArtifactFinding:
    """A bounded, terminal-safe preview of a possible next-stage artifact."""

    artifact_type: str
    preview: str
    source: str
    decoded_preview: str | None = None


@dataclass(frozen=True)
class AnalysisLimit:
    """A resource-limit decision that reduced analysis coverage.

    ``action`` is ``skipped`` (input not analysed), ``partial`` (only a prefix
    was analysed) or ``stopped`` (a cumulative budget ended processing).
    ``limit`` is in ``unit``; ``observed`` is set only when the measured
    quantity is known without extra reads. ``count`` aggregates repeats.
    """

    source: str
    reason: str
    action: Literal["skipped", "partial", "stopped"]
    limit: int
    unit: str
    observed: int | None = None
    count: int = 1


def record_analysis_limit(
    limits: list[AnalysisLimit] | None, event: AnalysisLimit
) -> None:
    """Append or aggregate one event; a ``None`` target records nothing."""
    if limits is None:
        return
    key = (event.source, event.reason, event.action, event.limit, event.unit)
    for index, existing in enumerate(limits):
        if (
            existing.source, existing.reason, existing.action,
            existing.limit, existing.unit,
        ) == key:
            limits[index] = replace(
                existing,
                count=existing.count + event.count,
                observed=(
                    existing.observed
                    if existing.observed == event.observed
                    else None
                ),
            )
            return
    if len(limits) < MAX_ANALYSIS_LIMIT_EVENTS:
        limits.append(event)


class _GroupMatch(Protocol):
    """Flag scanning only ever reads the full match, ``group(0)``."""

    def group(self, index: Literal[0], /) -> str: ...


class FlagMatcher(Protocol):
    """What flag scanning needs from a pattern: ``re.Pattern[str]`` or
    ``BoundedFlagPattern``."""

    @property
    def pattern(self) -> str: ...

    @property
    def flags(self) -> int: ...

    def finditer(self, string: str, /) -> Iterator[_GroupMatch]: ...


@dataclass(frozen=True)
class FlagPatternConfig:
    """A compiled flag matcher and stable reporting metadata."""

    compiled: re.Pattern[str] | BoundedFlagPattern
    display: str
    source: Literal["user", "builtin"]


def _wait_fd(fd: int, event: int, deadline: float) -> bool:
    """Wait until ``fd`` is ready for ``event``; False once ``deadline`` passed."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    poller = select.poll()
    poller.register(fd, event)
    return bool(poller.poll(math.ceil(remaining * 1000)))


def _send_frame(fd: int, data: bytes, deadline: float) -> bool:
    """Write one frame; False if ``deadline`` passed first (non-blocking fd)."""
    for part in (_FRAME_HEADER.pack(len(data)), data):
        view = memoryview(part)
        while view:
            try:
                view = view[os.write(fd, view):]
            except BlockingIOError:
                if not _wait_fd(fd, select.POLLOUT, deadline):
                    return False
    return True


def _recv_exact(fd: int, size: int, deadline: float) -> bytes | None:
    buffer = bytearray()
    while len(buffer) < size:
        try:
            chunk = os.read(fd, min(size - len(buffer), 1 << 20))
        except BlockingIOError:
            if not _wait_fd(fd, select.POLLIN, deadline):
                return None
            continue
        if not chunk:
            raise EOFError("flag regex peer closed the connection")
        buffer += chunk
    return bytes(buffer)


def _recv_frame(fd: int, max_size: int, deadline: float) -> bytes | None:
    """Read one frame of at most ``max_size`` bytes; None on deadline.

    A larger announced size raises ``ValueError`` before anything is
    allocated; a closed peer raises ``EOFError``. With a blocking ``fd`` (the
    worker side) the deadline is never consulted.
    """
    header = _recv_exact(fd, _FRAME_HEADER.size, deadline)
    if header is None:
        return None
    (size,) = _FRAME_HEADER.unpack(header)
    if size > max_size:
        raise ValueError("flag regex frame exceeds its size limit")
    return _recv_exact(fd, size, deadline)


def _flag_regex_worker(
    connection: Connection,
    pattern: str,
    flags: int,
    memory_bytes: int,
    cpu_seconds: int,
    max_matches: int,
) -> None:
    """Match one user pattern per request; the parent kills this on deadline.

    Replies per request: ``M``+match for each new unique match (so matches
    found before a kill are kept), then ``D`` (done), ``L`` (a further unique
    match was refused) or ``E`` (error). ``R``/``E`` acknowledge startup.
    Frames use blocking I/O here; only the parent enforces deadlines.
    """
    if os.name == "posix":
        os.setsid()  # Terminal SIGINT goes to the parent, which owns this process.
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            # Backstop only: the parent kills the worker at each deadline.
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        except (ImportError, OSError, ValueError):
            pass
    fd = connection.fileno()
    try:
        compiled = re.compile(pattern, flags)
        _send_frame(fd, b"R", math.inf)
    except BaseException:
        _send_frame(fd, b"E", math.inf)
        return
    while True:
        try:
            request = _recv_frame(fd, _FLAG_REGEX_MAX_REQUEST_BYTES, math.inf)
        except (EOFError, OSError, ValueError):
            return
        if request is None:  # unreachable on a blocking fd
            return
        try:
            seen: set[str] = set()
            status = b"D"
            text = request.decode("utf-8", "surrogatepass")
            for match in compiled.finditer(text):
                value = match.group(0)
                if value in seen:
                    continue
                if len(seen) >= max_matches:
                    status = b"L"
                    break
                seen.add(value)
                _send_frame(fd, b"M" + value.encode("utf-8", "surrogatepass"), math.inf)
            _send_frame(fd, status, math.inf)
        except BaseException:
            try:
                _send_frame(fd, b"E", math.inf)
            except BaseException:
                pass
            return


def _stop_flag_regex_process(process: BaseProcess) -> None:
    if process.pid is None:
        return
    if process.is_alive():
        process.kill()
    process.join(timeout=_FLAG_REGEX_KILL_GRACE_SECONDS)


class _FlagRegexEngine:
    """One lazily started worker plus the time budget shared by one scan.

    Everything done under the request lock (worker start, IPC, matching,
    kill/reap after a timeout) is charged to the budget, so the total time all
    callers can wait on this engine is the budget plus one overrun of at most
    a worker start (``_FLAG_REGEX_START_SECONDS``) and one kill/reap grace
    (the reap after a failure is not charged; matching stops after it).
    """

    def __init__(self, pattern: str, flags: int, budget_seconds: float) -> None:
        self._pattern = pattern
        self._flags = flags
        self._request_lock = threading.Lock()  # one request at a time
        self._state_lock = threading.Lock()  # lets close() kill mid-request
        self._process: BaseProcess | None = None
        self._connection: Connection | None = None
        self.worker_starts = 0
        self.reset(budget_seconds)

    def reset(self, budget_seconds: float) -> None:
        """Start a new budget with a fresh worker (started on first use)."""
        try:
            budget = float(budget_seconds)
        except OverflowError:  # an int beyond float range
            budget = math.inf
        if math.isnan(budget):
            budget = math.inf  # treated as "no value": the finite maximum
        with self._request_lock:
            self._discard_worker()
            self._budget = min(max(0.0, budget), MAX_FLAG_REGEX_BUDGET_SECONDS)
            self._spent = 0.0
            self._failed = False
            self._budget_warned = False
            with self._state_lock:
                self._closed = False

    def close(self) -> None:
        """Kill the worker now; matching is refused until ``reset``."""
        with self._state_lock:
            self._closed = True
            process = self._process
        if process is not None:
            _stop_flag_regex_process(process)  # unblocks a pending request
        with self._request_lock:
            self._discard_worker()

    def _discard_worker(self) -> None:
        with self._state_lock:
            process, connection = self._process, self._connection
            self._process = self._connection = None
        if connection is not None:
            connection.close()
        if process is not None:
            _stop_flag_regex_process(process)

    def _start_worker(self) -> Connection:
        if not _DEADLINE_IPC_SUPPORTED:
            raise RuntimeError("deadline-bounded worker IPC requires POSIX poll()")
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        cpu_seconds = int(self._budget + MAX_FLAG_REGEX_CALL_SECONDS) + 2
        process = context.Process(
            target=_flag_regex_worker,
            args=(
                child, self._pattern, self._flags, _FLAG_REGEX_MEMORY_BYTES,
                cpu_seconds, MAX_FLAG_MATCHES,
            ),
            daemon=True,
        )
        with self._state_lock:
            if self._closed:
                raise RuntimeError("flag regex engine is closed")
            self._process, self._connection = process, parent
        try:
            process.start()
        finally:
            child.close()
        os.set_blocking(parent.fileno(), False)
        with self._state_lock:
            closed = self._closed  # close() may have run before start()
        if closed or _recv_frame(
            parent.fileno(), 1, time.monotonic() + _FLAG_REGEX_START_SECONDS
        ) != b"R":
            raise RuntimeError("flag regex worker did not start")
        self.worker_starts += 1
        return parent

    @staticmethod
    def _exchange(
        connection: Connection, payload: bytes, deadline: float, hits: list[str]
    ) -> str:
        fd = connection.fileno()
        try:
            if not _send_frame(fd, payload, deadline):
                return "timeout"
            while True:
                message = _recv_frame(fd, len(payload) + 1, deadline)
                if message is None:
                    return "timeout"
                kind = message[:1]
                if kind == b"M":
                    hits.append(message[1:].decode("utf-8", "surrogatepass"))
                elif kind == b"D":
                    return "done"
                elif kind == b"L":
                    return "limit"
                else:
                    return "error"
        except (EOFError, OSError, ValueError):
            return "error"

    def _budget_event(self, action: Literal["skipped", "partial"]) -> AnalysisLimit:
        if not self._budget_warned:
            self._budget_warned = True
            logger.warning(
                "[scanner] Yeğenim flag desenine ayırdığım süre bütçesi "
                "bitti; kalan girdileri bu desenle taramıyorum, rapora "
                "eksik tarama olarak yazıyorum."
            )
        return AnalysisLimit(
            "flag_regex", "flag_regex_budget_exhausted", action,
            int(self._budget * 1000), "milliseconds",
        )

    def _fail(self, events: list[AnalysisLimit], message: str) -> None:
        self._failed = True
        self._discard_worker()
        if not self._closed:  # a deliberate close() is not a failure to log
            logger.error(message)
        record_analysis_limit(events, AnalysisLimit(
            "flag_regex", "flag_regex_worker_failure", "skipped", 0, "none",
        ))

    def collect(self, text: str, events: list[AnalysisLimit]) -> list[str]:
        """Return unique matches in order; record every coverage reduction."""
        with self._request_lock:
            if self._closed or self._failed:
                record_analysis_limit(events, AnalysisLimit(
                    "flag_regex", "flag_regex_worker_failure", "skipped", 0, "none",
                ))
                return []
            if len(text) > MAX_FLAG_REGEX_INPUT_CHARS:
                record_analysis_limit(events, AnalysisLimit(
                    "flag_regex", "flag_regex_input_limit", "skipped",
                    MAX_FLAG_REGEX_INPUT_CHARS, "characters", len(text),
                ))
                return []
            if self._budget - self._spent <= 0:
                record_analysis_limit(events, self._budget_event("skipped"))
                return []
            started = time.monotonic()
            try:
                connection = (
                    self._connection
                    if self._connection is not None
                    else self._start_worker()
                )
            except Exception as exc:
                self._spent += time.monotonic() - started
                self._fail(
                    events,
                    f"[scanner] Yeğenim flag deseni işçisi başlatılamadı: {exc!r}",
                )
                return []
            except BaseException:
                self._discard_worker()
                raise
            self._spent += time.monotonic() - started
            remaining = self._budget - self._spent
            if remaining <= 0:
                record_analysis_limit(events, self._budget_event("skipped"))
                return []
            call_limit = MAX_FLAG_REGEX_CALL_SECONDS
            started = time.monotonic()
            payload = text.encode("utf-8", "surrogatepass")
            hits: list[str] = []
            try:
                status = self._exchange(
                    connection, payload, started + min(call_limit, remaining), hits
                )
                if status == "timeout":
                    self._discard_worker()  # kill + reap is charged as well
            except BaseException:
                self._discard_worker()  # e.g. KeyboardInterrupt while waiting
                raise
            finally:
                self._spent += time.monotonic() - started
            if status == "timeout":
                logger.warning(
                    "[scanner] Yeğenim flag deseni bu girdide süre sınırını "
                    "aştı; eşleştiriciyi durdurdum, girdi eksik tarandı."
                )
                record_analysis_limit(
                    events,
                    self._budget_event("partial")
                    if remaining < call_limit
                    else AnalysisLimit(
                        "flag_regex", "flag_regex_timeout", "partial",
                        int(call_limit * 1000), "milliseconds",
                    ),
                )
            elif status == "limit":
                record_analysis_limit(events, AnalysisLimit(
                    "flag_regex", "flag_match_limit", "partial",
                    MAX_FLAG_MATCHES, "matches",
                ))
            elif status == "error":
                self._fail(
                    events,
                    "[scanner] Yeğenim flag deseni işçisi beklenmedik şekilde "
                    "durdu; bu taramada desenle eşleştirme kapalı.",
                )
            return hits


class _BoundedMatch:
    """The full-match value of one bounded match (``group()`` / ``group(0)``)."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def group(self, index: int = 0, /) -> str:
        if index != 0:
            raise IndexError("bounded flag matches expose only the full match")
        return self._value


class BoundedFlagPattern:
    """A user flag pattern that is matched only in a killable worker process.

    Implements ``FlagMatcher``, the ``re.Pattern`` subset flag scanning uses:
    ``pattern``, ``flags`` and ``finditer`` (one match per unique value,
    first-occurrence order, at most ``MAX_FLAG_MATCHES``; only ``group(0)``).
    Other ``re.Pattern`` methods are deliberately absent. Coverage reductions
    (timeout, budget, input size, match count, worker failure) are appended to
    ``limit_events``. ``for_plugin`` returns a view that shares the worker and
    budget but collects its own events. Outside ``DayiRunner`` the budget is
    ``budget_seconds`` for the object's lifetime until ``start_scan``.
    ``start_scan`` and ``close`` belong to a single owner (the runner) and must
    not be called concurrently with each other; matching may run in any thread.
    """

    def __init__(
        self,
        compiled: re.Pattern[str],
        *,
        budget_seconds: float = DEFAULT_FLAG_REGEX_BUDGET_SECONDS,
        _engine: _FlagRegexEngine | None = None,
    ) -> None:
        self._compiled = compiled
        self.pattern: str = compiled.pattern
        self.flags: int = compiled.flags
        self._engine = (
            _engine
            if _engine is not None
            else _FlagRegexEngine(compiled.pattern, compiled.flags, budget_seconds)
        )
        self.limit_events: list[AnalysisLimit] = []

    def for_plugin(self) -> BoundedFlagPattern:
        return BoundedFlagPattern(self._compiled, _engine=self._engine)

    def start_scan(self, budget_seconds: float) -> None:
        """Reset budget, failure state, worker and events for a new scan."""
        self._engine.reset(budget_seconds)
        self.limit_events.clear()

    def close(self) -> None:
        """Stop the worker; matching is refused until ``start_scan``."""
        self._engine.close()

    @property
    def worker_starts(self) -> int:
        return self._engine.worker_starts

    def finditer(self, string: str, /) -> Iterator[_BoundedMatch]:
        return iter([
            _BoundedMatch(value)
            for value in self._engine.collect(string, self.limit_events)
        ])


def _safe_preview(value: str, limit: int = _PREVIEW_LIMIT) -> str:
    """Make untrusted tool output safe to print without terminal controls."""
    escaped: list[str] = []
    rendered_length = 0
    for char in value.strip():
        codepoint = ord(char)
        if char == "\n":
            rendered = r"\n"
        elif char == "\r":
            rendered = r"\r"
        elif char == "\t":
            rendered = r"\t"
        elif unicodedata.category(char).startswith("C"):
            if codepoint <= 0xFF:
                rendered = f"\\x{codepoint:02x}"
            elif codepoint <= 0xFFFF:
                rendered = f"\\u{codepoint:04x}"
            else:
                rendered = f"\\U{codepoint:08x}"
        else:
            rendered = char
        if rendered_length + len(rendered) >= limit:
            remaining = max(0, limit - rendered_length - 1)
            if remaining:
                escaped.append(rendered[:remaining])
            escaped.append("…")
            return "".join(escaped)
        escaped.append(rendered)
        rendered_length += len(rendered)

    preview = "".join(escaped)
    if len(preview) <= limit:
        return preview
    return preview[: limit - 1] + "…"


def _overlaps(span: tuple[int, int], occupied: list[tuple[int, int]]) -> bool:
    """Return whether a match overlaps an already classified text span."""
    start, end = span
    index = bisect.bisect_right(occupied, (start, float("inf")))
    if index and occupied[index - 1][1] > start:
        return True
    return index < len(occupied) and occupied[index][0] < end


def _label_entropy(label: str) -> float:
    if not label:
        return 0.0
    counts = {character: label.count(character) for character in set(label)}
    return -sum(
        (count / len(label)) * math.log2(count / len(label))
        for count in counts.values()
    )


def _has_domain_context(
    content: str,
    span: tuple[int, int] | None,
    domain: str,
) -> bool:
    if domain.startswith("www."):
        return True
    if span is None:
        return False
    prefix = content[max(0, span[0] - 32):span[0]].lower()
    return re.search(
        r"(?:host\s*[:=]\s*|url\s*[:=]\s*|domain\s*[:=]\s*|@)$",
        prefix,
    ) is not None


def classify_domain_confidence(
    domain: str,
    *,
    source: str,
    content: str = "",
    span: tuple[int, int] | None = None,
) -> ArtifactConfidence:
    """Classify one syntactically valid domain without network access."""
    normalized = domain.lower().rstrip(".")
    if len(normalized) < 6 or len(normalized) > 253:
        return "noise"
    labels = normalized.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        return "noise"

    registrable = labels[-2]
    tld = labels[-1]
    explicit_context = _has_domain_context(content, span, normalized)
    score = 3 if tld in _COMMON_DOMAIN_TLDS else -2
    if len(normalized) >= 6:
        score += 1
    if len(registrable) >= 5:
        score += 1
    elif len(registrable) <= 3:
        score -= 1
    if any(character in "aeiou" for character in registrable):
        score += 1
    if len(labels) >= 3:
        score += 1
    if registrable in _CTF_DOMAIN_LABELS:
        score += 3
    if explicit_context:
        score += 3

    lowered_source = source.lower()
    if any(marker in lowered_source for marker in _BINARY_ARTIFACT_SOURCES):
        score -= 2
    elif any(marker in lowered_source for marker in _RELIABLE_ARTIFACT_SOURCES):
        score += 1

    if any(character.isdigit() for character in registrable):
        score -= 1
    if len(registrable) <= 4 and not any(
        character in "aeiou" for character in registrable
    ):
        score -= 3
    if len(registrable) >= 8 and _label_entropy(registrable) >= 3.3:
        score -= 2

    if score >= 6:
        return "confirmed"
    if score >= 3:
        return "probable"
    if score >= 1:
        return "possible"
    return "noise"


def decode_base64_text(candidate: str) -> str | None:
    """Strictly decode Base64 and accept only printable UTF-8 text."""
    if len(candidate) < 20 or len(candidate) % 4 == 1:
        return None

    padded = candidate + ("=" * (-len(candidate) % 4))
    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded_text = decoded_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None

    if not decoded_text:
        return None
    if any(not (char.isprintable() or char in "\r\n\t") for char in decoded_text):
        return None

    # Reject non-canonical lookalikes that happen to decode successfully.
    canonical = base64.b64encode(decoded_bytes).decode("ascii").rstrip("=")
    if canonical != candidate.rstrip("="):
        return None
    return decoded_text


def scan_artifacts(
    content: str,
    source: str,
    max_findings: int = MAX_ARTIFACT_FINDINGS,
    *,
    include_possible: bool = False,
    limits: list[AnalysisLimit] | None = None,
) -> list[ArtifactFinding]:
    """
    Detect passive next-stage artifacts in existing textual output.

    The scanner performs no I/O. Returned values are bounded and stripped of
    terminal control characters so callers can safely display the previews.
    When ``limits`` is given, input truncation and finding-budget stops are
    recorded there.
    """
    if len(content) > MAX_ARTIFACT_INPUT_CHARS:
        record_analysis_limit(limits, AnalysisLimit(
            "artifact_scan", "artifact_input_limit", "partial",
            MAX_ARTIFACT_INPUT_CHARS, "characters", len(content),
        ))
    content = content[:MAX_ARTIFACT_INPUT_CHARS]
    findings: list[ArtifactFinding] = []
    seen: set[tuple[str, str, str | None]] = set()
    occupied_urls: list[tuple[int, int]] = []
    # With ``limits``, set only when a new, valid finding is refused, so
    # reaching the budget exactly with nothing left to add does not count as a
    # stop. Without it, stop as soon as the budget is full.
    budget_stopped = limits is None and max_findings <= 0

    def add(artifact_type: str, value: str, decoded: str | None = None) -> None:
        nonlocal budget_stopped
        preview = _safe_preview(value)
        decoded_preview = _safe_preview(decoded) if decoded is not None else None
        key = (artifact_type, preview, decoded_preview)
        if not preview or key in seen:
            return
        if len(findings) >= max_findings:
            budget_stopped = True
            return
        seen.add(key)
        findings.append(
            ArtifactFinding(
                artifact_type=artifact_type,
                preview=preview,
                source=source,
                decoded_preview=decoded_preview,
            )
        )
        if limits is None and len(findings) >= max_findings:
            budget_stopped = True

    for match in _URL_PATTERN.finditer(content):
        if budget_stopped:
            break
        value = match.group(0).rstrip(".,;:!?)]}")
        if value:
            add("url", value)
            occupied_urls.append((match.start(), match.start() + len(value)))

    for match in _CREDENTIAL_PATTERN.finditer(content):
        if budget_stopped:
            break
        add("credential", match.group(0).rstrip(".])}"))

    for match in _DMS_COORDINATE_PATTERN.finditer(content):
        if budget_stopped:
            break
        lat_deg, lat_min, lat_sec, _lat_dir, lon_deg, lon_min, lon_sec, _lon_dir = (
            match.groups()
        )
        latitude_boundary_valid = int(lat_deg) < 90 or (
            int(lat_min) == 0 and float(lat_sec) == 0
        )
        longitude_boundary_valid = int(lon_deg) < 180 or (
            int(lon_min) == 0 and float(lon_sec) == 0
        )
        if (
            int(lat_deg) <= 90
            and int(lon_deg) <= 180
            and int(lat_min) < 60
            and int(lon_min) < 60
            and float(lat_sec) < 60
            and float(lon_sec) < 60
            and latitude_boundary_valid
            and longitude_boundary_valid
        ):
            add("coordinates_dms", match.group(0))

    for match in _DECIMAL_COORDINATE_PATTERN.finditer(content):
        if budget_stopped:
            break
        latitude, longitude = match.groups()
        # A decimal coordinate must contain a fractional component. This avoids
        # classifying common comma-separated integer output as a location.
        if "." not in latitude and "." not in longitude:
            continue
        if -90 <= float(latitude) <= 90 and -180 <= float(longitude) <= 180:
            add("coordinates_decimal", match.group(0))

    valid_ipv6: list[tuple[re.Match[str], ipaddress.IPv6Address]] = []
    occupied_ipv6: list[tuple[int, int]] = []
    for match in _IPV6_CANDIDATE_PATTERN.finditer(content):
        if budget_stopped:
            break
        candidate = match.group(0).strip("[]")
        if (
            len(candidate) <= 7
            or candidate.count(":") < 3
            or _overlaps(match.span(), occupied_urls)
        ):
            continue
        try:
            address_v6 = ipaddress.IPv6Address(candidate)
        except ipaddress.AddressValueError:
            continue
        if address_v6.is_unspecified or address_v6.is_loopback:
            continue
        valid_ipv6.append((match, address_v6))
        occupied_ipv6.append(match.span())

    for match in _IPV4_CANDIDATE_PATTERN.finditer(content):
        if budget_stopped:
            break
        if _overlaps(match.span(), occupied_urls) or _overlaps(match.span(), occupied_ipv6):
            continue
        try:
            address_v4 = ipaddress.IPv4Address(match.group(0))
        except ipaddress.AddressValueError:
            continue
        add("ipv4", str(address_v4))

    for _match, address_v6 in valid_ipv6:
        if budget_stopped:
            break
        add("ipv6", str(address_v6))

    for match in _BASE64_CANDIDATE_PATTERN.finditer(content):
        if budget_stopped:
            break
        candidate = match.group(0)
        decoded = decode_base64_text(candidate)
        if decoded is not None:
            add("base64", candidate, decoded)

    for match in _DOMAIN_PATTERN.finditer(content):
        if budget_stopped:
            break
        if _overlaps(match.span(), occupied_urls):
            continue
        domain = match.group(0).lower()
        confidence = classify_domain_confidence(
            domain,
            source=source,
            content=content,
            span=match.span(),
        )
        if domain.rsplit(".", 1)[-1] in _COMMON_FILE_SUFFIXES:
            continue
        if confidence == "noise" or (
            confidence == "possible" and not include_possible
        ):
            continue
        add("domain", domain)

    if budget_stopped:
        record_analysis_limit(limits, AnalysisLimit(
            "artifact_scan", "artifact_finding_limit", "stopped",
            max_findings, "findings",
        ))
    return findings


def _collect_matches(pattern: FlagMatcher, text: str) -> list[str]:
    """Extract unique full-match strings while preserving insertion order."""
    seen: dict[str, None] = {}
    for match in pattern.finditer(text):
        seen[match.group(0)] = None
        if len(seen) >= MAX_FLAG_MATCHES:
            break
    return list(seen)


def scan_text(content: str, pattern: FlagMatcher) -> list[str]:
    """Search text for all occurrences of a compiled flag pattern."""
    return _collect_matches(pattern, content)


class IncrementalFlagScanner:
    """Find bounded regex matches in one independently decoded byte stream."""

    def __init__(self, pattern: FlagMatcher) -> None:
        self.pattern = pattern
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._tail = ""
        self._matches: dict[str, None] = {}
        self._matched_characters = 0
        self._finished = False

    def feed(self, chunk: bytes) -> None:
        """Decode and scan one chunk without retaining the complete stream."""
        if self._finished or not chunk:
            return
        self._scan_decoded(self._decoder.decode(chunk, final=False))

    def finish(self) -> None:
        """Flush an incomplete UTF-8 sequence using the established replacement policy."""
        if self._finished:
            return
        self._finished = True
        self._scan_decoded(self._decoder.decode(b"", final=True))

    def _scan_decoded(self, decoded: str) -> None:
        if not decoded:
            return
        window = self._tail + decoded
        for flag in scan_text(window, self.pattern):
            if flag in self._matches or len(flag) > MAX_DIRECT_FLAG_LENGTH:
                continue
            if (
                len(self._matches) >= MAX_DIRECT_FLAGS
                or self._matched_characters + len(flag)
                > MAX_DIRECT_FLAG_CHARACTERS
            ):
                break
            self._matches[flag] = None
            self._matched_characters += len(flag)

        # Any eligible match split at the next boundary is at most 2,048
        # characters, so this established direct-flag limit is sufficient and
        # prevents an unbounded regex carry buffer.
        self._tail = window[-MAX_DIRECT_FLAG_LENGTH:]

    @property
    def flags(self) -> tuple[str, ...]:
        return tuple(self._matches)

    @property
    def retained_state_characters(self) -> int:
        """Expose the persistent character bound for deterministic tests."""
        return len(self._tail) + self._matched_characters


class SubprocessFlagScanner:
    """Track bounded flag matches and their stdout/stderr source."""

    def __init__(self, pattern: FlagMatcher) -> None:
        self.pattern = pattern
        self.stdout = IncrementalFlagScanner(pattern)
        self.stderr = IncrementalFlagScanner(pattern)

    def findings(self, retained_stdout: str, retained_stderr: str) -> dict[str, list[str]]:
        """Merge retained-text and incremental matches per stream with deduplication."""
        findings: dict[str, list[str]] = {}
        for source, retained, observer in (
            ("stdout", retained_stdout, self.stdout),
            ("stderr", retained_stderr, self.stderr),
        ):
            hits = list(dict.fromkeys(scan_text(retained, self.pattern) + list(observer.flags)))
            if hits:
                findings[source] = hits
        return findings


def scan_file(
    filepath: Path,
    pattern: FlagMatcher,
    *,
    limits: list[AnalysisLimit] | None = None,
) -> list[str]:
    """Read a bounded regular file and return unique flag matches.

    An oversized file is skipped; with ``limits`` the skip is recorded.
    """
    try:
        if filepath.is_symlink() or not filepath.is_file():
            return []
        with filepath.open("rb") as source:
            raw = source.read(MAX_SCAN_FILE_BYTES + 1)
            size = os.fstat(source.fileno()).st_size
        if len(raw) > MAX_SCAN_FILE_BYTES:
            logger.debug(
                f"[scan_file] {filepath} güvenli tarama sınırını aştı; atlandı."
            )
            record_analysis_limit(limits, AnalysisLimit(
                "scan_file", "extracted_file_size_limit", "skipped",
                MAX_SCAN_FILE_BYTES, "bytes",
                size if size > MAX_SCAN_FILE_BYTES else None,
            ))
            return []
        content = raw.decode("utf-8", errors="replace")
        return _collect_matches(pattern, content)
    except Exception as exc:
        logger.debug(f"[scan_file] {filepath} okunamadı yeğenim: {exc}")
        return []


def scan_directory(
    directory: Path,
    pattern: FlagMatcher,
    *,
    limits: list[AnalysisLimit] | None = None,
) -> dict[str, list[str]]:
    """Recursively scan a directory for flags only, never for artifacts.

    With ``limits``, budget stops and oversized-file skips are recorded.
    """
    results: dict[str, list[str]] = {}
    if not directory.exists():
        return results

    scanned_files = 0
    scanned_bytes = 0
    for root, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(root) / name).is_symlink()]
        for filename in files:
            filepath = Path(root) / filename
            if filepath.is_symlink():
                continue
            try:
                file_size = filepath.stat().st_size
            except OSError:
                continue
            if scanned_files >= MAX_SCAN_FILES:
                event = AnalysisLimit(
                    "scan_directory", "directory_file_limit", "stopped",
                    MAX_SCAN_FILES, "files",
                )
            elif scanned_bytes + file_size > MAX_SCAN_DIRECTORY_BYTES:
                event = AnalysisLimit(
                    "scan_directory", "directory_byte_budget", "stopped",
                    MAX_SCAN_DIRECTORY_BYTES, "bytes",
                )
            else:
                event = None
            if event is not None:
                logger.warning(
                    "[scanner] Yeğenim çıkarılan dosya tarama sınırına ulaştı; "
                    "kalanları güvenlik için es geçiyorum."
                )
                record_analysis_limit(limits, event)
                return results
            scanned_files += 1
            scanned_bytes += file_size
            found = scan_file(filepath, pattern, limits=limits)
            if found:
                results[str(filepath.relative_to(directory))] = found
    return results


def _has_nested_ambiguous_repeat(flag_regex: str) -> bool:
    """Detect nested repeats whose backtracking is not tightly bounded.

    A variable-count repeat may not contain variable repeats or alternation.
    A fixed-count repeat may contain bounded variable repeats while the
    combined number of choices stays within ``_REGEX_NESTED_CHOICE_LIMIT``,
    so ``(?:\\d{1,3}\\.){3}`` stays usable and ``(?:a?){30}`` is rejected.
    This is a syntactic heuristic, not a proof that matching is linear.
    """
    try:
        parsed = _regex_parser.parse(flag_regex)
    except (re.error, OverflowError):
        return False  # re.compile reports the syntax error.

    # Unbounded repeats and alternation count as "too many choices".
    too_many = _REGEX_NESTED_CHOICE_LIMIT + 1

    def choices(items) -> int | None:
        """Return the capped choice count of a sequence, or None if unsafe."""
        total = 1
        for opcode, argument in items:
            subpatterns = []
            if opcode in _REGEX_REPEAT_OPCODES:
                minimum, maximum, body = argument
                inner = choices(body)
                if inner is None:
                    return None
                if minimum == maximum:
                    current = inner ** min(minimum, 64)
                    if minimum > 1 and current > _REGEX_NESTED_CHOICE_LIMIT:
                        return None
                elif maximum > 1:
                    if inner > 1:
                        return None
                    current = (
                        too_many
                        if maximum == _regex_parser.MAXREPEAT
                        else maximum - minimum + 1
                    )
                else:
                    current = inner + 1
            elif opcode is _regex_parser.BRANCH:
                subpatterns = argument[1]
                current = too_many
            else:
                values = argument if isinstance(argument, tuple) else (argument,)
                subpatterns = [
                    value for value in values
                    if isinstance(value, _regex_parser.SubPattern)
                ]
                current = 1
            for subpattern in subpatterns:
                inner = choices(subpattern)
                if inner is None:
                    return None
                if opcode is not _regex_parser.BRANCH:
                    current *= inner
            total = min(total * current, too_many)
        return total

    return choices(parsed) is None


def compile_pattern(flag_regex: str) -> Optional[re.Pattern]:
    """Safely compile a user-supplied flag regex pattern."""
    unsafe_patterns = (
        r"\\[1-9]",
        r"\(\?(?:[=!]|<[=!])",
        r"\((?:[^()\\]|\\.)*[*+](?:[^()\\]|\\.)*\)\s*[*+{]",
        r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)\s*[*+{]",
    )
    if (
        len(flag_regex) > MAX_FLAG_REGEX_CHARS
        or any(re.search(unsafe, flag_regex) for unsafe in unsafe_patterns)
        or _has_nested_ambiguous_repeat(flag_regex)
    ):
        logger.error(
            "[scanner] Yeğenim bu flag deseni güvenli regex sınırlarını aşıyor; "
            "iç içe tekrar, geri referans ve lookaround kullanma."
        )
        return None
    try:
        return re.compile(flag_regex)
    except (re.error, OverflowError) as exc:
        logger.error(f"[scanner] Flag regex deseni geçersiz yeğenim: {exc}")
        return None


def compile_user_pattern(flag_regex: str) -> Optional[re.Pattern]:
    """Compile an untrusted user pattern with the established safety checks."""
    return compile_pattern(flag_regex)


def get_builtin_flag_pattern() -> re.Pattern:
    """Return the trusted conservative matcher for common CTF flag prefixes."""
    return _BUILTIN_FLAG_PATTERN


def build_flag_pattern_config(flag_regex: str | None) -> FlagPatternConfig | None:
    """Build user or built-in pattern configuration for one scan."""
    if flag_regex is None:
        return FlagPatternConfig(
            compiled=get_builtin_flag_pattern(),
            display=BUILTIN_FLAG_PATTERN_DISPLAY,
            source="builtin",
        )

    compiled = compile_user_pattern(flag_regex)
    if compiled is None:
        return None
    return FlagPatternConfig(
        compiled=BoundedFlagPattern(compiled),
        display=flag_regex,
        source="user",
    )
