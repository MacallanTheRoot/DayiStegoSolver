"""Optional streaming Scapy scanner for PCAP and PCAPNG targets."""
from __future__ import annotations

import asyncio
import importlib
import itertools
import logging
import re
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

from dayi.persona import log_artifact
from dayi.reporter import ToolResult
from dayi.scanner import ArtifactFinding, scan_artifacts, scan_text
from dayi.tools._base import async_run_isolated, make_skipped_result
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin

logger = logging.getLogger("dayi")

TOOL_NAME = "pcap_scanner"
MAX_PCAP_BYTES = 128 * 1024 * 1024
MAX_PACKETS = 50_000
MAX_COMBINED_TEXT_CHARS = 4 * 1024 * 1024
MAX_PACKET_ERRORS = 100
MAX_ARTIFACTS = 256
PROGRESS_INTERVAL = 1_000
MAX_CARVED_FILES = 50
MAX_CARVED_PAYLOAD_BYTES = 10 * 1024 * 1024
MAX_PACKET_TEXT_BYTES = 1024 * 1024

_PCAP_MAGICS = frozenset(
    {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    }
)
_CARVABLE_MAGICS = (
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"PK\x03\x04", "zip"),
    (b"%PDF-", "pdf"),
)

ProgressCallback = Callable[[int, int | None], None]
ArtifactCallback = Callable[[str], None]


@dataclass(frozen=True)
class PCAPDependencies:
    """Late-loaded scapy.all module required by the scanner."""

    scapy: Any
    http: Any | None = None


@dataclass(frozen=True)
class PCAPExtraction:
    """Bounded text and counters produced by one streaming capture pass."""

    text: str
    errors: tuple[str, ...]
    packets_scanned: int
    payloads_extracted: int
    dns_queries_extracted: int
    carved_files_count: int
    carved_dir: str | None
    packet_limit_reached: bool
    text_limit_reached: bool


class PCAPSafetyError(ValueError):
    """Raised when a capture violates a scanner safety limit."""


def _load_pcap_dependencies() -> PCAPDependencies | None:
    """Load scapy.all without making Scapy a core dependency."""
    try:
        scapy = importlib.import_module("scapy.all")
    except Exception:
        return None
    try:
        http = importlib.import_module("scapy.layers.http")
    except Exception:
        http = None
    return PCAPDependencies(scapy=scapy, http=http)


def _has_pcap_magic(target: Path) -> bool:
    """Recognize classic PCAP and PCAPNG capture headers."""
    if target.is_symlink() or not target.is_file():
        return False
    try:
        with target.open("rb") as source:
            magic = source.read(4)
    except OSError:
        return False
    return magic in _PCAP_MAGICS


def _validate_pcap_size(target: Path) -> None:
    """Reject empty or oversized captures before invoking Scapy."""
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise PCAPSafetyError(f"cannot stat capture input: {exc}") from exc
    if size <= 0:
        raise PCAPSafetyError("capture input is empty")
    if size > MAX_PCAP_BYTES:
        raise PCAPSafetyError(
            f"capture size {size} exceeds safety limit {MAX_PCAP_BYTES}"
        )


def _safe_text(value: bytes, limit: int) -> str:
    """Decode and sanitize an untrusted packet field."""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        text = value.decode("latin-1")
    cleaned = "".join(
        char
        for char in text
        if char in "\n\t" or not unicodedata.category(char).startswith("C")
    )
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit]


def _safe_callback(
    callback: Callable[..., None] | None,
    *args: object,
) -> None:
    """Invoke a presentation callback without disrupting packet parsing."""
    if callback is None:
        return
    try:
        callback(*args)
    except Exception as exc:
        logger.debug(
            f"[pcap_scanner] Sunum geri çağrısı tökezledi yeğenim: {exc}"
        )


def _field_bytes(value: Any) -> bytes:
    """Convert a Scapy field value to bytes without trusting its type."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return str(value).encode("utf-8", errors="replace")


def _carvable_magic(payload: bytes) -> str | None:
    """Return the recognized file type for a raw payload prefix."""
    for signature, magic_name in _CARVABLE_MAGICS:
        if payload.startswith(signature):
            return magic_name
    return None


def _prepare_carved_dir(workspace: Path) -> Path:
    """Create a non-symlinked carving directory inside the workspace."""
    if workspace.is_symlink():
        raise PCAPSafetyError("workspace must not be a symbolic link")
    workspace.mkdir(parents=True, exist_ok=True)
    if not workspace.is_dir():
        raise PCAPSafetyError("workspace is not a directory")

    workspace_root = workspace.resolve()
    carved_dir = workspace / "pcap_extracted"
    if carved_dir.is_symlink():
        raise PCAPSafetyError("carving directory must not be a symbolic link")
    carved_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
    if not carved_dir.is_dir() or carved_dir.resolve().parent != workspace_root:
        raise PCAPSafetyError("carving directory escaped the workspace")
    return carved_dir


def _carve_payload(
    payload: bytes,
    workspace: Path | None,
    carved_index: int,
) -> Path | None:
    """Persist one recognized and bounded raw payload inside the workspace."""
    if workspace is None or not payload:
        return None
    if len(payload) > MAX_CARVED_PAYLOAD_BYTES:
        return None

    magic_name = _carvable_magic(payload)
    if magic_name is None:
        return None

    carved_dir = _prepare_carved_dir(workspace)
    destination = carved_dir / f"carved_{carved_index}_{magic_name}.bin"
    if destination.is_symlink():
        raise PCAPSafetyError("carved destination must not be a symbolic link")
    try:
        with destination.open("xb") as output:
            output.write(payload)
    except FileExistsError:
        return None
    except OSError:
        destination.unlink(missing_ok=True)
        raise
    return destination


def _extract_pcap_sync(
    target: Path,
    dependencies: PCAPDependencies,
    workspace: Path | None,
    timeout: float,
    progress_callback: ProgressCallback | None,
) -> PCAPExtraction:
    """Stream packets with PcapReader and retain only bounded cleartext."""
    deadline = time.monotonic() + max(1.0, timeout)
    sections: list[str] = []
    errors: list[str] = []
    combined_chars = 0
    packets_scanned = 0
    payloads_extracted = 0
    dns_queries_extracted = 0
    carved_files_count = 0
    carved_dir: str | None = None
    packet_limit_reached = False
    text_limit_reached = False

    with dependencies.scapy.PcapReader(str(target)) as pcap_reader:
        try:
            for packet in itertools.islice(pcap_reader, MAX_PACKETS + 1):
                if packets_scanned >= MAX_PACKETS:
                    packet_limit_reached = True
                    break
                if time.monotonic() >= deadline:
                    errors.append(
                        f"PCAP time budget exhausted after {packets_scanned} packets"
                    )
                    break

                packets_scanned += 1
                try:
                    packet_sections: list[str] = []
                    if packet.haslayer(dependencies.scapy.DNSQR):
                        qname = _field_bytes(
                            packet[dependencies.scapy.DNSQR].qname
                        )
                        dns_text = _safe_text(qname, 1_024).rstrip(".")
                        if dns_text:
                            packet_sections.append(f"DNS query: {dns_text}")
                            dns_queries_extracted += 1

                    if packet.haslayer(dependencies.scapy.DNSRR):
                        rdata = _field_bytes(
                            packet[dependencies.scapy.DNSRR].rdata
                        )
                        record_text = _safe_text(rdata, 4_096).strip()
                        if record_text:
                            packet_sections.append(
                                f"DNS resource record: {record_text}"
                            )

                    if packet.haslayer(dependencies.scapy.ICMP):
                        icmp_layer = packet[dependencies.scapy.ICMP]
                        icmp_load = getattr(icmp_layer, "load", b"")
                        if icmp_load:
                            icmp_text = _safe_text(
                                _field_bytes(icmp_load),
                                MAX_COMBINED_TEXT_CHARS,
                            )
                            if icmp_text:
                                packet_sections.append(
                                    f"ICMP payload:\n{icmp_text}"
                                )

                    if dependencies.http is not None and packet.haslayer(
                        dependencies.http.HTTPRequest
                    ):
                        request = packet[dependencies.http.HTTPRequest]
                        request_text = _safe_text(
                            bytes(request),
                            64 * 1024,
                        ).strip()
                        if request_text:
                            packet_sections.append(
                                f"HTTP request:\n{request_text}"
                            )
                        for label, field_name in (
                            ("HTTP path", "Path"),
                            ("HTTP cookie", "Cookie"),
                            ("HTTP authorization", "Authorization"),
                        ):
                            value = getattr(request, field_name, None)
                            if not value:
                                continue
                            header_text = _safe_text(
                                _field_bytes(value),
                                8_192,
                            ).strip()
                            if header_text:
                                packet_sections.append(
                                    f"{label}: {header_text}"
                                )

                    if packet.haslayer(dependencies.scapy.Raw):
                        raw_load = packet[dependencies.scapy.Raw].load
                        raw_size = len(raw_load) if hasattr(raw_load, "__len__") else None
                        if isinstance(raw_load, bytes):
                            payload = raw_load[:MAX_CARVED_PAYLOAD_BYTES]
                        elif isinstance(raw_load, (bytearray, memoryview)):
                            payload = bytes(raw_load[:MAX_CARVED_PAYLOAD_BYTES])
                        else:
                            payload = _field_bytes(raw_load)[:MAX_CARVED_PAYLOAD_BYTES]
                        if (
                            carved_files_count < MAX_CARVED_FILES
                            and (raw_size is None or raw_size <= MAX_CARVED_PAYLOAD_BYTES)
                        ):
                            carved_path = _carve_payload(
                                payload,
                                workspace,
                                carved_files_count + 1,
                            )
                            if carved_path is not None:
                                carved_files_count += 1
                                carved_dir = str(carved_path.parent)
                        payload_text = (
                            _safe_text(payload[:MAX_PACKET_TEXT_BYTES], MAX_PACKET_TEXT_BYTES)
                            if not text_limit_reached
                            else ""
                        )
                        if payload_text:
                            packet_sections.append(f"Raw payload:\n{payload_text}")
                            payloads_extracted += 1
                except Exception as exc:
                    if len(errors) < MAX_PACKET_ERRORS:
                        errors.append(
                            f"packet {packets_scanned}: {type(exc).__name__}: {exc}"
                        )
                    if packets_scanned % PROGRESS_INTERVAL == 0:
                        _safe_callback(progress_callback, packets_scanned, None)
                    continue

                if packet_sections and not text_limit_reached:
                    section = (
                        f"[Packet {packets_scanned}]\n"
                        + "\n".join(packet_sections)
                    )
                    remaining = MAX_COMBINED_TEXT_CHARS - combined_chars
                    if remaining <= 0:
                        text_limit_reached = True
                    else:
                        bounded = section[:remaining]
                        sections.append(bounded)
                        combined_chars += len(bounded)
                        if len(bounded) < len(section):
                            text_limit_reached = True

                if packets_scanned % PROGRESS_INTERVAL == 0:
                    _safe_callback(progress_callback, packets_scanned, None)
        except Exception as exc:
            errors.append(f"packet stream failed: {type(exc).__name__}: {exc}")

        return PCAPExtraction(
            text="\n\n".join(sections),
            errors=tuple(errors),
            packets_scanned=packets_scanned,
            payloads_extracted=payloads_extracted,
            dns_queries_extracted=dns_queries_extracted,
            carved_files_count=carved_files_count,
            carved_dir=carved_dir,
            packet_limit_reached=packet_limit_reached,
            text_limit_reached=text_limit_reached,
        )


def _extract_pcap_isolated(
    target: Path,
    workspace: Path | None,
    timeout: float,
) -> PCAPExtraction:
    """Load Scapy and stream a capture inside an isolated parser process."""
    dependencies = _load_pcap_dependencies()
    if dependencies is None:
        raise ImportError("optional Scapy dependency is unavailable")
    return _extract_pcap_sync(target, dependencies, workspace, timeout, None)


def _emit_artifact(
    message: str,
    artifact_callback: ArtifactCallback | None,
) -> None:
    """Publish a PCAP finding through the active UI or plain logger."""
    if artifact_callback is None:
        log_artifact(logger, message)
    else:
        _safe_callback(artifact_callback, message)


async def run_pcap_scanner(
    target: Path,
    flag_pattern: re.Pattern,
    workspace: Path | None = None,
    timeout: float = 60.0,
    progress_callback: ProgressCallback | None = None,
    artifact_callback: ArtifactCallback | None = None,
) -> ToolResult:
    """Stream a capture and scan bounded cleartext for flags and artifacts."""
    command = ["python:scapy.PcapReader", str(target)]
    if not _has_pcap_magic(target):
        return make_skipped_result(
            TOOL_NAME,
            "target does not have PCAP or PCAPNG magic bytes",
            command,
        )

    try:
        _validate_pcap_size(target)
    except PCAPSafetyError as exc:
        logger.warning(f"[-] Yeğenim PCAP güvenlik sınırına takıldı: {exc}")
        return make_skipped_result(TOOL_NAME, str(exc), command)

    dependencies = _load_pcap_dependencies()
    if dependencies is None:
        logger.info(
            "[-] Yeğenim ağ stetoskopu çantada yok; Scapy kurulursa "
            "paketlerin fısıltısını da dinlerim."
        )
        return make_skipped_result(
            TOOL_NAME,
            "optional Scapy dependency is unavailable",
            command,
        )

    logger.info(
        "[+] Yeğenim, ağda kim kiminle fısıldaşmış bir bakalım, "
        "pcap dosyasını dinlemeye aldım..."
    )
    started = time.monotonic()
    try:
        if isinstance(dependencies.scapy, ModuleType):
            extraction = await async_run_isolated(
                _extract_pcap_isolated,
                target,
                workspace,
                timeout,
                timeout=timeout,
            )
        else:
            extraction = await asyncio.to_thread(
                _extract_pcap_sync,
                target,
                dependencies,
                workspace,
                timeout,
                progress_callback,
            )
    except asyncio.TimeoutError:
        return ToolResult(
            tool_name=TOOL_NAME,
            command=command,
            return_code=None,
            stdout="",
            stderr="PCAP parsing time budget exhausted",
            flags_found=[],
            elapsed_seconds=time.monotonic() - started,
            timed_out=True,
        )
    except Exception as exc:
        reason = f"PCAP parsing failed: {type(exc).__name__}: {exc}"
        logger.warning(
            f"[-] Yeğenim ağ kaydı cızırtıya boğuldu, okuyamadım: {exc}"
        )
        return make_skipped_result(TOOL_NAME, reason, command)

    errors = list(extraction.errors)
    if extraction.packet_limit_reached:
        errors.append(f"packet limit reached ({MAX_PACKETS})")
    if extraction.text_limit_reached:
        errors.append(
            f"combined cleartext limit reached ({MAX_COMBINED_TEXT_CHARS})"
        )
    if extraction.carved_files_count:
        _emit_artifact(
            "[!] Yeğenim, ağ paketlerinin içinden "
            f"{extraction.carved_files_count} dosya çıkardım; "
            "zulanın devamı burada olabilir!",
            artifact_callback,
        )

    flags = scan_text(extraction.text, flag_pattern)
    all_artifacts = scan_artifacts(
        extraction.text,
        source=f"{TOOL_NAME}/pcap-cleartext",
    )
    artifacts: list[ArtifactFinding] = all_artifacts[:MAX_ARTIFACTS]
    if len(all_artifacts) > MAX_ARTIFACTS:
        errors.append(
            f"artifact limit reached: retained {MAX_ARTIFACTS} of "
            f"{len(all_artifacts)} findings"
        )
    for finding in artifacts:
        decoded = (
            f" | çözülen: {finding.decoded_preview}"
            if finding.decoded_preview is not None
            else ""
        )
        _emit_artifact(
            "[!] Yeğenim, ağ trafiğinde bir "
            f"{finding.artifact_type} yakaladım: {finding.preview}{decoded}",
            artifact_callback,
        )

    summary = "\n".join(
        [
            f"Packets scanned: {extraction.packets_scanned}",
            f"Cleartext payloads extracted: {extraction.payloads_extracted}",
            f"DNS queries extracted: {extraction.dns_queries_extracted}",
            f"Files carved: {extraction.carved_files_count}",
        ]
    )
    stdout = summary if not extraction.text else f"{summary}\n\n{extraction.text}"
    return ToolResult(
        tool_name=TOOL_NAME,
        command=command,
        return_code=0 if extraction.packets_scanned else 1,
        stdout=stdout,
        stderr="\n".join(errors),
        flags_found=flags,
        elapsed_seconds=time.monotonic() - started,
        extracted_dir=extraction.carved_dir,
        artifacts_found=artifacts,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_pcap_scanner(
        context.target,
        context.flag_pattern,
        workspace=context.workspace,
        timeout=context.timeout,
        progress_callback=context.report_progress,
        artifact_callback=context.report_artifact,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="pcap_scanner",
        phase=PluginPhase.CONCURRENT,
        priority=47,
        run=_plugin_run,
        contributes_to_mini_wordlist=True,
        required_python_modules=("scapy",),
    ),
)
