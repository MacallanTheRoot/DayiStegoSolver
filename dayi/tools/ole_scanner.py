"""Optional oletools-based VBA macro scanner for OLE and OpenXML targets."""
from __future__ import annotations

import asyncio
import importlib
import logging
import re
import time
import unicodedata
import zipfile
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

TOOL_NAME = "ole_scanner"
MAX_OFFICE_BYTES = 64 * 1024 * 1024
MAX_MACROS = 128
MAX_MACRO_BYTES = 512 * 1024
MAX_LABEL_CHARS = 1024
MAX_OPENXML_MEMBERS = 4096
MAX_OPENXML_UNCOMPRESSED_BYTES = 128 * 1024 * 1024

_OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

ProgressCallback = Callable[[int, int | None], None]
ArtifactCallback = Callable[[str], None]


@dataclass(frozen=True)
class OLEDependencies:
    """Late-loaded oletools module required by the scanner."""

    olevba: Any


@dataclass(frozen=True)
class OLEExtraction:
    """Bounded VBA extraction produced by one parser run."""

    stdout: str
    macro_text: str
    errors: tuple[str, ...]
    parser_type: str
    macros_detected: bool
    macro_count: int


class UnsupportedOfficeFile(ValueError):
    """Raised when olevba does not classify a target as OLE or OpenXML."""


class OLESafetyError(ValueError):
    """Raised when an Office input violates a scanner safety limit."""


def _load_ole_dependencies() -> OLEDependencies | None:
    """Load oletools.olevba without making it a core dependency."""
    try:
        olevba = importlib.import_module("oletools.olevba")
    except (ImportError, ModuleNotFoundError):
        return None
    return OLEDependencies(olevba=olevba)


def _has_office_container_magic(target: Path) -> bool:
    """Recognize OLE Compound File or ZIP-based OpenXML containers."""
    if target.is_symlink() or not target.is_file():
        return False
    try:
        with target.open("rb") as source:
            header = source.read(len(_OLE_MAGIC))
    except OSError:
        return False
    return header.startswith(_OLE_MAGIC) or header.startswith(_ZIP_MAGICS)


def _validate_office_size(target: Path) -> None:
    """Reject oversized Office inputs and OpenXML ZIP bombs."""
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise OLESafetyError(f"cannot stat Office input: {exc}") from exc
    if size <= 0:
        raise OLESafetyError("Office input is empty")
    if size > MAX_OFFICE_BYTES:
        raise OLESafetyError(
            f"Office size {size} exceeds safety limit {MAX_OFFICE_BYTES}"
        )

    try:
        with target.open("rb") as source:
            is_openxml = source.read(4).startswith(_ZIP_MAGICS)
    except OSError as exc:
        raise OLESafetyError(f"cannot inspect Office input: {exc}") from exc
    if not is_openxml:
        return

    try:
        with zipfile.ZipFile(target) as archive:
            members = archive.infolist()
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise OLESafetyError(f"invalid OpenXML ZIP container: {exc}") from exc
    if len(members) > MAX_OPENXML_MEMBERS:
        raise OLESafetyError(
            f"OpenXML member count {len(members)} exceeds safety limit "
            f"{MAX_OPENXML_MEMBERS}"
        )
    total_uncompressed = sum(member.file_size for member in members)
    if total_uncompressed > MAX_OPENXML_UNCOMPRESSED_BYTES:
        raise OLESafetyError(
            f"OpenXML expanded size {total_uncompressed} exceeds safety limit "
            f"{MAX_OPENXML_UNCOMPRESSED_BYTES}"
        )


def _coerce_safe_text(value: Any, limit: int) -> str:
    """Convert macro data to bounded text without terminal controls."""
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            text = value.decode("latin-1", errors="replace")
    else:
        try:
            text = str(value)
        except Exception:
            text = "<unprintable macro value>"

    text = text[:limit]
    cleaned = "".join(
        char
        if char in "\n\t" or not unicodedata.category(char).startswith("C")
        else " "
        for char in text
    )
    return cleaned


def _coerce_bounded_macro(value: Any, byte_limit: int) -> tuple[str, bool]:
    """Convert VBA source to safe text within an exact UTF-8 byte limit."""
    if byte_limit <= 0:
        return "", True

    truncated = False
    if isinstance(value, bytes):
        truncated = len(value) > byte_limit
        raw_value = value[:byte_limit]
        try:
            text = raw_value.decode("utf-8")
        except UnicodeDecodeError:
            text = raw_value.decode("latin-1", errors="replace")
    elif isinstance(value, str):
        # Every Unicode code point occupies at least one UTF-8 byte, so this
        # character slice also prevents an oversized temporary encoding.
        truncated = len(value) > byte_limit
        text = value[:byte_limit]
    else:
        try:
            text = str(value)
        except Exception:
            text = "<unprintable macro value>"
        truncated = len(text) > byte_limit
        text = text[:byte_limit]

    cleaned = "".join(
        char
        if char in "\n\t" or not unicodedata.category(char).startswith("C")
        else " "
        for char in text
    )
    encoded = cleaned.encode("utf-8")
    if len(encoded) <= byte_limit:
        return cleaned, truncated

    # Ignoring an incomplete trailing code point makes the result valid UTF-8
    # while guaranteeing that the hard byte ceiling is never exceeded.
    return encoded[:byte_limit].decode("utf-8", errors="ignore"), True


def _safe_callback(
    callback: Callable[..., None] | None,
    *args: object,
) -> None:
    """Invoke one UI callback without allowing it to stop analysis."""
    if callback is None:
        return
    try:
        callback(*args)
    except Exception as exc:
        logger.debug(
            f"[ole_scanner] Sunum geri çağrısı tökezledi yeğenim: {exc}"
        )


def _supported_parser_types(olevba: Any) -> set[Any]:
    """Return documented OLE/OpenXML parser type constants when available."""
    return {
        parser_type
        for parser_type in (
            getattr(olevba, "TYPE_OLE", None),
            getattr(olevba, "TYPE_OpenXML", None),
        )
        if parser_type is not None
    }


def _extract_ole_sync(
    target: Path,
    dependencies: OLEDependencies,
    timeout: float,
    progress_callback: ProgressCallback | None,
) -> OLEExtraction:
    """Detect and extract bounded VBA source with documented olevba APIs."""
    deadline = time.monotonic() + max(1.0, timeout)
    parser: Any | None = None
    errors: list[str] = []
    sections: list[str] = []
    macro_source_parts: list[str] = []
    combined_bytes = 0
    macro_count = 0

    try:
        parser = dependencies.olevba.VBA_Parser(str(target))
        parser_type_value = getattr(parser, "type", None)
        supported_types = _supported_parser_types(dependencies.olevba)
        if supported_types and parser_type_value not in supported_types:
            raise UnsupportedOfficeFile(
                f"unsupported olevba parser type: {parser_type_value!r}"
            )
        parser_type = _coerce_safe_text(
            parser_type_value if parser_type_value is not None else "unknown",
            128,
        )

        macros_detected = bool(parser.detect_vba_macros())
        if not macros_detected:
            return OLEExtraction(
                stdout="\n".join(
                    [
                        f"Container type: {parser_type}",
                        "VBA macros detected: no",
                        "Macros extracted: 0",
                    ]
                ),
                macro_text="",
                errors=(),
                parser_type=parser_type,
                macros_detected=False,
                macro_count=0,
            )

        try:
            macro_iterator = parser.extract_macros()
            for index, macro_record in enumerate(macro_iterator):
                if index >= MAX_MACROS:
                    errors.append(f"macro limit reached ({MAX_MACROS})")
                    break
                if time.monotonic() >= deadline:
                    errors.append(
                        f"OLE time budget exhausted after {index} macros"
                    )
                    break
                try:
                    filename, stream_path, vba_filename, vba_code = macro_record
                except (TypeError, ValueError) as exc:
                    errors.append(
                        f"macro {index + 1}: invalid extract_macros tuple: {exc}"
                    )
                    _safe_callback(progress_callback, index + 1, None)
                    continue

                separator = "\n\n" if macro_source_parts else ""
                separator_bytes = len(separator.encode("utf-8"))
                remaining = MAX_MACRO_BYTES - combined_bytes
                if separator_bytes > remaining:
                    errors.append(
                        f"combined VBA source limit reached ({MAX_MACRO_BYTES} bytes)"
                    )
                    break
                if separator:
                    macro_source_parts.append(separator)
                    combined_bytes += separator_bytes
                    remaining -= separator_bytes
                if remaining <= 0:
                    errors.append(
                        f"combined VBA source limit reached ({MAX_MACRO_BYTES} bytes)"
                    )
                    break
                code, code_truncated = _coerce_bounded_macro(vba_code, remaining)
                code_bytes = len(code.encode("utf-8"))
                macro_source_parts.append(code)
                combined_bytes += code_bytes
                macro_count += 1

                safe_filename = _coerce_safe_text(
                    filename, MAX_LABEL_CHARS
                ).strip()
                safe_stream = _coerce_safe_text(
                    stream_path, MAX_LABEL_CHARS
                ).strip()
                safe_vba_filename = _coerce_safe_text(
                    vba_filename, MAX_LABEL_CHARS
                ).strip()
                sections.append(
                    "\n".join(
                        [
                            f"[Macro {index + 1}]",
                            f"Container: {safe_filename}",
                            f"OLE stream: {safe_stream}",
                            f"VBA filename: {safe_vba_filename}",
                            code,
                        ]
                    )
                )
                _safe_callback(progress_callback, index + 1, None)
                if code_truncated or combined_bytes >= MAX_MACRO_BYTES:
                    errors.append(
                        f"combined VBA source truncated at {MAX_MACRO_BYTES} bytes"
                    )
                    break
        except Exception as exc:
            errors.append(
                f"macro extraction failed: {type(exc).__name__}: {exc}"
            )

        header = "\n".join(
            [
                f"Container type: {parser_type}",
                "VBA macros detected: yes",
                f"Macros extracted: {macro_count}",
                f"VBA source bytes retained: {combined_bytes}/{MAX_MACRO_BYTES}",
            ]
        )
        stdout = "\n\n".join([header, *sections])
        return OLEExtraction(
            stdout=stdout,
            macro_text="".join(macro_source_parts),
            errors=tuple(errors),
            parser_type=parser_type,
            macros_detected=True,
            macro_count=macro_count,
        )
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception as exc:
                logger.debug(
                    "[ole_scanner] Office sandığını kapatırken ufak bir "
                    f"pürüz çıktı yeğenim: {exc}"
                )


def _extract_ole_isolated(target: Path, timeout: float) -> OLEExtraction:
    """Load olevba and extract macros inside an isolated parser process."""
    dependencies = _load_ole_dependencies()
    if dependencies is None:
        raise ImportError("optional oletools dependency is unavailable")
    return _extract_ole_sync(target, dependencies, timeout, None)


def _emit_artifact(
    message: str,
    artifact_callback: ArtifactCallback | None,
) -> None:
    """Publish an OLE finding through the active UI or plain logger."""
    if artifact_callback is None:
        log_artifact(logger, message)
    else:
        _safe_callback(artifact_callback, message)


async def run_ole_scanner(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float = 60.0,
    progress_callback: ProgressCallback | None = None,
    artifact_callback: ArtifactCallback | None = None,
) -> ToolResult:
    """Extract VBA source and scan it for flags and passive artifacts."""
    command = ["python:oletools.olevba", str(target)]
    if not _has_office_container_magic(target):
        return make_skipped_result(
            TOOL_NAME,
            "target is not an OLE or ZIP-based OpenXML container",
            command,
        )

    try:
        _validate_office_size(target)
    except OLESafetyError as exc:
        logger.warning(f"[-] Yeğenim Office güvenlik sınırına takıldı: {exc}")
        return make_skipped_result(TOOL_NAME, str(exc), command)

    dependencies = _load_ole_dependencies()
    if dependencies is None:
        logger.info(
            "[-] Yeğenim makro büyüteci çantada yok; oletools kurulursa "
            "Office sandığını da eşelerim."
        )
        return make_skipped_result(
            TOOL_NAME,
            "optional oletools dependency is unavailable",
            command,
        )

    logger.info(
        "[+] Yeğenim, bu eski püskü Office dosyasının içinde makro "
        "virüsü mü var, bir bakalım..."
    )
    started = time.monotonic()
    try:
        if isinstance(dependencies.olevba, ModuleType):
            extraction = await async_run_isolated(
                _extract_ole_isolated, target, timeout, timeout=timeout
            )
        else:
            extraction = await asyncio.to_thread(
                _extract_ole_sync,
                target,
                dependencies,
                timeout,
                progress_callback,
            )
    except asyncio.TimeoutError:
        return ToolResult(
            tool_name=TOOL_NAME,
            command=command,
            return_code=None,
            stdout="",
            stderr="OLE/VBA parsing time budget exhausted",
            flags_found=[],
            elapsed_seconds=time.monotonic() - started,
            timed_out=True,
        )
    except UnsupportedOfficeFile as exc:
        logger.info(
            f"[-] Yeğenim bu kap olevba'nın tanıdığı Office türü değil: {exc}"
        )
        return make_skipped_result(TOOL_NAME, str(exc), command)
    except Exception as exc:
        reason = f"OLE/VBA parsing failed: {type(exc).__name__}: {exc}"
        logger.warning(
            f"[-] Yeğenim Office sandığının kilidi dağıldı, okuyamadım: {exc}"
        )
        return make_skipped_result(TOOL_NAME, reason, command)

    if not extraction.macros_detected:
        logger.info(
            "[-] Yeğenim Office dosyasını didikledim; saklı VBA makrosu "
            "çıkmadı."
        )
        return ToolResult(
            tool_name=TOOL_NAME,
            command=command,
            return_code=0,
            stdout=extraction.stdout,
            stderr="",
            flags_found=[],
            elapsed_seconds=time.monotonic() - started,
        )

    _emit_artifact(
        "[!] Yeğenim, Office sandığında VBA makro izi buldum; "
        f"{extraction.macro_count} kaynak modülü çıkardım!",
        artifact_callback,
    )

    flags = scan_text(extraction.macro_text, flag_pattern)
    artifacts: list[ArtifactFinding] = scan_artifacts(
        extraction.macro_text,
        source=f"{TOOL_NAME}/vba-source",
    )
    for finding in artifacts:
        decoded = (
            f" | çözülen: {finding.decoded_preview}"
            if finding.decoded_preview is not None
            else ""
        )
        _emit_artifact(
            "[!] Yeğenim, makronun satır arasında bir "
            f"{finding.artifact_type} buldum: {finding.preview}{decoded}",
            artifact_callback,
        )

    return ToolResult(
        tool_name=TOOL_NAME,
        command=command,
        return_code=0 if extraction.macro_count else 1,
        stdout=extraction.stdout,
        stderr="\n".join(extraction.errors),
        flags_found=flags,
        elapsed_seconds=time.monotonic() - started,
        artifacts_found=artifacts,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_ole_scanner(
        context.target,
        context.flag_pattern,
        timeout=context.timeout,
        progress_callback=context.report_progress,
        artifact_callback=context.report_artifact,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="ole_scanner",
        phase=PluginPhase.CONCURRENT,
        priority=46,
        run=_plugin_run,
        contributes_to_mini_wordlist=True,
    ),
)
