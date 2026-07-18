"""Optional pypdf-based metadata and text scanner for PDF targets."""
from __future__ import annotations

import asyncio
import importlib
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

TOOL_NAME = "pdf_scanner"
MAX_PDF_BYTES = 64 * 1024 * 1024
MAX_PAGES = 256
MAX_METADATA_ITEMS = 128
MAX_METADATA_VALUE_CHARS = 16 * 1024
MAX_PAGE_TEXT_CHARS = 256 * 1024
MAX_COMBINED_TEXT_CHARS = 2 * 1024 * 1024

_PDF_MAGIC = b"%PDF-"

ProgressCallback = Callable[[int, int | None], None]
ArtifactCallback = Callable[[str], None]


@dataclass(frozen=True)
class PDFDependencies:
    """Late-loaded optional module required by the PDF implementation."""

    pypdf: Any


@dataclass(frozen=True)
class PDFExtraction:
    """Bounded text and diagnostics extracted from one PDF."""

    stdout: str
    errors: tuple[str, ...]
    encrypted: bool
    empty_password_accepted: bool


class EncryptedPDFError(ValueError):
    """Raised when an encrypted PDF rejects the empty password."""


class PDFSafetyError(ValueError):
    """Raised when an input violates a PDF scanner safety limit."""


def _load_pdf_dependencies() -> PDFDependencies | None:
    """Load pypdf without making it a mandatory core dependency."""
    try:
        pypdf = importlib.import_module("pypdf")
    except (ImportError, ModuleNotFoundError):
        return None
    return PDFDependencies(pypdf=pypdf)


def _has_pdf_magic(target: Path) -> bool:
    """Return whether a regular, non-symlink file starts with %PDF-."""
    if target.is_symlink() or not target.is_file():
        return False
    try:
        with target.open("rb") as source:
            return source.read(len(_PDF_MAGIC)) == _PDF_MAGIC
    except OSError:
        return False


def _validate_pdf_size(target: Path) -> None:
    """Reject empty or oversized PDF inputs before invoking pypdf."""
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise PDFSafetyError(f"cannot stat PDF input: {exc}") from exc
    if size <= 0:
        raise PDFSafetyError("PDF input is empty")
    if size > MAX_PDF_BYTES:
        raise PDFSafetyError(
            f"PDF size {size} exceeds safety limit {MAX_PDF_BYTES}"
        )


def _safe_text(value: Any, limit: int) -> str:
    """Convert an untrusted PDF value into bounded, terminal-safe text."""
    try:
        text = str(value)
    except Exception:
        text = "<unprintable PDF value>"
    text = text[:limit]
    cleaned = "".join(
        char
        if char in "\n\t" or not unicodedata.category(char).startswith("C")
        else " "
        for char in text
    )
    return cleaned


def _safe_callback(
    callback: Callable[..., None] | None,
    *args: object,
) -> None:
    """Invoke a presentation callback without disrupting PDF analysis."""
    if callback is None:
        return
    try:
        callback(*args)
    except Exception as exc:
        logger.debug(
            f"[pdf_scanner] Sunum geri çağrısı tökezledi yeğenim: {exc}"
        )


def _extract_pdf_sync(
    target: Path,
    dependencies: PDFDependencies,
    timeout: float,
    progress_callback: ProgressCallback | None,
) -> PDFExtraction:
    """Extract bounded metadata and page text using documented pypdf APIs."""
    deadline = time.monotonic() + max(1.0, timeout)
    reader: Any | None = None
    errors: list[str] = []
    sections: list[str] = []
    combined_chars = 0
    encrypted = False
    empty_password_accepted = False

    def append_section(section: str) -> bool:
        nonlocal combined_chars
        remaining = MAX_COMBINED_TEXT_CHARS - combined_chars
        if remaining <= 0:
            return False
        bounded = section[:remaining]
        sections.append(bounded)
        combined_chars += len(bounded)
        return len(bounded) == len(section)

    try:
        reader = dependencies.pypdf.PdfReader(target, strict=False)
        encrypted = bool(reader.is_encrypted)
        if encrypted:
            try:
                decryption_status = reader.decrypt("")
                empty_password_accepted = int(decryption_status) != 0
            except Exception as exc:
                raise EncryptedPDFError(
                    f"empty-password decryption failed: {exc}"
                ) from exc
            if not empty_password_accepted:
                raise EncryptedPDFError("PDF rejects the empty password")

        metadata_lines: list[str] = []
        try:
            metadata = reader.metadata
        except Exception as exc:
            metadata = None
            errors.append(f"metadata extraction failed: {type(exc).__name__}: {exc}")

        if metadata is not None:
            metadata_lines = ["[Metadata]"]
            try:
                for index, (key, value) in enumerate(metadata.items()):
                    if index >= MAX_METADATA_ITEMS:
                        errors.append(
                            f"metadata item limit reached ({MAX_METADATA_ITEMS})"
                        )
                        break
                    safe_key = _safe_text(key, 256).strip() or "<empty-key>"
                    safe_value = _safe_text(value, MAX_METADATA_VALUE_CHARS)
                    metadata_lines.append(f"{safe_key}: {safe_value}")
            except Exception as exc:
                errors.append(
                    f"metadata iteration failed: {type(exc).__name__}: {exc}"
                )

        try:
            total_pages = len(reader.pages)
        except Exception as exc:
            total_pages = 0
            errors.append(f"page enumeration failed: {type(exc).__name__}: {exc}")

        pages_to_scan = min(total_pages, MAX_PAGES)
        if total_pages > MAX_PAGES:
            errors.append(
                f"page limit reached: scanning {MAX_PAGES} of {total_pages} pages"
            )

        header = "\n".join(
            [
                f"PDF encrypted: {'yes' if encrypted else 'no'}",
                f"Empty password accepted: "
                f"{'yes' if empty_password_accepted else 'not required'}",
                f"Pages reported: {total_pages}",
                f"Pages selected: {pages_to_scan}",
            ]
        )
        append_section(header)
        if len(metadata_lines) > 1:
            if not append_section("\n".join(metadata_lines)):
                errors.append("combined PDF text limit reached in metadata")

        for index in range(pages_to_scan):
            if time.monotonic() >= deadline:
                errors.append(
                    f"PDF time budget exhausted after {index} of "
                    f"{pages_to_scan} pages"
                )
                break
            try:
                raw_text = reader.pages[index].extract_text()
                page_text = "" if raw_text is None else _safe_text(
                    raw_text, MAX_PAGE_TEXT_CHARS
                )
            except Exception as exc:
                errors.append(
                    f"page {index + 1}: {type(exc).__name__}: {exc}"
                )
                _safe_callback(progress_callback, index + 1, pages_to_scan)
                continue

            if page_text.strip():
                if not append_section(f"[Page {index + 1}]\n{page_text}"):
                    errors.append(
                        f"combined PDF text limit reached at page {index + 1}"
                    )
                    _safe_callback(progress_callback, index + 1, pages_to_scan)
                    break
            _safe_callback(progress_callback, index + 1, pages_to_scan)

        return PDFExtraction(
            stdout="\n\n".join(sections),
            errors=tuple(errors),
            encrypted=encrypted,
            empty_password_accepted=empty_password_accepted,
        )
    finally:
        if reader is not None:
            close = getattr(reader, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    logger.debug(
                        "[pdf_scanner] PDF'in kapağını kapatırken ufak bir "
                        f"pürüz çıktı yeğenim: {exc}"
                    )


def _extract_pdf_isolated(target: Path, timeout: float) -> PDFExtraction:
    """Load pypdf and extract content inside an isolated parser process."""
    dependencies = _load_pdf_dependencies()
    if dependencies is None:
        raise ImportError("optional pypdf dependency is unavailable")
    return _extract_pdf_sync(target, dependencies, timeout, None)


def _emit_artifact(
    message: str,
    artifact_callback: ArtifactCallback | None,
) -> None:
    """Publish a PDF finding through the active UI or plain logger."""
    if artifact_callback is None:
        log_artifact(logger, message)
    else:
        _safe_callback(artifact_callback, message)


async def run_pdf_scanner(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float = 60.0,
    progress_callback: ProgressCallback | None = None,
    artifact_callback: ArtifactCallback | None = None,
) -> ToolResult:
    """Extract PDF metadata/text and scan it for flags and passive artifacts."""
    command = ["python:pypdf", str(target)]
    if not _has_pdf_magic(target):
        return make_skipped_result(
            TOOL_NAME,
            "target does not start with the PDF magic bytes",
            command,
        )

    try:
        _validate_pdf_size(target)
    except PDFSafetyError as exc:
        logger.warning(f"[-] Yeğenim PDF güvenlik sınırına takıldı: {exc}")
        return make_skipped_result(TOOL_NAME, str(exc), command)

    dependencies = _load_pdf_dependencies()
    if dependencies is None:
        logger.info(
            "[-] Yeğenim PDF büyüteci çantada yok; pypdf kurulursa "
            "sayfaların arasına da bakarım."
        )
        return make_skipped_result(
            TOOL_NAME,
            "optional pypdf dependency is unavailable",
            command,
        )

    logger.info(
        "[+] Yeğenim, PDF'in sayfalarını tek tek çeviriyorum, "
        "satır aralarına bakıyorum..."
    )
    started = time.monotonic()
    try:
        if isinstance(dependencies.pypdf, ModuleType):
            extraction = await async_run_isolated(
                _extract_pdf_isolated, target, timeout, timeout=timeout
            )
        else:
            extraction = await asyncio.to_thread(
                _extract_pdf_sync,
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
            stderr="PDF parsing time budget exhausted",
            flags_found=[],
            elapsed_seconds=time.monotonic() - started,
            timed_out=True,
        )
    except EncryptedPDFError as exc:
        message = (
            "[!] Yeğenim, PDF kilitli çıktı; boş anahtar da uymadı, "
            "bu turu es geçiyorum."
        )
        _emit_artifact(message, artifact_callback)
        logger.warning(
            "[pdf_scanner] Boş anahtar PDF kilidine uymadı yeğenim. "
            f"({exc})"
        )
        return make_skipped_result(TOOL_NAME, str(exc), command)
    except Exception as exc:
        reason = f"PDF parsing failed: {type(exc).__name__}: {exc}"
        logger.warning(f"[-] Yeğenim PDF'in cildi dağıldı, okuyamadım: {exc}")
        return make_skipped_result(TOOL_NAME, reason, command)

    if extraction.encrypted:
        _emit_artifact(
            "[!] Yeğenim, PDF kilitliymiş ama boş anahtar kapıyı açtı; "
            "sayfaları taramaya devam ettim.",
            artifact_callback,
        )

    flags = scan_text(extraction.stdout, flag_pattern)
    artifacts: list[ArtifactFinding] = scan_artifacts(
        extraction.stdout,
        source=f"{TOOL_NAME}/pdf-content",
    )
    for finding in artifacts:
        decoded = (
            f" | çözülen: {finding.decoded_preview}"
            if finding.decoded_preview is not None
            else ""
        )
        _emit_artifact(
            "[!] Yeğenim, PDF'in satır arasında bir "
            f"{finding.artifact_type} buldum: {finding.preview}{decoded}",
            artifact_callback,
        )

    return ToolResult(
        tool_name=TOOL_NAME,
        command=command,
        return_code=0,
        stdout=extraction.stdout,
        stderr="\n".join(extraction.errors),
        flags_found=flags,
        elapsed_seconds=time.monotonic() - started,
        artifacts_found=artifacts,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_pdf_scanner(
        context.target,
        context.flag_pattern,
        timeout=context.timeout,
        progress_callback=context.report_progress,
        artifact_callback=context.report_artifact,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="pdf_scanner",
        phase=PluginPhase.CONCURRENT,
        priority=45,
        run=_plugin_run,
        contributes_to_mini_wordlist=True,
        required_python_modules=("pypdf",),
    ),
)
