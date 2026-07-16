"""Optional OCR plugin for target and runner-owned extracted images."""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from dayi.persona import log_artifact
from dayi.reporter import ToolResult
from dayi.scanner import scan_text
from dayi.tools._base import make_skipped_result
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin

logger = logging.getLogger("dayi")

TOOL_NAME = "ocr_scanner"
MAX_IMAGES = 128
MAX_IMAGE_BYTES = 32 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000
MAX_TEXT_PER_IMAGE = 8 * 1024
OCR_PREVIEW_LIMIT = 180
MAX_PER_IMAGE_TIMEOUT = 15.0

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True)
class OCRDependencies:
    """Late-loaded optional modules required by the OCR implementation."""

    image_module: Any
    pytesseract: Any


def _load_ocr_dependencies() -> OCRDependencies | None:
    """Load Pillow and pytesseract without making them core dependencies."""
    try:
        image_module = importlib.import_module("PIL.Image")
        pytesseract = importlib.import_module("pytesseract")
    except (ImportError, ModuleNotFoundError):
        return None
    return OCRDependencies(image_module=image_module, pytesseract=pytesseract)


def _has_supported_image_magic(path: Path) -> bool:
    """Recognize JPEG, PNG, or BMP from a bounded header read."""
    try:
        with path.open("rb") as source:
            header = source.read(16)
    except OSError:
        return False
    return bool(
        header.startswith(b"\xff\xd8\xff")
        or header.startswith(_PNG_SIGNATURE)
        or header.startswith(b"BM")
    )


def _bounded_digest(path: Path) -> bytes | None:
    """Hash one size-validated image for deterministic content deduplication."""
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_IMAGE_BYTES:
                    return None
                digest.update(chunk)
    except OSError:
        return None
    return digest.digest()


def _discover_images(target: Path, workspace: Path) -> list[tuple[Path, str]]:
    """Find bounded images in the explicit target and runner-owned workspace."""
    raw_candidates: list[tuple[Path, str]] = [(target, f"target:{target.name}")]
    try:
        workspace_root = workspace.resolve()
    except OSError:
        workspace_root = workspace

    if workspace.exists() and workspace.is_dir():
        for candidate in sorted(workspace.rglob("*")):
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                resolved = candidate.resolve()
                if not resolved.is_relative_to(workspace_root):
                    continue
                label = str(resolved.relative_to(workspace_root))
            except (OSError, ValueError):
                continue
            raw_candidates.append((resolved, label))

    images: list[tuple[Path, str]] = []
    seen_content: set[bytes] = set()
    for path, label in raw_candidates:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > MAX_IMAGE_BYTES or not _has_supported_image_magic(path):
            continue
        digest = _bounded_digest(path)
        if digest is None or digest in seen_content:
            continue
        seen_content.add(digest)
        images.append((path, label))
        if len(images) >= MAX_IMAGES:
            break
    return images


def _safe_ocr_text(text: str, limit: int) -> str:
    """Remove terminal controls and bound untrusted OCR output."""
    cleaned = "".join(
        char if char.isprintable() or char in "\n\t" else " " for char in text
    )
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def _ocr_preview(text: str) -> str:
    """Create a compact single-line preview for Dayı artifact output."""
    compact = " ".join(_safe_ocr_text(text, OCR_PREVIEW_LIMIT * 2).split())
    if len(compact) <= OCR_PREVIEW_LIMIT:
        return compact
    return compact[: OCR_PREVIEW_LIMIT - 1] + "…"


def _ocr_image_sync(
    path: Path,
    dependencies: OCRDependencies,
    timeout: float,
) -> str:
    """Open, validate, and OCR one image in a worker thread."""
    with dependencies.image_module.open(path) as image:
        width, height = image.size
        if width <= 0 or height <= 0:
            raise ValueError(f"invalid image dimensions: {width}x{height}")
        if width * height > MAX_IMAGE_PIXELS:
            raise ValueError(
                f"image pixel count exceeds safety limit: {width * height}"
            )
        image.load()
        text = dependencies.pytesseract.image_to_string(image, timeout=timeout)
    if not isinstance(text, str):
        raise TypeError("pytesseract.image_to_string returned non-text output")
    return text


def _emit_artifact(
    message: str,
    artifact_callback: Callable[[str], None] | None,
) -> None:
    """Publish an OCR finding without allowing UI failures to stop scanning."""
    try:
        if artifact_callback is None:
            log_artifact(logger, message)
        else:
            artifact_callback(message)
    except Exception as exc:
        logger.debug(f"[ocr_scanner] Artifact callback failed: {exc}")


async def run_ocr_scanner(
    target: Path,
    workspace: Path,
    flag_pattern: re.Pattern,
    timeout: float = 60.0,
    artifact_callback: Callable[[str], None] | None = None,
) -> ToolResult:
    """OCR the main image and extracted workspace images, then scan for flags."""
    command = ["python:pytesseract", str(target), str(workspace)]
    dependencies = _load_ocr_dependencies()
    if dependencies is None:
        logger.info(
            "[-] Yeğenim OCR gözlüğü çantada yok; Pillow ve pytesseract "
            "kurulursa bu turu da hallederiz."
        )
        return make_skipped_result(
            TOOL_NAME,
            "optional OCR dependencies are unavailable",
            command,
        )

    try:
        await asyncio.to_thread(dependencies.pytesseract.get_tesseract_version)
    except Exception as exc:
        logger.warning(
            "[-] Yeğenim pytesseract hazır ama sistemde Tesseract motoru "
            f"çalışmıyor; OCR turunu geçiyorum. ({exc})"
        )
        return make_skipped_result(
            TOOL_NAME,
            f"Tesseract OCR executable is unavailable: {exc}",
            command,
        )

    images = await asyncio.to_thread(_discover_images, target, workspace)
    if not images:
        logger.info(
            "[-] Yeğenim OCR'lık JPEG/PNG/BMP bulamadım; optik gözlüğü "
            "boşuna takmayalım."
        )
        return make_skipped_result(
            TOOL_NAME,
            "no bounded JPEG, PNG, or BMP images found",
            command,
        )

    logger.info(
        f"[+] Yeğenim, {len(images)} görsel buldum; optik gözlerimi açıp "
        "üstlerindeki yazıları okuyorum..."
    )
    started = time.monotonic()
    deadline = started + max(1.0, timeout)
    all_flags: list[str] = []
    extracted_flags: dict[str, list[str]] = {}
    stdout_sections: list[str] = []
    errors: list[str] = []
    processed = 0

    for path, label in images:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            errors.append("OCR time budget exhausted")
            break
        per_image_timeout = max(1.0, min(MAX_PER_IMAGE_TIMEOUT, remaining))
        try:
            text = await asyncio.to_thread(
                _ocr_image_sync,
                path,
                dependencies,
                per_image_timeout,
            )
        except Exception as exc:
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
            continue

        processed += 1
        hits = scan_text(text, flag_pattern)
        if hits:
            extracted_flags[label] = hits
            for flag in hits:
                if flag not in all_flags:
                    all_flags.append(flag)

        preview = _ocr_preview(text)
        if preview and (hits or sum(char.isalnum() for char in preview) >= 4):
            _emit_artifact(
                "[!] Yeğenim, görselin içinde gizli bir yazı yakaladım: "
                f"{preview}",
                artifact_callback,
            )

        if text.strip():
            stdout_sections.append(
                f"[{label}]\n{_safe_ocr_text(text, MAX_TEXT_PER_IMAGE)}"
            )

    elapsed = time.monotonic() - started
    return ToolResult(
        tool_name=TOOL_NAME,
        command=command,
        return_code=0 if processed else 1,
        stdout="\n\n".join(stdout_sections),
        stderr="\n".join(errors),
        flags_found=all_flags,
        elapsed_seconds=elapsed,
        skipped=False,
        extracted_flags=extracted_flags,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_ocr_scanner(
        context.target,
        context.workspace,
        context.flag_pattern,
        timeout=context.timeout,
        artifact_callback=context.report_artifact,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="ocr_scanner",
        phase=PluginPhase.ARCHIVE,
        priority=20,
        run=_plugin_run,
    ),
)
