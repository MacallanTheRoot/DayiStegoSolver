"""Bounded validation for files produced by extraction tools."""
from __future__ import annotations

import hashlib
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


MAX_EXTRACTION_VALIDATION_BYTES = 1024 * 1024
MAX_EXTRACTION_FLAGS = 64
_MEANINGFUL_WORD_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9'_-]{2,}")

ExtractionConfidence = Literal["none", "low", "medium", "high"]


@dataclass(frozen=True)
class ExtractionEvidence:
    """Immutable evidence collected from one bounded extraction output."""

    output_exists: bool
    output_size: int
    non_empty: bool
    differs_from_baseline: bool
    known_magic: str | None
    printable_ratio: float
    flags_found: tuple[str, ...]
    meaningful_text: bool
    confidence: ExtractionConfidence
    verified: bool
    content_sha256: str | None = None


def _known_magic(data: bytes) -> str | None:
    """Return a stable label for a recognized file signature."""
    signatures = (
        (b"\xff\xd8\xff", "JPEG"),
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"BM", "BMP"),
        (b"PK\x03\x04", "ZIP"),
        (b"PK\x05\x06", "ZIP"),
        (b"%PDF-", "PDF"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE"),
        (b"\x1f\x8b", "GZIP"),
        (b"Rar!\x1a\x07", "RAR"),
        (b"7z\xbc\xaf\x27\x1c", "7ZIP"),
    )
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "WAV"
    for signature, label in signatures:
        if data.startswith(signature):
            return label
    return None


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data)
    return printable / len(data)


def _meaningful_text(data: bytes, printable_ratio: float) -> bool:
    if len(data) < 16 or printable_ratio < 0.85:
        return False
    text = data.decode("utf-8", errors="replace")
    words = _MEANINGFUL_WORD_PATTERN.findall(text)
    if len(words) < 3:
        return False
    distinct = {character.lower() for word in words for character in word}
    return len(distinct) >= 5


def _flags(data: bytes, pattern: re.Pattern) -> tuple[str, ...]:
    text = data.decode("utf-8", errors="replace")
    found: dict[str, None] = {}
    for match in pattern.finditer(text):
        found[match.group(0)] = None
        if len(found) >= MAX_EXTRACTION_FLAGS:
            break
    return tuple(found)


def _empty_evidence(*, output_exists: bool = False) -> ExtractionEvidence:
    return ExtractionEvidence(
        output_exists=output_exists,
        output_size=0,
        non_empty=False,
        differs_from_baseline=False,
        known_magic=None,
        printable_ratio=0.0,
        flags_found=(),
        meaningful_text=False,
        confidence="none",
        verified=False,
    )


def validate_extracted_payload(
    output_path: Path,
    flag_pattern: re.Pattern,
    *,
    baseline: ExtractionEvidence | None = None,
    max_bytes: int = MAX_EXTRACTION_VALIDATION_BYTES,
) -> ExtractionEvidence:
    """Validate one regular extraction output using only bounded local reads."""
    try:
        metadata = output_path.lstat()
    except OSError:
        return _empty_evidence()
    if not stat.S_ISREG(metadata.st_mode):
        return _empty_evidence(output_exists=True)

    output_size = metadata.st_size
    if output_size <= 0:
        return _empty_evidence(output_exists=True)

    bounded_limit = max(1, min(max_bytes, MAX_EXTRACTION_VALIDATION_BYTES))
    try:
        with output_path.open("rb") as source:
            data = source.read(bounded_limit)
    except OSError:
        return _empty_evidence(output_exists=True)

    digest = hashlib.sha256(data).hexdigest()
    differs = baseline is None or (
        output_size != baseline.output_size
        or digest != baseline.content_sha256
    )
    magic = _known_magic(data)
    ratio = _printable_ratio(data)
    flags = _flags(data, flag_pattern)
    meaningful = _meaningful_text(data, ratio)
    strong_evidence = bool(flags or magic or meaningful)
    verified = differs and strong_evidence
    if flags or magic:
        confidence: ExtractionConfidence = "high" if verified else "low"
    elif meaningful:
        confidence = "medium" if verified else "low"
    else:
        confidence = "low"

    return ExtractionEvidence(
        output_exists=True,
        output_size=output_size,
        non_empty=True,
        differs_from_baseline=differs,
        known_magic=magic,
        printable_ratio=ratio,
        flags_found=flags,
        meaningful_text=meaningful,
        confidence=confidence,
        verified=verified,
        content_sha256=digest,
    )
