"""Shared bounded primitives for local OCR and passive QR analysis."""
from __future__ import annotations

import hashlib
import importlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dayi.text_stego import escape_unsafe_text


MAX_SOURCE_IMAGE_BYTES = 64 * 1024 * 1024
MAX_DECODED_PIXELS = 50_000_000
MAX_IMAGE_DIMENSION = 20_000
MAX_FRAMES_PER_IMAGE = 5
MAX_SOURCE_IMAGES = 20
MAX_DISCOVERY_ENTRIES = 16_384
MAX_TOTAL_SOURCE_BYTES = 256 * 1024 * 1024
MAX_OCR_VARIANTS_PER_IMAGE = 20
MAX_OCR_INVOCATIONS_PER_IMAGE = 30
MAX_TOTAL_OCR_INVOCATIONS = 200
MAX_OCR_TEXT_PER_INVOCATION = 1024 * 1024
MAX_AGGREGATE_OCR_TEXT = 8 * 1024 * 1024
MAX_QR_VARIANTS_PER_IMAGE = 16
MAX_QR_SYMBOLS_PER_IMAGE = 20
MAX_QR_PAYLOAD_BYTES = 1024 * 1024
MAX_AGGREGATE_QR_BYTES = 8 * 1024 * 1024
MAX_RECURSIVE_IMAGE_DEPTH = 2
MAX_RECURSIVE_IMAGES = 20
MAX_RECURSIVE_IMAGE_BYTES = 8 * 1024 * 1024
MAX_AGGREGATE_RECURSIVE_BYTES = 32 * 1024 * 1024
OCR_INVOCATION_TIMEOUT = 15.0
OCR_PLUGIN_TIMEOUT = 90.0
QR_PLUGIN_TIMEOUT = 45.0
FINDING_PREVIEW_LIMIT = 512
MAX_BOUNDING_BOXES = 64

ImageKind = Literal["PNG", "JPEG", "BMP", "GIF", "TIFF", "WEBP", "PNM"]
FindingConfidence = Literal["confirmed", "high", "medium", "low"]


class ImageSafetyError(ValueError):
    """Raised when bounded metadata cannot establish safe image dimensions."""


@dataclass(frozen=True)
class ImageSource:
    """One content-identified image in the target or managed workspace."""

    path: Path
    source: str
    kind: ImageKind
    size: int
    sha256: str


@dataclass(frozen=True)
class OCRVariant:
    """Deterministic description of one bounded OCR preprocessing pass."""

    name: str
    rotation: int = 0
    scale: int = 1
    channel: str = "original"
    threshold: int | None = None
    inversion: bool = False
    psm: int = 6
    language: str = "eng"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "rotation": self.rotation,
            "scale": self.scale,
            "channel": self.channel,
            "threshold": self.threshold,
            "inversion": self.inversion,
            "psm": self.psm,
            "language": self.language,
        }


@dataclass(frozen=True)
class OCRFinding:
    """One deduplicated, sanitized OCR result suitable for reports."""

    text: str
    sanitized_text: str
    confidence: FindingConfidence
    mean_word_confidence: float | None
    source: str
    variant: OCRVariant
    bounding_boxes: tuple[tuple[int, int, int, int], ...] = ()
    flags_found: tuple[str, ...] = ()
    decoder_chain: tuple[str, ...] = ()
    repeated_count: int = 1
    evidence: tuple[str, ...] = ()
    flag_decoder_chains: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def decoder_chain_for(self, flag: str) -> tuple[str, ...]:
        """Return the precise chain for one flag, with legacy fallback."""
        for mapped_flag, chain in self.flag_decoder_chains:
            if mapped_flag == flag:
                return chain
        return self.decoder_chain if flag in self.flags_found else ()

    def to_dict(self) -> dict[str, object]:
        return {
            "text": self.sanitized_text[:FINDING_PREVIEW_LIMIT],
            "confidence": self.confidence,
            "mean_word_confidence": self.mean_word_confidence,
            "source": self.source,
            "variant": self.variant.to_dict(),
            "bounding_boxes": [list(item) for item in self.bounding_boxes],
            "flags_found": list(self.flags_found),
            "decoder_chain": list(self.decoder_chain),
            "flag_decoder_chains": [
                {"flag": flag, "decoder_chain": list(chain)}
                for flag, chain in self.flag_decoder_chains
            ],
            "repeated_count": self.repeated_count,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class QRFinding:
    """One passive QR decode with bounded, terminal-safe payload data."""

    payload_type: str
    payload_text: str | None
    payload_bytes_preview: str | None
    backend: str
    variant: str
    source: str
    polygon: tuple[tuple[float, float], ...] = ()
    flags_found: tuple[str, ...] = ()
    decoder_chain: tuple[str, ...] = ()
    recursive_artifact: str | None = None
    confidence: FindingConfidence = "high"

    def to_dict(self) -> dict[str, object]:
        return {
            "payload_type": self.payload_type,
            "payload_text": self.payload_text,
            "payload_bytes_preview": self.payload_bytes_preview,
            "backend": self.backend,
            "variant": self.variant,
            "source": self.source,
            "polygon": [list(item) for item in self.polygon],
            "flags_found": list(self.flags_found),
            "decoder_chain": list(self.decoder_chain),
            "recursive_artifact": self.recursive_artifact,
            "confidence": self.confidence,
        }


def sanitize_image_text(value: str, *, limit: int = FINDING_PREVIEW_LIMIT) -> str:
    """Escape controls and bound image-derived text before presentation."""
    return escape_unsafe_text(value, limit=limit)


def detect_image_magic_bytes(header: bytes) -> ImageKind | None:
    """Classify a supported image solely from a bounded byte prefix."""
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if header.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if header.startswith(b"BM"):
        return "BMP"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    if header.startswith((b"II*\x00", b"MM\x00*")):
        return "TIFF"
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return "WEBP"
    if len(header) >= 3 and header[:2] in {
        b"P1", b"P2", b"P3", b"P4", b"P5", b"P6"
    } and header[2:3] in b" \t\r\n":
        return "PNM"
    return None


def detect_image_magic(path: Path) -> ImageKind | None:
    """Read only the header needed for supported image classification."""
    try:
        with path.open("rb") as source:
            return detect_image_magic_bytes(source.read(16))
    except OSError:
        return None


def _header_dimensions(path: Path, kind: ImageKind) -> tuple[int, int, int]:
    """Read bounded format headers when Pillow is not installed."""
    with path.open("rb") as source:
        data = source.read(min(MAX_SOURCE_IMAGE_BYTES, 1024 * 1024))
    try:
        if kind == "PNG" and data[12:16] == b"IHDR":
            width, height = struct.unpack(">II", data[16:24])
            return width, height, 1
        if kind == "GIF":
            width, height = struct.unpack("<HH", data[6:10])
            return width, height, 1
        if kind == "BMP" and len(data) >= 26:
            dib_size = struct.unpack("<I", data[14:18])[0]
            if dib_size == 12:
                width, height = struct.unpack("<HH", data[18:22])
            elif dib_size >= 40:
                width, raw_height = struct.unpack("<ii", data[18:26])
                height = abs(raw_height)
            else:
                raise ImageSafetyError("unsupported BMP header")
            return width, height, 1
        if kind == "JPEG":
            position = 2
            sof_markers = {
                0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF,
            }
            while position + 4 <= len(data):
                if data[position] != 0xFF:
                    position += 1
                    continue
                while position < len(data) and data[position] == 0xFF:
                    position += 1
                if position >= len(data):
                    break
                marker = data[position]
                position += 1
                if marker in {0x01, *range(0xD0, 0xDA)}:
                    continue
                if position + 2 > len(data):
                    break
                segment = struct.unpack(">H", data[position:position + 2])[0]
                if segment < 2 or position + segment > len(data):
                    break
                if marker in sof_markers and segment >= 7:
                    height, width = struct.unpack(">HH", data[position + 3:position + 7])
                    return width, height, 1
                position += segment
        if kind == "PNM":
            tokens: list[bytes] = []
            for line in data.splitlines():
                line = line.split(b"#", 1)[0]
                tokens.extend(line.split())
                if len(tokens) >= 3:
                    break
            if len(tokens) >= 3:
                return int(tokens[1]), int(tokens[2]), 1
        if kind == "WEBP" and len(data) >= 30:
            chunk = data[12:16]
            if chunk == b"VP8X":
                width = int.from_bytes(data[24:27], "little") + 1
                height = int.from_bytes(data[27:30], "little") + 1
                return width, height, 1
            if chunk == b"VP8L" and data[20:21] == b"/":
                bits = int.from_bytes(data[21:25], "little")
                return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1, 1
            if chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
                width = int.from_bytes(data[26:28], "little") & 0x3FFF
                height = int.from_bytes(data[28:30], "little") & 0x3FFF
                return width, height, 1
        if kind == "TIFF" and len(data) >= 8:
            order = "<" if data[:2] == b"II" else ">"
            offset = struct.unpack(order + "I", data[4:8])[0]
            if offset + 2 > len(data):
                raise ImageSafetyError("truncated TIFF directory")
            entries = struct.unpack(order + "H", data[offset:offset + 2])[0]
            dimensions: dict[int, int] = {}
            for index in range(min(entries, 4096)):
                start = offset + 2 + index * 12
                if start + 12 > len(data):
                    break
                tag, value_type, count = struct.unpack(order + "HHI", data[start:start + 8])
                if tag not in {256, 257} or count != 1 or value_type not in {3, 4}:
                    continue
                if value_type == 3:
                    value = struct.unpack(order + "H", data[start + 8:start + 10])[0]
                else:
                    value = struct.unpack(order + "I", data[start + 8:start + 12])[0]
                dimensions[tag] = value
            if 256 in dimensions and 257 in dimensions:
                return dimensions[256], dimensions[257], 1
    except (IndexError, struct.error, ValueError) as exc:
        raise ImageSafetyError("malformed image metadata") from exc
    raise ImageSafetyError("image dimensions could not be inspected safely")


def inspect_image_dimensions(
    path: Path,
    *,
    image_module: object | None = None,
) -> tuple[int, int, int]:
    """Validate source bytes, dimensions, pixels, and frames before decoding."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ImageSafetyError("image metadata is unreadable") from exc
    if size <= 0 or size > MAX_SOURCE_IMAGE_BYTES:
        raise ImageSafetyError("image source size exceeds safety limit")
    kind = detect_image_magic(path)
    if kind is None:
        raise ImageSafetyError("unsupported or malformed image magic")

    module = image_module
    if module is None:
        try:
            module = importlib.import_module("PIL.Image")
        except (ImportError, ModuleNotFoundError):
            module = False
    if module is False:
        width, height, frames = _header_dimensions(path, kind)
    else:
        try:
            with module.open(path) as image:  # type: ignore[union-attr]
                width, height = image.size
                frames = int(getattr(image, "n_frames", 1) or 1)
        except Exception as exc:
            raise ImageSafetyError("malformed image metadata") from exc

    if width <= 0 or height <= 0:
        raise ImageSafetyError("invalid image dimensions")
    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        raise ImageSafetyError("image dimension exceeds safety limit")
    if width * height > MAX_DECODED_PIXELS:
        raise ImageSafetyError("image pixel count exceeds safety limit")
    if frames <= 0 or frames > MAX_FRAMES_PER_IMAGE:
        raise ImageSafetyError("image frame count exceeds safety limit")
    return width, height, frames


def _bounded_digest(path: Path, limit: int = MAX_SOURCE_IMAGE_BYTES) -> str | None:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    return digest.hexdigest()
                total += len(chunk)
                if total > limit:
                    return None
                digest.update(chunk)
    except OSError:
        return None


def discover_images(target: Path, workspace: Path) -> tuple[ImageSource, ...]:
    """Discover bounded, unique images without trusting filename suffixes."""
    candidates: list[tuple[Path, str]] = [(target, f"target:{target.name}")]
    try:
        workspace_root = workspace.resolve()
    except OSError:
        workspace_root = workspace
    visited = 0
    if workspace.is_dir():
        for root, directories, files in os.walk(workspace, followlinks=False):
            directories[:] = sorted(
                name for name in directories if not (Path(root) / name).is_symlink()
            )
            for name in sorted(files):
                visited += 1
                if visited > MAX_DISCOVERY_ENTRIES:
                    break
                candidate = Path(root) / name
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                try:
                    resolved = candidate.resolve()
                    if not resolved.is_relative_to(workspace_root):
                        continue
                    label = str(resolved.relative_to(workspace_root))
                except (OSError, ValueError):
                    continue
                candidates.append((resolved, label))
            if visited > MAX_DISCOVERY_ENTRIES:
                break

    results: list[ImageSource] = []
    seen: set[str] = set()
    total_bytes = 0
    for path, source in candidates:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > MAX_SOURCE_IMAGE_BYTES:
            continue
        kind = detect_image_magic(path)
        if kind is None:
            continue
        digest = _bounded_digest(path)
        if digest is None or digest in seen:
            continue
        if total_bytes + size > MAX_TOTAL_SOURCE_BYTES:
            break
        seen.add(digest)
        total_bytes += size
        results.append(ImageSource(path, source, kind, size, digest))
        if len(results) >= MAX_SOURCE_IMAGES:
            break
    return tuple(results)
