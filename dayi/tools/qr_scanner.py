"""Passive, bounded QR decoding for local target and workspace images."""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import importlib
import json
import os
import re
import shutil
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Literal

from dayi.image_analysis import (
    MAX_AGGREGATE_QR_BYTES,
    MAX_AGGREGATE_RECURSIVE_BYTES,
    MAX_DECODED_PIXELS,
    MAX_IMAGE_DIMENSION,
    MAX_QR_PAYLOAD_BYTES,
    MAX_QR_SYMBOLS_PER_IMAGE,
    MAX_QR_VARIANTS_PER_IMAGE,
    MAX_RECURSIVE_IMAGE_BYTES,
    MAX_RECURSIVE_IMAGE_DEPTH,
    MAX_RECURSIVE_IMAGES,
    QRFinding,
    detect_image_magic_bytes,
    discover_images,
    inspect_image_dimensions,
    sanitize_image_text,
)
from dayi.reporter import ToolResult
from dayi.scanner import ArtifactFinding, scan_artifacts, scan_text
from dayi.text_stego import analyze_text_input, detect_text_bytes
from dayi.tools._base import (
    async_run_command_bytes,
    async_run_isolated,
    make_skipped_result,
)
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin


TOOL_NAME = "qr_scanner"
MAX_ZBAR_OUTPUT = MAX_QR_PAYLOAD_BYTES + 2
QR_SUBPROCESS_TIMEOUT = 10.0
MAX_QR_GENERATED_PIXELS = MAX_DECODED_PIXELS * 3
MAX_QR_GENERATED_BYTES = 256 * 1024 * 1024
MAX_NATIVE_QR_RESPONSE = MAX_AGGREGATE_QR_BYTES + 1024 * 1024


def _remaining_plugin_time(deadline: float) -> float:
    return deadline - time.monotonic()


@dataclass(frozen=True)
class QRBackend:
    """One selected optional QR backend, fixed for the plugin invocation."""

    name: Literal["opencv", "pyzbar", "zbarimg"]
    api: Any


@dataclass(frozen=True)
class _DecodedSymbol:
    payload: bytes
    polygon: tuple[tuple[float, float], ...] = ()


@dataclass
class _QRVariantBudget:
    """Aggregate per-image preprocessing budget shared across all frames."""

    max_variants: int = MAX_QR_VARIANTS_PER_IMAGE
    max_generated_pixels: int = MAX_QR_GENERATED_PIXELS
    max_estimated_bytes: int = MAX_QR_GENERATED_BYTES
    variants: int = 0
    generated_pixels: int = 0
    estimated_bytes: int = 0

    def reserve(
        self,
        width: int,
        height: int,
        *,
        bytes_per_pixel: int,
        generated: bool = True,
    ) -> bool:
        pixels = width * height
        if width <= 0 or height <= 0 or pixels > MAX_DECODED_PIXELS:
            return False
        if self.variants >= self.max_variants:
            return False
        added_pixels = pixels if generated else 0
        added_bytes = pixels * max(1, bytes_per_pixel) if generated else 0
        if self.generated_pixels + added_pixels > self.max_generated_pixels:
            return False
        if self.estimated_bytes + added_bytes > self.max_estimated_bytes:
            return False
        self.variants += 1
        self.generated_pixels += added_pixels
        self.estimated_bytes += added_bytes
        return True


def select_qr_backend() -> QRBackend | None:
    """Select the first usable backend without making any one dependency core."""
    try:
        cv2 = importlib.import_module("cv2")
        if callable(getattr(cv2, "QRCodeDetector", None)):
            return QRBackend("opencv", cv2)
    except Exception:
        pass
    try:
        pyzbar = importlib.import_module("pyzbar.pyzbar")
        if callable(getattr(pyzbar, "decode", None)):
            return QRBackend("pyzbar", pyzbar)
    except Exception:
        pass
    executable = shutil.which("zbarimg")
    return QRBackend("zbarimg", executable) if executable else None


def _opencv_variants(
    cv2: Any,
    image: Any,
    *,
    budget: _QRVariantBudget | None = None,
) -> Iterator[tuple[str, Any]]:
    """Yield deterministic OpenCV variants one at a time within one budget."""
    if image is None or not hasattr(image, "shape"):
        return
    height, width = image.shape[:2]
    if width <= 0 or height <= 0 or width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        return
    if width * height > MAX_DECODED_PIXELS:
        return
    active_budget = budget if budget is not None else _QRVariantBudget()
    channels = image.shape[2] if len(image.shape) >= 3 else 1
    if not active_budget.reserve(
        width, height, bytes_per_pixel=channels, generated=False
    ):
        return
    yield "original", image

    if active_budget.reserve(width, height, bytes_per_pixel=1):
        gray = (
            cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            if len(image.shape) >= 3 else image.copy()
        )
        yield "grayscale", gray
        del gray
    if active_budget.reserve(width, height, bytes_per_pixel=2):
        gray = (
            cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            if len(image.shape) >= 3 else image.copy()
        )
        variant = cv2.bitwise_not(gray)
        del gray
        yield "inverted", variant
        del variant
    if active_budget.reserve(width, height, bytes_per_pixel=2):
        gray = (
            cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            if len(image.shape) >= 3 else image.copy()
        )
        variant = cv2.threshold(
            gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
        )[1]
        del gray
        yield "threshold", variant
        del variant
    if max(width, height) <= 1600 and active_budget.reserve(
        width * 2, height * 2, bytes_per_pixel=channels
    ):
        variant = cv2.resize(
            image, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC
        )
        yield "scale-2x", variant
        del variant
    if max(width, height) <= 600 and active_budget.reserve(
        width * 4, height * 4, bytes_per_pixel=channels
    ):
        variant = cv2.resize(
            image, None, fx=4, fy=4, interpolation=cv2.INTER_CUBIC
        )
        yield "scale-4x", variant
        del variant
    for name, rotation in (
        ("rot90", cv2.ROTATE_90_CLOCKWISE),
        ("rot180", cv2.ROTATE_180),
        ("rot270", cv2.ROTATE_90_COUNTERCLOCKWISE),
    ):
        if active_budget.reserve(height, width, bytes_per_pixel=channels):
            variant = cv2.rotate(image, rotation)
            yield name, variant
            del variant
    if len(getattr(image, "shape", ())) == 3 and image.shape[2] == 4:
        for label, level in (("alpha-white", 255.0), ("alpha-black", 0.0)):
            if not active_budget.reserve(width, height, bytes_per_pixel=11):
                continue
            alpha = image[:, :, 3:4].astype(float) / 255.0
            color = image[:, :, :3].astype(float)
            composed = (color * alpha + level * (1.0 - alpha)).astype("uint8")
            del alpha, color
            yield label, composed
            del composed


def _polygon(value: Any) -> tuple[tuple[float, float], ...]:
    try:
        points = value.tolist() if hasattr(value, "tolist") else value
        while len(points) == 1 and isinstance(points[0], (list, tuple)):
            points = points[0]
        return tuple((round(float(item[0]), 3), round(float(item[1]), 3)) for item in points[:8])
    except (IndexError, TypeError, ValueError):
        return ()


def _decode_opencv_variant(cv2: Any, image: Any) -> list[_DecodedSymbol]:
    detector = cv2.QRCodeDetector()
    symbols: list[_DecodedSymbol] = []
    multi = getattr(detector, "detectAndDecodeMulti", None)
    if callable(multi):
        try:
            result = multi(image)
        except Exception:
            result = ()
        if isinstance(result, tuple) and len(result) >= 3 and bool(result[0]):
            texts, points = result[1], result[2]
            for index, text in enumerate(texts[:MAX_QR_SYMBOLS_PER_IMAGE]):
                if text:
                    point = points[index] if points is not None and index < len(points) else ()
                    symbols.append(_DecodedSymbol(str(text).encode("utf-8"), _polygon(point)))
    if not symbols:
        try:
            text, points, _straight = detector.detectAndDecode(image)
        except Exception:
            return []
        if text:
            symbols.append(_DecodedSymbol(str(text).encode("utf-8"), _polygon(points)))
    return symbols[:MAX_QR_SYMBOLS_PER_IMAGE]


def _pillow_qr_variants(
    image: Any,
    image_module: Any,
    image_ops: Any,
    *,
    budget: _QRVariantBudget | None = None,
) -> Iterator[tuple[str, Any]]:
    """Yield and close Pillow transformations one by one."""
    width, height = image.size
    active_budget = budget if budget is not None else _QRVariantBudget()
    source_channels = max(1, len(str(getattr(image, "mode", "RGB"))))
    if not active_budget.reserve(
        width, height, bytes_per_pixel=source_channels, generated=False
    ):
        return
    yield "original", image

    if active_budget.reserve(width, height, bytes_per_pixel=1):
        variant = image_ops.grayscale(image)
        try:
            yield "grayscale", variant
        finally:
            variant.close()
    if active_budget.reserve(width, height, bytes_per_pixel=2):
        gray = image_ops.grayscale(image)
        variant = image_ops.autocontrast(gray)
        gray.close()
        try:
            yield "autocontrast", variant
        finally:
            variant.close()
    if active_budget.reserve(width, height, bytes_per_pixel=2):
        gray = image_ops.grayscale(image)
        variant = image_ops.invert(gray)
        gray.close()
        try:
            yield "inverted", variant
        finally:
            variant.close()
    if active_budget.reserve(width, height, bytes_per_pixel=2):
        gray = image_ops.grayscale(image)
        variant = gray.point(lambda value: 255 if value >= 128 else 0)
        gray.close()
        try:
            yield "threshold", variant
        finally:
            variant.close()
    resampling = getattr(image_module, "Resampling", None)
    resize_filter = getattr(resampling, "LANCZOS", None)
    if max(width, height) <= 1600 and active_budget.reserve(
        width * 2, height * 2, bytes_per_pixel=source_channels
    ):
        variant = image.resize((width * 2, height * 2), resize_filter)
        try:
            yield "scale-2x", variant
        finally:
            variant.close()
    if max(width, height) <= 600 and active_budget.reserve(
        width * 4, height * 4, bytes_per_pixel=source_channels
    ):
        variant = image.resize((width * 4, height * 4), resize_filter)
        try:
            yield "scale-4x", variant
        finally:
            variant.close()
    for name, angle in (("rot90", 90), ("rot180", 180), ("rot270", 270)):
        if active_budget.reserve(height, width, bytes_per_pixel=source_channels):
            variant = image.rotate(angle, expand=True)
            try:
                yield name, variant
            finally:
                variant.close()
    if "A" in str(getattr(image, "mode", "")):
        for name, color in (("alpha-white", "white"), ("alpha-black", "black")):
            if not active_budget.reserve(width, height, bytes_per_pixel=11):
                continue
            rgba = image.convert("RGBA")
            background = image_module.new("RGBA", rgba.size, color)
            background.alpha_composite(rgba)
            variant = background.convert("RGB")
            rgba.close()
            background.close()
            try:
                yield name, variant
            finally:
                variant.close()


def _decode_opencv_image(
    cv2: Any,
    image: Any,
    verbose: bool,
) -> list[tuple[str, _DecodedSymbol]]:
    """Decode a lazy variant stream without retaining transformed arrays."""
    results: list[tuple[str, _DecodedSymbol]] = []
    variants = iter(_opencv_variants(cv2, image, budget=_QRVariantBudget()))
    try:
        for name, variant in variants:
            decoded = _decode_opencv_variant(cv2, variant)
            results.extend((name, symbol) for symbol in decoded)
            del variant
            if decoded and not verbose:
                break
    finally:
        close = getattr(variants, "close", None)
        if callable(close):
            close()
    return results


def _decode_pyzbar(path: Path, api: Any) -> list[tuple[str, _DecodedSymbol]]:
    try:
        image_module = importlib.import_module("PIL.Image")
        image_ops = importlib.import_module("PIL.ImageOps")
        with image_module.open(path) as image:
            width, height = image.size
            if width <= 0 or height <= 0 or width * height > MAX_DECODED_PIXELS:
                return []
            image.load()
            decoded_variants: list[tuple[str, Any]] = []
            budget = _QRVariantBudget()
            for frame_index in range(min(int(getattr(image, "n_frames", 1) or 1), 5)):
                if frame_index:
                    image.seek(frame_index)
                suffix = f"-frame{frame_index}" if getattr(image, "n_frames", 1) > 1 else ""
                variants = iter(_pillow_qr_variants(
                    image, image_module, image_ops, budget=budget
                ))
                try:
                    for name, variant in variants:
                        decoded = api.decode(
                            variant, symbols=None
                        )[:MAX_QR_SYMBOLS_PER_IMAGE]
                        decoded_variants.extend(
                            (name + suffix, item) for item in decoded
                        )
                        del variant
                        if decoded:
                            break
                finally:
                    close = getattr(variants, "close", None)
                    if callable(close):
                        close()
                if len(decoded_variants) >= MAX_QR_SYMBOLS_PER_IMAGE:
                    break
    except Exception:
        return []
    results: list[tuple[str, _DecodedSymbol]] = []
    for variant_name, item in decoded_variants:
        payload = getattr(item, "data", b"")
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        if isinstance(payload, bytes) and payload:
            rect = getattr(item, "rect", None)
            polygon = ()
            if rect is not None:
                polygon = ((float(rect.left), float(rect.top)),)
            results.append((variant_name, _DecodedSymbol(payload, polygon)))
    return results


def _decode_native_worker(
    path: str,
    backend_name: str,
    verbose: bool,
) -> list[tuple[str, _DecodedSymbol]]:
    """Import and run one native QR backend inside an isolated process."""
    image_path = Path(path)
    inspect_image_dimensions(image_path)
    if backend_name == "opencv":
        os.environ["OPENBLAS_NUM_THREADS"] = "1"
        os.environ["OMP_NUM_THREADS"] = "1"
        os.environ["MKL_NUM_THREADS"] = "1"
        cv2 = importlib.import_module("cv2")
        image = cv2.imread(str(image_path), cv2.IMREAD_UNCHANGED)
        if image is None:
            return []
        try:
            return _decode_opencv_image(cv2, image, verbose)
        finally:
            del image
    if backend_name == "pyzbar":
        api = importlib.import_module("pyzbar.pyzbar")
        return _decode_pyzbar(image_path, api)
    raise ValueError("unsupported native QR backend")


async def _decode_native_isolated(
    path: Path,
    backend_name: str,
    verbose: bool,
    *,
    timeout: float,
    worker: Callable[..., list[tuple[str, _DecodedSymbol]]] | None = None,
) -> list[tuple[str, _DecodedSymbol]]:
    """Run native QR decoding under a killable remaining-time deadline."""
    selected_worker = _decode_native_worker if worker is None else worker
    return await async_run_isolated(
        selected_worker,
        str(path),
        backend_name,
        verbose,
        timeout=max(0.01, timeout),
        max_response_bytes=MAX_NATIVE_QR_RESPONSE,
    )


async def _decode_zbar(
    path: Path,
    executable: str,
    *,
    timeout: float = QR_SUBPROCESS_TIMEOUT,
) -> tuple[list[_DecodedSymbol], bool]:
    if timeout <= 0:
        return [], True
    bounded_timeout = min(QR_SUBPROCESS_TIMEOUT, timeout)
    (
        rc,
        stdout,
        _stderr,
        _elapsed,
        timed_out,
        stdout_truncated,
        _stderr_truncated,
    ) = await async_run_command_bytes(
        [executable, "--quiet", "--raw", "--oneshot", str(path)],
        TOOL_NAME,
        timeout=bounded_timeout,
        stdout_limit=MAX_ZBAR_OUTPUT,
        stderr_limit=64 * 1024,
    )
    if timed_out or stdout_truncated or rc not in (0, 4):
        return [], timed_out
    # --oneshot deliberately limits this fallback to one symbol. zbarimg's
    # raw multi-symbol newline framing is ambiguous for binary payloads, so
    # remove exactly its final record delimiter and preserve every payload byte.
    payload = stdout[:-1] if stdout.endswith(b"\n") else stdout
    if len(payload) > MAX_QR_PAYLOAD_BYTES or not payload:
        return [], False
    return [_DecodedSymbol(payload)], False


def classify_qr_payload(payload: bytes) -> str:
    """Classify data passively; classification never triggers an action."""
    kind = detect_image_magic_bytes(payload[:16])
    if kind is not None:
        return "image-data"
    if payload.startswith((b"\x1f\x8b", b"x\x9c", b"x\xda")):
        return "compressed-data"
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    stripped = text.strip()
    lower = stripped.casefold()
    if re.match(r"https?://", stripped, re.IGNORECASE):
        return "url"
    if lower.startswith("mailto:") or re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", stripped):
        return "email"
    if stripped.startswith("WIFI:"):
        return "wifi"
    if stripped.startswith("BEGIN:VCARD"):
        return "vcard"
    if lower.startswith("otpauth://"):
        return "otp-uri"
    if lower.startswith("geo:"):
        return "geographic-coordinates"
    if re.fullmatch(r"[0-9A-Fa-f]{16,}", stripped) and len(stripped) % 2 == 0:
        return "hex-like-text"
    try:
        json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        pass
    else:
        return "json"
    if re.fullmatch(r"[A-Za-z0-9+/_-]{16,}={0,2}", stripped):
        return "base64-like-text"
    return "text"


def _bounded_decompress(payload: bytes, wbits: int) -> bytes | None:
    try:
        decoder = zlib.decompressobj(wbits)
        output = decoder.decompress(payload, MAX_QR_PAYLOAD_BYTES + 1)
        if len(output) > MAX_QR_PAYLOAD_BYTES or decoder.unconsumed_tail:
            return None
        output += decoder.flush(MAX_QR_PAYLOAD_BYTES + 1 - len(output))
        return output if len(output) <= MAX_QR_PAYLOAD_BYTES else None
    except (ValueError, zlib.error):
        return None


def _decode_text_payload(payload: bytes, pattern: re.Pattern) -> tuple[str | None, tuple[str, ...], dict[str, tuple[str, ...]]]:
    variants: list[tuple[bytes, tuple[str, ...]]] = [(payload, ())]
    if payload.startswith(b"\x1f\x8b"):
        expanded = _bounded_decompress(payload, 16 + zlib.MAX_WBITS)
        if expanded is not None:
            variants.append((expanded, ("gzip",)))
    elif payload.startswith((b"x\x9c", b"x\xda", b"x\x01")):
        expanded = _bounded_decompress(payload, zlib.MAX_WBITS)
        if expanded is not None:
            variants.append((expanded, ("zlib",)))

    display_text: str | None = None
    text_variants: list[tuple[str, tuple[str, ...]]] = []
    for value, prefix in variants:
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if display_text is None:
            display_text = sanitize_image_text(decoded, limit=MAX_QR_PAYLOAD_BYTES)
        text_variants.append((decoded, prefix))
        try:
            json_value = json.loads(decoded)
        except (json.JSONDecodeError, TypeError):
            continue
        pending = [json_value]
        scalars = 0
        while pending and scalars < 64:
            item = pending.pop(0)
            if isinstance(item, dict):
                pending.extend(item[key] for key in sorted(item, key=str)[:64])
            elif isinstance(item, list):
                pending.extend(item[:64])
            elif isinstance(item, str) and len(item) <= MAX_QR_PAYLOAD_BYTES:
                text_variants.append((item, prefix + ("json-field",)))
                scalars += 1

    chains: dict[str, tuple[str, ...]] = {}
    for text, prefix in sorted(text_variants, key=lambda item: -len(item[1])):
        for flag in scan_text(text, pattern):
            chains.setdefault(flag, prefix)
        analysis = analyze_text_input(detect_text_bytes(text.encode("utf-8")), pattern)
        for candidate in analysis.candidates:
            for flag in candidate.flags_found:
                chains.setdefault(flag, prefix + candidate.chain)
    return display_text, tuple(chains), chains


def _decoded_image(payload: bytes) -> bytes | None:
    """Decode only clear bounded image encodings, never arbitrary payloads."""
    candidates: list[bytes] = []
    if payload.startswith(b"data:image/") and b"," in payload[:256]:
        header, encoded = payload.split(b",", 1)
        if b";base64" in header.lower():
            try:
                candidates.append(base64.b64decode(encoded, validate=True))
            except (binascii.Error, ValueError):
                pass
    compact = re.sub(rb"\s+", b"", payload)
    if 16 <= len(compact) <= MAX_RECURSIVE_IMAGE_BYTES * 2:
        try:
            candidates.append(base64.b64decode(compact, validate=True))
        except (binascii.Error, ValueError):
            pass
        if len(compact) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f]+", compact):
            try:
                candidates.append(binascii.unhexlify(compact))
            except (binascii.Error, ValueError):
                pass
    for candidate in candidates:
        if 0 < len(candidate) <= MAX_RECURSIVE_IMAGE_BYTES and detect_image_magic_bytes(candidate[:16]):
            return candidate
    return None


def _persist_recursive_image(data: bytes, workspace: Path) -> Path | None:
    kind = detect_image_magic_bytes(data[:16])
    if kind is None:
        return None
    root = workspace / "qr_decoded"
    try:
        root.mkdir(parents=True, exist_ok=True)
        resolved_root = root.resolve()
        digest = hashlib.sha256(data).hexdigest()
        target = root / f"{digest[:24]}.{kind.lower()}"
        if not target.resolve(strict=False).is_relative_to(resolved_root):
            return None
        if not target.exists():
            with target.open("xb") as output:
                output.write(data)
        return target
    except OSError:
        return None


async def run_qr_scanner(
    target: Path,
    workspace: Path,
    flag_pattern: re.Pattern,
    *,
    timeout: float = 45.0,
    verbose: bool = False,
    backend: QRBackend | None = None,
) -> ToolResult:
    """Decode QR symbols passively and feed their text to bounded analyzers."""
    command = ["internal:qr", str(target), str(workspace)]
    selected = backend if backend is not None else select_qr_backend()
    if selected is None:
        return make_skipped_result(TOOL_NAME, "no optional QR backend is available", command)
    initial = list(await asyncio.to_thread(discover_images, target, workspace))
    if not initial:
        return make_skipped_result(TOOL_NAME, "no bounded supported images found", command)

    started = time.monotonic()
    deadline = started + min(45.0, max(1.0, timeout))
    queue: list[tuple[Path, str, int, str]] = [
        (item.path, item.source, 0, item.sha256) for item in initial
    ]
    seen_images = {item.sha256 for item in initial}
    seen_payloads: set[bytes] = set()
    findings: list[QRFinding] = []
    flags: list[str] = []
    extracted_flags: dict[str, list[str]] = {}
    artifacts: list[ArtifactFinding] = []
    aggregate_payload = 0
    recursive_bytes = 0
    recursive_count = 0
    recursive_paths: list[Path] = []
    timed_out = False

    while queue and time.monotonic() < deadline:
        path, source, depth, _digest = queue.pop(0)
        variant_symbols: list[tuple[str, _DecodedSymbol]] = []
        if selected.name in {"opencv", "pyzbar"}:
            remaining = _remaining_plugin_time(deadline)
            if remaining <= 0:
                timed_out = True
                break
            try:
                await asyncio.to_thread(inspect_image_dimensions, path)
                decoded = await _decode_native_isolated(
                    path,
                    selected.name,
                    verbose,
                    timeout=remaining,
                )
                variant_symbols.extend(decoded)
            except asyncio.TimeoutError:
                timed_out = True
                break
            except Exception:
                variant_symbols = []
        else:
            try:
                await asyncio.to_thread(inspect_image_dimensions, path)
            except Exception:
                variant_symbols = []
                continue
            remaining = _remaining_plugin_time(deadline)
            if remaining <= 0:
                timed_out = True
                break
            decoded, timed_out = await _decode_zbar(
                path,
                str(selected.api),
                timeout=remaining,
            )
            variant_symbols.extend(("original", symbol) for symbol in decoded)
            if timed_out:
                break

        ordered = sorted(
            variant_symbols,
            key=lambda item: (
                item[1].polygon[0][1] if item[1].polygon else float("inf"),
                item[1].polygon[0][0] if item[1].polygon else float("inf"),
                item[0], item[1].payload,
            ),
        )
        for variant, symbol in ordered[:MAX_QR_SYMBOLS_PER_IMAGE]:
            payload = symbol.payload
            if not payload or len(payload) > MAX_QR_PAYLOAD_BYTES or payload in seen_payloads:
                continue
            if aggregate_payload + len(payload) > MAX_AGGREGATE_QR_BYTES:
                queue.clear()
                break
            seen_payloads.add(payload)
            aggregate_payload += len(payload)
            payload_type = classify_qr_payload(payload)
            text, found, chains = _decode_text_payload(payload, flag_pattern)
            label = f"{source}>qr:{selected.name}:{variant}"
            for flag in found:
                if flag not in flags:
                    flags.append(flag)
                    chain = chains.get(flag, ())
                    source_label = label + ((">" + ">".join(chain)) if chain else "")
                    extracted_flags.setdefault(source_label, []).append(flag)
            recursive_artifact: str | None = None
            image_data = _decoded_image(payload)
            if (
                image_data is not None and depth < MAX_RECURSIVE_IMAGE_DEPTH
                and recursive_count < MAX_RECURSIVE_IMAGES
                and recursive_bytes + len(image_data) <= MAX_AGGREGATE_RECURSIVE_BYTES
            ):
                digest = hashlib.sha256(image_data).hexdigest()
                if digest not in seen_images:
                    persisted = _persist_recursive_image(image_data, workspace)
                    if persisted is not None:
                        seen_images.add(digest)
                        recursive_count += 1
                        recursive_bytes += len(image_data)
                        recursive_artifact = str(persisted.relative_to(workspace))
                        recursive_paths.append(persisted)
                        queue.append((persisted, f"qr_decoded/{persisted.name}", depth + 1, digest))
            safe_text = text[:512] if text is not None else None
            byte_preview = None if text is not None else payload[:64].hex()
            finding = QRFinding(
                payload_type=payload_type,
                payload_text=safe_text,
                payload_bytes_preview=byte_preview,
                backend=selected.name,
                variant=variant,
                source=source,
                polygon=symbol.polygon,
                flags_found=found,
                decoder_chain=chains.get(found[0], ()) if found else (),
                recursive_artifact=recursive_artifact,
                confidence="confirmed" if found else "high",
            )
            findings.append(finding)
            if text is not None:
                artifacts.extend(scan_artifacts(text, source=label, include_possible=verbose))

    # QR-created images are already decoded recursively above and will be seen
    # by the later OCR plugin. Apply a small compatible local image pass here
    # because metadata/LSB plugins ran before this archive phase.
    if recursive_paths and time.monotonic() < deadline:
        from dayi.tools.exiftool import run_exiftool
        from dayi.tools.lsb import run_lsb
        from dayi.tools.zsteg import run_zsteg

        for decoded_path in recursive_paths[:4]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            per_tool = max(1.0, min(5.0, remaining))
            operations = (
                ("metadata", run_exiftool(decoded_path, flag_pattern, per_tool)),
                ("lsb", run_lsb(decoded_path, flag_pattern, per_tool)),
                ("zsteg", run_zsteg(decoded_path, flag_pattern, per_tool)),
            )
            results = await asyncio.gather(
                *(operation for _name, operation in operations),
                return_exceptions=True,
            )
            for (name, _operation), result in zip(operations, results, strict=True):
                if isinstance(result, BaseException):
                    if isinstance(result, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                        raise result
                    continue
                source_label = f"qr:decoded-image:{decoded_path.name}>{name}"
                nested_flags = list(result.flags_found)
                for child_flags in result.extracted_flags.values():
                    nested_flags.extend(child_flags)
                for flag in nested_flags:
                    if flag not in flags:
                        flags.append(flag)
                        extracted_flags.setdefault(source_label, []).append(flag)
                artifacts.extend(result.artifacts_found)

    stderr = "QR plugin time budget exhausted" if timed_out or time.monotonic() >= deadline else ""
    lines = [
        f"QR backend: {selected.name}",
        "QR payloads are passive; URLs and command-like content are never opened or executed.",
    ]
    for item in findings[:25 if verbose else 10]:
        preview = item.payload_text or item.payload_bytes_preview or "binary"
        lines.append(
            f"[{item.confidence}] {item.source} / {item.variant} [{item.payload_type}]: {preview}"
        )
    return ToolResult(
        tool_name=TOOL_NAME,
        command=command,
        return_code=0,
        stdout="\n".join(lines),
        stderr=stderr,
        flags_found=flags,
        elapsed_seconds=time.monotonic() - started,
        timed_out=bool(stderr),
        extracted_dir=str(workspace / "qr_decoded") if recursive_count else None,
        extracted_flags=extracted_flags,
        artifacts_found=artifacts,
        extraction_succeeded=bool(recursive_count),
        qr_findings=findings[:25 if verbose else 10],
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_qr_scanner(
        context.target,
        context.workspace,
        context.flag_pattern,
        timeout=min(45.0, max(1.0, context.timeout)),
        verbose=context.verbose,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="qr_scanner",
        phase=PluginPhase.ARCHIVE,
        priority=15,
        run=_plugin_run,
    ),
)
