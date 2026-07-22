"""Bounded multi-pass OCR for target and runner-owned extracted images."""
from __future__ import annotations

import asyncio
import importlib
import re
import shutil
import statistics
import time
from dataclasses import dataclass, replace
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterator

from dayi.image_analysis import (
    MAX_AGGREGATE_OCR_TEXT,
    MAX_DECODED_PIXELS,
    MAX_IMAGE_DIMENSION,
    MAX_OCR_INVOCATIONS_PER_IMAGE,
    MAX_OCR_TEXT_PER_INVOCATION,
    MAX_OCR_VARIANTS_PER_IMAGE,
    MAX_SOURCE_IMAGE_BYTES,
    MAX_SOURCE_IMAGES,
    MAX_TOTAL_OCR_INVOCATIONS,
    OCR_INVOCATION_TIMEOUT,
    OCRFinding,
    OCRVariant,
    discover_images,
    sanitize_image_text,
)
from dayi.persona import log_artifact
from dayi.reporter import ToolResult
from dayi.scanner import ArtifactFinding, scan_artifacts, scan_text
from dayi.text_stego import (
    MAX_DIRECT_FLAG_LENGTH,
    analyze_text_input,
    detect_text_bytes,
)
from dayi.tools._base import async_run_command, async_run_isolated, make_skipped_result
from dayi.tools._opencv import configure_opencv_runtime
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin

try:
    from re import _parser as _regex_parser
except ImportError:  # pragma: no cover - Python 3.10 compatibility
    import sre_parse as _regex_parser


TOOL_NAME = "ocr_scanner"
MAX_IMAGES = MAX_SOURCE_IMAGES
MAX_IMAGE_BYTES = MAX_SOURCE_IMAGE_BYTES
MAX_IMAGE_PIXELS = MAX_DECODED_PIXELS
MAX_TEXT_PER_IMAGE = MAX_OCR_TEXT_PER_INVOCATION
MAX_PER_IMAGE_TIMEOUT = OCR_INVOCATION_TIMEOUT
OCR_PREVIEW_LIMIT = 180
MAX_OCR_ANALYSIS_RESPONSE = 32 * 1024 * 1024
MAX_OCR_GENERATED_PIXELS = MAX_DECODED_PIXELS * 3
MAX_OCR_GENERATED_BYTES = 256 * 1024 * 1024
OCR_LANGUAGE_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\+[A-Za-z0-9][A-Za-z0-9_-]*)*\Z"
)


@dataclass(frozen=True)
class OCRDependencies:
    """Late-loaded optional APIs used by OCR preprocessing and Tesseract."""

    image_module: Any
    pytesseract: Any
    image_ops: Any | None = None
    image_enhance: Any | None = None
    image_filter: Any | None = None


@dataclass(frozen=True)
class _OCRPass:
    text: str
    mean_confidence: float | None
    boxes: tuple[tuple[int, int, int, int], ...]


@dataclass
class _OCRVariantBudget:
    """Aggregate preprocessing work allowed for one source image."""

    max_variants: int = MAX_OCR_VARIANTS_PER_IMAGE
    max_generated_pixels: int = MAX_OCR_GENERATED_PIXELS
    max_estimated_bytes: int = MAX_OCR_GENERATED_BYTES
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
        if (
            width <= 0
            or height <= 0
            or width > MAX_IMAGE_DIMENSION
            or height > MAX_IMAGE_DIMENSION
            or pixels > MAX_DECODED_PIXELS
            or self.variants >= self.max_variants
        ):
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


def validate_ocr_language(value: str) -> str:
    """Return a safe Tesseract language expression or raise ValueError."""
    if not isinstance(value, str) or OCR_LANGUAGE_PATTERN.fullmatch(value) is None:
        raise ValueError("OCR language must use letters, digits, '_', '-' and '+' only")
    return value


def _load_ocr_dependencies() -> OCRDependencies | None:
    try:
        return OCRDependencies(
            image_module=importlib.import_module("PIL.Image"),
            pytesseract=importlib.import_module("pytesseract"),
            image_ops=importlib.import_module("PIL.ImageOps"),
            image_enhance=importlib.import_module("PIL.ImageEnhance"),
            image_filter=importlib.import_module("PIL.ImageFilter"),
        )
    except (ImportError, ModuleNotFoundError):
        return None


def _has_supported_image_magic(path: Path) -> bool:
    return bool(discover_images(path, path.parent / ".dayi-no-workspace"))


def _discover_images(target: Path, workspace: Path) -> list[tuple[Path, str]]:
    """Compatibility view over shared content-based image discovery."""
    return [(item.path, item.source) for item in discover_images(target, workspace)]


def _safe_ocr_text(text: str, limit: int) -> str:
    return sanitize_image_text(text, limit=limit)


def _ocr_preview(text: str) -> str:
    compact = " ".join(_safe_ocr_text(text, OCR_PREVIEW_LIMIT * 2).split())
    return compact if len(compact) <= OCR_PREVIEW_LIMIT else compact[:179] + "…"


def _validate_dimensions(image: Any) -> None:
    width, height = image.size
    if width <= 0 or height <= 0:
        raise ValueError("invalid image dimensions")
    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        raise ValueError("image dimension exceeds safety limit")
    if width * height > MAX_DECODED_PIXELS:
        raise ValueError("image pixel count exceeds safety limit")


def _call_image_to_string(
    engine: Any, image: Any, timeout: float, language: str, psm: int
) -> str:
    try:
        value = engine.image_to_string(
            image, timeout=timeout, lang=language, config=f"--psm {psm}"
        )
    except TypeError:
        value = engine.image_to_string(image, timeout=timeout)
    if not isinstance(value, str):
        raise TypeError("pytesseract.image_to_string returned non-text output")
    return value


def _structured_ocr(
    engine: Any,
    image: Any,
    timeout: float,
    language: str,
    psm: int,
    *,
    order_words_by_x: bool = False,
) -> _OCRPass:
    image_to_data = getattr(engine, "image_to_data", None)
    if callable(image_to_data):
        output = getattr(getattr(engine, "Output", None), "DICT", None)
        kwargs = {
            "timeout": timeout,
            "lang": language,
            "config": f"--psm {psm}",
        }
        if output is not None:
            kwargs["output_type"] = output
        try:
            data = image_to_data(image, **kwargs)
        except TypeError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("text"), list):
            words: list[str] = []
            confidences: list[float] = []
            boxes: list[tuple[int, int, int, int]] = []
            positioned_words: list[tuple[int, str]] = []
            texts = data.get("text", [])[:4096]
            for index, raw_word in enumerate(texts):
                word = str(raw_word).strip()
                if not word:
                    continue
                words.append(word)
                try:
                    confidence = float(data.get("conf", [])[index])
                except (IndexError, TypeError, ValueError):
                    confidence = -1.0
                if confidence >= 0:
                    confidences.append(confidence)
                if len(boxes) < 64:
                    try:
                        box = tuple(int(data[key][index]) for key in (
                            "left", "top", "width", "height"
                        ))
                        boxes.append(box)
                        positioned_words.append((box[0], word))
                    except (IndexError, KeyError, TypeError, ValueError):
                        pass
            if words:
                if order_words_by_x and len(positioned_words) == len(words):
                    words = [word for _left, word in sorted(positioned_words)]
                return _OCRPass(
                    " ".join(words),
                    statistics.fmean(confidences) if confidences else None,
                    tuple(boxes),
                )
    return _OCRPass(
        _call_image_to_string(engine, image, timeout, language, psm), None, ()
    )


def _ocr_image_sync(
    path: Path,
    dependencies: OCRDependencies,
    timeout: float,
    language: str = "eng",
    psm: int = 6,
) -> str:
    """Compatibility single-pass OCR with the same safety checks as multi-pass."""
    validate_ocr_language(language)
    with dependencies.image_module.open(path) as image:
        _validate_dimensions(image)
        image.load()
        text = _call_image_to_string(
            dependencies.pytesseract, image, timeout, language, psm
        )
    return _safe_ocr_text(text, MAX_OCR_TEXT_PER_INVOCATION)


def _close_image(image: Any) -> None:
    closer = getattr(image, "close", None)
    if callable(closer):
        closer()


def _image_channels(image: Any) -> int:
    getter = getattr(image, "getbands", None)
    if callable(getter):
        try:
            return max(1, len(getter()))
        except (TypeError, ValueError):
            pass
    return max(1, len(str(getattr(image, "mode", "RGB"))))


def _build_variants(
    image: Any,
    dependencies: OCRDependencies,
    exhaustive: bool,
    *,
    budget: _OCRVariantBudget | None = None,
) -> Iterator[tuple[str, Any]]:
    """Yield one deterministic OCR transformation at a time."""
    width, height = image.size
    active_budget = budget if budget is not None else _OCRVariantBudget()
    channels = _image_channels(image)
    if not active_budget.reserve(
        width, height, bytes_per_pixel=channels, generated=False
    ):
        return
    yield "original", image

    ops = dependencies.image_ops
    enhance = dependencies.image_enhance
    filters = dependencies.image_filter
    if ops is None or not hasattr(image, "convert"):
        return
    resampling = getattr(dependencies.image_module, "Resampling", None)
    resize_filter = getattr(resampling, "LANCZOS", None)

    if active_budget.reserve(width, height, bytes_per_pixel=1):
        variant = ops.grayscale(image)
        try:
            yield "grayscale", variant
        finally:
            _close_image(variant)
    for name, transform in (
        ("autocontrast", ops.autocontrast),
        ("inverted", ops.invert),
        ("threshold", lambda gray: gray.point(
            lambda value: 255 if value >= 128 else 0
        )),
    ):
        if active_budget.reserve(width, height, bytes_per_pixel=2):
            gray = ops.grayscale(image)
            try:
                variant = transform(gray)
            finally:
                _close_image(gray)
            try:
                yield name, variant
            finally:
                _close_image(variant)
    if filters is not None and active_budget.reserve(
        width, height, bytes_per_pixel=2
    ):
        gray = ops.grayscale(image)
        try:
            variant = gray.filter(filters.SHARPEN)
        finally:
            _close_image(gray)
        try:
            yield "sharpened", variant
        finally:
            _close_image(variant)
    if enhance is not None and active_budget.reserve(
        width, height, bytes_per_pixel=2
    ):
        gray = ops.grayscale(image)
        try:
            variant = enhance.Contrast(gray).enhance(2.0)
        finally:
            _close_image(gray)
        try:
            yield "contrast-2x", variant
        finally:
            _close_image(variant)

    # Large photographs often contain one tiny line on a monitor bezel or
    # caption band. Whole-image OCR cannot upscale those sources without
    # exceeding the decoded-image cap, so examine one bounded relative band.
    crop_box = (
        int(width * 0.28),
        int(height * 0.603),
        int(width * 0.63),
        int(height * 0.625),
    )
    crop_width = crop_box[2] - crop_box[0]
    crop_height = crop_box[3] - crop_box[1]
    crop_scale = 10
    scaled_width = crop_width * crop_scale
    scaled_height = crop_height * crop_scale
    if (
        width >= 1000
        and height >= 1000
        and crop_width >= 64
        and crop_height >= 8
        and active_budget.reserve(
            scaled_width,
            scaled_height,
            bytes_per_pixel=2,
        )
    ):
        crop = image.crop(crop_box)
        gray = ops.grayscale(crop)
        _close_image(crop)
        try:
            contrasted = ops.autocontrast(gray, cutoff=1)
        finally:
            _close_image(gray)
        try:
            variant = contrasted.resize(
                (scaled_width, scaled_height), resize_filter
            )
        finally:
            _close_image(contrasted)
        if filters is not None:
            sharpened = variant.filter(filters.SHARPEN)
            _close_image(variant)
            variant = sharpened
        try:
            yield "scale-lower-center-band-10x", variant
        finally:
            _close_image(variant)

    mode = str(getattr(image, "mode", ""))
    if "A" in mode:
        image_module = dependencies.image_module
        for background_name, color in (("alpha-white", "white"), ("alpha-black", "black")):
            if not active_budget.reserve(width, height, bytes_per_pixel=12):
                continue
            rgba = image.convert("RGBA")
            background = image_module.new("RGBA", rgba.size, color)
            try:
                background.alpha_composite(rgba)
                variant = background.convert("RGB")
            finally:
                _close_image(background)
                _close_image(rgba)
            try:
                yield background_name, variant
            finally:
                _close_image(variant)
        if active_budget.reserve(width, height, bytes_per_pixel=5):
            rgba = image.convert("RGBA")
            try:
                variant = rgba.getchannel("A")
            finally:
                _close_image(rgba)
            try:
                yield "alpha-channel", variant
            finally:
                _close_image(variant)

    if mode in {"RGB", "RGBA"}:
        extrema = getattr(image, "getextrema", lambda: ())()
        color_extrema = tuple(extrema[:3]) if len(extrema) >= 3 else ()
        if len(color_extrema) == 3 and len(set(color_extrema)) > 1:
            for channel_name in ("R", "G", "B"):
                if active_budget.reserve(width, height, bytes_per_pixel=1):
                    variant = image.getchannel(channel_name)
                    try:
                        yield f"channel-{channel_name.lower()}", variant
                    finally:
                        _close_image(variant)

    if max(width, height) <= 1600 and active_budget.reserve(
        width * 2, height * 2, bytes_per_pixel=channels
    ):
        variant = image.resize((width * 2, height * 2), resize_filter)
        try:
            yield "scale-2x", variant
        finally:
            _close_image(variant)
    if exhaustive and max(width, height) <= 700 and active_budget.reserve(
        width * 4, height * 4, bytes_per_pixel=channels
    ):
        variant = image.resize((width * 4, height * 4), resize_filter)
        try:
            yield "scale-4x", variant
        finally:
            _close_image(variant)
    for name, angle in (("rot90", 90), ("rot180", 180), ("rot270", 270)):
        rotated_width, rotated_height = (
            (height, width) if angle in {90, 270} else (width, height)
        )
        if active_budget.reserve(
            rotated_width,
            rotated_height,
            bytes_per_pixel=channels,
        ):
            variant = image.rotate(angle, expand=True)
            try:
                yield name, variant
            finally:
                _close_image(variant)


def _psm_modes(name: str, image: Any, exhaustive: bool) -> tuple[int, ...]:
    if name == "scale-lower-center-band-10x":
        return (6, 7, 11)
    if name in {"original", "grayscale"}:
        modes = (3, 6, 11)
    elif name.startswith(("scale", "rot")) and image.size[0] >= image.size[1] * 3:
        modes = (7, 13)
    else:
        modes = (6, 11) if exhaustive else (6,)
    return modes


def _normalize_ocr(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return re.sub(r"\s+([,.;:!?}\]])", r"\1", value).casefold()


def _confidence(text: str, flags: tuple[str, ...], mean: float | None, repeats: int) -> str:
    if flags:
        return "confirmed"
    printable = sum(character.isprintable() for character in text) / max(1, len(text))
    useful = sum(character.isalnum() for character in text)
    if printable >= 0.95 and useful >= 8 and repeats >= 2:
        return "high"
    if printable >= 0.85 and useful >= 4:
        return "medium"
    return "low"


def _literal_flag_prefixes(pattern: re.Pattern) -> tuple[str, ...]:
    """Derive bounded literal prefixes from regex semantics up to ``{``."""
    max_prefixes = 16
    max_prefix_length = 64
    max_depth = 16

    def walk(sequence, prefixes: tuple[str, ...], depth: int):
        if depth > max_depth:
            return (), False
        current = prefixes
        for operation, argument in sequence:
            if operation in {
                _regex_parser.AT,
                _regex_parser.ASSERT,
                _regex_parser.ASSERT_NOT,
            }:
                continue
            if operation is _regex_parser.LITERAL:
                character = chr(argument)
                if character == "{":
                    return current, True
                if not re.fullmatch(r"[A-Za-z0-9_-]", character):
                    return (), False
                current = tuple(
                    prefix + character for prefix in current
                    if len(prefix) < max_prefix_length
                )
                if not current:
                    return (), False
                continue
            if operation is _regex_parser.SUBPATTERN:
                current, found = walk(argument[-1], current, depth + 1)
                if found:
                    return current, True
                if not current:
                    return (), False
                continue
            if operation is _regex_parser.BRANCH:
                branch_results = [
                    walk(branch, current, depth + 1)
                    for branch in argument[1][:max_prefixes]
                ]
                if not branch_results:
                    return (), False
                found_values = {found for _items, found in branch_results}
                if len(found_values) != 1:
                    return (), False
                combined: list[str] = []
                for items, _found in branch_results:
                    for item in items:
                        if item not in combined:
                            combined.append(item)
                        if len(combined) >= max_prefixes:
                            break
                    if len(combined) >= max_prefixes:
                        break
                current = tuple(combined)
                found = branch_results[0][1]
                if found:
                    return current, True
                if not current:
                    return (), False
                continue
            return (), False
        return current, False

    try:
        parsed = _regex_parser.parse(pattern.pattern, pattern.flags)
        prefixes, found_brace = walk(parsed, ("",), 0)
    except (AttributeError, OverflowError, RuntimeError, TypeError, ValueError):
        return ()
    if not found_brace:
        return ()
    return tuple(
        prefix for prefix in prefixes
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,63}", prefix)
    )[:max_prefixes]


def _repair_flag_candidates(text: str, pattern: re.Pattern) -> tuple[str, ...]:
    """Try a tiny fixed repair set only around brace-like candidate text."""
    if (
        len(text) > MAX_DIRECT_FLAG_LENGTH
        or not any(character in text for character in "{}[]")
    ):
        return ()
    options = [text.replace("[", "{").replace("]", "}")]
    options.append(re.sub(r"\s*([{}_])\s*", r"\1", options[0]))
    translations = str.maketrans({"|": "I", "–": "-"})
    options.append(options[0].translate(translations))
    compact = re.sub(r"\s+", "", options[0])
    options.append(compact)

    # Sparse-line OCR may split a fixed flag prefix and commonly reads a final
    # lowercase i/l as '!'. Generate only a tiny, regex-gated repair set. The
    # prefix comes from parsed regex semantics, not a particular brace spelling.
    prefixes = _literal_flag_prefixes(pattern)
    for replacement in ("i",):
        repaired_option = re.sub(
            r"(?<=[A-Za-z])!(?=[^A-Za-z]|$)", replacement, compact
        )
        repaired_option = re.sub(
            r"(?<=[A-Za-z0-9])[.,;:'\"]+(?=[A-Za-z0-9_])",
            "_",
            repaired_option,
        )
        for prefix in prefixes:
            brace_index = repaired_option.find("{")
            prefix_start = brace_index - len(prefix)
            if (
                brace_index >= 0
                and prefix_start >= 0
                and repaired_option[prefix_start:brace_index].casefold()
                == prefix.casefold()
            ):
                options.append(
                    repaired_option[:prefix_start]
                    + prefix
                    + repaired_option[brace_index:]
                )
    repaired: list[str] = []
    for candidate in options[:16]:
        for hit in scan_text(candidate, pattern):
            if hit not in repaired and hit not in scan_text(text, pattern):
                repaired.append(hit)
    return tuple(repaired)


def _analyze_ocr_text(text: str, pattern: re.Pattern) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    direct = tuple(scan_text(text, pattern))
    chains: dict[str, tuple[str, ...]] = {flag: () for flag in direct}
    decode_variants: list[tuple[str, tuple[str, ...]]] = [(text, ())]
    compact = re.sub(r"\s+", "", text)
    if 16 <= len(compact) <= 4096 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact):
        repairs = (
            compact.replace("L", "l"),
            compact.replace("I", "J"),
            compact.replace("L", "l").replace("I", "J"),
            compact.replace("1", "l"),
            compact.replace("0", "O"),
        )
        for repaired in repairs:
            candidates = [repaired]
            if len(repaired) % 4 == 1:
                candidates.append(repaired[:-1])
            elif len(repaired) % 4 in {2, 3}:
                candidates.append(repaired + "=" * (-len(repaired) % 4))
            for candidate in candidates:
                if candidate != text and all(candidate != item[0] for item in decode_variants):
                    decode_variants.append((candidate, ("ocr-repair",)))
                if len(decode_variants) >= 16:
                    break
            if len(decode_variants) >= 16:
                break
    for candidate_text, prefix in decode_variants:
        source = detect_text_bytes(candidate_text.encode("utf-8", errors="replace"))
        analysis = analyze_text_input(source, pattern)
        for candidate in analysis.candidates:
            for flag in candidate.flags_found:
                if re.search(r"\\x[0-9A-Fa-f]{2}|<U\+[0-9A-Fa-f]{4,6}", flag):
                    continue
                chains.setdefault(flag, prefix + candidate.chain)
    repaired_flags = _repair_flag_candidates(text, pattern)
    for repaired in repaired_flags:
        chains.setdefault(repaired, ("ocr-repair",))
    if repaired_flags:
        for original in direct:
            normalized_original = re.sub(r"\s+", "", original).replace("[", "{").replace("]", "}")
            if normalized_original in repaired_flags and original != normalized_original:
                chains.pop(original, None)
    return tuple(chains), chains


def _emit_artifact(message: str, callback: Callable[[str], None] | None) -> None:
    try:
        (callback or (lambda value: log_artifact(__import__("logging").getLogger("dayi"), value)))(message)
    except Exception:
        return


async def _probe_ocr_languages(timeout: float) -> tuple[str, ...] | None:
    """Query the static Tesseract CLI with bounded output and process timeout."""
    executable = shutil.which("tesseract")
    if executable is None:
        return None
    rc, stdout, _stderr, _elapsed, timed_out = await async_run_command(
        [executable, "--list-langs"],
        TOOL_NAME,
        timeout=max(1.0, min(5.0, timeout)),
    )
    if timed_out or rc != 0:
        return None
    return tuple(sorted({
        line.strip() for line in stdout.splitlines()[1:65]
        if re.fullmatch(r"[A-Za-z0-9_-]+", line.strip())
    }))


def _process_image_sync(
    path: Path,
    source: str,
    dependencies: OCRDependencies,
    language: str,
    exhaustive: bool,
    deadline: float,
    pattern: re.Pattern,
    remaining_invocations: int,
    remaining_text_bytes: int,
) -> tuple[list[OCRFinding], int, int, bool]:
    raw: list[OCRFinding] = []
    invocations = 0
    text_bytes = 0
    with dependencies.image_module.open(path) as opened:
        _validate_dimensions(opened)
        opened.load()
        frames = min(int(getattr(opened, "n_frames", 1) or 1), 5)
        variant_budget = _OCRVariantBudget()
        for frame_index in range(frames):
            if time.monotonic() >= deadline:
                return raw, invocations, text_bytes, True
            if frame_index:
                opened.seek(frame_index)
            frame = opened
            frame_suffix = f"-frame{frame_index}" if frames > 1 else ""
            variants = iter(_build_variants(
                frame,
                dependencies,
                exhaustive,
                budget=variant_budget,
            ))
            try:
                for name, variant_image in variants:
                    if time.monotonic() >= deadline:
                        return raw, invocations, text_bytes, True
                    for psm in _psm_modes(name, variant_image, exhaustive):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return raw, invocations, text_bytes, True
                        if invocations >= min(
                            MAX_OCR_INVOCATIONS_PER_IMAGE,
                            remaining_invocations,
                        ):
                            return raw, invocations, text_bytes, False
                        result = _structured_ocr(
                            dependencies.pytesseract,
                            variant_image,
                            min(OCR_INVOCATION_TIMEOUT, remaining),
                            language,
                            psm,
                            order_words_by_x=(
                                name == "scale-lower-center-band-10x"
                                and psm == 11
                            ),
                        )
                        invocations += 1
                        safe = _safe_ocr_text(
                            result.text, MAX_OCR_TEXT_PER_INVOCATION
                        )
                        encoded_size = len(
                            safe.encode("utf-8", errors="replace")
                        )
                        if encoded_size > remaining_text_bytes - text_bytes:
                            return raw, invocations, text_bytes, False
                        text_bytes += encoded_size
                        if not safe.strip():
                            continue
                        if time.monotonic() >= deadline:
                            direct_flags = tuple(scan_text(safe, pattern))
                            raw.append(OCRFinding(
                                text=safe,
                                sanitized_text=_safe_ocr_text(safe, 512),
                                confidence=(
                                    "confirmed" if direct_flags else "low"
                                ),
                                mean_word_confidence=result.mean_confidence,
                                source=source,
                                variant=OCRVariant(
                                    name=f"{name}{frame_suffix}-psm{psm}",
                                    rotation=(
                                        int(name[3:])
                                        if name.startswith("rot") else 0
                                    ),
                                    scale=(
                                        10 if "10x" in name
                                        else 4 if "4x" in name
                                        else 2 if "2x" in name else 1
                                    ),
                                    channel=(
                                        name.split("channel-", 1)[1]
                                        if name.startswith("channel-")
                                        else "original"
                                    ),
                                    threshold=(
                                        128 if name == "threshold" else None
                                    ),
                                    inversion=name == "inverted",
                                    psm=psm,
                                    language=language,
                                ),
                                bounding_boxes=result.boxes,
                                flags_found=direct_flags,
                                flag_decoder_chains=tuple(
                                    (flag, ()) for flag in direct_flags
                                ),
                                evidence=(
                                    ("active-flag-regex",)
                                    if direct_flags else ()
                                ),
                            ))
                            return raw, invocations, text_bytes, True
                        flags, chains = _analyze_ocr_text(safe, pattern)
                        chain = chains.get(flags[0], ()) if flags else ()
                        raw.append(OCRFinding(
                            text=safe,
                            sanitized_text=_safe_ocr_text(safe, 512),
                            confidence="confirmed" if flags else "low",
                            mean_word_confidence=result.mean_confidence,
                            source=source,
                            variant=OCRVariant(
                                name=f"{name}{frame_suffix}-psm{psm}",
                                rotation=(
                                    int(name[3:])
                                    if name.startswith("rot") else 0
                                ),
                                scale=(
                                    10 if "10x" in name
                                    else 4 if "4x" in name
                                    else 2 if "2x" in name else 1
                                ),
                                channel=(
                                    name.split("channel-", 1)[1]
                                    if name.startswith("channel-")
                                    else "original"
                                ),
                                threshold=(
                                    128 if name == "threshold" else None
                                ),
                                inversion=name == "inverted",
                                psm=psm,
                                language=language,
                            ),
                            bounding_boxes=result.boxes,
                            flags_found=flags,
                            decoder_chain=chain,
                            flag_decoder_chains=tuple(
                                (flag, chains.get(flag, ()))
                                for flag in flags
                            ),
                            evidence=(
                                ("active-flag-regex",) if flags else ()
                            ),
                        ))
                        if flags and not exhaustive:
                            return raw, invocations, text_bytes, False
            finally:
                close_variants = getattr(variants, "close", None)
                if callable(close_variants):
                    close_variants()
    return raw, invocations, text_bytes, time.monotonic() >= deadline


def _process_image_worker(
    path: str,
    source: str,
    language: str,
    exhaustive: bool,
    budget_seconds: float,
    pattern: str,
    pattern_flags: int,
    remaining_invocations: int,
    remaining_text_bytes: int,
):
    configure_opencv_runtime()
    dependencies = _load_ocr_dependencies()
    if dependencies is None:
        raise RuntimeError("OCR dependencies became unavailable")
    return _process_image_sync(
        Path(path),
        source,
        dependencies,
        language,
        exhaustive,
        time.monotonic() + max(0.0, budget_seconds),
        re.compile(pattern, pattern_flags),
        remaining_invocations,
        remaining_text_bytes,
    )


def _deduplicate(findings: list[OCRFinding]) -> list[OCRFinding]:
    grouped: dict[str, list[OCRFinding]] = {}
    for finding in findings:
        key = _normalize_ocr(finding.text)
        if key:
            grouped.setdefault(key, []).append(finding)
    results: list[OCRFinding] = []
    rank = {"confirmed": 3, "high": 2, "medium": 1, "low": 0}
    for group in grouped.values():
        strongest = max(
            group,
            key=lambda item: (
                bool(item.flags_found), item.mean_word_confidence or -1,
                -len(item.variant.name), item.variant.name,
            ),
        )
        flags = tuple(dict.fromkeys(flag for item in group for flag in item.flags_found))
        chains: dict[str, tuple[str, ...]] = {}
        for item in group:
            for flag in item.flags_found:
                chains.setdefault(flag, item.decoder_chain_for(flag))
        confidence = _confidence(strongest.text, flags, strongest.mean_word_confidence, len(group))
        candidate = replace(
            strongest,
            flags_found=flags,
            flag_decoder_chains=tuple(
                (flag, chains.get(flag, ())) for flag in flags
            ),
            confidence=confidence,
            repeated_count=len(group),
            evidence=tuple(dict.fromkeys((*strongest.evidence, *(
                ("variant-consensus",) if len(group) > 1 else ()
            )))),
        )
        results.append(candidate)
    results.sort(key=lambda item: (-rank[item.confidence], item.source, item.variant.name, item.sanitized_text))
    return results


async def run_ocr_scanner(
    target: Path,
    workspace: Path,
    flag_pattern: re.Pattern,
    timeout: float = 60.0,
    artifact_callback: Callable[[str], None] | None = None,
    *,
    language: str = "eng",
    exhaustive: bool = False,
    verbose: bool = False,
) -> ToolResult:
    """Run bounded, deterministic OCR and passive text decoding."""
    command = ["python:pytesseract", str(target), str(workspace)]
    try:
        language = validate_ocr_language(language)
    except ValueError:
        return make_skipped_result(TOOL_NAME, "invalid OCR language expression", command)
    images = await asyncio.to_thread(discover_images, target, workspace)
    if not images:
        return make_skipped_result(TOOL_NAME, "no bounded supported images found", command)
    dependencies = _load_ocr_dependencies()
    if dependencies is None:
        return make_skipped_result(TOOL_NAME, "optional OCR dependencies are unavailable", command)
    if shutil.which("tesseract") is None:
        return make_skipped_result(TOOL_NAME, "Tesseract OCR executable is unavailable", command)
    installed = await _probe_ocr_languages(timeout)
    requested = language.split("+")
    if installed is not None and any(item not in installed for item in requested):
        return make_skipped_result(
            TOOL_NAME,
            f"requested OCR language is unavailable: {language}",
            command,
        )

    started = time.monotonic()
    deadline = started + min(90.0, max(1.0, timeout))
    all_raw: list[OCRFinding] = []
    errors: list[str] = []
    invocations = 0
    aggregate_text = 0
    processed = 0
    timed_out = False
    for image in images:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or invocations >= MAX_TOTAL_OCR_INVOCATIONS:
            errors.append("OCR total budget exhausted")
            break
        try:
            invocation_budget = MAX_TOTAL_OCR_INVOCATIONS - invocations
            text_budget = MAX_AGGREGATE_OCR_TEXT - aggregate_text
            if isinstance(dependencies.pytesseract, ModuleType):
                findings, used, text_used, image_timed_out = await async_run_isolated(
                    _process_image_worker,
                    str(image.path),
                    image.source,
                    language,
                    exhaustive,
                    remaining,
                    flag_pattern.pattern,
                    flag_pattern.flags,
                    invocation_budget,
                    text_budget,
                    timeout=remaining,
                    max_response_bytes=MAX_OCR_ANALYSIS_RESPONSE,
                )
            else:
                findings, used, text_used, image_timed_out = await asyncio.wait_for(
                    asyncio.to_thread(
                        _process_image_sync,
                        image.path,
                        image.source,
                        dependencies,
                        language,
                        exhaustive,
                        deadline,
                        flag_pattern,
                        invocation_budget,
                        text_budget,
                    ),
                    timeout=remaining + 0.25,
                )
        except asyncio.TimeoutError:
            errors.append("OCR total budget exhausted")
            timed_out = True
            break
        except Exception as exc:
            errors.append(f"{image.source}: {type(exc).__name__}")
            continue
        processed += 1
        invocations += used
        aggregate_text += text_used
        all_raw.extend(findings)
        if image_timed_out:
            errors.append("OCR total budget exhausted")
            timed_out = True
            break

    findings = _deduplicate(all_raw)
    all_flags: list[str] = []
    extracted_flags: dict[str, list[str]] = {}
    artifacts: list[ArtifactFinding] = []
    stdout: list[str] = [
        f"OCR language: {language}",
        f"OCR invocations: {invocations}/{MAX_TOTAL_OCR_INVOCATIONS}",
    ]
    for finding in findings:
        attribution = f"ocr:{finding.source}:{finding.variant.name}"
        if finding.decoder_chain:
            attribution += ">" + ">".join(finding.decoder_chain)
        for flag in finding.flags_found:
            if flag not in all_flags:
                all_flags.append(flag)
                flag_attribution = (
                    f"ocr:{finding.source}:{finding.variant.name}"
                )
                chain = finding.decoder_chain_for(flag)
                if chain:
                    flag_attribution += ">" + ">".join(chain)
                if finding.source.startswith("document_extracted/"):
                    flag_attribution = f"document:{flag_attribution}"
                extracted_flags.setdefault(flag_attribution, []).append(flag)
        if finding.confidence in {"confirmed", "high", "medium"} or verbose:
            preview = _ocr_preview(finding.sanitized_text)
            if preview:
                stdout.append(
                    f"[{finding.confidence}] {finding.source} / {finding.variant.name}: {preview}"
                )
                _emit_artifact(
                    "[!] Yeğenim, görselin içinde gizli bir yazı yakaladım: " + preview,
                    artifact_callback,
                )
            artifacts.extend(scan_artifacts(
                finding.text,
                source=attribution,
                include_possible=verbose,
            ))

    return ToolResult(
        tool_name=TOOL_NAME,
        command=command,
        return_code=0 if processed else 1,
        stdout="\n".join(stdout),
        stderr="\n".join(errors),
        flags_found=all_flags,
        elapsed_seconds=time.monotonic() - started,
        timed_out=timed_out or time.monotonic() >= deadline,
        extracted_flags=extracted_flags,
        artifacts_found=artifacts,
        ocr_findings=findings[:25 if verbose else 10],
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_ocr_scanner(
        context.target,
        context.workspace,
        context.flag_pattern,
        timeout=context.timeout,
        artifact_callback=context.report_artifact,
        language=context.ocr_language,
        exhaustive=context.ocr_exhaustive,
        verbose=context.verbose,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="ocr_scanner",
        phase=PluginPhase.ARCHIVE,
        priority=20,
        run=_plugin_run,
        required_executables=("tesseract",),
        required_python_modules=("PIL", "pytesseract"),
    ),
)
