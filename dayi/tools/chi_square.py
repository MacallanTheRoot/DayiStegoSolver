"""Pure-Python chi-square steganalysis for PNG and uncompressed BMP images."""
from __future__ import annotations

import asyncio
import binascii
import logging
import math
import re
import struct
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from dayi.persona import log_artifact
from dayi.reporter import ToolResult
from dayi.tools._base import make_skipped_result
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin

logger = logging.getLogger("dayi")

TOOL_NAME = "chi_square"
UNIFORMITY_WARNING_THRESHOLD = 95.0

MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_COMPRESSED_BYTES = 96 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_PIXELS = 25_000_000
MAX_CHUNK_BYTES = 64 * 1024 * 1024
MIN_SAMPLE_BYTES = 1_024

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_CHANNELS = {0: 1, 2: 3, 4: 2, 6: 4}
_PNG_COLOR_INDICES = {
    0: (0,),
    2: (0, 1, 2),
    4: (0,),
    6: (0, 1, 2),
}

_GAMMA_EPSILON = 1e-14
_GAMMA_MAX_ITERATIONS = 10_000
_GAMMA_FPMIN = 1e-300


class ImageParseError(ValueError):
    """Raised when image input is malformed, unsupported, or unsafe."""


class AnalysisCancelled(Exception):
    """Internal signal used for cooperative worker-thread cancellation."""


@dataclass(frozen=True)
class PixelData:
    """Validated color-channel bytes extracted from one image."""

    image_format: str
    width: int
    height: int
    color_bytes: bytes


@dataclass(frozen=True)
class ChiSquareAnalysis:
    """PoV chi-square result and its p-value-derived uniformity heuristic."""

    image_format: str
    width: int
    height: int
    sample_count: int
    active_pairs: int
    chi_square: float
    p_value: float
    uniformity_score: float


def _check_cancelled(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise AnalysisCancelled


def _checked_pixel_count(width: int, height: int) -> int:
    if width <= 0 or height <= 0:
        raise ImageParseError(f"invalid dimensions: {width}x{height}")
    pixel_count = width * height
    if pixel_count > MAX_PIXELS:
        raise ImageParseError(
            f"pixel count {pixel_count} exceeds safety limit {MAX_PIXELS}"
        )
    return pixel_count


def _paeth_predictor(left: int, up: int, up_left: int) -> int:
    """Return the PNG Paeth predictor for three neighboring bytes."""
    estimate = left + up - up_left
    distance_left = abs(estimate - left)
    distance_up = abs(estimate - up)
    distance_up_left = abs(estimate - up_left)
    if distance_left <= distance_up and distance_left <= distance_up_left:
        return left
    if distance_up <= distance_up_left:
        return up
    return up_left


def _decompress_png_idat(compressed: bytes, expected_size: int) -> bytes:
    """Decompress exactly one bounded zlib stream for PNG scanline data."""
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise ImageParseError("PNG IDAT data exceeds compressed-size limit")
    if expected_size > MAX_DECOMPRESSED_BYTES:
        raise ImageParseError("PNG scanlines exceed decompressed-size limit")

    decompressor = zlib.decompressobj()
    try:
        raw = bytearray(decompressor.decompress(compressed, expected_size + 1))
        if len(raw) > expected_size:
            raise ImageParseError("PNG decompressed data exceeds expected size")

        remaining = expected_size + 1 - len(raw)
        raw.extend(decompressor.flush(remaining))
    except zlib.error as exc:
        raise ImageParseError(f"PNG zlib stream is invalid: {exc}") from exc

    if len(raw) != expected_size:
        raise ImageParseError(
            f"PNG decompressed size mismatch: {len(raw)} != {expected_size}"
        )
    if not decompressor.eof or decompressor.unconsumed_tail:
        raise ImageParseError("PNG zlib stream is truncated or exceeds its limit")
    if decompressor.unused_data:
        raise ImageParseError("PNG IDAT contains trailing compressed data")
    return bytes(raw)


def parse_png(
    data: bytes, cancel_event: threading.Event | None = None
) -> PixelData:
    """Parse a bounded non-interlaced 8-bit PNG and reconstruct filters 0–4."""
    if len(data) > MAX_FILE_BYTES:
        raise ImageParseError("PNG file data exceeds safety limit")
    if not data.startswith(_PNG_SIGNATURE):
        raise ImageParseError("invalid PNG signature")

    position = len(_PNG_SIGNATURE)
    ihdr: tuple[int, int, int, int, int, int, int] | None = None
    idat_chunks: list[bytes] = []
    total_idat_size = 0
    found_iend = False

    while position < len(data):
        _check_cancelled(cancel_event)
        if len(data) - position < 12:
            raise ImageParseError("truncated PNG chunk header")

        length = struct.unpack_from(">I", data, position)[0]
        if length > MAX_CHUNK_BYTES:
            raise ImageParseError(f"PNG chunk exceeds size limit: {length}")
        chunk_end = position + 12 + length
        if chunk_end > len(data):
            raise ImageParseError("truncated PNG chunk payload")

        chunk_type = data[position + 4 : position + 8]
        chunk_data = data[position + 8 : position + 8 + length]
        expected_crc = struct.unpack_from(">I", data, position + 8 + length)[0]
        actual_crc = binascii.crc32(chunk_type)
        actual_crc = binascii.crc32(chunk_data, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ImageParseError(
                f"PNG chunk CRC mismatch for {chunk_type.decode('ascii', 'replace')}"
            )

        if chunk_type == b"IHDR":
            if ihdr is not None or position != len(_PNG_SIGNATURE) or length != 13:
                raise ImageParseError("PNG must contain one leading 13-byte IHDR")
            ihdr = struct.unpack(">IIBBBBB", chunk_data)
        elif chunk_type == b"IDAT":
            if ihdr is None:
                raise ImageParseError("PNG IDAT appears before IHDR")
            total_idat_size += length
            if total_idat_size > MAX_COMPRESSED_BYTES:
                raise ImageParseError("PNG IDAT data exceeds compressed-size limit")
            idat_chunks.append(chunk_data)
        elif chunk_type == b"IEND":
            if length != 0:
                raise ImageParseError("PNG IEND chunk must be empty")
            found_iend = True
            position = chunk_end
            break

        position = chunk_end

    if ihdr is None or not idat_chunks or not found_iend:
        raise ImageParseError("PNG is missing IHDR, IDAT, or IEND")
    if position != len(data):
        raise ImageParseError("PNG contains trailing data after IEND")

    width, height, bit_depth, color_type, compression, filter_method, interlace = ihdr
    _checked_pixel_count(width, height)
    if bit_depth != 8:
        raise ImageParseError(f"unsupported PNG bit depth: {bit_depth}")
    if color_type not in _PNG_CHANNELS:
        raise ImageParseError(f"unsupported PNG color type: {color_type}")
    if compression != 0 or filter_method != 0:
        raise ImageParseError("unsupported PNG compression or filter method")
    if interlace != 0:
        raise ImageParseError("Adam7-interlaced PNG is not supported")

    channels = _PNG_CHANNELS[color_type]
    row_bytes = width * channels
    expected_size = height * (row_bytes + 1)
    raw = _decompress_png_idat(b"".join(idat_chunks), expected_size)

    previous_row = bytearray(row_bytes)
    color_bytes = bytearray()
    color_indices = _PNG_COLOR_INDICES[color_type]
    source_offset = 0

    for _row_index in range(height):
        _check_cancelled(cancel_event)
        filter_type = raw[source_offset]
        source_offset += 1
        encoded_row = raw[source_offset : source_offset + row_bytes]
        source_offset += row_bytes
        reconstructed = bytearray(row_bytes)

        for index, encoded_byte in enumerate(encoded_row):
            left = reconstructed[index - channels] if index >= channels else 0
            up = previous_row[index]
            up_left = previous_row[index - channels] if index >= channels else 0

            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = up
            elif filter_type == 3:
                predictor = (left + up) // 2
            elif filter_type == 4:
                predictor = _paeth_predictor(left, up, up_left)
            else:
                raise ImageParseError(f"unsupported PNG row filter: {filter_type}")

            reconstructed[index] = (encoded_byte + predictor) & 0xFF

        for pixel_start in range(0, row_bytes, channels):
            for channel_index in color_indices:
                color_bytes.append(reconstructed[pixel_start + channel_index])
        previous_row = reconstructed

    return PixelData("PNG", width, height, bytes(color_bytes))


def parse_bmp(
    data: bytes, cancel_event: threading.Event | None = None
) -> PixelData:
    """Parse uncompressed 24/32-bit BMP color bytes, excluding padding/alpha."""
    if len(data) > MAX_FILE_BYTES:
        raise ImageParseError("BMP file data exceeds safety limit")
    if len(data) < 54 or data[:2] != b"BM":
        raise ImageParseError("invalid or truncated BMP header")

    try:
        declared_size = struct.unpack_from("<I", data, 2)[0]
        pixel_offset = struct.unpack_from("<I", data, 10)[0]
        dib_size = struct.unpack_from("<I", data, 14)[0]
        width = struct.unpack_from("<i", data, 18)[0]
        signed_height = struct.unpack_from("<i", data, 22)[0]
        planes = struct.unpack_from("<H", data, 26)[0]
        bit_count = struct.unpack_from("<H", data, 28)[0]
        compression = struct.unpack_from("<I", data, 30)[0]
    except struct.error as exc:
        raise ImageParseError(f"truncated BMP header: {exc}") from exc

    if dib_size < 40 or 14 + dib_size > len(data):
        raise ImageParseError(f"unsupported or truncated BMP DIB header: {dib_size}")
    if declared_size and declared_size > len(data):
        raise ImageParseError("BMP declared file size exceeds available data")
    if planes != 1 or compression != 0 or bit_count not in (24, 32):
        raise ImageParseError(
            f"unsupported BMP layout: planes={planes}, bits={bit_count}, "
            f"compression={compression}"
        )
    if signed_height == 0:
        raise ImageParseError("BMP height cannot be zero")

    height = abs(signed_height)
    _checked_pixel_count(width, height)
    bytes_per_pixel = bit_count // 8
    row_payload = width * bytes_per_pixel
    row_stride = (row_payload + 3) & ~3
    pixel_end = pixel_offset + row_stride * height
    if pixel_offset < 14 + dib_size or pixel_end > len(data):
        raise ImageParseError("BMP pixel array is truncated or overlaps its headers")

    color_bytes = bytearray()
    for logical_row in range(height):
        _check_cancelled(cancel_event)
        physical_row = logical_row if signed_height < 0 else height - 1 - logical_row
        row_start = pixel_offset + physical_row * row_stride
        for pixel_index in range(width):
            pixel_start = row_start + pixel_index * bytes_per_pixel
            color_bytes.extend(data[pixel_start : pixel_start + 3])

    return PixelData("BMP", width, height, bytes(color_bytes))


def _regularized_gamma_q(shape: float, value: float) -> float:
    """Compute Q(shape, value) via series or Lentz continued fraction."""
    if shape <= 0.0 or value < 0.0:
        raise ValueError("gamma arguments must satisfy shape > 0 and value >= 0")
    if value == 0.0:
        return 1.0

    log_factor = -value + shape * math.log(value) - math.lgamma(shape)

    if value < shape + 1.0:
        term = 1.0 / shape
        series_sum = term
        adjusted_shape = shape
        for _ in range(_GAMMA_MAX_ITERATIONS):
            adjusted_shape += 1.0
            term *= value / adjusted_shape
            series_sum += term
            if abs(term) <= abs(series_sum) * _GAMMA_EPSILON:
                gamma_p = series_sum * math.exp(log_factor)
                return min(1.0, max(0.0, 1.0 - gamma_p))
        raise ArithmeticError("incomplete gamma series did not converge")

    fraction_b = value + 1.0 - shape
    fraction_c = 1.0 / _GAMMA_FPMIN
    fraction_d = 1.0 / max(fraction_b, _GAMMA_FPMIN)
    fraction_h = fraction_d

    for iteration in range(1, _GAMMA_MAX_ITERATIONS + 1):
        coefficient = -iteration * (iteration - shape)
        fraction_b += 2.0
        fraction_d = coefficient * fraction_d + fraction_b
        if abs(fraction_d) < _GAMMA_FPMIN:
            fraction_d = _GAMMA_FPMIN
        fraction_c = fraction_b + coefficient / fraction_c
        if abs(fraction_c) < _GAMMA_FPMIN:
            fraction_c = _GAMMA_FPMIN
        fraction_d = 1.0 / fraction_d
        delta = fraction_d * fraction_c
        fraction_h *= delta
        if abs(delta - 1.0) <= _GAMMA_EPSILON:
            gamma_q = math.exp(log_factor) * fraction_h
            return min(1.0, max(0.0, gamma_q))

    raise ArithmeticError("incomplete gamma continued fraction did not converge")


def chi_square_survival(chi_square: float, degrees_of_freedom: int) -> float:
    """Return the chi-square survival probability for a valid statistic."""
    if chi_square < 0.0 or degrees_of_freedom <= 0:
        raise ValueError("chi-square and degrees of freedom must be positive")
    return _regularized_gamma_q(degrees_of_freedom / 2.0, chi_square / 2.0)


def analyze_pixel_data(pixel_data: PixelData) -> ChiSquareAnalysis:
    """Calculate the PoV chi-square statistic over color-channel bytes."""
    sample_count = len(pixel_data.color_bytes)
    if sample_count < MIN_SAMPLE_BYTES:
        raise ImageParseError(
            f"only {sample_count} color bytes; at least {MIN_SAMPLE_BYTES} required"
        )

    frequencies = [0] * 256
    for value in pixel_data.color_bytes:
        frequencies[value] += 1

    chi_square = 0.0
    active_pairs = 0
    for even_value in range(0, 256, 2):
        even_count = frequencies[even_value]
        odd_count = frequencies[even_value + 1]
        pair_total = even_count + odd_count
        if pair_total == 0:
            continue
        active_pairs += 1
        difference = even_count - odd_count
        chi_square += (difference * difference) / pair_total

    if active_pairs == 0:
        raise ImageParseError("no active pairs of values were observed")

    p_value = chi_square_survival(chi_square, active_pairs)
    return ChiSquareAnalysis(
        image_format=pixel_data.image_format,
        width=pixel_data.width,
        height=pixel_data.height,
        sample_count=sample_count,
        active_pairs=active_pairs,
        chi_square=chi_square,
        p_value=p_value,
        uniformity_score=p_value * 100.0,
    )


def _analyze_file_sync(
    target: Path, cancel_event: threading.Event
) -> ChiSquareAnalysis:
    """Read, parse, and analyze one bounded image inside a worker thread."""
    try:
        file_size = target.stat().st_size
    except OSError as exc:
        raise ImageParseError(f"cannot stat target: {exc}") from exc
    if file_size > MAX_FILE_BYTES:
        raise ImageParseError(
            f"file size {file_size} exceeds safety limit {MAX_FILE_BYTES}"
        )

    _check_cancelled(cancel_event)
    try:
        with target.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ImageParseError(f"cannot read target: {exc}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise ImageParseError("file grew beyond its safety limit while reading")

    _check_cancelled(cancel_event)
    if data.startswith(_PNG_SIGNATURE):
        pixels = parse_png(data, cancel_event)
    elif data.startswith(b"BM"):
        pixels = parse_bmp(data, cancel_event)
    else:
        raise ImageParseError("chi-square analyzer supports PNG and BMP only")
    return analyze_pixel_data(pixels)


async def run_chi_square(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float = 30.0,
    artifact_callback: Callable[[str], None] | None = None,
) -> ToolResult:
    """Run bounded PoV chi-square steganalysis without external dependencies."""
    del flag_pattern, timeout  # Interface compatibility; this analyzer finds no flags.
    command = ["python:chi-square", str(target)]
    started = time.monotonic()
    cancel_event = threading.Event()
    loop = asyncio.get_running_loop()

    logger.info(
        "[+] Piksellerin nabzını ölçüyorum yeğenim, "
        "LSB dağılımına bir bakalım..."
    )

    try:
        with ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="dayi-chi-square"
        ) as executor:
            worker = loop.run_in_executor(
                executor, _analyze_file_sync, target, cancel_event
            )
            try:
                analysis = await asyncio.shield(worker)
            except asyncio.CancelledError:
                cancel_event.set()
                try:
                    await worker
                except AnalysisCancelled:
                    pass
                raise
    except ImageParseError as exc:
        reason = str(exc)
        logger.info(f"[-] Chi-square turu atlandı yeğenim: {reason}")
        return make_skipped_result(TOOL_NAME, reason, command)
    except (ArithmeticError, OSError, struct.error, zlib.error) as exc:
        reason = f"statistical analysis failed: {exc}"
        logger.warning(f"[chi_square] Hesap şaştı yeğenim: {exc}")
        return make_skipped_result(TOOL_NAME, reason, command)

    elapsed = time.monotonic() - started
    if analysis.uniformity_score > UNIFORMITY_WARNING_THRESHOLD:
        message = (
            "[!] Yeğenim, bu dosyanın piksellerinde bir bit yeniği var! "
            "LSB'lerde şifreli veri olma ihtimali: "
            f"%{analysis.uniformity_score:.2f}"
        )
        if artifact_callback is None:
            log_artifact(logger, message)
        else:
            artifact_callback(message)

    stdout = "\n".join(
        [
            f"Format: {analysis.image_format}",
            f"Dimensions: {analysis.width}x{analysis.height}",
            f"Color-channel samples: {analysis.sample_count}",
            f"Active PoV pairs / degrees of freedom: {analysis.active_pairs}",
            f"Chi-square: {analysis.chi_square:.8f}",
            f"p-value: {analysis.p_value:.12g}",
            f"LSB uniformity heuristic: {analysis.uniformity_score:.2f}%",
        ]
    )
    return ToolResult(
        tool_name=TOOL_NAME,
        command=command,
        return_code=0,
        stdout=stdout,
        stderr="",
        flags_found=[],
        elapsed_seconds=elapsed,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_chi_square(
        context.target,
        context.flag_pattern,
        context.timeout,
        artifact_callback=context.report_artifact,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="chi_square",
        phase=PluginPhase.CONCURRENT,
        priority=70,
        run=_plugin_run,
    ),
)
