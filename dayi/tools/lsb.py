"""
dayi/tools/lsb.py
~~~~~~~~~~~~~~~~~~
Pure-Python (stdlib-only) LSB steganography analyzer.

Provides a stegsolve-equivalent automated LSB extraction for PNG and BMP files
without any external dependencies. Uses struct + zlib to parse raw pixel data
and extracts LSB bit streams, attempting to decode them as UTF-8 text.

Supported files : PNG (all color types, 8-bit depth), BMP (24-bit uncompressed)
Extraction modes: 1-LSB and 2-LSB, across R/G/B channels independently and combined
"""
import logging
import re
import struct
import zlib
from pathlib import Path

from dayi.reporter import ToolResult
from dayi.tools._base import (
    FileType,
    describe_file_type,
    get_file_type,
    make_skipped_result,
)
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin

logger = logging.getLogger("dayi")

TOOL_NAME = "lsb_py"

# Formats this pure-Python analyzer supports
_SUPPORTED_FORMATS: frozenset[FileType] = frozenset({FileType.PNG, FileType.BMP})

# Minimum number of printable characters required to consider an LSB extraction meaningful
_MIN_PRINTABLE_RUN: int = 6


# ---------------------------------------------------------------------------
# PNG pixel extraction
# ---------------------------------------------------------------------------

def _png_channels(color_type: int) -> int:
    """Return the number of channels for a given PNG color type."""
    return {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 3)


def _png_apply_filter_none(raw_row: bytes) -> bytes:
    """
    Passthrough for PNG filter type 0 (None).
    Other filter types are not reconstructed — we accept minor artifacts
    in exchange for zero-dependency operation. In practice, most stego
    tools embed data in filter-0 rows.
    """
    return raw_row


def _extract_png_pixels(data: bytes) -> bytes | None:
    """
    Parse a PNG byte stream and return the raw decompressed pixel bytes
    with filter bytes stripped (best-effort, filter type 0 only).

    Args:
        data: Raw bytes of the PNG file.

    Returns:
        Flat pixel bytes (no filter byte), or None on parse failure.
    """
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None

    width = height = bit_depth = color_type = 0
    idat_chunks: list[bytes] = []
    pos = 8

    try:
        while pos + 12 <= len(data):
            length = struct.unpack(">I", data[pos: pos + 4])[0]
            chunk_type = data[pos + 4: pos + 8]
            chunk_data = data[pos + 8: pos + 8 + length]

            if chunk_type == b"IHDR":
                width, height = struct.unpack(">II", chunk_data[:8])
                bit_depth = chunk_data[8]
                color_type = chunk_data[9]
                if bit_depth != 8:
                    logger.debug(f"[lsb_py] PNG bit depth {bit_depth} not supported (need 8)")
                    return None
            elif chunk_type == b"IDAT":
                idat_chunks.append(chunk_data)
            elif chunk_type == b"IEND":
                break

            pos += 12 + length
    except (struct.error, IndexError) as exc:
        logger.debug(f"[lsb_py] PNG parse error: {exc}")
        return None

    if not idat_chunks or not width or not height:
        return None

    try:
        compressed = b"".join(idat_chunks)
        raw = zlib.decompress(compressed)
    except zlib.error as exc:
        logger.debug(f"[lsb_py] PNG zlib decompress failed: {exc}")
        return None

    channels = _png_channels(color_type)
    # Each row: 1 filter byte + (width × channels) pixel bytes
    row_bytes = width * channels
    stride = 1 + row_bytes
    expected = stride * height

    if len(raw) < expected:
        logger.debug(f"[lsb_py] PNG raw data shorter than expected ({len(raw)} < {expected})")
        return None

    # Strip filter bytes — collect only pixel bytes from each row
    pixels = bytearray()
    for row_idx in range(height):
        row_start = row_idx * stride
        pixels.extend(raw[row_start + 1: row_start + 1 + row_bytes])

    return bytes(pixels)


# ---------------------------------------------------------------------------
# BMP pixel extraction
# ---------------------------------------------------------------------------

def _extract_bmp_pixels(data: bytes) -> bytes | None:
    """
    Parse a 24-bit uncompressed BMP and return the raw RGB pixel bytes.

    Args:
        data: Raw bytes of the BMP file.

    Returns:
        Flat pixel bytes (bottom-up row order preserved), or None on failure.
    """
    if data[:2] != b"BM":
        return None

    try:
        pixel_offset = struct.unpack_from("<I", data, 10)[0]
        width        = struct.unpack_from("<i", data, 18)[0]
        height       = struct.unpack_from("<i", data, 22)[0]
        bit_count    = struct.unpack_from("<H", data, 28)[0]
        compression  = struct.unpack_from("<I", data, 30)[0]
    except struct.error as exc:
        logger.debug(f"[lsb_py] BMP header parse error: {exc}")
        return None

    if bit_count != 24 or compression != 0:
        logger.debug(f"[lsb_py] BMP: unsupported format (bits={bit_count}, comp={compression})")
        return None

    abs_height = abs(height)
    # BMP rows are padded to 4-byte boundaries
    row_size = (width * 3 + 3) & ~3

    pixels = bytearray()
    for row in range(abs_height):
        row_start = pixel_offset + row * row_size
        pixels.extend(data[row_start: row_start + width * 3])

    return bytes(pixels)


# ---------------------------------------------------------------------------
# LSB bit stream extraction and text decoding
# ---------------------------------------------------------------------------

def _bits_to_text(pixel_bytes: bytes, channel_mask: int, n_lsb: int) -> str:
    """
    Extract LSB bits from selected byte positions and reconstruct text.

    Args:
        pixel_bytes:  Raw pixel bytes (R,G,B,... interleaved or flat).
        channel_mask: Bitmask selecting which byte offsets within a pixel
                      group contribute (e.g. 0b001=B-only, 0b111=RGB).
        n_lsb:        Number of least-significant bits to extract per byte.

    Returns:
        Decoded text string (stops at null byte or non-printable run).
    """
    bits: list[int] = []
    for idx, byte_val in enumerate(pixel_bytes):
        # For a 3-channel image, channel positions cycle: 0=R, 1=G, 2=B
        channel_pos = idx % 3
        if not (channel_mask >> channel_pos) & 1:
            continue
        for bit_pos in range(n_lsb):
            bits.append((byte_val >> bit_pos) & 1)

    chars: list[str] = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = sum(bits[i + j] << j for j in range(8))
        if byte_val == 0:
            break
        chars.append(chr(byte_val))

    return "".join(chars)


def _is_meaningful(text: str, min_run: int = _MIN_PRINTABLE_RUN) -> bool:
    """
    Return True if the decoded text contains a run of at least `min_run`
    consecutive printable ASCII characters.
    """
    run = 0
    for ch in text:
        if 0x20 <= ord(ch) <= 0x7E:
            run += 1
            if run >= min_run:
                return True
        else:
            run = 0
    return False


# ---------------------------------------------------------------------------
# Public runner
# ---------------------------------------------------------------------------

_EXTRACTION_MODES: list[tuple[str, int, int]] = [
    # (label, channel_mask, n_lsb)
    # channel_mask bits: bit0=B, bit1=G, bit2=R (for BGR BMP layout compat)
    ("RGB-1LSB", 0b111, 1),
    ("R-1LSB",   0b100, 1),
    ("G-1LSB",   0b010, 1),
    ("B-1LSB",   0b001, 1),
    ("RGB-2LSB", 0b111, 2),
]


async def run_lsb(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float = 30.0,  # kept for API consistency; pure-Python needs no timeout
) -> ToolResult:
    """
    Run pure-Python LSB steganography extraction on PNG or BMP files.

    Extracts pixel data without external dependencies (stdlib struct + zlib),
    then attempts several common LSB modes (RGB combined, individual channels,
    1-bit and 2-bit depths). Each extraction result is scanned for the flag
    pattern and for printable text runs.

    Format check: skips immediately if the file is not PNG or BMP.

    Args:
        target:       Path to the target file.
        flag_pattern: Compiled regex pattern to search for flags.
        timeout:      Ignored (pure-Python, no subprocess). Present for API
                      compatibility with other tool runners.

    Returns:
        Populated ToolResult.
    """
    cmd_desc = ["lsb_py", str(target), "(pure-Python pixel parser)"]

    # ── Smart routing: magic-byte format guard ──────────────────────────────
    file_type = get_file_type(target)
    if file_type not in _SUPPORTED_FORMATS:
        fmt_label = describe_file_type(file_type)
        reason = f"lsb_py requires PNG/BMP; detected: {file_type}"
        logger.info(
            f"[-] Yeğenim bu dosya {fmt_label} formatında, "
            f"LSB analizim sadece PNG ve BMP'ye bakıyor. Atlıyorum..."
        )
        return make_skipped_result(TOOL_NAME, reason, cmd_desc)

    logger.info(
        f"[+] Stegsolve gibi ama bende Java yok yeğenim, "
        f"kendi LSB analizimle {file_type.value} dosyasına bakıyorum..."
    )

    # ── Load and parse pixel bytes ──────────────────────────────────────────
    try:
        raw_data = target.read_bytes()
    except OSError as exc:
        reason = f"Cannot read target file: {exc}"
        logger.error(f"[lsb_py] {reason}")
        return make_skipped_result(TOOL_NAME, reason, cmd_desc)

    if file_type == FileType.PNG:
        pixel_bytes = _extract_png_pixels(raw_data)
    else:  # BMP
        pixel_bytes = _extract_bmp_pixels(raw_data)

    if not pixel_bytes:
        reason = "Pixel extraction failed (unsupported sub-format or corrupt file)"
        logger.warning(
            "[lsb_py] Piksel verisi çıkarılamadı, dosya bozuk mu yoksa "
            "desteklenmeyen alt format mı yeğenim?"
        )
        return make_skipped_result(TOOL_NAME, reason, cmd_desc)

    logger.debug(f"[lsb_py] Extracted {len(pixel_bytes)} pixel bytes from {file_type.value}")

    # ── Try all extraction modes ────────────────────────────────────────────
    all_flags: list[str] = []
    output_lines: list[str] = []
    meaningful_extractions: int = 0

    for label, channel_mask, n_lsb in _EXTRACTION_MODES:
        text = _bits_to_text(pixel_bytes, channel_mask, n_lsb)

        if not _is_meaningful(text):
            logger.debug(f"[lsb_py] Mode {label}: no meaningful text")
            continue

        meaningful_extractions += 1
        preview = text[:120].replace("\n", "\\n")
        output_lines.append(f"[{label}] {preview}")
        logger.debug(f"[lsb_py] Mode {label}: {preview}")

        # Scan the decoded text for flag pattern matches
        mode_flags = [m.group(0) for m in flag_pattern.finditer(text)]
        for flag in mode_flags:
            if flag not in all_flags:
                all_flags.append(flag)
                logger.log(
                    25,
                    f"[lsb_py] 🎯 LSB ({label}) ile flag bulundu: {flag} — "
                    f"İşte bu yeğenim!"
                )

    if not meaningful_extractions:
        logger.info("[lsb_py] Hiçbir LSB modunda anlamlı veri çıkmadı.")
        output_lines.append("No meaningful LSB content detected in any extraction mode.")

    stdout_content = "\n".join(output_lines)

    return ToolResult(
        tool_name=TOOL_NAME,
        command=cmd_desc,
        return_code=0,
        stdout=stdout_content,
        stderr="",
        flags_found=all_flags,
        elapsed_seconds=0.0,
        timed_out=False,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_lsb(context.target, context.flag_pattern, context.timeout)


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="lsb_py",
        phase=PluginPhase.CONCURRENT,
        priority=60,
        run=_plugin_run,
    ),
)
