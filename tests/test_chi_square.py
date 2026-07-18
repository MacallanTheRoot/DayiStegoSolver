import asyncio
import binascii
import math
import re
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from dayi.tools.chi_square import (
    ImageParseError,
    MAX_PIXELS,
    PixelData,
    analyze_pixel_data,
    chi_square_survival,
    parse_bmp,
    parse_png,
    run_chi_square,
)


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    crc = binascii.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def _paeth(left: int, up: int, up_left: int) -> int:
    estimate = left + up - up_left
    distances = (
        abs(estimate - left),
        abs(estimate - up),
        abs(estimate - up_left),
    )
    if distances[0] <= distances[1] and distances[0] <= distances[2]:
        return left
    return up if distances[1] <= distances[2] else up_left


def _encode_png_row(raw: bytes, previous: bytes, channels: int, filter_type: int) -> bytes:
    encoded = bytearray(len(raw))
    for index, value in enumerate(raw):
        left = raw[index - channels] if index >= channels else 0
        up = previous[index]
        up_left = previous[index - channels] if index >= channels else 0
        if filter_type == 0:
            predictor = 0
        elif filter_type == 1:
            predictor = left
        elif filter_type == 2:
            predictor = up
        elif filter_type == 3:
            predictor = (left + up) // 2
        elif filter_type == 4:
            predictor = _paeth(left, up, up_left)
        else:
            raise ValueError(filter_type)
        encoded[index] = (value - predictor) & 0xFF
    return bytes([filter_type]) + bytes(encoded)


def _make_png(
    width: int,
    rows: list[bytes],
    color_type: int = 2,
    filter_types: list[int] | None = None,
) -> bytes:
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[color_type]
    if filter_types is None:
        filter_types = [0] * len(rows)
    previous = bytes(width * channels)
    scanlines = bytearray()
    for row, filter_type in zip(rows, filter_types, strict=True):
        if len(row) != width * channels:
            raise ValueError("row size mismatch")
        scanlines.extend(_encode_png_row(row, previous, channels, filter_type))
        previous = row

    ihdr = struct.pack(">IIBBBBB", width, len(rows), 8, color_type, 0, 0, 0)
    return b"".join(
        [
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"IDAT", zlib.compress(bytes(scanlines))),
            _png_chunk(b"IEND", b""),
        ]
    )


def _make_png_with_raw_stream(width: int, height: int, raw: bytes) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"".join(
        [
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"IDAT", zlib.compress(raw)),
            _png_chunk(b"IEND", b""),
        ]
    )


def _make_bmp(
    width: int,
    logical_rows: list[bytes],
    bit_count: int = 24,
    top_down: bool = False,
    padding_byte: int = 0xFF,
) -> bytes:
    bytes_per_pixel = bit_count // 8
    row_payload = width * bytes_per_pixel
    row_stride = (row_payload + 3) & ~3
    padding = bytes([padding_byte]) * (row_stride - row_payload)
    physical_rows = logical_rows if top_down else list(reversed(logical_rows))
    pixel_data = b"".join(row + padding for row in physical_rows)
    pixel_offset = 14 + 40
    file_size = pixel_offset + len(pixel_data)
    signed_height = -len(logical_rows) if top_down else len(logical_rows)
    file_header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, pixel_offset)
    dib_header = struct.pack(
        "<IiiHHIIiiII",
        40,
        width,
        signed_height,
        1,
        bit_count,
        0,
        len(pixel_data),
        2835,
        2835,
        0,
        0,
    )
    return file_header + dib_header + pixel_data


def _rgb_rows_from_values(width: int, height: int, values: bytes) -> list[bytes]:
    row_size = width * 3
    if len(values) != row_size * height:
        raise ValueError("value count does not match image dimensions")
    return [values[offset : offset + row_size] for offset in range(0, len(values), row_size)]


class ChiSquareParserTests(unittest.TestCase):
    def test_png_reconstructs_filters_zero_through_four(self) -> None:
        width = 4
        rows = [
            bytes((row * 37 + index * 11) & 0xFF for index in range(width * 3))
            for row in range(5)
        ]

        parsed = parse_png(_make_png(width, rows, filter_types=[0, 1, 2, 3, 4]))

        self.assertEqual(parsed.image_format, "PNG")
        self.assertEqual(parsed.color_bytes, b"".join(rows))

    def test_png_excludes_alpha_channel(self) -> None:
        rgba_row = bytes([10, 20, 30, 0, 40, 50, 60, 255])

        parsed = parse_png(_make_png(2, [rgba_row], color_type=6))

        self.assertEqual(parsed.color_bytes, bytes([10, 20, 30, 40, 50, 60]))

    def test_bmp_skips_row_padding_and_restores_bottom_up_rows(self) -> None:
        rows = [
            bytes(range(1, 16)),
            bytes(range(31, 46)),
        ]

        parsed = parse_bmp(_make_bmp(5, rows, bit_count=24, padding_byte=0x01))

        self.assertEqual(parsed.color_bytes, b"".join(rows))

    def test_bmp_supports_top_down_32_bit_and_excludes_alpha(self) -> None:
        rows = [bytes([1, 2, 3, 99, 4, 5, 6, 88])]

        parsed = parse_bmp(_make_bmp(2, rows, bit_count=32, top_down=True))

        self.assertEqual(parsed.color_bytes, bytes([1, 2, 3, 4, 5, 6]))

    def test_png_rejects_decompression_bomb_beyond_expected_scanlines(self) -> None:
        malicious = _make_png_with_raw_stream(1, 1, b"\x00" * 50_000)

        with self.assertRaisesRegex(ImageParseError, "exceeds expected size"):
            parse_png(malicious)

    def test_png_rejects_crc_corruption(self) -> None:
        png = bytearray(_make_png(1, [b"\x01\x02\x03"]))
        png[20] ^= 0x01

        with self.assertRaisesRegex(ImageParseError, "CRC mismatch"):
            parse_png(bytes(png))

    def test_png_rejects_dimensions_above_pixel_limit(self) -> None:
        oversized = _make_png_with_raw_stream(MAX_PIXELS + 1, 1, b"")

        with self.assertRaisesRegex(ImageParseError, "pixel count"):
            parse_png(oversized)

    def test_bmp_rejects_truncated_pixel_array(self) -> None:
        bmp = _make_bmp(2, [bytes(range(6))])

        with self.assertRaisesRegex(ImageParseError, "exceeds|truncated"):
            parse_bmp(bmp[:-1])


class ChiSquareMathTests(unittest.TestCase):
    def test_survival_function_matches_closed_form_for_two_degrees(self) -> None:
        self.assertAlmostEqual(
            chi_square_survival(2.0, 2),
            math.exp(-1.0),
            places=13,
        )

    def test_uniform_pov_pairs_score_high_and_skewed_pairs_score_low(self) -> None:
        balanced = bytes(range(256)) * 8
        skewed = bytes(value * 2 for value in range(128)) * 16

        balanced_result = analyze_pixel_data(PixelData("TEST", 1, 1, balanced))
        skewed_result = analyze_pixel_data(PixelData("TEST", 1, 1, skewed))

        self.assertEqual(balanced_result.chi_square, 0.0)
        self.assertEqual(balanced_result.uniformity_score, 100.0)
        self.assertLess(skewed_result.uniformity_score, 0.01)


class ChiSquareIntegrationTests(unittest.TestCase):
    def _balanced_png(self) -> bytes:
        width, height = 256, 16
        values = bytes(range(256)) * 48
        return _make_png(width, _rgb_rows_from_values(width, height, values))

    def _skewed_bmp(self) -> bytes:
        width, height = 128, 16
        values = bytes(value * 2 for value in range(128)) * 48
        rows = _rgb_rows_from_values(width, height, values)
        return _make_bmp(width, rows)

    def test_mock_png_and_bmp_produce_anomalous_and_clean_scores(self) -> None:
        png_pixels = parse_png(self._balanced_png())
        bmp_pixels = parse_bmp(self._skewed_bmp())

        png_result = analyze_pixel_data(png_pixels)
        bmp_result = analyze_pixel_data(bmp_pixels)

        self.assertGreater(png_result.uniformity_score, 95.0)
        self.assertLess(bmp_result.uniformity_score, 5.0)

    def test_async_runner_logs_high_uniformity_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "balanced.png"
            target.write_bytes(self._balanced_png())

            with self.assertLogs("dayi", level=26) as captured:
                result = asyncio.run(
                    run_chi_square(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertEqual(result.return_code, 0)
        self.assertIn("LSB uniformity heuristic: 100.00%", result.stdout)
        self.assertTrue(
            any("piksellerinde bir bit yeniği var" in line for line in captured.output)
        )


if __name__ == "__main__":
    unittest.main()
