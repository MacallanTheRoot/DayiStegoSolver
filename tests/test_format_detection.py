import asyncio
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dayi.tools._base import FileType, describe_file_type, get_file_type
from dayi.tools.exiv2 import run_exiv2
from dayi.tools.zsteg import run_zsteg


class ContentFormatDetectionTests(unittest.TestCase):
    def test_plain_utf8_text_is_detected_without_using_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            extensionless = root / "carrier"
            misleading = root / "carrier.png"
            extensionless.write_text("ordinary UTF-8 text\nTürkçe içerik", encoding="utf-8")
            misleading.write_text("plain text with a misleading suffix", encoding="utf-8")

            self.assertEqual(get_file_type(extensionless), FileType.TEXT)
            self.assertEqual(get_file_type(misleading), FileType.TEXT)

    def test_binary_data_remains_unknown_and_magic_has_priority(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            binary = root / "binary.txt"
            png = root / "image.txt"
            binary.write_bytes(b"\x13\x37\x00\xff" * 16)
            png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"printable text" * 4)

            self.assertEqual(get_file_type(binary), FileType.UNKNOWN)
            self.assertEqual(get_file_type(png), FileType.PNG)

    def test_descriptions_do_not_duplicate_format_wording(self) -> None:
        self.assertEqual(describe_file_type(FileType.TEXT), "UTF-8 text")
        rendered = f"{describe_file_type(FileType.UNKNOWN)} formatında"
        self.assertEqual(rendered, "bilinmeyen formatında")
        self.assertNotIn("formatta formatında", rendered)

    def test_image_only_tools_skip_text_before_optional_tool_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "plain.data"
            target.write_text("plain UTF-8 text", encoding="utf-8")
            with patch("dayi.tools.exiv2.is_tool_available") as exiv2_available:
                exiv2_result = asyncio.run(
                    run_exiv2(target, re.compile(r"CTF\{.*?\}"))
                )
            with patch("dayi.tools.zsteg.is_tool_available") as zsteg_available:
                zsteg_result = asyncio.run(
                    run_zsteg(target, re.compile(r"CTF\{.*?\}"))
                )

        self.assertTrue(exiv2_result.skipped)
        self.assertIn("not applicable", exiv2_result.skip_reason)
        exiv2_available.assert_not_called()
        self.assertTrue(zsteg_result.skipped)
        self.assertIn("detected format: TEXT", zsteg_result.skip_reason)
        zsteg_available.assert_not_called()


if __name__ == "__main__":
    unittest.main()
