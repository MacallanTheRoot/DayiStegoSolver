import asyncio
import json
import os
import re
import struct
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from unittest.mock import AsyncMock, patch

from dayi.image_analysis import ImageSafetyError, ImageSource
from dayi.reporter import (
    ScanReport,
    ToolResult,
    _build_flag_attribution,
    _fallback_markdown,
    write_json_report,
)
from dayi.tools.ocr_scanner import (
    OCRDependencies,
    _process_image_sync,
)
from dayi.tools.qr_scanner import (
    QRBackend,
    _DecodedSymbol,
    _decode_zbar,
    run_qr_scanner,
)


PATTERN = re.compile(r"SiberVatan\{[^}]+\}")


def _png(path: Path, marker: bytes = b"") -> ImageSource:
    def chunk(name: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + name + data
            + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00" + marker))
        + chunk(b"IEND", b"")
    )
    digest = (path.name.encode().hex() + "0" * 64)[:64]
    return ImageSource(path, path.name, "PNG", path.stat().st_size, digest)


class ZbarDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_decode_zbar_caps_timeout_to_remaining_budget(self) -> None:
        runner = AsyncMock(
            return_value=(0, b"payload\n", b"", 0.01, False, False, False)
        )
        with patch("dayi.tools.qr_scanner.async_run_command_bytes", runner):
            await _decode_zbar(Path("image.png"), "zbarimg", timeout=0.75)

        self.assertGreater(runner.await_args.kwargs["timeout"], 0)
        self.assertLessEqual(runner.await_args.kwargs["timeout"], 0.75)

    async def test_late_invocation_receives_only_current_remaining_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = _png(root / "late.png")

            def inspect(_path: Path):
                return 1, 1, 1

            decoder = AsyncMock(return_value=([], False))
            with (
                patch(
                    "dayi.tools.qr_scanner.discover_images",
                    return_value=(source,),
                ),
                patch("dayi.tools.qr_scanner.inspect_image_dimensions", side_effect=inspect),
                patch(
                    "dayi.tools.qr_scanner._remaining_plugin_time",
                    return_value=0.3,
                ),
                patch("dayi.tools.qr_scanner._decode_zbar", decoder),
            ):
                await run_qr_scanner(
                    source.path,
                    root / "workspace",
                    PATTERN,
                    timeout=1.0,
                    backend=QRBackend("zbarimg", "zbarimg"),
                )

        self.assertAlmostEqual(decoder.await_args.kwargs["timeout"], 0.3)

    async def test_zbar_does_not_start_after_validation_exhausts_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = _png(root / "expired.png")

            def inspect(_path: Path):
                return 1, 1, 1

            decoder = AsyncMock(return_value=([], False))
            with (
                patch(
                    "dayi.tools.qr_scanner.discover_images",
                    return_value=(source,),
                ),
                patch("dayi.tools.qr_scanner.inspect_image_dimensions", side_effect=inspect),
                patch(
                    "dayi.tools.qr_scanner._remaining_plugin_time",
                    return_value=-0.1,
                ),
                patch("dayi.tools.qr_scanner._decode_zbar", decoder),
            ):
                result = await run_qr_scanner(
                    source.path,
                    root / "workspace",
                    PATTERN,
                    timeout=1.0,
                    backend=QRBackend("zbarimg", "zbarimg"),
                )

        decoder.assert_not_awaited()
        self.assertTrue(result.timed_out)

    async def test_zbar_validates_image_before_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = _png(root / "unsafe.png")
            decoder = AsyncMock(return_value=([], False))
            with (
                patch(
                    "dayi.tools.qr_scanner.discover_images",
                    return_value=(source,),
                ),
                patch(
                    "dayi.tools.qr_scanner.inspect_image_dimensions",
                    side_effect=ImageSafetyError("oversized"),
                ),
                patch("dayi.tools.qr_scanner._decode_zbar", decoder),
            ):
                await run_qr_scanner(
                    source.path,
                    root / "workspace",
                    PATTERN,
                    backend=QRBackend("zbarimg", "zbarimg"),
                )

        decoder.assert_not_awaited()

    async def test_earlier_flag_survives_later_zbar_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = _png(root / "first.png")
            second = _png(root / "second.png")
            decoder = AsyncMock(side_effect=[
                ([_DecodedSymbol(b"SiberVatan{earlier_zbar}")], False),
                ([], True),
            ])
            with (
                patch(
                    "dayi.tools.qr_scanner.discover_images",
                    return_value=(first, second),
                ),
                patch(
                    "dayi.tools.qr_scanner.inspect_image_dimensions",
                    return_value=(1, 1, 1),
                ),
                patch("dayi.tools.qr_scanner._decode_zbar", decoder),
            ):
                result = await run_qr_scanner(
                    first.path,
                    root / "workspace",
                    PATTERN,
                    timeout=2.0,
                    backend=QRBackend("zbarimg", "zbarimg"),
                )

        self.assertIn("SiberVatan{earlier_zbar}", result.flags_found)
        self.assertTrue(result.timed_out)

    async def test_zbar_timeout_reaps_child(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            executable = root / "slow-zbar"
            executable.write_text("#!/bin/sh\nsleep 10\n", encoding="ascii")
            executable.chmod(0o700)
            processes = []
            original = asyncio.create_subprocess_exec

            async def capture(*args, **kwargs):
                process = await original(*args, **kwargs)
                processes.append(process)
                return process

            with patch("asyncio.create_subprocess_exec", side_effect=capture):
                decoded, timed_out = await _decode_zbar(
                    root / "image.png", str(executable), timeout=0.1
                )

        self.assertTrue(timed_out)
        self.assertEqual(decoded, [])
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)
        with self.assertRaises(ProcessLookupError):
            os.kill(processes[0].pid, 0)


class _Image:
    size = (80, 40)
    n_frames = 1

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def load(self) -> None:
        return None


class _Images:
    @staticmethod
    def open(_path: Path) -> _Image:
        return _Image()


class _Tesseract:
    class Output:
        DICT = "dict"

    def __init__(self, text: str) -> None:
        self.text = text

    def image_to_data(self, _image, **_kwargs):
        return {
            "text": [self.text], "conf": ["90"],
            "left": [1], "top": [2], "width": [3], "height": [4],
        }


class PerFlagOCRChainTests(unittest.TestCase):
    def _finding(self, text: str):
        dependencies = OCRDependencies(_Images, _Tesseract(text))
        with (
            patch(
                "dayi.tools.ocr_scanner._build_variants",
                return_value=iter((("original", object()),)),
            ),
            patch("dayi.tools.ocr_scanner._psm_modes", return_value=(6,)),
        ):
            findings, _calls, _bytes, _timed_out = _process_image_sync(
                Path("synthetic.png"),
                "target:synthetic.png",
                dependencies,
                "eng",
                False,
                time.monotonic() + 5.0,
                PATTERN,
                1,
                1024 * 1024,
            )
        return findings[0]

    def test_direct_and_html_flags_keep_separate_chains(self) -> None:
        direct = "SiberVatan{direct}"
        encoded = "SiberVatan{html}"
        finding = self._finding(
            direct + " SiberVatan&#123;html&#125;"
        )

        self.assertEqual(finding.decoder_chain_for(direct), ())
        self.assertIn("html-entity", finding.decoder_chain_for(encoded))

    def test_multiple_encoded_flags_keep_separate_chains(self) -> None:
        finding = self._finding(
            "SiberVatan&#123;html&#125; "
            "SiberVatan%7Bpercent%7D"
        )

        self.assertIn(
            "html-entity", finding.decoder_chain_for("SiberVatan{html}")
        )
        self.assertIn(
            "url-percent", finding.decoder_chain_for("SiberVatan{percent}")
        )

    def test_duplicate_flags_remain_deduplicated(self) -> None:
        finding = self._finding(
            "SiberVatan{same} SiberVatan{same}"
        )
        self.assertEqual(finding.flags_found, ("SiberVatan{same}",))
        self.assertEqual(len(finding.flag_decoder_chains), 1)

    def test_json_and_markdown_use_each_flags_chain(self) -> None:
        direct = "SiberVatan{direct}"
        html = "SiberVatan{html}"
        finding = self._finding(
            direct + " SiberVatan&#123;html&#125;"
        )
        result = ToolResult(
            "ocr_scanner", [], 0, "", "", [direct, html], 0.1,
            extracted_flags={finding.source: [direct, html]},
            ocr_findings=[finding],
        )
        report = ScanReport(
            "synthetic.png", PATTERN.pattern, None, "a", "b",
            [direct, html], [result],
        )
        attribution = _build_flag_attribution([result])
        self.assertNotIn("html-entity", attribution[direct][0])
        self.assertIn("html-entity", attribution[html][0])

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            json_path = root / "report.json"
            markdown_path = root / "report.md"
            write_json_report(report, json_path)
            _fallback_markdown(report, markdown_path)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")

        self.assertNotIn(
            "html-entity", payload["flag_attribution"][direct][0]
        )
        self.assertIn(
            "html-entity", payload["flag_attribution"][html][0]
        )
        self.assertIn("html-entity", markdown)


if __name__ == "__main__":
    unittest.main()
