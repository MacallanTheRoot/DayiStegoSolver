import asyncio
import base64
import binascii
import gzip
import re
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from dayi.image_analysis import ImageSource
from dayi.tools._plugin import PluginPhase, discover_plugins
from dayi.tools.qr_scanner import (
    PLUGIN_SPECS,
    QRBackend,
    _DecodedSymbol,
    _decode_zbar,
    classify_qr_payload,
    run_qr_scanner,
    select_qr_backend,
)


class QRClassificationTests(unittest.TestCase):
    def test_passive_payload_classes(self) -> None:
        cases = {
            b"https://example.com/path": "url",
            b"WIFI:T:WPA;S:test;P:redacted;;": "wifi",
            b"BEGIN:VCARD\nFN:Test\nEND:VCARD": "vcard",
            b"otpauth://totp/example": "otp-uri",
            b'{"value":"test"}': "json",
            b"4141414141414141": "hex-like-text",
            b"\x89PNG\r\n\x1a\nrest": "image-data",
            b"\xff\x00\xfe": "binary",
        }
        for payload, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(classify_qr_payload(payload), expected)

    def test_backend_priority_and_clean_unavailable_state(self) -> None:
        cv2 = SimpleNamespace(QRCodeDetector=lambda: object())
        with patch("dayi.tools.qr_scanner.importlib.import_module", return_value=cv2):
            self.assertEqual(select_qr_backend().name, "opencv")
        with patch("dayi.tools.qr_scanner.shutil.which", return_value=None):
            with patch(
                "dayi.tools.qr_scanner.importlib.import_module",
                side_effect=ImportError,
            ):
                self.assertIsNone(select_qr_backend())


class QRScannerTests(unittest.TestCase):
    def _source(self, root: Path) -> ImageSource:
        path = root / "qr.bin"
        def chunk(name: bytes, data: bytes) -> bytes:
            return (
                struct.pack(">I", len(data)) + name + data
                + struct.pack(">I", binascii.crc32(name + data) & 0xFFFFFFFF)
            )
        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        path.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
            + chunk(b"IEND", b"")
        )
        return ImageSource(path, "document_extracted/qr.bin", "PNG", path.stat().st_size, "a" * 64)

    def _run_payloads(self, payloads: list[bytes], pattern: str = r"SiberVatan\{.*?\}"):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = self._source(root)
            cv2 = SimpleNamespace(IMREAD_UNCHANGED=-1, imread=lambda *_args: object())
            with (
                patch("dayi.tools.qr_scanner.discover_images", return_value=(source,)),
                patch(
                    "dayi.tools.qr_scanner._decode_native_isolated",
                    new=AsyncMock(return_value=[
                        ("original", _DecodedSymbol(item)) for item in payloads
                    ]),
                ),
            ):
                return asyncio.run(
                    run_qr_scanner(source.path, root / "workspace", re.compile(pattern), backend=QRBackend("opencv", cv2))
                )

    def test_plugin_order_count_and_core_availability(self) -> None:
        self.assertEqual(PLUGIN_SPECS[0].phase, PluginPhase.ARCHIVE)
        self.assertEqual(PLUGIN_SPECS[0].priority, 15)
        registry = discover_plugins()
        self.assertEqual(len(registry.plugins), 22)
        ids = [item.plugin_id for item in registry.plugins]
        self.assertLess(ids.index("document_stego_scanner"), ids.index("qr_scanner"))
        self.assertLess(ids.index("qr_scanner"), ids.index("ocr_scanner"))

    def test_flag_base64_and_duplicate_payloads_are_deduplicated(self) -> None:
        encoded = base64.b64encode(b"SiberVatan{qr_nested}")
        result = self._run_payloads([encoded, encoded])
        self.assertEqual(result.flags_found, ["SiberVatan{qr_nested}"])
        self.assertEqual(len(result.qr_findings), 1)
        self.assertIn("base64", result.qr_findings[0].decoder_chain)
        self.assertTrue(any(
            label.startswith("document_extracted/qr.bin>qr:opencv:original")
            for label in result.extracted_flags
        ))

    def test_url_and_command_payloads_are_passive_and_sanitized(self) -> None:
        with (
            patch("socket.create_connection", side_effect=AssertionError("network forbidden")) as network,
            patch("subprocess.Popen", side_effect=AssertionError("payload execution forbidden")) as process,
        ):
            result = self._run_payloads([
                b"https://example.com/path",
                b"rm -rf /\x1b[31m\xe2\x80\xae",
            ])
        network.assert_not_called()
        process.assert_not_called()
        self.assertFalse(result.flags_found)
        self.assertTrue(any(item.payload_type == "url" for item in result.qr_findings))
        rendered = result.stdout
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn("U+202E", rendered)
        self.assertIn("never opened or executed", rendered)

    def test_binary_payload_is_bounded_and_not_a_flag(self) -> None:
        result = self._run_payloads([b"\xff\x00\xfe"])
        self.assertEqual(result.flags_found, [])
        finding = result.qr_findings[0]
        self.assertEqual(finding.payload_type, "binary")
        self.assertEqual(finding.payload_bytes_preview, "ff00fe")

    def test_multiple_symbols_are_ordered_top_to_bottom_then_left_to_right(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = self._source(root)
            cv2 = SimpleNamespace(IMREAD_UNCHANGED=-1, imread=lambda *_args: object())
            symbols = [
                _DecodedSymbol(b"second", ((50.0, 20.0),)),
                _DecodedSymbol(b"first", ((10.0, 10.0),)),
            ]
            with (
                patch("dayi.tools.qr_scanner.discover_images", return_value=(source,)),
                patch(
                    "dayi.tools.qr_scanner._decode_native_isolated",
                    new=AsyncMock(return_value=[
                        ("original", symbol) for symbol in symbols
                    ]),
                ),
            ):
                result = asyncio.run(run_qr_scanner(
                    source.path, root / "workspace", re.compile("never"), backend=QRBackend("opencv", cv2)
                ))
        self.assertEqual([item.payload_text for item in result.qr_findings], ["first", "second"])

    def test_gzip_and_json_fields_enter_bounded_nested_decoding(self) -> None:
        compressed = gzip.compress(b"SiberVatan{gzip_qr}")
        json_payload = b'{"payload":"U2liZXJWYXRhbntqc29uX3FyfQ=="}'
        result = self._run_payloads([compressed, json_payload])
        self.assertEqual(
            result.flags_found,
            ["SiberVatan{gzip_qr}", "SiberVatan{json_qr}"],
        )
        chains = [item.decoder_chain for item in result.qr_findings]
        self.assertTrue(any("gzip" in chain for chain in chains))
        self.assertTrue(any("json-field" in chain and "base64" in chain for chain in chains))

    def test_data_image_recursion_is_workspace_bounded_and_cycle_safe(self) -> None:
        with tempfile.TemporaryDirectory() as image_tmpdir:
            nested_source = self._source(Path(image_tmpdir))
            nested = nested_source.path.read_bytes()
        payload = b"data:image/png;base64," + base64.b64encode(nested)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = self._source(root)
            workspace = root / "workspace"
            cv2 = SimpleNamespace(IMREAD_UNCHANGED=-1, imread=lambda *_args: object())
            decoder = AsyncMock(side_effect=[
                [("original", _DecodedSymbol(payload))],
                [("original", _DecodedSymbol(b"SiberVatan{recursive_qr}"))],
            ])
            with (
                patch("dayi.tools.qr_scanner.discover_images", return_value=(source,)),
                patch(
                    "dayi.tools.qr_scanner._decode_native_isolated",
                    decoder,
                ),
                patch("dayi.tools.exiftool.run_exiftool", new=AsyncMock(return_value=SimpleNamespace(flags_found=[], extracted_flags={}, artifacts_found=[]))),
                patch("dayi.tools.lsb.run_lsb", new=AsyncMock(return_value=SimpleNamespace(flags_found=[], extracted_flags={}, artifacts_found=[]))),
                patch("dayi.tools.zsteg.run_zsteg", new=AsyncMock(return_value=SimpleNamespace(flags_found=[], extracted_flags={}, artifacts_found=[]))),
            ):
                result = asyncio.run(run_qr_scanner(
                    source.path, workspace, re.compile(r"SiberVatan\{.*?\}"), backend=QRBackend("opencv", cv2)
                ))
            persisted = list((workspace / "qr_decoded").glob("*"))
        self.assertEqual(len(persisted), 1)
        self.assertIn("SiberVatan{recursive_qr}", result.flags_found)
        self.assertLessEqual(decoder.await_count, 2)

    def test_unavailable_backend_skips_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = self._source(root)
            with patch("dayi.tools.qr_scanner.select_qr_backend", return_value=None):
                result = asyncio.run(run_qr_scanner(source.path, root / "w", re.compile("x")))
        self.assertTrue(result.skipped)

    def test_zbar_uses_static_arguments_and_timeout(self) -> None:
        runner = AsyncMock(
            return_value=(0, b"FLAG{x}\n", b"", 0.1, False, False, False)
        )
        with patch("dayi.tools.qr_scanner.async_run_command_bytes", runner):
            decoded, timed_out = asyncio.run(_decode_zbar(Path("image.png"), "/usr/bin/zbarimg"))
        self.assertFalse(timed_out)
        self.assertEqual(decoded[0].payload, b"FLAG{x}")
        command = runner.await_args.args[0]
        self.assertEqual(command[:3], ["/usr/bin/zbarimg", "--quiet", "--raw"])
        self.assertIn("--oneshot", command)

    def test_zbar_timeout_and_payload_symbol_limits_are_contained(self) -> None:
        runner = AsyncMock(
            return_value=(None, b"", b"", 10.0, True, False, False)
        )
        with patch("dayi.tools.qr_scanner.async_run_command_bytes", runner):
            decoded, timed_out = asyncio.run(_decode_zbar(Path("image.png"), "/usr/bin/zbarimg"))
        self.assertTrue(timed_out)
        self.assertEqual(decoded, [])

        payloads = [f"payload-{index}".encode() for index in range(25)]
        payloads.insert(0, b"x" * (1024 * 1024 + 1))
        result = self._run_payloads(payloads)
        self.assertLessEqual(len(result.qr_findings), 10)
        self.assertTrue(all(item.payload_text != "x" * (1024 * 1024 + 1) for item in result.qr_findings))

    @unittest.skipUnless(__import__("importlib").util.find_spec("qrcode") and __import__("importlib").util.find_spec("cv2"), "local QR integration dependencies unavailable")
    def test_real_local_qr_decode_when_backend_is_available(self) -> None:
        import qrcode
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "wrong-extension.bin"
            qrcode.make("SiberVatan{real_qr}").save(target, format="PNG")
            result = asyncio.run(run_qr_scanner(target, root / "workspace", re.compile(r"SiberVatan\{.*?\}")))
        self.assertIn("SiberVatan{real_qr}", result.flags_found)


if __name__ == "__main__":
    unittest.main()
