import asyncio
import binascii
import importlib.metadata
import io
import multiprocessing
import re
import struct
import tempfile
import time
import unittest
import zipfile
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from dayi.doctor import (
    PYTHON_CAPABILITY_DEFINITIONS,
    PythonCapabilityDiagnostic,
    diagnose_opencv_qr_capability,
    diagnose_python_capability,
)
from dayi.document import analyze_document
from dayi.image_analysis import ImageSafetyError, ImageSource, inspect_image_dimensions
from dayi.tools.document_stego_scanner import _await_analysis
from dayi.tools.ocr_scanner import OCRDependencies, _process_image_sync
from dayi.tools.qr_scanner import QRBackend, _decode_zbar, run_qr_scanner
from dayi.tools.text_stego_scanner import _await_text_analysis
from dayi.tools._base import async_run_isolated


PATTERN = re.compile(r"SiberVatan\{.*?\}")


def _png_header(width: int, height: int) -> bytes:
    def chunk(name: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + name + data
            + struct.pack(">I", binascii.crc32(name + data) & 0xFFFFFFFF)
        )

    row = b"\x00" + b"\x00" * ((width + 7) // 8)
    ihdr = struct.pack(">IIBBBBB", width, height, 1, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(row * height))
        + chunk(b"IEND", b"")
    )


def _content_types() -> bytes:
    return (
        '<?xml version="1.0"?><Types '
        'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.'
        'wordprocessingml.document.main+xml"/></Types>'
    ).encode()


def _package_rels() -> bytes:
    return (
        '<?xml version="1.0"?><Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="officeDocument" '
        'Target="word/document.xml"/></Relationships>'
    ).encode()


def _media_rels() -> bytes:
    return (
        '<?xml version="1.0"?><Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId2" Type="image" '
        'Target="media/image1.png"/></Relationships>'
    ).encode()


def _docx_bytes(*, media: bytes, embedded: bytes | None = None) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _content_types())
        archive.writestr("_rels/.rels", _package_rels())
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/'
            'wordprocessingml/2006/main"><w:body/></w:document>',
        )
        archive.writestr("word/_rels/document.xml.rels", _media_rels())
        archive.writestr("word/media/image1.png", media)
        if embedded is not None:
            archive.writestr("word/embeddings/nested.docx", embedded)
    return output.getvalue()


class _Image:
    size = (80, 40)
    n_frames = 1

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def load(self):
        return None


class _Images:
    @staticmethod
    def open(_path):
        return _Image()


class _SlowOCR:
    class Output:
        DICT = "dict"

    def __init__(self, text: str = "ordinary", delay: float = 0.06):
        self.calls = 0
        self.timeouts: list[float] = []
        self.text = text
        self.delay = delay

    def image_to_data(self, _image, **kwargs):
        self.calls += 1
        self.timeouts.append(kwargs["timeout"])
        time.sleep(self.delay)
        return {
            "text": [self.text], "conf": ["80"],
            "left": [0], "top": [0], "width": [1], "height": [1],
        }

    @staticmethod
    def image_to_string(_image, **_kwargs):
        return ""


def _slow_document_worker(*_args):
    time.sleep(5.0)


def _slow_text_worker(*_args):
    time.sleep(5.0)


def _exception_worker(kind: str):
    if kind == "keyboard":
        raise KeyboardInterrupt
    if kind == "system-exit":
        raise SystemExit
    raise ValueError("private parser detail")


class CorrectiveHardeningRegressions(unittest.TestCase):
    def test_opencv_rejects_oversized_header_before_decode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "oversized.bin"
            target.write_bytes(_png_header(20_001, 1))
            source = ImageSource(
                target, "target:oversized.bin", "PNG", target.stat().st_size, "a" * 64
            )
            decoder = AsyncMock(return_value=[])
            with (
                patch("dayi.tools.qr_scanner.discover_images", return_value=(source,)),
                patch(
                    "dayi.tools.qr_scanner._decode_native_isolated",
                    decoder,
                ),
            ):
                asyncio.run(
                    run_qr_scanner(
                        target, root / "workspace", PATTERN,
                        backend=QRBackend("opencv", object()),
                    )
                )
        decoder.assert_not_awaited()

    def test_opencv_valid_image_reaches_decode_and_malformed_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            valid = root / "valid.bin"
            valid.write_bytes(_png_header(8, 8))
            malformed = root / "bad.bin"
            malformed.write_bytes(b"\x89PNG\r\n\x1a\ntruncated")
            for target, should_decode in ((valid, True), (malformed, False)):
                decoder = AsyncMock(return_value=[])
                source = ImageSource(
                    target, f"target:{target.name}", "PNG",
                    target.stat().st_size, target.name * 8,
                )
                with (
                    patch("dayi.tools.qr_scanner.discover_images", return_value=(source,)),
                    patch(
                        "dayi.tools.qr_scanner._decode_native_isolated",
                        decoder,
                    ),
                ):
                    asyncio.run(run_qr_scanner(
                        target, root / "workspace", PATTERN,
                        backend=QRBackend("opencv", object()),
                    ))
                self.assertEqual(bool(decoder.await_count), should_decode)

    def test_image_metadata_fallback_accepts_safe_png_and_rejects_malformed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            valid = root / "valid"
            valid.write_bytes(_png_header(16, 8))
            self.assertEqual(
                inspect_image_dimensions(valid, image_module=False),
                (16, 8, 1),
            )
            malformed = root / "malformed"
            malformed.write_bytes(b"\x89PNG\r\n\x1a\ntruncated")
            with self.assertRaises(ImageSafetyError):
                inspect_image_dimensions(malformed, image_module=False)

            with patch("dayi.image_analysis.MAX_SOURCE_IMAGE_BYTES", 32):
                with self.assertRaises(ImageSafetyError):
                    inspect_image_dimensions(valid, image_module=False)

            excessive_pixels = root / "pixels"
            excessive_pixels.write_bytes(
                b"\x89PNG\r\n\x1a\n"
                + struct.pack(">I", 13)
                + b"IHDR"
                + struct.pack(">II", 10_000, 10_000)
                + b"\x01\x00\x00\x00\x00"
            )
            with self.assertRaises(ImageSafetyError):
                inspect_image_dimensions(excessive_pixels, image_module=False)

    def test_document_timeout_does_not_leave_worker_process(self) -> None:
        before = {child.pid for child in multiprocessing.active_children()}
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            started = time.monotonic()
            with self.assertRaises(asyncio.TimeoutError):
                asyncio.run(_await_analysis(
                    root / "x", PATTERN, root / "w", 0.05,
                    worker=_slow_document_worker,
                ))
            self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(
            {child.pid for child in multiprocessing.active_children()}, before
        )

    def test_isolated_worker_errors_interrupts_and_cancellation_are_distinct(self) -> None:
        with self.assertRaises(ValueError):
            asyncio.run(async_run_isolated(
                _exception_worker, "error", timeout=1.0
            ))
        for kind, exception in (
            ("keyboard", KeyboardInterrupt),
            ("system-exit", SystemExit),
        ):
            with self.subTest(kind=kind), self.assertRaises(exception):
                asyncio.run(async_run_isolated(
                    _exception_worker, kind, timeout=1.0
                ))

        before = {child.pid for child in multiprocessing.active_children()}

        async def cancel_worker() -> None:
            task = asyncio.create_task(async_run_isolated(
                _slow_text_worker, "x", timeout=5.0
            ))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(cancel_worker())
        self.assertEqual(
            {child.pid for child in multiprocessing.active_children()}, before
        )

    def test_text_timeout_does_not_leave_worker_process(self) -> None:
        before = {child.pid for child in multiprocessing.active_children()}
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "text"
            target.write_text("ordinary text", encoding="utf-8")
            started = time.monotonic()
            with self.assertRaises(asyncio.TimeoutError):
                asyncio.run(_await_text_analysis(
                    target, PATTERN, 0.05, worker=_slow_text_worker
                ))
            self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(
            {child.pid for child in multiprocessing.active_children()}, before
        )

    def test_ocr_recomputes_deadline_before_each_pass(self) -> None:
        engine = _SlowOCR()
        started = time.monotonic()
        _findings, _used, _text, timed_out = _process_image_sync(
            Path("image"), "target:image", OCRDependencies(_Images, engine),
            "eng", False, time.monotonic() + 0.05, PATTERN, 30, 1024 * 1024,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(engine.calls, 1)
        self.assertLess(elapsed, 0.14)
        self.assertTrue(timed_out)

    def test_ocr_timeouts_shrink_and_completed_flag_survives_deadline(self) -> None:
        engine = _SlowOCR(text="", delay=0.02)
        _findings, used, _text, _timed_out = _process_image_sync(
            Path("image"), "target:image", OCRDependencies(_Images, engine),
            "eng", True, time.monotonic() + 0.09, PATTERN, 30, 1024 * 1024,
        )
        self.assertEqual(used, 3)
        self.assertTrue(all(
            later < earlier
            for earlier, later in zip(engine.timeouts, engine.timeouts[1:])
        ))
        self.assertLessEqual(used, 30)

        flagged = _SlowOCR(text="SiberVatan{deadline_flag}", delay=0.06)
        findings, used, _text, timed_out = _process_image_sync(
            Path("image"), "target:image", OCRDependencies(_Images, flagged),
            "eng", True, time.monotonic() + 0.05, PATTERN, 30, 1024 * 1024,
        )
        self.assertEqual(used, 1)
        self.assertTrue(timed_out)
        self.assertEqual(findings[0].flags_found, ("SiberVatan{deadline_flag}",))

    def test_nested_packages_use_independent_extraction_paths(self) -> None:
        nested = _docx_bytes(
            media=_png_header(1, 1) + b"SiberVatan{nested_media}"
        )
        parent = _docx_bytes(
            media=_png_header(1, 1) + b"parent-media", embedded=nested
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "parent.docx"
            target.write_bytes(parent)
            analysis = analyze_document(target, PATTERN, workspace=root / "workspace")
            paths = [item.path for item in analysis.extracted_artifacts]
            self.assertEqual(len(paths), 3)
            self.assertEqual(len(set(paths)), 3)
            self.assertTrue(all(path.is_file() for path in paths))
        self.assertFalse(any("File exists" in error for error in analysis.errors))
        self.assertTrue(any(
            "SiberVatan{nested_media}" in finding.flags_found
            for finding in analysis.findings
        ))

    def test_referenced_odf_media_is_not_orphaned(self) -> None:
        content = (
            '<office:document-content '
            'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
            'xmlns:xlink="http://www.w3.org/1999/xlink">'
            '<office:body><draw:image xlink:href="Pictures/image.png"/>'
            '</office:body></office:document-content>'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "document.odt"
            with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("mimetype", "application/vnd.oasis.opendocument.text")
                archive.writestr("content.xml", content)
                archive.writestr("Pictures/image.png", _png_header(1, 1))
            analysis = analyze_document(target, PATTERN, workspace=root / "workspace")
        self.assertFalse(any(
            finding.mechanism == "unreferenced-media"
            and finding.source_member == "Pictures/image.png"
            for finding in analysis.findings
        ))

    def test_odf_reference_variants_orphans_and_unsafe_targets(self) -> None:
        mime_types = (
            "application/vnd.oasis.opendocument.text",
            "application/vnd.oasis.opendocument.spreadsheet",
            "application/vnd.oasis.opendocument.presentation",
        )
        content = (
            '<office:document-content '
            'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
            'xmlns:xlink="http://www.w3.org/1999/xlink">'
            '<office:body><draw:image xlink:href="Pictures/referenced.png"/>'
            '<draw:image xlink:href="../escape.png"/>'
            '<draw:image xlink:href="https://example.invalid/passive.png"/>'
            '<draw:image xlink:href="Pictures/missing.png"/>'
            '</office:body></office:document-content>'
        )
        manifest = (
            '<manifest:manifest '
            'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
            '<manifest:file-entry manifest:full-path="Pictures/referenced.png"/>'
            '</manifest:manifest>'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for index, mime in enumerate(mime_types):
                target = root / f"document-{index}"
                with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("mimetype", mime)
                    archive.writestr("content.xml", content)
                    archive.writestr("META-INF/manifest.xml", manifest)
                    archive.writestr("Pictures/referenced.png", _png_header(1, 1))
                    archive.writestr("Pictures/orphan.png", _png_header(1, 1))
                analysis = analyze_document(
                    target, PATTERN, workspace=root / f"workspace-{index}"
                )
                mechanisms = {
                    (finding.mechanism, finding.source_member)
                    for finding in analysis.findings
                }
                self.assertNotIn(
                    ("unreferenced-media", "Pictures/referenced.png"), mechanisms
                )
                self.assertIn(
                    ("unreferenced-media", "Pictures/orphan.png"), mechanisms
                )
                self.assertIn(
                    ("unsafe-odf-reference", "content.xml"), mechanisms
                )
                self.assertIn(
                    ("missing-internal-target", "content.xml"), mechanisms
                )
                self.assertIn(("external", "content.xml"), mechanisms)

    def test_zbar_binary_payload_is_not_utf8_reencoded(self) -> None:
        payload = b"\xff\x00\x89PNG\r\n\x1a\nembedded\nnewline"
        runner = AsyncMock(
            return_value=(0, payload + b"\n", b"", 0.01, False, False, False)
        )
        with patch("dayi.tools.qr_scanner.async_run_command_bytes", runner):
            decoded, timed_out = asyncio.run(_decode_zbar(Path("image"), "zbarimg"))
        self.assertFalse(timed_out)
        self.assertEqual(decoded[0].payload, payload)

    def test_zbar_preserves_image_and_compressed_bytes_and_rejects_truncation(self) -> None:
        payloads = (_png_header(1, 1), zlib.compress(b"bounded payload"))
        for payload in payloads:
            with self.subTest(prefix=payload[:4]):
                runner = AsyncMock(
                    return_value=(
                        0, payload + b"\n", b"", 0.01,
                        False, False, False,
                    )
                )
                with patch(
                    "dayi.tools.qr_scanner.async_run_command_bytes", runner
                ):
                    decoded, _timed_out = asyncio.run(
                        _decode_zbar(Path("image"), "zbarimg")
                    )
                self.assertEqual(decoded[0].payload, payload)

        runner = AsyncMock(
            return_value=(0, b"x" * 10, b"", 0.01, False, True, False)
        )
        with patch("dayi.tools.qr_scanner.async_run_command_bytes", runner):
            decoded, timed_out = asyncio.run(_decode_zbar(Path("image"), "zbarimg"))
        self.assertFalse(timed_out)
        self.assertEqual(decoded, [])

    def test_doctor_accepts_headless_opencv_metadata(self) -> None:
        definition = next(
            item for item in PYTHON_CAPABILITY_DEFINITIONS
            if item.capability_id == "opencv_qr"
        )

        def version(name: str) -> str:
            if name == "opencv-python-headless":
                return "4.10"
            raise importlib.metadata.PackageNotFoundError(name)

        result = diagnose_python_capability(
            definition,
            find_spec=lambda _name: SimpleNamespace(
                origin="/site/cv2/__init__.py", submodule_search_locations=None
            ),
            distribution_version=version,
            site_roots=(Path("/site"),),
        )
        self.assertTrue(result.available)
        self.assertEqual(result.metadata_status, "ok")
        self.assertEqual(result.distribution, "opencv-python-headless")

    def test_doctor_accepts_desktop_opencv_and_rejects_missing_qr_api(self) -> None:
        definition = next(
            item for item in PYTHON_CAPABILITY_DEFINITIONS
            if item.capability_id == "opencv_qr"
        )

        def version(name: str) -> str:
            if name == "opencv-python":
                return "4.10"
            raise importlib.metadata.PackageNotFoundError(name)

        desktop = diagnose_python_capability(
            definition,
            find_spec=lambda _name: SimpleNamespace(
                origin="/site/cv2/__init__.py", submodule_search_locations=None
            ),
            distribution_version=version,
            site_roots=(Path("/site"),),
        )
        self.assertEqual(desktop.metadata_status, "ok")
        self.assertEqual(desktop.distribution, "opencv-python")

        base = PythonCapabilityDiagnostic(
            "opencv_qr", "cv2", "opencv-python-headless", "OpenCV QR",
            True, "4.10", "ok", "preferred QR backend", None, "site-packages",
        )
        with (
            patch("dayi.doctor.diagnose_python_capability", return_value=base),
            patch("dayi.doctor.importlib.import_module", return_value=object()),
        ):
            missing_api = diagnose_opencv_qr_capability(definition)
        self.assertFalse(missing_api.available)
        self.assertEqual(missing_api.metadata_status, "api-missing")


if __name__ == "__main__":
    unittest.main()
