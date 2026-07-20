import asyncio
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dayi.tools._plugin import PluginPhase
from dayi.tools.ocr_scanner import (
    OCRDependencies,
    PLUGIN_SPECS,
    run_ocr_scanner,
)


def _mock_png(marker: bytes) -> bytes:
    """Return enough PNG-like bytes for the bounded magic prefilter."""
    return b"\x89PNG\r\n\x1a\n" + marker


class _FakeImage:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.size = (64, 32)
        self.loaded = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def load(self) -> None:
        self.loaded = True


class _FakeImageModule:
    def __init__(self) -> None:
        self.opened: list[Path] = []

    def open(self, path: Path) -> _FakeImage:
        image_path = Path(path)
        self.opened.append(image_path)
        return _FakeImage(image_path)


class _FakeTesseract:
    def __init__(self, outputs: dict[str, str | BaseException]) -> None:
        self.outputs = outputs
        self.calls: list[tuple[str, float]] = []

    def get_tesseract_version(self) -> str:
        return "5.0-test"

    def image_to_string(self, image: _FakeImage, timeout: float) -> str:
        self.calls.append((image.path.name, timeout))
        output = self.outputs.get(image.path.name, "")
        if isinstance(output, BaseException):
            raise output
        return output


class OCRScannerTests(unittest.TestCase):
    def test_plugin_runs_after_zip_cracker_in_archive_phase(self) -> None:
        self.assertEqual(len(PLUGIN_SPECS), 1)
        self.assertEqual(PLUGIN_SPECS[0].plugin_id, "ocr_scanner")
        self.assertEqual(PLUGIN_SPECS[0].phase, PluginPhase.ARCHIVE)
        self.assertGreater(PLUGIN_SPECS[0].priority, 10)

    def test_missing_optional_dependencies_skip_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.png"
            target.write_bytes(_mock_png(b"target"))
            with patch(
                "dayi.tools.ocr_scanner._load_ocr_dependencies",
                return_value=None,
            ):
                result = asyncio.run(
                    run_ocr_scanner(
                        target,
                        root / "workspace",
                        re.compile(r"FLAG\{.*?\}"),
                    )
                )

        self.assertTrue(result.skipped)
        self.assertIn("optional OCR dependencies", result.skip_reason)

    def test_missing_tesseract_executable_skip_gracefully(self) -> None:
        class MissingTesseract(_FakeTesseract):
            def get_tesseract_version(self) -> str:
                raise RuntimeError("tesseract binary not found")

        dependencies = OCRDependencies(
            image_module=_FakeImageModule(),
            pytesseract=MissingTesseract({}),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.png"
            target.write_bytes(_mock_png(b"target"))
            with patch(
                "dayi.tools.ocr_scanner._load_ocr_dependencies",
                return_value=dependencies,
            ), patch(
                "dayi.tools.ocr_scanner.shutil.which",
                return_value=None,
            ):
                result = asyncio.run(
                    run_ocr_scanner(
                        target,
                        root / "workspace",
                        re.compile(r"FLAG\{.*?\}"),
                    )
                )

        self.assertTrue(result.skipped)
        self.assertIn("Tesseract OCR executable", result.skip_reason)

    def test_scans_target_and_recursive_workspace_images(self) -> None:
        image_module = _FakeImageModule()
        tesseract = _FakeTesseract(
            {
                "target.png": "Dayinin optik gozleri burada",
                "flag.png": "hidden FLAG{ocr_workspace_success}",
            }
        )
        dependencies = OCRDependencies(image_module, tesseract)
        messages: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.png"
            target.write_bytes(_mock_png(b"main-image"))
            workspace = root / "workspace"
            extracted = workspace / "binwalk" / "nested"
            extracted.mkdir(parents=True)
            (extracted / "flag.png").write_bytes(_mock_png(b"flag-image"))
            # Binwalk's copied input must not be OCR'd twice.
            (workspace / "binwalk" / "target.png").write_bytes(
                target.read_bytes()
            )
            (extracted / "noise.txt").write_text("not an image", encoding="utf-8")

            with patch(
                "dayi.tools.ocr_scanner._load_ocr_dependencies",
                return_value=dependencies,
            ), patch(
                "dayi.tools.ocr_scanner.shutil.which",
                return_value="/controlled/tesseract",
            ), patch(
                "dayi.tools.ocr_scanner._probe_ocr_languages",
                return_value=("eng",),
            ):
                result = asyncio.run(
                    run_ocr_scanner(
                        target,
                        workspace,
                        re.compile(r"FLAG\{.*?\}"),
                        artifact_callback=messages.append,
                    )
                )

        self.assertFalse(result.skipped)
        self.assertEqual(result.flags_found, ["FLAG{ocr_workspace_success}"])
        self.assertEqual(
            result.extracted_flags,
            {
                "ocr:binwalk/nested/flag.png:original-psm3": [
                    "FLAG{ocr_workspace_success}"
                ]
            },
        )
        self.assertEqual(
            sorted(path.name for path in image_module.opened),
            ["flag.png", "target.png"],
        )
        self.assertEqual(len(messages), 2)
        self.assertTrue(
            all(
                message.startswith(
                    "[!] Yeğenim, görselin içinde gizli bir yazı yakaladım:"
                )
                for message in messages
            )
        )
        self.assertIn("FLAG{ocr_workspace_success}", result.stdout)

    def test_one_bad_image_does_not_hide_flags_from_other_images(self) -> None:
        image_module = _FakeImageModule()
        tesseract = _FakeTesseract(
            {
                "bad.png": RuntimeError("OCR engine rejected image"),
                "good.png": "FLAG{ocr_partial_success}",
            }
        )
        dependencies = OCRDependencies(image_module, tesseract)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "not-an-image.bin"
            target.write_bytes(b"data")
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "bad.png").write_bytes(_mock_png(b"bad"))
            (workspace / "good.png").write_bytes(_mock_png(b"good"))

            with patch(
                "dayi.tools.ocr_scanner._load_ocr_dependencies",
                return_value=dependencies,
            ), patch(
                "dayi.tools.ocr_scanner.shutil.which",
                return_value="/controlled/tesseract",
            ), patch(
                "dayi.tools.ocr_scanner._probe_ocr_languages",
                return_value=("eng",),
            ):
                result = asyncio.run(
                    run_ocr_scanner(
                        target,
                        workspace,
                        re.compile(r"FLAG\{.*?\}"),
                    )
                )

        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.flags_found, ["FLAG{ocr_partial_success}"])
        self.assertIn("bad.png: RuntimeError", result.stderr)


if __name__ == "__main__":
    unittest.main()
