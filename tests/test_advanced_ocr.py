import asyncio
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dayi import cli
from dayi.image_analysis import (
    MAX_SOURCE_IMAGES,
    OCRFinding,
    OCRVariant,
    detect_image_magic_bytes,
    discover_images,
)
from dayi.reporter import ScanReport, ToolResult, write_json_report
from dayi.tools.ocr_scanner import OCRDependencies, run_ocr_scanner


class _Image:
    size = (80, 40)
    n_frames = 1

    def __init__(self, path: Path) -> None:
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def load(self) -> None:
        return None


class _Images:
    @staticmethod
    def open(path: Path) -> _Image:
        return _Image(Path(path))


class _StructuredTesseract:
    class Output:
        DICT = "dict"

    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0

    @staticmethod
    def get_tesseract_version() -> str:
        return "5-test"

    @staticmethod
    def get_languages(config: str = "") -> list[str]:
        return ["eng", "tur"]

    def image_to_data(self, _image, **_kwargs):
        self.calls += 1
        return {
            "text": [self.text],
            "conf": ["88"],
            "left": [1], "top": [2], "width": [3], "height": [4],
        }


class _SparseBandTesseract(_StructuredTesseract):
    """Expose the synthetic flag only to the bounded wide-band OCR pass."""

    def __init__(self) -> None:
        super().__init__("")

    def image_to_string(self, _image, **_kwargs):
        return ""

    def image_to_data(self, image, **kwargs):
        self.calls += 1
        if (
            image.size[0] < 4000
            or image.size[1] >= 500
            or "--psm 11" not in kwargs.get("config", "")
        ):
            return {"text": [], "conf": [], "left": [], "top": [],
                    "width": [], "height": []}
        # Sparse OCR engines can return a slanted line in vertical rather than
        # horizontal order. The runtime sorts this one-line crop by x.
        return {
            "text": ["_gordun}", "ae", "nasil", "siberV", "atan{ben!."],
            "conf": ["81", "20", "78", "75", "72"],
            "left": [2300, 400, 2000, 1100, 1450],
            "top": [80, 200, 110, 190, 150],
            "width": [500, 100, 300, 320, 500],
            "height": [50, 30, 40, 45, 50],
        }


def _png(marker: bytes = b"") -> bytes:
    return b"\x89PNG\r\n\x1a\n" + marker


class ImageDiscoveryTests(unittest.TestCase):
    def test_supported_magic_is_content_based(self) -> None:
        samples = {
            b"\x89PNG\r\n\x1a\n": "PNG",
            b"\xff\xd8\xff": "JPEG",
            b"BM": "BMP",
            b"GIF89a": "GIF",
            b"II*\x00": "TIFF",
            b"RIFFxxxxWEBP": "WEBP",
            b"P6\n": "PNM",
        }
        for data, expected in samples.items():
            with self.subTest(expected=expected):
                self.assertEqual(detect_image_magic_bytes(data), expected)
        self.assertIsNone(detect_image_magic_bytes(b"not an image"))

    def test_discovery_deduplicates_and_caps_images(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(_png(b"same"))
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "duplicate.dat").write_bytes(target.read_bytes())
            for index in range(MAX_SOURCE_IMAGES + 5):
                (workspace / f"{index}.dat").write_bytes(_png(str(index).encode()))
            images = discover_images(target, workspace)
        self.assertEqual(len(images), MAX_SOURCE_IMAGES)
        self.assertEqual(len({item.sha256 for item in images}), len(images))


class AdvancedOCRTests(unittest.TestCase):
    def _run(
        self,
        text: str,
        pattern: str = r"SiberVatan\{.*?\}",
        *,
        exhaustive: bool = False,
    ):
        engine = _StructuredTesseract(text)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "image.anything"
            target.write_bytes(_png(b"fixture"))
            with (
                patch(
                    "dayi.tools.ocr_scanner._load_ocr_dependencies",
                    return_value=OCRDependencies(_Images, engine),
                ),
                patch(
                    "dayi.tools.ocr_scanner.shutil.which",
                    return_value="/controlled/tesseract",
                ),
                patch(
                    "dayi.tools.ocr_scanner._probe_ocr_languages",
                    return_value=("eng", "tur"),
                ),
            ):
                result = asyncio.run(
                    run_ocr_scanner(
                        target,
                        root / "workspace",
                        re.compile(pattern),
                        exhaustive=exhaustive,
                    )
                )
        return result, engine

    def test_structured_results_deduplicate_variant_consensus(self) -> None:
        result, engine = self._run("SiberVatan{structured_ocr}", exhaustive=True)
        self.assertEqual(result.flags_found, ["SiberVatan{structured_ocr}"])
        self.assertEqual(len(result.ocr_findings), 1)
        self.assertEqual(result.ocr_findings[0].repeated_count, 3)
        self.assertEqual(result.ocr_findings[0].mean_word_confidence, 88.0)
        self.assertLessEqual(engine.calls, 30)

    def test_ocr_text_enters_nested_decoder(self) -> None:
        result, _engine = self._run("U2liZXJWYXRhbntvY3JfYmFzZTY0fQ==")
        self.assertIn("SiberVatan{ocr_base64}", result.flags_found)
        finding = next(item for item in result.ocr_findings if item.flags_found)
        self.assertIn("base64", finding.decoder_chain)

    def test_confusion_repair_is_limited_to_flag_like_context(self) -> None:
        result, _engine = self._run("SiberVatan[ocr_repair]")
        self.assertIn("SiberVatan{ocr_repair}", result.flags_found)
        finding = next(item for item in result.ocr_findings if item.flags_found)
        self.assertEqual(finding.decoder_chain, ("ocr-repair",))

    def test_controls_are_escaped_and_language_is_validated(self) -> None:
        result, _engine = self._run("hint\x1b[31m\u202e")
        rendered = "\n".join(item.sanitized_text for item in result.ocr_findings)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn("U+202E", rendered)
        with self.assertRaises(SystemExit):
            cli.parse_cli_args(["scan", "x.png", "--ocr-lang", "eng --psm 6"])
        args = cli.parse_cli_args(["scan", "x.png", "--ocr-lang", "eng+tur", "--ocr-exhaustive"])
        self.assertEqual(args.ocr_lang, "eng+tur")
        self.assertTrue(args.ocr_exhaustive)

    def test_missing_requested_language_is_an_actionable_skip(self) -> None:
        engine = _StructuredTesseract("text")
        engine.get_languages = lambda config="": ["eng"]
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "image"
            target.write_bytes(_png())
            with (
                patch("dayi.tools.ocr_scanner._load_ocr_dependencies", return_value=OCRDependencies(_Images, engine)),
                patch("dayi.tools.ocr_scanner.shutil.which", return_value="/controlled/tesseract"),
                patch("dayi.tools.ocr_scanner._probe_ocr_languages", return_value=("eng",)),
            ):
                result = asyncio.run(run_ocr_scanner(target, root / "w", re.compile("x"), language="tur"))
        self.assertTrue(result.skipped)
        self.assertIn("tur", result.skip_reason)

    @unittest.skipUnless(__import__("importlib").util.find_spec("PIL"), "Pillow unavailable")
    def test_real_preprocessing_schedule_respects_invocation_cap(self) -> None:
        from PIL import Image
        from dayi.tools.ocr_scanner import _load_ocr_dependencies

        engine = _StructuredTesseract("ordinary prose without a flag")
        dependencies = _load_ocr_dependencies()
        self.assertIsNotNone(dependencies)
        dependencies = OCRDependencies(
            dependencies.image_module,
            engine,
            dependencies.image_ops,
            dependencies.image_enhance,
            dependencies.image_filter,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "animated.bin"
            frames = [Image.new("RGB", (40, 20), (index, 0, 0)) for index in range(8)]
            frames[0].save(target, format="GIF", save_all=True, append_images=frames[1:])
            with (
                patch("dayi.tools.ocr_scanner._load_ocr_dependencies", return_value=dependencies),
                patch("dayi.tools.ocr_scanner.shutil.which", return_value="/controlled/tesseract"),
                patch("dayi.tools.ocr_scanner._probe_ocr_languages", return_value=("eng",)),
            ):
                result = asyncio.run(run_ocr_scanner(
                    target, root / "workspace", re.compile(r"SiberVatan\{.*?\}"), exhaustive=True
                ))
        self.assertLessEqual(engine.calls, 30)
        self.assertIn("/200", result.stdout)

    @unittest.skipUnless(__import__("importlib").util.find_spec("PIL"), "Pillow unavailable")
    def test_large_scene_uses_bounded_band_and_repairs_sparse_ocr(self) -> None:
        from PIL import Image
        from dayi.tools.ocr_scanner import _load_ocr_dependencies

        engine = _SparseBandTesseract()
        loaded = _load_ocr_dependencies()
        self.assertIsNotNone(loaded)
        dependencies = OCRDependencies(
            loaded.image_module,
            engine,
            loaded.image_ops,
            loaded.image_enhance,
            loaded.image_filter,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "large-scene.png"
            Image.new("RGB", (1200, 1200), "black").save(target)
            with (
                patch("dayi.tools.ocr_scanner._load_ocr_dependencies", return_value=dependencies),
                patch("dayi.tools.ocr_scanner.shutil.which", return_value="/controlled/tesseract"),
                patch("dayi.tools.ocr_scanner._probe_ocr_languages", return_value=("eng",)),
            ):
                result = asyncio.run(run_ocr_scanner(
                    target,
                    root / "workspace",
                    re.compile(r"SiberVatan\{.*?\}"),
                ))

        self.assertEqual(result.flags_found, ["SiberVatan{beni_nasil_gordun}"])
        finding = next(item for item in result.ocr_findings if item.flags_found)
        self.assertIn("scale-lower-center-band-10x", finding.variant.name)
        self.assertEqual(finding.decoder_chain, ("ocr-repair",))
        self.assertLessEqual(engine.calls, 30)

    def test_json_finding_is_bounded_and_primitive_only(self) -> None:
        finding = OCRFinding(
            text="flag", sanitized_text="flag", confidence="high",
            mean_word_confidence=90.0, source="target:image",
            variant=OCRVariant("original-psm6"), bounding_boxes=((1, 2, 3, 4),),
        )
        result = ToolResult("ocr_scanner", [], 0, "", "", [], 0.1, ocr_findings=[finding])
        report = ScanReport("image", "x", None, "a", "b", [], [result])
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            write_json_report(report, output)
            payload = json.loads(output.read_text())
        self.assertEqual(payload["tool_results"][0]["ocr_findings"][0]["variant"]["psm"], 6)

    def test_oversized_dimensions_fail_before_tesseract(self) -> None:
        class HugeImage(_Image):
            size = (20_001, 1)

        class HugeImages:
            @staticmethod
            def open(path: Path) -> HugeImage:
                return HugeImage(Path(path))

        engine = _StructuredTesseract("SiberVatan{must_not_run}")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "huge"
            target.write_bytes(_png())
            with (
                patch("dayi.tools.ocr_scanner._load_ocr_dependencies", return_value=OCRDependencies(HugeImages, engine)),
                patch("dayi.tools.ocr_scanner.shutil.which", return_value="/controlled/tesseract"),
                patch("dayi.tools.ocr_scanner._probe_ocr_languages", return_value=("eng",)),
            ):
                result = asyncio.run(run_ocr_scanner(target, root / "w", re.compile("must_not_run")))
        self.assertEqual(result.return_code, 1)
        self.assertEqual(engine.calls, 0)
        self.assertNotIn("20_001", result.stderr)


if __name__ == "__main__":
    unittest.main()
