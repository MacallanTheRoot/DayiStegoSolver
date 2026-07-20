import asyncio
import json
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from dayi.document.limits import MAX_FINDINGS
from dayi.document.openxml import _FindingCollector
from dayi.image_analysis import ImageSource, OCRFinding, OCRVariant
from dayi.reporter import _build_flag_attribution
from dayi.tools.ocr_scanner import OCRDependencies, run_ocr_scanner
from scripts.run_private_regression import HarnessConfig, ScanExecution, run_harness


def _empty_scan_report() -> dict[str, object]:
    return {
        "all_flags_found": [],
        "flag_attribution": {},
        "artifacts_found": [],
        "tool_results": [],
    }


class FinalReleaseBlockerTests(unittest.TestCase):
    def test_manifest_inside_corpus_is_not_scanned_as_a_challenge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            corpus.mkdir()
            challenge = corpus / "challenge.bin"
            challenge.write_bytes(b"synthetic challenge")
            manifest = corpus / "expectations.json"
            manifest.write_text(
                json.dumps({"challenge.bin": {}}), encoding="utf-8"
            )
            scanned: list[Path] = []

            def executor(path, *_args):
                scanned.append(path)
                return ScanExecution(_empty_scan_report(), 0.01, 0)

            run_harness(
                HarnessConfig(
                    corpus,
                    root / "output",
                    manifest,
                    2.0,
                    10,
                    True,
                    False,
                ),
                scan_executor=executor,
            )

            self.assertEqual(scanned, [challenge])

    def test_confirmed_document_flag_displaces_low_finding_at_limit(self) -> None:
        collector = _FindingCollector(re.compile(r"FLAG\{[^}]+\}"))
        for index in range(MAX_FINDINGS):
            collector.add(
                "metadata",
                "ordinary",
                f"member-{index}",
                f"ordinary value {index}",
                "low",
            )

        collector.add(
            "hidden_text",
            "vanish",
            "word/document.xml",
            "FLAG{late_confirmed}",
            "confirmed",
        )

        findings = collector.finish()
        self.assertEqual(len(findings), MAX_FINDINGS)
        self.assertTrue(
            any("FLAG{late_confirmed}" in item.flags_found for item in findings)
        )
        self.assertIn("finding-count", collector.limits)

    def test_ocr_flag_beyond_display_cap_keeps_exact_attribution(self) -> None:
        flags = [f"FLAG{{ocr_{index}}}" for index in range(11)]
        findings = [
            OCRFinding(
                text=flag,
                sanitized_text=flag,
                confidence="confirmed",
                mean_word_confidence=90.0,
                source=f"image-{index:02d}.png",
                variant=OCRVariant(f"variant-{index:02d}", psm=6),
                flags_found=(flag,),
                decoder_chain=(f"decoder-{index}",),
                flag_decoder_chains=((flag, (f"decoder-{index}",)),),
            )
            for index, flag in enumerate(flags)
        ]

        class Engine:
            @staticmethod
            def get_tesseract_version() -> str:
                return "5.0"

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "synthetic.png"
            target.write_bytes(b"not decoded by this synthetic test")
            image = ImageSource(target, "target:synthetic.png", "PNG", 1, "a" * 64)
            dependencies = OCRDependencies(object(), Engine())
            with (
                patch(
                    "dayi.tools.ocr_scanner.discover_images",
                    return_value=(image,),
                ),
                patch(
                    "dayi.tools.ocr_scanner._load_ocr_dependencies",
                    return_value=dependencies,
                ),
                patch(
                    "dayi.tools.ocr_scanner._probe_ocr_languages",
                    return_value=("eng",),
                ),
                patch(
                    "dayi.tools.ocr_scanner._process_image_sync",
                    return_value=(findings, 1, 0, False),
                ),
            ):
                result = asyncio.run(
                    run_ocr_scanner(
                        target,
                        root / "workspace",
                        re.compile(r"FLAG\{[^}]+\}"),
                    )
                )

        self.assertEqual(len(result.ocr_findings), 10)
        attribution = _build_flag_attribution([result])
        self.assertEqual(
            attribution[flags[-1]],
            ["ocr:image-10.png:variant-10>decoder-10"],
        )

    def test_ocr_does_not_use_an_unkillable_version_probe_thread(self) -> None:
        class SlowEngine:
            called = False

            @classmethod
            def get_tesseract_version(cls) -> str:
                cls.called = True
                time.sleep(1.25)
                return "5.0"

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "synthetic.png"
            target.write_bytes(b"synthetic")
            image = ImageSource(target, "target:synthetic.png", "PNG", 1, "b" * 64)
            dependencies = OCRDependencies(object(), SlowEngine())
            started = time.monotonic()
            with (
                patch(
                    "dayi.tools.ocr_scanner.discover_images",
                    return_value=(image,),
                ),
                patch(
                    "dayi.tools.ocr_scanner._load_ocr_dependencies",
                    return_value=dependencies,
                ),
                patch("dayi.tools.ocr_scanner.shutil.which", return_value="/usr/bin/tesseract"),
                patch(
                    "dayi.tools.ocr_scanner._probe_ocr_languages",
                    return_value=("eng",),
                ),
                patch(
                    "dayi.tools.ocr_scanner._process_image_sync",
                    return_value=([], 0, 0, False),
                ),
            ):
                asyncio.run(
                    run_ocr_scanner(
                        target,
                        root / "workspace",
                        re.compile(r"FLAG\{[^}]+\}"),
                        timeout=1.0,
                    )
                )
            elapsed = time.monotonic() - started

        self.assertFalse(SlowEngine.called)
        self.assertLess(elapsed, 0.5)


if __name__ == "__main__":
    unittest.main()
