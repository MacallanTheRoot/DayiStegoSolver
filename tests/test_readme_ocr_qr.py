import re
import unittest
from pathlib import Path

from dayi.plugin_inspector import inspect_plugins


class OCRQRDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = Path("README.md").read_text(encoding="utf-8")
        cls.semantic = " ".join(cls.readme.casefold().split())
        cls.changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    def test_ocr_cli_and_limits_are_documented(self) -> None:
        for value in (
            "--ocr-lang", "--ocr-exhaustive", "20 source images", "20 variants",
            "30 invocations per image", "200 OCR invocations", "1 MiB", "8 MiB",
            "64 MiB", "50 million", "--timeout 60",
        ):
            self.assertIn(value, self.readme)
        self.assertRegex(self.readme, re.compile(r"15\s+seconds"))
        self.assertIn("ocr remains heuristic", self.semantic)
        self.assertIn("ocr heuristic bir analizdir", self.semantic)

    def test_qr_backends_passive_policy_and_plugin_count_are_documented(self) -> None:
        for value in ("OpenCV", "pyzbar", "zbarimg"):
            self.assertIn(value, self.readme)
        for behavior in ("never opened", "fetched", "executed"):
            self.assertIn(behavior, self.semantic)
        self.assertIn("qr_scanner", self.changelog)

    def test_documented_plugin_counts_match_the_registry(self) -> None:
        report = inspect_plugins()
        concurrent_count = sum(
            plugin.phase == "CONCURRENT" for plugin in report.plugins
        )

        self.assertEqual(report.plugin_count, 22)
        self.assertEqual(concurrent_count, 12)
        self.assertRegex(
            self.semantic,
            rf"\b{report.plugin_count}\s+registered plugins\b",
        )
        self.assertRegex(
            self.semantic,
            rf"\b{concurrent_count}\s+(?:concurrent phase operations|concurrent plugins)\b",
        )
        self.assertRegex(
            self.semantic,
            rf"\b{report.plugin_count}\s+kayıtlı plugin\b",
        )
        self.assertRegex(
            self.semantic,
            rf"\b{concurrent_count}\s+(?:concurrent aşama işlemi|concurrent plugin)\b",
        )

    def test_release_candidate_status_and_version_are_current(self) -> None:
        self.assertIn("## [4.5.1] - 2026-07-20", self.changelog)
        self.assertIn("Tagging and publication remain", self.changelog)
        self.assertEqual(
            Path("dayi/__init__.py").read_text(encoding="utf-8").count('4.5.1'),
            1,
        )


if __name__ == "__main__":
    unittest.main()
