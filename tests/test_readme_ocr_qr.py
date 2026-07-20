import re
import unittest
from pathlib import Path

from dayi.plugin_inspector import inspect_plugins


class OCRQRDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = Path("README.md").read_text(encoding="utf-8")
        cls.changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    def test_ocr_cli_and_limits_are_documented(self) -> None:
        for value in ("--ocr-lang", "--ocr-exhaustive", "200 OCR"):
            self.assertIn(value, self.readme)
        self.assertRegex(self.readme, re.compile(r"15\s+seconds"))
        self.assertIn("OCR remains heuristic", self.readme)
        self.assertIn("OCR heuristic bir analizdir", self.readme)

    def test_qr_backends_passive_policy_and_plugin_count_are_documented(self) -> None:
        for value in ("OpenCV", "pyzbar", "zbarimg", "22 plugins", "22 eklenti"):
            self.assertIn(value, self.readme)
        self.assertRegex(self.readme, re.compile(r"never opened.*executed", re.I | re.S))
        self.assertIn("qr_scanner", self.changelog)

    def test_documented_plugin_counts_match_the_registry(self) -> None:
        report = inspect_plugins()
        concurrent_count = sum(
            plugin.phase == "CONCURRENT" for plugin in report.plugins
        )

        self.assertEqual(report.plugin_count, 22)
        self.assertEqual(concurrent_count, 12)
        self.assertIn(
            f"runs the {concurrent_count} `CONCURRENT`-phase plugin operations "
            f"together within the {report.plugin_count}-plugin registered pipeline",
            self.readme,
        )
        self.assertIn(
            f"toplam {report.plugin_count} kayıtlı eklentili pipeline'ın "
            f"`CONCURRENT` aşamasındaki {concurrent_count} eklenti işlemini",
            self.readme,
        )

    def test_release_candidate_status_and_version_are_current(self) -> None:
        self.assertIn("## [4.5.0] - 2026-07-20", self.changelog)
        self.assertIn("Tagging and publication remain", self.changelog)
        self.assertEqual(
            Path("dayi/__init__.py").read_text(encoding="utf-8").count('4.5.0'),
            1,
        )


if __name__ == "__main__":
    unittest.main()
