import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _semantic_text(value: str) -> str:
    value = re.sub(r"[-/]+", " ", value.casefold())
    value = re.sub(r"[*`_]", "", value)
    return " ".join(value.split())


class TextStegoDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.semantic = _semantic_text(cls.readme)
        cls.changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_english_and_turkish_sections_describe_core_plugin(self) -> None:
        self.assertIn("`text_stego_scanner`", self.readme)
        for concept in (
            "text steganography", "metin steganografisi", "plugin and decoder chain attribution",
        ):
            self.assertIn(concept, self.semantic)

    def test_usage_and_decoder_classes_are_documented(self) -> None:
        for term in (
            "bacon", "whitespace snow", "zero width unicode", "homoglyph",
            "acrostic structural", "ghost text", "letter case binary ascii",
        ):
            self.assertIn(term, self.semantic)

    def test_security_bounds_and_network_free_behavior_are_documented(self) -> None:
        for term in ("8 mib", "4 million", "512 candidates", "64 kib", "depth 3", "16 mib"):
            self.assertIn(term, self.semantic)
        self.assertIn("without network access", self.semantic)
        self.assertIn("ansi bidi control", self.semantic)

    def test_changelog_keeps_feature_in_4_5_release_candidate(self) -> None:
        release = self.changelog.split("## [4.5.0]", 1)[1].split("## [4.1.0]", 1)[0]
        self.assertIn("Release candidate prepared", release)
        self.assertIn("text_stego_scanner", release)
        self.assertIn("Tagging and publication remain", release)


if __name__ == "__main__":
    unittest.main()
