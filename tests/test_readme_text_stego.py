import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TextStegoDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_english_and_turkish_sections_describe_core_plugin(self) -> None:
        self.assertIn("**Bounded text steganography**", self.readme)
        self.assertIn("**Sınırlandırılmış metin steganografisi**", self.readme)
        self.assertIn("`text_stego_scanner`", self.readme)
        self.assertIn("22 plugins", self.readme)
        self.assertIn("22 eklenti", self.readme)

    def test_usage_and_decoder_classes_are_documented(self) -> None:
        self.assertIn("SiberVatan", self.readme)
        for term in (
            "Bacon", "whitespace", "zero-width Unicode", "homoglyph",
            "acrostic/structural", "ghost-text",
        ):
            self.assertIn(term, self.readme)

    def test_security_bounds_and_network_free_behavior_are_documented(self) -> None:
        for term in ("8 MiB", "4 million", "512 candidates", "64 KiB", "depth 3", "16 MiB"):
            self.assertIn(term, self.readme)
        self.assertIn("without network access", self.readme)
        self.assertIn("ANSI/bidi/control", self.readme)

    def test_changelog_keeps_feature_in_4_5_release_candidate(self) -> None:
        release = self.changelog.split("## [4.5.0]", 1)[1].split("## [4.1.0]", 1)[0]
        self.assertIn("Release candidate prepared", release)
        self.assertIn("text_stego_scanner", release)
        self.assertIn("Tagging and publication remain", release)


if __name__ == "__main__":
    unittest.main()
