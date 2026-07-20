import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DocumentStegoDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_english_and_turkish_document_scope_is_explicit(self) -> None:
        self.assertIn("**Bounded document steganography**", self.readme)
        self.assertIn("**Sınırlandırılmış belge steganografisi**", self.readme)
        self.assertIn("`document_stego_scanner`", self.readme)
        self.assertIn("22 plugins", self.readme)
        self.assertIn("22 eklenti", self.readme)
        for document_type in ("XLSX/XLSM", "PPTX/PPTM", "ODT/ODS/ODP", "RTF"):
            self.assertIn(document_type, self.readme)
        self.assertIn("does not claim complete", self.readme)
        self.assertIn("uyumluluğu iddia etmez", self.readme)

    def test_mechanisms_and_local_only_behavior_are_documented(self) -> None:
        for term in (
            "hidden styles", "comments", "revisions", "headers/footers",
            "alt text", "embedded objects", "never run",
        ):
            self.assertIn(term, self.readme)
        self.assertIn("Harici ilişkiler yalnızca raporlanır", self.readme)
        self.assertIn("makrolar", self.readme)
        self.assertIn("çalıştırılmaz", self.readme)

    def test_openxml_bounds_are_documented(self) -> None:
        for term in (
            "128 MiB", "5,000", "32 MiB", "256 MiB", "16 MiB",
            "media at 100", "embedded objects at 50", "depth at 3",
        ):
            self.assertIn(term, self.readme)

    def test_release_candidate_changelog_describes_core_without_publication_claim(self) -> None:
        release = self.changelog.split("## [4.5.0]", 1)[1].split("## [4.1.0]", 1)[0]
        self.assertIn("document_stego_scanner", release)
        self.assertIn("XLSX/XLSM", release)
        self.assertIn("PPTX/PPTM", release)
        self.assertIn("ODT/ODS/ODP", release)
        self.assertIn("bounded RTF", release)
        self.assertIn("External relationships and macros", release)
        self.assertIn("Tagging and publication remain", release)


if __name__ == "__main__":
    unittest.main()
