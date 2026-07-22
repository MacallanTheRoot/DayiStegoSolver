import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _semantic_text(value: str) -> str:
    value = re.sub(r"[*`_]", "", value.casefold())
    value = re.sub(r"[-/]+", " ", value)
    return " ".join(value.split())


class DocumentStegoDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.semantic = _semantic_text(cls.readme)
        cls.changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_english_and_turkish_document_scope_is_explicit(self) -> None:
        self.assertIn("`document_stego_scanner`", self.readme)
        for document_type in ("XLSX/XLSM", "PPTX/PPTM", "ODT/ODS/ODP", "RTF"):
            self.assertIn(document_type, self.readme)
        for concept in ("document analysis", "belge analizi", "format corpus dependent"):
            self.assertIn(concept, self.semantic)
        self.assertRegex(self.semantic, r"do(?:es)? not claim complete")
        self.assertIn("uyumluluğu iddia etmez", self.semantic)

    def test_mechanisms_and_local_only_behavior_are_documented(self) -> None:
        for term in (
            "hidden styles", "comments", "revisions", "headers footers",
            "alt text", "embedded objects", "external relationships are reported only",
            "never run or fetched",
        ):
            self.assertIn(term, self.semantic)
        for term in ("harici ilişkiler yalnızca raporlanır", "makrolar", "çalıştırılmaz"):
            self.assertIn(term, self.semantic)

    def test_openxml_bounds_are_documented(self) -> None:
        for term in (
            "128 MiB", "5,000", "32 MiB", "256 MiB", "16 MiB",
        ):
            self.assertIn(term, self.readme)
        for bound in ("media at 100", "embedded objects at 50", "depth 3"):
            self.assertIn(bound, self.semantic)

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
