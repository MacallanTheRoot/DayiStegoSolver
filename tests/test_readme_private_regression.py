import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _semantic_text(value: str) -> str:
    return " ".join(value.casefold().split())


class PrivateRegressionDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.semantic = _semantic_text(cls.readme)
        cls.changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_english_and_turkish_privacy_guidance_is_present(self) -> None:
        self.assertIn("DAYI_PRIVATE_CORPUS", self.readme)
        self.assertIn("--anonymize", self.readme)
        self.assertIn("--redact-flags", self.readme)
        self.assertIn("--show-flags", self.readme)
        for concept in (
            "private corpora", "outside this repository", "read-only and local",
            "never commit challenge samples or exact flags",
            "özel corpus", "repository'nin dışında", "read-only ve yerel",
        ):
            self.assertIn(concept, self.semantic)
        self.assertNotRegex(self.readme, re.compile(r"/home/[^\s`]+"))

    def test_harness_limit_and_error_guidance_is_documented(self) -> None:
        self.assertIn("--timeout 180 --max-files 500", self.readme)
        for concept in (
            "timeouts, parser failures, unsupported inputs, and missing tools",
            "synthetic tests are required", "no network access",
            "does not execute decoded payloads", "timeout, parser hatası",
            "sentetik", "decoded payload çalıştırılmaz",
        ):
            self.assertIn(concept, self.semantic)

    def test_release_candidate_changelog_describes_only_generic_behavior(self) -> None:
        release = self.changelog.split("## [4.5.0]", 1)[1].split("## [4.1.0]", 1)[0]
        self.assertIn("local-only private regression harness", release)
        self.assertIn("archive priority 12", release)
        self.assertIn("preserved plugin error/extraction state", release)
        self.assertIn("Tagging and publication remain", release)


if __name__ == "__main__":
    unittest.main()
