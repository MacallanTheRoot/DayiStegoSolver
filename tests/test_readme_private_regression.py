import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PrivateRegressionDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_english_and_turkish_privacy_guidance_is_present(self) -> None:
        self.assertIn("Local private regression", self.readme)
        self.assertIn("Yerel özel regresyon", self.readme)
        self.assertIn("DAYI_PRIVATE_CORPUS", self.readme)
        self.assertIn("--anonymize", self.readme)
        self.assertIn("--redact-flags", self.readme)
        self.assertIn("--show-flags", self.readme)
        self.assertIn("outside this repository", self.readme)
        self.assertIn("repository'nin dışında", self.readme)

    def test_harness_limit_and_error_guidance_is_documented(self) -> None:
        self.assertIn("--timeout 180 --max-files 500", self.readme)
        self.assertIn("timeouts, parser failures, unsupported inputs, and missing tools", self.readme)
        self.assertIn("timeout, parser hatası", self.readme)
        self.assertIn("synthetic tests are required", self.readme)
        self.assertIn("sentetik testlerle", self.readme)

    def test_release_candidate_changelog_describes_only_generic_behavior(self) -> None:
        release = self.changelog.split("## [4.5.0]", 1)[1].split("## [4.1.0]", 1)[0]
        self.assertIn("local-only private regression harness", release)
        self.assertIn("archive priority 12", release)
        self.assertIn("preserved plugin error/extraction state", release)
        self.assertIn("Tagging and publication remain", release)


if __name__ == "__main__":
    unittest.main()
