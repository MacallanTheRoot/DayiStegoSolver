import re
import unittest
from pathlib import Path


README = Path(__file__).resolve().parents[1] / "README.md"


def _semantic_text(value: str) -> str:
    return " ".join(value.casefold().split())


class NotificationDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = README.read_text(encoding="utf-8")
        cls.lowered = cls.text.lower()
        cls.semantic = _semantic_text(cls.text)

    def test_obsolete_notification_architecture_is_absent(self) -> None:
        for obsolete in (
            "ctfshit → aiohttp → urllib",
            "ctfshit → aiohttp → stdlib urllib",
            "ctfshit.src",
            "ctfshit/src",
            "FlagSubmitter + send_flag_notification",
        ):
            self.assertNotIn(obsolete, self.text)

    def test_all_notification_and_writeup_environment_variables_are_documented(self) -> None:
        for variable in (
            "DAYI_CTFD_URL",
            "DAYI_CTFD_TOKEN",
            "DAYI_CTFD_CHALLENGE_ID",
            "DAYI_DISCORD_WEBHOOK_URL",
            "DAYI_CHALLENGE_NAME",
            "DAYI_CTFSHIT_PATH",
        ):
            self.assertIn(variable, self.text)

    def test_cli_options_and_field_precedence_are_documented(self) -> None:
        for option in (
            "--webhook",
            "--ctfd-url",
            "--ctfd-token",
            "--challenge-id",
            "--challenge-name",
            "--ctfshit-path",
        ):
            self.assertIn(option, self.text)
        self.assertRegex(
            self.semantic,
            r"explicit cli value.{0,40}nonblank environment value.{0,80}(?:default|disabled)",
        )

    def test_secret_exposure_warning_and_safe_placeholders_are_documented(self) -> None:
        self.assertIn("process listings", self.text)
        self.assertIn("shell history", self.text)
        self.assertIn("terminal logs", self.text)
        self.assertIn("screenshots", self.semantic)
        self.assertIn("committed files", self.semantic)
        self.assertIn("TOKEN_REDACTED", self.text)
        self.assertIn("https://ctfd.example", self.text)
        self.assertIn("https://discord.example/webhook", self.text)
        for unsafe_example in (
            "YOUR_TOKEN",
            "https://discord.com/api/webhooks/",
            "--ctfd-token TOKEN",
        ):
            self.assertNotIn(unsafe_example, self.text)

    def test_native_transport_and_independent_failure_behavior_are_documented(self) -> None:
        for concept in (
            "selects usable aiohttp", "stdlib urllib", "fixed for the scan",
            "ctfd and discord are dispatched independently",
            "never invalidates a completed scan",
        ):
            self.assertIn(concept, self.semantic)

    def test_ctfshit_is_documented_as_writeup_only_with_fallback(self) -> None:
        for concept in (
            "used only for rich markdown writeups",
            "discord and ctfd do not depend on it",
            "built-in markdown is the writeup fallback",
        ):
            self.assertIn(concept, self.semantic)

    def test_network_security_and_doctor_limitations_are_documented(self) -> None:
        for concept in (
            "discord webhook urls require https",
            "ctfd http remains accepted for backward",
            "url userinfo, query strings, and fragments are rejected",
            "redirects are blocked", "requests use bounded timeouts",
            "does not test endpoints, credentials, or reachability",
            "not added to txt, json, or markdown reports",
        ):
            self.assertIn(concept, self.semantic)

    def test_required_usage_examples_are_present_without_real_secret_shapes(self) -> None:
        for example in (
            "export DAYI_CTFD_URL=https://ctfd.example",
            "export DAYI_CTFD_TOKEN=TOKEN_REDACTED",
            "export DAYI_DISCORD_WEBHOOK_URL=https://discord.example/webhook",
            "dayi scan challenge.jpg --challenge-id 43",
            "dayi scan challenge.jpg --writeup writeup.md",
            "dayi doctor --json",
        ):
            self.assertIn(example, self.text)
        self.assertIsNone(
            re.search(r"(?i)(?:token|webhook)[=:][A-Za-z0-9_-]{24,}", self.text)
        )


if __name__ == "__main__":
    unittest.main()
