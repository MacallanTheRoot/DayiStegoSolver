import re
import unittest
from pathlib import Path


README = Path(__file__).resolve().parents[1] / "README.md"


class NotificationDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = README.read_text(encoding="utf-8")
        cls.lowered = cls.text.lower()

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
        self.assertIn(
            "explicit CLI value, then nonblank\nenvironment value",
            self.text,
        )

    def test_secret_exposure_warning_and_safe_placeholders_are_documented(self) -> None:
        self.assertIn("process listings", self.text)
        self.assertIn("shell history", self.text)
        self.assertIn("terminal logs", self.text)
        self.assertIn("REDACTED_TOKEN", self.text)
        self.assertIn(
            "https://discord.example.invalid/webhook-placeholder",
            self.text,
        )
        for unsafe_example in (
            "YOUR_TOKEN",
            "https://discord.com/api/webhooks/",
            "--ctfd-token TOKEN",
        ):
            self.assertNotIn(unsafe_example, self.text)

    def test_native_transport_and_independent_failure_behavior_are_documented(self) -> None:
        self.assertIn("selects usable aiohttp", self.text)
        self.assertIn("stdlib urllib", self.text)
        self.assertIn("selection is fixed for the scan", self.text)
        self.assertIn("CTFd and Discord are dispatched independently", self.text)
        self.assertIn("never invalidates a\ncompleted scan", self.text)

    def test_ctfshit_is_documented_as_writeup_only_with_fallback(self) -> None:
        self.assertIn("used only for\nrich Markdown writeups", self.text)
        self.assertIn("Discord and CTFd do not depend on it", self.text)
        self.assertIn("built-in Markdown", self.text)

    def test_network_security_and_doctor_limitations_are_documented(self) -> None:
        for statement in (
            "Discord webhook URLs require HTTPS",
            "CTFd HTTP remains accepted for backward",
            "URL userinfo, query strings, and\nfragments are rejected",
            "redirects are blocked",
            "requests use bounded timeouts",
            "does not test endpoints, credentials, or reachability",
            "not added to TXT, JSON, or Markdown reports",
        ):
            self.assertIn(statement, self.text)

    def test_required_usage_examples_are_present_without_real_secret_shapes(self) -> None:
        for label in (
            "CTFd from environment only",
            "Discord from environment only",
            "Both channels together",
            "One CLI value overrides",
            "Rich writeup exporter",
            "Network-free diagnostics",
        ):
            self.assertIn(label, self.text)
        self.assertIsNone(
            re.search(r"(?i)(?:token|webhook)[=:][A-Za-z0-9_-]{24,}", self.text)
        )


if __name__ == "__main__":
    unittest.main()
