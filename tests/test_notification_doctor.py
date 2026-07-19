import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dayi import doctor, integrations
from dayi.doctor import (
    DOCTOR_SCHEMA_VERSION,
    CoreDiagnostic,
    build_doctor_report,
    diagnose_native_notification_capability,
    doctor_exit_code,
    render_json,
    render_plain,
)
from dayi.integrations import inspect_native_notification_configuration


def _core() -> CoreDiagnostic:
    return CoreDiagnostic(
        status="healthy",
        dayi_version="4.0.0",
        python_implementation="CPython",
        python_version="3.10.0",
        python_supported=True,
        minimum_python="3.10",
        platform="TestOS",
        architecture="test-arch",
        python_executable="python",
        package_path=None,
        cli_operational=True,
    )


def _usable_aiohttp():
    return SimpleNamespace(ClientSession=lambda: None, ClientTimeout=lambda: None)


class DoctorNotificationTransportTests(unittest.TestCase):
    def test_usable_aiohttp_is_reported_as_preferred_transport(self) -> None:
        with patch(
            "dayi.integrations.importlib.import_module",
            return_value=_usable_aiohttp(),
        ):
            capability = diagnose_native_notification_capability()

        self.assertTrue(capability.available)
        self.assertEqual(capability.metadata_status, "ok")
        self.assertEqual(capability.location_status, "aiohttp")
        self.assertIn("native notifications available via aiohttp", capability.capability)

    def test_missing_aiohttp_reports_available_urllib_fallback(self) -> None:
        with patch(
            "dayi.integrations.importlib.import_module",
            side_effect=ImportError("missing"),
        ):
            capability = diagnose_native_notification_capability()

        self.assertTrue(capability.available)
        self.assertEqual(capability.location_status, "urllib-fallback")
        self.assertIn("available via urllib fallback", capability.capability)

    def test_malformed_aiohttp_api_uses_urllib_fallback(self) -> None:
        malformed_modules = (
            SimpleNamespace(ClientTimeout=lambda: None),
            SimpleNamespace(ClientSession=lambda: None),
            SimpleNamespace(ClientSession=None, ClientTimeout=lambda: None),
        )
        for module in malformed_modules:
            with self.subTest(module=module), patch(
                "dayi.integrations.importlib.import_module", return_value=module
            ):
                capability = diagnose_native_notification_capability()
            self.assertEqual(capability.location_status, "urllib-fallback")

    def test_ctfshit_notification_modules_are_never_imported(self) -> None:
        imported: list[str] = []

        def import_module(name: str):
            imported.append(name)
            if name == "aiohttp":
                return _usable_aiohttp()
            raise AssertionError(f"unexpected import: {name}")

        with patch(
            "dayi.integrations.importlib.import_module", side_effect=import_module
        ):
            diagnose_native_notification_capability()

        self.assertEqual(imported, ["aiohttp"])
        self.assertFalse(any("ctfshit" in name for name in imported))

    def test_notification_diagnostic_performs_no_network_or_delivery(self) -> None:
        native_definition = next(
            definition
            for definition in doctor.PYTHON_CAPABILITY_DEFINITIONS
            if definition.capability_id == "native_notifications"
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(integrations.urllib.request, "urlopen") as urlopen,
            patch.object(integrations, "_urllib_post_json") as urllib_post,
            patch.object(integrations, "IntegrationManager") as manager,
            patch.object(doctor, "EXTERNAL_TOOL_DEFINITIONS", ()),
            patch.object(
                doctor, "PYTHON_CAPABILITY_DEFINITIONS", (native_definition,)
            ),
            patch(
                "dayi.integrations.importlib.import_module",
                side_effect=ImportError("missing"),
            ),
        ):
            report = doctor.run_diagnostics()

        self.assertEqual(
            report.python_capabilities[0].capability_id,
            "native_notifications",
        )
        urlopen.assert_not_called()
        urllib_post.assert_not_called()
        manager.assert_not_called()


class DoctorNotificationConfigurationTests(unittest.TestCase):
    def _inspect(self, environment: dict[str, str]):
        with patch("dayi.integrations._resolve_aiohttp", return_value=None):
            return inspect_native_notification_configuration(environment)

    def test_no_environment_is_not_configured(self) -> None:
        result = self._inspect({})
        self.assertEqual(result.ctfd_status, "not-configured")
        self.assertEqual(result.discord_status, "not-configured")

    def test_complete_valid_ctfd_environment_is_configured(self) -> None:
        result = self._inspect({
            "DAYI_CTFD_URL": "https://ctf.example.com",
            "DAYI_CTFD_TOKEN": "secret-token",
            "DAYI_CTFD_CHALLENGE_ID": "42",
        })
        self.assertEqual(result.ctfd_status, "configured")

    def test_incomplete_ctfd_environment_is_distinct(self) -> None:
        for environment in (
            {"DAYI_CTFD_URL": "https://ctf.example.com"},
            {"DAYI_CTFD_TOKEN": "secret-token"},
            {"DAYI_CTFD_CHALLENGE_ID": "42"},
        ):
            with self.subTest(environment=tuple(environment)):
                self.assertEqual(self._inspect(environment).ctfd_status, "incomplete")

    def test_invalid_ctfd_url_is_invalid(self) -> None:
        result = self._inspect({
            "DAYI_CTFD_URL": "https://user:password@ctf.example.com/path?secret=yes",
            "DAYI_CTFD_TOKEN": "secret-token",
            "DAYI_CTFD_CHALLENGE_ID": "42",
        })
        self.assertEqual(result.ctfd_status, "invalid")

    def test_invalid_or_nonpositive_challenge_id_is_invalid(self) -> None:
        for challenge_id in ("not-an-integer", "0", "-1"):
            with self.subTest(challenge_id=challenge_id):
                result = self._inspect({
                    "DAYI_CTFD_URL": "https://ctf.example.com",
                    "DAYI_CTFD_TOKEN": "secret-token",
                    "DAYI_CTFD_CHALLENGE_ID": challenge_id,
                })
                self.assertEqual(result.ctfd_status, "invalid")

    def test_valid_discord_environment_is_configured(self) -> None:
        result = self._inspect({
            "DAYI_DISCORD_WEBHOOK_URL": (
                "https://discord.example.invalid/webhook-placeholder"
            )
        })
        self.assertEqual(result.discord_status, "configured")

    def test_http_discord_environment_is_invalid(self) -> None:
        result = self._inspect({
            "DAYI_DISCORD_WEBHOOK_URL": "http://discord.example.invalid/secret-path"
        })
        self.assertEqual(result.discord_status, "invalid")

    def test_ctfd_and_discord_states_are_independent(self) -> None:
        result = self._inspect({
            "DAYI_CTFD_URL": "https://ctf.example.com",
            "DAYI_CTFD_TOKEN": "secret-token",
            "DAYI_CTFD_CHALLENGE_ID": "42",
            "DAYI_DISCORD_WEBHOOK_URL": "http://discord.example.invalid/secret-path",
        })
        self.assertEqual(result.ctfd_status, "configured")
        self.assertEqual(result.discord_status, "invalid")

    def test_whitespace_environment_values_are_unset(self) -> None:
        result = self._inspect({
            "DAYI_CTFD_URL": " ",
            "DAYI_CTFD_TOKEN": "\t",
            "DAYI_CTFD_CHALLENGE_ID": "\n",
            "DAYI_DISCORD_WEBHOOK_URL": "   ",
        })
        self.assertEqual(result.ctfd_status, "not-configured")
        self.assertEqual(result.discord_status, "not-configured")


class DoctorNotificationPrivacyAndSchemaTests(unittest.TestCase):
    def _render_secret_environment(self) -> tuple[str, str, dict]:
        environment = {
            "DAYI_CTFD_URL": "https://ctf.example.com/private-base-path",
            "DAYI_CTFD_TOKEN": "private-token-value",
            "DAYI_CTFD_CHALLENGE_ID": "42",
            "DAYI_DISCORD_WEBHOOK_URL": (
                "https://discord.example.invalid/private-webhook-path"
            ),
            "DAYI_CHALLENGE_NAME": "private-challenge-name",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "dayi.integrations._resolve_aiohttp", return_value=None
        ):
            capability = diagnose_native_notification_capability()
        report = build_doctor_report(_core(), [], [capability])
        plain = render_plain(report)
        encoded = render_json(report)
        return plain, encoded, json.loads(encoded)

    def test_plain_and_json_exclude_all_environment_values(self) -> None:
        plain, encoded, _payload = self._render_secret_environment()
        for secret in (
            "https://ctf.example.com/private-base-path",
            "private-base-path",
            "private-token-value",
            "https://discord.example.invalid/private-webhook-path",
            "private-webhook-path",
            "private-challenge-name",
        ):
            self.assertNotIn(secret, plain)
            self.assertNotIn(secret, encoded)

    def test_schema_shape_and_json_types_remain_compatible(self) -> None:
        _plain, _encoded, payload = self._render_secret_environment()
        self.assertEqual(payload["schema_version"], DOCTOR_SCHEMA_VERSION)
        self.assertEqual(
            set(payload),
            {
                "schema_version",
                "overall_status",
                "core_usable",
                "core",
                "external_tools",
                "python_capabilities",
            },
        )
        notification = payload["python_capabilities"][0]
        self.assertIsNone(notification["location"])
        self.assertFalse(any(isinstance(value, Path) for value in notification.values()))
        json.dumps(payload)

    def test_missing_configuration_and_aiohttp_do_not_fail_core_health(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch(
            "dayi.integrations._resolve_aiohttp", return_value=None
        ):
            capability = diagnose_native_notification_capability()
        report = build_doctor_report(_core(), [], [capability])
        self.assertTrue(capability.available)
        self.assertEqual(report.overall_status, "healthy")
        self.assertTrue(report.core_usable)
        self.assertEqual(doctor_exit_code(report), 0)

    def test_ctfshit_writeup_and_notifications_are_separate_capabilities(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch(
            "dayi.integrations._resolve_aiohttp", return_value=None
        ), patch(
            "dayi.doctor.resolve_writeup_exporter",
            return_value=SimpleNamespace(
                available=False,
                source_kind="unavailable",
                status_code="not-found",
                safe_detail="ctfshit writeup exporter was not found",
            ),
        ):
            notification = diagnose_native_notification_capability()
            writeup = doctor.diagnose_ctfshit_capability()

        self.assertEqual(notification.capability_id, "native_notifications")
        self.assertNotIn("ctfshit", notification.capability)
        self.assertEqual(writeup.capability_id, "ctfshit")
        self.assertIn("built-in Markdown fallback active", writeup.capability)
        self.assertNotIn("notification", writeup.capability.lower())


if __name__ == "__main__":
    unittest.main()
