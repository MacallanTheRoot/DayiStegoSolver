import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from dayi import cli, doctor
from dayi.ctfshit_resolver import CtfshitResolution
from dayi.doctor import (
    DOCTOR_SCHEMA_VERSION,
    CoreDiagnostic,
    build_doctor_report,
    diagnose_ctfshit_capability,
    doctor_exit_code,
    render_json,
    render_plain,
)


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


def _resolution(
    *,
    available: bool,
    source_kind: str,
    status_code: str,
    exporter=None,
    safe_detail: str = "safe resolver detail",
) -> CtfshitResolution:
    return CtfshitResolution(
        available=available,
        source_kind=source_kind,
        status_code=status_code,
        exporter=exporter,
        safe_detail=safe_detail,
        resolved_root=Path("/internal/not-for-output"),
    )


def _report_for(capability):
    return build_doctor_report(_core(), [], [capability])


class DoctorCtfshitParserTests(unittest.TestCase):
    def test_doctor_help_includes_ctfshit_path(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            cli.parse_cli_args(["doctor", "--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("--ctfshit-path PATH", output.getvalue())

    def test_doctor_plain_and_json_forms_parse_ctfshit_path(self) -> None:
        plain = cli.parse_cli_args(["doctor", "--ctfshit-path", "checkout"])
        machine = cli.parse_cli_args(
            ["doctor", "--json", "--ctfshit-path", "checkout"]
        )

        self.assertEqual(plain.ctfshit_path, Path("checkout"))
        self.assertFalse(plain.json_output)
        self.assertEqual(machine.ctfshit_path, Path("checkout"))
        self.assertTrue(machine.json_output)

    def test_scan_and_plugins_option_scopes_remain_separate(self) -> None:
        scan = cli.parse_cli_args(
            ["scan", "sample.bin", "--ctfshit-path", "scan-checkout"]
        )
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as raised:
            cli.parse_cli_args(
                ["plugins", "list", "--ctfshit-path", "not-allowed"]
            )

        self.assertEqual(scan.ctfshit_path, Path("scan-checkout"))
        self.assertEqual(raised.exception.code, 2)


class DoctorCtfshitPrecedenceTests(unittest.TestCase):
    def _invoke(self, argv: list[str], environment: dict[str, str]):
        capability = doctor.PythonCapabilityDiagnostic(
            "ctfshit",
            "src.writeup_exporter",
            "csl-ctfshitcli",
            "ctfshit",
            False,
            None,
            "not-found",
            "built-in Markdown fallback active",
            None,
            "unavailable",
        )
        report = _report_for(capability)
        output = io.StringIO()
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(sys, "argv", ["dayi", *argv]),
            patch("dayi.cli.run_diagnostics", return_value=report) as diagnostics,
            contextlib.redirect_stdout(output),
            self.assertRaises(SystemExit) as raised,
        ):
            cli.main()
        self.assertEqual(raised.exception.code, 0)
        return diagnostics

    def test_cli_path_overrides_environment_for_doctor(self) -> None:
        diagnostics = self._invoke(
            ["doctor", "--ctfshit-path", "cli-checkout"],
            {"DAYI_CTFSHIT_PATH": "environment-checkout"},
        )

        diagnostics.assert_called_once_with(
            ctfshit_path=Path("cli-checkout"),
            ctfshit_path_source="cli",
        )

    def test_environment_path_is_used_when_cli_is_absent(self) -> None:
        diagnostics = self._invoke(
            ["doctor"],
            {"DAYI_CTFSHIT_PATH": " environment-checkout "},
        )

        diagnostics.assert_called_once_with(
            ctfshit_path=Path("environment-checkout"),
            ctfshit_path_source="environment",
        )

    def test_empty_whitespace_and_absent_environment_pass_none(self) -> None:
        for environment in (
            {"DAYI_CTFSHIT_PATH": ""},
            {"DAYI_CTFSHIT_PATH": " \t "},
            {},
        ):
            with self.subTest(environment=environment):
                diagnostics = self._invoke(["doctor"], environment)
                diagnostics.assert_called_once_with(
                    ctfshit_path=None,
                    ctfshit_path_source=None,
                )


class DoctorCtfshitResolutionTests(unittest.TestCase):
    def _diagnose(self, resolution, *, path=None, path_source=None):
        with patch(
            "dayi.doctor.resolve_writeup_exporter",
            return_value=resolution,
        ) as resolver:
            result = diagnose_ctfshit_capability(
                path,
                path_source=path_source,
                project_root=Path("/verified/dayi"),
            )
        resolver.assert_called_once_with(
            explicit_path=path,
            project_root=Path("/verified/dayi"),
        )
        return result

    def test_available_sources_are_mapped_deterministically(self) -> None:
        cases = (
            ("installed", None, None, "installed"),
            ("explicit-path", Path("cli"), "cli", "explicit-path"),
            (
                "explicit-path",
                Path("environment"),
                "environment",
                "environment-configured",
            ),
            ("sibling", None, None, "sibling"),
            ("child", None, None, "child"),
        )
        for source_kind, path, path_source, expected_source in cases:
            with self.subTest(source_kind=source_kind, path_source=path_source):
                exporter = Mock(side_effect=AssertionError("must not be invoked"))
                result = self._diagnose(
                    _resolution(
                        available=True,
                        source_kind=source_kind,
                        status_code="ok",
                        exporter=exporter,
                    ),
                    path=path,
                    path_source=path_source,
                )
                self.assertTrue(result.available)
                self.assertEqual(result.metadata_status, "ok")
                self.assertEqual(result.location_status, expected_source)
                self.assertIn("rich ctfshit writeup exporter available", result.capability)
                exporter.assert_not_called()

    def test_unavailable_statuses_are_mapped_deterministically(self) -> None:
        cases = (
            ("unavailable", "not-found", None),
            ("explicit-path", "invalid-path", Path("invalid")),
            ("installed", "distribution-mismatch", None),
            ("installed", "exporter-missing", None),
            ("installed", "import-failed", None),
        )
        for source_kind, status_code, path in cases:
            with self.subTest(status_code=status_code):
                result = self._diagnose(
                    _resolution(
                        available=False,
                        source_kind=source_kind,
                        status_code=status_code,
                    ),
                    path=path,
                )
                self.assertFalse(result.available)
                self.assertEqual(result.metadata_status, status_code)
                self.assertEqual(result.location_status, source_kind)
                self.assertIn("built-in Markdown fallback active", result.capability)

    def test_invalid_environment_path_keeps_environment_source(self) -> None:
        result = self._diagnose(
            _resolution(
                available=False,
                source_kind="explicit-path",
                status_code="invalid-path",
            ),
            path=Path("invalid-environment"),
            path_source="environment",
        )

        self.assertFalse(result.available)
        self.assertEqual(result.metadata_status, "invalid-path")
        self.assertEqual(result.location_status, "environment-configured")

    def test_runtime_exception_becomes_safe_unavailable_capability(self) -> None:
        with patch(
            "dayi.doctor.resolve_writeup_exporter",
            side_effect=RuntimeError("/secret/local/path"),
        ):
            result = diagnose_ctfshit_capability(
                Path("configured"),
                path_source="cli",
            )

        self.assertFalse(result.available)
        self.assertEqual(result.metadata_status, "import-failed")
        self.assertEqual(result.location_status, "explicit-path")
        self.assertNotIn("/secret/local/path", result.capability)
        payload = json.loads(render_json(_report_for(result)))
        self.assertEqual(payload["schema_version"], DOCTOR_SCHEMA_VERSION)
        self.assertEqual(payload["overall_status"], "degraded")

    def test_keyboard_interrupt_and_system_exit_propagate(self) -> None:
        for error in (KeyboardInterrupt(), SystemExit(2)):
            with self.subTest(error=type(error).__name__), patch(
                "dayi.doctor.resolve_writeup_exporter",
                side_effect=error,
            ):
                with self.assertRaises(type(error)):
                    diagnose_ctfshit_capability()


class DoctorCtfshitRenderingTests(unittest.TestCase):
    def test_missing_ctfshit_is_optional_degraded_and_plain_states_fallback(self) -> None:
        capability = diagnose_ctfshit_capability
        with patch(
            "dayi.doctor.resolve_writeup_exporter",
            return_value=_resolution(
                available=False,
                source_kind="unavailable",
                status_code="not-found",
            ),
        ):
            resolved = capability()
        report = _report_for(resolved)
        plain = render_plain(report)

        self.assertTrue(report.core_usable)
        self.assertEqual(report.overall_status, "degraded")
        self.assertEqual(doctor_exit_code(report), 0)
        self.assertIn("built-in Markdown fallback active", plain)

    def test_available_plain_and_json_are_path_and_callable_free(self) -> None:
        exporter = Mock(side_effect=AssertionError("must not be invoked"))
        secret_path = Path("/secret/checkout/ctfshitcli")
        with patch(
            "dayi.doctor.resolve_writeup_exporter",
            return_value=_resolution(
                available=True,
                source_kind="explicit-path",
                status_code="ok",
                exporter=exporter,
            ),
        ):
            capability = diagnose_ctfshit_capability(
                secret_path,
                path_source="environment",
            )
        report = _report_for(capability)
        plain = render_plain(report)
        encoded = render_json(report)
        payload = json.loads(encoded)
        ctfshit = payload["python_capabilities"][0]

        self.assertEqual(report.overall_status, "healthy")
        self.assertIn("rich ctfshit writeup exporter available", plain)
        self.assertIn("environment configured", plain)
        self.assertNotIn(str(secret_path), plain)
        self.assertNotIn(str(secret_path), encoded)
        self.assertNotIn("/internal/not-for-output", encoded)
        self.assertIsNone(ctfshit["location"])
        self.assertEqual(ctfshit["import_name"], "src.writeup_exporter")
        self.assertEqual(ctfshit["distribution"], "csl-ctfshitcli")
        self.assertEqual(ctfshit["location_status"], "environment-configured")
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
        self.assertEqual(payload["schema_version"], DOCTOR_SCHEMA_VERSION)
        exporter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
