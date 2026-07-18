import contextlib
import importlib.metadata
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dayi import cli
from dayi.doctor import (
    DOCTOR_SCHEMA_VERSION,
    EXTERNAL_TOOL_DEFINITIONS,
    PYTHON_CAPABILITY_DEFINITIONS,
    CoreDiagnostic,
    ExternalToolDefinition,
    ExternalToolDiagnostic,
    PythonCapabilityDefinition,
    PythonCapabilityDiagnostic,
    build_doctor_report,
    diagnose_core,
    diagnose_external_tool,
    diagnose_python_capability,
    doctor_exit_code,
    render_json,
    render_plain,
)


class FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        wait_results: tuple[object, ...] = (0,),
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.wait_results = list(wait_results)
        self.wait_timeouts: list[float] = []
        self.killed = False

    def wait(self, timeout: float) -> int:
        self.wait_timeouts.append(timeout)
        result = self.wait_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return int(result)

    def kill(self) -> None:
        self.killed = True


def _external(
    *, found: bool = True, probe_status: str = "ok"
) -> ExternalToolDiagnostic:
    return ExternalToolDiagnostic(
        tool_id="tool",
        command="tool",
        found=found,
        path="/usr/bin/tool" if found else None,
        version="1.0" if probe_status == "ok" else None,
        probe_status=probe_status,
        category="format-specific",
        capability="test capability",
    )


def _capability(
    *, available: bool = True, metadata_status: str = "ok"
) -> PythonCapabilityDiagnostic:
    return PythonCapabilityDiagnostic(
        capability_id="module",
        import_name="module",
        distribution="module",
        display_name="Module",
        available=available,
        version="1.0" if metadata_status == "ok" else None,
        metadata_status=metadata_status,
        capability="test module",
        location="/site/module.py" if available else None,
        location_status="site-packages" if available else "unknown",
    )


def _core(*, healthy: bool = True) -> CoreDiagnostic:
    return CoreDiagnostic(
        status="healthy" if healthy else "unhealthy",
        dayi_version="3.0.0" if healthy else None,
        python_implementation="CPython",
        python_version="3.13.5",
        python_supported=healthy,
        minimum_python="3.10",
        platform="TestOS",
        architecture="test-arch",
        python_executable="/usr/bin/python",
        package_path="/package/dayi" if healthy else None,
        cli_operational=healthy,
    )


class DoctorCLIParsingTests(unittest.TestCase):
    def test_doctor_and_json_parse_as_real_top_level_commands(self) -> None:
        plain = cli.parse_cli_args(["doctor"])
        machine = cli.parse_cli_args(["doctor", "--json"])
        self.assertEqual(plain.command, "doctor")
        self.assertFalse(plain.json_output)
        self.assertTrue(machine.json_output)
        self.assertEqual(cli.normalize_cli_argv(["doctor"]), ["doctor"])
        self.assertEqual(
            cli.normalize_cli_argv(["doctor", "--json"]),
            ["doctor", "--json"],
        )

    def test_help_lists_doctor_and_doctor_help_needs_no_target(self) -> None:
        self.assertIn("doctor", cli.build_arg_parser().format_help())
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            cli.parse_cli_args(["doctor", "--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("dayi doctor", output.getvalue())

    def test_doctor_rejects_targets_and_scan_only_options(self) -> None:
        for argv in (["doctor", "target.bin"], ["doctor", "--flag", "FLAG"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as raised:
                cli.parse_cli_args(list(argv))
            self.assertEqual(raised.exception.code, 2)

    def test_legacy_scan_normalization_is_unchanged(self) -> None:
        self.assertEqual(
            cli.normalize_cli_argv(["--flag", "FLAG", "sample.bin"]),
            ["scan", "--flag", "FLAG", "sample.bin"],
        )
        self.assertEqual(
            cli.parse_cli_args(["sample.bin"]).target,
            Path("sample.bin"),
        )


class CoreDiagnosticTests(unittest.TestCase):
    def test_supported_core_fields_are_deterministic(self) -> None:
        with (
            patch("dayi.doctor.platform.python_implementation", return_value="CPython"),
            patch("dayi.doctor.platform.python_version", return_value="3.13.5"),
            patch("dayi.doctor.platform.system", return_value="TestOS"),
            patch("dayi.doctor.platform.machine", return_value="test-arch"),
            patch("dayi.doctor.sys.executable", "/python"),
        ):
            result = diagnose_core(
                version_info=(3, 13, 5),
                package_path="/package/dayi",
                cli_operational=True,
            )
        self.assertEqual(result.status, "healthy")
        self.assertTrue(result.python_supported)
        self.assertEqual(result.minimum_python, "3.10")
        self.assertEqual(result.platform, "TestOS")
        self.assertEqual(result.architecture, "test-arch")
        self.assertEqual(result.python_executable, "/python")

    def test_unsupported_python_and_missing_metadata_are_unhealthy(self) -> None:
        unsupported = diagnose_core(
            version_info=(3, 9, 18),
            package_path="/package/dayi",
            cli_operational=True,
        )
        missing_version = diagnose_core(
            version_info=(3, 13, 0),
            dayi_version=None,
            package_path="/package/dayi",
            cli_operational=True,
        )
        self.assertEqual(unsupported.status, "unhealthy")
        self.assertFalse(unsupported.python_supported)
        self.assertEqual(missing_version.status, "unhealthy")


class ExternalExecutableTests(unittest.TestCase):
    definition = ExternalToolDefinition(
        "example", "example", ("--version",), "format-specific", "example scan"
    )

    def _diagnose(self, process: FakeProcess):
        popen = Mock(return_value=process)
        result = diagnose_external_tool(
            self.definition,
            which=lambda _name: "/usr/bin/example",
            popen=popen,
        )
        return result, popen

    def test_missing_and_found_path(self) -> None:
        missing = diagnose_external_tool(
            self.definition, which=lambda _name: None
        )
        found, _popen = self._diagnose(FakeProcess(stdout=b"example 1.2\n"))
        self.assertFalse(missing.found)
        self.assertEqual(missing.probe_status, "missing")
        self.assertTrue(found.found)
        self.assertEqual(found.path, "/usr/bin/example")
        self.assertEqual(found.version, "example 1.2")

    def test_stdout_stderr_and_nonzero_versions(self) -> None:
        stdout, _ = self._diagnose(FakeProcess(stdout=b"v1 stdout\n", wait_results=(0,)))
        stderr, _ = self._diagnose(FakeProcess(stderr=b"v2 stderr\n", wait_results=(0,)))
        nonzero, _ = self._diagnose(FakeProcess(stderr=b"v3 usable\n", wait_results=(1,)))
        self.assertEqual(stdout.version, "v1 stdout")
        self.assertEqual(stderr.version, "v2 stderr")
        self.assertEqual(nonzero.probe_status, "ok")
        self.assertEqual(nonzero.version, "v3 usable")

    def test_timeout_empty_failure_and_spawn_exception_keep_found_state(self) -> None:
        timeout_error = subprocess.TimeoutExpired(["example"], 3)
        timed_out, _ = self._diagnose(
            FakeProcess(wait_results=(timeout_error, 0))
        )
        unavailable, _ = self._diagnose(FakeProcess(wait_results=(0,)))
        failed, _ = self._diagnose(FakeProcess(wait_results=(1,)))
        spawn_failed = diagnose_external_tool(
            self.definition,
            which=lambda _name: "/usr/bin/example",
            popen=Mock(side_effect=OSError("cannot spawn")),
        )
        self.assertTrue(timed_out.found)
        self.assertEqual(timed_out.probe_status, "timeout")
        self.assertEqual(unavailable.probe_status, "unavailable")
        self.assertEqual(failed.probe_status, "failed")
        self.assertTrue(spawn_failed.found)
        self.assertEqual(spawn_failed.probe_status, "failed")

    def test_output_is_control_free_single_line_and_bounded(self) -> None:
        raw = b"\x1b[31mversion\x00 one\x1b[0m\nsecond line\n" + b"x" * 20_000
        result, _ = self._diagnose(FakeProcess(stdout=raw))
        self.assertEqual(result.version, "version one")
        self.assertNotIn("\x1b", result.version or "")
        self.assertNotIn("\n", result.version or "")
        oversized, _ = self._diagnose(FakeProcess(stdout=b"x" * 20_000))
        self.assertEqual(len(oversized.version or ""), 240)

    def test_subprocess_contract_uses_static_argument_list_and_bounds(self) -> None:
        process = FakeProcess(stdout=b"version\n")
        result, popen = self._diagnose(process)
        args, kwargs = popen.call_args
        self.assertEqual(args[0], ["/usr/bin/example", "--version"])
        self.assertIsInstance(args[0], list)
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"], subprocess.PIPE)
        self.assertIs(kwargs["stderr"], subprocess.PIPE)
        self.assertFalse(kwargs["shell"])
        self.assertGreater(process.wait_timeouts[0], 0)
        self.assertEqual(result.probe_status, "ok")

    def test_allowlist_commands_are_static_and_unique(self) -> None:
        ids = [item.tool_id for item in EXTERNAL_TOOL_DEFINITIONS]
        commands = [item.command for item in EXTERNAL_TOOL_DEFINITIONS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(command and "/" not in command for command in commands))


class PythonCapabilityTests(unittest.TestCase):
    definition = PythonCapabilityDefinition(
        "pillow", "PIL", "Pillow", "Pillow", "image loading"
    )

    def test_missing_found_and_distribution_name_mismatch(self) -> None:
        missing = diagnose_python_capability(
            self.definition, find_spec=lambda _name: None
        )
        requested: list[str] = []
        found = diagnose_python_capability(
            self.definition,
            find_spec=lambda name: SimpleNamespace(
                origin=f"/site/{name}/__init__.py",
                submodule_search_locations=None,
            ),
            distribution_version=lambda name: requested.append(name) or "12.0",
            site_roots=(Path("/site"),),
        )
        self.assertFalse(missing.available)
        self.assertTrue(found.available)
        self.assertEqual(found.version, "12.0")
        self.assertEqual(requested, ["Pillow"])
        self.assertEqual(found.location_status, "site-packages")

    def test_missing_metadata_broken_discovery_and_outside_location(self) -> None:
        spec = SimpleNamespace(
            origin="/work/fake/PIL/__init__.py",
            submodule_search_locations=None,
        )

        def missing_version(_name: str) -> str:
            raise importlib.metadata.PackageNotFoundError

        metadata_missing = diagnose_python_capability(
            self.definition,
            find_spec=lambda _name: spec,
            distribution_version=missing_version,
            site_roots=(Path("/site"),),
        )
        discovery_broken = diagnose_python_capability(
            self.definition,
            find_spec=Mock(side_effect=ImportError("broken finder")),
        )
        self.assertTrue(metadata_missing.available)
        self.assertEqual(metadata_missing.metadata_status, "missing")
        self.assertEqual(metadata_missing.location_status, "outside-site-packages")
        self.assertFalse(discovery_broken.available)
        self.assertEqual(discovery_broken.metadata_status, "discovery-error")

    def test_capability_definition_order_is_stable(self) -> None:
        self.assertEqual(
            [item.capability_id for item in PYTHON_CAPABILITY_DEFINITIONS],
            [
                "rich", "aiohttp", "pillow", "pytesseract",
                "pypdf", "oletools", "scapy", "ctfshit",
            ],
        )


class StatusAndRenderingTests(unittest.TestCase):
    def test_health_and_exit_code_semantics(self) -> None:
        healthy = build_doctor_report(_core(), [_external()], [_capability()])
        missing_tool = build_doctor_report(
            _core(), [_external(found=False, probe_status="missing")], [_capability()]
        )
        missing_module = build_doctor_report(
            _core(), [_external()], [_capability(available=False, metadata_status="not-installed")]
        )
        timeout = build_doctor_report(
            _core(), [_external(probe_status="timeout")], [_capability()]
        )
        unhealthy = build_doctor_report(_core(healthy=False), [], [])
        self.assertEqual(healthy.overall_status, "healthy")
        for degraded in (missing_tool, missing_module, timeout):
            self.assertEqual(degraded.overall_status, "degraded")
            self.assertEqual(doctor_exit_code(degraded), 0)
        self.assertEqual(unhealthy.overall_status, "unhealthy")
        self.assertEqual(doctor_exit_code(unhealthy), 1)

    def test_plain_and_json_rendering_are_deterministic_and_secret_free(self) -> None:
        report = build_doctor_report(
            _core(),
            [_external(found=False, probe_status="missing")],
            [_capability(available=False, metadata_status="not-installed")],
        )
        plain = render_plain(report)
        encoded = render_json(report)
        payload = json.loads(encoded)
        self.assertIn("Core", plain)
        self.assertIn("External tools", plain)
        self.assertIn("Python capabilities", plain)
        self.assertLess(plain.index("External tools"), plain.index("Python capabilities"))
        self.assertNotIn("CTFD_TOKEN", plain)
        self.assertEqual(payload["schema_version"], DOCTOR_SCHEMA_VERSION)
        self.assertTrue(payload["core_usable"])
        self.assertIsNone(payload["external_tools"][0]["path"])
        self.assertNotIn("\x1b", encoded)


class DoctorSideEffectTests(unittest.TestCase):
    def test_doctor_help_does_not_collect_or_start_runtime(self) -> None:
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["dayi", "doctor", "--help"]),
            patch("dayi.cli.run_diagnostics") as diagnostics,
            patch("dayi.cli.asyncio.run") as asyncio_run,
            patch("dayi.cli.DayiRunner") as runner,
            contextlib.redirect_stdout(output),
        ):
            with self.assertRaises(SystemExit) as raised:
                cli.main()
        self.assertEqual(raised.exception.code, 0)
        diagnostics.assert_not_called()
        asyncio_run.assert_not_called()
        runner.assert_not_called()

    def test_json_command_avoids_scan_runtime_and_prints_only_json(self) -> None:
        report = build_doctor_report(_core(), [_external()], [_capability()])
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["dayi", "doctor", "--json"]),
            patch("dayi.cli.run_diagnostics", return_value=report),
            patch("dayi.cli.asyncio.run") as asyncio_run,
            patch("dayi.cli.DayiRunner") as runner,
            patch("dayi.cli.build_integration") as integration,
            patch("dayi.cli.build_flag_pattern_config") as pattern_config,
            patch("dayi.cli.write_report") as report_writer,
            patch("dayi.cli.export_markdown_writeup") as writeup_writer,
            patch("dayi.runner._create_scan_workspace") as workspace,
            contextlib.redirect_stdout(output),
        ):
            with self.assertRaises(SystemExit) as raised:
                cli.main()
        self.assertEqual(raised.exception.code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["schema_version"], DOCTOR_SCHEMA_VERSION)
        asyncio_run.assert_not_called()
        runner.assert_not_called()
        integration.assert_not_called()
        pattern_config.assert_not_called()
        report_writer.assert_not_called()
        writeup_writer.assert_not_called()
        workspace.assert_not_called()


if __name__ == "__main__":
    unittest.main()
