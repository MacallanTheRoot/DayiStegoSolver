import contextlib
import io
import json
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dayi import cli
from dayi.plugin_inspector import (
    PLUGIN_INSPECTION_SCHEMA_VERSION,
    PluginAvailability,
    PluginDiagnostic,
    PluginInspectionReport,
    evaluate_plugin_availability,
    inspect_discovery_result,
    inspect_plugin,
    render_json,
    render_plain,
)
from dayi.reporter import ToolResult
from dayi.tools._plugin import (
    PluginDiscoveryIssue,
    PluginPhase,
    ToolPlugin,
    discover_plugins_with_issues,
    extraction_evidence_success,
)


async def _runner(_context) -> ToolResult:
    raise AssertionError("plugin runner must not execute during inspection")


def _plugin(
    plugin_id: str = "example",
    phase: PluginPhase = PluginPhase.CONCURRENT,
    priority: int = 10,
    **kwargs,
) -> ToolPlugin:
    return ToolPlugin(plugin_id, phase, priority, _runner, **kwargs)


def _diagnostic(
    plugin_id: str = "example",
    *,
    status: str = "available",
) -> PluginDiagnostic:
    return PluginDiagnostic(
        plugin_id=plugin_id,
        phase="CONCURRENT",
        priority=10,
        requires_wordlist=False,
        requires_mini_wordlist=False,
        contributes_to_mini_wordlist=False,
        skip_if_phase_succeeded=(),
        skip_if_plugins_succeeded=(),
        has_custom_success_evaluator=False,
        module="dayi.tools.example",
        required_executables=(),
        required_python_modules=(),
        availability=PluginAvailability(
            status=status,
            runnable=status == "available",
            reasons=(),
        ),
    )


class PluginsCLIParsingTests(unittest.TestCase):
    def test_list_and_json_parse_as_nested_commands(self) -> None:
        plain = cli.parse_cli_args(["plugins", "list"])
        machine = cli.parse_cli_args(["plugins", "list", "--json"])
        self.assertEqual(plain.command, "plugins")
        self.assertEqual(plain.plugins_action, "list")
        self.assertFalse(plain.json_output)
        self.assertTrue(machine.json_output)
        self.assertEqual(
            cli.normalize_cli_argv(["plugins", "list"]),
            ["plugins", "list"],
        )

    def test_help_and_missing_or_invalid_nested_action(self) -> None:
        for argv in (["plugins", "--help"], ["plugins", "list", "--help"]):
            with self.subTest(argv=argv):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaises(
                    SystemExit
                ) as raised:
                    cli.parse_cli_args(list(argv))
                self.assertEqual(raised.exception.code, 0)
                self.assertIn("usage:", output.getvalue())

        for argv in (["plugins"], ["plugins", "unknown"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as raised:
                cli.parse_cli_args(list(argv))
            self.assertEqual(raised.exception.code, 2)

    def test_scan_options_and_targets_are_rejected(self) -> None:
        for argv in (
            ["plugins", "list", "--flag", "FLAG"],
            ["plugins", "list", "target.bin"],
        ):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as raised:
                cli.parse_cli_args(list(argv))
            self.assertEqual(raised.exception.code, 2)

    def test_top_help_and_scan_compatibility(self) -> None:
        self.assertIn("plugins", cli.build_arg_parser().format_help())
        self.assertEqual(cli.parse_cli_args(["scan", "sample.bin"]).command, "scan")
        self.assertEqual(cli.parse_cli_args(["sample.bin"]).command, "scan")
        self.assertEqual(
            cli.normalize_cli_argv(["--flag", "FLAG", "sample.bin"]),
            ["scan", "--flag", "FLAG", "sample.bin"],
        )


class PluginMetadataAndAvailabilityTests(unittest.TestCase):
    def test_all_requested_fields_and_module_attribution(self) -> None:
        plugin = _plugin(
            "custom",
            PluginPhase.MAIN_FALLBACK,
            7,
            requires_wordlist=True,
            contributes_to_mini_wordlist=True,
            skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,),
            skip_if_plugins_succeeded=("primary",),
            success_evaluator=extraction_evidence_success,
            required_executables=("tool",),
            required_python_modules=("module",),
        )
        diagnostic = inspect_plugin(
            plugin,
            which=lambda _name: "/usr/bin/tool",
            find_spec=lambda _name: object(),
        )
        self.assertEqual(diagnostic.plugin_id, "custom")
        self.assertEqual(diagnostic.phase, "MAIN_FALLBACK")
        self.assertEqual(diagnostic.priority, 7)
        self.assertTrue(diagnostic.requires_wordlist)
        self.assertFalse(diagnostic.requires_mini_wordlist)
        self.assertTrue(diagnostic.contributes_to_mini_wordlist)
        self.assertEqual(diagnostic.skip_if_phase_succeeded, ("MINI_BRUTE_FORCE",))
        self.assertEqual(diagnostic.skip_if_plugins_succeeded, ("primary",))
        self.assertTrue(diagnostic.has_custom_success_evaluator)
        self.assertEqual(diagnostic.module, __name__)
        self.assertEqual(diagnostic.required_executables, ("tool",))
        self.assertEqual(diagnostic.required_python_modules, ("module",))
        self.assertEqual(diagnostic.availability.status, "conditional")

    def test_static_and_scan_time_availability_states(self) -> None:
        available = evaluate_plugin_availability(_plugin())
        missing_tool = evaluate_plugin_availability(
            _plugin(required_executables=("tool",)),
            which=lambda _name: None,
        )
        present_tool = evaluate_plugin_availability(
            _plugin(required_executables=("tool",)),
            which=lambda _name: "/usr/bin/tool",
        )
        main_wordlist = evaluate_plugin_availability(
            _plugin(requires_wordlist=True)
        )
        mini_wordlist = evaluate_plugin_availability(
            _plugin(requires_mini_wordlist=True)
        )
        missing_module = evaluate_plugin_availability(
            _plugin(required_python_modules=("optional",)),
            find_spec=lambda _name: None,
        )
        unknown = evaluate_plugin_availability(
            _plugin(required_python_modules=("optional",)),
            find_spec=Mock(side_effect=RuntimeError("unsupported finder")),
        )
        self.assertEqual(available.status, "available")
        self.assertTrue(available.runnable)
        self.assertEqual(missing_tool.status, "unavailable")
        self.assertFalse(missing_tool.runnable)
        self.assertEqual(present_tool.status, "available")
        self.assertEqual(main_wordlist.status, "conditional")
        self.assertEqual(mini_wordlist.status, "conditional")
        self.assertEqual(missing_module.status, "unavailable")
        self.assertEqual(unknown.status, "unknown")

    def test_multiple_reasons_are_stable_and_deduplicated(self) -> None:
        availability = evaluate_plugin_availability(
            _plugin(
                requires_wordlist=True,
                required_executables=("tool", "tool"),
                required_python_modules=("module", "module"),
            ),
            which=lambda _name: None,
            find_spec=lambda _name: None,
        )
        self.assertEqual(
            availability.reasons,
            (
                "external executable 'tool' was not found",
                "Python module 'module' was not found",
                "requires a scan-time main wordlist",
            ),
        )

    def test_inspector_preserves_registry_order_and_tie_breaks_from_discovery(self) -> None:
        modules = {
            "fake": SimpleNamespace(__path__=["fake"], __name__="fake"),
            "fake.a": SimpleNamespace(
                PLUGIN_SPECS=(_plugin("zulu", PluginPhase.CONCURRENT, 10),)
            ),
            "fake.b": SimpleNamespace(
                PLUGIN_SPECS=(_plugin("alpha", PluginPhase.CONCURRENT, 10),)
            ),
            "fake.c": SimpleNamespace(
                PLUGIN_SPECS=(_plugin("later", PluginPhase.ARCHIVE, 1),)
            ),
            "fake.d": SimpleNamespace(
                PLUGIN_SPECS=(_plugin("first", PluginPhase.CONCURRENT, 1),)
            ),
        }
        infos = [SimpleNamespace(name=name) for name in modules if name != "fake"]
        with (
            patch("dayi.tools._plugin.pkgutil.iter_modules", return_value=infos),
            patch("dayi.tools._plugin.importlib.import_module", side_effect=modules.get),
        ):
            discovery = discover_plugins_with_issues("fake")
        report = inspect_discovery_result(discovery)
        self.assertEqual(
            [plugin.plugin_id for plugin in report.plugins],
            ["first", "alpha", "zulu", "later"],
        )


class StructuredDiscoveryIssueTests(unittest.TestCase):
    def test_all_actual_issue_conditions_are_retained_with_valid_plugins(self) -> None:
        def sync_runner(_context):
            return None

        modules = {
            "fake": SimpleNamespace(__path__=["fake"], __name__="fake"),
            "fake.a_valid": SimpleNamespace(PLUGIN_SPECS=(_plugin("valid"),)),
            "fake.b_malformed": SimpleNamespace(PLUGIN_SPECS="bad"),
            "fake.c_nonplugin": SimpleNamespace(PLUGIN_SPECS=(object(),)),
            "fake.d_duplicate": SimpleNamespace(PLUGIN_SPECS=(_plugin("valid"),)),
            "fake.f_invalid_runner": SimpleNamespace(
                PLUGIN_SPECS=(
                    ToolPlugin("sync", PluginPhase.CONCURRENT, 1, sync_runner),
                )
            ),
            "fake.g_unresolved": SimpleNamespace(
                PLUGIN_SPECS=(
                    _plugin("unresolved", skip_if_plugins_succeeded=("missing",)),
                )
            ),
            "fake.h_pruned": SimpleNamespace(
                PLUGIN_SPECS=(
                    _plugin("pruned", skip_if_plugins_succeeded=("unresolved",)),
                )
            ),
        }
        module_names = [
            "fake.a_valid", "fake.b_malformed", "fake.c_nonplugin",
            "fake.d_duplicate", "fake.e_import", "fake.f_invalid_runner",
            "fake.g_unresolved", "fake.h_pruned",
        ]

        def import_module(name: str):
            if name == "fake.e_import":
                raise ImportError("module exploded")
            return modules[name]

        with (
            patch(
                "dayi.tools._plugin.pkgutil.iter_modules",
                return_value=[SimpleNamespace(name=name) for name in module_names],
            ),
            patch("dayi.tools._plugin.importlib.import_module", side_effect=import_module),
        ):
            discovery = discover_plugins_with_issues("fake")

        self.assertEqual(
            [plugin.plugin_id for plugin in discovery.registry.plugins],
            ["valid"],
        )
        self.assertEqual(
            [issue.code for issue in discovery.issues],
            [
                "invalid-plugin-spec",
                "invalid-plugin-spec",
                "duplicate-plugin-id",
                "module-import-error",
                "invalid-runner",
                "unresolved-dependency",
                "dependency-pruned",
            ],
        )
        self.assertTrue(all(issue.severity == "warning" for issue in discovery.issues))
        self.assertEqual(len(discovery.registry.issues), len(discovery.issues))


class PluginRenderingTests(unittest.TestCase):
    def _report(self) -> PluginInspectionReport:
        conditional = PluginDiagnostic(
            **{
                **_diagnostic("fallback").__dict__,
                "requires_wordlist": True,
                "skip_if_phase_succeeded": ("MINI_BRUTE_FORCE",),
                "skip_if_plugins_succeeded": ("primary",),
                "required_executables": ("tool",),
                "availability": PluginAvailability(
                    "conditional", False, ("requires a scan-time main wordlist",)
                ),
            }
        )
        issue = PluginDiscoveryIssue(
            "dayi.tools.broken", None, "module-import-error", "broken", "warning"
        )
        return PluginInspectionReport(
            plugins=(_diagnostic("alpha"), conditional), issues=(issue,)
        )

    def test_json_schema_counts_types_order_and_clean_output(self) -> None:
        encoded = render_json(self._report())
        payload = json.loads(encoded)
        self.assertEqual(payload["schema_version"], PLUGIN_INSPECTION_SCHEMA_VERSION)
        self.assertEqual(payload["plugin_count"], 2)
        self.assertEqual(payload["issue_count"], 1)
        self.assertEqual(
            [plugin["plugin_id"] for plugin in payload["plugins"]],
            ["alpha", "fallback"],
        )
        self.assertIs(payload["plugins"][0]["requires_wordlist"], False)
        self.assertIsInstance(payload["plugins"][1]["skip_if_phase_succeeded"], list)
        self.assertNotIn("\x1b", encoded)
        self.assertNotIn("Dayı Plugins\n{", encoded)

    def test_plain_output_contains_counts_dependencies_and_issues(self) -> None:
        rendered = render_plain(self._report())
        self.assertIn("Registered plugins: 2", rendered)
        self.assertIn("CONCURRENT", rendered)
        self.assertIn("conditional", rendered)
        self.assertIn("wordlist", rendered)
        self.assertIn("skip if phase succeeds: MINI_BRUTE_FORCE", rendered)
        self.assertIn("skip if plugin succeeds: primary", rendered)
        self.assertIn("module-import-error", rendered)
        self.assertNotIn("Traceback", rendered)
        self.assertNotIn("CTFD_TOKEN", rendered)


class PluginsSideEffectTests(unittest.TestCase):
    def test_list_command_does_not_start_scan_doctor_external_or_network_work(self) -> None:
        report = PluginInspectionReport((_diagnostic(),), ())
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["dayi", "plugins", "list", "--json"]),
            patch("dayi.cli.inspect_plugins", return_value=report),
            patch("dayi.cli.asyncio.run") as asyncio_run,
            patch("dayi.cli.DayiRunner") as runner,
            patch("dayi.cli.build_integration") as integration,
            patch("dayi.cli.build_flag_pattern_config") as pattern_config,
            patch("dayi.cli.write_report") as report_writer,
            patch("dayi.cli.export_markdown_writeup") as writeup_writer,
            patch("dayi.runner._create_scan_workspace") as workspace,
            patch("dayi.doctor.diagnose_external_tool") as doctor_probe,
            patch("urllib.request.urlopen") as network,
            contextlib.redirect_stdout(output),
        ):
            with self.assertRaises(SystemExit) as raised:
                cli.main()
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(json.loads(output.getvalue())["plugin_count"], 1)
        asyncio_run.assert_not_called()
        runner.assert_not_called()
        integration.assert_not_called()
        pattern_config.assert_not_called()
        report_writer.assert_not_called()
        writeup_writer.assert_not_called()
        workspace.assert_not_called()
        doctor_probe.assert_not_called()
        network.assert_not_called()

    def test_inspection_failure_returns_one(self) -> None:
        error = io.StringIO()
        with (
            patch.object(sys, "argv", ["dayi", "plugins", "list"]),
            patch("dayi.cli.inspect_plugins", side_effect=RuntimeError("broken")),
            contextlib.redirect_stderr(error),
        ):
            with self.assertRaises(SystemExit) as raised:
                cli.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("registry", error.getvalue())


if __name__ == "__main__":
    unittest.main()
