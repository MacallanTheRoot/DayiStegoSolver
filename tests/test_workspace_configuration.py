import asyncio
import json
import logging
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from dayi import cli
from dayi.reporter import ScanReport, ToolResult, write_json_report, write_txt_report
from dayi.runner import (
    DayiRunner,
    WorkspaceConfigurationError,
    validate_workspace_parent,
)
from dayi.tools._plugin import PluginContext, PluginPhase, PluginRegistry, ToolPlugin


def _result(name: str, extracted_dir: Path | None = None) -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name],
        return_code=0,
        stdout="",
        stderr="",
        flags_found=[],
        elapsed_seconds=0.001,
        extracted_dir=str(extracted_dir) if extracted_dir is not None else None,
    )


def _registry(run) -> PluginRegistry:
    return PluginRegistry((ToolPlugin(
        plugin_id="workspace_test",
        phase=PluginPhase.CONCURRENT,
        priority=1,
        run=run,
    ),))


class WorkspaceLocationTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_uses_unique_system_temp_children_not_cwd(self) -> None:
        received: list[Path] = []

        async def plugin(context: PluginContext) -> ToolResult:
            received.append(context.workspace)
            self.assertTrue(os.access(context.workspace, os.W_OK))
            return _result("workspace_test")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            system_temp = root / "system-temp"
            system_temp.mkdir()
            cwd = root / "cwd"
            cwd.mkdir()
            target = root / "target.bin"
            target.write_bytes(b"target")
            old_cwd = Path.cwd()
            os.chdir(cwd)
            try:
                with patch("dayi.runner.tempfile.tempdir", str(system_temp)):
                    first = await DayiRunner(
                        target, re.compile("x"), registry=_registry(plugin)
                    ).run_all()
                    second = await DayiRunner(
                        target, re.compile("x"), registry=_registry(plugin)
                    ).run_all()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(first.retained_workspace, None)
            self.assertEqual(second.retained_workspace, None)
            self.assertEqual(len(received), 2)
            self.assertNotEqual(received[0], received[1])
            self.assertTrue(all(path.parent == system_temp for path in received))
            self.assertTrue(all(path.name.startswith("dayi_runner_") for path in received))
            self.assertTrue(all(not path.exists() for path in received))

    async def test_default_creation_never_consults_current_directory(self) -> None:
        async def plugin(context: PluginContext) -> ToolResult:
            return _result("workspace_test")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            system_temp = root / "system-temp"
            system_temp.mkdir()
            target = root / "target.bin"
            target.write_bytes(b"target")
            with (
                patch("dayi.runner.tempfile.tempdir", str(system_temp)),
                patch("dayi.runner.Path.cwd", side_effect=AssertionError("cwd used")),
            ):
                report = await DayiRunner(
                    target, re.compile("x"), registry=_registry(plugin)
                ).run_all()
        self.assertIsNone(report.retained_workspace)

    async def test_custom_parent_is_created_preserved_and_never_reused(self) -> None:
        received: list[Path] = []

        async def plugin(context: PluginContext) -> ToolResult:
            received.append(context.workspace)
            return _result("workspace_test")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"target")
            parent = root / "missing" / "workspaces"
            marker = parent / "keep.txt"
            parent.mkdir(parents=True)
            marker.write_text("keep", encoding="utf-8")

            for _ in range(2):
                report = await DayiRunner(
                    target,
                    re.compile("x"),
                    registry=_registry(plugin),
                    workspace_parent=parent,
                ).run_all()
                self.assertIsNone(report.retained_workspace)

            self.assertTrue(parent.is_dir())
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")
            self.assertNotEqual(received[0], received[1])
            self.assertTrue(all(path.parent == parent for path in received))
            self.assertTrue(all(not path.exists() for path in received))

            missing_parent = root / "new-parent"
            await DayiRunner(
                target,
                re.compile("x"),
                registry=_registry(plugin),
                workspace_parent=missing_parent,
            ).run_all()
            self.assertTrue(missing_parent.is_dir())

    async def test_useful_artifact_retains_exact_child(self) -> None:
        captured: list[Path] = []

        async def plugin(context: PluginContext) -> ToolResult:
            captured.append(context.workspace)
            extracted = context.workspace / "extract"
            extracted.mkdir()
            (extracted / "artifact.bin").write_bytes(b"useful")
            return _result("workspace_test", extracted)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"target")
            parent = root / "parent"
            report = await DayiRunner(
                target,
                re.compile("x"),
                registry=_registry(plugin),
                workspace_parent=parent,
            ).run_all()
            retained = Path(report.retained_workspace or "")
            self.assertEqual(retained, captured[0])
            self.assertEqual(retained.parent, parent)
            self.assertEqual(
                (retained / "extract" / "artifact.bin").read_bytes(), b"useful"
            )

    async def test_binwalk_target_copy_alone_does_not_trigger_retention(self) -> None:
        captured: list[Path] = []

        async def plugin(context: PluginContext) -> ToolResult:
            captured.append(context.workspace)
            binwalk_dir = context.workspace / "binwalk"
            binwalk_dir.mkdir()
            (binwalk_dir / context.target.name).write_bytes(context.target.read_bytes())
            return _result("binwalk", binwalk_dir)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"target")
            parent = root / "parent"
            report = await DayiRunner(
                target,
                re.compile("x"),
                registry=_registry(plugin),
                workspace_parent=parent,
            ).run_all()
            self.assertIsNone(report.retained_workspace)
            self.assertFalse(captured[0].exists())
            self.assertTrue(parent.is_dir())


class WorkspaceBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_external_and_symlinked_declarations_are_ignored(self) -> None:
        captured: list[Path] = []

        async def outside_plugin(context: PluginContext) -> ToolResult:
            captured.append(context.workspace)
            return _result("outside", external_dir)

        async def symlink_plugin(context: PluginContext) -> ToolResult:
            link = context.workspace / "linked-dir"
            link.symlink_to(external_dir, target_is_directory=True)
            return _result("linked", link)

        async def symlink_file_plugin(context: PluginContext) -> ToolResult:
            extracted = context.workspace / "extract"
            extracted.mkdir()
            (extracted / "linked-file").symlink_to(external_file)
            return _result("linked-file", extracted)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"target")
            external_dir = root / "external"
            external_dir.mkdir()
            external_file = external_dir / "keep.txt"
            external_file.write_text("untouched", encoding="utf-8")
            parent = root / "parent"
            registry = PluginRegistry((
                ToolPlugin("outside", PluginPhase.CONCURRENT, 1, outside_plugin),
                ToolPlugin("linked", PluginPhase.CONCURRENT, 2, symlink_plugin),
                ToolPlugin("linked-file", PluginPhase.CONCURRENT, 3, symlink_file_plugin),
            ))
            report = await DayiRunner(
                target,
                re.compile("x"),
                registry=registry,
                workspace_parent=parent,
            ).run_all()

            self.assertIsNone(report.retained_workspace)
            self.assertFalse(captured[0].exists())
            self.assertEqual(external_file.read_text(encoding="utf-8"), "untouched")

    async def test_cancellation_clears_and_removes_empty_workspace(self) -> None:
        entered = asyncio.Event()
        captured: list[Path] = []

        async def plugin(context: PluginContext) -> ToolResult:
            captured.append(context.workspace)
            entered.set()
            await asyncio.sleep(60)
            return _result("slow")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"target")
            runner = DayiRunner(
                target,
                re.compile("x"),
                registry=_registry(plugin),
                workspace_parent=root / "parent",
            )
            task = asyncio.create_task(runner.run_all())
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertIsNone(runner._workspace)
            self.assertIsNotNone(runner._last_report)
            self.assertIsNone(runner._last_report.retained_workspace)
            self.assertFalse(captured[0].exists())

    async def test_plugin_exception_preserves_error_result_and_cleanup(self) -> None:
        captured: list[Path] = []

        async def plugin(context: PluginContext) -> ToolResult:
            captured.append(context.workspace)
            raise RuntimeError("plugin exploded")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"target")
            report = await DayiRunner(
                target,
                re.compile("x"),
                registry=_registry(plugin),
                workspace_parent=root / "parent",
            ).run_all()
            self.assertEqual(len(report.tool_results), 1)
            self.assertTrue(report.tool_results[0].error)
            self.assertIn("plugin exploded", report.tool_results[0].stderr)
            self.assertFalse(captured[0].exists())


class WorkspaceValidationAndCLITests(unittest.IsolatedAsyncioTestCase):
    async def test_regular_file_and_creation_failures_are_clean(self) -> None:
        calls = 0

        async def plugin(context: PluginContext) -> ToolResult:
            nonlocal calls
            calls += 1
            return _result("workspace_test")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"target")
            invalid = root / "not-a-directory"
            invalid.write_text("file", encoding="utf-8")
            runner = DayiRunner(
                target,
                re.compile("x"),
                registry=_registry(plugin),
                workspace_parent=invalid,
            )
            with self.assertRaises(WorkspaceConfigurationError):
                await runner.run_all()
            self.assertEqual(calls, 0)
            self.assertIsNone(runner._workspace)
            self.assertIsNotNone(runner._last_report)

            with patch("dayi.runner.Path.mkdir", side_effect=OSError("denied")):
                with self.assertRaisesRegex(WorkspaceConfigurationError, "cannot prepare"):
                    validate_workspace_parent(root / "cannot-create")

            valid_parent = root / "valid"
            valid_parent.mkdir()
            failing_runner = DayiRunner(
                target,
                re.compile("x"),
                registry=_registry(plugin),
                workspace_parent=valid_parent,
            )
            with patch("dayi.runner.tempfile.mkdtemp", side_effect=OSError("full")):
                with self.assertRaisesRegex(WorkspaceConfigurationError, "cannot create"):
                    await failing_runner.run_all()
            self.assertEqual(calls, 0)

    def test_cli_parses_workspace_and_version_still_short_circuits(self) -> None:
        parser = cli.build_arg_parser()
        args = cli.parse_cli_args([
            "target.bin", "--flag", "FLAG", "--workspace-dir", "~/workspaces"
        ], parser)
        self.assertEqual(args.workspace_dir, Path("~/workspaces"))

        with self.assertRaises(SystemExit) as version_exit:
            cli.parse_cli_args(["--version", "--workspace-dir", "ignored"], parser)
        self.assertEqual(version_exit.exception.code, 0)

        with self.assertRaises(SystemExit) as missing_target:
            cli.parse_cli_args(["--flag", "FLAG", "--workspace-dir", "tmp"], parser)
        self.assertEqual(missing_target.exception.code, 2)

    async def test_invalid_cli_parent_stops_before_integrations_and_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"target")
            args = cli.parse_cli_args([
                str(target), "--flag", "FLAG", "--workspace-dir", str(root / "bad")
            ])
            logger = Mock(spec=logging.Logger)
            with (
                patch(
                    "dayi.cli.validate_workspace_parent",
                    side_effect=WorkspaceConfigurationError("not writable"),
                ),
                patch("dayi.cli.build_integration") as integration,
                patch("dayi.cli.DayiRunner") as runner,
            ):
                report, exit_code = await cli._run_analysis(args, logger)

        self.assertIsNone(report)
        self.assertEqual(exit_code, 1)
        integration.assert_not_called()
        runner.assert_not_called()
        self.assertIn("not writable", logger.error.call_args.args[0])

    def test_retained_workspace_is_written_to_txt_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            retained = root / "dayi_runner_unique"
            report = ScanReport(
                target_file="target.bin",
                flag_pattern="FLAG",
                wordlist=None,
                started_at="start",
                finished_at="finish",
                all_flags=[],
                tool_results=[],
                retained_workspace=str(retained),
            )
            txt = root / "report.txt"
            json_path = root / "report.json"
            write_txt_report(report, txt)
            write_json_report(report, json_path)
            self.assertIn(str(retained), txt.read_text(encoding="utf-8"))
            self.assertIn("güvenilmeyen", txt.read_text(encoding="utf-8"))
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["retained_workspace"], str(retained))

            report.retained_workspace = None
            write_txt_report(report, txt)
            write_json_report(report, json_path)
            self.assertNotIn("Korunan çalışma alanı", txt.read_text(encoding="utf-8"))
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertIsNone(payload["retained_workspace"])


if __name__ == "__main__":
    unittest.main()
