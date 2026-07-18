import asyncio
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dayi.reporter import ToolResult
from dayi.runner import DayiRunner
from dayi.tools.binwalk import run_binwalk
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
)


def _result(tool_name: str, extracted_dir: str | None = None) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        return_code=0,
        stdout="",
        stderr="",
        flags_found=[],
        elapsed_seconds=0.01,
        extracted_dir=extracted_dir,
    )


class WorkspaceLifecycleTests(unittest.TestCase):
    def test_binwalk_retains_caller_owned_workspace(self) -> None:
        async def fake_command(cmd, tool_name, timeout, cwd=None, stdin_data=None):
            self.assertIn("-D", cmd)
            self.assertEqual(cmd[cmd.index("-D") + 1], r"^zip archive data:zip")
            output_root = Path(cmd[cmd.index("-C") + 1])
            extracted = output_root / "_target.bin.extracted"
            extracted.mkdir(parents=True)
            (extracted / "hint.txt").write_text("no flag", encoding="utf-8")
            return 0, "", "", 0.01, False

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"data")
            workspace = root / "owned"

            with patch("dayi.tools.binwalk.is_tool_available", return_value=True):
                with patch(
                    "dayi.tools.binwalk.async_run_command",
                    side_effect=fake_command,
                ):
                    result = asyncio.run(
                        run_binwalk(
                            target,
                            re.compile(r"FLAG\{.*?\}"),
                            workspace=workspace,
                        )
                    )

            self.assertTrue(workspace.is_dir())
            self.assertTrue(Path(result.extracted_dir).is_dir())
            self.assertEqual(
                result.command[result.command.index("-D") + 1],
                r"^zip archive data:zip",
            )

    def test_runner_cleans_workspace_after_dependent_phases(self) -> None:
        captured_workspace: list[Path] = []
        archive_workspace_state: list[bool] = []

        async def fake_tool(context: PluginContext) -> ToolResult:
            return _result("stub")

        async def fake_binwalk(context: PluginContext) -> ToolResult:
            context.workspace.mkdir(parents=True, exist_ok=True)
            extracted = context.workspace / "_target.extracted"
            extracted.mkdir()
            captured_workspace.append(context.workspace)
            return _result("binwalk", str(extracted))

        async def fake_archive(context: PluginContext) -> ToolResult:
            dependency = context.result("binwalk")
            archive_workspace_state.append(
                context.workspace.is_dir()
                and dependency is not None
                and dependency.extracted_dir is not None
                and Path(dependency.extracted_dir).is_dir()
            )
            return _result("zip_cracker")

        registry = PluginRegistry(
            (
                ToolPlugin(
                    plugin_id="stub",
                    phase=PluginPhase.CONCURRENT,
                    priority=10,
                    run=fake_tool,
                ),
                ToolPlugin(
                    plugin_id="binwalk",
                    phase=PluginPhase.CONCURRENT,
                    priority=20,
                    run=fake_binwalk,
                ),
                ToolPlugin(
                    plugin_id="zip_cracker",
                    phase=PluginPhase.ARCHIVE,
                    priority=10,
                    run=fake_archive,
                ),
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"data")
            runner = DayiRunner(
                target,
                re.compile(r"FLAG\{.*?\}"),
                registry=registry,
            )
            report = asyncio.run(runner.run_all())

            self.assertEqual(
                [result.tool_name for result in report.tool_results],
                ["stub", "binwalk", "zip_cracker"],
            )
            self.assertEqual(archive_workspace_state, [True])

        self.assertEqual(len(captured_workspace), 1)
        self.assertFalse(captured_workspace[0].exists())
        self.assertIsNone(runner._workspace)


if __name__ == "__main__":
    unittest.main()
