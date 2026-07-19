import asyncio
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dayi.cli import build_arg_parser, parse_cli_args
from dayi.integrations import IntegrationManager
from dayi.persona import setup_logger
from dayi.reporter import ScanReport, ToolResult, _fallback_markdown
from dayi.runner import DayiRunner
from dayi.scanner import (
    MAX_ARTIFACT_FINDINGS,
    MAX_FLAG_MATCHES,
    compile_pattern,
    scan_artifacts,
    scan_text,
)
from dayi.tools import _base
from dayi.tools._plugin import PluginContext, PluginPhase, PluginRegistry, ToolPlugin


def _result(name: str, extracted_dir: str | None = None) -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name],
        return_code=0,
        stdout="",
        stderr="",
        flags_found=[],
        elapsed_seconds=0.0,
        extracted_dir=extracted_dir,
    )


class SubprocessLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdin_is_delivered_and_output_is_bounded(self) -> None:
        script = "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data+b'x'*1000)"
        with patch.object(_base, "PIPE_OUTPUT_LIMIT", 32):
            rc, stdout, _stderr, _elapsed, timed_out = await _base.async_run_command(
                [sys.executable, "-c", script], "test", 5, stdin_data=b"hello"
            )
        self.assertEqual(rc, 0)
        self.assertFalse(timed_out)
        self.assertTrue(stdout.startswith("hello"))
        self.assertIn("truncated", stdout)

    @unittest.skipUnless(os.name == "posix", "process groups require POSIX")
    async def test_timeout_kills_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pid_file = Path(tmpdir) / "child.pid"
            script = (
                "import pathlib,subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
            )
            result = await _base.async_run_command(
                [sys.executable, "-c", script, str(pid_file)], "test", 0.25
            )
            self.assertTrue(result[4])
            child_pid = int(pid_file.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)

    async def test_cancellation_reaps_process(self) -> None:
        task = asyncio.create_task(
            _base.async_run_command(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                "test",
                60,
            )
        )
        await asyncio.sleep(0.1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)


class RunnerRetentionTests(unittest.IsolatedAsyncioTestCase):
    async def test_meaningful_extraction_is_retained_and_reported(self) -> None:
        async def carve(context: PluginContext) -> ToolResult:
            extracted = context.workspace / "binwalk" / "_sample.extracted"
            extracted.mkdir(parents=True)
            (extracted / "flag.png").write_bytes(b"PNG payload")
            return _result("binwalk", str(extracted))

        registry = PluginRegistry((ToolPlugin(
            plugin_id="binwalk", phase=PluginPhase.CONCURRENT,
            priority=1, run=carve,
        ),))
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "sample.bin"
            target.write_bytes(b"input")
            workspace_parent = root / "workspaces"
            report = await DayiRunner(
                target,
                re.compile(r"FLAG\{[^}]+\}"),
                registry=registry,
                workspace_parent=workspace_parent,
            ).run_all()
            retained = Path(report.retained_workspace or "")
            self.assertTrue(retained.is_dir())
            self.assertTrue((retained / "binwalk" / "_sample.extracted" / "flag.png").is_file())
            self.assertEqual(retained.parent, workspace_parent)

    async def test_cancellation_builds_partial_report_and_closes_workspace(self) -> None:
        entered = asyncio.Event()

        async def slow(context: PluginContext) -> ToolResult:
            entered.set()
            await asyncio.sleep(60)
            return _result("slow")

        registry = PluginRegistry((ToolPlugin(
            plugin_id="slow", phase=PluginPhase.CONCURRENT, priority=1, run=slow
        ),))
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"x")
            runner = DayiRunner(target, re.compile("x"), registry=registry)
            task = asyncio.create_task(runner.run_all())
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertIsNotNone(runner._last_report)
            self.assertIsNone(runner._workspace)


class BoundAndIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def test_core_and_plugin_discovery_import_without_optional_packages(self) -> None:
        code = r'''
import importlib.abc
import sys

blocked = ("aiohttp", "PIL", "pytesseract", "pypdf", "oletools", "scapy", "rich", "ctfshit")
class Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".", 1)[0] in blocked:
            raise ImportError(f"blocked optional dependency: {fullname}")
        return None
sys.meta_path.insert(0, Blocker())
from dayi.tools._plugin import discover_plugins
registry = discover_plugins()
assert not registry.issues, registry.issues
assert len(registry.plugins) == 19
'''
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_regex_guard_and_artifact_result_cap(self) -> None:
        self.assertIsNone(compile_pattern(r"(a+)+$"))
        findings = scan_artifacts(
            " ".join(
                f"https://example{i}.org/path"
                for i in range(MAX_ARTIFACT_FINDINGS * 2)
            ),
            source="regression",
        )
        self.assertLessEqual(len(findings), MAX_ARTIFACT_FINDINGS)
        flag_text = " ".join(f"F{i}" for i in range(MAX_FLAG_MATCHES * 2))
        self.assertEqual(
            len(scan_text(flag_text, re.compile(r"F\d+"))),
            MAX_FLAG_MATCHES,
        )

    def test_cli_rejects_unsafe_numeric_values(self) -> None:
        parser = build_arg_parser()
        for option, value in (("--timeout", "0"), ("--threads", "-1"), ("--bf-limit", "-1")):
            with self.assertRaises(SystemExit):
                parse_cli_args(["target.bin", "--flag", "x", option, value], parser)

    def test_setup_logger_does_not_duplicate_owned_handlers(self) -> None:
        name = f"dayi.test.{id(self)}"
        first = setup_logger(name)
        second = setup_logger(name)
        self.assertIs(first, second)
        self.assertEqual(sum(bool(getattr(h, "_dayi_owned", False)) for h in second.handlers), 1)

    async def test_integration_timeout_cancels_pending_notifications(self) -> None:
        manager = IntegrationManager(webhook_url="https://example.invalid/hook")

        async def never(_flag: str, _tool: str) -> None:
            await asyncio.sleep(60)

        manager._dispatch = never  # type: ignore[method-assign]
        manager.notify("FLAG{timeout}", "test")
        await manager.drain(timeout=0.01)
        self.assertFalse(manager._tasks)

    async def test_integration_backend_failure_is_contained(self) -> None:
        manager = IntegrationManager(webhook_url="https://example.invalid/hook")

        async def fail(_flag: str) -> None:
            raise TimeoutError("network stalled")

        manager._transport = "aiohttp"
        manager._send_discord_aiohttp = fail  # type: ignore[method-assign]
        results = await manager._dispatch("FLAG{safe}", "test")
        self.assertEqual(results[0].error_category, "timeout")

    def test_fallback_markdown_contains_untrusted_backticks_safely(self) -> None:
        result = _result("scanner")
        result.flags_found = ["FLAG{``` injected}"]
        report = ScanReport(
            target_file="evil`name.md",
            flag_pattern="FLAG.*",
            wordlist=None,
            started_at="start",
            finished_at="finish",
            all_flags=result.flags_found,
            tool_results=[result],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.md"
            _fallback_markdown(report, output)
            rendered = output.read_text(encoding="utf-8")
        self.assertIn(r"evil\`name\.md", rendered)
        self.assertIn("````text", rendered)


if __name__ == "__main__":
    unittest.main()
