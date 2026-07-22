import asyncio
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dayi.persona import TerminalUI
from dayi.reporter import write_json_report, write_txt_report
from dayi.runner import DayiRunner
from dayi.scanner import (
    MAX_DIRECT_FLAG_CHARACTERS,
    MAX_DIRECT_FLAG_LENGTH,
    SubprocessFlagScanner,
)
from dayi.tools import _base
from dayi.tools import strings as strings_plugin
from dayi.tools._plugin import PluginRegistry


FLAG = "CTF{stream_boundary_regression}"
PATTERN = re.compile(r"CTF\{[^}]+\}")
TEST_LIMIT = 64
TEST_CHUNK = 16


class _RecordingUI(TerminalUI):
    def __init__(self) -> None:
        self.events: list[tuple] = []

    def plugin_finished(self, plugin_id: str, outcome: str) -> None:
        self.events.append(("plugin_finished", plugin_id, outcome))

    def show_flag(self, flag: str, source: str | None = None) -> None:
        self.events.append(("flag", flag, source))


def _write_emitter(path: Path) -> None:
    source = f"""#!{sys.executable}
import os
import sys
import time

flag = {FLAG.encode()!r}
mode = sys.argv[1] if len(sys.argv) > 1 else "plugin"
if mode.startswith("-"):
    mode = "plugin"
limit = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else {TEST_LIMIT}
stdout = sys.stdout.buffer
stderr = sys.stderr.buffer

if mode == "stdout-before":
    stdout.write(b"pre:" + flag)
elif mode == "stdout-after" or mode == "plugin":
    stdout.write(b"x" * limit + flag)
elif mode == "stdout-chunk-split":
    stdout.write(b"x" * 9 + flag[:10])
    stdout.flush()
    time.sleep(0.05)
    stdout.write(flag[10:])
elif mode == "stdout-limit-split":
    stdout.write(b"x" * (limit - 12) + flag)
elif mode == "stderr-before":
    stderr.write(b"pre:" + flag)
elif mode == "stderr-after":
    stderr.write(b"x" * limit + flag)
elif mode == "no-flag":
    stdout.write(b"ordinary-output-" * (limit * 8))
elif mode == "duplicate":
    stdout.write(flag + b"x" * (limit * 2) + flag)
elif mode == "invalid-utf8":
    stdout.write(b"x" * (limit + 5) + b"\\xff\\xfe" + flag + b"\\x80")
elif mode == "timeout":
    Path = __import__("pathlib").Path
    Path(sys.argv[3]).write_text(str(os.getpid()))
    stdout.write(b"x" * (limit + 5) + flag)
    stdout.flush()
    time.sleep(60)
else:
    raise SystemExit(2)
"""
    path.write_text(source, encoding="utf-8")
    path.chmod(0o700)


class IncrementalSubprocessFlagTests(unittest.IsolatedAsyncioTestCase):
    async def _run(
        self,
        executable: Path,
        mode: str,
        *,
        timeout: float = 5.0,
        pid_file: Path | None = None,
    ):
        scanner = SubprocessFlagScanner(PATTERN)
        command = [str(executable), mode, str(TEST_LIMIT)]
        if pid_file is not None:
            command.append(str(pid_file))
        with (
            patch.object(_base, "PIPE_OUTPUT_LIMIT", TEST_LIMIT),
            patch.object(_base, "PIPE_BUFFER_LIMIT", TEST_CHUNK),
        ):
            result = await _base.async_run_command(
                command,
                "synthetic-stream",
                timeout,
                stdout_observer=scanner.stdout,
                stderr_observer=scanner.stderr,
            )
        return result, scanner.findings(result[1], result[2]), scanner

    async def test_stdout_positions_and_boundaries(self) -> None:
        expected_truncation = {
            "stdout-before": False,
            "stdout-after": True,
            "stdout-chunk-split": False,
            "stdout-limit-split": True,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            executable = Path(tmpdir) / "emit-stream"
            _write_emitter(executable)
            for mode, truncated in expected_truncation.items():
                with self.subTest(mode=mode):
                    result, findings, _scanner = await self._run(executable, mode)
                    stdout = result[1]
                    self.assertEqual(findings, {"stdout": [FLAG]})
                    self.assertEqual(findings["stdout"][0], FLAG)
                    self.assertEqual("truncated" in stdout, truncated)
                    retained = stdout.partition("\n... [subprocess stdout truncated")[0]
                    self.assertLessEqual(len(retained), TEST_LIMIT)

    async def test_stderr_before_and_after_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            executable = Path(tmpdir) / "emit-stream"
            _write_emitter(executable)
            for mode, truncated in (("stderr-before", False), ("stderr-after", True)):
                with self.subTest(mode=mode):
                    result, findings, _scanner = await self._run(executable, mode)
                    self.assertEqual(findings, {"stderr": [FLAG]})
                    self.assertEqual("truncated" in result[2], truncated)
                    retained = result[2].partition(
                        "\n... [subprocess stderr truncated"
                    )[0]
                    self.assertLessEqual(len(retained), TEST_LIMIT)

    async def test_no_flag_duplicate_and_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            executable = Path(tmpdir) / "emit-stream"
            _write_emitter(executable)

            no_flag_result, no_flags, no_flag_scanner = await self._run(
                executable, "no-flag"
            )
            self.assertEqual(no_flags, {})
            self.assertIn("truncated", no_flag_result[1])
            state_limit = MAX_DIRECT_FLAG_LENGTH + MAX_DIRECT_FLAG_CHARACTERS
            self.assertLessEqual(
                no_flag_scanner.stdout.retained_state_characters,
                state_limit,
            )

            duplicate_result, duplicate_flags, _scanner = await self._run(
                executable, "duplicate"
            )
            self.assertIn("truncated", duplicate_result[1])
            self.assertEqual(duplicate_flags, {"stdout": [FLAG]})

            invalid_result, invalid_flags, _scanner = await self._run(
                executable, "invalid-utf8"
            )
            self.assertIn("truncated", invalid_result[1])
            self.assertEqual(invalid_flags, {"stdout": [FLAG]})

    @unittest.skipUnless(os.name == "posix", "process cleanup assertion requires POSIX")
    async def test_timeout_after_truncation_preserves_flags_and_reaps_child(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            executable = root / "emit-stream"
            pid_file = root / "pid"
            _write_emitter(executable)
            result, findings, _scanner = await self._run(
                executable,
                "timeout",
                timeout=0.2,
                pid_file=pid_file,
            )

            self.assertTrue(result[4])
            self.assertIn("truncated", result[1])
            self.assertEqual(findings, {"stdout": [FLAG]})
            pid = int(pid_file.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


class StreamFlagReportingTests(unittest.TestCase):
    def test_plugin_terminal_and_json_keep_stream_source_and_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            executable = root / "emit-stream"
            target = root / "target.bin"
            target.write_bytes(b"fixture")
            _write_emitter(executable)
            ui = _RecordingUI()
            with (
                patch.object(_base, "PIPE_OUTPUT_LIMIT", TEST_LIMIT),
                patch.object(_base, "PIPE_BUFFER_LIMIT", TEST_CHUNK),
                patch.object(strings_plugin, "BINARY", str(executable)),
                patch.object(strings_plugin, "is_tool_available", return_value=True),
            ):
                report = asyncio.run(DayiRunner(
                    target,
                    PATTERN,
                    registry=PluginRegistry(strings_plugin.PLUGIN_SPECS),
                    ui=ui,
                ).run_all())
            json_path = root / "report.json"
            text_path = root / "report.txt"
            write_json_report(report, json_path)
            write_txt_report(report, text_path)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            rendered = text_path.read_text(encoding="utf-8")

        result = report.tool_results[0]
        self.assertEqual(result.flags_found, [FLAG])
        self.assertEqual(result.stream_flags, {"stdout": [FLAG]})
        self.assertIn("truncated", result.stdout)
        self.assertEqual(report.all_flags, [FLAG])
        self.assertEqual(payload["flag_attribution"], {FLAG: ["strings"]})
        self.assertEqual(
            payload["tool_results"][0]["stream_flags"],
            {"stdout": [FLAG]},
        )
        self.assertIn("[stdout]: " + FLAG, rendered)
        self.assertIn(("plugin_finished", "strings", "complete"), ui.events)
        self.assertIn(("flag", FLAG, "strings"), ui.events)


if __name__ == "__main__":
    unittest.main()
