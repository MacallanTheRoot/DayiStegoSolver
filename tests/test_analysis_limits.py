"""Resource-limit decisions surfaced as structured report events (T2.3)."""
import asyncio
import json
import re
import sys
import tempfile
import unittest
import zipfile
from dataclasses import fields
from pathlib import Path
from typing import Any
from unittest.mock import patch

from dayi import scanner
from dayi import text_stego
from dayi.document.model import DocumentFinding
from dayi.persona import TerminalUI
from dayi.reporter import (
    ScanReport,
    ToolResult,
    _build_notes_text,
    _fallback_markdown,
    write_json_report,
    write_txt_report,
)
from dayi.runner import DayiRunner
from dayi.scanner import (
    MAX_ANALYSIS_LIMIT_EVENTS,
    AnalysisLimit,
    record_analysis_limit,
    scan_artifacts,
    scan_directory,
    scan_file,
)
from dayi.tools import _base
from dayi.tools import binwalk as binwalk_plugin
from dayi.tools import exiftool as exiftool_plugin
from dayi.tools import exiv2 as exiv2_plugin
from dayi.tools import outguess as outguess_plugin
from dayi.tools import steghide as steghide_plugin
from dayi.tools import stegseek as stegseek_plugin
from dayi.tools import strings as strings_plugin
from dayi.tools import text_stego_scanner
from dayi.tools import zip_cracker
from dayi.tools import zsteg as zsteg_plugin
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
)

PATTERN = re.compile(r"FLAG\{[^}]+\}")
FLAG = "FLAG{t23}"
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 60
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 60


def _event(limits, reason):
    matches = [item for item in limits if item.reason == reason]
    return matches[0] if len(matches) == 1 else None


def _result(name: str, **kwargs) -> ToolResult:
    values: dict[str, Any] = dict(
        tool_name=name,
        command=[name],
        return_code=0,
        stdout="",
        stderr="",
        flags_found=[],
        elapsed_seconds=0.0,
    )
    values.update(kwargs)
    return ToolResult(**values)


class _QuietUI(TerminalUI):
    pass


# ---------------------------------------------------------------------------
# Event model and bounded aggregation
# ---------------------------------------------------------------------------

class AnalysisLimitModelTests(unittest.TestCase):
    def test_record_aggregates_repeated_events_and_keeps_known_observed(self) -> None:
        limits: list[AnalysisLimit] = []
        event = AnalysisLimit("scan_file", "extracted_file_size_limit", "skipped", 8, "bytes", 9)
        record_analysis_limit(limits, event)
        record_analysis_limit(limits, event)
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0].count, 2)
        self.assertEqual(limits[0].observed, 9)

    def test_differing_observed_values_become_unknown_not_invented(self) -> None:
        limits: list[AnalysisLimit] = []
        record_analysis_limit(limits, AnalysisLimit("s", "r", "skipped", 8, "bytes", 9))
        record_analysis_limit(limits, AnalysisLimit("s", "r", "skipped", 8, "bytes", 12))
        self.assertEqual(limits, [AnalysisLimit("s", "r", "skipped", 8, "bytes", None, 2)])

    def test_none_target_is_a_no_op(self) -> None:
        record_analysis_limit(None, AnalysisLimit("s", "r", "partial", 1, "bytes"))

    def test_distinct_events_are_bounded_and_ordered_by_first_occurrence(self) -> None:
        limits: list[AnalysisLimit] = []
        for index in range(MAX_ANALYSIS_LIMIT_EVENTS + 20):
            record_analysis_limit(limits, AnalysisLimit("s", f"r{index}", "partial", 1, "bytes"))
        self.assertEqual(len(limits), MAX_ANALYSIS_LIMIT_EVENTS)
        self.assertEqual(
            [item.reason for item in limits],
            [f"r{index}" for index in range(MAX_ANALYSIS_LIMIT_EVENTS)],
        )

    def test_tool_result_constructor_is_backward_compatible(self) -> None:
        positional = ToolResult("t", [], 0, "", "", [], 0.0)
        self.assertEqual(positional.analysis_limits, [])
        self.assertEqual([item.name for item in fields(ToolResult)][-1], "analysis_limits")
        report = ScanReport("t", "p", None, "s", "f", [], [positional])
        self.assertIsNone(report.scan_status)


# ---------------------------------------------------------------------------
# Scanner decision points
# ---------------------------------------------------------------------------

class ScanFileLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, size: int) -> Path:
        path = self.root / name
        body = FLAG.encode()
        path.write_bytes(body + b"x" * (size - len(body)) if size else b"")
        return path

    def test_size_boundaries(self) -> None:
        limit = 32
        with patch.object(scanner, "MAX_SCAN_FILE_BYTES", limit):
            for size, expected_flags, expect_event in (
                (limit - 1, [FLAG], False),
                (limit, [FLAG], False),
                (limit + 1, [], True),
            ):
                with self.subTest(size=size):
                    limits: list[AnalysisLimit] = []
                    path = self._write(f"f{size}", size)
                    self.assertEqual(scan_file(path, PATTERN, limits=limits), expected_flags)
                    if expect_event:
                        self.assertEqual(limits, [AnalysisLimit(
                            "scan_file", "extracted_file_size_limit", "skipped",
                            limit, "bytes", limit + 1,
                        )])
                    else:
                        self.assertEqual(limits, [])

    def test_empty_file_is_analysed_without_event(self) -> None:
        limits: list[AnalysisLimit] = []
        self.assertEqual(scan_file(self._write("empty", 0), PATTERN, limits=limits), [])
        self.assertEqual(limits, [])

    def test_default_call_keeps_return_type(self) -> None:
        with patch.object(scanner, "MAX_SCAN_FILE_BYTES", 4):
            self.assertEqual(scan_file(self._write("big", 64), PATTERN), [])


class ScanDirectoryLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _files(self, *sizes: int) -> None:
        for index, size in enumerate(sizes):
            (self.root / f"f{index}").write_bytes(b"x" * size)

    def test_file_count_limit(self) -> None:
        with patch.object(scanner, "MAX_SCAN_FILES", 2):
            self._files(1, 1)
            exact: list[AnalysisLimit] = []
            scan_directory(self.root, PATTERN, limits=exact)
            self.assertEqual(exact, [])

            self._files(1, 1, 1)
            over: list[AnalysisLimit] = []
            scan_directory(self.root, PATTERN, limits=over)
            self.assertEqual(over, [AnalysisLimit(
                "scan_directory", "directory_file_limit", "stopped", 2, "files", None,
            )])

    def test_aggregate_byte_budget(self) -> None:
        with patch.object(scanner, "MAX_SCAN_DIRECTORY_BYTES", 10):
            self._files(5, 5)
            exact: list[AnalysisLimit] = []
            scan_directory(self.root, PATTERN, limits=exact)
            self.assertEqual(exact, [])

            self._files(6, 6)
            over: list[AnalysisLimit] = []
            scan_directory(self.root, PATTERN, limits=over)
            self.assertEqual(over, [AnalysisLimit(
                "scan_directory", "directory_byte_budget", "stopped", 10, "bytes", None,
            )])

    def test_oversized_member_events_propagate_and_aggregate(self) -> None:
        with patch.object(scanner, "MAX_SCAN_FILE_BYTES", 4):
            self._files(8, 8, 2)
            limits: list[AnalysisLimit] = []
            scan_directory(self.root, PATTERN, limits=limits)
        self.assertEqual(limits, [AnalysisLimit(
            "scan_file", "extracted_file_size_limit", "skipped", 4, "bytes", 8, 2,
        )])


class ScanArtifactsLimitTests(unittest.TestCase):
    def test_input_character_limit(self) -> None:
        with patch.object(scanner, "MAX_ARTIFACT_INPUT_CHARS", 40):
            exact: list[AnalysisLimit] = []
            scan_artifacts("a" * 40, "t/stdout", limits=exact)
            self.assertEqual(exact, [])

            over: list[AnalysisLimit] = []
            scan_artifacts("a" * 41, "t/stdout", limits=over)
            self.assertEqual(over, [AnalysisLimit(
                "artifact_scan", "artifact_input_limit", "partial", 40, "characters", 41,
            )])

    def test_finding_limit_only_when_a_candidate_remained(self) -> None:
        exact: list[AnalysisLimit] = []
        found = scan_artifacts(
            "http://a.example/x http://b.example/y", "t", max_findings=2, limits=exact
        )
        self.assertEqual(len(found), 2)
        self.assertEqual(exact, [])

        over: list[AnalysisLimit] = []
        found = scan_artifacts(
            "http://a.example/x http://b.example/y http://c.example/z",
            "t", max_findings=2, limits=over,
        )
        self.assertEqual(len(found), 2)
        self.assertEqual(over, [AnalysisLimit(
            "artifact_scan", "artifact_finding_limit", "stopped", 2, "findings", None,
        )])

    def test_without_limits_scan_stops_once_budget_is_full(self) -> None:
        # Callers that pass no ``limits`` list cannot use the exact-stop
        # check, so the scan must not keep evaluating matches past the budget.
        content = "10.0.0.1 10.0.0.2 10.0.0.3 " + "10.0.0.1 " * 100
        for max_findings in (0, 3):
            with self.subTest(max_findings=max_findings):
                with patch.object(
                    scanner, "_safe_preview", wraps=scanner._safe_preview
                ) as preview:
                    found = scan_artifacts(content, "t", max_findings=max_findings)
                self.assertEqual(len(found), max_findings)
                self.assertEqual(preview.call_count, max_findings)

        # With a list, the scan still looks past the budget and, finding only
        # duplicates, records nothing.
        exact: list[AnalysisLimit] = []
        found = scan_artifacts(content, "t", max_findings=3, limits=exact)
        self.assertEqual(len(found), 3)
        self.assertEqual(exact, [])


# ---------------------------------------------------------------------------
# Text-stego input truncation
# ---------------------------------------------------------------------------

class TextStegoLimitTests(unittest.IsolatedAsyncioTestCase):
    def test_text_input_records_each_truncation_cause(self) -> None:
        plain = text_stego.detect_text_bytes(b"hello world " * 4)
        self.assertFalse(plain.source_truncated or plain.decoded_truncated)
        source = text_stego.detect_text_bytes(b"hello world " * 4, truncated=True)
        self.assertTrue(source.source_truncated)
        self.assertFalse(source.decoded_truncated)
        self.assertTrue(source.truncated)
        with patch.object(text_stego, "MAX_DECODED_CHARACTERS", 10):
            decoded = text_stego.detect_text_bytes(b"hello world " * 4)
            exact = text_stego.detect_text_bytes(b"helloworld")
        self.assertTrue(decoded.decoded_truncated)
        self.assertFalse(decoded.source_truncated)
        self.assertFalse(exact.decoded_truncated)

    async def _run(self, source: text_stego.TextInput) -> ToolResult:
        analysis = text_stego.analyze_text_input(source, PATTERN)

        async def fake_analysis(*_args, **_kwargs):
            return analysis

        with patch.object(text_stego_scanner, "_await_text_analysis", fake_analysis):
            return await text_stego_scanner.run_text_stego(Path("target.txt"), PATTERN)

    async def test_plugin_reports_truncation_events(self) -> None:
        # The plugin's window check must use the engine's slice constant.
        self.assertIs(
            text_stego_scanner.MAX_ANALYSIS_CHARACTERS, text_stego.MAX_ANALYSIS_CHARACTERS
        )
        text = "The quick brown fox jumps over the lazy dog. " * 8
        with patch.object(text_stego_scanner, "MAX_ANALYSIS_CHARACTERS", len(text)):
            exact = await self._run(text_stego.detect_text_bytes(text.encode()))
        self.assertFalse(exact.skipped)
        self.assertEqual(exact.analysis_limits, [])

        source = text_stego.detect_text_bytes(text.encode(), truncated=True)
        with patch.object(text_stego_scanner, "MAX_ANALYSIS_CHARACTERS", len(text) - 1):
            result = await self._run(source)
        self.assertEqual(result.analysis_limits, [
            AnalysisLimit(
                "text_stego", "text_source_byte_limit", "partial",
                text_stego.MAX_SOURCE_BYTES, "bytes", None,
            ),
            AnalysisLimit(
                "text_stego", "text_analysis_char_limit", "partial",
                len(text) - 1, "characters", len(text),
            ),
        ])

    def test_merge_keeps_per_input_events(self) -> None:
        event = AnalysisLimit("text_stego", "text_source_byte_limit", "partial", 8, "bytes")
        merged = text_stego_scanner._merge_text_results(
            [
                ("target", _result("text_stego", analysis_limits=[event])),
                ("workspace/a", _result("text_stego", analysis_limits=[event])),
            ],
            0.0,
        )
        self.assertEqual(merged.analysis_limits, [AnalysisLimit(
            "text_stego", "text_source_byte_limit", "partial", 8, "bytes", None, 2,
        )])


# ---------------------------------------------------------------------------
# Subprocess retained-output limit
# ---------------------------------------------------------------------------

class SubprocessOutputLimitTests(unittest.IsolatedAsyncioTestCase):
    async def _emit(self, stdout_bytes: int, stderr_bytes: int = 0):
        code = (
            "import sys;"
            f"sys.stdout.write('x'*{stdout_bytes});"
            f"sys.stderr.write('y'*{stderr_bytes})"
        )
        limits: list[AnalysisLimit] = []
        with patch.object(_base, "PIPE_OUTPUT_LIMIT", 32), patch.object(
            _base, "PIPE_BUFFER_LIMIT", 8
        ):
            result = await _base.async_run_command(
                [sys.executable, "-I", "-c", code], "synthetic", 10.0, limits=limits
            )
        return result, limits

    async def test_exact_limit_is_not_reported(self) -> None:
        result, limits = await self._emit(32, 32)
        self.assertNotIn("truncated", result[1])
        self.assertEqual(limits, [])

    async def test_streams_over_limit_are_reported_separately(self) -> None:
        result, limits = await self._emit(33, 40)
        self.assertEqual(len(result), 5)
        self.assertEqual(limits, [
            AnalysisLimit("subprocess_stdout", "subprocess_output_limit", "partial", 32, "bytes"),
            AnalysisLimit("subprocess_stderr", "subprocess_output_limit", "partial", 32, "bytes"),
        ])

    async def test_each_output_retaining_plugin_attaches_the_event(self) -> None:
        async def truncated_bytes(*_args, **_kwargs):
            return 0, b"retained", b"", 0.01, False, True, False

        cases = (
            ("strings", strings_plugin, lambda t: strings_plugin.run_strings(t, PATTERN), b"data"),
            ("exiftool", exiftool_plugin, lambda t: exiftool_plugin.run_exiftool(t, PATTERN), JPEG),
            ("exiv2", exiv2_plugin, lambda t: exiv2_plugin.run_exiv2(t, PATTERN), JPEG),
            ("zsteg", zsteg_plugin, lambda t: zsteg_plugin.run_zsteg(t, PATTERN), PNG),
            ("outguess", outguess_plugin, lambda t: outguess_plugin.run_outguess(t, PATTERN), JPEG),
            ("steghide", steghide_plugin, lambda t: steghide_plugin.run_steghide(t, PATTERN), JPEG),
            ("stegseek", stegseek_plugin, lambda t: stegseek_plugin.run_stegseek(t, PATTERN, None), JPEG),
            (
                "binwalk", binwalk_plugin,
                lambda t: binwalk_plugin.run_binwalk(t, PATTERN, workspace=t.parent / "bw"),
                b"data",
            ),
        )
        expected = AnalysisLimit(
            "subprocess_stdout", "subprocess_output_limit", "partial",
            _base.PIPE_OUTPUT_LIMIT, "bytes",
        )
        for name, module, run, header in cases:
            with self.subTest(plugin=name), tempfile.TemporaryDirectory() as tmpdir:
                target = Path(tmpdir) / "target.bin"
                target.write_bytes(header)
                with patch.object(module, "is_tool_available", return_value=True), patch.object(
                    _base, "async_run_command_bytes", truncated_bytes
                ):
                    result = await run(target)
                self.assertFalse(result.skipped, result.skip_reason)
                self.assertEqual(result.analysis_limits, [expected])


class SubprocessFlagBeyondRetentionTests(unittest.TestCase):
    def test_flag_after_retained_prefix_is_found_and_partial_coverage_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            emitter = root / "emit"
            emitter.write_text(
                f"#!{sys.executable} -I\nimport sys\n"
                f"sys.stdout.write('x' * 100 + {FLAG!r})\n",
                encoding="utf-8",
            )
            emitter.chmod(0o700)
            target = root / "target.bin"
            target.write_bytes(b"fixture")
            with (
                patch.object(_base, "PIPE_OUTPUT_LIMIT", 64),
                patch.object(_base, "PIPE_BUFFER_LIMIT", 16),
                patch.object(strings_plugin, "BINARY", str(emitter)),
                patch.object(strings_plugin, "is_tool_available", return_value=True),
            ):
                report = asyncio.run(DayiRunner(
                    target, PATTERN,
                    registry=PluginRegistry(strings_plugin.PLUGIN_SPECS),
                    ui=_QuietUI(),
                    workspace_parent=root / "ws",
                ).run_all())
            json_path = root / "report.json"
            write_json_report(report, json_path)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(report.all_flags, [FLAG])
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(payload["analysis_limits"], [{
            "tool": "strings",
            "source": "subprocess_stdout",
            "reason": "subprocess_output_limit",
            "action": "partial",
            "limit": 64,
            "unit": "bytes",
            "observed": None,
            "count": 1,
        }])


# ---------------------------------------------------------------------------
# Extraction plugins wiring
# ---------------------------------------------------------------------------

class ExtractionPluginWiringTests(unittest.IsolatedAsyncioTestCase):
    async def test_steghide_and_stegseek_report_oversized_extracted_payload(self) -> None:
        async def steghide_cmd(cmd, tool_name, timeout, **_kwargs):
            if "extract" in cmd:
                Path(cmd[cmd.index("-xf") + 1]).write_bytes(b"x" * 64)
            return 0, "", "", 0.01, False

        async def stegseek_cmd(cmd, tool_name, timeout, **_kwargs):
            Path(cmd[4]).write_bytes(b"x" * 64)
            return 0, "", "", 0.01, False

        expected = [AnalysisLimit(
            "scan_file", "extracted_file_size_limit", "skipped", 16, "bytes", 64,
        )]
        for module, command, run in (
            (steghide_plugin, steghide_cmd, lambda t: steghide_plugin.run_steghide(t, PATTERN)),
            (stegseek_plugin, stegseek_cmd, lambda t: stegseek_plugin.run_stegseek(t, PATTERN, None)),
        ):
            with self.subTest(plugin=module.TOOL_NAME), tempfile.TemporaryDirectory() as tmpdir:
                target = Path(tmpdir) / "carrier.jpg"
                target.write_bytes(JPEG)
                with patch.object(module, "is_tool_available", return_value=True), patch.object(
                    module, "async_run_command", side_effect=command
                ), patch.object(scanner, "MAX_SCAN_FILE_BYTES", 16):
                    result = await run(target)
                self.assertEqual(result.analysis_limits, expected)

    async def test_steghide_bruteforce_reports_oversized_payload(self) -> None:
        async def command(cmd, tool_name, timeout, **_kwargs):
            Path(cmd[cmd.index("-xf") + 1]).write_bytes(b"x" * 64)
            return 0, "", "", 0.01, False

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "carrier.jpg"
            target.write_bytes(JPEG)
            with patch.object(steghide_plugin, "is_tool_available", return_value=True), patch.object(
                steghide_plugin, "async_run_command", side_effect=command
            ), patch.object(scanner, "MAX_SCAN_FILE_BYTES", 16):
                result = await steghide_plugin.run_steghide_bruteforce(
                    target, PATTERN, wordlist_data=["a", "b"], max_concurrent=1,
                )
        event = _event(result.analysis_limits, "extracted_file_size_limit")
        assert event is not None
        self.assertEqual((event.limit, event.observed), (16, 64))

    async def test_binwalk_reports_directory_scan_budget(self) -> None:
        async def command(cmd, tool_name, timeout, cwd=None, **_kwargs):
            extracted = Path(cmd[cmd.index("-C") + 1]) / "_target.bin.extracted"
            extracted.mkdir(parents=True)
            for index in range(3):
                (extracted / f"m{index}").write_text("data", encoding="utf-8")
            return 0, "", "", 0.01, False

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"fixture")
            with patch.object(binwalk_plugin, "is_tool_available", return_value=True), patch.object(
                binwalk_plugin, "async_run_command", side_effect=command
            ), patch.object(scanner, "MAX_SCAN_FILES", 2):
                result = await binwalk_plugin.run_binwalk(
                    target, PATTERN, workspace=Path(tmpdir) / "bw"
                )
        self.assertEqual(result.analysis_limits, [AnalysisLimit(
            "scan_directory", "directory_file_limit", "stopped", 2, "files", None,
        )])

    async def test_zip_cracker_reports_directory_scan_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir) / "binwalk"
            workspace.mkdir()
            with zipfile.ZipFile(workspace / "carved.zip", "w") as archive:
                for index in range(3):
                    archive.writestr(f"m{index}.txt", "data")
            with patch.object(scanner, "MAX_SCAN_FILES", 2):
                result = await zip_cracker.run_zip_cracker(workspace, PATTERN, [])
        self.assertEqual(result.analysis_limits, [AnalysisLimit(
            "scan_directory", "directory_file_limit", "stopped", 2, "files", None,
        )])

    async def test_zip_cracker_timeout_keeps_recorded_events(self) -> None:
        def worker(*_args, limits=None):
            limits.append(LIMIT_EVENT)
            raise zip_cracker.ArchiveCrackingCancelled()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(zip_cracker, "_crack_archives_sync", worker), patch.object(
                zip_cracker.asyncio, "wait_for", side_effect=asyncio.TimeoutError
            ):
                result = await zip_cracker.run_zip_cracker(Path(tmpdir), PATTERN, [])
        self.assertTrue(result.timed_out)
        self.assertEqual(result.analysis_limits, [LIMIT_EVENT])


# ---------------------------------------------------------------------------
# Runner lifecycle
# ---------------------------------------------------------------------------

LIMIT_EVENT = AnalysisLimit("scan_file", "extracted_file_size_limit", "skipped", 8, "bytes", 9)


def _plugin(plugin_id, run, phase=PluginPhase.CONCURRENT, priority=10):
    return ToolPlugin(plugin_id=plugin_id, phase=phase, priority=priority, run=run)


class RunnerLimitTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.target = self.root / "target.bin"
        self.target.write_bytes(b"fixture")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _runner(self, plugins, **kwargs) -> DayiRunner:
        return DayiRunner(
            self.target, PATTERN,
            registry=PluginRegistry(tuple(plugins)),
            ui=_QuietUI(),
            workspace_parent=self.root / "ws",
            **kwargs,
        )

    @staticmethod
    def _returns(name, *, flag=None, limits=(), stdout=""):
        async def run(context: PluginContext) -> ToolResult:
            return _result(
                name, flags_found=[flag] if flag else [],
                analysis_limits=list(limits), stdout=stdout,
            )
        return run

    async def test_completed_pipeline_with_limits_is_not_failed(self) -> None:
        report = await self._runner([_plugin("a", self._returns("a", limits=[LIMIT_EVENT]))]).run_all()
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(report.tool_results[0].analysis_limits, [LIMIT_EVENT])

    async def test_runner_records_artifact_input_limit_per_stream(self) -> None:
        stdout = "x" * 50
        with patch.object(scanner, "MAX_ARTIFACT_INPUT_CHARS", 40):
            report = await self._runner([_plugin("a", self._returns("a", stdout=stdout))]).run_all()
        self.assertEqual(report.tool_results[0].analysis_limits, [AnalysisLimit(
            "artifact_scan/stdout", "artifact_input_limit", "partial", 40, "characters", 50,
        )])

    async def test_runner_reports_artifact_budget_as_per_result_limit(self) -> None:
        urls = " ".join(f"http://h{index}.example/p" for index in range(5))
        supplied = scanner.ArtifactFinding("url", "http://plugin.example", "a")

        async def run(context: PluginContext) -> ToolResult:
            # One plugin-supplied finding leaves a call budget of 2 of 3.
            return _result("a", stdout=urls, artifacts_found=[supplied])

        with patch("dayi.runner.MAX_ARTIFACT_FINDINGS", 3):
            report = await self._runner([_plugin("a", run)]).run_all()
        result = report.tool_results[0]
        self.assertEqual(len(result.artifacts_found), 3)
        self.assertEqual(result.analysis_limits, [AnalysisLimit(
            "artifact_scan/stdout", "artifact_finding_limit", "stopped", 3, "findings", None,
        )])

    async def test_full_budget_without_new_artifacts_is_not_reported(self) -> None:
        urls = " ".join(f"http://h{index}.example/p" for index in range(3))

        def plugin(stderr):
            async def run(context: PluginContext) -> ToolResult:
                return _result("a", stdout=urls, stderr=stderr)
            return run

        with patch("dayi.runner.MAX_ARTIFACT_FINDINGS", 3):
            quiet = await self._runner([_plugin("a", plugin("just a warning"))]).run_all()
            repeated = await self._runner([_plugin("a", plugin(urls))]).run_all()
            new = await self._runner(
                [_plugin("a", plugin("see http://new.example/q"))]
            ).run_all()
        for report in (quiet, repeated):
            self.assertEqual(len(report.tool_results[0].artifacts_found), 3)
            self.assertEqual(report.tool_results[0].analysis_limits, [])
        self.assertEqual(new.tool_results[0].analysis_limits, [AnalysisLimit(
            "artifact_scan/stderr", "artifact_finding_limit", "stopped", 3, "findings", None,
        )])

    async def test_new_artifact_after_repeats_of_a_full_budget_is_reported(self) -> None:
        supplied = [
            scanner.ArtifactFinding("url", f"http://p{index}.example/x", "a")
            for index in range(3)
        ]

        async def run(context: PluginContext) -> ToolResult:
            # Plugin artifacts fill the budget; stdout repeats one of them
            # before a new artifact, so the probe must look past the repeats.
            return _result(
                "a",
                stdout="http://p0.example/x http://new.example/q",
                artifacts_found=list(supplied),
            )

        with patch("dayi.runner.MAX_ARTIFACT_FINDINGS", 3):
            report = await self._runner([_plugin("a", run)]).run_all()
        result = report.tool_results[0]
        self.assertEqual(result.artifacts_found, supplied)
        self.assertEqual(result.analysis_limits, [AnalysisLimit(
            "artifact_scan/stdout", "artifact_finding_limit", "stopped", 3, "findings", None,
        )])

    async def test_artifact_recovered_by_later_stream_is_not_reported(self) -> None:
        supplied = scanner.ArtifactFinding("url", "http://a.example/x", "a")

        async def run(context: PluginContext) -> ToolResult:
            # stdout's call budget (2) spends one slot on the supplied
            # duplicate and refuses c; stderr then keeps c.
            return _result(
                "a",
                stdout="http://a.example/x http://b.example/y http://c.example/z",
                stderr="http://c.example/z",
                artifacts_found=[supplied],
            )

        with patch("dayi.runner.MAX_ARTIFACT_FINDINGS", 3):
            report = await self._runner([_plugin("a", run)]).run_all()
        result = report.tool_results[0]
        self.assertEqual(
            [item.preview for item in result.artifacts_found],
            ["http://a.example/x", "http://b.example/y", "http://c.example/z"],
        )
        self.assertEqual(result.analysis_limits, [])

    async def test_cross_stream_duplicates_below_budget_are_not_reported(self) -> None:
        urls = "http://a.example/x http://b.example/y"

        async def run(context: PluginContext) -> ToolResult:
            return _result("a", stdout=urls, stderr=urls)

        with patch("dayi.runner.MAX_ARTIFACT_FINDINGS", 3):
            report = await self._runner([_plugin("a", run)]).run_all()
        self.assertEqual(len(report.tool_results[0].artifacts_found), 2)
        self.assertEqual(report.tool_results[0].analysis_limits, [])

    async def test_retained_artifacts_match_a_budgeted_scan(self) -> None:
        # Retention must equal the pre-T2.3 per-stream max_findings=remaining scan.
        stdout = " ".join(f"http://s{index}.example/p" for index in range(4))
        stderr = "http://s0.example/p " + " ".join(
            f"http://e{index}.example/p" for index in range(4)
        )

        async def run(context: PluginContext) -> ToolResult:
            return _result("a", stdout=stdout, stderr=stderr)

        with patch("dayi.runner.MAX_ARTIFACT_FINDINGS", 6):
            report = await self._runner([_plugin("a", run)]).run_all()
        expected = scan_artifacts(stdout, "a/stdout", max_findings=6)
        keys = {(f.artifact_type, f.preview) for f in expected}
        for finding in scan_artifacts(stderr, "a/stderr", max_findings=6 - len(expected)):
            if (finding.artifact_type, finding.preview) not in keys:
                expected.append(finding)
        self.assertEqual(report.tool_results[0].artifacts_found, expected)

    async def test_runner_reports_trimmed_plugin_artifacts(self) -> None:
        findings = [
            scanner.ArtifactFinding("url", f"http://h{index}.example", "a") for index in range(5)
        ]

        async def run(context: PluginContext) -> ToolResult:
            return _result("a", artifacts_found=list(findings))

        with patch("dayi.runner.MAX_ARTIFACT_FINDINGS", 3):
            report = await self._runner([_plugin("a", run)]).run_all()
        self.assertEqual(report.tool_results[0].analysis_limits, [AnalysisLimit(
            "artifact_scan", "artifact_finding_limit", "stopped", 3, "findings", 5,
        )])

    async def test_repeated_runs_do_not_carry_stale_events(self) -> None:
        calls: list[int] = []

        async def run(context: PluginContext) -> ToolResult:
            calls.append(1)
            return _result("a", analysis_limits=[LIMIT_EVENT] if len(calls) == 1 else [])

        runner = self._runner([_plugin("a", run)])
        # Snapshot first: report.tool_results aliases the runner's list
        # (pre-existing), which the next run_all() clears.
        first = list((await runner.run_all()).tool_results[0].analysis_limits)
        second = await runner.run_all()
        self.assertEqual(first, [LIMIT_EVENT])
        self.assertEqual(second.tool_results[0].analysis_limits, [])

    async def test_cancellation_preserves_recorded_events(self) -> None:
        entered = asyncio.Event()

        async def blocks(context: PluginContext) -> ToolResult:
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        runner = self._runner([
            _plugin("a", self._returns("a", limits=[LIMIT_EVENT]), priority=1),
            _plugin("b", blocks, priority=2),
        ])
        task = asyncio.create_task(runner.run_all())
        await entered.wait()
        for _ in range(5):
            await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        report = runner._last_report
        assert report is not None
        self.assertEqual(report.scan_status, "cancelled")
        self.assertEqual(report.tool_results[0].analysis_limits, [LIMIT_EVENT])

    async def test_early_stop_and_full_scan_keep_limit_policy(self) -> None:
        def plugins():
            return [
                _plugin("a", self._returns("a", flag=FLAG, limits=[LIMIT_EVENT])),
                _plugin(
                    "z", self._returns("z", limits=[LIMIT_EVENT]),
                    phase=PluginPhase.ARCHIVE,
                ),
            ]

        default = await self._runner(plugins()).run_all()
        self.assertEqual(default.scan_status, "early_stopped")
        self.assertEqual([r.tool_name for r in default.tool_results], ["a"])
        self.assertEqual(default.tool_results[0].analysis_limits, [LIMIT_EVENT])

        full = await self._runner(plugins(), full_scan=True).run_all()
        self.assertEqual(full.scan_status, "completed")
        self.assertEqual(
            [(r.tool_name, r.analysis_limits) for r in full.tool_results],
            [("a", [LIMIT_EVENT]), ("z", [LIMIT_EVENT])],
        )


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

class ReportRenderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _report(self, results) -> ScanReport:
        return ScanReport(
            target_file="/tmp/target.bin", flag_pattern="FLAG", wordlist=None,
            started_at="s", finished_at="f", all_flags=[], tool_results=results,
            scan_status="completed", plugins_not_run=[],
        )

    def _limited(self) -> ScanReport:
        return self._report([
            _result("binwalk", analysis_limits=[
                AnalysisLimit("scan_file", "extracted_file_size_limit", "skipped", 8, "bytes", None, 2),
                AnalysisLimit("scan_directory", "directory_file_limit", "stopped", 4096, "files"),
            ]),
            _result("strings", analysis_limits=[
                AnalysisLimit("subprocess_stdout", "subprocess_output_limit", "partial", 10, "bytes"),
            ]),
        ])

    def test_json_lists_events_in_deterministic_order(self) -> None:
        path = self.root / "r.json"
        write_json_report(self._limited(), path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            [(item["tool"], item["source"], item["reason"]) for item in payload["analysis_limits"]],
            [
                ("binwalk", "scan_directory", "directory_file_limit"),
                ("binwalk", "scan_file", "extracted_file_size_limit"),
                ("strings", "subprocess_stdout", "subprocess_output_limit"),
            ],
        )
        self.assertEqual(payload["analysis_limits"][1]["count"], 2)
        self.assertIsNone(payload["analysis_limits"][1]["observed"])
        self.assertNotIn("analysis_limits", payload["tool_results"][0])

    def test_json_without_events_has_empty_list_and_existing_keys(self) -> None:
        path = self.root / "r.json"
        write_json_report(self._report([_result("a")]), path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["analysis_limits"], [])
        self.assertEqual(list(payload), [
            "meta", "all_flags_found", "flag_attribution", "artifacts_found",
            "retained_workspace", "scan_status", "plugins_not_run",
            "analysis_limits", "tool_results",
        ])

    def test_txt_notes_and_markdown_show_events(self) -> None:
        report = self._limited()
        txt = self.root / "r.txt"
        md = self.root / "r.md"
        write_txt_report(report, txt)
        _fallback_markdown(report, md)
        rendered_txt = txt.read_text(encoding="utf-8")
        rendered_md = md.read_text(encoding="utf-8")
        notes = _build_notes_text(report)
        for rendered in (rendered_txt, notes):
            self.assertIn("KAYNAK SINIRLARI", rendered)
            self.assertIn(
                "binwalk / scan_file: extracted_file_size_limit — atlandı "
                "(sınır: 8 bytes, 2 kez)",
                rendered,
            )
            self.assertIn("strings / subprocess_stdout: subprocess_output_limit — kısmen analiz edildi", rendered)
        self.assertIn("#### Kaynak Sınırları", rendered_md)
        self.assertIn(r"extracted\_file\_size\_limit", rendered_md)

    def test_no_events_means_no_section(self) -> None:
        report = self._report([_result("a")])
        txt = self.root / "r.txt"
        write_txt_report(report, txt)
        self.assertNotIn("KAYNAK SINIRLARI", txt.read_text(encoding="utf-8"))
        self.assertNotIn("KAYNAK SINIRLARI", _build_notes_text(report))

    def test_display_truncation_is_labelled_and_not_an_analysis_limit(self) -> None:
        findings = [
            DocumentFinding("c", "m", "word/document.xml", "v", "low", preview=f"p{index}")
            for index in range(53)
        ]
        stdout = "\n".join(f"line{index}" for index in range(30))
        report = self._report([_result("document_stego", document_findings=findings, stdout=stdout)])
        txt = self.root / "r.txt"
        jsn = self.root / "r.json"
        write_txt_report(report, txt)
        write_json_report(report, jsn)
        rendered = txt.read_text(encoding="utf-8")
        notes = _build_notes_text(report)
        self.assertIn("(+3 bulgu yalnızca bu rapor görünümünde gösterilmedi)", rendered)
        self.assertIn("(+3 bulgu yalnızca bu rapor görünümünde gösterilmedi)", notes)
        self.assertIn("(+10 satır yalnızca bu rapor görünümünde gösterilmedi)", notes)
        self.assertNotIn("KAYNAK SINIRLARI", rendered)
        payload = json.loads(jsn.read_text(encoding="utf-8"))
        self.assertEqual(payload["analysis_limits"], [])
        self.assertEqual(len(payload["tool_results"][0]["document_findings"]), 53)


if __name__ == "__main__":
    unittest.main()
