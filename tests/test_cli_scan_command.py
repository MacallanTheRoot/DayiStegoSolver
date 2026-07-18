import contextlib
import io
import json
import logging
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from dayi import cli
from dayi.reporter import ScanReport, write_json_report, write_txt_report
from dayi.runner import DayiRunner


def _parse(argv: list[str]):
    return cli.parse_cli_args(argv)


class ScanCommandParsingTests(unittest.TestCase):
    def test_explicit_scan_accepts_options_before_and_after_target(self) -> None:
        first = _parse(["scan", "sample.png"])
        second = _parse([
            "scan", "--format", "json", "sample.png", "--flag", r"HTB\{[^}]+\}"
        ])
        self.assertEqual(first.command, "scan")
        self.assertEqual(first.target, Path("sample.png"))
        self.assertIsNone(first.flag)
        self.assertEqual(second.format, "json")
        self.assertEqual(second.flag, r"HTB\{[^}]+\}")

    def test_legacy_forms_normalize_to_explicit_namespace(self) -> None:
        cases = [
            ["sample.png"],
            ["sample.png", "--flag", "FLAG"],
            ["--flag", "FLAG", "sample.png"],
            ["--wordlist", "words.txt", "sample.png"],
            ["--workspace-dir", "/tmp/dayi", "sample.png"],
            ["sample.png", "--format", "json"],
        ]
        for legacy in cases:
            with self.subTest(legacy=legacy):
                explicit = _parse(["scan", *legacy])
                compatible = _parse(legacy)
                self.assertEqual(vars(compatible), vars(explicit))

    def test_missing_target_and_unknown_option_fail(self) -> None:
        for argv in (["scan"], ["scan", "sample.png", "--unknown"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as raised:
                _parse(list(argv))
            self.assertEqual(raised.exception.code, 2)

    def test_unknown_command_is_a_legacy_target_and_scan_filename_is_explicit(self) -> None:
        self.assertEqual(_parse(["unknown-command"]).target, Path("unknown-command"))
        self.assertEqual(_parse(["scan", "--", "scan"]).target, Path("scan"))

    def test_top_and_scan_help_short_circuit_without_runtime_startup(self) -> None:
        for argv in (["dayi", "--help"], ["dayi", "scan", "--help"]):
            with self.subTest(argv=argv):
                output = io.StringIO()
                with (
                    patch.object(sys, "argv", argv),
                    patch("dayi.cli.asyncio.run") as asyncio_run,
                    patch("dayi.cli.build_integration") as integration,
                    patch("dayi.cli.DayiRunner") as runner,
                    contextlib.redirect_stdout(output),
                ):
                    with self.assertRaises(SystemExit) as raised:
                        cli.main()
                self.assertEqual(raised.exception.code, 0)
                asyncio_run.assert_not_called()
                integration.assert_not_called()
                runner.assert_not_called()
                self.assertIn("usage:", output.getvalue())


class ScanCommandExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def _capture_runner(self, argv: list[str]) -> tuple[dict, int]:
        args = _parse(argv)
        captured: dict = {}

        class FakeRunner:
            def __init__(self, **kwargs) -> None:
                captured.update(kwargs)

            async def run_all(self) -> ScanReport:
                return ScanReport(
                    target_file=str(captured["target"]),
                    flag_pattern=captured["pattern_display"],
                    flag_pattern_source=captured["pattern_source"],
                    wordlist=None,
                    started_at="start",
                    finished_at="finish",
                    all_flags=[],
                    tool_results=[],
                )

        logger = Mock(spec=logging.Logger)
        with patch("dayi.cli.build_integration", return_value=None), patch(
            "dayi.cli.DayiRunner", FakeRunner
        ):
            _report, code = await cli._run_analysis(args, logger)
        return captured, code

    async def test_explicit_and_legacy_builtin_reach_same_runner_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.bin"
            target.write_bytes(b"CTF{sample}")
            explicit, explicit_code = await self._capture_runner(
                ["scan", str(target)]
            )
            legacy, legacy_code = await self._capture_runner([str(target)])
        self.assertEqual(explicit_code, 0)
        self.assertEqual(legacy_code, 0)
        self.assertEqual(explicit["pattern"].pattern, legacy["pattern"].pattern)
        self.assertEqual(explicit["pattern_source"], "builtin")
        self.assertEqual(legacy["pattern_source"], "builtin")

    async def test_custom_regex_reaches_runner_unchanged(self) -> None:
        raw = r"(CUSTOM)\{([^}]+)\}"
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.bin"
            target.write_bytes(b"CUSTOM{sample}")
            captured, code = await self._capture_runner(
                ["scan", str(target), "--flag", raw]
            )
        self.assertEqual(code, 0)
        self.assertEqual(captured["pattern"].pattern, raw)
        self.assertEqual(captured["pattern_display"], raw)
        self.assertEqual(captured["pattern_source"], "user")

    async def test_invalid_regex_starts_no_workspace_integration_or_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.bin"
            target.write_bytes(b"sample")
            args = _parse([
                "scan", str(target), "--flag", r"(a+)+$",
                "--workspace-dir", str(Path(tmpdir) / "workspaces"),
            ])
            logger = Mock(spec=logging.Logger)
            with (
                patch("dayi.cli.validate_workspace_parent") as validate_workspace,
                patch("dayi.cli.build_integration") as integration,
                patch("dayi.cli.DayiRunner") as runner,
            ):
                report, code = await cli._run_analysis(args, logger)
        self.assertIsNone(report)
        self.assertEqual(code, 1)
        validate_workspace.assert_not_called()
        integration.assert_not_called()
        runner.assert_not_called()


class PatternReportTests(unittest.TestCase):
    def _report(self, display: str, source: str) -> ScanReport:
        return ScanReport(
            target_file="sample.bin",
            flag_pattern=display,
            flag_pattern_source=source,
            wordlist=None,
            started_at="start",
            finished_at="finish",
            all_flags=[],
            tool_results=[],
        )

    def test_txt_and_json_include_pattern_display_and_source(self) -> None:
        for display, source in (
            (r"CTF\{[^}]+\}", "user"),
            ("built-in common CTF patterns", "builtin"),
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                txt = root / "report.txt"
                json_path = root / "report.json"
                write_txt_report(self._report(display, source), txt)
                write_json_report(self._report(display, source), json_path)
                rendered = txt.read_text(encoding="utf-8")
                payload = json.loads(json_path.read_text(encoding="utf-8"))
                self.assertIn(display, rendered)
                self.assertIn(source, rendered)
                self.assertEqual(payload["meta"]["flag_pattern"], display)
                self.assertEqual(payload["meta"]["flag_pattern_source"], source)

    def test_direct_runner_defaults_to_user_pattern_metadata(self) -> None:
        runner = DayiRunner(Path("sample.bin"), re.compile("FLAG"), registry=Mock())
        report = runner._build_report()
        self.assertEqual(report.flag_pattern, "FLAG")
        self.assertEqual(report.flag_pattern_source, "user")


if __name__ == "__main__":
    unittest.main()
