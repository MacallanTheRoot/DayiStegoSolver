import contextlib
import io
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import ANY, AsyncMock, Mock, patch

from dayi import cli
from dayi.reporter import ScanReport


def _report() -> ScanReport:
    return ScanReport(
        target_file="sample.bin",
        flag_pattern="built-in common CTF patterns",
        wordlist=None,
        started_at="start",
        finished_at="finish",
        all_flags=[],
        tool_results=[],
        flag_pattern_source="builtin",
    )


class CtfshitPathParsingTests(unittest.TestCase):
    def test_scan_help_includes_ctfshit_path_and_root_help_remains_valid(self) -> None:
        parser = cli.build_arg_parser()
        root_help = parser.format_help()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            cli.parse_cli_args(["scan", "--help"], parser)

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("usage: dayi", root_help)
        self.assertIn("--ctfshit-path PATH", output.getvalue())

    def test_explicit_and_legacy_scan_syntax_accept_ctfshit_path(self) -> None:
        explicit = cli.parse_cli_args(
            ["scan", "sample.bin", "--writeup", "writeup.md", "--ctfshit-path", "checkout"]
        )
        legacy = cli.parse_cli_args(
            ["sample.bin", "--writeup", "writeup.md", "--ctfshit-path", "checkout"]
        )

        self.assertEqual(explicit.ctfshit_path, Path("checkout"))
        self.assertEqual(vars(legacy), vars(explicit))

    def test_missing_ctfshit_path_value_is_an_argparse_usage_error(self) -> None:
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as raised:
            cli.parse_cli_args(["scan", "sample.bin", "--ctfshit-path"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--ctfshit-path", error.getvalue())

    def test_doctor_default_and_plugins_command_remain_compatible(self) -> None:
        doctor = cli.parse_cli_args(["doctor"])
        plugins = cli.parse_cli_args(["plugins", "list"])

        self.assertEqual(doctor.command, "doctor")
        self.assertEqual(plugins.command, "plugins")
        self.assertIsNone(doctor.ctfshit_path)
        self.assertFalse(hasattr(plugins, "ctfshit_path"))


class CtfshitPathSelectionTests(unittest.TestCase):
    def test_cli_path_overrides_environment(self) -> None:
        with patch.dict(os.environ, {"DAYI_CTFSHIT_PATH": "/environment"}):
            selected, source = cli._select_ctfshit_path(Path("cli-checkout"))

        self.assertEqual(selected, Path("cli-checkout"))
        self.assertEqual(source, "cli")

    def test_environment_path_is_used_without_cli_path(self) -> None:
        with patch.dict(os.environ, {"DAYI_CTFSHIT_PATH": "  env-checkout  "}):
            selected, source = cli._select_ctfshit_path(None)

        self.assertEqual(selected, Path("env-checkout"))
        self.assertEqual(source, "environment")

    def test_empty_and_whitespace_environment_values_are_ignored(self) -> None:
        for value in ("", " \t\n "):
            with self.subTest(value=value), patch.dict(
                os.environ, {"DAYI_CTFSHIT_PATH": value}
            ):
                selected, source = cli._select_ctfshit_path(None)
            self.assertIsNone(selected)
            self.assertIsNone(source)

    def test_absent_sources_leave_installed_and_automatic_resolution_reachable(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            selected, source = cli._select_ctfshit_path(None)

        self.assertIsNone(selected)
        self.assertIsNone(source)


class CtfshitPathExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, argv: list[str], environment_value: str | None):
        args = cli.parse_cli_args(argv)
        environment = {}
        if environment_value is not None:
            environment["DAYI_CTFSHIT_PATH"] = environment_value
        logger = Mock(spec=logging.Logger)
        with (
            patch.dict(os.environ, environment, clear=True),
            patch("dayi.cli.setup_logger", return_value=logger),
            patch("dayi.cli._run_analysis", new=AsyncMock(return_value=(_report(), 0))),
            patch("dayi.cli.write_report") as report_writer,
            patch("dayi.cli.export_markdown_writeup") as writeup_writer,
        ):
            code = await cli.async_main(args)
        return code, report_writer, writeup_writer

    async def test_selected_cli_path_reaches_reporter(self) -> None:
        code, report_writer, writeup_writer = await self._run(
            [
                "scan", "sample.bin", "--writeup", "nested/writeup.md",
                "--ctfshit-path", "cli-checkout",
            ],
            "/environment-checkout",
        )

        self.assertEqual(code, 0)
        report_writer.assert_called_once()
        writeup_writer.assert_called_once_with(
            ANY,
            Path("nested/writeup.md"),
            ctfshit_path=Path("cli-checkout"),
        )

    async def test_selected_environment_path_reaches_reporter(self) -> None:
        code, _report_writer, writeup_writer = await self._run(
            ["scan", "sample.bin", "--writeup", "writeup.md"],
            "environment-checkout",
        )

        self.assertEqual(code, 0)
        writeup_writer.assert_called_once_with(
            ANY,
            Path("writeup.md"),
            ctfshit_path=Path("environment-checkout"),
        )

    async def test_no_sources_passes_none_and_txt_json_reporting_stays_successful(self) -> None:
        for report_format in ("txt", "json"):
            with self.subTest(report_format=report_format):
                code, report_writer, writeup_writer = await self._run(
                    [
                        "scan", "sample.bin", "--format", report_format,
                        "--writeup", "writeup.md",
                    ],
                    None,
                )
                self.assertEqual(code, 0)
                report_writer.assert_called_once()
                writeup_writer.assert_called_once_with(
                    ANY,
                    Path("writeup.md"),
                    ctfshit_path=None,
                )

    async def test_environment_is_not_selected_without_writeup(self) -> None:
        args = cli.parse_cli_args(["scan", "sample.bin"])
        logger = Mock(spec=logging.Logger)
        with (
            patch("dayi.cli.setup_logger", return_value=logger),
            patch("dayi.cli._run_analysis", new=AsyncMock(return_value=(_report(), 0))),
            patch("dayi.cli.write_report"),
            patch("dayi.cli._select_ctfshit_path") as selector,
            patch("dayi.cli.export_markdown_writeup") as writeup_writer,
        ):
            code = await cli.async_main(args)

        self.assertEqual(code, 0)
        selector.assert_not_called()
        writeup_writer.assert_not_called()

    async def test_invalid_cli_path_produces_builtin_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            output = root / "cli-writeup.md"
            args = cli.parse_cli_args([
                "scan", "sample.bin", "--writeup", str(output),
                "--ctfshit-path", str(root / "missing-cli-checkout"),
            ])
            logger = Mock(spec=logging.Logger)
            with (
                patch("dayi.cli.setup_logger", return_value=logger),
                patch(
                    "dayi.cli._run_analysis",
                    new=AsyncMock(return_value=(_report(), 0)),
                ),
                patch("dayi.cli.write_report") as report_writer,
                patch(
                    "dayi.ctfshit_resolver.importlib_metadata.distribution",
                    side_effect=AssertionError("explicit path must be authoritative"),
                ),
            ):
                code = await cli.async_main(args)

            rendered = output.read_text(encoding="utf-8")

        self.assertEqual(code, 0)
        report_writer.assert_called_once()
        self.assertIn("# CTF Writeups", rendered)

    async def test_invalid_environment_path_produces_builtin_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            output = root / "environment-writeup.md"
            args = cli.parse_cli_args([
                "scan", "sample.bin", "--writeup", str(output),
            ])
            logger = Mock(spec=logging.Logger)
            with (
                patch.dict(
                    os.environ,
                    {"DAYI_CTFSHIT_PATH": str(root / "missing-env-checkout")},
                ),
                patch("dayi.cli.setup_logger", return_value=logger),
                patch(
                    "dayi.cli._run_analysis",
                    new=AsyncMock(return_value=(_report(), 0)),
                ),
                patch("dayi.cli.write_report") as report_writer,
                patch(
                    "dayi.ctfshit_resolver.importlib_metadata.distribution",
                    side_effect=AssertionError("explicit path must be authoritative"),
                ),
            ):
                code = await cli.async_main(args)

            rendered = output.read_text(encoding="utf-8")

        self.assertEqual(code, 0)
        report_writer.assert_called_once()
        self.assertIn("# CTF Writeups", rendered)


if __name__ == "__main__":
    unittest.main()
