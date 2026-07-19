import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from dayi.persona import TerminalUI
from dayi.reporter import ToolResult, write_json_report
from dayi.runner import DayiRunner
from dayi.scanner import scan_artifacts
from dayi.tools._base import FileType
from dayi.tools._plugin import PluginPhase, discover_plugins, extraction_evidence_success
from dayi.tools.stegseek import PLUGIN_SPECS, run_stegseek


FLAG_PATTERN = re.compile(r"FLAG\{[^}]+\}")
STEGSEEK_SELF_URL = "https://github.com/RickdeJager/StegSeek"


class _ArtifactRecordingUI(TerminalUI):
    def __init__(self) -> None:
        self.artifacts: list[str] = []

    def show_artifact(self, message: str) -> None:
        self.artifacts.append(message)


class StegseekEligibilityTests(unittest.IsolatedAsyncioTestCase):
    async def _run_with_mocked_command(
        self,
        target: Path,
        wordlist: Path | None = None,
    ):
        command = AsyncMock(return_value=(1, "", "", 0.01, False))
        with patch(
            "dayi.tools.stegseek.is_tool_available", return_value=True
        ), patch("dayi.tools.stegseek.async_run_command", command):
            result = await run_stegseek(target, FLAG_PATTERN, wordlist)
        return result, command

    async def test_unsupported_real_formats_are_skipped(self) -> None:
        fixtures = {
            "target.pdf": b"%PDF-1.7\n",
            "target.pcap": b"\xd4\xc3\xb2\xa1" + b"\x00" * 20,
            "target.pcapng": b"\x0a\x0d\x0d\x0a" + b"\x00" * 20,
            "target.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 8,
            "target.zip": b"PK\x03\x04" + b"\x00" * 12,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            for filename, content in fixtures.items():
                with self.subTest(filename=filename):
                    target = Path(tmpdir) / filename
                    target.write_bytes(content)

                    result, command = await self._run_with_mocked_command(target)

                    self.assertTrue(result.skipped)
                    command.assert_not_called()
                    command.assert_not_awaited()

    async def test_unknown_binary_data_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"\x13\x37\x00\xff" * 4)

            result, command = await self._run_with_mocked_command(target)

        self.assertTrue(result.skipped)
        self.assertEqual(
            result.skip_reason,
            "stegseek requires JPEG/BMP/WAV; detected format: UNKNOWN",
        )
        command.assert_not_called()
        command.assert_not_awaited()

    async def test_skip_reason_does_not_use_runtime_enum_string_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"plain text\n")

            with patch.object(
                FileType,
                "__str__",
                return_value="runtime-dependent-enum-string",
            ):
                result, _ = await self._run_with_mocked_command(target)

        self.assertEqual(
            result.skip_reason,
            "stegseek requires JPEG/BMP/WAV; detected format: UNKNOWN",
        )

    async def test_misleading_jpg_extensions_are_skipped(self) -> None:
        fixtures = {
            "plain.jpg": b"plain text\n",
            "png.jpg": b"\x89PNG\r\n\x1a\n" + b"\x00" * 8,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            for filename, content in fixtures.items():
                with self.subTest(filename=filename):
                    target = Path(tmpdir) / filename
                    target.write_bytes(content)

                    result, command = await self._run_with_mocked_command(target)

                    self.assertTrue(result.skipped)
                    command.assert_not_awaited()

    async def test_supported_carriers_ignore_filename_extension(self) -> None:
        fixtures = {
            "jpeg.bin": b"\xff\xd8\xff" + b"\x00" * 13,
            "bitmap.data": b"BM" + b"\x00" * 14,
            "audio.payload": b"RIFF" + b"\x00" * 4 + b"WAVE" + b"\x00" * 4,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            for filename, content in fixtures.items():
                with self.subTest(filename=filename):
                    target = Path(tmpdir) / filename
                    target.write_bytes(content)

                    result, command = await self._run_with_mocked_command(target)

                    self.assertFalse(result.skipped)
                    command.assert_awaited_once()

    async def test_unsupported_result_contract_and_reason_are_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.png"
            target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)

            result, _ = await self._run_with_mocked_command(target)

        self.assertTrue(result.skipped)
        self.assertFalse(result.error)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.extraction_succeeded)
        self.assertEqual(
            result.skip_reason,
            "stegseek requires JPEG/BMP/WAV; detected format: PNG",
        )

    async def test_unsupported_input_does_not_enter_subprocess_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.zip"
            target.write_bytes(b"PK\x03\x04" + b"\x00" * 12)
            command = AsyncMock()
            temporary_directory = unittest.mock.Mock()

            with patch(
                "dayi.tools.stegseek.is_tool_available", return_value=True
            ), patch("dayi.tools.stegseek.async_run_command", command), patch(
                "dayi.tools.stegseek.tempfile.TemporaryDirectory",
                temporary_directory,
            ):
                await run_stegseek(target, FLAG_PATTERN, None)

        temporary_directory.assert_not_called()
        command.assert_not_called()
        command.assert_not_awaited()

    async def test_supported_input_preserves_existing_command_construction(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "carrier.bin"
            target.write_bytes(b"\xff\xd8\xff" + b"\x00" * 13)

            result, command = await self._run_with_mocked_command(target)

        args = command.await_args.args
        self.assertEqual(
            args[0],
            [
                "stegseek",
                "--crack",
                str(target),
                "/dev/null",
                args[0][4],
                "--quiet",
            ],
        )
        self.assertEqual(Path(args[0][4]).name, "stegseek_extracted")
        self.assertEqual(args[1:], ("stegseek", 300.0))
        self.assertEqual(result.command, args[0])

    async def test_supported_input_with_wordlist_preserves_command_construction(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "carrier.bin"
            target.write_bytes(b"BM" + b"\x00" * 14)
            wordlist = root / "words.txt"
            wordlist.write_text("password\n", encoding="utf-8")

            result, command = await self._run_with_mocked_command(target, wordlist)

        args = command.await_args.args
        self.assertEqual(
            args[0],
            ["stegseek", str(target), str(wordlist), args[0][3], "--quiet"],
        )
        self.assertEqual(Path(args[0][3]).name, "stegseek_extracted")
        self.assertEqual(args[1:], ("stegseek", 300.0))
        self.assertEqual(result.command, args[0])


class StegseekPluginInvariantTests(unittest.TestCase):
    def test_registry_contract_remains_unchanged(self) -> None:
        self.assertEqual(len(PLUGIN_SPECS), 1)
        plugin = PLUGIN_SPECS[0]
        self.assertEqual(plugin.plugin_id, "stegseek_main")
        self.assertEqual(plugin.phase, PluginPhase.MAIN_PRIMARY)
        self.assertEqual(plugin.priority, 10)
        self.assertFalse(plugin.requires_wordlist)
        self.assertFalse(plugin.requires_mini_wordlist)
        self.assertEqual(
            plugin.skip_if_phase_succeeded,
            (PluginPhase.MINI_BRUTE_FORCE,),
        )
        self.assertEqual(plugin.required_executables, ("stegseek",))
        self.assertIs(plugin.success_evaluator, extraction_evidence_success)

        plugin_ids = [item.plugin_id for item in discover_plugins().plugins]
        position = plugin_ids.index("stegseek_main")
        self.assertEqual(position, 16)
        self.assertEqual(plugin_ids[position - 1], "outguess_mini_bf")
        self.assertEqual(plugin_ids[position + 1], "steghide_main_bf")


class StegseekArtifactFilteringTests(unittest.TestCase):
    def _attach(
        self,
        *,
        stdout: str = "",
        stderr: str = "",
        tool_name: str = "stegseek",
    ) -> tuple[DayiRunner, ToolResult, _ArtifactRecordingUI]:
        ui = _ArtifactRecordingUI()
        runner = DayiRunner(Path("carrier.jpg"), FLAG_PATTERN, ui=ui)
        result = ToolResult(
            tool_name=tool_name,
            command=[tool_name],
            return_code=0,
            stdout=stdout,
            stderr=stderr,
            flags_found=[],
            elapsed_seconds=0.01,
        )
        runner._attach_artifacts(result)
        return runner, result, ui

    def test_self_url_in_stderr_is_not_a_target_artifact(self) -> None:
        _, result, ui = self._attach(stderr=STEGSEEK_SELF_URL)

        self.assertEqual(result.artifacts_found, [])
        self.assertEqual(ui.artifacts, [])

    def test_self_url_in_stdout_is_not_a_target_artifact(self) -> None:
        _, result, ui = self._attach(stdout=STEGSEEK_SELF_URL)

        self.assertEqual(result.artifacts_found, [])
        self.assertEqual(ui.artifacts, [])

    def test_typical_banner_self_url_is_not_a_target_artifact(self) -> None:
        banner = f"StegSeek 0.6 - {STEGSEEK_SELF_URL}\n"

        _, result, _ = self._attach(stdout=banner)

        self.assertEqual(result.artifacts_found, [])

    def test_same_url_in_target_text_file_remains_reportable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.txt"
            target.write_text(STEGSEEK_SELF_URL, encoding="utf-8")

            findings = scan_artifacts(
                target.read_text(encoding="utf-8"),
                source=str(target),
            )

        self.assertEqual(
            [(item.artifact_type, item.preview) for item in findings],
            [("url", STEGSEEK_SELF_URL)],
        )

    def test_same_url_in_target_metadata_output_remains_reportable(self) -> None:
        _, result, _ = self._attach(
            stdout=f"[EXIF] Comment: {STEGSEEK_SELF_URL}",
            tool_name="exiftool",
        )

        self.assertEqual(
            [(item.artifact_type, item.preview) for item in result.artifacts_found],
            [("url", STEGSEEK_SELF_URL)],
        )
        self.assertEqual(result.artifacts_found[0].source, "exiftool/stdout")

    def test_same_url_in_existing_extracted_evidence_remains_reportable(self) -> None:
        runner = DayiRunner(Path("carrier.jpg"), FLAG_PATTERN)
        extracted_finding = scan_artifacts(
            STEGSEEK_SELF_URL,
            source="stegseek/extracted-content",
        )[0]
        result = ToolResult(
            tool_name="stegseek",
            command=["stegseek"],
            return_code=0,
            stdout=STEGSEEK_SELF_URL,
            stderr="",
            flags_found=[],
            elapsed_seconds=0.01,
            artifacts_found=[extracted_finding],
        )

        runner._attach_artifacts(result)

        self.assertEqual(result.artifacts_found, [extracted_finding])

    def test_other_urls_in_both_stegseek_streams_remain_reportable(self) -> None:
        expected = {
            "stegseek/stdout": "https://example.org/from-stdout",
            "stegseek/stderr": "https://example.net/from-stderr",
        }

        _, result, _ = self._attach(
            stdout=expected["stegseek/stdout"],
            stderr=expected["stegseek/stderr"],
        )

        self.assertEqual(
            {item.source: item.preview for item in result.artifacts_found},
            expected,
        )

    def test_self_url_removal_preserves_another_url_on_the_same_line(self) -> None:
        legitimate_url = "https://challenge.example.org/next"
        line = f"StegSeek 0.6 - {STEGSEEK_SELF_URL} next: {legitimate_url}"

        _, result, _ = self._attach(stderr=line)

        self.assertEqual(
            [item.preview for item in result.artifacts_found],
            [legitimate_url],
        )

    def test_report_terminal_and_json_exclude_only_the_artifact(self) -> None:
        banner = f"StegSeek 0.6 - {STEGSEEK_SELF_URL}\n"
        runner, result, ui = self._attach(stdout=banner)
        runner._partial_results.append(result)
        report = runner._build_report()

        self.assertEqual(report.all_artifacts, [])
        self.assertEqual(ui.artifacts, [])

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            write_json_report(report, output)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["artifacts_found"], [])
        self.assertEqual(payload["tool_results"][0]["artifacts_found"], [])
        self.assertEqual(payload["tool_results"][0]["stdout"], banner)


class StegseekOutputPreservationTests(unittest.IsolatedAsyncioTestCase):
    async def _run_with_output(self, stdout: str, stderr: str) -> ToolResult:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "carrier.jpg"
            target.write_bytes(b"\xff\xd8\xff" + b"\x00" * 13)
            command = AsyncMock(return_value=(1, stdout, stderr, 0.01, False))
            with patch(
                "dayi.tools.stegseek.is_tool_available", return_value=True
            ), patch("dayi.tools.stegseek.async_run_command", command):
                return await run_stegseek(target, FLAG_PATTERN, None)

    async def test_flags_and_raw_diagnostics_are_preserved(self) -> None:
        stdout = f"StegSeek 0.6 - {STEGSEEK_SELF_URL}\nFLAG{{stdout_kept}}"
        stderr = f"diagnostic {STEGSEEK_SELF_URL}\nFLAG{{stderr_kept}}"

        result = await self._run_with_output(stdout, stderr)

        self.assertEqual(result.stdout, stdout)
        self.assertEqual(result.stderr, stderr)
        self.assertEqual(
            result.flags_found,
            ["FLAG{stdout_kept}", "FLAG{stderr_kept}"],
        )

    async def test_extraction_success_behavior_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "carrier.jpg"
            target.write_bytes(b"\xff\xd8\xff" + b"\x00" * 13)

            async def extract(cmd, tool_name, timeout):
                Path(cmd[4]).write_text("FLAG{embedded_kept}", encoding="utf-8")
                return 0, "", "", 0.01, False

            with patch(
                "dayi.tools.stegseek.is_tool_available", return_value=True
            ), patch("dayi.tools.stegseek.async_run_command", side_effect=extract):
                result = await run_stegseek(target, FLAG_PATTERN, None)

        self.assertTrue(result.extraction_succeeded)
        self.assertEqual(
            result.extracted_flags,
            {"stegseek_extracted": ["FLAG{embedded_kept}"]},
        )
        self.assertEqual(result.flags_found, ["FLAG{embedded_kept}"])


if __name__ == "__main__":
    unittest.main()
