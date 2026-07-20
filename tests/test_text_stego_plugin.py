import asyncio
import base64
import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from dayi import doctor
from dayi.doctor import diagnose_python_capability
from dayi.reporter import ScanReport, export_markdown_writeup, write_json_report
from dayi.runner import DayiRunner
from dayi.text_stego import DEFAULT_HINT_LIMIT, VERBOSE_HINT_LIMIT
from dayi.tools._plugin import PluginPhase, PluginRegistry
from dayi.tools.text_stego_scanner import (
    MAX_WORKSPACE_TEXT_FILES,
    PLUGIN_SPECS,
    _discover_text_sources,
    run_text_stego,
)


FLAG = "SiberVatan{text_plugin}"
PATTERN = re.compile(r"SiberVatan\{.*?\}")


def _bits(value: str) -> str:
    return "".join(f"{byte:08b}" for byte in value.encode("utf-8"))


def _zero_width_base64(value: str) -> str:
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return "cover:" + "".join(
        "\u200b" if bit == "0" else "\u200c" for bit in _bits(encoded)
    )


class TextStegoPluginUnitTests(unittest.IsolatedAsyncioTestCase):
    def test_plugin_contract_is_core_only_and_deterministic(self) -> None:
        self.assertEqual(len(PLUGIN_SPECS), 1)
        plugin = PLUGIN_SPECS[0]
        self.assertEqual(plugin.plugin_id, "text_stego_scanner")
        self.assertEqual(plugin.phase, PluginPhase.ARCHIVE)
        self.assertEqual(plugin.priority, 12)
        self.assertEqual(plugin.required_executables, ())
        self.assertEqual(plugin.required_python_modules, ())

    def test_workspace_discovery_is_bounded_and_rejects_symlink_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            workspace = root / "workspace"
            outside = root / "outside.txt"
            target.write_bytes(b"target")
            outside.write_text("outside", encoding="utf-8")
            workspace.mkdir()
            (workspace / "escape.txt").symlink_to(outside)
            unsafe_name = "00-unsafe\u202e.txt"
            (workspace / unsafe_name).write_text("synthetic hidden name", encoding="utf-8")
            for index in range(MAX_WORKSPACE_TEXT_FILES + 5):
                (workspace / f"payload-{index:02d}.bin").write_text(
                    f"synthetic text {index}",
                    encoding="utf-8",
                )

            sources = _discover_text_sources(target, workspace)

        self.assertEqual(sources[0], (target, "target"))
        self.assertLessEqual(len(sources), MAX_WORKSPACE_TEXT_FILES + 1)
        self.assertFalse(any(path == outside for path, _source in sources))
        self.assertFalse(any(source == "escape.txt" for _path, source in sources))
        self.assertFalse(any("\u202e" in source for _path, source in sources))
        self.assertTrue(any("U+202E" in source for _path, source in sources))

    def test_doctor_declares_core_text_stego_without_running_a_scan(self) -> None:
        definition = next(
            item
            for item in doctor.PYTHON_CAPABILITY_DEFINITIONS
            if item.capability_id == "text_stego"
        )
        diagnostic = diagnose_python_capability(
            definition,
            find_spec=lambda _name: SimpleNamespace(
                origin="/package/dayi/text_stego.py",
                submodule_search_locations=None,
            ),
            distribution_version=lambda _name: "4.5.0",
            site_roots=(),
        )

        self.assertTrue(diagnostic.available)
        self.assertEqual(diagnostic.import_name, "dayi.text_stego")
        self.assertIn("bounded core text-steganography", diagnostic.capability)

    async def test_extensionless_content_detection_and_chain_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "payload.bin"
            target.write_text(_zero_width_base64(FLAG), encoding="utf-8")
            result = await run_text_stego(target, PATTERN)

        self.assertFalse(result.skipped)
        self.assertEqual(result.flags_found, [])
        self.assertEqual(
            result.extracted_flags,
            {"text_stego:zero_width>binary>base64": [FLAG]},
        )
        self.assertNotIn("\u200b", result.stdout)
        self.assertNotIn("\u200c", result.stdout)

    async def test_utf16_text_runs_and_binary_data_skips(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            utf16 = Path(tmpdir) / "message.data"
            utf16.write_bytes(b"\xff\xfe" + FLAG.encode("utf-16-le"))
            binary = Path(tmpdir) / "random.txt"
            binary.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00\xff" * 128)

            decoded = await run_text_stego(utf16, PATTERN)
            skipped = await run_text_stego(binary, PATTERN)

        self.assertIn(FLAG, [flag for hits in decoded.extracted_flags.values() for flag in hits])
        self.assertIn("text_stego:source_decode>utf-16-le-bom", decoded.extracted_flags)
        self.assertTrue(skipped.skipped)
        self.assertIn("detected classification", skipped.skip_reason)

    async def test_analysis_timeout_returns_a_bounded_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "slow.txt"
            target.write_text("ordinary text", encoding="utf-8")
            with patch(
                "dayi.tools.text_stego_scanner._await_text_analysis",
                new=AsyncMock(side_effect=asyncio.TimeoutError),
            ):
                result = await run_text_stego(
                    target,
                    PATTERN,
                    analysis_timeout=0.01,
                )

        self.assertTrue(result.timed_out)
        self.assertTrue(result.error)
        self.assertFalse(result.skipped)
        self.assertEqual(result.extracted_flags, {})
        self.assertNotIn(str(target), result.stderr)

    async def test_default_suppresses_low_candidates_and_verbose_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "noise"
            target.write_text("AB" * 100, encoding="ascii")
            quiet = await run_text_stego(target, PATTERN, verbose=False)
            verbose = await run_text_stego(target, PATTERN, verbose=True)

        self.assertNotIn("Bounded candidate hints:", quiet.stdout)
        self.assertIn("[low]", verbose.stdout)
        verbose_hints = [line for line in verbose.stdout.splitlines() if line.startswith("  [")]
        self.assertLessEqual(len(verbose_hints), VERBOSE_HINT_LIMIT)
        self.assertGreater(len(verbose_hints), DEFAULT_HINT_LIMIT)

    async def test_decoded_artifacts_use_existing_local_scanner(self) -> None:
        encoded = base64.b64encode(b"https://example.org/next").decode("ascii")
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "url.txt"
            target.write_text(encoded, encoding="ascii")
            with patch("socket.getaddrinfo") as dns, patch(
                "urllib.request.urlopen"
            ) as fetch:
                result = await run_text_stego(target, PATTERN)

        self.assertIn(
            ("url", "https://example.org/next"),
            [(finding.artifact_type, finding.preview) for finding in result.artifacts_found],
        )
        dns.assert_not_called()
        fetch.assert_not_called()

    async def test_ansi_and_bidi_never_reach_plugin_output_raw(self) -> None:
        ansi_flag = "".join(
            f"\x1b[31m{character}\x1b[0m" for character in FLAG
        )
        content = ansi_flag + "\nordinary\u202etext\u202c"
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "controls.txt"
            target.write_text(content, encoding="utf-8")
            result = await run_text_stego(target, PATTERN, verbose=True)

        self.assertNotIn("\x1b", result.stdout)
        self.assertNotIn("\u202e", result.stdout)
        self.assertNotIn("\u202c", result.stdout)
        self.assertIn(FLAG, [flag for hits in result.extracted_flags.values() for flag in hits])

    async def test_control_characters_remain_escaped_in_json_and_markdown(self) -> None:
        ansi_flag = "".join(
            f"\x1b[32m{character}\x1b[0m" for character in FLAG
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "unsafe.txt"
            target.write_text(ansi_flag + "\u202e", encoding="utf-8")
            result = await run_text_stego(target, PATTERN, verbose=True)
            report = ScanReport(
                target_file=str(target),
                flag_pattern=PATTERN.pattern,
                wordlist=None,
                started_at="start",
                finished_at="finish",
                all_flags=[FLAG],
                tool_results=[result],
            )
            json_path = root / "report.json"
            markdown_path = root / "writeup.md"
            write_json_report(report, json_path)
            with patch(
                "dayi.reporter.resolve_writeup_exporter",
                return_value=SimpleNamespace(
                    available=False,
                    exporter=None,
                    source_kind="unavailable",
                    status_code="not-found",
                    safe_detail="not found",
                ),
            ):
                export_markdown_writeup(report, markdown_path)
            serialized = json_path.read_text(encoding="utf-8") + markdown_path.read_text(encoding="utf-8")

        self.assertNotIn("\x1b", serialized)
        self.assertNotIn("\u202e", serialized)


class TextStegoRunnerAndReporterTests(unittest.TestCase):
    def test_runner_report_json_and_markdown_preserve_decoder_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "challenge"
            target.write_text(_zero_width_base64(FLAG), encoding="utf-8")
            runner = DayiRunner(
                target,
                PATTERN,
                registry=PluginRegistry(PLUGIN_SPECS),
                pattern_display=PATTERN.pattern,
            )
            report = asyncio.run(runner.run_all())
            json_path = root / "report.json"
            markdown_path = root / "writeup.md"
            write_json_report(report, json_path)
            with patch(
                "dayi.reporter.resolve_writeup_exporter",
                return_value=SimpleNamespace(
                    available=False,
                    exporter=None,
                    source_kind="unavailable",
                    status_code="not-found",
                    safe_detail="not found",
                ),
            ):
                export_markdown_writeup(report, markdown_path)

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")

        self.assertEqual(report.all_flags, [FLAG])
        self.assertEqual(
            payload["flag_attribution"][FLAG],
            ["text_stego:zero_width>binary>base64"],
        )
        self.assertIn(
            "text\\_stego:zero\\_width\\>binary\\>base64",
            markdown,
        )

    def test_duplicate_flag_candidates_are_deduplicated_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "bacon.txt"
            encoded = base64.b32encode(FLAG.encode()).decode().rstrip("=")
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            bits = "".join(f"{alphabet.index(character):05b}" for character in encoded)
            target.write_text("".join("A" if bit == "0" else "B" for bit in bits), encoding="ascii")
            first = asyncio.run(run_text_stego(target, PATTERN))
            second = asyncio.run(run_text_stego(target, PATTERN))

        first_flags = [flag for hits in first.extracted_flags.values() for flag in hits]
        self.assertEqual(first_flags, [FLAG])
        self.assertEqual(first.extracted_flags, second.extracted_flags)
        self.assertEqual(first.stdout, second.stdout)


if __name__ == "__main__":
    unittest.main()
