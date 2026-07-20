import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from dayi.extraction import validate_extracted_payload
from dayi.reporter import ToolResult
from dayi.runner import DayiRunner
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
    extraction_evidence_success,
)
from dayi.tools.outguess import run_outguess_bruteforce


FLAG_PATTERN = re.compile(r"FLAG\{[^}]+\}")


def _result(name: str, *, stdout: str = "") -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name],
        return_code=0,
        stdout=stdout,
        stderr="",
        flags_found=[],
        elapsed_seconds=0.001,
    )


class ExtractionEvidenceTests(unittest.TestCase):
    def test_known_magic_meaningful_text_and_flags_are_verified(self) -> None:
        fixtures = (
            (b"\x89PNG\r\n\x1a\n" + b"\x00" * 32, "PNG", False, ()),
            (b"this is clearly meaningful extracted text\n", None, True, ()),
            (
                b"\x00" * 20 + b"FLAG{verified_payload}",
                None,
                False,
                ("FLAG{verified_payload}",),
            ),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            for index, (content, magic, meaningful, flags) in enumerate(fixtures):
                with self.subTest(index=index):
                    output = Path(tmpdir) / f"output-{index}.bin"
                    output.write_bytes(content)
                    evidence = validate_extracted_payload(output, FLAG_PATTERN)
                    self.assertTrue(evidence.verified)
                    self.assertEqual(evidence.known_magic, magic)
                    self.assertEqual(evidence.meaningful_text, meaningful)
                    self.assertEqual(evidence.flags_found, flags)

    def test_identical_baseline_and_meaningless_data_are_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            baseline_path = root / "baseline.bin"
            baseline_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
            baseline = validate_extracted_payload(baseline_path, FLAG_PATTERN)

            identical = root / "identical.bin"
            identical.write_bytes(baseline_path.read_bytes())
            identical_evidence = validate_extracted_payload(
                identical,
                FLAG_PATTERN,
                baseline=baseline,
            )
            meaningless = root / "meaningless.bin"
            meaningless.write_bytes(b"\x01\x02\x03\x04" * 16)
            meaningless_evidence = validate_extracted_payload(
                meaningless,
                FLAG_PATTERN,
                baseline=baseline,
            )

        self.assertFalse(identical_evidence.differs_from_baseline)
        self.assertFalse(identical_evidence.verified)
        self.assertTrue(meaningless_evidence.differs_from_baseline)
        self.assertFalse(meaningless_evidence.verified)


class OutguessValidationTests(unittest.IsolatedAsyncioTestCase):
    async def _run(
        self,
        baseline_data: bytes | None,
        candidate_data: bytes | None,
    ) -> tuple[ToolResult, AsyncMock, list[Path]]:
        output_paths: list[Path] = []

        async def command(args, *_unused):
            output = Path(args[-1])
            output_paths.append(output)
            data = (
                baseline_data
                if args[2].startswith("dayi-invalid-")
                else candidate_data
            )
            if data is not None:
                output.write_bytes(data)
            return 0, "", "", 0.001, False

        mocked_command = AsyncMock(side_effect=command)
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "carrier.jpg"
            target.write_bytes(b"\xff\xd8\xff" + b"\x00" * 32)
            with patch(
                "dayi.tools.outguess.is_tool_available", return_value=True
            ), patch(
                "dayi.tools.outguess.async_run_command", mocked_command
            ):
                result = await run_outguess_bruteforce(
                    target,
                    FLAG_PATTERN,
                    wordlist_data=["candidate"],
                    max_concurrent=1,
                )
            self.assertTrue(all(not path.exists() for path in output_paths))

        return result, mocked_command, output_paths

    async def test_rc_zero_without_output_is_not_success(self) -> None:
        result, command, _ = await self._run(None, None)

        self.assertEqual(command.await_count, 2)
        self.assertFalse(result.extraction_succeeded)
        self.assertFalse(extraction_evidence_success(result))
        self.assertEqual(result.return_code, 1)
        self.assertIn("Bulunan şifre: Yok", result.stdout)

    async def test_rc_zero_with_empty_output_is_not_success(self) -> None:
        result, _, _ = await self._run(b"", b"")

        self.assertFalse(result.extraction_succeeded)
        self.assertFalse(extraction_evidence_success(result))

    async def test_identical_baseline_output_is_not_success(self) -> None:
        false_payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        result, _, _ = await self._run(false_payload, false_payload)

        self.assertFalse(result.extraction_succeeded)
        self.assertIn("Doğrulanmamış çıktılar: 1", result.stdout)

    async def test_different_meaningless_output_is_not_success(self) -> None:
        result, _, _ = await self._run(
            b"\x01\x02\x03\x04" * 16,
            b"\x05\x06\x07\x08" * 16,
        )

        self.assertFalse(result.extraction_succeeded)
        self.assertFalse(extraction_evidence_success(result))

    async def test_known_magic_output_is_verified(self) -> None:
        result, _, _ = await self._run(
            b"baseline-noise",
            b"%PDF-1.7\n" + b"\x00" * 32,
        )

        self.assertTrue(result.extraction_succeeded)
        self.assertTrue(extraction_evidence_success(result))
        self.assertIn("Bulunan şifre: candidate", result.stdout)

    async def test_meaningful_printable_output_is_verified(self) -> None:
        result, _, _ = await self._run(
            b"baseline-noise",
            b"this is clearly meaningful extracted text\n",
        )

        self.assertTrue(result.extraction_succeeded)

    async def test_flag_output_is_verified(self) -> None:
        result, _, _ = await self._run(
            b"baseline-noise",
            b"FLAG{outguess_verified}",
        )

        self.assertTrue(result.extraction_succeeded)
        self.assertEqual(result.flags_found, ["FLAG{outguess_verified}"])

    async def test_temporary_outputs_are_removed(self) -> None:
        _, _, output_paths = await self._run(
            b"baseline-noise",
            b"\x01\x02\x03\x04" * 16,
        )

        self.assertEqual(len(output_paths), 2)
        self.assertTrue(all(not path.exists() for path in output_paths))


class OutguessPhaseControlTests(unittest.IsolatedAsyncioTestCase):
    async def _run_scenario(self, candidate_data: bytes) -> dict[str, int]:
        calls = {"stegseek_main": 0, "steghide_main_bf": 0, "outguess_main_bf": 0}

        async def command(args, *_unused):
            output = Path(args[-1])
            data = (
                b"baseline-noise"
                if args[2].startswith("dayi-invalid-")
                else candidate_data
            )
            output.write_bytes(data)
            return 0, "", "", 0.001, False

        async def source(_context: PluginContext) -> ToolResult:
            return _result("source", stdout="candidate")

        async def mini(context: PluginContext) -> ToolResult:
            return await run_outguess_bruteforce(
                context.target,
                context.flag_pattern,
                wordlist_data=list(context.mini_wordlist),
                max_concurrent=1,
            )

        def main(plugin_id: str):
            async def run(_context: PluginContext) -> ToolResult:
                calls[plugin_id] += 1
                return _result(plugin_id)

            return run

        skip_mini = (PluginPhase.MINI_BRUTE_FORCE,)
        registry = PluginRegistry((
            ToolPlugin(
                "source",
                PluginPhase.CONCURRENT,
                1,
                source,
                contributes_to_mini_wordlist=True,
            ),
            ToolPlugin(
                "outguess_mini_bf",
                PluginPhase.MINI_BRUTE_FORCE,
                1,
                mini,
                requires_mini_wordlist=True,
                success_evaluator=extraction_evidence_success,
            ),
            ToolPlugin(
                "stegseek_main",
                PluginPhase.MAIN_PRIMARY,
                1,
                main("stegseek_main"),
                skip_if_phase_succeeded=skip_mini,
            ),
            ToolPlugin(
                "steghide_main_bf",
                PluginPhase.MAIN_FALLBACK,
                1,
                main("steghide_main_bf"),
                requires_wordlist=True,
                skip_if_phase_succeeded=skip_mini,
            ),
            ToolPlugin(
                "outguess_main_bf",
                PluginPhase.MAIN_FINAL,
                1,
                main("outguess_main_bf"),
                requires_wordlist=True,
                skip_if_phase_succeeded=skip_mini,
            ),
        ))

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "carrier.jpg"
            target.write_bytes(b"\xff\xd8\xff" + b"\x00" * 32)
            wordlist = root / "wordlist.txt"
            wordlist.write_text("candidate\n", encoding="utf-8")
            with patch(
                "dayi.tools.outguess.is_tool_available", return_value=True
            ), patch("dayi.tools.outguess.async_run_command", side_effect=command):
                await DayiRunner(
                    target,
                    FLAG_PATTERN,
                    wordlist=wordlist,
                    registry=registry,
                ).run_all()

        return calls

    async def test_false_positive_does_not_succeed_phase_or_skip_main(self) -> None:
        calls = await self._run_scenario(b"\x01\x02\x03\x04" * 16)

        self.assertEqual(calls, {
            "stegseek_main": 1,
            "steghide_main_bf": 1,
            "outguess_main_bf": 1,
        })

    async def test_verified_extraction_retains_intended_skip_behavior(self) -> None:
        calls = await self._run_scenario(b"%PDF-1.7\n" + b"\x00" * 32)

        self.assertEqual(calls, {
            "stegseek_main": 0,
            "steghide_main_bf": 0,
            "outguess_main_bf": 0,
        })


if __name__ == "__main__":
    unittest.main()
