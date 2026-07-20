import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dayi.extraction import MAX_EXTRACTION_VALIDATION_BYTES
from dayi.reporter import ToolResult
from dayi.runner import DayiRunner
from dayi.text_stego import (
    MAX_ANALYSIS_CHARACTERS,
    MAX_DECODED_CHARACTERS,
    analyze_text_input,
    detect_text_bytes,
)
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
    extraction_evidence_success,
)
from dayi.tools.outguess import run_outguess_bruteforce


FLAG_PATTERN = re.compile(r"SiberVatan\{[^}]+\}")
CANDIDATE_PAYLOAD = b"%PDF-1.7\n" + b"\x00" * 32


def _tool_result(name: str, *, stdout: str = "") -> ToolResult:
    return ToolResult(name, [name], 0, stdout, "", [], 0.001)


class InvalidOutGuessBaselineTests(unittest.IsolatedAsyncioTestCase):
    async def _run(
        self,
        *,
        baseline_data: bytes | None,
        baseline_rc: int = 0,
        baseline_timed_out: bool = False,
        candidate_data: bytes = CANDIDATE_PAYLOAD,
    ) -> ToolResult:
        async def command(args, *_unused):
            output = Path(args[-1])
            is_baseline = args[2].startswith("dayi-invalid-")
            data = baseline_data if is_baseline else candidate_data
            if data is not None:
                output.write_bytes(data)
            if is_baseline:
                return (
                    baseline_rc,
                    "",
                    "",
                    0.001,
                    baseline_timed_out,
                )
            return 0, "", "", 0.001, False

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "carrier.jpg"
            target.write_bytes(b"\xff\xd8\xff" + b"\x00" * 32)
            with (
                patch("dayi.tools.outguess.is_tool_available", return_value=True),
                patch(
                    "dayi.tools.outguess.async_run_command",
                    side_effect=command,
                ),
            ):
                return await run_outguess_bruteforce(
                    target,
                    FLAG_PATTERN,
                    wordlist_data=["wrong-password"],
                    max_concurrent=1,
                )

    async def test_timeout_baseline_fails_closed(self) -> None:
        result = await self._run(
            baseline_data=b"baseline output",
            baseline_timed_out=True,
        )
        self.assertFalse(result.extraction_succeeded)
        self.assertFalse(extraction_evidence_success(result))

    async def test_nonzero_baseline_fails_closed(self) -> None:
        result = await self._run(
            baseline_data=b"baseline output",
            baseline_rc=1,
        )
        self.assertFalse(result.extraction_succeeded)

    async def test_missing_and_oversized_baselines_fail_closed(self) -> None:
        for baseline_data in (
            None,
            b"x" * (MAX_EXTRACTION_VALIDATION_BYTES + 1),
        ):
            with self.subTest(size=None if baseline_data is None else len(baseline_data)):
                result = await self._run(baseline_data=baseline_data)
                self.assertFalse(result.extraction_succeeded)
                self.assertEqual(result.return_code, 1)
                self.assertIn("Bulunan şifre: Yok", result.stdout)

    async def test_valid_baseline_allows_distinct_verified_candidate(self) -> None:
        result = await self._run(baseline_data=b"bounded baseline noise")
        self.assertTrue(result.extraction_succeeded)
        self.assertIn("Bulunan şifre: wrong-password", result.stdout)

    async def test_baseline_failure_keeps_fallback_phase_available(self) -> None:
        fallback_calls = 0

        async def command(args, *_unused):
            output = Path(args[-1])
            if not args[2].startswith("dayi-invalid-"):
                output.write_bytes(CANDIDATE_PAYLOAD)
            return 0, "", "", 0.001, False

        async def source(_context: PluginContext) -> ToolResult:
            return _tool_result("source", stdout="wrong-password")

        async def mini(context: PluginContext) -> ToolResult:
            return await run_outguess_bruteforce(
                context.target,
                context.flag_pattern,
                wordlist_data=list(context.mini_wordlist),
                max_concurrent=1,
            )

        async def fallback(_context: PluginContext) -> ToolResult:
            nonlocal fallback_calls
            fallback_calls += 1
            return _tool_result("stegseek_main")

        registry = PluginRegistry((
            ToolPlugin(
                "source", PluginPhase.CONCURRENT, 1, source,
                contributes_to_mini_wordlist=True,
            ),
            ToolPlugin(
                "outguess_mini_bf", PluginPhase.MINI_BRUTE_FORCE, 1, mini,
                requires_mini_wordlist=True,
                success_evaluator=extraction_evidence_success,
            ),
            ToolPlugin(
                "stegseek_main", PluginPhase.MAIN_PRIMARY, 1, fallback,
                skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,),
            ),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "carrier.jpg"
            target.write_bytes(b"\xff\xd8\xff" + b"\x00" * 32)
            with (
                patch("dayi.tools.outguess.is_tool_available", return_value=True),
                patch(
                    "dayi.tools.outguess.async_run_command",
                    side_effect=command,
                ),
            ):
                await DayiRunner(
                    target, FLAG_PATTERN, registry=registry
                ).run_all()

        self.assertEqual(fallback_calls, 1)


class RetainedTextDirectFlagTests(unittest.TestCase):
    @staticmethod
    def _flags(text: str) -> set[str]:
        with (
            patch("dayi.text_stego._bacon_candidates"),
            patch("dayi.text_stego._whitespace_candidates"),
            patch("dayi.text_stego._zero_width_candidates"),
            patch("dayi.text_stego._homoglyph_candidates"),
            patch("dayi.text_stego._structural_candidates"),
            patch("dayi.text_stego._ghost_candidates"),
            patch("dayi.text_stego._common_children", return_value=[]),
        ):
            analysis = analyze_text_input(
                detect_text_bytes(text.encode("utf-8")), FLAG_PATTERN
            )
        return {
            flag
            for candidate in analysis.candidates
            for flag in candidate.flags_found
        }

    def test_direct_flag_after_decoder_window_is_found(self) -> None:
        flag = "SiberVatan{after_decoder_window}"
        text = "x" * (MAX_ANALYSIS_CHARACTERS + 128) + flag
        self.assertIn(flag, self._flags(text))

    def test_direct_flag_near_retained_text_limit_is_found(self) -> None:
        flag = "SiberVatan{near_retained_limit}"
        text = "x" * (MAX_DECODED_CHARACTERS - len(flag) - 1) + flag
        self.assertIn(flag, self._flags(text))

    def test_expensive_decoders_receive_only_the_analysis_window(self) -> None:
        text = "ordinary bounded prose " * 80_000
        observed: list[int] = []

        def record(value, *_args):
            observed.append(len(value))

        with (
            patch("dayi.text_stego._bacon_candidates", side_effect=record),
            patch("dayi.text_stego._zero_width_candidates", side_effect=record),
            patch("dayi.text_stego._homoglyph_candidates", side_effect=record),
            patch("dayi.text_stego._structural_candidates", side_effect=record),
            patch("dayi.text_stego._ghost_candidates", side_effect=record),
            patch("dayi.text_stego._common_children", return_value=[]),
        ):
            analyze_text_input(
                detect_text_bytes(text.encode("utf-8")), FLAG_PATTERN
            )

        self.assertTrue(observed)
        self.assertTrue(all(size <= MAX_ANALYSIS_CHARACTERS for size in observed))

    def test_ordinary_large_text_creates_no_flag(self) -> None:
        text = ("This is ordinary local prose without a secret. " * 50_000)
        self.assertEqual(self._flags(text), set())


if __name__ == "__main__":
    unittest.main()
