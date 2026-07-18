import logging
import re
import tempfile
import unittest
from pathlib import Path

from dayi.persona import TerminalUI
from dayi.reporter import ToolResult
from dayi.runner import DayiRunner
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
    extraction_evidence_success,
)


def _result(
    name: str,
    *,
    return_code: int | None = 1,
    skipped: bool = False,
    timed_out: bool = False,
    error: bool = False,
    extraction_succeeded: bool = False,
) -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name],
        return_code=return_code,
        stdout="",
        stderr="",
        flags_found=[],
        elapsed_seconds=0.001,
        skipped=skipped,
        timed_out=timed_out,
        error=error,
        extraction_succeeded=extraction_succeeded,
        skip_reason="unavailable" if skipped else "",
    )


class _PhaseRecordingUI(TerminalUI):
    def __init__(self) -> None:
        self.started: list[str] = []

    def phase_started(self, phase: str, plugins: tuple[str, ...]) -> None:
        self.started.append(phase)


class BruteForcePhaseControlTests(unittest.IsolatedAsyncioTestCase):
    async def _run(
        self,
        registry: PluginRegistry,
        root: Path,
        ui: TerminalUI | None = None,
    ):
        target = root / "target.bin"
        target.write_bytes(b"fixture")
        wordlist = root / "wordlist.txt"
        wordlist.write_text("candidate\n", encoding="utf-8")
        return await DayiRunner(
            target,
            re.compile(r"FLAG\{[^}]+\}"),
            wordlist=wordlist,
            registry=registry,
            ui=ui,
        ).run_all()

    @staticmethod
    def _source_plugin():
        async def source(context: PluginContext) -> ToolResult:
            result = _result("source", return_code=0)
            result.stdout = "candidate"
            return result

        return ToolPlugin(
            "source",
            PluginPhase.CONCURRENT,
            1,
            source,
            contributes_to_mini_wordlist=True,
        )

    async def test_genuine_mini_success_skips_only_declared_redundant_work(self) -> None:
        calls = {"mini": 0, "primary": 0, "fallback": 0, "final": 0, "unrelated": 0}

        async def mini(context: PluginContext) -> ToolResult:
            calls["mini"] += 1
            return _result(
                "mini", return_code=0, extraction_succeeded=True
            )

        def main_runner(name: str):
            async def run(context: PluginContext) -> ToolResult:
                calls[name] += 1
                return _result(name)

            return run

        skip_mini = (PluginPhase.MINI_BRUTE_FORCE,)
        registry = PluginRegistry((
            self._source_plugin(),
            ToolPlugin(
                "mini", PluginPhase.MINI_BRUTE_FORCE, 1, mini,
                requires_mini_wordlist=True,
                success_evaluator=extraction_evidence_success,
            ),
            ToolPlugin(
                "primary", PluginPhase.MAIN_PRIMARY, 1,
                main_runner("primary"), requires_wordlist=True,
                skip_if_phase_succeeded=skip_mini,
            ),
            ToolPlugin(
                "fallback", PluginPhase.MAIN_FALLBACK, 1,
                main_runner("fallback"), requires_wordlist=True,
                skip_if_phase_succeeded=skip_mini,
            ),
            ToolPlugin(
                "final", PluginPhase.MAIN_FINAL, 1,
                main_runner("final"), requires_wordlist=True,
                skip_if_phase_succeeded=skip_mini,
            ),
            ToolPlugin(
                "unrelated", PluginPhase.MAIN_FINAL, 2,
                main_runner("unrelated"), requires_wordlist=True,
            ),
        ))
        ui = _PhaseRecordingUI()

        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertLogs("dayi", level=logging.INFO) as captured:
                report = await self._run(registry, Path(tmpdir), ui)

        self.assertEqual(calls, {
            "mini": 1, "primary": 0, "fallback": 0, "final": 0, "unrelated": 1,
        })
        self.assertNotIn("primary", [item.tool_name for item in report.tool_results])
        self.assertNotIn(PluginPhase.MAIN_PRIMARY.name, ui.started)
        self.assertNotIn(PluginPhase.MAIN_FALLBACK.name, ui.started)
        self.assertIn(PluginPhase.MAIN_FINAL.name, ui.started)
        logs = "\n".join(captured.output)
        self.assertIn("gereksiz ilan edilen eklentiler çalıştırılmayacak", logs)
        self.assertNotIn("Ana rockyou turunu atlıyorum", logs)

    async def test_unsuccessful_mini_runs_main_once(self) -> None:
        calls = {"mini": 0, "main": 0}

        async def mini(context: PluginContext) -> ToolResult:
            calls["mini"] += 1
            return _result("mini", return_code=1)

        async def main(context: PluginContext) -> ToolResult:
            calls["main"] += 1
            return _result("main")

        registry = PluginRegistry((
            self._source_plugin(),
            ToolPlugin(
                "mini", PluginPhase.MINI_BRUTE_FORCE, 1, mini,
                requires_mini_wordlist=True,
                success_evaluator=extraction_evidence_success,
            ),
            ToolPlugin(
                "main", PluginPhase.MAIN_FALLBACK, 1, main,
                requires_wordlist=True,
                skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,),
            ),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            await self._run(registry, Path(tmpdir))
        self.assertEqual(calls, {"mini": 1, "main": 1})

    async def test_zero_exit_without_extraction_evidence_does_not_skip_main(self) -> None:
        self.assertFalse(extraction_evidence_success(_result("mini", return_code=0)))
        calls = {"main": 0}

        async def mini(context: PluginContext) -> ToolResult:
            return _result("mini", return_code=0)

        async def main(context: PluginContext) -> ToolResult:
            calls["main"] += 1
            return _result("main")

        registry = PluginRegistry((
            self._source_plugin(),
            ToolPlugin(
                "mini", PluginPhase.MINI_BRUTE_FORCE, 1, mini,
                requires_mini_wordlist=True,
                success_evaluator=extraction_evidence_success,
            ),
            ToolPlugin(
                "main", PluginPhase.MAIN_FALLBACK, 1, main,
                requires_wordlist=True,
                skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,),
            ),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            await self._run(registry, Path(tmpdir))
        self.assertEqual(calls["main"], 1)

    async def test_mini_failure_states_do_not_suppress_main(self) -> None:
        async def skipped(context: PluginContext) -> ToolResult:
            return _result("mini", skipped=True)

        async def timed_out(context: PluginContext) -> ToolResult:
            return _result("mini", timed_out=True)

        async def errored(context: PluginContext) -> ToolResult:
            raise RuntimeError("plugin failure")

        async def unavailable(context: PluginContext) -> ToolResult:
            result = _result("mini", skipped=True)
            result.skip_reason = "external tool is unavailable"
            return result

        for label, mini_runner in (
            ("skipped", skipped),
            ("timed_out", timed_out),
            ("errored", errored),
            ("unavailable", unavailable),
        ):
            with self.subTest(label=label):
                main_calls = 0

                async def main(context: PluginContext) -> ToolResult:
                    nonlocal main_calls
                    main_calls += 1
                    return _result("main")

                registry = PluginRegistry((
                    self._source_plugin(),
                    ToolPlugin(
                        "mini", PluginPhase.MINI_BRUTE_FORCE, 1, mini_runner,
                        requires_mini_wordlist=True,
                        success_evaluator=extraction_evidence_success,
                    ),
                    ToolPlugin(
                        "main", PluginPhase.MAIN_FALLBACK, 1, main,
                        requires_wordlist=True,
                        skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,),
                    ),
                ))
                with tempfile.TemporaryDirectory() as tmpdir:
                    await self._run(registry, Path(tmpdir))
                self.assertEqual(main_calls, 1)

    async def test_empty_mini_wordlist_skips_mini_but_runs_main(self) -> None:
        calls = {"mini": 0, "main": 0}

        async def mini(context: PluginContext) -> ToolResult:
            calls["mini"] += 1
            return _result("mini", extraction_succeeded=True)

        async def main(context: PluginContext) -> ToolResult:
            calls["main"] += 1
            return _result("main")

        registry = PluginRegistry((
            ToolPlugin(
                "mini", PluginPhase.MINI_BRUTE_FORCE, 1, mini,
                requires_mini_wordlist=True,
                success_evaluator=extraction_evidence_success,
            ),
            ToolPlugin(
                "main", PluginPhase.MAIN_FALLBACK, 1, main,
                requires_wordlist=True,
                skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,),
            ),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            await self._run(registry, Path(tmpdir))
        self.assertEqual(calls, {"mini": 0, "main": 1})


if __name__ == "__main__":
    unittest.main()
