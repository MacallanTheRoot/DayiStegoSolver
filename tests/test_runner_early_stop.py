import asyncio
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


def _result(name: str, *, flag: str | None = None) -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name],
        return_code=0,
        stdout="",
        stderr="",
        flags_found=[flag] if flag else [],
        elapsed_seconds=0.0,
    )


class _RecordingUI(TerminalUI):
    def __init__(self) -> None:
        self.phases: list[str] = []
        self.finished: list[str] = []
        self.outcomes: list[tuple[str, str]] = []
        self.warnings: list[str] = []
        self.flags: list[tuple[str, str | None]] = []

    def phase_started(self, phase: str, plugins: tuple[str, ...]) -> None:
        self.phases.append(phase)

    def phase_finished(self, phase: str) -> None:
        self.finished.append(phase)

    def plugin_finished(self, plugin_id: str, outcome: str) -> None:
        self.outcomes.append((plugin_id, outcome))

    def show_warning(self, message: str) -> None:
        self.warnings.append(message)

    def show_flag(self, flag: str, source: str | None = None) -> None:
        self.flags.append((flag, source))


class _RecordingIntegration:
    def __init__(self) -> None:
        self.notified: list[tuple[str, str]] = []
        self.drained = False

    def notify(self, flag: str, tool_name: str) -> None:
        self.notified.append((flag, tool_name))

    async def drain(self) -> None:
        self.drained = True


class RunnerEarlyStopTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, root: Path, registry: PluginRegistry, **kwargs):
        target = root / "target.bin"
        target.write_bytes(b"fixture")
        wordlist = root / "wordlist.txt"
        wordlist.write_text("candidate\n", encoding="utf-8")
        runner = DayiRunner(
            target,
            re.compile(r"FLAG\{[^}]+\}"),
            wordlist=wordlist,
            registry=registry,
            workspace_parent=root / "workspaces",
            **kwargs,
        )
        report = await runner.run_all()
        return runner, report

    async def _check_concurrent_winner(self, *, extracted: bool) -> None:
        entered = asyncio.Event()
        cancelled = asyncio.Event()
        cleaned = asyncio.Event()
        normal_finish = False
        later_calls: list[str] = []
        ui = _RecordingUI()
        integration = _RecordingIntegration()
        flag = "FLAG{extracted}" if extracted else "FLAG{winner}"

        async def winner(context: PluginContext) -> ToolResult:
            await entered.wait()
            result = _result("winner", flag=None if extracted else flag)
            if extracted:
                result.extracted_flags = {"some/extracted/file": [flag]}
            else:
                extracted_dir = context.workspace / "winner"
                extracted_dir.mkdir()
                (extracted_dir / "useful.bin").write_bytes(b"useful")
                result.extracted_dir = str(extracted_dir)
            return result

        async def slow(context: PluginContext) -> ToolResult:
            nonlocal normal_finish
            try:
                entered.set()
                await asyncio.Event().wait()
                normal_finish = True
                return _result("slow")
            except asyncio.CancelledError:
                cancelled.set()
                raise
            finally:
                cleaned.set()

        def later(name: str):
            async def run(context: PluginContext) -> ToolResult:
                later_calls.append(name)
                return _result(name)

            return run

        registry = PluginRegistry((
            ToolPlugin("winner", PluginPhase.CONCURRENT, 1, winner),
            ToolPlugin("slow", PluginPhase.CONCURRENT, 2, slow),
            ToolPlugin("archive", PluginPhase.ARCHIVE, 1, later("archive")),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1, later("mini")),
            ToolPlugin("primary", PluginPhase.MAIN_PRIMARY, 1, later("primary")),
            ToolPlugin("fallback", PluginPhase.MAIN_FALLBACK, 1, later("fallback")),
            ToolPlugin("final", PluginPhase.MAIN_FINAL, 1, later("final")),
        ))

        with tempfile.TemporaryDirectory() as tmpdir:
            runner, report = await asyncio.wait_for(
                self._run(Path(tmpdir), registry, ui=ui, integration=integration),
                timeout=3,
            )
            self.assertEqual(report.all_flags, [flag])
            self.assertEqual([r.tool_name for r in report.tool_results], ["winner"])
            self.assertIs(runner._results_by_plugin["winner"], report.tool_results[0])
            self.assertIs(runner._last_report, report)
            self.assertTrue(runner._flag_found)
            if not extracted:
                retained = Path(report.retained_workspace or "")
                self.assertTrue((retained / "winner" / "useful.bin").is_file())

        self.assertTrue(cancelled.is_set())
        self.assertTrue(cleaned.is_set())
        self.assertFalse(normal_finish)
        self.assertEqual(later_calls, [])
        self.assertEqual(ui.phases, ["CONCURRENT"])
        self.assertEqual(ui.finished, ["CONCURRENT"])
        self.assertIn(("winner", "complete"), ui.outcomes)
        self.assertIn(("slow", "cancelled"), ui.outcomes)
        self.assertFalse(any("durdurduk" in warning for warning in ui.warnings))
        self.assertEqual(ui.flags, [(flag, "winner")])
        self.assertEqual(integration.notified, [(flag, "winner")])
        self.assertTrue(integration.drained)

    async def test_fast_concurrent_direct_flag_cancels_sibling_and_later_phases(self) -> None:
        await self._check_concurrent_winner(extracted=False)

    async def test_concurrent_extracted_flag_cancels_sibling_and_later_phases(self) -> None:
        await self._check_concurrent_winner(extracted=True)

    async def test_completed_batch_keeps_both_results_in_registry_order(self) -> None:
        async def winner(context: PluginContext) -> ToolResult:
            return _result("winner", flag="FLAG{batch}")

        async def other(context: PluginContext) -> ToolResult:
            return _result("other")

        registry = PluginRegistry((
            ToolPlugin("other", PluginPhase.CONCURRENT, 1, other),
            ToolPlugin("winner", PluginPhase.CONCURRENT, 2, winner),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            runner, report = await self._run(Path(tmpdir), registry, ui=_RecordingUI())
        self.assertEqual([r.tool_name for r in report.tool_results], ["other", "winner"])
        self.assertEqual(report.all_flags, ["FLAG{batch}"])
        self.assertEqual(set(runner._results_by_plugin), {"other", "winner"})

    async def test_sequential_flag_stops_next_plugin_and_later_phases(self) -> None:
        calls: list[str] = []

        def plugin(name: str, flag: str | None = None):
            async def run(context: PluginContext) -> ToolResult:
                calls.append(name)
                return _result(name, flag=flag)

            return run

        ui = _RecordingUI()
        registry = PluginRegistry((
            ToolPlugin("first", PluginPhase.ARCHIVE, 1, plugin("first", "FLAG{archive}")),
            ToolPlugin("second", PluginPhase.ARCHIVE, 2, plugin("second")),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1, plugin("mini")),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, plugin("main")),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            runner, report = await self._run(Path(tmpdir), registry, ui=ui)
        self.assertEqual(calls, ["first"])
        self.assertEqual(report.all_flags, ["FLAG{archive}"])
        self.assertTrue(runner._flag_found)
        self.assertEqual(ui.phases, ["ARCHIVE"])
        self.assertEqual(ui.finished, ["ARCHIVE"])

    async def test_mini_flag_prevents_all_main_phases(self) -> None:
        calls: list[str] = []

        async def source(context: PluginContext) -> ToolResult:
            result = _result("source")
            result.stdout = "candidate"
            return result

        def plugin(name: str, flag: str | None = None):
            async def run(context: PluginContext) -> ToolResult:
                calls.append(name)
                return _result(name, flag=flag)

            return run

        registry = PluginRegistry((
            ToolPlugin("source", PluginPhase.CONCURRENT, 1, source,
                       contributes_to_mini_wordlist=True),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1,
                       plugin("mini", "FLAG{mini}"), requires_mini_wordlist=True),
            ToolPlugin("primary", PluginPhase.MAIN_PRIMARY, 1, plugin("primary")),
            ToolPlugin("fallback", PluginPhase.MAIN_FALLBACK, 1, plugin("fallback")),
            ToolPlugin("final", PluginPhase.MAIN_FINAL, 1, plugin("final")),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            _, report = await self._run(Path(tmpdir), registry, ui=_RecordingUI())
        self.assertEqual(calls, ["mini"])
        self.assertEqual(report.all_flags, ["FLAG{mini}"])

    async def test_extraction_success_without_flag_keeps_declarative_skip_rules(self) -> None:
        calls: list[str] = []

        async def source(context: PluginContext) -> ToolResult:
            result = _result("source")
            result.stdout = "candidate"
            return result

        async def mini(context: PluginContext) -> ToolResult:
            calls.append("mini")
            result = _result("mini")
            result.extraction_succeeded = True
            return result

        def main(name: str):
            async def run(context: PluginContext) -> ToolResult:
                calls.append(name)
                return _result(name)

            return run

        registry = PluginRegistry((
            ToolPlugin("source", PluginPhase.CONCURRENT, 1, source,
                       contributes_to_mini_wordlist=True),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1, mini,
                       requires_mini_wordlist=True,
                       success_evaluator=extraction_evidence_success),
            ToolPlugin("declared_skip", PluginPhase.MAIN_PRIMARY, 1,
                       main("declared_skip"),
                       skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,)),
            ToolPlugin("independent", PluginPhase.MAIN_FINAL, 1,
                       main("independent")),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            runner, report = await self._run(Path(tmpdir), registry, ui=_RecordingUI())
        self.assertEqual(calls, ["mini", "independent"])
        self.assertFalse(runner._flag_found)
        self.assertEqual(report.all_flags, [])

    async def test_primary_or_fallback_flag_stops_remaining_main_phases(self) -> None:
        for winning_phase in (PluginPhase.MAIN_PRIMARY, PluginPhase.MAIN_FALLBACK):
            with self.subTest(winning_phase=winning_phase):
                calls: list[str] = []

                def main(name: str, phase: PluginPhase):
                    async def run(context: PluginContext) -> ToolResult:
                        calls.append(name)
                        return _result(
                            name,
                            flag="FLAG{main}" if phase == winning_phase else None,
                        )

                    return ToolPlugin(name, phase, 1, run)

                registry = PluginRegistry(tuple(
                    main(name, phase) for name, phase in (
                        ("primary", PluginPhase.MAIN_PRIMARY),
                        ("fallback", PluginPhase.MAIN_FALLBACK),
                        ("final", PluginPhase.MAIN_FINAL),
                    )
                ))
                ui = _RecordingUI()
                with tempfile.TemporaryDirectory() as tmpdir:
                    _, report = await self._run(Path(tmpdir), registry, ui=ui)
                expected = (["primary"] if winning_phase == PluginPhase.MAIN_PRIMARY
                            else ["primary", "fallback"])
                self.assertEqual(calls, expected)
                self.assertEqual(ui.phases, [phase.name for phase in (
                    PluginPhase.MAIN_PRIMARY,
                    *((PluginPhase.MAIN_FALLBACK,) if len(expected) == 2 else ()),
                )])
                self.assertEqual(report.all_flags, ["FLAG{main}"])

    async def test_known_flag_prevents_main_phase_calls(self) -> None:
        calls = 0

        async def main(context: PluginContext) -> ToolResult:
            nonlocal calls
            calls += 1
            return _result("main")

        plugin = ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, main)
        ui = _RecordingUI()
        runner = DayiRunner(
            Path("unused.bin"), re.compile("FLAG"),
            registry=PluginRegistry((plugin,)), ui=ui,
        )
        runner._record_result(plugin, _result("main", flag="FLAG{known}"))
        await runner._run_main_wordlist_phase()
        self.assertEqual(calls, 0)
        self.assertEqual(ui.phases, [])

    async def test_external_cancellation_cleans_children_and_keeps_partial_report(self) -> None:
        entered = [asyncio.Event(), asyncio.Event()]
        cleaned = [asyncio.Event(), asyncio.Event()]
        children: list[asyncio.Task] = []

        def blocking(index: int):
            async def run(context: PluginContext) -> ToolResult:
                children.append(asyncio.current_task())
                try:
                    entered[index].set()
                    await asyncio.Event().wait()
                finally:
                    cleaned[index].set()

            return run

        registry = PluginRegistry((
            ToolPlugin("slow_one", PluginPhase.CONCURRENT, 1, blocking(0)),
            ToolPlugin("slow_two", PluginPhase.CONCURRENT, 2, blocking(1)),
        ))
        ui = _RecordingUI()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"fixture")
            runner = DayiRunner(target, re.compile("FLAG"), registry=registry, ui=ui)
            task = asyncio.create_task(runner.run_all())
            await asyncio.gather(*(event.wait() for event in entered))
            workspace = runner._workspace
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=3)
            self.assertIsNotNone(runner._last_report)
            self.assertEqual(runner._last_report.tool_results, [])
            self.assertIsNone(runner._workspace)
            self.assertFalse(workspace.exists())

        self.assertTrue(all(event.is_set() for event in cleaned))
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.done() and child.cancelled() for child in children))
        self.assertEqual(ui.finished, ["CONCURRENT"])
        self.assertTrue(any("durdurduk" in warning for warning in ui.warnings))

    async def test_external_cancel_during_internal_cleanup_does_not_cancel_child_twice(self) -> None:
        entered = asyncio.Event()
        cleaning = asyncio.Event()
        release_cleanup = asyncio.Event()
        cleaned = asyncio.Event()
        cancelled_twice = asyncio.Event()

        async def winner(context: PluginContext) -> ToolResult:
            await entered.wait()
            return _result("winner", flag="FLAG{winner}")

        async def slow(context: PluginContext) -> ToolResult:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleaning.set()
                try:
                    await release_cleanup.wait()
                except asyncio.CancelledError:
                    cancelled_twice.set()
                    raise
                finally:
                    cleaned.set()
                raise

        registry = PluginRegistry((
            ToolPlugin("winner", PluginPhase.CONCURRENT, 1, winner),
            ToolPlugin("slow", PluginPhase.CONCURRENT, 2, slow),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"fixture")
            runner = DayiRunner(target, re.compile("FLAG"), registry=registry,
                                ui=_RecordingUI())
            task = asyncio.create_task(runner.run_all())
            await asyncio.wait_for(cleaning.wait(), timeout=3)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(cancelled_twice.is_set())
            release_cleanup.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=3)

        self.assertTrue(cleaned.is_set())
        self.assertFalse(cancelled_twice.is_set())
        self.assertIsNotNone(runner._last_report)
        self.assertEqual(runner._last_report.all_flags, ["FLAG{winner}"])

    async def test_flag_state_resets_on_each_run(self) -> None:
        runs = 0
        main_calls = 0

        async def concurrent(context: PluginContext) -> ToolResult:
            nonlocal runs
            runs += 1
            return _result("concurrent", flag="FLAG{first}" if runs == 1 else None)

        async def main(context: PluginContext) -> ToolResult:
            nonlocal main_calls
            main_calls += 1
            return _result("main")

        registry = PluginRegistry((
            ToolPlugin("concurrent", PluginPhase.CONCURRENT, 1, concurrent),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, main),
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target.bin"
            target.write_bytes(b"fixture")
            runner = DayiRunner(target, re.compile("FLAG"), registry=registry,
                                ui=_RecordingUI())
            first = await runner.run_all()
            second = await runner.run_all()
        self.assertEqual(first.all_flags, ["FLAG{first}"])
        self.assertEqual(second.all_flags, [])
        self.assertEqual(main_calls, 1)
        self.assertFalse(runner._flag_found)


if __name__ == "__main__":
    unittest.main()
