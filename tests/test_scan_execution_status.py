"""Scan lifecycle status and per-plugin execution accounting (T2.1)."""
import asyncio
import json
import re
import tempfile
import unittest
from pathlib import Path

from dayi.persona import TerminalUI
from dayi.reporter import (
    PluginNotRun,
    ScanReport,
    ToolResult,
    _build_notes_text,
    _fallback_markdown,
    write_json_report,
    write_txt_report,
)
from dayi.runner import DayiRunner, WorkspaceConfigurationError
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
    extraction_evidence_success,
)

FLAG = "FLAG{t21}"


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


def _returns(name: str, flag: str | None = None, calls: list[str] | None = None):
    async def run(context: PluginContext) -> ToolResult:
        if calls is not None:
            calls.append(name)
        return _result(name, flag=flag)

    return run


def _blocks(entered: asyncio.Event | None = None):
    async def run(context: PluginContext) -> ToolResult:
        if entered is not None:
            entered.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    return run


class _QuietUI(TerminalUI):
    pass


def _not_run(report: ScanReport) -> list[tuple[str, str]]:
    assert report.plugins_not_run is not None
    return [(item.plugin_id, item.reason) for item in report.plugins_not_run]


class ScanExecutionStatusTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.target = self.root / "target.bin"
        self.target.write_bytes(b"fixture")
        self.wordlist = self.root / "wordlist.txt"
        self.wordlist.write_text("candidate\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _runner(self, plugins, *, wordlist: bool = True, cls=DayiRunner, **kwargs):
        return cls(
            self.target,
            re.compile(r"FLAG\{[^}]+\}"),
            wordlist=self.wordlist if wordlist else None,
            registry=PluginRegistry(tuple(plugins)),
            ui=_QuietUI(),
            workspace_parent=self.root / "workspaces",
            **kwargs,
        )

    def _last(self, runner: DayiRunner) -> ScanReport:
        report = runner._last_report
        assert report is not None
        return report

    def assertAccountedOnce(self, runner: DayiRunner, report: ScanReport) -> None:
        recorded = [result.tool_name for result in report.tool_results]
        not_run = [plugin_id for plugin_id, _ in _not_run(report)]
        self.assertEqual(len(recorded), len(set(recorded)))
        self.assertEqual(len(not_run), len(set(not_run)))
        self.assertFalse(set(recorded) & set(not_run))
        registry_ids = [plugin.plugin_id for plugin in runner.registry.plugins]
        self.assertEqual(sorted(recorded + not_run), sorted(registry_ids))
        # plugins_not_run follows registry order.
        self.assertEqual(not_run, [pid for pid in registry_ids if pid in not_run])

    # 1 ------------------------------------------------------------------
    async def test_normal_completion_without_flag(self) -> None:
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc")),
            ToolPlugin("arch", PluginPhase.ARCHIVE, 1, _returns("arch")),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main"),
                       requires_wordlist=True),
        ])
        report = await runner.run_all()
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [])
        self.assertEqual(report.all_flags, [])
        self.assertAccountedOnce(runner, report)

    # 2 ------------------------------------------------------------------
    async def test_flag_from_final_eligible_operation_is_completed(self) -> None:
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc")),
            ToolPlugin("final", PluginPhase.MAIN_FINAL, 1, _returns("final", FLAG)),
        ])
        report = await runner.run_all()
        self.assertEqual(report.all_flags, [FLAG])
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [])

    async def test_flag_before_plugins_that_would_be_skipped_anyway_is_completed(self) -> None:
        runner = self._runner([
            ToolPlugin("primary", PluginPhase.MAIN_PRIMARY, 1,
                       _returns("primary", FLAG)),
            ToolPlugin("needs_wl", PluginPhase.MAIN_FINAL, 1, _returns("needs_wl"),
                       requires_wordlist=True),
            ToolPlugin("redundant", PluginPhase.MAIN_FINAL, 2, _returns("redundant"),
                       skip_if_phase_succeeded=(PluginPhase.MAIN_PRIMARY,)),
        ], wordlist=False)
        report = await runner.run_all()
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [
            ("needs_wl", "wordlist_missing"),
            ("redundant", "redundant_after_success"),
        ])

    # 3, 4, 7 ------------------------------------------------------------
    async def test_concurrent_flag_early_stop_cancels_started_siblings(self) -> None:
        entered = [asyncio.Event(), asyncio.Event()]
        later: list[str] = []

        async def winner(context: PluginContext) -> ToolResult:
            await asyncio.gather(*(event.wait() for event in entered))
            return _result("winner", flag=FLAG)

        runner = self._runner([
            ToolPlugin("winner", PluginPhase.CONCURRENT, 1, winner),
            ToolPlugin("slow_a", PluginPhase.CONCURRENT, 2, _blocks(entered[0])),
            ToolPlugin("slow_b", PluginPhase.CONCURRENT, 3, _blocks(entered[1])),
            ToolPlugin("archive", PluginPhase.ARCHIVE, 1, _returns("archive", calls=later)),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1, _returns("mini", calls=later),
                       requires_mini_wordlist=True),
            ToolPlugin("primary", PluginPhase.MAIN_PRIMARY, 1,
                       _returns("primary", calls=later)),
        ])
        report = await asyncio.wait_for(runner.run_all(), timeout=3)
        self.assertEqual(later, [])
        self.assertEqual(report.all_flags, [FLAG])
        self.assertEqual(report.scan_status, "early_stopped")
        self.assertEqual(_not_run(report), [
            ("slow_a", "cancelled_early_stop"),
            ("slow_b", "cancelled_early_stop"),
            ("archive", "not_started_early_stop"),
            # Mini-wordlist was never built, so its requirement is unknown.
            ("mini", "not_started_early_stop"),
            ("primary", "not_started_early_stop"),
        ])
        self.assertAccountedOnce(runner, report)

    async def test_concurrent_flag_with_nothing_curtailed_is_completed(self) -> None:
        runner = self._runner([
            ToolPlugin("other", PluginPhase.CONCURRENT, 1, _returns("other")),
            ToolPlugin("winner", PluginPhase.CONCURRENT, 2, _returns("winner", FLAG)),
        ])
        report = await runner.run_all()
        self.assertEqual([r.tool_name for r in report.tool_results], ["other", "winner"])
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [])

    # 5 ------------------------------------------------------------------
    async def test_operation_completing_at_early_stop_boundary_is_counted_once(self) -> None:
        winner_done = asyncio.Event()

        async def winner(context: PluginContext) -> ToolResult:
            winner_done.set()
            return _result("winner", flag=FLAG)

        async def near(context: PluginContext) -> ToolResult:
            # Finishes right after the winner; may land in the same batch,
            # in the post-wait sweep, or be cancelled by the early stop.
            await winner_done.wait()
            return _result("near")

        runner = self._runner([
            ToolPlugin("winner", PluginPhase.CONCURRENT, 1, winner),
            ToolPlugin("near", PluginPhase.CONCURRENT, 2, near),
            ToolPlugin("primary", PluginPhase.MAIN_PRIMARY, 1, _returns("primary")),
        ])
        report = await runner.run_all()
        self.assertAccountedOnce(runner, report)
        self.assertEqual(report.scan_status, "early_stopped")
        near_entries = [entry for entry in _not_run(report) if entry[0] == "near"]
        recorded = [r.tool_name for r in report.tool_results]
        if "near" in recorded:
            self.assertEqual(near_entries, [])
        else:
            self.assertEqual(near_entries, [("near", "cancelled_early_stop")])
        self.assertIn(("primary", "not_started_early_stop"), _not_run(report))

    # 6, 7 ---------------------------------------------------------------
    async def test_sequential_flag_early_stop(self) -> None:
        calls: list[str] = []
        runner = self._runner([
            ToolPlugin("first", PluginPhase.ARCHIVE, 1, _returns("first", FLAG, calls)),
            ToolPlugin("second", PluginPhase.ARCHIVE, 2, _returns("second", calls=calls)),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1, _returns("mini", calls=calls),
                       requires_mini_wordlist=True),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main", calls=calls)),
        ])
        report = await runner.run_all()
        self.assertEqual(calls, ["first"])
        self.assertEqual(report.scan_status, "early_stopped")
        self.assertEqual(_not_run(report), [
            ("second", "not_started_early_stop"),
            # The mini-wordlist was built (empty) before the stop.
            ("mini", "mini_wordlist_missing"),
            ("main", "not_started_early_stop"),
        ])
        self.assertAccountedOnce(runner, report)

    # 8 ------------------------------------------------------------------
    async def test_user_cancellation_during_concurrent_phase(self) -> None:
        entered = [asyncio.Event(), asyncio.Event()]
        runner = self._runner([
            ToolPlugin("slow_a", PluginPhase.CONCURRENT, 1, _blocks(entered[0])),
            ToolPlugin("slow_b", PluginPhase.CONCURRENT, 2, _blocks(entered[1])),
            ToolPlugin("archive", PluginPhase.ARCHIVE, 1, _returns("archive")),
            ToolPlugin("needs_wl", PluginPhase.MAIN_PRIMARY, 1, _returns("needs_wl"),
                       requires_wordlist=True),
        ], wordlist=False)
        task = asyncio.create_task(runner.run_all())
        await asyncio.wait_for(
            asyncio.gather(*(event.wait() for event in entered)), timeout=3
        )
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        report = self._last(runner)
        self.assertEqual(report.scan_status, "cancelled")
        self.assertEqual(_not_run(report), [
            ("slow_a", "cancelled_user_cancel"),
            ("slow_b", "cancelled_user_cancel"),
            ("archive", "not_started_user_cancel"),
            ("needs_wl", "wordlist_missing"),
        ])
        self.assertAccountedOnce(runner, report)

    async def test_finished_but_unrecorded_result_on_user_cancel_is_not_called_cancelled(self) -> None:
        entered = asyncio.Event()
        runner = self._runner([
            ToolPlugin("fast", PluginPhase.CONCURRENT, 1, _returns("fast")),
            ToolPlugin("slow", PluginPhase.CONCURRENT, 2, _blocks(entered)),
        ])
        task = asyncio.create_task(runner.run_all())
        await asyncio.wait_for(entered.wait(), timeout=3)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        report = self._last(runner)
        self.assertAccountedOnce(runner, report)
        self.assertEqual(report.scan_status, "cancelled")
        self.assertIn(("slow", "cancelled_user_cancel"), _not_run(report))
        # "fast" either made it into tool_results or finished after the
        # runner stopped recording; it was never cancelled.
        fast = [entry for entry in _not_run(report) if entry[0] == "fast"]
        if "fast" not in [r.tool_name for r in report.tool_results]:
            self.assertEqual(fast, [("fast", "result_discarded")])

    async def test_sibling_ignoring_early_stop_cancel_is_result_discarded(self) -> None:
        entered = asyncio.Event()

        async def winner(context: PluginContext) -> ToolResult:
            await entered.wait()
            return _result("winner", flag=FLAG)

        async def stubborn(context: PluginContext) -> ToolResult:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                pass
            return _result("stubborn", flag="FLAG{late}")

        runner = self._runner([
            ToolPlugin("winner", PluginPhase.CONCURRENT, 1, winner),
            ToolPlugin("stubborn", PluginPhase.CONCURRENT, 2, stubborn),
        ])
        report = await asyncio.wait_for(runner.run_all(), timeout=3)
        # Existing behaviour: the late result is not recorded.
        self.assertEqual(report.all_flags, [FLAG])
        self.assertEqual(_not_run(report), [("stubborn", "result_discarded")])
        self.assertEqual(report.scan_status, "early_stopped")

    async def test_scheduled_but_unstarted_concurrent_task_is_not_reported_started(self) -> None:
        bodies: list[str] = []

        async def tracked(context: PluginContext) -> ToolResult:
            bodies.append("first")
            return _result("first")

        class CancelWhileScheduling(DayiRunner):
            def _make_context(self, mini_wordlist=None, plugin_id="unknown"):
                if plugin_id == "second":
                    raise asyncio.CancelledError
                return super()._make_context(mini_wordlist, plugin_id)

        runner = self._runner([
            ToolPlugin("first", PluginPhase.CONCURRENT, 1, tracked),
            ToolPlugin("second", PluginPhase.CONCURRENT, 2, _returns("second")),
            ToolPlugin("primary", PluginPhase.MAIN_PRIMARY, 1, _returns("primary")),
        ], cls=CancelWhileScheduling)
        with self.assertRaises(asyncio.CancelledError):
            await runner.run_all()
        self.assertEqual(bodies, [])
        report = self._last(runner)
        self.assertEqual(report.scan_status, "cancelled")
        self.assertEqual(_not_run(report), [
            ("first", "not_started_user_cancel"),
            ("second", "not_started_user_cancel"),
            ("primary", "not_started_user_cancel"),
        ])

    # 9 ------------------------------------------------------------------
    async def test_user_cancellation_during_sequential_phase(self) -> None:
        entered = asyncio.Event()
        runner = self._runner([
            ToolPlugin("first", PluginPhase.ARCHIVE, 1, _returns("first")),
            ToolPlugin("blocking", PluginPhase.ARCHIVE, 2, _blocks(entered)),
            ToolPlugin("third", PluginPhase.ARCHIVE, 3, _returns("third")),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main")),
        ])
        task = asyncio.create_task(runner.run_all())
        await asyncio.wait_for(entered.wait(), timeout=3)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        report = self._last(runner)
        self.assertEqual([r.tool_name for r in report.tool_results], ["first"])
        self.assertEqual(report.scan_status, "cancelled")
        self.assertEqual(_not_run(report), [
            ("blocking", "cancelled_user_cancel"),
            ("third", "not_started_user_cancel"),
            ("main", "not_started_user_cancel"),
        ])

    # 10 -----------------------------------------------------------------
    async def test_cancellation_during_integration_cleanup(self) -> None:
        draining = asyncio.Event()

        class BlockingDrain:
            def notify(self, flag: str, tool_name: str) -> None:
                pass

            async def drain(self) -> None:
                draining.set()
                await asyncio.Event().wait()

        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc")),
        ], integration=BlockingDrain())
        task = asyncio.create_task(runner.run_all())
        await asyncio.wait_for(draining.wait(), timeout=3)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        # Existing contract: no report is built inside run_all here; the CLI
        # falls back to _build_report().
        self.assertIsNone(runner._last_report)
        report = runner._build_report()
        self.assertEqual(report.scan_status, "cancelled")
        self.assertEqual(_not_run(report), [])

    async def test_user_cancel_during_early_stop_cleanup_keeps_early_stop_reason(self) -> None:
        entered = asyncio.Event()
        cleaning = asyncio.Event()
        release = asyncio.Event()

        async def winner(context: PluginContext) -> ToolResult:
            await entered.wait()
            return _result("winner", flag=FLAG)

        async def slow(context: PluginContext) -> ToolResult:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleaning.set()
                await release.wait()
                raise
            raise AssertionError("unreachable")

        runner = self._runner([
            ToolPlugin("winner", PluginPhase.CONCURRENT, 1, winner),
            ToolPlugin("slow", PluginPhase.CONCURRENT, 2, slow),
            ToolPlugin("primary", PluginPhase.MAIN_PRIMARY, 1, _returns("primary")),
        ])
        task = asyncio.create_task(runner.run_all())
        await asyncio.wait_for(cleaning.wait(), timeout=3)
        task.cancel()
        await asyncio.sleep(0)
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        report = self._last(runner)
        self.assertEqual(report.all_flags, [FLAG])
        self.assertEqual(report.scan_status, "cancelled")
        self.assertEqual(_not_run(report), [
            ("slow", "cancelled_early_stop"),
            ("primary", "not_started_early_stop"),
        ])

    # 11 -----------------------------------------------------------------
    async def test_missing_wordlist(self) -> None:
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc")),
            ToolPlugin("needs_wl", PluginPhase.MAIN_PRIMARY, 1, _returns("needs_wl"),
                       requires_wordlist=True),
            ToolPlugin("independent", PluginPhase.MAIN_FINAL, 1, _returns("independent")),
        ], wordlist=False)
        report = await runner.run_all()
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [("needs_wl", "wordlist_missing")])

    # 12 -----------------------------------------------------------------
    async def test_empty_mini_wordlist(self) -> None:
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc"),
                       contributes_to_mini_wordlist=True),
            ToolPlugin("mini_req", PluginPhase.MINI_BRUTE_FORCE, 1, _returns("mini_req"),
                       requires_mini_wordlist=True),
            ToolPlugin("mini_free", PluginPhase.MINI_BRUTE_FORCE, 2, _returns("mini_free")),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main")),
        ])
        report = await runner.run_all()
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [
            ("mini_req", "mini_wordlist_missing"),
            ("mini_free", "mini_wordlist_missing"),
        ])

    # 13 -----------------------------------------------------------------
    async def test_skip_after_success_rules(self) -> None:
        async def source(context: PluginContext) -> ToolResult:
            result = _result("source")
            result.stdout = "candidate"
            return result

        async def mini(context: PluginContext) -> ToolResult:
            result = _result("mini")
            result.extraction_succeeded = True
            return result

        runner = self._runner([
            ToolPlugin("source", PluginPhase.CONCURRENT, 1, source,
                       contributes_to_mini_wordlist=True),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1, mini,
                       requires_mini_wordlist=True,
                       success_evaluator=extraction_evidence_success),
            ToolPlugin("phase_skip", PluginPhase.MAIN_PRIMARY, 1, _returns("phase_skip"),
                       skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,)),
            ToolPlugin("plugin_skip", PluginPhase.MAIN_FALLBACK, 1, _returns("plugin_skip"),
                       skip_if_plugins_succeeded=("mini",)),
            ToolPlugin("independent", PluginPhase.MAIN_FINAL, 1, _returns("independent")),
        ])
        report = await runner.run_all()
        self.assertEqual(
            [r.tool_name for r in report.tool_results], ["source", "mini", "independent"]
        )
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [
            ("phase_skip", "redundant_after_success"),
            ("plugin_skip", "redundant_after_success"),
        ])

    # 14, 15 -------------------------------------------------------------
    async def test_skipped_timeout_and_error_results_stay_tool_results(self) -> None:
        async def skipped(context: PluginContext) -> ToolResult:
            result = _result("skipped")
            result.skipped = True
            result.skip_reason = "dependency unavailable"
            return result

        async def times_out(context: PluginContext) -> ToolResult:
            raise TimeoutError("budget")

        async def explodes(context: PluginContext) -> ToolResult:
            raise RuntimeError("boom")

        runner = self._runner([
            ToolPlugin("skipped", PluginPhase.CONCURRENT, 1, skipped),
            ToolPlugin("times_out", PluginPhase.CONCURRENT, 2, times_out),
            ToolPlugin("explodes", PluginPhase.ARCHIVE, 1, explodes),
        ])
        report = await runner.run_all()
        by_name = {r.tool_name: r for r in report.tool_results}
        self.assertTrue(by_name["skipped"].skipped)
        self.assertEqual(by_name["skipped"].skip_reason, "dependency unavailable")
        self.assertTrue(by_name["times_out"].timed_out)
        self.assertTrue(by_name["explodes"].error)
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [])

    # 16 -----------------------------------------------------------------
    async def test_fatal_runner_failure(self) -> None:
        async def fatal(context: PluginContext) -> ToolResult:
            raise SystemExit("fatal")

        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc")),
            ToolPlugin("fatal", PluginPhase.ARCHIVE, 1, fatal),
            ToolPlugin("after", PluginPhase.ARCHIVE, 2, _returns("after")),
            ToolPlugin("needs_wl", PluginPhase.MAIN_PRIMARY, 1, _returns("needs_wl"),
                       requires_wordlist=True),
        ], wordlist=False)
        with self.assertRaises(SystemExit):
            await runner.run_all()
        report = self._last(runner)
        self.assertEqual(report.scan_status, "failed")
        self.assertEqual(_not_run(report), [
            ("fatal", "interrupted_runner_failure"),
            ("after", "not_started_runner_failure"),
            ("needs_wl", "wordlist_missing"),
        ])
        self.assertAccountedOnce(runner, report)

    async def test_fatal_failure_while_scheduling_concurrent_tasks(self) -> None:
        bodies: list[str] = []

        async def tracked(context: PluginContext) -> ToolResult:
            bodies.append("first")
            return _result("first")

        class FailWhileScheduling(DayiRunner):
            def _make_context(self, mini_wordlist=None, plugin_id="unknown"):
                if plugin_id == "second":
                    raise RuntimeError("context failure")
                return super()._make_context(mini_wordlist, plugin_id)

        runner = self._runner([
            ToolPlugin("first", PluginPhase.CONCURRENT, 1, tracked),
            ToolPlugin("second", PluginPhase.CONCURRENT, 2, _returns("second")),
        ], cls=FailWhileScheduling)
        with self.assertRaisesRegex(RuntimeError, "context failure"):
            await runner.run_all()
        self.assertEqual(bodies, [])
        self.assertEqual(self._last(runner).scan_status, "failed")
        self.assertEqual(_not_run(self._last(runner)), [
            ("first", "not_started_runner_failure"),
            ("second", "not_started_runner_failure"),
        ])

    async def test_keyboard_interrupt_inside_pipeline_is_cancelled(self) -> None:
        async def interrupted(context: PluginContext) -> ToolResult:
            raise KeyboardInterrupt

        runner = self._runner([
            ToolPlugin("interrupted", PluginPhase.ARCHIVE, 1, interrupted),
        ])
        with self.assertRaises(KeyboardInterrupt):
            await runner.run_all()
        self.assertEqual(self._last(runner).scan_status, "cancelled")
        self.assertEqual(
            _not_run(self._last(runner)),
            [("interrupted", "cancelled_user_cancel")],
        )

    # 17 -----------------------------------------------------------------
    async def test_workspace_initialization_failure_retains_failed_report(self) -> None:
        calls: list[str] = []
        not_a_dir = self.root / "file"
        not_a_dir.write_text("x", encoding="utf-8")
        runner = DayiRunner(
            self.target,
            re.compile("FLAG"),
            registry=PluginRegistry((
                ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", calls=calls)),
                ToolPlugin("needs_wl", PluginPhase.MAIN_PRIMARY, 1, _returns("needs_wl"),
                           requires_wordlist=True),
            )),
            ui=_QuietUI(),
            workspace_parent=not_a_dir,
        )
        with self.assertRaises(WorkspaceConfigurationError):
            await runner.run_all()
        self.assertEqual(calls, [])
        report = self._last(runner)
        self.assertEqual(report.scan_status, "failed")
        self.assertEqual(_not_run(report), [
            ("conc", "not_started_runner_failure"),
            ("needs_wl", "wordlist_missing"),
        ])

    # 18 -----------------------------------------------------------------
    async def test_repeated_runs_do_not_reuse_execution_state(self) -> None:
        runs = 0

        async def conc(context: PluginContext) -> ToolResult:
            nonlocal runs
            runs += 1
            return _result("conc", flag=FLAG if runs == 1 else None)

        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, conc),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main")),
        ])
        first = await runner.run_all()
        second = await runner.run_all()
        self.assertEqual(first.scan_status, "early_stopped")
        self.assertEqual(_not_run(first), [("main", "not_started_early_stop")])
        self.assertEqual(second.scan_status, "completed")
        self.assertEqual(_not_run(second), [])
        self.assertEqual(_not_run(first), [("main", "not_started_early_stop")])


class ScanReportCompatibilityTests(unittest.TestCase):
    def _manual_report(self, **kwargs) -> ScanReport:
        return ScanReport(
            "/tmp/target.bin", "FLAG", None, "start", "end", [FLAG],
            [_result("manual", flag=FLAG)], **kwargs,
        )

    def test_manual_constructor_defaults_mean_not_tracked(self) -> None:
        report = self._manual_report()
        self.assertIsNone(report.scan_status)
        self.assertIsNone(report.plugins_not_run)

    def test_writers_render_untracked_and_tracked_reports(self) -> None:
        tracked = self._manual_report(
            scan_status="early_stopped",
            plugins_not_run=[
                PluginNotRun("later_a", "not_started_early_stop"),
                PluginNotRun("later_b", "wordlist_missing"),
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for name, report in (("untracked", self._manual_report()), ("tracked", tracked)):
                write_json_report(report, root / f"{name}.json")
                write_txt_report(report, root / f"{name}.txt")
                _fallback_markdown(report, root / f"{name}.md")

            legacy_keys = {
                "meta", "all_flags_found", "flag_attribution", "artifacts_found",
                "retained_workspace", "tool_results",
            }
            untracked_json = json.loads((root / "untracked.json").read_text("utf-8"))
            self.assertTrue(legacy_keys <= set(untracked_json))
            self.assertIsNone(untracked_json["scan_status"])
            self.assertIsNone(untracked_json["plugins_not_run"])

            tracked_json = json.loads((root / "tracked.json").read_text("utf-8"))
            self.assertTrue(legacy_keys <= set(tracked_json))
            self.assertEqual(tracked_json["all_flags_found"], [FLAG])
            self.assertEqual(tracked_json["flag_attribution"], {FLAG: ["manual"]})
            self.assertEqual(tracked_json["scan_status"], "early_stopped")
            self.assertEqual(tracked_json["plugins_not_run"], [
                {"plugin_id": "later_a", "reason": "not_started_early_stop"},
                {"plugin_id": "later_b", "reason": "wordlist_missing"},
            ])

            tracked_txt = (root / "tracked.txt").read_text("utf-8")
            self.assertIn("Tarama Durumu: early_stopped", tracked_txt)
            self.assertIn("later_a: not_started_early_stop", tracked_txt)
            self.assertIn("later_b: wordlist_missing", tracked_txt)
            self.assertIn(
                "Tarama Durumu: kayıtlı değil",
                (root / "untracked.txt").read_text("utf-8"),
            )

            tracked_md = (root / "tracked.md").read_text("utf-8")
            self.assertIn(r"**Tarama Durumu:** early\_stopped", tracked_md)
            self.assertIn("later_a: not_started_early_stop", tracked_md)
            self.assertIn("✅ Çözüldü", tracked_md)

    def test_external_exporter_notes_include_execution_summary(self) -> None:
        notes = _build_notes_text(self._manual_report(
            scan_status="completed",
            plugins_not_run=[PluginNotRun("needs_wl", "wordlist_missing")],
        ))
        self.assertIn("Tarama Durumu: completed", notes)
        self.assertIn("ÇALIŞTIRILMAYAN EKLENTİLER:", notes)
        self.assertIn("needs_wl: wordlist_missing", notes)


class ReadmeScanStatusContractTests(unittest.TestCase):
    CODES = (
        "completed", "early_stopped", "cancelled", "failed",
        "wordlist_missing", "mini_wordlist_missing", "redundant_after_success",
        "not_started_early_stop", "cancelled_early_stop",
        "not_started_user_cancel", "cancelled_user_cancel",
        "not_started_runner_failure", "interrupted_runner_failure",
        "result_discarded",
    )

    def test_bilingual_readme_documents_every_code(self) -> None:
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text("utf-8")
        english, turkish = readme.split("## Türkçe Dokümantasyon", 1)
        for heading, section in (("### Scan status", english), ("### Tarama durumu", turkish)):
            body = section.split(heading, 1)[1].split("\n---\n", 1)[0]
            for name in ("scan_status", "plugins_not_run", *self.CODES):
                with self.subTest(heading=heading, name=name):
                    self.assertIn(f"`{name}`", body)


if __name__ == "__main__":
    unittest.main()
