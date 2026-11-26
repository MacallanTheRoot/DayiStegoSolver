"""Opt-in full-scan mode: a confirmed flag does not stop the pipeline (T2.2)."""
import asyncio
import contextlib
import inspect
import io
import logging
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from dayi import cli
from dayi.integrations import IntegrationManager
from dayi.persona import TerminalUI
from dayi.reporter import ScanReport, ToolResult
from dayi.runner import DayiRunner
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
    flags_found_success,
)


def _result(name: str, *, flag: str | None = None, stdout: str = "") -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name],
        return_code=0,
        stdout=stdout,
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


def _blocks(entered: asyncio.Event):
    async def run(context: PluginContext) -> ToolResult:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    return run


def _signals_when_recorded(event: asyncio.Event):
    """Success evaluator that fires once the runner records the result.

    The runner evaluates success right after updating its flag state and
    before deciding whether to stop, so a sibling waiting on this event is
    cancelled in default mode and resumes only when nothing stops the scan.
    """

    def evaluate(result: ToolResult) -> bool:
        event.set()
        return flags_found_success(result)

    return evaluate


class _RecordingUI(TerminalUI):
    def __init__(self) -> None:
        self.outcomes: list[tuple[str, str]] = []
        self.flags: list[tuple[str, str | None]] = []

    def plugin_finished(self, plugin_id: str, outcome: str) -> None:
        self.outcomes.append((plugin_id, outcome))

    def show_flag(self, flag: str, source: str | None = None) -> None:
        self.flags.append((flag, source))


class _RecordingIntegration:
    def __init__(self) -> None:
        self.notified: list[tuple[str, str]] = []
        self.drains = 0

    def notify(self, flag: str, tool_name: str) -> None:
        self.notified.append((flag, tool_name))

    async def drain(self) -> None:
        self.drains += 1


def _not_run(report: ScanReport) -> list[tuple[str, str]]:
    assert report.plugins_not_run is not None
    return [(item.plugin_id, item.reason) for item in report.plugins_not_run]


class FullScanRunnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.target = self.root / "target.bin"
        self.target.write_bytes(b"fixture")
        self.wordlist = self.root / "wordlist.txt"
        self.wordlist.write_text("candidate\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _runner(self, plugins, *, wordlist: bool = True, **kwargs):
        kwargs.setdefault("ui", _RecordingUI())
        return DayiRunner(
            self.target,
            re.compile(r"FLAG\{[^}]+\}"),
            wordlist=self.wordlist if wordlist else None,
            registry=PluginRegistry(tuple(plugins)),
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
        self.assertFalse(set(recorded) & set(not_run))
        registry_ids = [plugin.plugin_id for plugin in runner.registry.plugins]
        self.assertEqual(sorted(recorded + not_run), sorted(registry_ids))

    def assertNoEarlyStop(self, report: ScanReport) -> None:
        self.assertEqual(
            [entry for entry in _not_run(report) if "early_stop" in entry[1]], []
        )

    def _pipeline(self, calls: list[str], recorded: asyncio.Event):
        """A flag in CONCURRENT followed by every later phase."""

        async def sibling(context: PluginContext) -> ToolResult:
            await recorded.wait()
            calls.append("sibling")
            return _result("sibling", flag="FLAG{sibling}")

        return [
            ToolPlugin("winner", PluginPhase.CONCURRENT, 1,
                       _returns("winner", "FLAG{winner}", calls),
                       success_evaluator=_signals_when_recorded(recorded)),
            ToolPlugin("sibling", PluginPhase.CONCURRENT, 2, sibling),
            ToolPlugin("archive", PluginPhase.ARCHIVE, 1,
                       _returns("archive", "FLAG{archive}", calls)),
            ToolPlugin("primary", PluginPhase.MAIN_PRIMARY, 1,
                       _returns("primary", calls=calls)),
            ToolPlugin("fallback", PluginPhase.MAIN_FALLBACK, 1,
                       _returns("fallback", calls=calls)),
            ToolPlugin("final", PluginPhase.MAIN_FINAL, 1,
                       _returns("final", "FLAG{final}", calls)),
        ]

    # Constructor compatibility -------------------------------------------
    def test_constructor_default_and_signature_are_backward_compatible(self) -> None:
        runner = DayiRunner(Path("sample.bin"), re.compile("FLAG"), registry=Mock())
        self.assertFalse(runner.full_scan)
        parameters = list(inspect.signature(DayiRunner).parameters)
        # Existing parameters keep their positions; the new one is appended.
        self.assertEqual(parameters[:15], [
            "target", "pattern", "wordlist", "timeout", "bf_threads", "bf_limit",
            "integration", "registry", "ui", "workspace_parent",
            "pattern_display", "pattern_source", "include_possible_artifacts",
            "ocr_language", "ocr_exhaustive",
        ])
        self.assertEqual(parameters[-1], "full_scan")
        self.assertIs(
            inspect.signature(DayiRunner).parameters["full_scan"].default, False
        )

    # Default mode stays unchanged -------------------------------------------
    async def test_default_and_explicit_false_keep_early_stop(self) -> None:
        for explicit in (False, True):
            with self.subTest(explicit_full_scan_false=explicit):
                calls: list[str] = []
                plugins = self._pipeline(calls, asyncio.Event())
                runner = (
                    self._runner(plugins, full_scan=False)
                    if explicit else self._runner(plugins)
                )
                report = await asyncio.wait_for(runner.run_all(), timeout=3)
                self.assertEqual(calls, ["winner"])
                self.assertEqual(report.all_flags, ["FLAG{winner}"])
                self.assertEqual(report.scan_status, "early_stopped")
                self.assertEqual(_not_run(report), [
                    ("sibling", "cancelled_early_stop"),
                    ("archive", "not_started_early_stop"),
                    ("primary", "not_started_early_stop"),
                    ("fallback", "not_started_early_stop"),
                    ("final", "not_started_early_stop"),
                ])

    # Concurrent flag, later phases, multiple flags --------------------------
    async def test_concurrent_flag_does_not_cancel_siblings_or_later_phases(self) -> None:
        calls: list[str] = []
        ui = _RecordingUI()
        runner = self._runner(
            self._pipeline(calls, asyncio.Event()), full_scan=True, ui=ui
        )
        report = await asyncio.wait_for(runner.run_all(), timeout=3)
        self.assertEqual(
            calls, ["winner", "sibling", "archive", "primary", "fallback", "final"]
        )
        self.assertEqual([r.tool_name for r in report.tool_results], [
            "winner", "sibling", "archive", "primary", "fallback", "final",
        ])
        self.assertNotIn(("sibling", "cancelled"), ui.outcomes)
        self.assertEqual(report.all_flags, [
            "FLAG{winner}", "FLAG{sibling}", "FLAG{archive}", "FLAG{final}",
        ])
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [])
        self.assertAccountedOnce(runner, report)

    async def test_mini_wordlist_is_built_and_run_after_concurrent_flag(self) -> None:
        seen: list[tuple[str, ...]] = []

        async def source(context: PluginContext) -> ToolResult:
            return _result("source", flag="FLAG{meta}", stdout="hunter2secret")

        async def mini(context: PluginContext) -> ToolResult:
            seen.append(context.mini_wordlist)
            return _result("mini", flag="FLAG{mini}")

        runner = self._runner([
            ToolPlugin("source", PluginPhase.CONCURRENT, 1, source,
                       contributes_to_mini_wordlist=True),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1, mini,
                       requires_mini_wordlist=True),
        ], full_scan=True)
        report = await runner.run_all()
        self.assertEqual(len(seen), 1)
        self.assertIn("hunter2secret", seen[0])
        self.assertEqual(report.all_flags, ["FLAG{meta}", "FLAG{mini}"])
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [])

    # Sequential phase --------------------------------------------------------
    async def test_sequential_flag_continues_phase_and_later_phases(self) -> None:
        calls: list[str] = []
        runner = self._runner([
            ToolPlugin("first", PluginPhase.ARCHIVE, 1, _returns("first", "FLAG{a}", calls)),
            ToolPlugin("second", PluginPhase.ARCHIVE, 2, _returns("second", "FLAG{b}", calls)),
            ToolPlugin("third", PluginPhase.ARCHIVE, 3, _returns("third", calls=calls)),
            ToolPlugin("main_a", PluginPhase.MAIN_PRIMARY, 1,
                       _returns("main_a", "FLAG{c}", calls)),
            ToolPlugin("main_b", PluginPhase.MAIN_PRIMARY, 2, _returns("main_b", calls=calls)),
        ], full_scan=True)
        report = await runner.run_all()
        self.assertEqual(calls, ["first", "second", "third", "main_a", "main_b"])
        self.assertEqual(report.all_flags, ["FLAG{a}", "FLAG{b}", "FLAG{c}"])
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [])

    # Duplicates, attribution, notifications ----------------------------------
    async def test_duplicate_flags_are_deduplicated_with_all_sources(self) -> None:
        ui = _RecordingUI()
        integration = _RecordingIntegration()
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{dup}")),
            ToolPlugin("arch", PluginPhase.ARCHIVE, 1, _returns("arch", "FLAG{dup}")),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main", "FLAG{other}")),
        ], full_scan=True, ui=ui, integration=integration)
        report = await runner.run_all()
        self.assertEqual(report.all_flags, ["FLAG{dup}", "FLAG{other}"])
        self.assertEqual(ui.flags, [("FLAG{dup}", "conc, arch"), ("FLAG{other}", "main")])
        # The runner forwards every per-result hit, as in default mode; the
        # integration manager is responsible for de-duplicating submissions.
        self.assertEqual(integration.notified, [
            ("FLAG{dup}", "conc"), ("FLAG{dup}", "arch"), ("FLAG{other}", "main"),
        ])
        self.assertEqual(integration.drains, 1)

    async def test_default_mode_notifications_are_unchanged(self) -> None:
        integration = _RecordingIntegration()
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{one}")),
            ToolPlugin("arch", PluginPhase.ARCHIVE, 1, _returns("arch", "FLAG{two}")),
        ], integration=integration)
        report = await runner.run_all()
        self.assertEqual(integration.notified, [("FLAG{one}", "conc")])
        self.assertEqual(integration.drains, 1)
        self.assertEqual(report.scan_status, "early_stopped")

    # Skip rules and degradation are preserved --------------------------------
    async def test_missing_wordlist_and_mini_wordlist_still_skip(self) -> None:
        calls: list[str] = []
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{x}", calls)),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1, _returns("mini", calls=calls),
                       requires_mini_wordlist=True),
            ToolPlugin("needs_wl", PluginPhase.MAIN_PRIMARY, 1,
                       _returns("needs_wl", calls=calls), requires_wordlist=True),
            ToolPlugin("free", PluginPhase.MAIN_FINAL, 1, _returns("free", calls=calls)),
        ], wordlist=False, full_scan=True)
        report = await runner.run_all()
        self.assertEqual(calls, ["conc", "free"])
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [
            ("mini", "mini_wordlist_missing"),
            ("needs_wl", "wordlist_missing"),
        ])
        self.assertAccountedOnce(runner, report)

    async def test_skip_after_success_rules_still_apply(self) -> None:
        calls: list[str] = []

        async def source(context: PluginContext) -> ToolResult:
            return _result("source", stdout="hunter2secret")

        runner = self._runner([
            ToolPlugin("source", PluginPhase.CONCURRENT, 1, source,
                       contributes_to_mini_wordlist=True),
            ToolPlugin("mini", PluginPhase.MINI_BRUTE_FORCE, 1,
                       _returns("mini", "FLAG{mini}", calls), requires_mini_wordlist=True),
            ToolPlugin("phase_skip", PluginPhase.MAIN_PRIMARY, 1,
                       _returns("phase_skip", calls=calls),
                       skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,)),
            ToolPlugin("plugin_skip", PluginPhase.MAIN_FALLBACK, 1,
                       _returns("plugin_skip", calls=calls),
                       skip_if_plugins_succeeded=("mini",)),
            ToolPlugin("independent", PluginPhase.MAIN_FINAL, 1,
                       _returns("independent", calls=calls)),
        ], full_scan=True)
        report = await runner.run_all()
        self.assertEqual(calls, ["mini", "independent"])
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [
            ("phase_skip", "redundant_after_success"),
            ("plugin_skip", "redundant_after_success"),
        ])

    async def test_incompatible_timeout_and_failing_plugins_keep_representation(self) -> None:
        async def incompatible(context: PluginContext) -> ToolResult:
            result = _result("incompatible")
            result.skipped = True
            result.skip_reason = "unsupported file format"
            return result

        async def times_out(context: PluginContext) -> ToolResult:
            raise TimeoutError("budget")

        async def explodes(context: PluginContext) -> ToolResult:
            raise RuntimeError("boom")

        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{x}")),
            ToolPlugin("incompatible", PluginPhase.ARCHIVE, 1, incompatible),
            ToolPlugin("times_out", PluginPhase.ARCHIVE, 2, times_out),
            ToolPlugin("explodes", PluginPhase.MAIN_PRIMARY, 1, explodes),
            ToolPlugin("after", PluginPhase.MAIN_FINAL, 1, _returns("after")),
        ], full_scan=True)
        report = await runner.run_all()
        by_name = {r.tool_name: r for r in report.tool_results}
        self.assertEqual(
            list(by_name), ["conc", "incompatible", "times_out", "explodes", "after"]
        )
        self.assertTrue(by_name["incompatible"].skipped)
        self.assertEqual(by_name["incompatible"].skip_reason, "unsupported file format")
        self.assertTrue(by_name["times_out"].timed_out)
        self.assertTrue(by_name["explodes"].error)
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [])

    # Cancellation and failure are not masked ---------------------------------
    async def test_user_cancel_after_flag_in_concurrent_phase(self) -> None:
        recorded = asyncio.Event()
        entered = asyncio.Event()

        async def blocker(context: PluginContext) -> ToolResult:
            await recorded.wait()
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        runner = self._runner([
            ToolPlugin("winner", PluginPhase.CONCURRENT, 1, _returns("winner", "FLAG{w}"),
                       success_evaluator=_signals_when_recorded(recorded)),
            ToolPlugin("blocker", PluginPhase.CONCURRENT, 2, blocker),
            ToolPlugin("archive", PluginPhase.ARCHIVE, 1, _returns("archive")),
        ], full_scan=True)
        task = asyncio.create_task(runner.run_all())
        await asyncio.wait_for(entered.wait(), timeout=3)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        report = self._last(runner)
        self.assertEqual(report.all_flags, ["FLAG{w}"])
        self.assertEqual(report.scan_status, "cancelled")
        self.assertEqual(_not_run(report), [
            ("blocker", "cancelled_user_cancel"),
            ("archive", "not_started_user_cancel"),
        ])
        self.assertAccountedOnce(runner, report)

    async def test_user_cancel_after_flag_in_later_sequential_phase(self) -> None:
        entered = asyncio.Event()
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{c}")),
            ToolPlugin("arch", PluginPhase.ARCHIVE, 1, _returns("arch", "FLAG{a}")),
            ToolPlugin("blocker", PluginPhase.MAIN_PRIMARY, 1, _blocks(entered)),
            ToolPlugin("needs_wl", PluginPhase.MAIN_FALLBACK, 1, _returns("needs_wl"),
                       requires_wordlist=True),
            ToolPlugin("final", PluginPhase.MAIN_FINAL, 1, _returns("final")),
        ], wordlist=False, full_scan=True)
        task = asyncio.create_task(runner.run_all())
        await asyncio.wait_for(entered.wait(), timeout=3)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        report = self._last(runner)
        self.assertEqual(report.all_flags, ["FLAG{c}", "FLAG{a}"])
        self.assertEqual(report.scan_status, "cancelled")
        self.assertEqual(_not_run(report), [
            ("blocker", "cancelled_user_cancel"),
            ("needs_wl", "wordlist_missing"),
            ("final", "not_started_user_cancel"),
        ])
        self.assertAccountedOnce(runner, report)

    async def test_fatal_runner_failure_after_flag(self) -> None:
        async def fatal(context: PluginContext) -> ToolResult:
            raise SystemExit("fatal")

        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{c}")),
            ToolPlugin("fatal", PluginPhase.ARCHIVE, 1, fatal),
            ToolPlugin("after", PluginPhase.MAIN_PRIMARY, 1, _returns("after")),
        ], full_scan=True)
        with self.assertRaises(SystemExit):
            await runner.run_all()
        report = self._last(runner)
        self.assertEqual(report.all_flags, ["FLAG{c}"])
        self.assertEqual(report.scan_status, "failed")
        self.assertEqual(_not_run(report), [
            ("fatal", "interrupted_runner_failure"),
            ("after", "not_started_runner_failure"),
        ])

    async def test_real_integration_manager_dispatches_each_distinct_flag_once(self) -> None:
        with patch("dayi.integrations._resolve_aiohttp", return_value=None):
            manager = IntegrationManager(webhook_url="https://discord.invalid/hook")
        manager._dispatch = AsyncMock(return_value=())
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{dup}")),
            ToolPlugin("arch", PluginPhase.ARCHIVE, 1, _returns("arch", "FLAG{dup}")),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main", "FLAG{new}")),
        ], full_scan=True, integration=manager)
        report = await runner.run_all()
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(
            [call.args for call in manager._dispatch.await_args_list],
            [("FLAG{dup}", "conc"), ("FLAG{new}", "main")],
        )

    # Repeated execution -------------------------------------------------------
    async def test_repeated_full_scans_on_one_runner_are_independent(self) -> None:
        calls: list[str] = []
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{c}", calls)),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main", "FLAG{m}", calls)),
        ], full_scan=True)
        first = await runner.run_all()
        second = await runner.run_all()
        self.assertEqual(calls, ["conc", "main", "conc", "main"])
        for report in (first, second):
            self.assertEqual(report.all_flags, ["FLAG{c}", "FLAG{m}"])
            self.assertEqual(report.scan_status, "completed")
            self.assertEqual(_not_run(report), [])
            self.assertNoEarlyStop(report)
        self.assertEqual([r.tool_name for r in second.tool_results], ["conc", "main"])


    # Active policy is fixed per run ------------------------------------------
    def _toggling(self, holder: list[DayiRunner], value: bool, flag: str | None = None):
        """Plugin that changes the public setting while the scan is running."""

        async def run(context: PluginContext) -> ToolResult:
            holder[0].full_scan = value
            return _result("toggler", flag=flag)

        return run

    async def test_disabling_full_scan_mid_run_keeps_full_scan_policy(self) -> None:
        holder: list[DayiRunner] = []
        calls: list[str] = []
        runner = self._runner([
            ToolPlugin("toggler", PluginPhase.CONCURRENT, 1,
                       self._toggling(holder, False, "FLAG{t}")),
            ToolPlugin("arch", PluginPhase.ARCHIVE, 1, _returns("arch", calls=calls)),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main", calls=calls)),
        ], full_scan=True)
        holder.append(runner)
        report = await runner.run_all()
        self.assertEqual(calls, ["arch", "main"])
        self.assertEqual(report.scan_status, "completed")
        self.assertEqual(_not_run(report), [])

    async def test_enabling_full_scan_mid_run_keeps_default_policy(self) -> None:
        holder: list[DayiRunner] = []
        calls: list[str] = []
        runner = self._runner([
            ToolPlugin("toggler", PluginPhase.CONCURRENT, 1,
                       self._toggling(holder, True, "FLAG{t}")),
            ToolPlugin("arch", PluginPhase.ARCHIVE, 1, _returns("arch", calls=calls)),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main", calls=calls)),
        ])
        holder.append(runner)
        report = await runner.run_all()
        self.assertEqual(calls, [])
        self.assertEqual(report.scan_status, "early_stopped")
        self.assertEqual(_not_run(report), [
            ("arch", "not_started_early_stop"),
            ("main", "not_started_early_stop"),
        ])

    async def test_mid_run_change_does_not_alter_report_classification(self) -> None:
        holder: list[DayiRunner] = []
        entered = asyncio.Event()

        async def toggles_then_blocks(context: PluginContext) -> ToolResult:
            holder[0].full_scan = False
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{c}")),
            ToolPlugin("arch", PluginPhase.ARCHIVE, 1, toggles_then_blocks),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main")),
        ], full_scan=True)
        holder.append(runner)
        task = asyncio.create_task(runner.run_all())
        await asyncio.wait_for(entered.wait(), timeout=3)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        report = self._last(runner)
        self.assertEqual(report.scan_status, "cancelled")
        self.assertEqual(_not_run(report), [
            ("arch", "cancelled_user_cancel"),
            ("main", "not_started_user_cancel"),
        ])

    async def test_setting_changes_between_runs_take_effect(self) -> None:
        runner = self._runner([
            ToolPlugin("conc", PluginPhase.CONCURRENT, 1, _returns("conc", "FLAG{c}")),
            ToolPlugin("main", PluginPhase.MAIN_PRIMARY, 1, _returns("main")),
        ])
        statuses = []
        for value in (False, True, False):
            runner.full_scan = value
            report = await runner.run_all()
            statuses.append((report.scan_status, _not_run(report)))
        self.assertEqual(statuses, [
            ("early_stopped", [("main", "not_started_early_stop")]),
            ("completed", []),
            ("early_stopped", [("main", "not_started_early_stop")]),
        ])


class SequentialPhaseGuardTests(unittest.IsolatedAsyncioTestCase):
    """Direct calls to the compatibility phase wrappers honour the stop policy."""

    async def _direct_archive_call(self, *, full_scan: bool) -> _RecordingUI:
        calls: list[str] = []
        ui = _RecordingUI()
        known = ToolPlugin("known", PluginPhase.CONCURRENT, 1, _returns("known"))
        needs_wl = ToolPlugin("needs_wl", PluginPhase.ARCHIVE, 1,
                              _returns("needs_wl", calls=calls), requires_wordlist=True)
        runner = DayiRunner(
            Path("unused.bin"), re.compile("FLAG"),
            registry=PluginRegistry((known, needs_wl)), ui=ui, full_scan=full_scan,
        )
        runner._record_result(known, _result("known", flag="FLAG{known}"))
        await runner._run_archive_phase([])
        self.assertEqual(calls, [])
        return ui

    async def test_known_flag_prevents_direct_archive_phase_in_default_mode(self) -> None:
        # Even a phase whose plugins would all be skipped is not evaluated.
        ui = await self._direct_archive_call(full_scan=False)
        self.assertEqual(ui.outcomes, [])

    async def test_full_scan_direct_archive_phase_still_applies_skip_rules(self) -> None:
        ui = await self._direct_archive_call(full_scan=True)
        self.assertEqual(ui.outcomes, [("needs_wl", "skipped")])


class FullScanCliTests(unittest.IsolatedAsyncioTestCase):
    def test_parsing_with_and_without_option(self) -> None:
        self.assertTrue(cli.parse_cli_args(["scan", "x.png", "--full-scan"]).full_scan)
        self.assertTrue(cli.parse_cli_args(["scan", "--full-scan", "x.png"]).full_scan)
        self.assertFalse(cli.parse_cli_args(["scan", "x.png"]).full_scan)

    def test_legacy_flat_syntax_matches_explicit_scan(self) -> None:
        for legacy in (["x.png", "--full-scan"], ["--full-scan", "x.png"], ["x.png"]):
            with self.subTest(legacy=legacy):
                self.assertEqual(
                    vars(cli.parse_cli_args(legacy)),
                    vars(cli.parse_cli_args(["scan", *legacy])),
                )

    def test_scan_help_lists_option(self) -> None:
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["dayi", "scan", "--help"]),
            contextlib.redirect_stdout(output),
            self.assertRaises(SystemExit) as raised,
        ):
            cli.main()
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("--full-scan", output.getvalue())

    async def test_option_reaches_runner(self) -> None:
        for argv, expected in ((["--full-scan"], True), ([], False)):
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as tmpdir:
                target = Path(tmpdir) / "sample.bin"
                target.write_bytes(b"sample")
                captured: dict = {}

                class FakeRunner:
                    def __init__(self, **kwargs) -> None:
                        captured.update(kwargs)

                    async def run_all(self) -> ScanReport:
                        return ScanReport(
                            target_file=str(target),
                            flag_pattern="FLAG",
                            wordlist=None,
                            started_at="start",
                            finished_at="finish",
                            all_flags=[],
                            tool_results=[],
                        )

                args = cli.parse_cli_args(["scan", str(target), *argv])
                with patch("dayi.cli.build_integration", return_value=None), patch(
                    "dayi.cli.DayiRunner", FakeRunner
                ):
                    _report, code = await cli._run_analysis(
                        args, Mock(spec=logging.Logger)
                    )
                self.assertEqual(code, 0)
                self.assertIs(captured["full_scan"], expected)


class ReadmeFullScanContractTests(unittest.TestCase):
    def test_bilingual_readme_documents_full_scan(self) -> None:
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text("utf-8")
        english, turkish = readme.split("## Türkçe Dokümantasyon", 1)
        for heading, section in (
            ("### Early stop and full scan", english),
            ("### Erken durma ve tam tarama", turkish),
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, section)
                body = section.split(heading, 1)[1].split("### ", 1)[0]
                for token in (
                    "`--full-scan`", "`--wordlist`", "`scan_status: completed`",
                    "`*_early_stop`", "`cancelled`", "`failed`", "v4.5.2",
                    "`--ctfd-url`", "`DAYI_CTFD_URL`",
                ):
                    self.assertIn(token, body)


if __name__ == "__main__":
    unittest.main()
