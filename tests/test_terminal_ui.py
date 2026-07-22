import asyncio
import io
import json
import logging
import re
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from dayi.persona import (
    PlainTerminalUI,
    RichTerminalUI,
    TerminalUI,
    _RichComponents,
    create_terminal_ui,
)
from dayi.reporter import ToolResult, write_json_report, write_txt_report
from dayi.runner import DayiRunner
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
)


class _TTYBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


class _FakeRenderable:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs


class _FakeTable(_FakeRenderable):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.columns: list[tuple[tuple, dict]] = []
        self.rows: list[tuple] = []

    def add_column(self, *args, **kwargs) -> None:
        self.columns.append((args, kwargs))

    def add_row(self, *values) -> None:
        self.rows.append(values)


class _FakeConsole:
    instances: list["_FakeConsole"] = []

    def __init__(self, file=None) -> None:
        self.file = file
        self.printed: list[object] = []
        self.__class__.instances.append(self)

    def print(self, renderable) -> None:
        self.printed.append(renderable)


class _FakeProgress:
    instances: list["_FakeProgress"] = []
    active = 0
    maximum_active = 0

    def __init__(self, *columns, **kwargs) -> None:
        self.columns = columns
        self.kwargs = kwargs
        self.tasks: dict[int, dict[str, object]] = {}
        self.started = False
        self.__class__.instances.append(self)

    def start(self) -> None:
        if not self.started:
            self.started = True
            self.__class__.active += 1
            self.__class__.maximum_active = max(
                self.__class__.maximum_active,
                self.__class__.active,
            )

    def stop(self) -> None:
        if self.started:
            self.started = False
            self.__class__.active -= 1

    def add_task(self, description: str, total=None) -> int:
        task_id = len(self.tasks) + 1
        self.tasks[task_id] = {
            "description": description,
            "total": total,
            "completed": 0,
        }
        return task_id

    def update(self, task_id: int, **values) -> None:
        self.tasks[task_id].update(values)


class _FakeRichHandler(logging.Handler):
    def __init__(self, **kwargs) -> None:
        super().__init__()
        self.kwargs = kwargs
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))


def _fake_components() -> _RichComponents:
    column = type("FakeColumn", (), {"__init__": lambda self, *a, **k: None})
    return _RichComponents(
        Console=_FakeConsole,
        Panel=_FakeRenderable,
        Table=_FakeTable,
        Text=_FakeRenderable,
        Progress=_FakeProgress,
        SpinnerColumn=column,
        TextColumn=column,
        BarColumn=column,
        TaskProgressColumn=column,
        TimeElapsedColumn=column,
        RichHandler=_FakeRichHandler,
    )


def _result(tool_name: str, flags: list[str] | None = None) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        return_code=0,
        stdout="",
        stderr="",
        flags_found=flags or [],
        elapsed_seconds=0.001,
    )


class TerminalUIFactoryTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeConsole.instances.clear()
        _FakeProgress.instances.clear()
        _FakeProgress.active = 0
        _FakeProgress.maximum_active = 0
        self.logger = logging.getLogger(f"dayi.ui.test.{id(self)}")
        self.logger.handlers.clear()
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)
        self.stream_handler = logging.StreamHandler(io.StringIO())
        self.logger.addHandler(self.stream_handler)

    def tearDown(self) -> None:
        for handler in list(self.logger.handlers):
            self.logger.removeHandler(handler)
            handler.close()

    def test_missing_rich_falls_back_on_interactive_terminal(self) -> None:
        with patch("dayi.persona._load_rich_components", return_value=None):
            ui = create_terminal_ui(self.logger, _TTYBuffer())

        self.assertIsInstance(ui, PlainTerminalUI)

    def test_non_tty_never_attempts_rich_import(self) -> None:
        loader = unittest.mock.Mock(side_effect=AssertionError("must not load"))
        with patch("dayi.persona._load_rich_components", loader):
            ui = create_terminal_ui(self.logger, io.StringIO())

        self.assertIsInstance(ui, PlainTerminalUI)
        loader.assert_not_called()

    def test_rich_mode_uses_one_live_owner_and_restores_logging(self) -> None:
        with patch(
            "dayi.persona._load_rich_components",
            return_value=_fake_components(),
        ):
            ui = create_terminal_ui(self.logger, _TTYBuffer())

        self.assertIsInstance(ui, RichTerminalUI)
        self.assertNotIn(self.stream_handler, self.logger.handlers)
        ui.phase_started("CONCURRENT", ("binwalk", "chi_square"))
        ui.plugin_started("binwalk")
        ui.plugin_progress("binwalk", 25, 100)
        ui.plugin_finished("binwalk", "complete")
        ui.show_artifact("[!] Bit yeniği var yeğenim")
        ui.show_flag("FLAG{rich}", "binwalk")
        ui.phase_finished("CONCURRENT")
        ui.close()
        ui.close()

        self.assertEqual(_FakeProgress.maximum_active, 1)
        self.assertEqual(_FakeProgress.active, 0)
        self.assertIn(self.stream_handler, self.logger.handlers)
        self.assertEqual(len(_FakeConsole.instances[0].printed), 2)

    def test_rich_initialization_failure_restores_plain_logging(self) -> None:
        class BrokenHandler:
            def __init__(self, **kwargs) -> None:
                raise RuntimeError("handler failure")

        components = replace(_fake_components(), RichHandler=BrokenHandler)
        with patch(
            "dayi.persona._load_rich_components",
            return_value=components,
        ):
            ui = create_terminal_ui(self.logger, _TTYBuffer())

        self.assertIsInstance(ui, PlainTerminalUI)
        self.assertIn(self.stream_handler, self.logger.handlers)


class _RecordingUI(TerminalUI):
    def __init__(self) -> None:
        self.events: list[tuple] = []

    def phase_started(self, phase: str, plugins: tuple[str, ...]) -> None:
        self.events.append(("phase_started", phase, plugins))

    def phase_finished(self, phase: str) -> None:
        self.events.append(("phase_finished", phase))

    def plugin_started(self, plugin_id: str) -> None:
        self.events.append(("plugin_started", plugin_id))

    def plugin_progress(
        self, plugin_id: str, attempted: int, total: int | None
    ) -> None:
        self.events.append(("progress", plugin_id, attempted, total))

    def plugin_finished(self, plugin_id: str, outcome: str) -> None:
        self.events.append(("plugin_finished", plugin_id, outcome))

    def show_flag(self, flag: str, source: str | None = None) -> None:
        self.events.append(("flag", flag, source))

    def show_no_flags(self) -> None:
        self.events.append(("no_flags",))

    def close(self) -> None:
        self.events.append(("close",))


class RunnerUIIntegrationTests(unittest.TestCase):
    def test_runner_routes_progress_and_lifecycle_events(self) -> None:
        ui = _RecordingUI()

        async def plugin(context: PluginContext) -> ToolResult:
            context.report_progress(4, 10)
            return _result("worker", ["FLAG{ui}"])

        registry = PluginRegistry(
            (
                ToolPlugin(
                    plugin_id="worker",
                    phase=PluginPhase.CONCURRENT,
                    priority=10,
                    run=plugin,
                ),
            )
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"data")
            runner = DayiRunner(
                target,
                re.compile(r"FLAG\{.*?\}"),
                registry=registry,
                ui=ui,
            )
            report = asyncio.run(runner.run_all())

        self.assertEqual(report.all_flags, ["FLAG{ui}"])
        self.assertIn(("progress", "worker", 4, 10), ui.events)
        self.assertIn(("plugin_finished", "worker", "complete"), ui.events)
        self.assertIn(("flag", "FLAG{ui}", "worker"), ui.events)
        self.assertEqual(ui.events[-1], ("close",))

    def test_plugin_exception_still_finishes_ui_and_scan(self) -> None:
        ui = _RecordingUI()

        async def broken(context: PluginContext) -> ToolResult:
            raise RuntimeError("boom")

        registry = PluginRegistry(
            (
                ToolPlugin(
                    plugin_id="broken",
                    phase=PluginPhase.CONCURRENT,
                    priority=10,
                    run=broken,
                ),
            )
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"data")
            report = asyncio.run(
                DayiRunner(
                    target,
                    re.compile(r"FLAG\{.*?\}"),
                    registry=registry,
                    ui=ui,
                ).run_all()
            )

        self.assertEqual(len(report.tool_results), 1)
        self.assertTrue(report.tool_results[0].skipped)
        self.assertIn(("plugin_finished", "broken", "failed"), ui.events)
        self.assertIn(("phase_finished", "CONCURRENT"), ui.events)
        self.assertEqual(ui.events[-1], ("close",))

    def test_timeout_exceptions_and_results_keep_distinct_runner_semantics(self) -> None:
        async def builtin_timeout(_context: PluginContext) -> ToolResult:
            raise TimeoutError("built-in deadline exceeded")

        async def asyncio_timeout(_context: PluginContext) -> ToolResult:
            raise asyncio.TimeoutError("asyncio deadline exceeded")

        async def returned_timeout(_context: PluginContext) -> ToolResult:
            return ToolResult(
                tool_name="returned-timeout",
                command=["controlled", "--timeout"],
                return_code=None,
                stdout="",
                stderr="controlled plugin time budget exhausted",
                flags_found=[],
                elapsed_seconds=1.25,
                timed_out=True,
            )

        async def ordinary_failure(_context: PluginContext) -> ToolResult:
            raise RuntimeError("ordinary plugin failure")

        cases = (
            ("builtin-timeout", builtin_timeout, "timed_out", True),
            ("asyncio-timeout", asyncio_timeout, "timed_out", True),
            ("returned-timeout", returned_timeout, "timed_out", True),
            ("ordinary-failure", ordinary_failure, "failed", False),
        )
        for plugin_id, run, outcome, is_timeout in cases:
            with self.subTest(plugin_id=plugin_id), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                target = root / "target.bin"
                target.write_bytes(b"data")
                ui = _RecordingUI()
                registry = PluginRegistry((ToolPlugin(
                    plugin_id=plugin_id,
                    phase=PluginPhase.CONCURRENT,
                    priority=10,
                    run=run,
                ),))
                report = asyncio.run(DayiRunner(
                    target,
                    re.compile(r"FLAG\{.*?\}"),
                    registry=registry,
                    ui=ui,
                ).run_all())
                json_path = root / "report.json"
                text_path = root / "report.txt"
                write_json_report(report, json_path)
                write_txt_report(report, text_path)
                payload = json.loads(json_path.read_text(encoding="utf-8"))
                rendered = text_path.read_text(encoding="utf-8")

            result = report.tool_results[0]
            serialized = payload["tool_results"][0]
            self.assertEqual(result.timed_out, is_timeout)
            self.assertEqual(result.error, not is_timeout)
            self.assertEqual(result.skipped, not is_timeout)
            self.assertEqual(serialized["timed_out"], is_timeout)
            self.assertEqual(serialized["error"], not is_timeout)
            self.assertEqual(serialized["skipped"], not is_timeout)
            self.assertEqual(serialized["skip_reason"], result.skip_reason)
            self.assertIn(("plugin_finished", plugin_id, outcome), ui.events)
            if plugin_id == "returned-timeout":
                self.assertEqual(result.command, ["controlled", "--timeout"])
                self.assertEqual(serialized["command"], result.command)
            else:
                self.assertEqual(result.tool_name, plugin_id)
            if is_timeout:
                self.assertEqual(result.skip_reason, "")
                self.assertNotIn("Unhandled plugin exception", result.stderr)
                self.assertIn("time", result.stderr.lower())
                self.assertIn("Durum  : TIMEOUT", rendered)
                self.assertNotIn("ATLANDI", rendered)
            else:
                self.assertIn("Unhandled plugin exception", result.skip_reason)
                self.assertIn("ordinary plugin failure", result.stderr)
                self.assertIn("ATLANDI", rendered)
                self.assertNotIn("TIMEOUT", rendered)

    def test_broken_ui_falls_back_without_aborting_plugins(self) -> None:
        class BrokenUI(TerminalUI):
            def phase_started(
                self, phase: str, plugins: tuple[str, ...]
            ) -> None:
                raise RuntimeError("render failure")

        async def plugin(context: PluginContext) -> ToolResult:
            return _result("worker")

        registry = PluginRegistry(
            (
                ToolPlugin(
                    plugin_id="worker",
                    phase=PluginPhase.CONCURRENT,
                    priority=10,
                    run=plugin,
                ),
            )
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"data")
            runner = DayiRunner(
                target,
                re.compile(r"FLAG\{.*?\}"),
                registry=registry,
                ui=BrokenUI(),
            )
            report = asyncio.run(runner.run_all())

        self.assertEqual(len(report.tool_results), 1)
        self.assertIsInstance(runner.ui, PlainTerminalUI)

    def test_context_ignores_invalid_or_failing_progress_callbacks(self) -> None:
        def failing(attempted: int, total: int | None) -> None:
            raise RuntimeError("display failed")

        context = PluginContext(
            target=Path("target.bin"),
            flag_pattern=re.compile("FLAG"),
            timeout=1.0,
            wordlist=None,
            mini_wordlist=(),
            bf_threads=1,
            bf_limit=1,
            workspace=Path("."),
            progress_reporter=failing,
        )

        context.report_progress(-1, 10)
        context.report_progress(1, -10)
        context.report_progress(1, 10)


if __name__ == "__main__":
    unittest.main()
