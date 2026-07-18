import asyncio
import importlib
import re
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

from dayi.reporter import ToolResult
from dayi.runner import DayiRunner
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
    discover_plugins,
    extraction_or_exit_success,
)


def _result(
    tool_name: str,
    *,
    stdout: str = "",
    flags: list[str] | None = None,
    return_code: int | None = 1,
) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        return_code=return_code,
        stdout=stdout,
        stderr="",
        flags_found=[] if flags is None else flags,
        elapsed_seconds=0.001,
    )


class PluginDiscoveryTests(unittest.TestCase):
    def test_builtin_plugins_are_complete_and_deterministic(self) -> None:
        registry = discover_plugins()

        self.assertEqual(registry.issues, ())
        self.assertEqual(
            [plugin.plugin_id for plugin in registry.plugins],
            [
                "exiftool",
                "exiv2",
                "strings",
                "binwalk",
                "pdf_scanner",
                "ole_scanner",
                "pcap_scanner",
                "zsteg",
                "lsb_py",
                "chi_square",
                "steghide_empty",
                "outguess_empty",
                "zip_cracker",
                "ocr_scanner",
                "steghide_mini_bf",
                "outguess_mini_bf",
                "stegseek_main",
                "steghide_main_bf",
                "outguess_main_bf",
            ],
        )

    def test_malformed_module_is_ignored_and_sorting_is_stable(self) -> None:
        package_name = f"dayi_test_plugins_{uuid.uuid4().hex}"
        valid_template = '''
from dayi.tools._plugin import PluginPhase, ToolPlugin

async def run(context):
    return None

PLUGIN_SPECS = (
    ToolPlugin(plugin_id={plugin_id!r}, phase=PluginPhase.CONCURRENT,
               priority={priority}, run=run),
)
'''

        with tempfile.TemporaryDirectory() as tmpdir:
            package_dir = Path(tmpdir) / package_name
            package_dir.mkdir()
            (package_dir / "__init__.py").write_text("", encoding="utf-8")
            (package_dir / "z_module.py").write_text(
                valid_template.format(plugin_id="alpha", priority=10),
                encoding="utf-8",
            )
            (package_dir / "a_module.py").write_text(
                valid_template.format(plugin_id="zulu", priority=10),
                encoding="utf-8",
            )
            (package_dir / "m_module.py").write_text(
                valid_template.format(plugin_id="omega", priority=20),
                encoding="utf-8",
            )
            (package_dir / "broken.py").write_text(
                "PLUGIN_SPECS = 'not-a-tuple'\n",
                encoding="utf-8",
            )

            sys.path.insert(0, tmpdir)
            importlib.invalidate_caches()
            try:
                with self.assertLogs("dayi", level="WARNING") as captured:
                    registry = discover_plugins(package_name)
            finally:
                sys.path.remove(tmpdir)
                for module_name in list(sys.modules):
                    if module_name == package_name or module_name.startswith(
                        f"{package_name}."
                    ):
                        sys.modules.pop(module_name, None)

        self.assertEqual(
            [plugin.plugin_id for plugin in registry.plugins],
            ["alpha", "zulu", "omega"],
        )
        self.assertEqual(len(registry.issues), 1)
        warning = "\n".join(captured.output)
        self.assertIn("'broken' eklentisi bozuk çıktı", warning)


class PluginRunnerTests(unittest.TestCase):
    def _run(self, registry: PluginRegistry, wordlist: Path | None = None):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.png"
            target.write_bytes(b"test")
            runner = DayiRunner(
                target,
                re.compile(r"FLAG\{.*?\}"),
                wordlist=wordlist,
                registry=registry,
            )
            return asyncio.run(runner.run_all())

    def test_concurrent_phase_really_starts_plugins_together(self) -> None:
        started = 0
        gate = asyncio.Event()

        async def operation(context: PluginContext) -> ToolResult:
            nonlocal started
            started += 1
            if started == 2:
                gate.set()
            await asyncio.wait_for(gate.wait(), timeout=0.5)
            return _result(f"tool_{started}")

        registry = PluginRegistry(
            tuple(
                ToolPlugin(
                    plugin_id=f"concurrent_{index}",
                    phase=PluginPhase.CONCURRENT,
                    priority=index,
                    run=operation,
                )
                for index in (1, 2)
            )
        )

        report = self._run(registry)

        self.assertEqual(started, 2)
        self.assertEqual(len(report.tool_results), 2)

    def test_successful_mini_phase_skips_declared_main_phases(self) -> None:
        calls: list[str] = []

        async def source(context: PluginContext) -> ToolResult:
            calls.append("source")
            return _result("metadata", stdout="70617373776f7264")

        async def mini(context: PluginContext) -> ToolResult:
            calls.append("mini")
            self.assertIn("password", context.mini_wordlist)
            return _result("mini", flags=["FLAG{mini}"])

        async def main(context: PluginContext) -> ToolResult:
            calls.append("main")
            return _result("main", flags=["FLAG{main}"])

        skip_mini = (PluginPhase.MINI_BRUTE_FORCE,)
        registry = PluginRegistry(
            (
                ToolPlugin(
                    "source",
                    PluginPhase.CONCURRENT,
                    10,
                    source,
                    contributes_to_mini_wordlist=True,
                ),
                ToolPlugin(
                    "mini",
                    PluginPhase.MINI_BRUTE_FORCE,
                    10,
                    mini,
                    requires_mini_wordlist=True,
                ),
                ToolPlugin(
                    "primary",
                    PluginPhase.MAIN_PRIMARY,
                    10,
                    main,
                    skip_if_phase_succeeded=skip_mini,
                ),
                ToolPlugin(
                    "fallback",
                    PluginPhase.MAIN_FALLBACK,
                    10,
                    main,
                    skip_if_phase_succeeded=skip_mini,
                ),
                ToolPlugin(
                    "final",
                    PluginPhase.MAIN_FINAL,
                    10,
                    main,
                    skip_if_phase_succeeded=skip_mini,
                ),
            )
        )

        report = self._run(registry)

        self.assertEqual(calls, ["source", "mini"])
        self.assertEqual(report.all_flags, ["FLAG{mini}"])

    def test_plugin_success_can_skip_only_its_declared_fallback(self) -> None:
        calls: list[str] = []

        async def primary(context: PluginContext) -> ToolResult:
            calls.append("primary")
            return _result("primary", return_code=0)

        async def fallback(context: PluginContext) -> ToolResult:
            calls.append("fallback")
            return _result("fallback")

        async def final(context: PluginContext) -> ToolResult:
            calls.append("final")
            return _result("final")

        registry = PluginRegistry(
            (
                ToolPlugin(
                    "primary",
                    PluginPhase.MAIN_PRIMARY,
                    10,
                    primary,
                    success_evaluator=extraction_or_exit_success,
                ),
                ToolPlugin(
                    "fallback",
                    PluginPhase.MAIN_FALLBACK,
                    10,
                    fallback,
                    skip_if_plugins_succeeded=("primary",),
                ),
                ToolPlugin(
                    "final",
                    PluginPhase.MAIN_FINAL,
                    10,
                    final,
                ),
            )
        )

        self._run(registry)

        self.assertEqual(calls, ["primary", "final"])


if __name__ == "__main__":
    unittest.main()
