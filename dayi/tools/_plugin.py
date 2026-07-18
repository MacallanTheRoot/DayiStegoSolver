"""Dynamic tool-plugin contracts and discovery for Dayı Stego Solver."""
from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import re
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Awaitable, Callable, Mapping

from dayi.reporter import ToolResult

logger = logging.getLogger("dayi")

_PLUGIN_ID_PATTERN = re.compile(r"[a-z][a-z0-9_.-]*\Z")

ProgressReporter = Callable[[int, int | None], None]
ArtifactReporter = Callable[[str], None]


def _ignore_progress(attempted: int, total: int | None) -> None:
    """Default progress sink used outside the runner."""


def _ignore_artifact(message: str) -> None:
    """Default artifact sink used outside the runner."""


class PluginPhase(IntEnum):
    """Ordered execution phases understood by the generic runner."""

    CONCURRENT = 10
    ARCHIVE = 20
    MINI_BRUTE_FORCE = 30
    MAIN_PRIMARY = 40
    MAIN_FALLBACK = 50
    MAIN_FINAL = 60


@dataclass(frozen=True)
class PluginContext:
    """Read-only runner state supplied to every plugin adapter."""

    target: Path
    flag_pattern: re.Pattern
    timeout: float
    wordlist: Path | None
    mini_wordlist: tuple[str, ...]
    bf_threads: int
    bf_limit: int
    workspace: Path
    results_by_plugin: Mapping[str, ToolResult] = field(default_factory=dict)
    progress_reporter: ProgressReporter = field(
        default=_ignore_progress,
        repr=False,
        compare=False,
    )
    artifact_reporter: ArtifactReporter = field(
        default=_ignore_artifact,
        repr=False,
        compare=False,
    )

    def result(self, plugin_id: str) -> ToolResult | None:
        """Return a previously completed plugin result, if available."""
        return self.results_by_plugin.get(plugin_id)

    def report_progress(self, attempted: int, total: int | None = None) -> None:
        """Safely publish bounded progress without coupling plugins to a UI."""
        if isinstance(attempted, bool) or not isinstance(attempted, int):
            return
        if attempted < 0:
            return
        if total is not None:
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                return
        try:
            self.progress_reporter(attempted, total)
        except Exception as exc:
            logger.debug(f"Plugin ilerleme bildirimi iletilemedi yeğenim: {exc}")

    def report_artifact(self, message: str) -> None:
        """Safely publish a persona warning through the active UI."""
        if not isinstance(message, str) or not message:
            return
        try:
            self.artifact_reporter(message)
        except Exception as exc:
            logger.debug(f"Plugin artifact bildirimi iletilemedi yeğenim: {exc}")


PluginRunner = Callable[[PluginContext], Awaitable[ToolResult]]
SuccessEvaluator = Callable[[ToolResult], bool]


def flags_found_success(result: ToolResult) -> bool:
    """Treat actual flag discovery as plugin success."""
    return bool(result.flags_found)


def extraction_or_exit_success(result: ToolResult) -> bool:
    """Treat flags, extracted output, or a zero exit code as success."""
    return bool(
        not result.skipped
        and not result.timed_out
        and (
            result.flags_found
            or result.extracted_flags
            or result.return_code == 0
        )
    )


@dataclass(frozen=True)
class ToolPlugin:
    """Declarative specification for one executable plugin operation."""

    plugin_id: str
    phase: PluginPhase
    priority: int
    run: PluginRunner
    requires_wordlist: bool = False
    requires_mini_wordlist: bool = False
    contributes_to_mini_wordlist: bool = False
    skip_if_phase_succeeded: tuple[PluginPhase, ...] = ()
    skip_if_plugins_succeeded: tuple[str, ...] = ()
    success_evaluator: SuccessEvaluator = flags_found_success


@dataclass(frozen=True)
class PluginRegistry:
    """Validated, deterministically ordered collection of discovered plugins."""

    plugins: tuple[ToolPlugin, ...]
    issues: tuple[str, ...] = ()

    def for_phase(self, phase: PluginPhase) -> tuple[ToolPlugin, ...]:
        """Return plugins for a phase in deterministic priority/ID order."""
        return tuple(plugin for plugin in self.plugins if plugin.phase == phase)

    def get(self, plugin_id: str) -> ToolPlugin | None:
        """Return one plugin specification by ID."""
        return next(
            (plugin for plugin in self.plugins if plugin.plugin_id == plugin_id),
            None,
        )


class PluginValidationError(ValueError):
    """Raised when a module exposes an invalid plugin specification."""


def _validate_plugin(plugin: ToolPlugin) -> None:
    if not isinstance(plugin, ToolPlugin):
        raise PluginValidationError("PLUGIN_SPECS entries must be ToolPlugin instances")
    if _PLUGIN_ID_PATTERN.fullmatch(plugin.plugin_id) is None:
        raise PluginValidationError(f"invalid plugin_id: {plugin.plugin_id!r}")
    if not isinstance(plugin.phase, PluginPhase):
        raise PluginValidationError(f"invalid phase for {plugin.plugin_id!r}")
    if isinstance(plugin.priority, bool) or not isinstance(plugin.priority, int):
        raise PluginValidationError(f"priority must be an integer: {plugin.plugin_id!r}")
    if not inspect.iscoroutinefunction(plugin.run):
        raise PluginValidationError(f"run adapter must be async: {plugin.plugin_id!r}")
    if not callable(plugin.success_evaluator):
        raise PluginValidationError(
            f"success_evaluator must be callable: {plugin.plugin_id!r}"
        )
    if not isinstance(plugin.skip_if_phase_succeeded, tuple) or any(
        not isinstance(phase, PluginPhase)
        for phase in plugin.skip_if_phase_succeeded
    ):
        raise PluginValidationError(
            f"skip_if_phase_succeeded must contain PluginPhase values: "
            f"{plugin.plugin_id!r}"
        )
    if not isinstance(plugin.skip_if_plugins_succeeded, tuple) or any(
        not isinstance(plugin_id, str) or not plugin_id
        for plugin_id in plugin.skip_if_plugins_succeeded
    ):
        raise PluginValidationError(
            f"skip_if_plugins_succeeded must contain plugin IDs: {plugin.plugin_id!r}"
        )
    for field_name in (
        "requires_wordlist",
        "requires_mini_wordlist",
        "contributes_to_mini_wordlist",
    ):
        if not isinstance(getattr(plugin, field_name), bool):
            raise PluginValidationError(
                f"{field_name} must be boolean: {plugin.plugin_id!r}"
            )


def _warn_broken_plugin(module_name: str, detail: str) -> None:
    logger.warning(
        f"[!] Yeğenim, tools klasörüne attığın şu '{module_name}' "
        f"eklentisi bozuk çıktı, onu es geçiyorum. ({detail})"
    )


def discover_plugins(package_name: str = "dayi.tools") -> PluginRegistry:
    """Import and validate every public module in a tool package."""
    importlib.invalidate_caches()
    issues: list[str] = []
    candidates: dict[str, tuple[ToolPlugin, str]] = {}

    try:
        package = importlib.import_module(package_name)
    except Exception as exc:
        detail = f"cannot import package: {exc}"
        _warn_broken_plugin(package_name, detail)
        return PluginRegistry((), (detail,))

    package_path = getattr(package, "__path__", None)
    if package_path is None:
        detail = "plugin package has no __path__"
        _warn_broken_plugin(package_name, detail)
        return PluginRegistry((), (detail,))

    module_names = sorted(
        module_info.name
        for module_info in pkgutil.iter_modules(
            package_path, prefix=f"{package.__name__}."
        )
        if not module_info.name.rsplit(".", 1)[-1].startswith("_")
    )

    for module_name in module_names:
        short_name = module_name.rsplit(".", 1)[-1]
        try:
            module = importlib.import_module(module_name)
            specs = getattr(module, "PLUGIN_SPECS")
            if not isinstance(specs, tuple) or not specs:
                raise PluginValidationError("PLUGIN_SPECS must be a non-empty tuple")
            for plugin in specs:
                _validate_plugin(plugin)
            duplicate_ids = [
                plugin.plugin_id for plugin in specs if plugin.plugin_id in candidates
            ]
            if duplicate_ids:
                raise PluginValidationError(
                    f"duplicate plugin IDs: {', '.join(sorted(duplicate_ids))}"
                )
        except Exception as exc:
            detail = str(exc)
            issues.append(f"{module_name}: {detail}")
            _warn_broken_plugin(short_name, detail)
            continue

        for plugin in specs:
            candidates[plugin.plugin_id] = (plugin, short_name)

    # Remove specifications with unresolved result dependencies. Repeat so a
    # dependency on a removed plugin is also rejected deterministically.
    while True:
        known_ids = set(candidates)
        invalid = [
            (plugin_id, plugin, module_name)
            for plugin_id, (plugin, module_name) in candidates.items()
            if any(
                dependency not in known_ids
                for dependency in plugin.skip_if_plugins_succeeded
            )
        ]
        if not invalid:
            break
        for plugin_id, plugin, module_name in invalid:
            missing = sorted(
                dependency
                for dependency in plugin.skip_if_plugins_succeeded
                if dependency not in known_ids
            )
            detail = f"unknown plugin dependencies: {', '.join(missing)}"
            issues.append(f"{module_name}.{plugin.plugin_id}: {detail}")
            _warn_broken_plugin(module_name, detail)
            candidates.pop(plugin_id, None)

    ordered = tuple(
        sorted(
            (plugin for plugin, _module_name in candidates.values()),
            key=lambda plugin: (
                int(plugin.phase),
                plugin.priority,
                plugin.plugin_id,
            ),
        )
    )
    return PluginRegistry(ordered, tuple(issues))
