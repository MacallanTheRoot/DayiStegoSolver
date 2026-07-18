"""Static inspection and rendering for the trusted Dayı plugin registry."""
from __future__ import annotations

import importlib.util
import json
import shutil
from dataclasses import asdict, dataclass
from typing import Any, Callable, Sequence

from dayi.tools._plugin import (
    PluginDiscoveryIssue,
    PluginDiscoveryResult,
    ToolPlugin,
    discover_plugins_with_issues,
    flags_found_success,
)

PLUGIN_INSPECTION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class PluginAvailability:
    """Static implementation availability and scan-time readiness."""

    status: str
    runnable: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class PluginDiagnostic:
    """Serializable metadata for one registered plugin."""

    plugin_id: str
    phase: str
    priority: int
    requires_wordlist: bool
    requires_mini_wordlist: bool
    contributes_to_mini_wordlist: bool
    skip_if_phase_succeeded: tuple[str, ...]
    skip_if_plugins_succeeded: tuple[str, ...]
    has_custom_success_evaluator: bool
    module: str | None
    required_executables: tuple[str, ...]
    required_python_modules: tuple[str, ...]
    availability: PluginAvailability


@dataclass(frozen=True)
class PluginInspectionReport:
    """Complete deterministic plugin registry inspection."""

    plugins: tuple[PluginDiagnostic, ...]
    issues: tuple[PluginDiscoveryIssue, ...]
    schema_version: int = PLUGIN_INSPECTION_SCHEMA_VERSION

    @property
    def plugin_count(self) -> int:
        return len(self.plugins)

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON-compatible inspection schema."""
        return {
            "schema_version": self.schema_version,
            "plugin_count": self.plugin_count,
            "issue_count": self.issue_count,
            "plugins": [asdict(plugin) for plugin in self.plugins],
            "issues": [asdict(issue) for issue in self.issues],
        }


def _deduplicate(values: Sequence[str]) -> tuple[str, ...]:
    """Deduplicate strings while preserving deterministic insertion order."""
    return tuple(dict.fromkeys(values))


def evaluate_plugin_availability(
    plugin: ToolPlugin,
    *,
    which: Callable[[str], str | None] | None = None,
    find_spec: Callable[[str], Any] | None = None,
) -> PluginAvailability:
    """Evaluate declared static requirements without executing plugin code."""
    which_func = shutil.which if which is None else which
    find_spec_func = importlib.util.find_spec if find_spec is None else find_spec
    missing: list[str] = []
    unknown: list[str] = []
    conditional: list[str] = []

    for executable in plugin.required_executables:
        try:
            resolved = which_func(executable)
        except Exception:
            unknown.append(
                f"external executable '{executable}' availability could not be determined"
            )
            continue
        if resolved is None:
            missing.append(f"external executable '{executable}' was not found")

    for module_name in plugin.required_python_modules:
        try:
            spec = find_spec_func(module_name)
        except Exception:
            unknown.append(
                f"Python module '{module_name}' availability could not be determined"
            )
            continue
        if spec is None:
            missing.append(f"Python module '{module_name}' was not found")

    if plugin.requires_wordlist:
        conditional.append("requires a scan-time main wordlist")
    if plugin.requires_mini_wordlist:
        conditional.append("requires a generated mini-wordlist")
    if plugin.skip_if_phase_succeeded:
        phases = ", ".join(phase.name for phase in plugin.skip_if_phase_succeeded)
        conditional.append(f"execution depends on phase outcomes: {phases}")
    if plugin.skip_if_plugins_succeeded:
        dependencies = ", ".join(plugin.skip_if_plugins_succeeded)
        conditional.append(f"execution depends on plugin outcomes: {dependencies}")

    reasons = _deduplicate((*missing, *unknown, *conditional))
    if missing:
        status = "unavailable"
    elif unknown:
        status = "unknown"
    elif conditional:
        status = "conditional"
    else:
        status = "available"
    return PluginAvailability(
        status=status,
        runnable=status == "available",
        reasons=reasons,
    )


def inspect_plugin(
    plugin: ToolPlugin,
    *,
    which: Callable[[str], str | None] | None = None,
    find_spec: Callable[[str], Any] | None = None,
) -> PluginDiagnostic:
    """Convert one validated plugin definition into inspection metadata."""
    return PluginDiagnostic(
        plugin_id=plugin.plugin_id,
        phase=plugin.phase.name,
        priority=plugin.priority,
        requires_wordlist=plugin.requires_wordlist,
        requires_mini_wordlist=plugin.requires_mini_wordlist,
        contributes_to_mini_wordlist=plugin.contributes_to_mini_wordlist,
        skip_if_phase_succeeded=tuple(
            phase.name for phase in plugin.skip_if_phase_succeeded
        ),
        skip_if_plugins_succeeded=plugin.skip_if_plugins_succeeded,
        has_custom_success_evaluator=(
            plugin.success_evaluator is not flags_found_success
        ),
        module=getattr(plugin.run, "__module__", None),
        required_executables=plugin.required_executables,
        required_python_modules=plugin.required_python_modules,
        availability=evaluate_plugin_availability(
            plugin, which=which, find_spec=find_spec
        ),
    )


def inspect_discovery_result(
    discovery: PluginDiscoveryResult,
    *,
    which: Callable[[str], str | None] | None = None,
    find_spec: Callable[[str], Any] | None = None,
) -> PluginInspectionReport:
    """Inspect a discovery result without changing its registry ordering."""
    plugins = tuple(
        inspect_plugin(plugin, which=which, find_spec=find_spec)
        for plugin in discovery.registry.plugins
    )
    return PluginInspectionReport(plugins=plugins, issues=discovery.issues)


def inspect_plugins() -> PluginInspectionReport:
    """Discover trusted package plugins and collect static inspection results."""
    return inspect_discovery_result(discover_plugins_with_issues())


def render_plain(report: PluginInspectionReport) -> str:
    """Render a precise zero-dependency plugin registry listing."""
    lines = [
        "Dayı Plugins",
        "",
        f"Registered plugins: {report.plugin_count}",
        f"Discovery issues: {report.issue_count}",
        "",
        "ID                       Phase              Priority  Availability  Requirements",
    ]
    for plugin in report.plugins:
        requirements = [
            *plugin.required_executables,
            *plugin.required_python_modules,
        ]
        if plugin.requires_wordlist:
            requirements.append("wordlist")
        if plugin.requires_mini_wordlist:
            requirements.append("mini-wordlist")
        rendered_requirements = ", ".join(requirements) or "-"
        lines.append(
            f"{plugin.plugin_id:<24} {plugin.phase:<18} "
            f"{plugin.priority:<9} {plugin.availability.status:<13} "
            f"{rendered_requirements}"
        )

    lines.extend(("", "Dependencies"))
    dependency_lines = 0
    for plugin in report.plugins:
        if not (
            plugin.skip_if_phase_succeeded
            or plugin.skip_if_plugins_succeeded
        ):
            continue
        dependency_lines += 1
        lines.append(f"  {plugin.plugin_id}:")
        if plugin.skip_if_phase_succeeded:
            lines.append(
                "    skip if phase succeeds: "
                + ", ".join(plugin.skip_if_phase_succeeded)
            )
        if plugin.skip_if_plugins_succeeded:
            lines.append(
                "    skip if plugin succeeds: "
                + ", ".join(plugin.skip_if_plugins_succeeded)
            )
    if not dependency_lines:
        lines.append("  none")

    lines.extend(("", "Discovery issues"))
    if report.issues:
        for issue in report.issues:
            subject = issue.plugin_id or issue.module or "registry"
            lines.append(
                f"  [{issue.severity}] {issue.code} ({subject}): {issue.message}"
            )
    else:
        lines.append("  none")
    lines.extend(
        (
            "",
            "[+] Yeğenim bu liste kayıtlı tanımları gösterir; eklenti runner'ları "
            "ve harici araçlar çalıştırılmadı.",
        )
    )
    return "\n".join(lines)


def render_json(report: PluginInspectionReport) -> str:
    """Render deterministic plugin inspection JSON without decoration."""
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
