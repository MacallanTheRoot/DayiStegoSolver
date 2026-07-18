"""Dynamic, phase-aware asynchronous orchestrator for Dayı Stego Solver."""
from __future__ import annotations

import asyncio
import binascii
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from dayi.persona import PlainTerminalUI, TerminalUI, create_terminal_ui
from dayi.reporter import ScanReport, ToolResult
from dayi.scanner import (
    MAX_ARTIFACT_FINDINGS,
    ArtifactFinding,
    decode_base64_text,
    scan_artifacts,
)
from dayi.tools._base import sanitize_token
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    PluginRegistry,
    ToolPlugin,
    discover_plugins,
)

MAX_WORKSPACE_RETENTION_ENTRIES = 16_384

if TYPE_CHECKING:
    from collections.abc import Awaitable
    from dayi.integrations import IntegrationManager

logger = logging.getLogger("dayi")

_MINI_WL_TOKEN_PATTERN: re.Pattern = re.compile(r"[^\s]{5,30}")
_HEX_TOKEN_PATTERN: re.Pattern = re.compile(r"[0-9a-fA-F]+")
_MINI_WL_MAX_TOKENS = 300
_DEFAULT_MINI_WL_SOURCE_TOOLS: frozenset[str] = frozenset(
    {"exiftool", "exiv2", "strings", "binwalk"}
)

_ARTIFACT_LABELS: dict[str, str] = {
    "url": "URL",
    "ipv4": "IPv4 adresi",
    "ipv6": "IPv6 adresi",
    "domain": "alan adı",
    "base64": "Base64 metni",
    "credential": "kimlik bilgisi ipucu",
    "coordinates_decimal": "ondalık koordinat",
    "coordinates_dms": "DMS koordinatı",
}


def _decode_hex_ascii(token: str) -> str | None:
    """Decode an even-length hexadecimal token into printable ASCII."""
    if len(token) % 2 != 0 or _HEX_TOKEN_PATTERN.fullmatch(token) is None:
        return None
    try:
        decoded = binascii.unhexlify(token)
    except (binascii.Error, ValueError):
        return None
    if not decoded or any(byte < 0x20 or byte > 0x7E for byte in decoded):
        return None
    text = decoded.decode("ascii")
    return text if text.strip() else None


def _decoded_token_variants(token: str) -> list[str]:
    """Return safe in-memory Hex/Base64 decodings for one sanitized token."""
    variants: list[str] = []
    hex_decoded = _decode_hex_ascii(token)
    if hex_decoded is not None:
        variants.append(hex_decoded)

    base64_decoded = decode_base64_text(token)
    if (
        base64_decoded is not None
        and base64_decoded.strip()
        and all(char.isprintable() for char in base64_decoded)
        and base64_decoded not in variants
    ):
        variants.append(base64_decoded)
    return variants


def _extract_mini_wordlist(
    results: list[ToolResult],
    source_tool_names: frozenset[str] | set[str] | None = None,
) -> list[str]:
    """Build a bounded, decoded mini-wordlist from declared source tools."""
    sources = (
        _DEFAULT_MINI_WL_SOURCE_TOOLS
        if source_tool_names is None
        else frozenset(source_tool_names)
    )
    seen: dict[str, None] = {}

    for result in results:
        if result.tool_name not in sources:
            continue
        for text in (result.stdout, result.stderr):
            for raw_token in _MINI_WL_TOKEN_PATTERN.findall(text):
                clean = sanitize_token(raw_token)
                if clean is None:
                    continue

                variants = (clean, *_decoded_token_variants(clean))
                new_variants = [
                    candidate for candidate in variants if candidate not in seen
                ]
                if len(seen) + len(new_variants) > _MINI_WL_MAX_TOKENS:
                    return list(seen)
                for candidate in new_variants:
                    seen[candidate] = None
    return list(seen)


class DayiRunner:
    """Discover plugins and execute their declared phases safely."""

    def __init__(
        self,
        target: Path,
        pattern: re.Pattern,
        wordlist: Path | None = None,
        timeout: float = 60.0,
        bf_threads: int = 8,
        bf_limit: int = 1000,
        integration: IntegrationManager | None = None,
        registry: PluginRegistry | None = None,
        ui: TerminalUI | None = None,
    ) -> None:
        self.target = target
        self.pattern = pattern
        self.wordlist = wordlist
        self.timeout = timeout
        self.bf_threads = bf_threads
        self.bf_limit = bf_limit
        self.integration = integration
        self.registry = registry if registry is not None else discover_plugins()
        self.ui = ui if ui is not None else create_terminal_ui(logger)

        self._partial_results: list[ToolResult] = []
        self._results_by_plugin: dict[str, ToolResult] = {}
        self._successful_plugins: set[str] = set()
        self._successful_phases: set[PluginPhase] = set()
        self._started_at = ""
        self._announced_artifacts: set[tuple[str, str, str | None]] = set()
        self._workspace: Path | None = None
        self._retained_workspace: Path | None = None
        self._last_report: ScanReport | None = None
        self._mini_wordlist: list[str] = []

    async def run_all(self) -> ScanReport:
        """Execute discovered plugins and return a complete or partial report."""
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._partial_results.clear()
        self._results_by_plugin.clear()
        self._successful_plugins.clear()
        self._successful_phases.clear()
        self._announced_artifacts.clear()
        self._mini_wordlist.clear()
        self._retained_workspace = None
        self._last_report = None
        self._workspace = Path(
            tempfile.mkdtemp(prefix="dayi_runner_", dir=Path.cwd())
        )
        cancelled = False
        fatal_error: BaseException | None = None

        try:
            await self._run_concurrent_phase()
            self._mini_wordlist = self._build_dynamic_mini_wordlist()
            await self._run_archive_phase(self._mini_wordlist)
            mini_succeeded = await self._run_mini_wordlist_phase(
                self._mini_wordlist
            )

            if mini_succeeded:
                logger.info(
                    "[runner] 🏆 Mini-wordlist şifreyi buldu! "
                    "Ana rockyou turunu atlıyorum, böyle olur işte yeğenim!"
                )
            await self._run_main_wordlist_phase()

        except asyncio.CancelledError:
            cancelled = True
            self._ui_call(
                "show_warning",
                "\n[!] Yeğenim acelen var galiba, durdurduk! "
                "Ama o ana kadar bulduklarımı rapora yazıyorum... "
                "Boşa gitmez hiçbir şey!",
            )
        except BaseException as exc:
            fatal_error = exc
            logger.error(
                f"[runner] Analiz yaşam döngüsü tökezledi yeğenim: {exc}"
            )
        finally:
            try:
                if self.integration:
                    try:
                        await self.integration.drain()
                    except Exception as exc:
                        logger.warning(
                            "[runner] Yeğenim bildirim kuyruğu kapanırken "
                            f"tökezledi; raporu yine kurtarıyorum. ({exc})"
                        )
            finally:
                workspace_path = self._workspace
                if workspace_path is not None and self._workspace_has_useful_files(
                    workspace_path
                ):
                    self._retained_workspace = workspace_path
                    logger.warning(
                        "[+] Yeğenim, içinden işe yarar dosyalar çıktı; "
                        f"emanetleri burada sakladım: {workspace_path}"
                    )
                elif workspace_path is not None:
                    shutil.rmtree(workspace_path, ignore_errors=True)
                    logger.debug(
                        f"[runner] Geçici analiz alanı temizlendi: {workspace_path}"
                    )
                self._workspace = None

        try:
            report = self._build_report()
            self._last_report = report
        finally:
            self._ui_call("close")
        if cancelled:
            raise asyncio.CancelledError
        if fatal_error is not None:
            raise fatal_error
        return report

    def _workspace_has_useful_files(self, workspace: Path) -> bool:
        """Return whether declared extraction outputs contain useful files."""
        declared: list[Path] = []
        for result in self._partial_results:
            if result.extracted_dir:
                declared.append(Path(result.extracted_dir))
        workspace_root = workspace.resolve()
        copied_target = workspace / "binwalk" / self.target.name
        for directory in declared:
            try:
                resolved = directory.resolve()
                if not resolved.is_relative_to(workspace_root) or not resolved.is_dir():
                    continue
                visited = 0
                for current, dirs, files in os.walk(resolved, followlinks=False):
                    dirs[:] = [
                        name for name in dirs
                        if not (Path(current) / name).is_symlink()
                    ]
                    for name in files:
                        visited += 1
                        if visited > MAX_WORKSPACE_RETENTION_ENTRIES:
                            return False
                        candidate = Path(current) / name
                        if candidate.is_symlink() or not candidate.is_file():
                            continue
                        if candidate == copied_target:
                            continue
                        if candidate.stat().st_size > 0:
                            return True
            except OSError:
                continue
        return False

    def _make_context(
        self,
        mini_wordlist: list[str] | tuple[str, ...] | None = None,
        plugin_id: str = "unknown",
    ) -> PluginContext:
        """Snapshot current runner state for a plugin invocation."""
        # Preserve direct/internal callers that populated only partial_results.
        for result in self._partial_results:
            self._results_by_plugin.setdefault(result.tool_name, result)

        workspace = self._workspace or self.target.parent
        loop = asyncio.get_running_loop()
        candidates = self._mini_wordlist if mini_wordlist is None else mini_wordlist
        return PluginContext(
            target=self.target,
            flag_pattern=self.pattern,
            timeout=self.timeout,
            wordlist=self.wordlist,
            mini_wordlist=tuple(candidates),
            bf_threads=self.bf_threads,
            bf_limit=self.bf_limit,
            workspace=workspace,
            results_by_plugin=MappingProxyType(dict(self._results_by_plugin)),
            progress_reporter=lambda attempted, total: loop.call_soon_threadsafe(
                self._ui_call, "plugin_progress", plugin_id, attempted, total
            ),
            artifact_reporter=lambda message: loop.call_soon_threadsafe(
                self._ui_call, "show_artifact", message
            ),
        )

    async def _run_concurrent_phase(self) -> None:
        plugins = self.registry.for_phase(PluginPhase.CONCURRENT)
        if not plugins:
            self._ui_call(
                "show_warning",
                "[runner] Çalışacak concurrent eklenti bulunamadı yeğenim."
            )
            return

        self._ui_call(
            "phase_started",
            PluginPhase.CONCURRENT.name,
            tuple(plugin.plugin_id for plugin in plugins),
        )
        try:
            gathered = await asyncio.gather(
                *(
                    self._execute_plugin(
                        plugin,
                        self._make_context((), plugin.plugin_id),
                    )
                    for plugin in plugins
                ),
                return_exceptions=True,
            )
            for plugin, item in zip(plugins, gathered, strict=True):
                if isinstance(item, BaseException):
                    if isinstance(item, asyncio.CancelledError):
                        raise item
                    logger.error(
                        f"[runner] '{plugin.plugin_id}' eklentisi çöktü: {item}"
                    )
                    result = self._error_result(plugin.plugin_id, item)
                else:
                    result = item
                self._record_result(plugin, result)
        finally:
            self._ui_call("phase_finished", PluginPhase.CONCURRENT.name)

    async def _run_sequential_phase(self, phase: PluginPhase) -> bool:
        """Execute one phase in deterministic priority order."""
        plugins = self.registry.for_phase(phase)
        if not plugins:
            return False
        self._ui_call(
            "phase_started",
            phase.name,
            tuple(plugin.plugin_id for plugin in plugins),
        )
        try:
            for plugin in plugins:
                reason = self._plugin_skip_reason(plugin)
                if reason is not None:
                    logger.debug(
                        f"[runner] {plugin.plugin_id} atlandı: {reason}"
                    )
                    self._ui_call("plugin_finished", plugin.plugin_id, "skipped")
                    continue
                context = self._make_context(plugin_id=plugin.plugin_id)
                result = await self._execute_plugin(plugin, context)
                self._record_result(plugin, result)
        finally:
            self._ui_call("phase_finished", phase.name)
        return phase in self._successful_phases

    async def _run_archive_phase(self, mini_wordlist: list[str]) -> None:
        """Compatibility wrapper for the dynamically declared archive phase."""
        self._mini_wordlist = list(mini_wordlist)
        await self._run_sequential_phase(PluginPhase.ARCHIVE)

    async def _run_mini_wordlist_phase(
        self, mini_wordlist: list[str] | None = None
    ) -> bool:
        """Execute declared mini-wordlist operations sequentially."""
        if mini_wordlist is not None:
            self._mini_wordlist = list(mini_wordlist)
        if not self._mini_wordlist:
            logger.info(
                "[runner] Metadata çıktısından aday token bulunamadı, "
                "mini-wordlist turu atlanıyor."
            )
            return False

        logger.info(
            f"[runner] Yeğenim, dosyanın sağından solundan "
            f"{len(self._mini_wordlist)} kelime topladım (temizlenmiş). "
            "Bence şifre bunlardan biri, ana wordlist'e girmeden önce "
            "şunları bir deneyeyim..."
        )
        logger.debug(
            f"[runner] Mini-wordlist sample: "
            f"{self._mini_wordlist[:10]}"
            f"{'...' if len(self._mini_wordlist) > 10 else ''}"
        )
        succeeded = await self._run_sequential_phase(
            PluginPhase.MINI_BRUTE_FORCE
        )
        if succeeded:
            logger.log(
                25,
                "[runner] 🎯 Mini-wordlist işe yaradı! "
                "Dedim ya yeğenim, şifre dosyanın içindeydi!",
            )
        else:
            logger.info(
                "[runner] Mini-wordlist turunda şifre bulunamadı. "
                "Asıl wordlist'e geçiyorum, sabret yeğenim..."
            )
        return succeeded

    async def _run_main_wordlist_phase(self) -> None:
        """Execute generic primary, fallback, and final main phases."""
        await self._run_sequential_phase(PluginPhase.MAIN_PRIMARY)
        await self._run_sequential_phase(PluginPhase.MAIN_FALLBACK)
        await self._run_sequential_phase(PluginPhase.MAIN_FINAL)

    def _plugin_skip_reason(self, plugin: ToolPlugin) -> str | None:
        if plugin.requires_wordlist and self.wordlist is None:
            return "wordlist is required"
        if plugin.requires_mini_wordlist and not self._mini_wordlist:
            return "mini-wordlist is required"
        successful_phase = next(
            (
                phase
                for phase in plugin.skip_if_phase_succeeded
                if phase in self._successful_phases
            ),
            None,
        )
        if successful_phase is not None:
            return f"phase {successful_phase.name} already succeeded"
        successful_dependency = next(
            (
                plugin_id
                for plugin_id in plugin.skip_if_plugins_succeeded
                if plugin_id in self._successful_plugins
            ),
            None,
        )
        if successful_dependency is not None:
            logger.info(
                f"[runner] '{successful_dependency}' başarılı oldu; "
                f"'{plugin.plugin_id}' turunu atlıyorum yeğenim."
            )
            return f"plugin {successful_dependency} already succeeded"
        return None

    async def _execute_plugin(
        self, plugin: ToolPlugin, context: PluginContext
    ) -> ToolResult:
        self._ui_call("plugin_started", plugin.plugin_id)
        try:
            result = await self._wrap_notify(plugin.run(context), plugin.plugin_id)
        except asyncio.CancelledError:
            self._ui_call("plugin_finished", plugin.plugin_id, "cancelled")
            raise
        self._ui_call(
            "plugin_finished",
            plugin.plugin_id,
            self._result_outcome(result),
        )
        return result

    @staticmethod
    def _result_outcome(result: ToolResult) -> str:
        if result.error:
            return "failed"
        if result.skipped:
            return "skipped"
        if result.timed_out:
            return "timed_out"
        if result.return_code not in (None, 0):
            return "failed"
        return "complete"

    def _ui_call(self, method_name: str, *args: object) -> None:
        """Invoke UI events without allowing presentation failures to abort scans."""
        try:
            method = getattr(self.ui, method_name)
            method(*args)
        except Exception as exc:
            logger.warning(
                "[!] Yeğenim terminal süsü tökezledi; düz ekrana dönüyorum. "
                f"({exc})"
            )
            failed_ui = self.ui
            self.ui = PlainTerminalUI(logger)
            if method_name != "close":
                try:
                    failed_ui.close()
                except Exception:
                    pass
                try:
                    getattr(self.ui, method_name)(*args)
                except Exception:
                    pass

    async def _wrap_notify(
        self,
        coro: Awaitable[ToolResult],
        plugin_id: str = "unknown",
    ) -> ToolResult:
        """Execute one operation, normalize failures, and notify immediately."""
        try:
            result = await coro
            if not isinstance(result, ToolResult):
                raise TypeError(
                    f"plugin returned {type(result).__name__}, expected ToolResult"
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                f"[runner] '{plugin_id}' eklentisinde beklenmedik hata: {exc}"
            )
            return self._error_result(plugin_id, exc)

        self._attach_artifacts(result)
        if self.integration:
            for flag in result.flags_found:
                self.integration.notify(flag, result.tool_name)
            for extracted_hits in result.extracted_flags.values():
                for flag in extracted_hits:
                    self.integration.notify(flag, result.tool_name)
        return result

    async def _run_and_track(
        self,
        coro: Awaitable[ToolResult],
        plugin_id: str = "unknown",
    ) -> ToolResult:
        """Backward-compatible helper for direct sequential callers."""
        result = await self._wrap_notify(coro, plugin_id)
        self._partial_results.append(result)
        self._results_by_plugin[plugin_id] = result
        return result

    @staticmethod
    def _error_result(plugin_id: str, exc: BaseException) -> ToolResult:
        return ToolResult(
            tool_name=plugin_id,
            command=[],
            return_code=None,
            stdout="",
            stderr=str(exc),
            flags_found=[],
            elapsed_seconds=0.0,
            skipped=True,
            error=True,
            skip_reason=f"Unhandled plugin exception: {exc}",
        )

    def _record_result(self, plugin: ToolPlugin, result: ToolResult) -> None:
        self._partial_results.append(result)
        self._results_by_plugin[plugin.plugin_id] = result
        try:
            succeeded = bool(plugin.success_evaluator(result))
        except Exception as exc:
            logger.warning(
                f"[runner] '{plugin.plugin_id}' başarı denetimi bozuk çıktı "
                f"yeğenim, başarısız sayıyorum. ({exc})"
            )
            succeeded = False
        if succeeded:
            self._successful_plugins.add(plugin.plugin_id)
            self._successful_phases.add(plugin.phase)

    def _build_dynamic_mini_wordlist(self) -> list[str]:
        source_results: list[ToolResult] = []
        source_names: set[str] = set()
        for plugin in self.registry.plugins:
            if not plugin.contributes_to_mini_wordlist:
                continue
            result = self._results_by_plugin.get(plugin.plugin_id)
            if result is not None:
                source_results.append(result)
                source_names.add(result.tool_name)
        return _extract_mini_wordlist(
            source_results,
            source_tool_names=source_names,
        )

    def _attach_artifacts(self, result: ToolResult) -> None:
        """Attach passive next-stage artifacts and announce each value once."""
        if len(result.artifacts_found) > MAX_ARTIFACT_FINDINGS:
            del result.artifacts_found[MAX_ARTIFACT_FINDINGS:]
        existing = {
            (item.artifact_type, item.preview, item.decoded_preview)
            for item in result.artifacts_found
        }
        for stream_name, content in (("stdout", result.stdout), ("stderr", result.stderr)):
            if not content:
                continue
            source = f"{result.tool_name}/{stream_name}"
            remaining = MAX_ARTIFACT_FINDINGS - len(existing)
            if remaining <= 0:
                break
            for finding in scan_artifacts(
                content, source=source, max_findings=remaining
            ):
                key = (
                    finding.artifact_type,
                    finding.preview,
                    finding.decoded_preview,
                )
                if key in existing:
                    continue
                result.artifacts_found.append(finding)
                existing.add(key)
                if key in self._announced_artifacts:
                    continue
                self._announced_artifacts.add(key)

                label = _ARTIFACT_LABELS.get(
                    finding.artifact_type, finding.artifact_type
                )
                decoded = (
                    f" | çözülen önizleme: {finding.decoded_preview!r}"
                    if finding.decoded_preview is not None
                    else ""
                )
                self._ui_call(
                    "show_artifact",
                    f"[!] Yeğenim bak burada bir {label} buldum, "
                    "buraları bir eşele; sonraki aşama bu olabilir! "
                    f"[{finding.source}] → {finding.preview!r}{decoded}",
                )

    def _build_report(self) -> ScanReport:
        """Construct the aggregate report, including partial cancellation state."""
        all_flags: list[str] = []
        all_artifacts: list[ArtifactFinding] = []
        seen_artifacts: set[tuple[str, str, str | None]] = set()

        for result in self._partial_results:
            for flag in result.flags_found:
                if flag not in all_flags:
                    all_flags.append(flag)
            for extracted_list in result.extracted_flags.values():
                for flag in extracted_list:
                    if flag not in all_flags:
                        all_flags.append(flag)
            for finding in result.artifacts_found:
                key = (
                    finding.artifact_type,
                    finding.preview,
                    finding.decoded_preview,
                )
                if key not in seen_artifacts:
                    seen_artifacts.add(key)
                    all_artifacts.append(finding)

        if all_flags:
            for flag in all_flags:
                sources = [
                    result.tool_name
                    for result in self._partial_results
                    if flag in result.flags_found
                    or any(
                        flag in hits for hits in result.extracted_flags.values()
                    )
                ]
                self._ui_call(
                    "show_flag",
                    flag,
                    ", ".join(dict.fromkeys(sources)) or None,
                )
        else:
            self._ui_call("show_no_flags")

        return ScanReport(
            target_file=str(self.target.resolve()),
            flag_pattern=self.pattern.pattern,
            wordlist=str(self.wordlist) if self.wordlist else None,
            started_at=self._started_at or datetime.now(timezone.utc).isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat(),
            all_flags=all_flags,
            tool_results=self._partial_results,
            all_artifacts=all_artifacts,
            retained_workspace=(
                str(self._retained_workspace)
                if self._retained_workspace is not None
                else None
            ),
        )
