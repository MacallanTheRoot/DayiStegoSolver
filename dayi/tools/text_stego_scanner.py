"""Core-only plugin adapter for bounded text steganography analysis."""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import time
from pathlib import Path
from typing import Callable

from dayi.reporter import ToolResult
from dayi.scanner import MAX_ARTIFACT_FINDINGS, ArtifactFinding, scan_artifacts
from dayi.text_stego import (
    DEFAULT_HINT_LIMIT,
    MAX_SOURCE_BYTES,
    VERBOSE_HINT_LIMIT,
    DecodeCandidate,
    analyze_text_file,
    escape_unsafe_text,
)
from dayi.tools._base import async_run_isolated
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin


TOOL_NAME = "text_stego"
TEXT_ANALYSIS_TIMEOUT_SECONDS = 30.0
MAX_WORKSPACE_TEXT_FILES = 32
MAX_WORKSPACE_TEXT_BYTES = 32 * 1024 * 1024
MAX_WORKSPACE_DISCOVERY_ENTRIES = 4_096
MAX_COMBINED_TEXT_OUTPUT = 64 * 1024
MAX_TEXT_ANALYSIS_RESPONSE = 64 * 1024 * 1024


def _candidate_source(candidate: DecodeCandidate) -> str:
    return f"text_stego:{candidate.decoder or 'source'}"


def _text_stego_success(result: ToolResult) -> bool:
    return any(result.extracted_flags.values())


def _text_analysis_worker(target: str, pattern: str, pattern_flags: int):
    """Compile runtime state inside the spawned text parser process."""
    return analyze_text_file(Path(target), re.compile(pattern, pattern_flags))


async def _await_text_analysis(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float,
    *,
    worker: Callable[..., object] = _text_analysis_worker,
):
    return await async_run_isolated(
        worker,
        str(target),
        flag_pattern.pattern,
        flag_pattern.flags,
        timeout=max(0.01, timeout),
        max_response_bytes=MAX_TEXT_ANALYSIS_RESPONSE,
    )


async def run_text_stego(
    target: Path,
    flag_pattern: re.Pattern,
    *,
    verbose: bool = False,
    analysis_timeout: float = TEXT_ANALYSIS_TIMEOUT_SECONDS,
) -> ToolResult:
    """Analyze a probable text file without external tools or network access."""
    started = time.monotonic()
    try:
        analysis = await _await_text_analysis(
            target, flag_pattern, analysis_timeout
        )
    except asyncio.TimeoutError:
        return ToolResult(
            tool_name=TOOL_NAME,
            command=["internal:text_stego", str(target)],
            return_code=None,
            stdout="",
            stderr="text-stego analysis exceeded its bounded timeout",
            flags_found=[],
            elapsed_seconds=time.monotonic() - started,
            timed_out=True,
            error=True,
        )
    except Exception:
        return ToolResult(
            tool_name=TOOL_NAME,
            command=["internal:text_stego", str(target)],
            return_code=None,
            stdout="",
            stderr="bounded text-stego analysis failed safely",
            flags_found=[],
            elapsed_seconds=time.monotonic() - started,
            error=True,
        )
    elapsed = time.monotonic() - started
    source = analysis.source
    if source.classification != "probable-text":
        reason = (
            "text_stego requires probable text; "
            f"detected classification: {source.classification}"
        )
        return ToolResult(
            tool_name=TOOL_NAME,
            command=["internal:text_stego", str(target)],
            return_code=None,
            stdout="",
            stderr="",
            flags_found=[],
            elapsed_seconds=elapsed,
            skipped=True,
            skip_reason=reason,
        )

    extracted_flags: dict[str, list[str]] = {}
    seen_flags: set[str] = set()
    for candidate in analysis.candidates:
        for flag in candidate.flags_found:
            if flag in seen_flags:
                continue
            seen_flags.add(flag)
            extracted_flags.setdefault(_candidate_source(candidate), []).append(flag)

    visible = [
        candidate
        for candidate in analysis.candidates
        if candidate.confidence in {"confirmed", "high", "medium"}
        or (verbose and candidate.confidence == "low")
    ]
    hint_limit = VERBOSE_HINT_LIMIT if verbose else DEFAULT_HINT_LIMIT
    visible = visible[:hint_limit]

    lines = [
        f"Text classification: {source.classification}",
        f"Encoding: {source.encoding or 'none'}",
        f"Generated candidates: {analysis.total_generated}",
    ]
    if analysis.limits_reached:
        lines.append(f"Limits reached: {', '.join(analysis.limits_reached)}")
    if visible:
        lines.append("Bounded candidate hints:")
        for candidate in visible:
            lines.append(
                f"  [{candidate.confidence}] {_candidate_source(candidate)} "
                f"({candidate.variant}) -> {candidate.normalized_preview}"
            )

    artifacts: list[ArtifactFinding] = []
    seen_artifacts: set[tuple[str, str, str | None]] = set()
    for candidate in visible:
        remaining = MAX_ARTIFACT_FINDINGS - len(artifacts)
        if remaining <= 0:
            break
        for finding in scan_artifacts(
            candidate.value,
            source=_candidate_source(candidate),
            max_findings=remaining,
            include_possible=verbose,
        ):
            key = (
                finding.artifact_type,
                finding.preview,
                finding.decoded_preview,
            )
            if key in seen_artifacts:
                continue
            seen_artifacts.add(key)
            artifacts.append(finding)

    return ToolResult(
        tool_name=TOOL_NAME,
        command=["internal:text_stego", str(target)],
        return_code=0,
        stdout="\n".join(lines),
        stderr="",
        flags_found=[],
        elapsed_seconds=elapsed,
        extracted_flags=extracted_flags,
        artifacts_found=artifacts,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    sources = _discover_text_sources(context.target, context.workspace)
    started = time.monotonic()
    deadline = started + min(
        TEXT_ANALYSIS_TIMEOUT_SECONDS,
        max(1.0, context.timeout),
    )
    results: list[tuple[str, ToolResult]] = []
    for path, source in sources:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        results.append((
            source,
            await run_text_stego(
                path,
                context.flag_pattern,
                verbose=context.verbose,
                analysis_timeout=remaining,
            ),
        ))
    return _merge_text_results(results, time.monotonic() - started)


def _bounded_digest(path: Path) -> str | None:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    return digest.hexdigest()
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    return None
                digest.update(chunk)
    except OSError:
        return None


def _discover_text_sources(target: Path, workspace: Path) -> tuple[tuple[Path, str], ...]:
    """Find bounded target/workspace inputs after extraction without suffix trust."""
    sources: list[tuple[Path, str]] = [(target, "target")]
    seen_digests: set[str] = set()
    target_digest = _bounded_digest(target)
    if target_digest is not None:
        seen_digests.add(target_digest)
    try:
        workspace_root = workspace.resolve()
    except (OSError, RuntimeError):
        return tuple(sources)
    if not workspace_root.is_dir():
        return tuple(sources)

    entries = 0
    aggregate_bytes = 0
    for root, directories, files in os.walk(workspace_root, followlinks=False):
        directories[:] = sorted(
            name for name in directories if not (Path(root) / name).is_symlink()
        )
        for name in sorted(files):
            entries += 1
            if entries > MAX_WORKSPACE_DISCOVERY_ENTRIES:
                return tuple(sources)
            candidate = Path(root) / name
            if candidate.is_symlink():
                continue
            try:
                resolved = candidate.resolve()
                relative = resolved.relative_to(workspace_root)
                size = resolved.stat().st_size
            except (OSError, RuntimeError, ValueError):
                continue
            if not resolved.is_file() or size <= 0 or size > MAX_SOURCE_BYTES:
                continue
            if aggregate_bytes + size > MAX_WORKSPACE_TEXT_BYTES:
                return tuple(sources)
            digest = _bounded_digest(resolved)
            if digest is None or digest in seen_digests:
                continue
            seen_digests.add(digest)
            aggregate_bytes += size
            sources.append((
                resolved,
                escape_unsafe_text(relative.as_posix(), limit=512),
            ))
            if len(sources) >= MAX_WORKSPACE_TEXT_FILES + 1:
                return tuple(sources)
    return tuple(sources)


def _merge_text_results(
    results: list[tuple[str, ToolResult]], elapsed: float
) -> ToolResult:
    """Combine bounded per-file analyses while retaining the first flag source."""
    if not results:
        return ToolResult(
            tool_name=TOOL_NAME,
            command=["internal:text_stego"],
            return_code=None,
            stdout="",
            stderr="",
            flags_found=[],
            elapsed_seconds=elapsed,
            skipped=True,
            skip_reason="no bounded text inputs were available",
        )

    extracted_flags: dict[str, list[str]] = {}
    artifacts: list[ArtifactFinding] = []
    seen_flags: set[str] = set()
    seen_artifacts: set[tuple[str, str, str | None]] = set()
    stdout_sections: list[str] = []
    stderr_lines: list[str] = []
    any_complete = False
    any_timeout = False
    any_error = False

    for source, result in results:
        if result.stdout:
            stdout_sections.append(f"Source: {source}\n{result.stdout}")
        if result.stderr:
            stderr_lines.append(f"{source}: {result.stderr}")
        any_complete = any_complete or not result.skipped
        any_timeout = any_timeout or result.timed_out
        any_error = any_error or result.error
        for label, hits in result.extracted_flags.items():
            if source == "target":
                attributed = label
            else:
                chain = label.removeprefix("text_stego:")
                attributed = f"text_stego:{source}>{chain}"
            for flag in hits:
                if flag in seen_flags:
                    continue
                seen_flags.add(flag)
                extracted_flags.setdefault(attributed, []).append(flag)
        for finding in result.artifacts_found:
            if source == "target":
                attributed_source = finding.source
            else:
                chain = finding.source.removeprefix("text_stego:")
                attributed_source = f"text_stego:{source}>{chain}"
            key = (
                finding.artifact_type,
                finding.preview,
                finding.decoded_preview,
            )
            if key in seen_artifacts:
                continue
            seen_artifacts.add(key)
            artifacts.append(ArtifactFinding(
                finding.artifact_type,
                finding.preview,
                attributed_source,
                finding.decoded_preview,
            ))

    stdout = "\n\n".join(stdout_sections)[:MAX_COMBINED_TEXT_OUTPUT]
    stderr = "\n".join(stderr_lines)[:MAX_COMBINED_TEXT_OUTPUT]
    return ToolResult(
        tool_name=TOOL_NAME,
        command=["internal:text_stego", "managed-workspace"],
        return_code=0 if any_complete and not any_error else None,
        stdout=stdout,
        stderr=stderr,
        flags_found=[],
        elapsed_seconds=elapsed,
        timed_out=any_timeout,
        skipped=not any_complete,
        error=any_error,
        skip_reason=(
            "no probable text found in bounded target/workspace inputs"
            if not any_complete else ""
        ),
        extracted_flags=extracted_flags,
        artifacts_found=artifacts,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="text_stego_scanner",
        phase=PluginPhase.ARCHIVE,
        priority=12,
        run=_plugin_run,
        success_evaluator=_text_stego_success,
    ),
)
