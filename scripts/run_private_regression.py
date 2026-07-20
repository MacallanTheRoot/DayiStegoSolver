#!/usr/bin/env python3
"""Run bounded, local-only Dayı regression scans without retaining corpus data."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dayi.document import DocumentType, detect_document_type  # noqa: E402
from dayi.image_analysis import detect_image_magic  # noqa: E402
from dayi.text_stego import escape_unsafe_text, read_text_input  # noqa: E402
from dayi.tools._base import FileType, get_file_type  # noqa: E402


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_ENTRIES = 5_000
MAX_EXPECTATIONS_PER_FILE = 64
MAX_PATTERN_CHARS = 512
MAX_COMBINED_PATTERN_CHARS = 512
MAX_DISCOVERY_ENTRIES = 20_000
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_SUMMARY_BYTES = 4 * 1024 * 1024
MAX_SUMMARY_FILES = 5_000
MAX_REPORTED_PLUGINS = 128
MAX_REPORTED_FLAGS = 64

Classification = Literal[
    "solved",
    "probable_candidate",
    "partial",
    "missed",
    "false_positive",
    "timeout",
    "unsupported",
    "parser_error",
    "tool_missing",
    "scan_error",
    "skipped_limit",
]

ErrorCategory = Literal[
    "unavailable",
    "unsupported",
    "invalid_input",
    "unsafe_input",
    "limit_exceeded",
    "timeout",
    "parser_error",
    "tool_error",
    "dependency_error",
    "permission_error",
    "internal_error",
]


class HarnessConfigurationError(ValueError):
    """Raised when local regression paths or manifest data are unsafe."""


@dataclass(frozen=True)
class ManifestEntry:
    relative_path: str
    expected_patterns: tuple[str, ...] = ()
    expected_flags: tuple[str, ...] = ()
    category: str | None = None
    expected_plugins: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanExecution:
    report: dict[str, Any] | None
    elapsed_seconds: float
    return_code: int | None
    timed_out: bool = False
    error_category: ErrorCategory | None = None


@dataclass(frozen=True)
class FileSummary:
    file_id: str
    relative_path: str | None
    detected_type: str
    file_size: int
    classification: Classification
    plugins: tuple[tuple[str, str], ...]
    runtime_seconds: float
    flag_count: int
    candidate_count: int
    artifact_count: int
    error_category: ErrorCategory | None
    timed_out: bool
    limit_status: str | None
    flags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_id": self.file_id,
            "relative_path": self.relative_path,
            "detected_type": self.detected_type,
            "file_size": self.file_size,
            "classification": self.classification,
            "plugins": [
                {"name": name, "status": status}
                for name, status in self.plugins
            ],
            "runtime_seconds": round(self.runtime_seconds, 3),
            "flag_count": self.flag_count,
            "candidate_count": self.candidate_count,
            "artifact_count": self.artifact_count,
            "error_category": self.error_category,
            "timed_out": self.timed_out,
            "limit_status": self.limit_status,
            "flags": list(self.flags),
        }


@dataclass(frozen=True)
class HarnessConfig:
    corpus_root: Path
    output_root: Path
    manifest_path: Path | None
    timeout: float
    max_files: int
    anonymize: bool
    show_flags: bool


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _absolute_path(value: Path, label: str) -> Path:
    if not value.is_absolute():
        raise HarnessConfigurationError(f"{label} must be an absolute path")
    try:
        return value.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise HarnessConfigurationError(f"cannot resolve {label}") from exc


def validate_paths(
    corpus: Path,
    output: Path,
    manifest: Path | None = None,
    *,
    repository_root: Path = PROJECT_ROOT,
) -> tuple[Path, Path, Path | None]:
    """Resolve authoritative local paths and reject repository/corpus overlap."""
    repository = repository_root.resolve()
    if corpus.is_symlink():
        raise HarnessConfigurationError("input corpus symlinks are not allowed")
    corpus_root = _absolute_path(corpus, "input corpus")
    if not corpus_root.is_dir():
        raise HarnessConfigurationError("input corpus must be an existing directory")
    if _is_within(corpus_root, repository):
        raise HarnessConfigurationError("input corpus must be outside the repository")

    if output.is_symlink():
        raise HarnessConfigurationError("output directory symlinks are not allowed")
    output_root = _absolute_path(output, "output directory")
    if _is_within(output_root, repository):
        raise HarnessConfigurationError("output directory must be outside the repository")
    if _is_within(output_root, corpus_root) or _is_within(corpus_root, output_root):
        raise HarnessConfigurationError("output directory must be separate from the corpus")
    if output_root.exists() and not output_root.is_dir():
        raise HarnessConfigurationError("output path is not a directory")

    manifest_path: Path | None = None
    if manifest is not None:
        if manifest.is_symlink():
            raise HarnessConfigurationError("manifest symlinks are not allowed")
        manifest_path = _absolute_path(manifest, "manifest")
        if _is_within(manifest_path, repository):
            raise HarnessConfigurationError("manifest must be outside the repository")
        if not manifest_path.is_file():
            raise HarnessConfigurationError("manifest must be an existing file")
    return corpus_root, output_root, manifest_path


def _manifest_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise HarnessConfigurationError("manifest contains an unsafe relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HarnessConfigurationError("manifest paths must remain under the corpus root")
    return path.as_posix()


def _string_list(value: object, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_EXPECTATIONS_PER_FILE:
        raise HarnessConfigurationError(f"manifest field {field!r} must be a bounded list")
    if any(not isinstance(item, str) or not item for item in value):
        raise HarnessConfigurationError(f"manifest field {field!r} contains invalid text")
    return tuple(value)


def load_manifest(path: Path | None) -> dict[str, ManifestEntry]:
    """Load and validate a bounded local expectation manifest without copying it."""
    if path is None:
        return {}

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise HarnessConfigurationError("manifest contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_MANIFEST_BYTES:
            raise HarnessConfigurationError("manifest size is outside the allowed bounds")
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except HarnessConfigurationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessConfigurationError("manifest is not valid bounded UTF-8 JSON") from exc
    if not isinstance(payload, dict) or len(payload) > MAX_MANIFEST_ENTRIES:
        raise HarnessConfigurationError("manifest root must be a bounded JSON object")

    entries: dict[str, ManifestEntry] = {}
    for raw_path, value in payload.items():
        relative = _manifest_relative_path(raw_path)
        identity = relative.casefold()
        if identity in entries:
            raise HarnessConfigurationError("manifest contains duplicate normalized paths")
        if not isinstance(value, dict):
            raise HarnessConfigurationError("manifest entries must be JSON objects")
        patterns = _string_list(value.get("expected_patterns"), "expected_patterns")
        for pattern in patterns:
            if len(pattern) > MAX_PATTERN_CHARS:
                raise HarnessConfigurationError("manifest regex exceeds the length limit")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise HarnessConfigurationError("manifest contains a malformed regex") from exc
        flags = _string_list(value.get("expected_flags"), "expected_flags")
        plugins = _string_list(value.get("expected_plugins"), "expected_plugins")
        category = value.get("category")
        if category is not None and (not isinstance(category, str) or len(category) > 128):
            raise HarnessConfigurationError("manifest category must be bounded text")
        entries[identity] = ManifestEntry(relative, patterns, flags, category, plugins)
    return entries


def _discover_corpus_files(
    root: Path,
    max_files: int,
    *,
    excluded_paths: frozenset[Path] = frozenset(),
) -> tuple[list[tuple[Path, str]], bool]:
    files: list[tuple[Path, str]] = []
    entries = 0
    limit_reached = False
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories if not (Path(current) / name).is_symlink()
        )
        for name in sorted(names):
            entries += 1
            if entries > MAX_DISCOVERY_ENTRIES:
                return files, True
            candidate = Path(current) / name
            if candidate.is_symlink():
                continue
            try:
                resolved = candidate.resolve()
                relative = resolved.relative_to(root).as_posix()
            except (OSError, RuntimeError, ValueError):
                continue
            if resolved in excluded_paths:
                continue
            if not resolved.is_file():
                continue
            if len(files) >= max_files:
                limit_reached = True
                return files, limit_reached
            files.append((resolved, relative))
    return files, limit_reached


def _anonymized_id(relative: str) -> str:
    digest = hashlib.sha256(relative.encode("utf-8", errors="surrogatepass")).hexdigest()
    return f"file-{digest[:12]}"


def _detect_type(path: Path) -> str:
    document_type = detect_document_type(path)
    if document_type not in {DocumentType.NOT_DOCUMENT, DocumentType.INVALID_DOCUMENT}:
        return document_type.value
    image_type = detect_image_magic(path)
    if image_type is not None:
        return image_type
    try:
        with path.open("rb") as source:
            header = source.read(16)
    except OSError:
        return "UNREADABLE"
    if header.startswith(b"%PDF-"):
        return "PDF"
    if header[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"}:
        return "PCAP"
    file_type = get_file_type(path)
    if file_type != FileType.UNKNOWN:
        return file_type.name
    text = read_text_input(path)
    if text.classification == "probable-text":
        return f"TEXT:{text.encoding or 'unknown'}"
    if document_type == DocumentType.INVALID_DOCUMENT:
        return DocumentType.INVALID_DOCUMENT.value
    return "UNKNOWN"


def _combined_pattern(entry: ManifestEntry | None) -> str | None:
    if entry is None:
        return None
    components = [f"(?:{item})" for item in entry.expected_patterns]
    components.extend(f"(?:{re.escape(item)})" for item in entry.expected_flags)
    if not components:
        return None
    combined = "|".join(components)
    if len(combined) > MAX_COMBINED_PATTERN_CHARS:
        raise HarnessConfigurationError("combined per-file expectation regex is too long")
    return combined


def _safe_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "DAYI_CTFD_URL",
        "DAYI_CTFD_TOKEN",
        "DAYI_CTFD_CHALLENGE_ID",
        "DAYI_DISCORD_WEBHOOK_URL",
        "DAYI_CHALLENGE_NAME",
        "DAYI_CTFSHIT_PATH",
        "DAYI_PRIVATE_CORPUS",
    ):
        environment.pop(name, None)
    existing = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + existing if existing else "")
    return environment


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        process.terminate()
    try:
        process.wait(timeout=2.0)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        process.kill()
    process.wait()


def execute_scan(
    target: Path,
    report_base: Path,
    workspace_parent: Path,
    timeout: float,
    pattern: str | None,
) -> ScanExecution:
    """Run one worktree-qualified scan with bounded lifetime and discarded console data."""
    command = [
        sys.executable,
        "-m",
        "dayi",
        "scan",
        str(target),
        "--format",
        "json",
        "--output",
        str(report_base),
        "--workspace-dir",
        str(workspace_parent),
        "--timeout",
        str(min(60.0, max(1.0, timeout / 3.0))),
    ]
    if pattern is not None:
        command.extend(("--flag", pattern))
    started = time.monotonic()
    try:
        process = subprocess.Popen(  # noqa: S603
            command,
            cwd=PROJECT_ROOT,
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, PermissionError):
        return ScanExecution(None, time.monotonic() - started, None, error_category="permission_error")
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process(process)
        return ScanExecution(
            None,
            time.monotonic() - started,
            process.returncode,
            timed_out=True,
            error_category="timeout",
        )

    elapsed = time.monotonic() - started
    report_path = report_base.with_suffix(".json")
    try:
        if not report_path.is_file() or report_path.stat().st_size > MAX_REPORT_BYTES:
            category: ErrorCategory = "limit_exceeded" if report_path.exists() else "tool_error"
            return ScanExecution(None, elapsed, return_code, error_category=category)
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ScanExecution(None, elapsed, return_code, error_category="parser_error")
    if not isinstance(payload, dict):
        return ScanExecution(None, elapsed, return_code, error_category="parser_error")
    return ScanExecution(payload, elapsed, return_code)


def _tool_status(item: dict[str, Any]) -> tuple[str, ErrorCategory | None]:
    reason = str(item.get("skip_reason") or "").casefold()
    if bool(item.get("timed_out")):
        return "timeout", "timeout"
    if bool(item.get("error")):
        if "permission" in reason:
            return "error", "permission_error"
        if "parser" in reason or "malformed" in reason:
            return "error", "parser_error"
        return "error", "tool_error"
    if bool(item.get("skipped")):
        if any(word in reason for word in ("unavailable", "not installed", "not found", "missing")):
            return "unavailable", "dependency_error"
        if any(word in reason for word in ("unsupported", "requires", "not applicable", "does not")):
            return "unsupported", "unsupported"
        if "limit" in reason or "oversized" in reason:
            return "limit_exceeded", "limit_exceeded"
        if "unsafe" in reason:
            return "unsafe_input", "unsafe_input"
        if "invalid" in reason or "malformed" in reason:
            return "invalid_input", "invalid_input"
        return "skipped", None
    return_code = item.get("return_code")
    if return_code not in (None, 0):
        return "failed", "tool_error"
    return "complete", None


def _report_metrics(
    report: dict[str, Any],
) -> tuple[list[str], tuple[tuple[str, str], ...], int, int, ErrorCategory | None]:
    raw_flags = report.get("all_flags_found", [])
    flags = list(dict.fromkeys(
        str(item) for item in raw_flags[:MAX_REPORTED_FLAGS]
        if isinstance(item, str)
    )) if isinstance(raw_flags, list) else []
    artifacts = report.get("artifacts_found", [])
    artifact_count = min(len(artifacts), 10_000) if isinstance(artifacts, list) else 0
    plugins: list[tuple[str, str]] = []
    candidates = 0
    categories: list[ErrorCategory] = []
    tool_results = report.get("tool_results", [])
    if not isinstance(tool_results, list):
        return flags, (), candidates, artifact_count, "parser_error"
    for raw_item in tool_results[:MAX_REPORTED_PLUGINS]:
        if not isinstance(raw_item, dict):
            categories.append("parser_error")
            continue
        name = str(raw_item.get("tool") or "unknown")[:128]
        status, category = _tool_status(raw_item)
        plugins.append((name, status))
        if category is not None:
            categories.append(category)
        for field in ("document_findings", "ocr_findings", "qr_findings"):
            value = raw_item.get(field, [])
            if isinstance(value, list):
                candidates += min(len(value), 10_000)
        stdout = raw_item.get("stdout")
        if isinstance(stdout, str):
            candidates += sum(
                min(int(match.group(1)), 10_000)
                for match in re.finditer(r"Generated candidates: (\d+)", stdout[:64 * 1024])
            )
    category = next((item for item in (
        "timeout", "parser_error", "limit_exceeded", "permission_error",
        "dependency_error", "tool_error", "unsupported", "invalid_input",
        "unsafe_input",
    ) if item in categories), None)
    return flags, tuple(plugins), min(candidates, 100_000), artifact_count, category  # type: ignore[arg-type]


def _plugin_aliases(plugins: tuple[tuple[str, str], ...]) -> set[str]:
    aliases = {name for name, _status in plugins}
    aliases.update({
        "text_stego_scanner" if name == "text_stego" else
        "document_stego_scanner" if name == "document_stego" else name
        for name in tuple(aliases)
    })
    return aliases


def _expectation_matches(
    entry: ManifestEntry | None,
    flags: list[str],
    plugins: tuple[tuple[str, str], ...],
) -> tuple[bool, bool, bool]:
    if entry is None:
        return False, False, False
    exact = [expected in flags for expected in entry.expected_flags]
    patterns = [
        any(re.search(pattern, flag) is not None for flag in flags)
        for pattern in entry.expected_patterns
    ]
    usable_plugins = {
        name for name, status in plugins
        if status not in {"unavailable", "unsupported", "skipped", "failed", "error", "timeout"}
    }
    aliases = _plugin_aliases(tuple((name, "complete") for name in usable_plugins))
    plugin_matches = [item in aliases for item in entry.expected_plugins]
    result_checks = exact + patterns
    return (
        bool(result_checks) and all(result_checks) and all(plugin_matches),
        any(result_checks),
        not (
        entry.expected_flags or entry.expected_patterns
        ),
    )


def _expected_plugin_missing(
    entry: ManifestEntry | None,
    plugins: tuple[tuple[str, str], ...],
) -> bool:
    if entry is None or not entry.expected_plugins:
        return False
    usable = {
        name for name, status in plugins
        if status not in {"unavailable", "unsupported", "skipped", "failed", "error", "timeout"}
    }
    aliases = _plugin_aliases(tuple((name, "complete") for name in usable))
    return any(item not in aliases for item in entry.expected_plugins)


def _only_missing_tools(plugins: tuple[tuple[str, str], ...]) -> bool:
    return bool(plugins) and any(status == "unavailable" for _name, status in plugins) and all(
        status in {"unavailable", "unsupported", "skipped"}
        for _name, status in plugins
    )


def summarize_execution(
    *,
    path: Path,
    relative: str,
    detected_type: str,
    execution: ScanExecution,
    entry: ManifestEntry | None,
    anonymize: bool,
    show_flags: bool,
) -> FileSummary:
    file_id = _anonymized_id(relative) if anonymize else relative
    relative_path = None if anonymize else escape_unsafe_text(relative, limit=1024)
    try:
        file_size = path.stat().st_size
    except OSError:
        file_size = 0
    if execution.report is None:
        category = execution.error_category or "internal_error"
        classification: Classification = (
            "timeout" if category == "timeout" else
            "unsupported" if category == "unsupported" else
            "parser_error" if category == "parser_error" else
            "tool_missing" if category in {"unavailable", "dependency_error"} else
            "scan_error"
        )
        return FileSummary(
            file_id, relative_path, detected_type, file_size, classification, (),
            execution.elapsed_seconds, 0, 0, 0, category,
            execution.timed_out, "limit_exceeded" if category == "limit_exceeded" else None,
        )

    flags, plugins, candidates, artifacts, category = _report_metrics(execution.report)
    all_expected, any_expected, expects_no_flags = _expectation_matches(entry, flags, plugins)
    if entry is not None and expects_no_flags and flags:
        classification = "false_positive"
    elif entry is not None and all_expected:
        classification = "solved"
    elif entry is not None and (any_expected or candidates or artifacts):
        classification = "partial"
    elif entry is not None and category == "timeout":
        classification = "timeout"
    elif entry is not None and category == "parser_error":
        classification = "parser_error"
    elif entry is not None and _expected_plugin_missing(entry, plugins):
        classification = "tool_missing"
    elif entry is not None and category == "unsupported":
        classification = "unsupported"
    elif entry is not None:
        classification = "missed"
    elif flags:
        classification = "solved"
    elif candidates:
        classification = "probable_candidate"
    elif artifacts:
        classification = "partial"
    elif category == "timeout":
        classification = "timeout"
    elif category == "parser_error":
        classification = "parser_error"
    elif _only_missing_tools(plugins):
        classification = "tool_missing"
    elif category == "unsupported":
        classification = "unsupported"
    else:
        classification = "missed"

    if show_flags:
        rendered_flags = tuple(escape_unsafe_text(flag, limit=512) for flag in flags)
    else:
        rendered_flags = tuple(
            f"<redacted:{hashlib.sha256(flag.encode('utf-8')).hexdigest()[:8]}>"
            for flag in flags
        )
    return FileSummary(
        file_id=file_id,
        relative_path=relative_path,
        detected_type=detected_type,
        file_size=file_size,
        classification=classification,
        plugins=plugins,
        runtime_seconds=execution.elapsed_seconds,
        flag_count=len(flags),
        candidate_count=candidates,
        artifact_count=artifacts,
        error_category=category,
        timed_out=execution.timed_out or category == "timeout",
        limit_status="limit_exceeded" if category == "limit_exceeded" else None,
        flags=rendered_flags,
    )


def _aggregate(files: list[FileSummary], limit_reached: bool) -> dict[str, Any]:
    counts = {name: 0 for name in (
        "solved", "probable_candidate", "partial", "missed", "false_positive",
        "timeout", "unsupported", "parser_error", "tool_missing", "scan_error",
        "skipped_limit",
    )}
    runtimes: list[float] = []
    plugin_failures: dict[str, int] = {}
    formats: dict[str, int] = {}
    missing_tools: dict[str, int] = {}
    for item in files:
        counts[item.classification] += 1
        runtimes.append(item.runtime_seconds)
        formats[item.detected_type] = formats.get(item.detected_type, 0) + 1
        for name, status in item.plugins:
            if status in {"failed", "error", "timeout"}:
                plugin_failures[name] = plugin_failures.get(name, 0) + 1
            if status == "unavailable":
                missing_tools[name] = missing_tools.get(name, 0) + 1
    total = len(files)
    return {
        "total_files": total,
        **counts,
        "solved_rate": round(counts["solved"] / total, 6) if total else 0.0,
        "partial_rate": round(counts["partial"] / total, 6) if total else 0.0,
        "missed_rate": round(counts["missed"] / total, 6) if total else 0.0,
        "timeout_rate": round(counts["timeout"] / total, 6) if total else 0.0,
        "average_runtime": round(statistics.fmean(runtimes), 3) if runtimes else 0.0,
        "median_runtime": round(statistics.median(runtimes), 3) if runtimes else 0.0,
        "maximum_runtime": round(max(runtimes), 3) if runtimes else 0.0,
        "plugin_failure_counts": dict(sorted(plugin_failures.items())),
        "detected_format_distribution": dict(sorted(formats.items())),
        "missing_tool_distribution": dict(sorted(missing_tools.items())),
        "file_limit_reached": limit_reached,
    }


def _markdown_escape(value: object) -> str:
    safe = escape_unsafe_text(str(value), limit=2048).replace("\\", "\\\\")
    return re.sub(r"([`*_{}\[\]()<>#+.!|~-])", r"\\\1", safe)


def _render_markdown(payload: dict[str, Any]) -> str:
    aggregate = payload["aggregate"]
    lines = [
        "# Dayı Local Regression Summary",
        "",
        "Private inputs were scanned locally. This summary contains bounded metadata only.",
        "",
        "## Aggregate",
        "",
    ]
    for key in (
        "total_files", "solved", "probable_candidate", "partial", "missed",
        "false_positive", "timeout", "unsupported", "parser_error", "tool_missing",
        "scan_error", "average_runtime", "median_runtime", "maximum_runtime",
    ):
        lines.append(f"- {_markdown_escape(key)}: {_markdown_escape(aggregate[key])}")
    lines.extend(("", "## Files", ""))
    for item in payload["files"]:
        lines.append(
            f"- `{_markdown_escape(item['file_id'])}`: "
            f"{_markdown_escape(item['classification'])}; "
            f"type={_markdown_escape(item['detected_type'])}; "
            f"flags={item['flag_count']}; candidates={item['candidate_count']}; "
            f"runtime={item['runtime_seconds']:.3f}s"
        )
    missing = payload.get("missing_manifest_entries", [])
    if missing:
        lines.extend(("", "## Missing Manifest Entries", ""))
        lines.extend(f"- `{_markdown_escape(item)}`" for item in missing)
    return "\n".join(lines) + "\n"


def _write_summaries(output: Path, payload: dict[str, Any]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "summary.json"
    markdown_path = output / "summary.md"
    if json_path.exists() or markdown_path.exists():
        raise HarnessConfigurationError("output summary files already exist")
    serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    markdown = _render_markdown(payload)
    if len(serialized.encode("utf-8")) > MAX_SUMMARY_BYTES or len(markdown.encode("utf-8")) > MAX_SUMMARY_BYTES:
        raise HarnessConfigurationError("bounded summary size limit exceeded")
    json_path.write_text(serialized, encoding="utf-8")
    markdown_path.write_text(markdown, encoding="utf-8")


def run_harness(
    config: HarnessConfig,
    *,
    scan_executor=execute_scan,
) -> dict[str, Any]:
    corpus_root, output_root, manifest_path = validate_paths(
        config.corpus_root,
        config.output_root,
        config.manifest_path,
    )
    manifest = load_manifest(manifest_path)
    excluded = frozenset((manifest_path,)) if manifest_path is not None else frozenset()
    discovered, limit_reached = _discover_corpus_files(
        corpus_root,
        config.max_files,
        excluded_paths=excluded,
    )
    summaries: list[FileSummary] = []
    seen_manifest: set[str] = set()
    for path, relative in discovered:
        identity = relative.casefold()
        entry = manifest.get(identity)
        if entry is not None:
            seen_manifest.add(identity)
        before = path.stat()
        with tempfile.TemporaryDirectory(prefix="dayi_private_regression_") as temp_dir:
            temporary = Path(temp_dir)
            execution = scan_executor(
                path,
                temporary / "report",
                temporary / "workspaces",
                config.timeout,
                _combined_pattern(entry),
            )
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            execution = ScanExecution(
                None,
                execution.elapsed_seconds,
                execution.return_code,
                error_category="internal_error",
            )
        summaries.append(summarize_execution(
            path=path,
            relative=relative,
            detected_type=_detect_type(path),
            execution=execution,
            entry=entry,
            anonymize=config.anonymize,
            show_flags=config.show_flags,
        ))
    if len(summaries) > MAX_SUMMARY_FILES:
        raise HarnessConfigurationError("summary file-count limit exceeded")

    missing = [manifest[key].relative_path for key in sorted(set(manifest) - seen_manifest)]
    if config.anonymize:
        missing = [_anonymized_id(item) for item in missing]
    else:
        missing = [escape_unsafe_text(item, limit=1024) for item in missing]
    payload = {
        "schema_version": SCHEMA_VERSION,
        "settings": {
            "anonymized": config.anonymize,
            "flags_redacted": not config.show_flags,
            "max_files": config.max_files,
            "per_file_timeout": config.timeout,
            "network_access": False,
        },
        "aggregate": _aggregate(summaries, limit_reached),
        "files": [item.to_dict() for item in summaries],
        "missing_manifest_entries": missing,
    }
    _write_summaries(output_root, payload)
    return payload


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0 or parsed > MAX_SUMMARY_FILES:
        raise argparse.ArgumentTypeError(f"value must be between 1 and {MAX_SUMMARY_FILES}")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded local-only regression scans over an external corpus.",
    )
    parser.add_argument("--input", type=Path, default=None, help="absolute external corpus directory")
    parser.add_argument("--output", type=Path, default=None, help="absolute external summary directory")
    parser.add_argument("--manifest", type=Path, default=None, help="optional external JSON manifest")
    parser.add_argument("--timeout", type=_positive_float, default=180.0, help="per-file timeout in seconds")
    parser.add_argument("--max-files", type=_positive_int, default=500, help="maximum files to scan")
    parser.add_argument("--anonymize", action="store_true", help="replace relative names with stable IDs")
    visibility = parser.add_mutually_exclusive_group()
    visibility.add_argument("--redact-flags", action="store_true", help="redact full flags (the default)")
    visibility.add_argument("--show-flags", action="store_true", help="include full flags in local summaries")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    input_value = args.input
    if input_value is None:
        environment_value = os.environ.get("DAYI_PRIVATE_CORPUS", "").strip()
        if environment_value:
            input_value = Path(environment_value)
    if input_value is None:
        parser.error("--input or DAYI_PRIVATE_CORPUS is required")
    output_value = args.output
    if output_value is None:
        output_value = Path(tempfile.mkdtemp(prefix="dayi-private-regression-output-"))
    try:
        corpus, output, manifest = validate_paths(input_value, output_value, args.manifest)
        config = HarnessConfig(
            corpus_root=corpus,
            output_root=output,
            manifest_path=manifest,
            timeout=args.timeout,
            max_files=args.max_files,
            anonymize=args.anonymize,
            show_flags=args.show_flags,
        )
        payload = run_harness(config)
    except HarnessConfigurationError as exc:
        print(f"regression harness error: {exc}", file=sys.stderr)
        return 2
    aggregate = payload["aggregate"]
    print(
        "Local regression complete: "
        f"files={aggregate['total_files']} solved={aggregate['solved']} "
        f"partial={aggregate['partial']} missed={aggregate['missed']} "
        f"timeout={aggregate['timeout']} errors="
        f"{aggregate['parser_error'] + aggregate['scan_error']}"
    )
    print(f"Summaries: {config.output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
