"""
dayi/tools/binwalk.py
~~~~~~~~~~~~~~~~~~~~~~
Async runner for `binwalk`: firmware/file analysis and embedded file extraction.

Binwalk extracts embedded files to a directory named '_<filename>.extracted'.
This module also scans that directory for flags after extraction.

FIXES applied in this version:
  1. findall() → finditer()+group(0) in stdout/stderr scanning to correctly
     handle user-supplied capture-group regex patterns.
  2. Extraction directory discovery is now robust: checks the standard
     binwalk naming convention first, then falls back to any subdirectory
     created during the run (not just the first one found).
  3. A caller-owned workspace can retain extracted files for dependent phases
     such as archive cracking. Standalone calls keep the original automatic
     cleanup behavior.
"""
import asyncio
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path

from dayi.reporter import ToolResult
from dayi.scanner import scan_directory
from dayi.tools._base import async_run_command, is_tool_available, make_skipped_result
from dayi.persona import TOOL_INTROS, TOOL_SKIP_MESSAGES, TOOL_SUCCESS_MESSAGES
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin

logger = logging.getLogger("dayi")

TOOL_NAME = "binwalk"
BINARY    = "binwalk"
ZIP_CARVE_RULE = r"^zip archive data:zip"
MAX_DISCOVERY_ENTRIES = 16_384
MAX_EXTRACTED_BYTES = 256 * 1024 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024


def _copy_target_safely(target: Path, destination: Path) -> None:
    """Copy a target without following or overwriting a destination symlink."""
    if destination.is_symlink() or destination.exists():
        raise ValueError("binwalk target-copy destination already exists")
    with target.open("rb") as source, destination.open("xb") as output:
        while True:
            chunk = source.read(_COPY_CHUNK_BYTES)
            if not chunk:
                break
            output.write(chunk)


def _find_extraction_directory(tmpdir: Path, target_name: str) -> Path:
    """Find a real extraction directory without following hostile symlinks."""
    root = tmpdir.resolve()
    standard = tmpdir / f"_{target_name}.extracted"
    if standard.is_dir() and not standard.is_symlink():
        return standard

    candidates: list[Path] = []
    visited = 0
    for current, dirs, _files in os.walk(tmpdir, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs if not (Path(current) / name).is_symlink()
        )
        for name in dirs:
            visited += 1
            if visited > MAX_DISCOVERY_ENTRIES:
                raise ValueError("binwalk extraction entry limit exceeded")
            candidate = Path(current) / name
            try:
                candidate.resolve().relative_to(root)
            except (OSError, ValueError):
                continue
            candidates.append(candidate)
    return min(candidates, key=lambda path: len(path.parts), default=tmpdir)


def _validate_extraction_budget(root: Path) -> None:
    """Reject extraction trees whose regular files exceed bounded quotas."""
    resolved_root = root.resolve()
    entries = 0
    total_bytes = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
        for name in files:
            entries += 1
            if entries > MAX_DISCOVERY_ENTRIES:
                raise ValueError("binwalk extraction entry limit exceeded")
            candidate = Path(current) / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            candidate.resolve().relative_to(resolved_root)
            total_bytes += candidate.stat().st_size
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError("binwalk extraction byte limit exceeded")


async def run_binwalk(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float = 120.0,
    workspace: Path | None = None,
) -> ToolResult:
    """
    Run binwalk with extraction mode against the target file.

    Extracted files land in an isolated directory and are scanned for flags.
    When ``workspace`` is provided, the caller owns its lifecycle so dependent
    post-processing can inspect the extracted files. Without it, this function
    creates and cleans its own temporary directory for backward compatibility.

    Args:
        target:       Path to the target file.
        flag_pattern: Compiled regex pattern to search for flags.
        timeout:      Subprocess timeout in seconds.
        workspace:    Optional caller-owned extraction directory.

    Returns:
        Populated ToolResult with extracted_dir (path before cleanup) and
        extracted_flags populated.
    """
    if not is_tool_available(BINARY):
        logger.warning(TOOL_SKIP_MESSAGES[TOOL_NAME])
        return make_skipped_result(
            TOOL_NAME,
            f"{BINARY} not found on PATH (sudo apt install binwalk)",
            [BINARY],
        )

    owns_workspace = workspace is None
    tmpdir = (
        Path(tempfile.mkdtemp(prefix="dayi_binwalk_"))
        if workspace is None
        else workspace
    )
    if tmpdir.is_symlink():
        raise ValueError("binwalk workspace must not be a symbolic link")
    tmpdir.mkdir(parents=True, exist_ok=True)

    try:
        # Copy target into tmpdir so binwalk writes all extractions relative to it
        target_copy = tmpdir / target.name
        await asyncio.to_thread(_copy_target_safely, target, target_copy)

        # Keep a command-free ZIP dd rule after binwalk's default extractors.
        # If unzip/jar/7z reject a protected archive, this final rule leaves the
        # raw carved bytes on disk for the dependent zip_cracker plugin.
        cmd = [
            BINARY,
            "-e",
            "-M",
            "-q",
            "-D",
            ZIP_CARVE_RULE,
            "-C",
            str(tmpdir),
            str(target_copy),
        ]

        logger.info(TOOL_INTROS[TOOL_NAME])
        rc, stdout, stderr, elapsed, timed_out = await async_run_command(
            cmd, TOOL_NAME, timeout, cwd=tmpdir
        )

        flags_from_output: list[str] = []
        extracted_flags:   dict[str, list[str]] = {}
        extracted_dir_str: str | None = None

        if not timed_out:
            logger.info(TOOL_SUCCESS_MESSAGES.get(TOOL_NAME, TOOL_SUCCESS_MESSAGES["default"]))

            # Fix: use finditer+group(0) to correctly handle capture-group patterns
            flags_from_output = list(dict.fromkeys(
                [m.group(0) for m in flag_pattern.finditer(stdout)] +
                [m.group(0) for m in flag_pattern.finditer(stderr)]
            ))

            extract_dir = await asyncio.to_thread(
                _find_extraction_directory, tmpdir, target_copy.name
            )
            try:
                await asyncio.to_thread(_validate_extraction_budget, extract_dir)
            except (OSError, ValueError) as exc:
                logger.warning(
                    f"[binwalk] Çıkarım güvenlik sınırını aştı yeğenim: {exc}"
                )
                try:
                    resolved_extract = extract_dir.resolve()
                    resolved_extract.relative_to(tmpdir.resolve())
                    if not extract_dir.is_symlink():
                        await asyncio.to_thread(
                            shutil.rmtree, resolved_extract, True
                        )
                except (OSError, ValueError):
                    pass
                return ToolResult(
                    tool_name=TOOL_NAME,
                    command=cmd,
                    return_code=rc,
                    stdout=stdout,
                    stderr=f"unsafe extraction tree: {exc}",
                    flags_found=flags_from_output,
                    elapsed_seconds=elapsed,
                    extracted_dir=None,
                    error=True,
                )

            extracted_dir_str = str(extract_dir)
            logger.debug(f"[binwalk] Çıkarım klasörü taranıyor: {extract_dir}")

            extracted_flags = await asyncio.to_thread(
                scan_directory, extract_dir, flag_pattern
            )

            if extracted_flags:
                total_flags = sum(len(v) for v in extracted_flags.values())
                logger.info(
                    f"[binwalk] Çıkarılan dosyalarda {total_flags} flag bulundu! "
                    f"Yeğenim içinden bir şeyler çıktı!"
                )
            else:
                logger.debug("[binwalk] Çıkarılan dosyalarda flag görünmedi yeğenim.")

        all_flags = list(dict.fromkeys(
            flags_from_output + [f for hits in extracted_flags.values() for f in hits]
        ))

        return ToolResult(
            tool_name=TOOL_NAME,
            command=cmd,
            return_code=rc,
            stdout=stdout,
            stderr=stderr,
            flags_found=all_flags,
            elapsed_seconds=elapsed,
            timed_out=timed_out,
            extracted_dir=extracted_dir_str,
            extracted_flags=extracted_flags,
        )

    finally:
        if owns_workspace:
            await asyncio.to_thread(shutil.rmtree, tmpdir, True)
            logger.debug(f"[binwalk] Geçici klasörü temizledim: {tmpdir}")
        else:
            logger.debug(
                f"[binwalk] Sonraki inceleme için çalışma alanını korudum: {tmpdir}"
            )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_binwalk(
        context.target,
        context.flag_pattern,
        context.timeout * 2,
        workspace=context.workspace / "binwalk",
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="binwalk",
        phase=PluginPhase.CONCURRENT,
        priority=40,
        run=_plugin_run,
        contributes_to_mini_wordlist=True,
    ),
)
