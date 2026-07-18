"""
dayi/tools/stegseek.py
~~~~~~~~~~~~~~~~~~~~~~~
Async runner for `stegseek`: ultra-fast steghide brute-force tool.

stegseek is purpose-built for cracking steghide-protected files and is
significantly faster than iterating steghide manually. Requires the wordlist
to be passed directly.
"""
import asyncio
import logging
import re
import tempfile
from pathlib import Path

from dayi.reporter import ToolResult
from dayi.scanner import scan_file, scan_text
from dayi.tools._base import async_run_command, is_tool_available, make_skipped_result
from dayi.persona import TOOL_INTROS, TOOL_SKIP_MESSAGES, TOOL_SUCCESS_MESSAGES
from dayi.tools._plugin import (
    PluginContext,
    PluginPhase,
    ToolPlugin,
    extraction_or_exit_success,
)

logger = logging.getLogger("dayi")

TOOL_NAME = "stegseek"
BINARY    = "stegseek"


async def run_stegseek(
    target: Path,
    flag_pattern: re.Pattern,
    wordlist_path: Path | None,
    timeout: float = 300.0,
) -> ToolResult:
    """
    Run stegseek against the target file with an optional wordlist.

    If no wordlist is provided, stegseek's default wordlist (if configured)
    is used, or the tool is invoked in info mode.

    Args:
        target:       Path to the target file.
        flag_pattern: Compiled regex pattern to search for flags.
        wordlist_path: Path to the password wordlist; None to use stegseek default.
        timeout:      Subprocess timeout in seconds.

    Returns:
        Populated ToolResult.
    """
    if not is_tool_available(BINARY):
        logger.warning(TOOL_SKIP_MESSAGES[TOOL_NAME])
        return make_skipped_result(
            TOOL_NAME,
            f"{BINARY} not found on PATH (install from GitHub: RickdeJager/stegseek)",
            [BINARY],
        )

    with tempfile.TemporaryDirectory(prefix="dayi_stegseek_") as tmpdir_str:
        out_path = Path(tmpdir_str) / "stegseek_extracted"

        if wordlist_path and wordlist_path.exists():
            cmd = [BINARY, str(target), str(wordlist_path), str(out_path), "--quiet"]
        else:
            # info mode: attempt with empty passphrase
            cmd = [BINARY, "--crack", str(target), "/dev/null", str(out_path), "--quiet"]

        logger.info(TOOL_INTROS[TOOL_NAME])
        rc, stdout, stderr, elapsed, timed_out = await async_run_command(
            cmd, TOOL_NAME, timeout
        )

        flags: list[str] = []
        extracted_flags: dict[str, list[str]] = {}

        if not timed_out:
            logger.info(TOOL_SUCCESS_MESSAGES.get(TOOL_NAME, TOOL_SUCCESS_MESSAGES["default"]))
            flags = list(dict.fromkeys(scan_text(stdout, flag_pattern) + scan_text(stderr, flag_pattern)))

            # Scan extracted output file if it was created
            if out_path.exists():
                hits = await asyncio.to_thread(scan_file, out_path, flag_pattern)
                if hits:
                    extracted_flags["stegseek_extracted"] = hits
                    flags = list(dict.fromkeys(flags + hits))
                    logger.log(25, f"[stegseek] 🎯 Çıkarılan dosyada {len(hits)} flag bulundu!")

        return ToolResult(
            tool_name=TOOL_NAME,
            command=cmd,
            return_code=rc,
            stdout=stdout,
            stderr=stderr,
            flags_found=flags,
            elapsed_seconds=elapsed,
            timed_out=timed_out,
            extracted_flags=extracted_flags,
        )


async def _plugin_run(context: PluginContext) -> ToolResult:
    timeout = context.timeout * 5 if context.wordlist else context.timeout
    return await run_stegseek(
        context.target,
        context.flag_pattern,
        context.wordlist,
        timeout,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="stegseek_main",
        phase=PluginPhase.MAIN_PRIMARY,
        priority=10,
        run=_plugin_run,
        skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,),
        success_evaluator=extraction_or_exit_success,
    ),
)
