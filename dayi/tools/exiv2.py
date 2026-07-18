"""
dayi/tools/exiv2.py
~~~~~~~~~~~~~~~~~~~~
Async runner for `exiv2`: prints image metadata in a different format than exiftool.
Useful for catching metadata that exiftool may not surface.
"""
import logging
import re
from pathlib import Path

from dayi.reporter import ToolResult
from dayi.scanner import scan_text
from dayi.tools._base import async_run_command, is_tool_available, make_skipped_result
from dayi.persona import TOOL_INTROS, TOOL_SKIP_MESSAGES, TOOL_SUCCESS_MESSAGES
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin

logger = logging.getLogger("dayi")

TOOL_NAME = "exiv2"
BINARY    = "exiv2"


async def run_exiv2(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float = 30.0,
) -> ToolResult:
    """
    Run exiv2 against the target file and scan metadata output for flags.

    Args:
        target:       Path to the target file.
        flag_pattern: Compiled regex pattern to search for flags.
        timeout:      Subprocess timeout in seconds.

    Returns:
        Populated ToolResult.
    """
    # -pa prints all metadata; -pt prints tag type detail
    cmd = [BINARY, "-pa", str(target)]

    if not is_tool_available(BINARY):
        logger.warning(TOOL_SKIP_MESSAGES[TOOL_NAME])
        return make_skipped_result(TOOL_NAME, f"{BINARY} not found on PATH", cmd)

    logger.info(TOOL_INTROS[TOOL_NAME])
    rc, stdout, stderr, elapsed, timed_out = await async_run_command(cmd, TOOL_NAME, timeout)

    flags: list[str] = []
    if not timed_out:
        logger.info(TOOL_SUCCESS_MESSAGES.get(TOOL_NAME, TOOL_SUCCESS_MESSAGES["default"]))
        flags = list(dict.fromkeys(scan_text(stdout, flag_pattern) + scan_text(stderr, flag_pattern)))

    return ToolResult(
        tool_name=TOOL_NAME,
        command=cmd,
        return_code=rc,
        stdout=stdout,
        stderr=stderr,
        flags_found=flags,
        elapsed_seconds=elapsed,
        timed_out=timed_out,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_exiv2(context.target, context.flag_pattern, context.timeout)


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="exiv2",
        phase=PluginPhase.CONCURRENT,
        priority=20,
        run=_plugin_run,
        contributes_to_mini_wordlist=True,
    ),
)
