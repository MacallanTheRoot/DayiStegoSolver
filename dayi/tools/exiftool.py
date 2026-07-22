"""
dayi/tools/exiftool.py
~~~~~~~~~~~~~~~~~~~~~~~
Async runner for `exiftool`: reads all EXIF/metadata tags from the target file.
"""
import logging
import re
from pathlib import Path

from dayi.reporter import ToolResult
from dayi.scanner import SubprocessFlagScanner
from dayi.tools._base import async_run_command, is_tool_available, make_skipped_result
from dayi.persona import TOOL_INTROS, TOOL_SKIP_MESSAGES, TOOL_SUCCESS_MESSAGES
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin

logger = logging.getLogger("dayi")

TOOL_NAME = "exiftool"
BINARY    = "exiftool"


async def run_exiftool(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float = 30.0,
) -> ToolResult:
    """
    Run exiftool against the target file and scan output for flags.

    Args:
        target:       Path to the target file.
        flag_pattern: Compiled regex pattern to search for flags.
        timeout:      Subprocess timeout in seconds.

    Returns:
        Populated ToolResult.
    """
    cmd = [BINARY, "-a", "-u", "-G1", str(target)]

    if not is_tool_available(BINARY):
        logger.warning(TOOL_SKIP_MESSAGES[TOOL_NAME])
        return make_skipped_result(TOOL_NAME, f"{BINARY} not found on PATH", cmd)

    logger.info(TOOL_INTROS[TOOL_NAME])
    stream_scanner = SubprocessFlagScanner(flag_pattern)
    rc, stdout, stderr, elapsed, timed_out = await async_run_command(
        cmd,
        TOOL_NAME,
        timeout,
        stdout_observer=stream_scanner.stdout,
        stderr_observer=stream_scanner.stderr,
    )

    stream_flags = stream_scanner.findings(stdout, stderr)
    flags = list(dict.fromkeys(
        flag for hits in stream_flags.values() for flag in hits
    ))
    if not timed_out:
        logger.info(TOOL_SUCCESS_MESSAGES.get(TOOL_NAME, TOOL_SUCCESS_MESSAGES["default"]))

    return ToolResult(
        tool_name=TOOL_NAME,
        command=cmd,
        return_code=rc,
        stdout=stdout,
        stderr=stderr,
        flags_found=flags,
        elapsed_seconds=elapsed,
        timed_out=timed_out,
        stream_flags=stream_flags,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_exiftool(context.target, context.flag_pattern, context.timeout)


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="exiftool",
        phase=PluginPhase.CONCURRENT,
        priority=10,
        run=_plugin_run,
        contributes_to_mini_wordlist=True,
        required_executables=(BINARY,),
    ),
)
