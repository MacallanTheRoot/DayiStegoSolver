"""
dayi/tools/exiftool.py
~~~~~~~~~~~~~~~~~~~~~~~
Async runner for `exiftool`: reads all EXIF/metadata tags from the target file.
"""
import logging
import re
from pathlib import Path

from dayi.reporter import ToolResult
from dayi.tools._base import async_run_command, is_tool_available, make_skipped_result
from dayi.persona import TOOL_INTROS, TOOL_SKIP_MESSAGES, TOOL_SUCCESS_MESSAGES, TOOL_TIMEOUT_MESSAGES

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
    rc, stdout, stderr, elapsed, timed_out = await async_run_command(cmd, TOOL_NAME, timeout)

    flags: list[str] = []
    if not timed_out:
        logger.info(TOOL_SUCCESS_MESSAGES.get(TOOL_NAME, TOOL_SUCCESS_MESSAGES["default"]))
        flags = flag_pattern.findall(stdout) + flag_pattern.findall(stderr)
        flags = list(dict.fromkeys(flags))

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
