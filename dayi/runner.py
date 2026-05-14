"""
dayi/runner.py
~~~~~~~~~~~~~~
Central async orchestrator — Dayı v2.0.

v2.0 Changes vs v1.x:
  CONCURRENT EXECUTION: Phases 1–4 (8 independent tools) now run via a single
    asyncio.gather() call. On an 8-core machine with external tools spending
    most of their time in kernel I/O, this cuts total scan time by ~60-75%.

  EARLY NOTIFICATION: Each tool coroutine is wrapped with _wrap_notify() which
    fires a fire-and-forget integration.notify() call the instant a flag is
    found, without waiting for the remaining concurrent tools to finish.

  TOOL-NAME-BASED MINI-WORDLIST: _extract_mini_wordlist() now filters results
    by tool name (not array index), so it is safe against the non-deterministic
    completion order produced by asyncio.gather().

  INTEGRATION: Optional FlagIntegration instance accepted in __init__. When
    present, every flag found (in all phases including BF) is dispatched for
    immediate notification.

Execution flow:
  Phase 1+2+3+4 (concurrent) → asyncio.gather() of 8 independent tools
  Phase 4.5 (mini-wordlist BF) → sequential, feeds from gather results
  Phase 5 (main wordlist BF)   → sequential, logic-dependent order

GRACEFUL SHUTDOWN: asyncio.CancelledError caught; partial ScanReport returned.
"""
import asyncio
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from dayi.reporter import ScanReport, ToolResult
from dayi.persona import FLAG_FOUND_BANNER, NO_FLAG_BANNER, log_found

# Tool runners
from dayi.tools.exiftool  import run_exiftool
from dayi.tools.binwalk   import run_binwalk
from dayi.tools.strings   import run_strings
from dayi.tools.zsteg     import run_zsteg
from dayi.tools.lsb       import run_lsb
from dayi.tools.steghide  import run_steghide, run_steghide_bruteforce
from dayi.tools.stegseek  import run_stegseek
from dayi.tools.outguess  import run_outguess, run_outguess_bruteforce
from dayi.tools.exiv2     import run_exiv2
from dayi.tools._base     import sanitize_token

if TYPE_CHECKING:
    from dayi.integrations import IntegrationManager

logger = logging.getLogger("dayi")

# ---------------------------------------------------------------------------
# Mini-wordlist extraction
# ---------------------------------------------------------------------------

_MINI_WL_TOKEN_PATTERN: re.Pattern = re.compile(r"[^\s]{5,30}")
_MINI_WL_MAX_TOKENS: int = 300

# Tools whose text output is considered a source for mini-wordlist tokens.
# Using a name-based set instead of index-based slicing — the concurrent
# gather() completion order is non-deterministic, so indices are unreliable.
_MINI_WL_SOURCE_TOOLS: frozenset[str] = frozenset({
    "exiftool", "exiv2", "strings", "binwalk",
})


def _extract_mini_wordlist(results: list[ToolResult]) -> list[str]:
    """
    Extract and sanitize candidate password tokens from metadata/binary tool
    output text.

    Filters results to only those produced by _MINI_WL_SOURCE_TOOLS (exiftool,
    exiv2, strings, binwalk). This makes the function correct regardless of
    the order in which gather() returned results.

    Tokenization: any non-whitespace sequence of 5–30 characters.
    Sanitization: sanitize_token() strips null bytes and control characters.

    Args:
        results: All ToolResult objects collected so far (from gather + sequential).

    Returns:
        De-duplicated list of sanitized candidate tokens, capped at
        _MINI_WL_MAX_TOKENS entries.
    """
    seen: dict[str, None] = {}

    # Only draw tokens from metadata/binary-analysis tools, not from LSB or BF results
    source_results = [r for r in results if r.tool_name in _MINI_WL_SOURCE_TOOLS]

    for result in source_results:
        for text in (result.stdout, result.stderr):
            for raw_token in _MINI_WL_TOKEN_PATTERN.findall(text):
                clean = sanitize_token(raw_token)
                if clean and clean not in seen:
                    seen[clean] = None
                if len(seen) >= _MINI_WL_MAX_TOKENS:
                    return list(seen)

    return list(seen)


# ---------------------------------------------------------------------------
# DayiRunner
# ---------------------------------------------------------------------------

class DayiRunner:
    """
    Orchestrates concurrent and sequential steganography tool execution.

    Phase 1+2+3+4 tools run concurrently via asyncio.gather(). The BF phases
    (4.5 and 5) remain sequential because they are logically dependent on the
    outcomes of earlier phases.

    Attributes:
        target:      Path to the target file.
        pattern:     Compiled regex flag pattern.
        wordlist:    Optional path to the main password wordlist.
        timeout:     Global per-tool timeout in seconds.
        bf_threads:  Concurrency limit for brute-force subprocess batches.
        bf_limit:    Max passwords for Python BF tools (0 = unlimited).
        integration: Optional IntegrationManager for real-time CTFd/Discord notify.
    """

    def __init__(
        self,
        target: Path,
        pattern: re.Pattern,
        wordlist: Optional[Path] = None,
        timeout: float = 60.0,
        bf_threads: int = 8,
        bf_limit: int = 1000,
        integration: Optional["IntegrationManager"] = None,
    ) -> None:
        self.target      = target
        self.pattern     = pattern
        self.wordlist    = wordlist
        self.timeout     = timeout
        self.bf_threads  = bf_threads
        self.bf_limit    = bf_limit
        self.integration = integration

        # Accumulated results (partial_results enables Ctrl+C recovery)
        self._partial_results: list[ToolResult] = []
        self._started_at: str = ""

    # -------------------------------------------------------------------------
    # Public entry point
    # -------------------------------------------------------------------------

    async def run_all(self) -> ScanReport:
        """
        Execute all tool phases and return an aggregated ScanReport.

        Phases 1–4 are launched concurrently. Phase 4.5 (mini-wordlist BF)
        and Phase 5 (main wordlist BF) remain sequential.

        On asyncio.CancelledError (Ctrl+C), logs a Dayı warning, drains
        pending integration tasks, and returns a partial ScanReport.

        Returns:
            Fully or partially populated ScanReport.
        """
        self._started_at = datetime.now(timezone.utc).isoformat()

        try:
            # ── Phases 1–4: Concurrent independent tools ─────────────────────
            logger.info(
                "[runner] Ortalık karışacak yeğenim! 8 araç aynı anda "
                "çalışıyor, sıkı dur..."
            )

            concurrent_coros = [
                # Phase 1: Metadata
                self._wrap_notify(run_exiftool(self.target, self.pattern, self.timeout)),
                self._wrap_notify(run_exiv2(self.target, self.pattern, self.timeout)),
                # Phase 2: Binary analysis
                self._wrap_notify(run_strings(self.target, self.pattern, self.timeout)),
                self._wrap_notify(run_binwalk(self.target, self.pattern, self.timeout * 2)),
                # Phase 3: LSB steganography
                self._wrap_notify(run_zsteg(self.target, self.pattern, self.timeout * 2)),
                self._wrap_notify(run_lsb(self.target, self.pattern)),
                # Phase 4: Empty-passphrase extraction
                self._wrap_notify(run_steghide(self.target, self.pattern, self.timeout)),
                self._wrap_notify(run_outguess(self.target, self.pattern, self.timeout)),
            ]

            # return_exceptions=True: one crashing tool does not abort the others
            gather_results = await asyncio.gather(*concurrent_coros, return_exceptions=True)

            for item in gather_results:
                if isinstance(item, BaseException):
                    # asyncio.CancelledError is a BaseException — re-raise it
                    if isinstance(item, asyncio.CancelledError):
                        raise item
                    logger.error(f"[runner] Bir tool çöktü (yakalandı): {item}")
                    self._partial_results.append(ToolResult(
                        tool_name="unknown",
                        command=[],
                        return_code=None,
                        stdout="",
                        stderr=str(item),
                        flags_found=[],
                        elapsed_seconds=0.0,
                        skipped=True,
                        skip_reason=f"Unhandled exception in gather: {item}",
                    ))
                else:
                    self._partial_results.append(item)

            logger.info(
                "[runner] Eş zamanlı tarama tamamlandı! "
                "Şimdi brute-force turuna geçiyoruz yeğenim..."
            )

            # ── Phase 4.5: Dynamic mini-wordlist BF ──────────────────────────
            mini_wl_succeeded = await self._run_mini_wordlist_phase()

            # ── Phase 5: Main wordlist BF ─────────────────────────────────────
            if mini_wl_succeeded:
                logger.info(
                    "[runner] 🏆 Mini-wordlist şifreyi buldu! "
                    "Ana rockyou turunu atlıyorum, böyle olur işte yeğenim!"
                )
            else:
                await self._run_main_wordlist_phase()

        except asyncio.CancelledError:
            logger.warning(
                "\n[!] Yeğenim acelen var galiba, durdurduk! "
                "Ama o ana kadar bulduklarımı rapora yazıyorum... "
                "Boşa gitmez hiçbir şey!"
            )

        finally:
            # Drain integration notification tasks before returning
            if self.integration:
                await self.integration.drain()

        return self._build_report()

    # -------------------------------------------------------------------------
    # Concurrent phase helpers
    # -------------------------------------------------------------------------

    async def _wrap_notify(self, coro) -> ToolResult:  # noqa: ANN001
        """
        Execute a tool coroutine and fire integration notification immediately
        when flags are found.

        This wrapper is what enables early notification: each tool within the
        concurrent gather() is independently wrapped, so a flag found by
        exiftool is dispatched while strings, binwalk, zsteg, etc. are still
        running.

        Exceptions other than CancelledError are caught and converted to a
        synthetic ToolResult so they do not abort the gather.

        Args:
            coro: The awaitable tool coroutine to execute.

        Returns:
            ToolResult from the coroutine, or a synthetic error result.
        """
        try:
            result: ToolResult = await coro
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(f"[runner] _wrap_notify caught unexpected exception: {exc}")
            return ToolResult(
                tool_name="unknown",
                command=[],
                return_code=None,
                stdout="",
                stderr=str(exc),
                flags_found=[],
                elapsed_seconds=0.0,
                skipped=True,
                skip_reason=f"Unhandled exception: {exc}",
            )

        # Fire-and-forget integration notification for each found flag
        if result.flags_found and self.integration:
            for flag in result.flags_found:
                self.integration.notify(flag, result.tool_name)

        # Also notify for flags found inside extracted files (e.g. binwalk)
        if result.extracted_flags and self.integration:
            for extracted_hits in result.extracted_flags.values():
                for flag in extracted_hits:
                    self.integration.notify(flag, result.tool_name)

        return result

    # -------------------------------------------------------------------------
    # Sequential phase helpers
    # -------------------------------------------------------------------------

    async def _run_and_track(self, coro) -> ToolResult:
        """
        Execute a sequential tool coroutine, track the result, and fire
        integration notifications immediately if flags are found.

        Used by Phase 4.5 and Phase 5 (BF phases) which cannot be parallelised
        due to their logical dependencies on each other's outcomes.

        Args:
            coro: Tool coroutine to execute.

        Returns:
            The ToolResult produced by the coroutine.
        """
        try:
            result: ToolResult = await coro
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(f"[runner] Beklenmedik hata: {exc}")
            result = ToolResult(
                tool_name="unknown",
                command=[],
                return_code=None,
                stdout="",
                stderr=str(exc),
                flags_found=[],
                elapsed_seconds=0.0,
                skipped=True,
                skip_reason=f"Unhandled exception: {exc}",
            )

        self._partial_results.append(result)

        if result.flags_found and self.integration:
            for flag in result.flags_found:
                self.integration.notify(flag, result.tool_name)

        return result

    async def _run_mini_wordlist_phase(self) -> bool:
        """
        Extract candidate tokens from metadata/binary tool results and run a
        rapid in-memory BF pass with steghide and outguess.

        Token source tools are identified by name (not array index), making
        this correct regardless of concurrent completion order.

        Returns:
            True if any flag was found via the mini-wordlist.
        """
        mini_wordlist = _extract_mini_wordlist(self._partial_results)

        if not mini_wordlist:
            logger.info(
                "[runner] Metadata çıktısından aday token bulunamadı, "
                "mini-wordlist turu atlanıyor."
            )
            return False

        logger.info(
            f"[runner] Yeğenim, dosyanın sağından solundan "
            f"{len(mini_wordlist)} kelime topladım (temizlenmiş). "
            f"Bence şifre bunlardan biri, rockyou'ya girmeden önce "
            f"şunları bir deneyeyim..."
        )
        logger.debug(
            f"[runner] Mini-wordlist sample: "
            f"{mini_wordlist[:10]}{'...' if len(mini_wordlist) > 10 else ''}"
        )

        sh_result = await self._run_and_track(
            run_steghide_bruteforce(
                self.target,
                self.pattern,
                wordlist_data=mini_wordlist,
                timeout_per_attempt=5.0,
                max_concurrent=self.bf_threads,
            )
        )

        og_result = await self._run_and_track(
            run_outguess_bruteforce(
                self.target,
                self.pattern,
                wordlist_data=mini_wordlist,
                timeout_per_attempt=5.0,
                max_concurrent=max(1, self.bf_threads // 2),
            )
        )

        mini_wl_found = bool(sh_result.flags_found or og_result.flags_found)
        if mini_wl_found:
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

        return mini_wl_found

    async def _run_main_wordlist_phase(self) -> None:
        """
        Execute the main brute-force phase with the user-supplied wordlist.

        Execution order:
          1. stegseek  → native-speed BF (fastest for JPEG steghide files).
          2. steghide_bf → Python subprocess BF (only if stegseek fails).
          3. outguess_bf → always runs (different algorithm; independent).

        Each result is tracked and integration-notified individually.
        """
        if not self.wordlist:
            await self._run_and_track(
                run_stegseek(self.target, self.pattern, None, self.timeout)
            )
            return

        stegseek_result = await self._run_and_track(
            run_stegseek(self.target, self.pattern, self.wordlist, self.timeout * 5)
        )
        stegseek_succeeded = bool(
            stegseek_result.flags_found
            or stegseek_result.extracted_flags
            or stegseek_result.return_code == 0
        )

        if stegseek_succeeded:
            logger.info(
                "[runner] Stegseek başarılı oldu, Python brute-force'u atlıyorum. "
                "Yeğenim zamanını boşa harcatmam!"
            )
        else:
            await self._run_and_track(
                run_steghide_bruteforce(
                    self.target,
                    self.pattern,
                    wordlist_path=self.wordlist,
                    timeout_per_attempt=10.0,
                    max_concurrent=self.bf_threads,
                    bf_limit=self.bf_limit,
                )
            )

        await self._run_and_track(
            run_outguess_bruteforce(
                self.target,
                self.pattern,
                wordlist_path=self.wordlist,
                timeout_per_attempt=10.0,
                max_concurrent=max(1, self.bf_threads // 2),
                bf_limit=self.bf_limit,
            )
        )

    # -------------------------------------------------------------------------
    # Report builder
    # -------------------------------------------------------------------------

    def _build_report(self) -> ScanReport:
        """
        Construct a ScanReport from all accumulated tool results.
        Called on both successful completion and Ctrl+C cancellation.
        """
        finished_at = datetime.now(timezone.utc).isoformat()
        all_flags: list[str] = []

        for result in self._partial_results:
            for flag in result.flags_found:
                if flag not in all_flags:
                    all_flags.append(flag)
            for extracted_list in result.extracted_flags.values():
                for flag in extracted_list:
                    if flag not in all_flags:
                        all_flags.append(flag)

        if all_flags:
            logger.log(25, FLAG_FOUND_BANNER)
            for flag in all_flags:
                log_found(logger, f"    🚩 {flag}")
        else:
            logger.warning(NO_FLAG_BANNER)

        return ScanReport(
            target_file=str(self.target.resolve()),
            flag_pattern=self.pattern.pattern,
            wordlist=str(self.wordlist) if self.wordlist else None,
            started_at=self._started_at or datetime.now(timezone.utc).isoformat(),
            finished_at=finished_at,
            all_flags=all_flags,
            tool_results=self._partial_results,
        )
