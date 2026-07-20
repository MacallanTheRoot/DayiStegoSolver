"""
dayi/tools/outguess.py
~~~~~~~~~~~~~~~~~~~~~~~
Async runners for `outguess`:
  1. Single-pass extraction with empty passphrase.
  2. Brute-force extraction using a streaming wordlist iterator OR an
     in-memory list (for the dynamic mini-wordlist feature in runner.py).

outguess works exclusively on JPEG files.

SMART ROUTING: A magic-byte format check runs before any subprocess is spawned.
    If the target file is not JPEG, the tool is skipped immediately without
    wasting a process slot. The Dayı persona explains why.

MINI-WORDLIST SUPPORT: run_outguess_bruteforce() accepts an optional
    `wordlist_data` list. When provided, it is used instead of streaming from
    the wordlist file, enabling the dynamic in-memory mini-wordlist feature.
"""
import asyncio
import logging
import re
import tempfile
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Callable, Iterator

from dayi.extraction import (
    MAX_EXTRACTION_VALIDATION_BYTES,
    ExtractionEvidence,
    validate_extracted_payload,
)
from dayi.reporter import ToolResult
from dayi.tools._base import (
    FileType,
    async_run_command,
    describe_file_type,
    get_file_type,
    is_tool_available,
    iter_wordlist_lines,
    make_skipped_result,
)
from dayi.persona import TOOL_INTROS, TOOL_SKIP_MESSAGES, TOOL_SUCCESS_MESSAGES
from dayi.tools._plugin import (
    PluginContext, PluginPhase, ToolPlugin, extraction_evidence_success,
)

logger = logging.getLogger("dayi")

TOOL_NAME    = "outguess"
BINARY       = "outguess"
BF_TOOL_NAME = "outguess_bf"

# outguess is a JPEG-only tool
_SUPPORTED_FORMATS: frozenset[FileType] = frozenset({FileType.JPEG})


async def run_outguess(
    target: Path,
    flag_pattern: re.Pattern,
    timeout: float = 30.0,
) -> ToolResult:
    """
    Run outguess with empty passphrase and attempt extraction.

    Performs a magic-byte format check before spawning any subprocess. If the
    file is not JPEG, the tool is skipped immediately with a Dayı persona log.

    Args:
        target:       Path to the target file.
        flag_pattern: Compiled regex pattern to search for flags.
        timeout:      Subprocess timeout in seconds.

    Returns:
        Populated ToolResult.
    """
    if not is_tool_available(BINARY):
        logger.warning(TOOL_SKIP_MESSAGES[TOOL_NAME])
        return make_skipped_result(
            TOOL_NAME,
            f"{BINARY} not found on PATH (sudo apt install outguess)",
            [BINARY],
        )

    # ── Smart routing: magic-byte format guard ──────────────────────────────
    file_type = get_file_type(target)
    if file_type not in _SUPPORTED_FORMATS:
        fmt_label = describe_file_type(file_type)
        skip_reason = f"outguess requires JPEG; detected format: {file_type.name}"
        logger.info(
            f"[-] Yeğenim bu dosya {fmt_label} formatında, "
            f"outguess sadece JPEG'e bakar, boşuna yormayalım aleti. Atlıyorum..."
        )
        return make_skipped_result(TOOL_NAME, skip_reason, [BINARY])

    with tempfile.TemporaryDirectory(prefix="dayi_outguess_") as tmpdir_str:
        out_path = Path(tmpdir_str) / "outguess_extracted.bin"
        # -r: retrieve (extract); outguess uses empty passphrase by default
        cmd = [BINARY, "-r", str(target), str(out_path)]

        logger.info(TOOL_INTROS[TOOL_NAME])
        rc, stdout, stderr, elapsed, timed_out = await async_run_command(
            cmd, TOOL_NAME, timeout
        )

        flags: list[str] = []
        extracted_flags: dict[str, list[str]] = {}
        extraction_succeeded = False

        if not timed_out:
            flags = list(dict.fromkeys(
                [m.group(0) for m in flag_pattern.finditer(stdout)] +
                [m.group(0) for m in flag_pattern.finditer(stderr)]
            ))

            evidence = await asyncio.to_thread(
                validate_extracted_payload,
                out_path,
                flag_pattern,
            )
            extraction_succeeded = evidence.verified
            if evidence.verified:
                logger.info(
                    TOOL_SUCCESS_MESSAGES.get(
                        TOOL_NAME, TOOL_SUCCESS_MESSAGES["default"]
                    )
                )
                hits = list(evidence.flags_found)
                if hits:
                    extracted_flags["outguess_extracted"] = hits
                    flags = list(dict.fromkeys(flags + hits))
                    logger.log(
                        25,
                        f"[outguess] 🎯 Çıkarılan dosyada {len(hits)} flag bulundu!",
                    )
            elif evidence.non_empty:
                logger.info(
                    "[outguess] Çıktı üretildi ama güçlü çıkarma kanıtı "
                    "doğrulanamadı; başarı saymıyorum."
                )

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
            extraction_succeeded=extraction_succeeded,
        )


async def run_outguess_bruteforce(
    target: Path,
    flag_pattern: re.Pattern,
    wordlist_path: Path | None = None,
    wordlist_data: list[str] | None = None,
    timeout_per_attempt: float = 10.0,
    max_concurrent: int = 4,
    bf_limit: int = 1000,
    progress_callback: Callable[[int, int | None], None] | None = None,
) -> ToolResult:
    """
    Brute-force outguess extraction using a wordlist source.

    Accepts EITHER a wordlist file (streamed lazily, memory-efficient) OR an
    in-memory list of passwords (for the dynamic mini-wordlist feature). The
    `wordlist_data` parameter takes precedence when both are provided.

    Also performs a magic-byte format guard — non-JPEG files are skipped
    without spawning any subprocess.

    Args:
        target:              Path to the target file.
        flag_pattern:        Compiled regex pattern to search for flags.
        wordlist_path:       Path to the password wordlist file (file-based BF).
        wordlist_data:       In-memory list of passwords (mini-wordlist BF).
                             When provided, wordlist_path and bf_limit are ignored.
        timeout_per_attempt: Per-password subprocess timeout in seconds.
        max_concurrent:      Max simultaneous outguess processes.
        bf_limit:            Max passwords from wordlist_path (0 = unlimited).
                             Ignored when wordlist_data is provided.
        progress_callback:   Optional dependency-free attempt counter callback.

    Returns:
        Populated ToolResult. Stops at first successful extraction.
    """
    cmd_template = [BINARY, "-k", "<PASSWORD>", "-r", str(target), "<OUTFILE>"]

    if not is_tool_available(BINARY):
        logger.warning(TOOL_SKIP_MESSAGES[BF_TOOL_NAME])
        return make_skipped_result(BF_TOOL_NAME, f"{BINARY} not found on PATH", cmd_template)

    # ── Smart routing: magic-byte format guard ──────────────────────────────
    file_type = get_file_type(target)
    if file_type not in _SUPPORTED_FORMATS:
        fmt_label = describe_file_type(file_type)
        skip_reason = f"outguess_bf requires JPEG; detected format: {file_type.name}"
        logger.info(
            f"[-] Yeğenim bu dosya {fmt_label}, outguess brute-force'u atlıyorum..."
        )
        return make_skipped_result(BF_TOOL_NAME, skip_reason, cmd_template)

    # ── Determine password source ─────────────────────────────────────────────
    using_mini_wordlist = wordlist_data is not None

    if using_mini_wordlist:
        password_iter: Iterator[str] = iter(wordlist_data)  # type: ignore[assignment]
        source_desc = f"mini-wordlist ({len(wordlist_data)} token)"
    elif wordlist_path and wordlist_path.exists():
        password_iter = iter_wordlist_lines(wordlist_path, limit=bf_limit)
        source_desc = f"wordlist: {wordlist_path.name}"
        if bf_limit:
            logger.warning(
                f"[outguess_bf] Yeğenim bu Python'la rockyou'yu baştan sona denemek "
                f"aylar sürer, ben ilk {bf_limit} şifreyi deniyorum. "
                f"Daha fazlası için stegseek'e bak!"
            )
    else:
        msg = (
            f"No valid wordlist source provided "
            f"(wordlist_path={wordlist_path}, "
            f"wordlist_data={'set' if wordlist_data else 'None'})"
        )
        logger.error(f"[outguess_bf] {msg}")
        return make_skipped_result(BF_TOOL_NAME, msg, cmd_template)

    logger.info(TOOL_INTROS[BF_TOOL_NAME])

    found_password: str | None = None
    found_flags: list[str] = []
    total_tested = 0
    unverified_outputs = 0
    progress_total = len(wordlist_data) if wordlist_data is not None else (
        bf_limit or None
    )
    start = time.monotonic()
    semaphore = asyncio.Semaphore(max_concurrent)

    async def try_password(
        password: str,
        tmpdir: Path,
        baseline: ExtractionEvidence | None,
    ) -> tuple[ExtractionEvidence, str]:
        """Attempt one password and return bounded extraction evidence."""
        out_path = tmpdir / f"out_{uuid.uuid4().hex}.bin"
        cmd = [BINARY, "-k", password, "-r", str(target), str(out_path)]
        try:
            async with semaphore:
                rc, _, _, _, timed_out = await async_run_command(
                    cmd, BF_TOOL_NAME, timeout_per_attempt
                )
            if timed_out or rc != 0:
                evidence = await asyncio.to_thread(
                    validate_extracted_payload,
                    out_path,
                    flag_pattern,
                )
                return replace(
                    evidence,
                    confidence="low" if evidence.non_empty else "none",
                    verified=False,
                ), password
            evidence = await asyncio.to_thread(
                validate_extracted_payload,
                out_path,
                flag_pattern,
                baseline=baseline if baseline is not None else None,
            )
            if baseline is None:
                return replace(
                    evidence,
                    differs_from_baseline=False,
                    confidence="low" if evidence.non_empty else "none",
                    verified=False,
                ), password
            return evidence, password
        finally:
            try:
                out_path.unlink(missing_ok=True)
            except OSError:
                logger.debug("[outguess_bf] Doğrulanmamış geçici çıktı temizlenemedi.")

    async def build_baseline(
        tmpdir: Path,
    ) -> tuple[ExtractionEvidence | None, str, bool]:
        """Generate one known-invalid comparison output for this target."""
        baseline_path = tmpdir / "known_invalid_baseline.bin"
        invalid_password = f"dayi-invalid-{uuid.uuid4().hex}"
        cmd = [
            BINARY,
            "-k",
            invalid_password,
            "-r",
            str(target),
            str(baseline_path),
        ]
        try:
            rc, _, _, _, timed_out = await async_run_command(
                cmd, BF_TOOL_NAME, timeout_per_attempt
            )
            if timed_out:
                return None, "known-invalid baseline timed out", True
            if rc != 0:
                return None, "known-invalid baseline command failed", False
            evidence = await asyncio.to_thread(
                validate_extracted_payload,
                baseline_path,
                flag_pattern,
            )
            if not evidence.output_exists:
                return None, "known-invalid baseline produced no output", False
            if (
                not evidence.non_empty
                or evidence.content_sha256 is None
            ):
                return None, "known-invalid baseline output was unreadable", False
            if evidence.output_size > MAX_EXTRACTION_VALIDATION_BYTES:
                return None, "known-invalid baseline exceeded validation limit", False
            return evidence, "", False
        finally:
            try:
                baseline_path.unlink(missing_ok=True)
            except OSError:
                logger.debug("[outguess_bf] Geçici baseline çıktısı temizlenemedi.")

    with tempfile.TemporaryDirectory(prefix="dayi_outguess_bf_") as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        baseline, baseline_error, baseline_timed_out = await build_baseline(tmpdir)
        batch_size = max_concurrent * 4
        batch: list[str] = []

        for password in password_iter:
            batch.append(password)
            if len(batch) < batch_size:
                continue

            tasks = [try_password(pw, tmpdir, baseline) for pw in batch]
            results = await asyncio.gather(*tasks)
            total_tested += len(batch)
            if progress_callback is not None:
                try:
                    progress_callback(total_tested, progress_total)
                except Exception as exc:
                    logger.debug(f"[outguess_bf] İlerleme bildirimi iletilemedi yeğenim: {exc}")
            batch = []

            for evidence, pw in results:
                if evidence.verified and found_password is None:
                    found_password = pw
                    found_flags.extend(evidence.flags_found)
                    logger.log(
                        25,
                        f"[outguess_bf] 🎯 Şifre bulundu: '{pw}' — Yeğenim bu işi hallettik!",
                    )
                elif evidence.non_empty:
                    unverified_outputs += 1

            if found_password:
                break

            if not using_mini_wordlist and total_tested % 500 == 0:
                logger.info(f"[outguess_bf] {total_tested} şifre denendi...")

        # Flush the last partial batch
        if batch and not found_password:
            tasks = [try_password(pw, tmpdir, baseline) for pw in batch]
            results = await asyncio.gather(*tasks)
            total_tested += len(batch)
            if progress_callback is not None:
                try:
                    progress_callback(total_tested, progress_total)
                except Exception as exc:
                    logger.debug(f"[outguess_bf] İlerleme bildirimi iletilemedi yeğenim: {exc}")
            for evidence, pw in results:
                if evidence.verified and found_password is None:
                    found_password = pw
                    found_flags.extend(evidence.flags_found)
                    logger.log(
                        25,
                        f"[outguess_bf] 🎯 Şifre bulundu: '{pw}' — Yeğenim bu işi hallettik!",
                    )
                elif evidence.non_empty:
                    unverified_outputs += 1

    elapsed = time.monotonic() - start
    found_flags = list(dict.fromkeys(found_flags))
    stdout_summary = (
        f"Brute-force tamamlandı [{source_desc}]. {total_tested} şifre denendi.\n"
        f"Bulunan şifre: {found_password or 'Yok'}\n"
        f"Doğrulanmamış çıktılar: {unverified_outputs}\n"
        f"Geçersiz parola baseline: {'hazır' if baseline is not None else 'kullanılamadı'}\n"
    )

    return ToolResult(
        tool_name=BF_TOOL_NAME,
        command=cmd_template,
        return_code=0 if found_password else 1,
        stdout=stdout_summary,
        stderr=baseline_error,
        flags_found=found_flags,
        elapsed_seconds=elapsed,
        timed_out=baseline_timed_out,
        extraction_succeeded=found_password is not None,
    )


async def _plugin_run_empty(context: PluginContext) -> ToolResult:
    return await run_outguess(context.target, context.flag_pattern, context.timeout)


async def _plugin_run_mini(context: PluginContext) -> ToolResult:
    return await run_outguess_bruteforce(
        context.target,
        context.flag_pattern,
        wordlist_data=list(context.mini_wordlist),
        timeout_per_attempt=5.0,
        max_concurrent=max(1, context.bf_threads // 2),
        progress_callback=context.report_progress,
    )


async def _plugin_run_main(context: PluginContext) -> ToolResult:
    return await run_outguess_bruteforce(
        context.target,
        context.flag_pattern,
        wordlist_path=context.wordlist,
        timeout_per_attempt=10.0,
        max_concurrent=max(1, context.bf_threads // 2),
        bf_limit=context.bf_limit,
        progress_callback=context.report_progress,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="outguess_empty",
        phase=PluginPhase.CONCURRENT,
        priority=90,
        run=_plugin_run_empty,
        required_executables=(BINARY,),
    ),
    ToolPlugin(
        plugin_id="outguess_mini_bf",
        phase=PluginPhase.MINI_BRUTE_FORCE,
        priority=20,
        run=_plugin_run_mini,
        requires_mini_wordlist=True,
        success_evaluator=extraction_evidence_success,
        required_executables=(BINARY,),
    ),
    ToolPlugin(
        plugin_id="outguess_main_bf",
        phase=PluginPhase.MAIN_FINAL,
        priority=10,
        run=_plugin_run_main,
        requires_wordlist=True,
        skip_if_phase_succeeded=(PluginPhase.MINI_BRUTE_FORCE,),
        success_evaluator=extraction_evidence_success,
        required_executables=(BINARY,),
    ),
)
