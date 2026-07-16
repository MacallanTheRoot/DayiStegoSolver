"""Passive stdlib ZIP recovery and ZipCrypto cracking for binwalk output."""
from __future__ import annotations

import asyncio
import logging
import re
import stat
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Iterator

from dayi.persona import log_artifact
from dayi.reporter import ToolResult
from dayi.scanner import scan_directory
from dayi.tools._base import iter_wordlist_lines, make_skipped_result
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin

logger = logging.getLogger("dayi")

TOOL_NAME = "zip_cracker"

# Extraction safety limits. These apply to expanded sizes reported by the ZIP
# central directory before any member is written to disk.
MAX_ARCHIVE_MEMBERS = 2_048
MAX_MEMBER_SIZE = 256 * 1024 * 1024
MAX_TOTAL_SIZE = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 2_000
_COPY_CHUNK_SIZE = 1024 * 1024


class UnsafeArchiveError(ValueError):
    """Raised when a ZIP violates safe extraction constraints."""


class ArchiveCrackingCancelled(Exception):
    """Internal signal used to stop worker-thread processing safely."""


def _find_zip_archives(workspace: Path) -> list[Path]:
    """Find ZIP payloads by signature without following symlinked paths."""
    if not workspace.exists() or not workspace.is_dir():
        return []

    archives: list[Path] = []
    for candidate in workspace.rglob("*"):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        try:
            is_archive = zipfile.is_zipfile(candidate)
        except OSError as exc:
            logger.debug(f"[zip_cracker] ZIP signature check failed: {candidate}: {exc}")
            continue
        if is_archive:
            archives.append(candidate)
    return sorted(archives)


def _safe_member_path(filename: str) -> PurePosixPath:
    """Normalize one member name and reject traversal or absolute paths."""
    normalized = filename.replace("\\", "/")
    member_path = PurePosixPath(normalized)
    parts = member_path.parts

    if (
        not parts
        or member_path.is_absolute()
        or ".." in parts
        or parts[0].endswith(":")
        or "\x00" in normalized
    ):
        raise UnsafeArchiveError(f"unsafe member path: {filename!r}")
    return member_path


def _validated_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Validate member paths, types, sizes, and compression ratios."""
    members = archive.infolist()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise UnsafeArchiveError(
            f"member count {len(members)} exceeds {MAX_ARCHIVE_MEMBERS}"
        )

    total_size = 0
    seen_paths: set[PurePosixPath] = set()
    for member in members:
        member_path = _safe_member_path(member.filename)
        if member_path in seen_paths:
            raise UnsafeArchiveError(f"duplicate member path: {member.filename!r}")
        seen_paths.add(member_path)

        mode = (member.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise UnsafeArchiveError(f"symbolic link member: {member.filename!r}")
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise UnsafeArchiveError(f"special file member: {member.filename!r}")

        if member.compress_type not in {
            zipfile.ZIP_STORED,
            zipfile.ZIP_DEFLATED,
            zipfile.ZIP_BZIP2,
            zipfile.ZIP_LZMA,
        }:
            raise NotImplementedError(
                f"unsupported ZIP compression/encryption method: {member.compress_type}"
            )

        if member.file_size > MAX_MEMBER_SIZE:
            raise UnsafeArchiveError(
                f"member {member.filename!r} exceeds {MAX_MEMBER_SIZE} bytes"
            )
        total_size += member.file_size
        if total_size > MAX_TOTAL_SIZE:
            raise UnsafeArchiveError(
                f"expanded size exceeds {MAX_TOTAL_SIZE} bytes"
            )

        if member.file_size:
            if member.compress_size == 0:
                raise UnsafeArchiveError(
                    f"invalid zero compressed size: {member.filename!r}"
                )
            ratio = member.file_size / member.compress_size
            if ratio > MAX_COMPRESSION_RATIO:
                raise UnsafeArchiveError(
                    f"compression ratio {ratio:.0f}:1 is unsafe: {member.filename!r}"
                )

    return members


def _password_candidates(
    mini_wordlist: Iterable[str],
    wordlist_path: Path | None,
    bf_limit: int,
) -> Iterator[str]:
    """Yield unique mini-wordlist candidates before streamed global entries."""
    seen: set[str] = set()

    for password in mini_wordlist:
        if password and password not in seen:
            seen.add(password)
            yield password

    if wordlist_path is None:
        return

    for password in iter_wordlist_lines(wordlist_path, limit=bf_limit):
        if password not in seen:
            seen.add(password)
            yield password


def _password_unlocks(
    archive: zipfile.ZipFile,
    encrypted_members: list[zipfile.ZipInfo],
    password: str,
    cancel_event: threading.Event,
) -> bool:
    """Validate a password by reading every encrypted member through CRC."""
    try:
        password_bytes = password.encode("utf-8")
        for member in encrypted_members:
            if cancel_event.is_set():
                raise ArchiveCrackingCancelled
            with archive.open(member, mode="r", pwd=password_bytes) as source:
                while True:
                    if cancel_event.is_set():
                        raise ArchiveCrackingCancelled
                    if not source.read(_COPY_CHUNK_SIZE):
                        break
    except (RuntimeError, zipfile.BadZipFile, NotImplementedError, ValueError):
        return False
    return True


def _extract_safely(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    output_dir: Path,
    password: str | None,
    cancel_event: threading.Event,
) -> None:
    """Extract validated members manually, without ZipFile.extractall()."""
    output_dir.mkdir(parents=True, exist_ok=False)
    password_bytes = password.encode("utf-8") if password is not None else None

    for member in members:
        if cancel_event.is_set():
            raise ArchiveCrackingCancelled
        member_path = _safe_member_path(member.filename)
        destination = output_dir.joinpath(*member_path.parts)

        if member.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue

        destination.parent.mkdir(parents=True, exist_ok=True)
        pwd = password_bytes if member.flag_bits & 0x1 else None
        with archive.open(member, mode="r", pwd=pwd) as source:
            with destination.open("wb") as target:
                while True:
                    if cancel_event.is_set():
                        raise ArchiveCrackingCancelled
                    chunk = source.read(_COPY_CHUNK_SIZE)
                    if not chunk:
                        break
                    target.write(chunk)


def _crack_archives_sync(
    workspace: Path,
    output_root: Path,
    mini_wordlist: list[str],
    wordlist_path: Path | None,
    bf_limit: int,
    flag_pattern: re.Pattern,
    cancel_event: threading.Event,
) -> tuple[
    list[str],
    dict[str, list[str]],
    list[tuple[Path, str]],
    list[Path],
    list[str],
    int,
]:
    """Perform blocking ZIP work in the worker thread used by the async API."""
    all_flags: list[str] = []
    extracted_flags: dict[str, list[str]] = {}
    cracked: list[tuple[Path, str]] = []
    unencrypted: list[Path] = []
    errors: list[str] = []
    protected_count = 0

    for archive_index, archive_path in enumerate(_find_zip_archives(workspace), start=1):
        if cancel_event.is_set():
            break
        try:
            with zipfile.ZipFile(archive_path) as archive:
                members = _validated_members(archive)
                encrypted_members = [
                    member
                    for member in members
                    if member.flag_bits & 0x1 and not member.is_dir()
                ]
                password: str | None = None
                if encrypted_members:
                    protected_count += 1
                    for candidate in _password_candidates(
                        mini_wordlist, wordlist_path, bf_limit
                    ):
                        if cancel_event.is_set():
                            raise ArchiveCrackingCancelled
                        if _password_unlocks(
                            archive, encrypted_members, candidate, cancel_event
                        ):
                            password = candidate
                            break
                    if password is None:
                        continue

                safe_stem = "".join(
                    char if char.isalnum() or char in "_.-" else "_"
                    for char in archive_path.stem
                ) or "archive"
                extraction_dir = output_root / f"{archive_index:03d}_{safe_stem}"
                _extract_safely(
                    archive, members, extraction_dir, password, cancel_event
                )
                if encrypted_members:
                    assert password is not None
                    cracked.append((archive_path, password))
                else:
                    unencrypted.append(archive_path)

                archive_label = str(archive_path.relative_to(workspace))
                for relative_name, hits in scan_directory(
                    extraction_dir, flag_pattern
                ).items():
                    key = f"{archive_label}!/{relative_name}"
                    extracted_flags[key] = hits
                    for flag in hits:
                        if flag not in all_flags:
                            all_flags.append(flag)

        except ArchiveCrackingCancelled:
            break
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
            errors.append(f"{archive_path}: unsupported or invalid ZIP: {exc}")
        except (UnsafeArchiveError, OSError, ValueError) as exc:
            errors.append(f"{archive_path}: {exc}")

    return (
        all_flags,
        extracted_flags,
        cracked,
        unencrypted,
        errors,
        protected_count,
    )


async def run_zip_cracker(
    workspace: Path,
    flag_pattern: re.Pattern,
    mini_wordlist: list[str],
    wordlist_path: Path | None = None,
    bf_limit: int = 1_000,
    artifact_callback: Callable[[str], None] | None = None,
) -> ToolResult:
    """Recover ZIPs in retained binwalk output and scan their contents."""
    if not workspace.exists() or not workspace.is_dir():
        return make_skipped_result(
            TOOL_NAME,
            "binwalk extraction workspace is unavailable",
            ["python:zipfile", str(workspace)],
        )

    output_root = workspace / "_dayi_zip_cracker"
    started = time.monotonic()
    cancel_event = threading.Event()
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="dayi-zip") as executor:
        worker = loop.run_in_executor(
            executor,
            _crack_archives_sync,
            workspace,
            output_root,
            mini_wordlist,
            wordlist_path,
            bf_limit,
            flag_pattern,
            cancel_event,
        )
        try:
            (
                flags,
                extracted_flags,
                cracked,
                unencrypted,
                errors,
                protected_count,
            ) = await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancel_event.set()
            await worker
            raise
    elapsed = time.monotonic() - started

    stdout_lines: list[str] = []
    for archive_path in unencrypted:
        message = (
            "[zip_cracker] Binwalk'un çıkaramadığı şifresiz ZIP dosyasını "
            "Dayı özel olarak çıkartıyor..."
        )
        if artifact_callback is None:
            log_artifact(logger, message)
        else:
            artifact_callback(message)
        stdout_lines.append(
            f"Extracted unencrypted ZIP {archive_path.relative_to(workspace)}"
        )

    for archive_path, password in cracked:
        safe_password = ascii(password)
        message = (
            "[!] Yeğenim, zulanın kilidini kırdım! "
            f"Arşiv şifresi: {safe_password}"
        )
        if artifact_callback is None:
            log_artifact(logger, message)
        else:
            artifact_callback(message)
        stdout_lines.append(
            f"Cracked {archive_path.relative_to(workspace)} with password {safe_password}"
        )

    if protected_count and not cracked:
        logger.info(
            f"[zip_cracker] {protected_count} kilitli ZIP buldum ama anahtar uymadı yeğenim."
        )

    return ToolResult(
        tool_name=TOOL_NAME,
        command=["python:zipfile", str(workspace)],
        return_code=0 if not errors else 1,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(errors),
        flags_found=flags,
        elapsed_seconds=elapsed,
        skipped=protected_count == 0 and not unencrypted and not errors,
        skip_reason=(
            "no ZIP archives requiring fallback extraction found"
            if protected_count == 0 and not unencrypted and not errors
            else ""
        ),
        extracted_dir=str(output_root) if cracked or unencrypted else None,
        extracted_flags=extracted_flags,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    binwalk_result = context.result("binwalk")
    extraction_root = (
        Path(binwalk_result.extracted_dir)
        if binwalk_result is not None and binwalk_result.extracted_dir
        else context.workspace / "binwalk-unavailable"
    )
    return await run_zip_cracker(
        extraction_root,
        context.flag_pattern,
        list(context.mini_wordlist),
        wordlist_path=context.wordlist,
        bf_limit=context.bf_limit,
        artifact_callback=context.report_artifact,
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="zip_cracker",
        phase=PluginPhase.ARCHIVE,
        priority=10,
        run=_plugin_run,
    ),
)
