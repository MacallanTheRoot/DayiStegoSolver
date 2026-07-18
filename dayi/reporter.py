"""
dayi/reporter.py
~~~~~~~~~~~~~~~~
Report generation: writes analysis results as TXT, JSON, or Markdown (v3.0).

v3.0 Addition — export_markdown_writeup():
    Converts a ScanReport into a professional Markdown writeup by constructing
    a minimal mock CTF workspace in a temporary directory and delegating to
    ctfshit.src.writeup_exporter.export_writeups().

    Mock workspace layout (inside a TemporaryDirectory):
        <tmpdir>/
        └── <target_stem>/
            ├── .challenge.json   ← Dayı-generated metadata
            └── notes.txt         ← Full scan findings (tools, flags, stdout)

    Library resolution:
        1. ctfshit.src.writeup_exporter.export_writeups() — rich Markdown with
           category grouping, timestamps, and solve.py/notes.txt embedding.
        2. Fallback (ctfshit unavailable): a hand-written Markdown generator
           that produces a clean, concise writeup from the ScanReport directly.

    The temporary directory is always cleaned up, even on exceptions.
"""
import json
import logging
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from dayi import __version__
from dayi.scanner import ArtifactFinding

logger = logging.getLogger("dayi")


# ---------------------------------------------------------------------------
# Data Models (plain dataclasses, zero external dependencies)
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Stores the outcome of a single tool execution."""
    tool_name: str
    command: list[str]
    return_code: int | None
    stdout: str
    stderr: str
    flags_found: list[str]
    elapsed_seconds: float
    timed_out: bool = False
    skipped: bool = False
    error: bool = False
    skip_reason: str = ""
    extracted_dir: str | None = None
    extracted_flags: dict[str, list[str]] = field(default_factory=dict)
    artifacts_found: list[ArtifactFinding] = field(default_factory=list)
    extraction_succeeded: bool = False


@dataclass
class ScanReport:
    """Top-level report aggregating all tool results for a single target file."""
    target_file: str
    flag_pattern: str
    wordlist: str | None
    started_at: str
    finished_at: str
    all_flags: list[str]
    tool_results: list[ToolResult]
    all_artifacts: list[ArtifactFinding] = field(default_factory=list)
    retained_workspace: str | None = None
    flag_pattern_source: str = "user"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _truncate(text: str, max_chars: int = 4096) -> str:
    """Truncate long strings for report readability."""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return (
        text[:half]
        + f"\n... [TRUNCATED — {len(text) - max_chars} chars omitted] ...\n"
        + text[-half:]
    )


def _markdown_inline(value: object) -> str:
    """Escape untrusted content used in Markdown prose and table-free lists."""
    text = str(value).replace("\\", "\\\\")
    return re.sub(r"([`*_{}\[\]()<>#+.!|~-])", r"\\\1", text)


def _markdown_fence(text: str) -> str:
    """Return a code fence longer than any backtick run in untrusted text."""
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _build_flag_attribution(tool_results: list[ToolResult]) -> dict[str, list[str]]:
    """
    Build a mapping from flag string → list of tool names that found it.

    Enables the report to show "CTF{flag} ← bulan: exiftool, binwalk"
    rather than just listing flags without discovery context.

    Args:
        tool_results: All ToolResult objects from the scan.

    Returns:
        Dict mapping each unique flag to an insertion-ordered list of
        tool names that found it (first finder first).
    """
    attribution: dict[str, list[str]] = {}

    for tr in tool_results:
        all_tool_flags: list[str] = list(tr.flags_found)
        for hits in tr.extracted_flags.values():
            all_tool_flags.extend(hits)

        for flag in all_tool_flags:
            if flag not in attribution:
                attribution[flag] = []
            if tr.tool_name not in attribution[flag]:
                attribution[flag].append(tr.tool_name)

    return attribution


def _format_artifact(finding: ArtifactFinding) -> str:
    """Render one bounded artifact preview for text-based reports."""
    rendered = f"[{finding.artifact_type}] {finding.preview} ({finding.source})"
    if finding.decoded_preview is not None:
        rendered += f" → decoded: {finding.decoded_preview}"
    return rendered


def _artifact_to_dict(finding: ArtifactFinding) -> dict[str, str | None]:
    """Serialize one artifact without exposing unbounded raw tool output."""
    return {
        "type": finding.artifact_type,
        "preview": finding.preview,
        "source": finding.source,
        "decoded_preview": finding.decoded_preview,
    }


def _build_notes_text(report: ScanReport) -> str:
    """
    Build a structured notes.txt body from the ScanReport.

    This text is written into the mock workspace so that writeup_exporter
    can embed it verbatim under the "Notes" section of the Markdown output.

    Args:
        report: Populated ScanReport.

    Returns:
        Multi-line string suitable for writing to notes.txt.
    """
    attribution = _build_flag_attribution(report.tool_results)
    sep = "=" * 60
    lines: list[str] = [
        sep,
        "  DAYI STEGO SOLVER — ANALIZ NOTLARI",
        sep,
        f"  Hedef Dosya : {report.target_file}",
        f"  Flag Regex  : {report.flag_pattern}",
        f"  Desen Kaynağı: {report.flag_pattern_source}",
        f"  Wordlist    : {report.wordlist or 'Belirtilmedi'}",
        f"  Başlangıç   : {report.started_at}",
        f"  Bitiş       : {report.finished_at}",
        sep,
        "",
    ]

    if report.all_flags:
        lines.append("BULUNAN FLAGLER:")
        for flag in report.all_flags:
            finders = attribution.get(flag, ["?"])
            lines.append(f"  → {flag}  ← bulan: [{', '.join(finders)}]")
        lines.append("")

    if report.all_artifacts:
        lines.append("SONRAKI AŞAMA OLABİLECEK ARTIFACT/IPUÇLARI:")
        for finding in report.all_artifacts:
            lines.append(f"  → {_format_artifact(finding)}")
        lines.append("")

    lines.append("ARAÇ SONUÇLARI:")
    lines.append("")

    for tr in report.tool_results:
        if tr.skipped:
            lines.append(f"  [{tr.tool_name.upper()}] ATLANDI — {tr.skip_reason}")
            continue

        status = f"TIMEOUT ({tr.elapsed_seconds:.1f}s)" if tr.timed_out else f"RC={tr.return_code} ({tr.elapsed_seconds:.2f}s)"
        lines.append(f"  [{tr.tool_name.upper()}] {status}")

        if tr.flags_found:
            lines.append(f"    Flagler: {', '.join(tr.flags_found)}")

        if tr.artifacts_found:
            lines.append("    Artifact/ipucu:")
            for finding in tr.artifacts_found:
                lines.append(f"      {_format_artifact(finding)}")

        if tr.stdout.strip():
            lines.append("    STDOUT (özet):")
            for out_line in _truncate(tr.stdout, 1024).splitlines()[:20]:
                lines.append(f"      {out_line}")

        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown writeup export (v3.0)
# ---------------------------------------------------------------------------

# Dynamic import of ctfshit — resolved once at function call time so that
# the module can be installed after the tool is imported without restarting.
def _try_import_writeup_exporter():
    """
    Attempt to import ctfshit.src.writeup_exporter.export_writeups.

    Returns:
        The export_writeups callable, or None if ctfshit is unavailable.
    """
    try:
        from ctfshit.src.writeup_exporter import export_writeups  # type: ignore[import]
        return export_writeups
    except ImportError:
        return None


def _fallback_markdown(report: ScanReport, output_path: Path) -> None:
    """
    Generate a minimal Markdown writeup without ctfshit.

    Produces a clean, self-contained CTF writeup document directly from
    the ScanReport when the writeup_exporter module is not available.

    Args:
        report:      Populated ScanReport.
        output_path: Destination .md file path.
    """
    attribution = _build_flag_attribution(report.tool_results)
    target_name = Path(report.target_file).name
    safe_target_name = _markdown_inline(target_name)
    solved       = bool(report.all_flags)
    first_flag   = report.all_flags[0] if report.all_flags else "N/A"
    timestamp    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines: list[str] = [
        "# CTF Writeups",
        f"\n*Generated automatically on {timestamp}*",
        "\n---",
        "\n## Steganography\n",
        f"### {safe_target_name}\n",
    ]

    # Brief challenge description block
    lines += [
        "**Dosya:** " + safe_target_name + "  ",
        "**Kategori:** Steganography  ",
        f"**Durum:** {'✅ Çözüldü' if solved else '❌ Çözülemedi'}  ",
        f"**Flag:** {_markdown_inline(first_flag)}  ",
        "",
    ]

    if report.all_flags:
        lines.append("#### Bulunan Flagler\n")
        for flag in report.all_flags:
            finders = attribution.get(flag, ["?"])
            lines.append(
                f"- {_markdown_inline(flag)} ← "
                f"{_markdown_inline(', '.join(finders))} tarafından bulundu"
            )
        lines.append("")

    if report.all_artifacts:
        lines.append("#### Sonraki Aşama Olabilecek Artifact/İpuçları\n")
        for finding in report.all_artifacts:
            lines.append(f"- {_markdown_inline(_format_artifact(finding))}")
        lines.append("")

    notes = _build_notes_text(report)
    fence = _markdown_fence(notes)
    lines += [
        "#### Analiz Notları\n",
        f"{fence}text",
        notes,
        f"{fence}\n",
        "---\n",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"[reporter] Yedek Markdown write-up yazıldı → {output_path}")


def export_markdown_writeup(report: ScanReport, output_md_path: Path) -> None:
    """
    Convert a ScanReport into a professional Markdown writeup document.

    Strategy:
        1. Attempt to import ctfshit.src.writeup_exporter.export_writeups.
        2. If available: build a minimal mock CTF workspace in a TemporaryDirectory
           containing a .challenge.json and notes.txt, then call export_writeups()
           to produce a rich, consistently-formatted Markdown document.
        3. If unavailable (ImportError): fall back to _fallback_markdown(), which
           produces a clean Markdown writeup directly from the ScanReport.

    The temporary directory is always cleaned up in a finally block.

    Args:
        report:        Populated ScanReport from the completed scan.
        output_md_path: Destination path for the Markdown file (e.g. writeup.md).
                        Parent directories are created automatically.
    """
    export_writeups = _try_import_writeup_exporter()

    if export_writeups is None:
        logger.info(
            "[reporter] ctfshit bulunamadı, yedek Markdown moduna geçiyorum. "
            "Makaleni el yapımı yazıyorum yeğenim, fabrika değil ama sağlamdır!"
        )
        _fallback_markdown(report, output_md_path)
        return

    # Enforce .md extension
    if output_md_path.suffix.lower() != ".md":
        output_md_path = output_md_path.with_suffix(".md")

    target_path = Path(report.target_file)
    # Use the stem of the target filename as the challenge directory name.
    # Sanitise to avoid path traversal or illegal filesystem characters.
    challenge_slug = "".join(
        c if (c.isalnum() or c in "_-.") else "_"
        for c in target_path.stem
    ) or "dayi_challenge"

    solved    = bool(report.all_flags)
    first_flag = report.all_flags[0] if report.all_flags else ""

    with tempfile.TemporaryDirectory(prefix="dayi_writeup_") as tmp_root:
        tmp_dir       = Path(tmp_root)
        challenge_dir = tmp_dir / challenge_slug
        challenge_dir.mkdir(parents=True, exist_ok=True)

        # ── .challenge.json ─────────────────────────────────────────────────
        # writeup_exporter looks for .challenge.json and checks:
        #   solved: true  (or flag present) → include in export
        meta = {
            "name":     target_path.name,
            "category": "Steganography",
            "solved":   solved,
            "flag":     first_flag,
            "points":   0,
        }
        challenge_json = challenge_dir / ".challenge.json"
        challenge_json.write_text(
            json.dumps(meta, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.debug(f"[reporter] Mock .challenge.json yazıldı: {challenge_json}")

        # ── notes.txt ────────────────────────────────────────────────────────
        # writeup_exporter embeds notes.txt verbatim inside a ```text block
        # when no solve.py is present in the challenge directory.
        notes_path = challenge_dir / "notes.txt"
        notes_path.write_text(_build_notes_text(report), encoding="utf-8")
        logger.debug(f"[reporter] Mock notes.txt yazıldı: {notes_path}")

        # ── Invoke writeup_exporter ──────────────────────────────────────────
        try:
            success, total, stats = export_writeups(
                workspace_root=tmp_dir,
                output_file=output_md_path,
            )

            if success:
                logger.info(
                    f"[reporter] 📝 Makaleni de yazdım yeğenim, at bloguna, havan olsun! "
                    f"→ {output_md_path}"
                )
            else:
                # export_writeups returned success=False (no solved challenges?)
                # This can happen if solved=False in the meta; fall back gracefully.
                logger.warning(
                    "[reporter] writeup_exporter 'çözülmüş challenge bulunamadı' dedi. "
                    "Yedek Markdown'a geçiyorum yeğenim..."
                )
                _fallback_markdown(report, output_md_path)

        except Exception as exc:
            logger.error(
                f"[reporter] writeup_exporter çöktü ({exc}). "
                "Yedek Markdown yazıyorum, panik yok yeğenim!"
            )
            _fallback_markdown(report, output_md_path)
        # TemporaryDirectory __exit__ cleans up tmp_root automatically here


# ---------------------------------------------------------------------------
# TXT report writer
# ---------------------------------------------------------------------------

def write_txt_report(report: ScanReport, output_path: Path) -> None:
    """
    Serialize a ScanReport to a human-readable plain-text file.

    The "BULUNAN FLAGLER" section shows which tool(s) found each flag,
    giving the analyst immediate discovery-method context.

    Args:
        report:      The populated ScanReport dataclass.
        output_path: Destination file path.
    """
    separator = "=" * 70

    lines: list[str] = [
        separator,
        "  DAYI STEGO SOLVER — ANALIZ RAPORU",
        separator,
        f"  Hedef Dosya : {report.target_file}",
        f"  Flag Regex  : {report.flag_pattern}",
        f"  Desen Kaynağı: {report.flag_pattern_source}",
        f"  Wordlist    : {report.wordlist or 'Belirtilmedi'}",
        f"  Başlangıç   : {report.started_at}",
        f"  Bitiş       : {report.finished_at}",
        separator,
        "",
    ]

    if report.all_flags:
        attribution = _build_flag_attribution(report.tool_results)
        lines.append("🎯  BULUNAN FLAGLER:")
        for flag in report.all_flags:
            finders = attribution.get(flag, ["?"])
            finder_str = ", ".join(finders)
            lines.append(f"    → {flag}  ← bulan: [{finder_str}]")
    else:
        lines.append("😤  Hiçbir flag bulunamadı. Manuel inceleme önerilir.")

    if report.all_artifacts:
        lines += ["", "🔎  SONRAKİ AŞAMA OLABİLECEK ARTIFACT/IPUÇLARI:"]
        for finding in report.all_artifacts:
            lines.append(f"    → {_format_artifact(finding)}")

    if report.retained_workspace:
        lines += [
            "",
            f"📁  Korunan çalışma alanı: {report.retained_workspace}",
            "    Uyarı: Çıkarılan dosyalar güvenilmeyen içeriktir.",
        ]

    lines += ["", separator, "  ARAÇ SONUÇLARI", separator, ""]

    for tr in report.tool_results:
        lines.append(f"[ {tr.tool_name.upper()} ]")
        if tr.skipped:
            lines.append(f"  Durum  : ATLANDI (Neden: {tr.skip_reason})")
        elif tr.timed_out:
            lines.append(f"  Durum  : TIMEOUT ({tr.elapsed_seconds:.1f}s)")
        else:
            lines.append(f"  Durum  : RC={tr.return_code} ({tr.elapsed_seconds:.2f}s)")

        lines.append(f"  Komut  : {' '.join(tr.command)}")

        if tr.flags_found:
            lines.append(f"  Flagler: {', '.join(tr.flags_found)}")

        if tr.extracted_flags:
            lines.append("  Çıkarılan Dosyalardaki Flagler:")
            for fname, flags in tr.extracted_flags.items():
                lines.append(f"    [{fname}]: {', '.join(flags)}")

        if tr.artifacts_found:
            lines.append("  Artifact/İpuçları:")
            for finding in tr.artifacts_found:
                lines.append(f"    {_format_artifact(finding)}")

        if tr.stdout.strip():
            lines.append("  STDOUT:")
            for out_line in _truncate(tr.stdout).splitlines():
                lines.append(f"    {out_line}")

        if tr.stderr.strip():
            lines.append("  STDERR:")
            for err_line in _truncate(tr.stderr).splitlines():
                lines.append(f"    {err_line}")

        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"[reporter] TXT rapor yazıldı → {output_path}")


# ---------------------------------------------------------------------------
# JSON report writer
# ---------------------------------------------------------------------------

def write_json_report(report: ScanReport, output_path: Path) -> None:
    """
    Serialize a ScanReport to a structured JSON file.

    Includes a `flag_attribution` map at the top level that shows which
    tool(s) discovered each flag.

    Args:
        report:      The populated ScanReport dataclass.
        output_path: Destination file path.
    """
    attribution = _build_flag_attribution(report.tool_results)

    def _tool_to_dict(tr: ToolResult) -> dict[str, Any]:
        return {
            "tool":            tr.tool_name,
            "command":         tr.command,
            "return_code":     tr.return_code,
            "elapsed_seconds": round(tr.elapsed_seconds, 3),
            "timed_out":       tr.timed_out,
            "skipped":         tr.skipped,
            "skip_reason":     tr.skip_reason,
            "flags_found":     tr.flags_found,
            "extracted_dir":   tr.extracted_dir,
            "extracted_flags": tr.extracted_flags,
            "artifacts_found": [_artifact_to_dict(item) for item in tr.artifacts_found],
            "stdout":          _truncate(tr.stdout),
            "stderr":          _truncate(tr.stderr),
        }

    payload: dict[str, Any] = {
        "meta": {
            "tool":         f"Dayı Stego Solver v{__version__}",
            "target_file":  report.target_file,
            "flag_pattern": report.flag_pattern,
            "flag_pattern_source": report.flag_pattern_source,
            "wordlist":     report.wordlist,
            "started_at":   report.started_at,
            "finished_at":  report.finished_at,
        },
        "all_flags_found":  report.all_flags,
        "flag_attribution": attribution,
        "artifacts_found":  [_artifact_to_dict(item) for item in report.all_artifacts],
        "retained_workspace": report.retained_workspace,
        "tool_results":     [_tool_to_dict(tr) for tr in report.tool_results],
    }

    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info(f"[reporter] JSON rapor yazıldı → {output_path}")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def write_report(report: ScanReport, output_path: Path, fmt: str = "txt") -> None:
    """
    Dispatch report writing to the appropriate format handler.

    Args:
        report:      Populated ScanReport.
        output_path: Destination path (extension will be enforced).
        fmt:         'txt' or 'json'.
    """
    fmt = fmt.lower()
    if fmt == "json":
        if output_path.suffix.lower() != ".json":
            output_path = output_path.with_suffix(".json")
        write_json_report(report, output_path)
    else:
        if output_path.suffix.lower() not in (".txt", ".log"):
            output_path = output_path.with_suffix(".txt")
        write_txt_report(report, output_path)
