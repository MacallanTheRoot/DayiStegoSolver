"""Core document-steganography plugin and bounded media bridge."""
from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Callable

from dayi.document import DocumentFinding, DocumentType, analyze_document, detect_document_type
from dayi.document.limits import DEFAULT_FINDING_LIMIT, VERBOSE_FINDING_LIMIT
from dayi.reporter import ToolResult
from dayi.scanner import ArtifactFinding, scan_artifacts
from dayi.tools._base import async_run_isolated
from dayi.tools._plugin import PluginContext, PluginPhase, ToolPlugin


TOOL_NAME = "document_stego"
MAX_MEDIA_PIPELINE_OBJECTS = 8
MAX_BINWALK_OBJECTS = 2
MAX_DOCUMENT_ANALYSIS_RESPONSE = 64 * 1024 * 1024


def _finding_source(finding: DocumentFinding, document_type: DocumentType) -> str:
    family = {
        DocumentType.XLSX: "xlsx", DocumentType.XLSM: "xlsx",
        DocumentType.PPTX: "pptx", DocumentType.PPTM: "pptx",
        DocumentType.ODT: "odt", DocumentType.ODS: "ods",
        DocumentType.ODP: "odp", DocumentType.OPENDOCUMENT_GENERIC: "odf",
        DocumentType.RTF: "rtf",
    }.get(document_type)
    mechanism = finding.mechanism
    if ":" in mechanism and mechanism.split(":", 1)[0] in {
        "xlsx", "pptx", "odf", "rtf",
    }:
        mechanism = mechanism.split(":", 1)[1]
    if finding.category == "style_encoding":
        prefix = (
            f"document:{family}:{mechanism}"
            if family else f"document_style:{finding.mechanism}"
        )
    elif finding.category == "visible_text":
        prefix = (
            f"document:{family}:{finding.source_member}"
            if family else f"document:{finding.source_member}"
        )
    elif family and finding.category in {family, "odf", "rtf"}:
        prefix = f"document:{family}:{mechanism}:{finding.source_member}"
    else:
        prefix = (
            f"document:{family}:{finding.category}:{finding.source_member}"
            if family else f"document:{finding.category}:{finding.source_member}"
        )
    if finding.decoder_chain:
        chain_parts = finding.decoder_chain
        if chain_parts[0] == prefix or (
            finding.category == "style_encoding"
            and chain_parts[0].startswith("document_style:")
        ):
            chain_parts = chain_parts[1:]
        if chain_parts and chain_parts[0] == "text_stego":
            remainder = ">".join(chain_parts[1:])
            chain = f"text_stego:{remainder}" if remainder else "text_stego"
        else:
            chain = ">".join(chain_parts)
        if not chain:
            return prefix
        return f"{prefix}>{chain}"
    return prefix


def _document_analysis_worker(
    target: str,
    pattern: str,
    pattern_flags: int,
    workspace: str,
):
    """Compile runtime state inside the spawned parser process."""
    return analyze_document(
        Path(target),
        re.compile(pattern, pattern_flags),
        workspace=Path(workspace),
    )


async def _await_analysis(
    target: Path,
    flag_pattern: re.Pattern,
    workspace: Path,
    timeout: float,
    *,
    worker: Callable[..., object] = _document_analysis_worker,
):
    """Run CPU/XML work in a killable, spawn-compatible process."""
    return await async_run_isolated(
        worker,
        str(target),
        flag_pattern.pattern,
        flag_pattern.flags,
        str(workspace),
        timeout=max(0.01, timeout),
        max_response_bytes=MAX_DOCUMENT_ANALYSIS_RESPONSE,
    )


def _merge_flags(
    extracted_flags: dict[str, list[str]],
    label: str,
    flags: list[str] | tuple[str, ...],
    seen: set[str],
) -> None:
    for flag in flags:
        if flag in seen:
            continue
        seen.add(flag)
        extracted_flags.setdefault(label, []).append(flag)


def _merge_artifacts(
    destination: list[ArtifactFinding],
    findings: list[ArtifactFinding],
) -> None:
    existing = {
        (item.artifact_type, item.preview, item.source, item.decoded_preview)
        for item in destination
    }
    for item in findings:
        key = (item.artifact_type, item.preview, item.source, item.decoded_preview)
        if key not in existing:
            existing.add(key)
            destination.append(item)


async def _run_embedded_pipeline(
    analysis,
    flag_pattern: re.Pattern,
    workspace: Path,
    timeout: float,
    document_type: DocumentType,
) -> tuple[dict[str, list[str]], list[ArtifactFinding], list[str]]:
    """Apply compatible existing local scanners without recursive runners."""
    from dayi.tools.binwalk import run_binwalk
    from dayi.tools.exiftool import run_exiftool
    from dayi.tools.lsb import run_lsb
    from dayi.tools.strings import run_strings
    from dayi.tools.zsteg import run_zsteg

    extracted_flags: dict[str, list[str]] = {}
    artifacts: list[ArtifactFinding] = []
    summaries: list[str] = []
    seen_flags: set[str] = set()
    deadline = time.monotonic() + max(1.0, timeout)
    binwalk_count = 0
    family = {
        DocumentType.XLSX: "xlsx", DocumentType.XLSM: "xlsx",
        DocumentType.PPTX: "pptx", DocumentType.PPTM: "pptx",
        DocumentType.ODT: "odt", DocumentType.ODS: "ods",
        DocumentType.ODP: "odp", DocumentType.OPENDOCUMENT_GENERIC: "odf",
        DocumentType.RTF: "rtf",
    }.get(document_type)
    for artifact in analysis.extracted_artifacts[:MAX_MEDIA_PIPELINE_OBJECTS]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            summaries.append("embedded local-analysis time budget exhausted")
            break
        per_tool = max(1.0, min(5.0, remaining))
        operations = [
            ("metadata", run_exiftool(artifact.path, flag_pattern, per_tool)),
            ("strings", run_strings(artifact.path, flag_pattern, per_tool)),
        ]
        if artifact.kind in {"PNG", "BMP"}:
            operations.extend([
                ("lsb", run_lsb(artifact.path, flag_pattern, per_tool)),
                ("zsteg", run_zsteg(artifact.path, flag_pattern, per_tool)),
            ])
        if artifact.kind in {"ZIP", "PDF", "OLE"} and binwalk_count < MAX_BINWALK_OBJECTS:
            binwalk_count += 1
            operations.append((
                "binwalk",
                run_binwalk(
                    artifact.path,
                    flag_pattern,
                    per_tool,
                    workspace=workspace / "document_binwalk" / artifact.sha256[:16],
                ),
            ))
        results = await asyncio.gather(
            *(operation for _name, operation in operations),
            return_exceptions=True,
        )
        for (name, _operation), result in zip(operations, results):
            label = (
                f"document:{family}:{artifact.source_member}>{name}"
                if family else f"document:{artifact.source_member}>{name}"
            )
            if isinstance(result, BaseException):
                if isinstance(result, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                    raise result
                summaries.append(f"{label}: local analyzer failed safely")
                continue
            _merge_flags(extracted_flags, label, result.flags_found, seen_flags)
            for child_label, flags in result.extracted_flags.items():
                _merge_flags(
                    extracted_flags,
                    f"{label}>{child_label}",
                    flags,
                    seen_flags,
                )
            _merge_artifacts(artifacts, result.artifacts_found)
        summaries.append(
            f"{artifact.source_member}: {artifact.kind}, {artifact.size} bytes; "
            "metadata/strings and compatible image analysis completed"
        )
    return extracted_flags, artifacts, summaries


async def run_document_stego(
    target: Path,
    workspace: Path,
    flag_pattern: re.Pattern,
    *,
    timeout: float = 60.0,
    verbose: bool = False,
    ole_result: ToolResult | None = None,
) -> ToolResult:
    """Analyze a detected supported document without active content."""
    started = time.monotonic()
    command = ["internal:document_stego", str(target)]
    document_type = detect_document_type(target)
    if document_type not in {
        DocumentType.DOCX, DocumentType.DOCM, DocumentType.OPENXML_GENERIC,
        DocumentType.XLSX, DocumentType.XLSM,
        DocumentType.PPTX, DocumentType.PPTM,
        DocumentType.ODT, DocumentType.ODS, DocumentType.ODP,
        DocumentType.OPENDOCUMENT_GENERIC, DocumentType.RTF,
    }:
        return ToolResult(
            tool_name=TOOL_NAME,
            command=command,
            return_code=None,
            stdout="",
            stderr="",
            flags_found=[],
            elapsed_seconds=time.monotonic() - started,
            skipped=True,
            skip_reason=f"unsupported document type: {document_type.value}",
        )
    try:
        analysis = await _await_analysis(
            target, flag_pattern, workspace, min(30.0, max(1.0, timeout))
        )
    except asyncio.TimeoutError:
        return ToolResult(
            tool_name=TOOL_NAME,
            command=command,
            return_code=None,
            stdout="",
            stderr="bounded document analysis timed out",
            flags_found=[],
            elapsed_seconds=time.monotonic() - started,
            timed_out=True,
            error=True,
        )
    except Exception:
        return ToolResult(
            tool_name=TOOL_NAME,
            command=command,
            return_code=None,
            stdout="",
            stderr="bounded document analysis failed safely",
            flags_found=[],
            elapsed_seconds=time.monotonic() - started,
            error=True,
        )

    findings = list(analysis.findings)
    extracted_flags: dict[str, list[str]] = {}
    seen_flags: set[str] = set()
    for finding in findings:
        _merge_flags(
            extracted_flags,
            _finding_source(finding, document_type),
            finding.flags_found,
            seen_flags,
        )

    artifacts: list[ArtifactFinding] = []
    for finding in findings:
        _merge_artifacts(
            artifacts,
            scan_artifacts(
                finding.value,
                source=f"document/{finding.category}/{finding.source_member}",
                include_possible=verbose,
            ),
        )

    media_flags, media_artifacts, media_summaries = await _run_embedded_pipeline(
        analysis,
        flag_pattern,
        workspace,
        max(1.0, min(20.0, timeout - (time.monotonic() - started))),
        document_type,
    )
    for label, flags in media_flags.items():
        _merge_flags(extracted_flags, label, flags, seen_flags)
    _merge_artifacts(artifacts, media_artifacts)

    macro_document = document_type in {
        DocumentType.DOCM, DocumentType.XLSM, DocumentType.PPTM,
    }
    if macro_document and ole_result is not None:
        macro_flags = list(ole_result.flags_found)
        for hits in ole_result.extracted_flags.values():
            macro_flags.extend(hits)
        _merge_flags(extracted_flags, "document:macro>olevba", macro_flags, seen_flags)
        _merge_artifacts(artifacts, ole_result.artifacts_found)

    visible = [
        finding for finding in findings
        if finding.confidence in {"confirmed", "high", "medium"}
        or (verbose and finding.confidence == "low")
    ]
    visible = visible[:VERBOSE_FINDING_LIMIT if verbose else DEFAULT_FINDING_LIMIT]
    lines = [
        f"Document type: {analysis.document_type}",
        f"Package members: {analysis.package_members}",
        f"Expanded bytes declared: {analysis.expanded_bytes}",
        f"Document findings: {len(analysis.findings)}",
        f"Extracted media/objects: {len(analysis.extracted_artifacts)}",
        f"QR-ready media objects: {sum(item.kind in {'PNG', 'JPEG', 'BMP', 'GIF'} for item in analysis.extracted_artifacts)}",
        "External relationships were reported passively and were not fetched.",
    ]
    if analysis.limits_reached:
        lines.append(f"Limits reached: {', '.join(analysis.limits_reached)}")
    if visible:
        lines.append("Bounded document findings:")
        for finding in visible:
            chain = (
                f" > {'>'.join(finding.decoder_chain)}"
                if finding.decoder_chain else ""
            )
            lines.append(
                f"  [{finding.confidence}] {finding.category}/{finding.mechanism} "
                f"@ {finding.source_member}{chain}: {finding.preview}"
            )
    lines.extend(media_summaries)
    errors = list(analysis.errors)
    if macro_document and ole_result is None:
        errors.append(
            f"{document_type.value} macro project was not executed; optional "
            "oletools result unavailable"
        )
    return ToolResult(
        tool_name=TOOL_NAME,
        command=command,
        return_code=0,
        stdout="\n".join(lines),
        stderr="\n".join(errors),
        flags_found=[],
        elapsed_seconds=time.monotonic() - started,
        extracted_dir=(str(analysis.extracted_dir) if analysis.extracted_dir else None),
        extracted_flags=extracted_flags,
        artifacts_found=artifacts,
        extraction_succeeded=bool(analysis.extracted_artifacts),
        document_findings=visible,
    )


async def _plugin_run(context: PluginContext) -> ToolResult:
    return await run_document_stego(
        context.target,
        context.workspace,
        context.flag_pattern,
        timeout=context.timeout,
        verbose=context.verbose,
        ole_result=context.result("ole_scanner"),
    )


PLUGIN_SPECS = (
    ToolPlugin(
        plugin_id="document_stego_scanner",
        phase=PluginPhase.ARCHIVE,
        priority=5,
        run=_plugin_run,
    ),
)
