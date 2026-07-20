"""Bounded PresentationML analysis for PPTX and PPTM packages."""
from __future__ import annotations

import re
from pathlib import Path

from dayi.document.detect import DocumentType, UnsafeOpenXML
from dayi.document.openxml import (
    OpenXMLPackage,
    _Budget,
    _FindingCollector,
    _analyze_package_document,
    _attr,
    _generic_xml_text,
    _local,
    _normalize_internal_target,
    _style_binary_findings,
)
from dayi.scanner import scan_text


def _outside_slide(value: str | None) -> bool:
    """Treat only explicit, well-formed extreme coordinates as off-slide."""
    try:
        coordinate = int(value or "0")
    except ValueError:
        return False
    return coordinate < 0 or coordinate > 100_000_000


def _read_xml(package: OpenXMLPackage, name: str, errors: list[str]):
    try:
        return package.xml(name)
    except UnsafeOpenXML as exc:
        errors.append(str(exc))
        return None


def _presentation_slides(
    package: OpenXMLPackage,
    errors: list[str],
) -> dict[str, int]:
    root = _read_xml(package, "ppt/presentation.xml", errors)
    if root is None:
        return {}
    targets: dict[str, str] = {}
    rel_name = "ppt/_rels/presentation.xml.rels"
    if rel_name in package.by_name:
        rels = _read_xml(package, rel_name, errors)
        if rels is not None:
            for rel in rels.iter():
                if _local(rel.tag) == "Relationship":
                    targets[_attr(rel, "Id") or ""] = _attr(rel, "Target") or ""
    result: dict[str, int] = {}
    index = 0
    for node in root.iter():
        if _local(node.tag) != "sldId":
            continue
        index += 1
        relationship_id = next(
            (
                value for key, value in node.attrib.items()
                if key.startswith("{") and _local(key) == "id"
            ),
            "",
        )
        target = targets.get(relationship_id, "")
        member = (
            _normalize_internal_target("ppt/presentation.xml", target)
            if target else ""
        )
        member = member or ""
        if member.startswith("ppt/slides/"):
            result[member] = index
    return result


def _member_kind(member: str) -> str:
    if member.startswith("ppt/notesSlides/"):
        return "speaker-notes"
    if member.startswith("ppt/comments/"):
        return "comment"
    if member.startswith("ppt/slideMasters/"):
        return "master-text"
    if member.startswith("ppt/slideLayouts/"):
        return "layout-text"
    if member.startswith("docProps/"):
        return "metadata"
    if member.startswith("customXml/"):
        return "custom-xml"
    return "slide-text"


def _analyze_presentation_package(
    package: OpenXMLPackage,
    collector: _FindingCollector,
    errors: list[str],
) -> None:
    slides = _presentation_slides(package, errors)
    members = [
        name for name in sorted(package.by_name)
        if name.endswith(".xml") and (
            re.fullmatch(r"ppt/slides/slide\d+\.xml", name)
            or re.fullmatch(r"ppt/notesSlides/notesSlide\d+\.xml", name)
            or name.startswith("ppt/comments/")
            or name == "ppt/commentAuthors.xml"
            or name.startswith("ppt/slideMasters/")
            or name.startswith("ppt/slideLayouts/")
            or name.startswith("docProps/")
            or name.startswith("customXml/")
        )
    ]
    for member in members:
        root = _read_xml(package, member, errors)
        if root is None:
            continue
        kind = _member_kind(member)
        slide_number = slides.get(member, 0)
        hidden_slide = (
            kind == "slide-text"
            and (_attr(root, "show") or "1").lower() in {"0", "false", "off"}
        )
        text = "".join(
            node.text or "" for node in root.iter()
            if _local(node.tag) in {"t", "text"}
        )
        if not text and kind in {"metadata", "custom-xml"}:
            text = _generic_xml_text(root)
        explicit_alpha = any(
            _local(node.tag) == "alpha" and (_attr(node, "val") or "") == "0"
            for node in root.iter()
        )
        white = any(
            _local(node.tag) == "srgbClr" and (_attr(node, "val") or "").upper() == "FFFFFF"
            for node in root.iter()
        )
        zero_size = any(
            _local(node.tag) == "ext"
            and ((_attr(node, "cx") or "") == "0" or (_attr(node, "cy") or "") == "0")
            for node in root.iter()
        )
        off_slide = any(
            _local(node.tag) == "off"
            and any(_outside_slide(_attr(node, axis)) for axis in ("x", "y"))
            for node in root.iter()
        )
        mechanism = (
            "hidden-slide" if hidden_slide else kind
            if kind != "slide-text" else "transparent-text" if explicit_alpha
            else "zero-size-shape" if zero_size else "off-slide-text" if off_slide
            else "white-text" if white else kind
        )
        if text.strip():
            hits = scan_text(text, collector.pattern)
            suspicious = hidden_slide or kind in {"speaker-notes", "comment"} or explicit_alpha or zero_size or off_slide or white
            source = f"{member}#slide-{slide_number}" if slide_number else member
            if hits or suspicious or kind in {"metadata", "custom-xml"}:
                collector.add(
                    "pptx", mechanism, source, text,
                    "confirmed" if hits else "high" if explicit_alpha or off_slide else "medium" if suspicious else "low",
                    flags=hits,
                )
            if not hits:
                collector.text_stego(text, "pptx", source)
            collector.add_artifacts(text, f"document/pptx/{source}")

        streams: dict[str, list[tuple[str, str]]] = {
            "pptx:bold": [], "pptx:italic": [], "pptx:font-family": [],
            "pptx:font-size": [], "pptx:font-color": [],
        }
        for run in (node for node in root.iter() if _local(node.tag) == "r"):
            run_text = "".join(node.text or "" for node in run.iter() if _local(node.tag) == "t")
            if not run_text:
                continue
            rpr = next((child for child in run if _local(child.tag) == "rPr"), None)
            properties = {
                "bold": _attr(rpr, "b") if rpr is not None else "0",
                "italic": _attr(rpr, "i") if rpr is not None else "0",
                "size": _attr(rpr, "sz") if rpr is not None else "",
                "font": "",
                "color": "",
            }
            if rpr is not None:
                for node in rpr.iter():
                    if _local(node.tag) in {"latin", "ea", "cs"} and not properties["font"]:
                        properties["font"] = _attr(node, "typeface") or ""
                    if _local(node.tag) == "srgbClr":
                        properties["color"] = _attr(node, "val") or ""
            for stream, key in (
                ("pptx:bold", "bold"), ("pptx:italic", "italic"),
                ("pptx:font-family", "font"), ("pptx:font-size", "size"),
                ("pptx:font-color", "color"),
            ):
                if properties[key] != "":
                    streams[stream].append((run_text, properties[key] or "0"))
        _style_binary_findings(streams, member, collector)

        for node in root.iter():
            for attribute in ("descr", "title", "name"):
                value = _attr(node, attribute)
                if not value or re.fullmatch(r"(?:Picture|Image|Shape|Text Box) \d+", value, re.I):
                    continue
                hits = scan_text(value, collector.pattern)
                if hits:
                    collector.add("pptx", "alt-text", member, value, "confirmed", flags=hits)


def analyze_presentation(
    path: Path,
    flag_pattern: re.Pattern,
    *,
    workspace: Path,
    document_type: DocumentType,
    depth: int,
    budget: _Budget | None,
):
    return _analyze_package_document(
        path, flag_pattern, workspace=workspace, document_type=document_type,
        analyzer=_analyze_presentation_package, depth=depth, budget=budget,
    )
