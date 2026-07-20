"""Bounded OpenDocument analysis for ODT, ODS, and ODP packages."""
from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree

from dayi.document.detect import DocumentType, UnsafeOpenXML
from dayi.document.openxml import (
    OpenXMLPackage,
    _Budget,
    _FindingCollector,
    _analyze_package_document,
    _attr,
    _generic_xml_text,
    _local,
    _style_binary_findings,
)
from dayi.scanner import scan_text


def _read_xml(package: OpenXMLPackage, name: str, errors: list[str]):
    try:
        return package.xml(name)
    except UnsafeOpenXML as exc:
        errors.append(str(exc))
        return None


def _style_map(package: OpenXMLPackage, errors: list[str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for member in ("styles.xml", "content.xml"):
        if member not in package.by_name:
            continue
        root = _read_xml(package, member, errors)
        if root is None:
            continue
        for style in (node for node in root.iter() if _local(node.tag) == "style"):
            name = _attr(style, "name")
            if not name:
                continue
            props: dict[str, str] = {}
            for node in style:
                for key, value in node.attrib.items():
                    local = _local(key)
                    if local in {
                        "font-weight", "font-style", "font-name", "font-size",
                        "color", "background-color", "text-align", "display",
                    }:
                        props[local] = value
            result[name] = props
    return result


def _element_text(element: ElementTree.Element) -> str:
    return "".join(element.itertext())


def _hidden_reason(element: ElementTree.Element, style: dict[str, str]) -> str | None:
    attrs = {_local(key): value.lower() for key, value in element.attrib.items()}
    if attrs.get("display") in {"none", "false"} or style.get("display", "").lower() == "none":
        return "display-none"
    if attrs.get("visibility") in {"hidden", "collapse", "filter"}:
        return "hidden-element"
    if attrs.get("condition") and attrs.get("display") != "true":
        return "conditional-hidden"
    color = style.get("color", "").lower()
    background = style.get("background-color", "").lower()
    if color in {"#ffffff", "white"} and background in {"", "#ffffff", "white", "transparent"}:
        return "white-on-white"
    if color and background and color == background:
        return "matching-color"
    size = style.get("font-size", "").lower()
    if size in {"0", "0pt", "0%"}:
        return "zero-font-size"
    try:
        if size.endswith("pt") and float(size[:-2]) <= 2:
            return "tiny-font-size"
    except ValueError:
        pass
    return None


def _explicit_mechanism(
    element: ElementTree.Element,
    style: dict[str, str],
) -> str | None:
    local = _local(element.tag)
    hidden = _hidden_reason(element, style)
    if local in {"annotation", "comment"}:
        return "annotation"
    if local in {"changed-region", "deletion", "tracked-changes"}:
        return "tracked-change"
    if local in {"notes", "notes-page"}:
        return "presentation-notes"
    if local in {"table", "table-row", "table-column"} and (
        (_attr(element, "visibility") or "").lower()
        in {"collapse", "filter", "hidden"}
    ):
        return f"hidden-{local}"
    if local in {"page", "draw-page"} and (
        (_attr(element, "visibility") or "").lower() in {"hidden", "false"}
    ):
        return "hidden-page"
    return hidden


def _contexts(
    root: ElementTree.Element,
    styles: dict[str, dict[str, str]],
) -> dict[ElementTree.Element, str | None]:
    """Propagate explicit concealment once, avoiding repeated ancestor walks."""
    result: dict[ElementTree.Element, str | None] = {}
    pending: list[tuple[ElementTree.Element, str | None]] = [(root, None)]
    while pending:
        element, inherited = pending.pop()
        style = styles.get(_attr(element, "style-name") or "", {})
        mechanism = _explicit_mechanism(element, style) or inherited
        result[element] = mechanism
        pending.extend((child, mechanism) for child in reversed(element))
    return result


def _text_groups(
    element: ElementTree.Element,
    contexts: dict[ElementTree.Element, str | None],
) -> dict[str | None, str]:
    grouped: dict[str | None, list[str]] = {}
    for node in element.iter():
        if node.text:
            grouped.setdefault(contexts.get(node), []).append(node.text)
        if node.tail:
            grouped.setdefault(contexts.get(element), []).append(node.tail)
    return {mechanism: "".join(parts) for mechanism, parts in grouped.items()}


def _analyze_odf_package(
    package: OpenXMLPackage,
    collector: _FindingCollector,
    errors: list[str],
) -> None:
    styles = _style_map(package, errors)
    members = [
        name for name in ("content.xml", "styles.xml", "meta.xml", "settings.xml", "META-INF/manifest.xml")
        if name in package.by_name
    ]
    for member in members:
        root = _read_xml(package, member, errors)
        if root is None:
            continue
        if member in {"meta.xml", "settings.xml"}:
            text = _generic_xml_text(root)
            hits = scan_text(text, collector.pattern)
            if hits:
                collector.add("odf", "metadata", member, text, "confirmed", flags=hits)
            elif text.strip():
                collector.text_stego(text, "odf", member)

        contexts = _contexts(root, styles)

        streams: dict[str, list[tuple[str, str]]] = {
            "odf:bold": [], "odf:italic": [], "odf:font-family": [],
            "odf:font-size": [], "odf:text-color": [],
            "odf:background-color": [], "odf:paragraph-style": [],
            "odf:alignment": [],
        }
        for element in root.iter():
            local = _local(element.tag)
            style_name = _attr(element, "style-name") or ""
            style = styles.get(style_name, {})

            is_text_unit = local in {"p", "h"} or (
                local in {
                    "span", "table-cell", "annotation", "comment",
                    "changed-region", "deletion", "notes", "notes-page",
                }
                and not any(_local(child.tag) in {"p", "h"} for child in element.iter() if child is not element)
            )
            if is_text_unit:
                for mechanism, text in _text_groups(element, contexts).items():
                    text = text.strip()
                    if not text:
                        continue
                    hits = scan_text(text, collector.pattern)
                    if hits or mechanism:
                        collector.add(
                            "odf", mechanism or "visible-text", member, text,
                            "confirmed" if hits else "high" if mechanism in {
                                "display-none", "white-on-white",
                                "matching-color", "zero-font-size",
                            } else "medium",
                            flags=hits,
                        )
                    if not hits:
                        collector.text_stego(text, "odf", member)

            for key, value in element.attrib.items():
                attribute = _local(key)
                if attribute in {"href", "title", "description", "name"} and value:
                    if attribute == "href" and re.match(r"(?:https?|file)://|\\\\", value, re.I):
                        collector.add(
                            "relationship", "external", member, value, "high",
                            evidence=("target was not fetched",),
                        )
                        collector.add_artifacts(value, f"document/odf/{member}")
                    elif scan_text(value, collector.pattern):
                        collector.add("odf", "alt-text", member, value, "confirmed")

            has_styled_children = any(
                _attr(child, "style-name") for child in element
            )
            style_text = (
                _element_text(element).strip()
                if style_name and (local == "span" or not has_styled_children)
                else ""
            )
            if style_text:
                values = {
                    "odf:bold": style.get("font-weight", "normal"),
                    "odf:italic": style.get("font-style", "normal"),
                    "odf:font-family": style.get("font-name", ""),
                    "odf:font-size": style.get("font-size", ""),
                    "odf:text-color": style.get("color", ""),
                    "odf:background-color": style.get("background-color", ""),
                    "odf:paragraph-style": style_name,
                    "odf:alignment": style.get("text-align", ""),
                }
                for stream, value in values.items():
                    if value:
                        streams[stream].append((style_text, value))
        _style_binary_findings(streams, member, collector)


def analyze_opendocument(
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
        analyzer=_analyze_odf_package, depth=depth, budget=budget,
    )
