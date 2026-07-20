"""Bounded SpreadsheetML analysis for XLSX and XLSM packages."""
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
    _normalize_internal_target,
    _style_binary_findings,
)
from dayi.scanner import scan_text


def _texts(root: ElementTree.Element) -> str:
    return "".join(
        node.text or "" for node in root.iter()
        if _local(node.tag) in {"t", "v", "f"}
    )


def _read_xml(
    package: OpenXMLPackage,
    name: str,
    errors: list[str],
) -> ElementTree.Element | None:
    try:
        return package.xml(name)
    except UnsafeOpenXML as exc:
        errors.append(str(exc))
        return None


def _shared_strings(package: OpenXMLPackage, errors: list[str]) -> list[str]:
    if "xl/sharedStrings.xml" not in package.by_name:
        return []
    root = _read_xml(package, "xl/sharedStrings.xml", errors)
    if root is None:
        return []
    return [
        "".join(node.text or "" for node in item.iter() if _local(node.tag) == "t")
        for item in root if _local(item.tag) == "si"
    ]


def _style_tables(
    package: OpenXMLPackage,
    errors: list[str],
) -> list[dict[str, str]]:
    if "xl/styles.xml" not in package.by_name:
        return []
    root = _read_xml(package, "xl/styles.xml", errors)
    if root is None:
        return []
    fonts: list[dict[str, str]] = []
    fills: list[str] = []
    number_formats: dict[str, str] = {}
    xfs: list[dict[str, str]] = []
    for node in root.iter():
        local = _local(node.tag)
        if local == "numFmt":
            number_formats[_attr(node, "numFmtId") or ""] = _attr(node, "formatCode") or ""
        elif local == "font":
            properties: dict[str, str] = {"b": "0", "i": "0"}
            for child in node:
                name = _local(child.tag)
                if name in {"b", "i"}:
                    properties[name] = _attr(child, "val") or "1"
                elif name == "name":
                    properties["font"] = _attr(child, "val") or ""
                elif name == "sz":
                    properties["size"] = _attr(child, "val") or ""
                elif name == "color":
                    properties["color"] = _attr(child, "rgb") or _attr(child, "indexed") or ""
            fonts.append(properties)
        elif local == "fill":
            color = ""
            for child in node.iter():
                if _local(child.tag) in {"fgColor", "bgColor"}:
                    color = _attr(child, "rgb") or _attr(child, "indexed") or color
            fills.append(color)
    cell_xfs = next((node for node in root.iter() if _local(node.tag) == "cellXfs"), None)
    if cell_xfs is not None:
        for xf in cell_xfs:
            if _local(xf.tag) != "xf":
                continue
            try:
                font_id = int(_attr(xf, "fontId") or 0)
                fill_id = int(_attr(xf, "fillId") or 0)
            except ValueError:
                font_id = fill_id = -1
            num_id = _attr(xf, "numFmtId") or "0"
            properties = dict(fonts[font_id]) if 0 <= font_id < len(fonts) else {}
            properties["fill"] = fills[fill_id] if 0 <= fill_id < len(fills) else ""
            properties["numfmt"] = number_formats.get(num_id, num_id)
            properties["border"] = _attr(xf, "borderId") or "0"
            alignment = next((child for child in xf if _local(child.tag) == "alignment"), None)
            properties["alignment"] = _attr(alignment, "horizontal") if alignment is not None else ""
            xfs.append(properties)
    return xfs


def _workbook_sheets(
    package: OpenXMLPackage,
    collector: _FindingCollector,
    errors: list[str],
) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    root = _read_xml(package, "xl/workbook.xml", errors)
    if root is None:
        return result
    rel_targets: dict[str, str] = {}
    rel_name = "xl/_rels/workbook.xml.rels"
    if rel_name in package.by_name:
        rel_root = _read_xml(package, rel_name, errors)
        if rel_root is not None:
            for rel in rel_root.iter():
                if _local(rel.tag) == "Relationship":
                    rel_targets[_attr(rel, "Id") or ""] = _attr(rel, "Target") or ""
    for node in root.iter():
        local = _local(node.tag)
        if local == "sheet":
            name = _attr(node, "name") or "unnamed"
            state = (_attr(node, "state") or "visible").lower()
            rel_id = _attr(node, "id") or ""
            target = rel_targets.get(rel_id, "")
            member = (
                _normalize_internal_target("xl/workbook.xml", target)
                if target else ""
            )
            member = member or ""
            if member.startswith("xl/worksheets/"):
                result[member] = (name, state)
            hits = scan_text(name, collector.pattern)
            if hits:
                collector.add("xlsx", "sheet-name", "xl/workbook.xml", name, "confirmed", flags=hits)
        elif local == "definedName" and (node.text or "").strip():
            value = node.text or ""
            hidden = (_attr(node, "hidden") or "0") in {"1", "true"}
            hits = scan_text(value, collector.pattern)
            collector.add(
                "xlsx", "hidden-defined-name" if hidden else "defined-name",
                "xl/workbook.xml", value,
                "confirmed" if hits else "medium" if hidden else "low", flags=hits,
                evidence=("formula/name inspected passively",),
            )
            if not hits:
                collector.text_stego(value, "xlsx", "xl/workbook.xml")
    return result


def _cell_value(
    cell: ElementTree.Element,
    shared: list[str],
) -> tuple[str, str | None]:
    cell_type = _attr(cell, "t") or ""
    formula = next((node.text or "" for node in cell if _local(node.tag) == "f"), None)
    if cell_type == "inlineStr":
        value = "".join(node.text or "" for node in cell.iter() if _local(node.tag) == "t")
    else:
        value = next((node.text or "" for node in cell if _local(node.tag) == "v"), "")
        if cell_type == "s" and value.isdigit() and int(value) < len(shared):
            value = shared[int(value)]
    return value, formula


def _analyze_spreadsheet_package(
    package: OpenXMLPackage,
    collector: _FindingCollector,
    errors: list[str],
) -> None:
    shared = _shared_strings(package, errors)
    styles = _style_tables(package, errors)
    sheets = _workbook_sheets(package, collector, errors)
    for member in sorted(name for name in package.by_name if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", name)):
        root = _read_xml(package, member, errors)
        if root is None:
            continue
        sheet_name, sheet_state = sheets.get(member, (member, "visible"))
        hidden_columns: set[int] = set()
        for node in root.iter():
            if _local(node.tag) == "col" and (
                (_attr(node, "hidden") or "0") in {"1", "true"}
                or (_attr(node, "width") or "") in {"0", "0.0"}
            ):
                try:
                    start = int(_attr(node, "min") or 0)
                    end = int(_attr(node, "max") or 0)
                except ValueError:
                    continue
                if start <= end and start <= 16_384:
                    hidden_columns.update(range(max(1, start), min(16_384, end) + 1))
        streams: dict[str, list[tuple[str, str]]] = {
            "xlsx:bold": [], "xlsx:italic": [], "xlsx:font-family": [],
            "xlsx:font-color": [], "xlsx:fill-style": [], "xlsx:border": [],
            "xlsx:alignment": [], "xlsx:number-format": [],
        }
        for row in (node for node in root.iter() if _local(node.tag) == "row"):
            row_hidden = ((_attr(row, "hidden") or "0") in {"1", "true"}
                          or (_attr(row, "ht") or "") in {"0", "0.0"})
            for cell in (node for node in row if _local(node.tag) == "c"):
                value, formula = _cell_value(cell, shared)
                reference = _attr(cell, "r") or "cell"
                column_letters = re.match(r"[A-Z]+", reference.upper())
                column = 0
                if column_letters:
                    for character in column_letters.group(0):
                        column = column * 26 + ord(character) - 64
                column_hidden = column in hidden_columns
                try:
                    style_index = int(_attr(cell, "s") or 0)
                except ValueError:
                    style_index = -1
                style = styles[style_index] if 0 <= style_index < len(styles) else {}
                hidden_format = style.get("numfmt") == ";;;"
                color = style.get("color", "").lstrip("#").upper()
                fill = style.get("fill", "").lstrip("#").upper()
                white_text = color.endswith("FFFFFF") and (
                    not fill or fill.endswith("FFFFFF")
                )
                matching_color = bool(color and fill and color == fill)
                try:
                    zero_font = float(style.get("size", "-1")) <= 0
                except ValueError:
                    zero_font = False
                explicit_hidden = (_attr(cell, "hidden") or "0").lower() in {
                    "1", "true",
                }
                hidden = (
                    sheet_state in {"hidden", "veryhidden"} or row_hidden
                    or column_hidden or hidden_format or white_text
                    or matching_color or zero_font or explicit_hidden
                )
                mechanism = (
                    f"{sheet_state}-sheet" if sheet_state in {"hidden", "veryhidden"}
                    else "hidden-row" if row_hidden else "hidden-column" if column_hidden
                    else "hidden-number-format" if hidden_format else "white-text-cell" if white_text
                    else "matching-cell-colors" if matching_color
                    else "zero-font-cell" if zero_font
                    else "hidden-cell" if explicit_hidden
                    else "cell-value"
                )
                source = f"{member}!{reference} ({sheet_name})"
                if value:
                    hits = scan_text(value, collector.pattern)
                    if hits or hidden:
                        collector.add(
                            "xlsx", mechanism, source, value,
                            "confirmed" if hits else "medium",
                            evidence=("cell value inspected without formula evaluation",), flags=hits,
                        )
                    if not hits:
                        collector.text_stego(value, "xlsx", source)
                    collector.add_artifacts(value, f"document/xlsx/{source}")
                if formula:
                    hits = scan_text(formula, collector.pattern)
                    collector.add(
                        "xlsx", "formula", source, formula,
                        "confirmed" if hits else "low",
                        evidence=("formula was not calculated",), flags=hits,
                    )
                    if not hits:
                        collector.text_stego(formula, "xlsx", source)
                    collector.add_artifacts(formula, f"document/xlsx/{source}/formula")
                for stream, key in (
                    ("xlsx:bold", "b"), ("xlsx:italic", "i"),
                    ("xlsx:font-family", "font"), ("xlsx:font-color", "color"),
                    ("xlsx:fill-style", "fill"), ("xlsx:border", "border"),
                    ("xlsx:alignment", "alignment"), ("xlsx:number-format", "numfmt"),
                ):
                    if key in style:
                        streams[stream].append((value or reference, style[key]))
        _style_binary_findings(streams, member, collector)

    interesting = [
        name for name in sorted(package.by_name)
        if name.startswith(("xl/comments", "xl/threadedComments/", "xl/persons/", "xl/externalLinks/", "docProps/", "customXml/"))
        and name.endswith(".xml")
    ]
    for member in interesting:
        root = _read_xml(package, member, errors)
        if root is None:
            continue
        text = _generic_xml_text(root)
        if text.strip():
            category = "comment" if "comment" in member.lower() else "metadata" if member.startswith("docProps/") else "xlsx"
            hits = scan_text(text, collector.pattern)
            if hits or category == "comment":
                collector.add("xlsx", category, member, text, "confirmed" if hits else "low", flags=hits)
            if not hits:
                collector.text_stego(text, "xlsx", member)
            collector.add_artifacts(text, f"document/xlsx/{member}")
        for node in root.iter():
            for attribute in ("descr", "title", "name"):
                value = _attr(node, attribute)
                if value and scan_text(value, collector.pattern):
                    collector.add("xlsx", "alt-text", member, value, "confirmed")


def analyze_spreadsheet(
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
        analyzer=_analyze_spreadsheet_package, depth=depth, budget=budget,
    )
