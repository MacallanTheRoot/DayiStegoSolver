"""Bounded WordprocessingML analysis without rendering or active content."""
from __future__ import annotations

import hashlib
import posixpath
import re
import urllib.parse
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable
from xml.etree import ElementTree

from dayi.document.detect import (
    DocumentType,
    UnsafeOpenXML,
    detect_document_type,
    safe_member_name,
    validate_zip_members,
)
from dayi.document.limits import (
    COPY_CHUNK_BYTES,
    MAX_EMBEDDED_OBJECTS,
    MAX_EXTRACTED_ARTIFACT_BYTES,
    MAX_FINDINGS,
    MAX_FINDING_PREVIEW_CHARS,
    MAX_FINDING_VALUE_CHARS,
    MAX_MACRO_LINE_CHARS,
    MAX_MACRO_LINES,
    MAX_MACRO_LITERALS,
    MAX_MEDIA_OBJECTS,
    MAX_PACKAGE_BYTES,
    MAX_RECURSION_DEPTH,
    MAX_RECURSIVE_EXTRACTED_BYTES,
    MAX_RECURSIVE_OBJECTS,
    MAX_RELATIONSHIPS,
    MAX_STATIC_STRINGS_BYTES,
    MAX_STYLE_DEPTH,
    MAX_STYLE_STREAMS,
    MAX_TEXT_STEGO_SECTIONS,
    MAX_XML_MEMBER_BYTES,
    MAX_XML_DEPTH,
    MAX_XML_NODES,
    MAX_XML_TEXT_CHARS,
)
from dayi.document.model import (
    DocumentAnalysis,
    DocumentFinding,
    ExtractedDocumentArtifact,
    safe_document_value,
)
from dayi.scanner import ArtifactFinding, scan_artifacts, scan_text
from dayi.text_stego import analyze_text_input, detect_text_bytes


_WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_XML_FORBIDDEN = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_GENERIC_OBJECT_NAME = re.compile(
    r"^(?:picture|image|text box|shape|object)\s*\d+$", re.IGNORECASE
)
_ACTIVE_FIELD = re.compile(
    r"\b(?:DDEAUTO?|INCLUDETEXT|INCLUDEPICTURE|HYPERLINK)\b", re.IGNORECASE
)
_EXECUTABLE_MAGICS = (b"MZ", b"\x7fELF", b"#!")
_IMAGE_MAGICS = {
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"BM": "BMP",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
}
_TEXT_TAGS = frozenset({"t", "delText", "instrText"})
_REVISION_TAGS = frozenset({"ins", "del", "moveFrom", "moveTo"})
_NORMAL_TOP_LEVEL = frozenset({
    "[Content_Types].xml", "_rels", "docProps", "customXml", "word", "xl",
    "ppt", "META-INF", "Pictures", "ObjectReplacements", "Objects",
    "Thumbnails", "mimetype", "Configurations2",
})
_VBA_STRING = re.compile(r'"((?:""|[^"\r\n])*)"')
_VBA_CHR = re.compile(
    r"\bChrW?\s*\(\s*(&H[0-9A-Fa-f]{1,6}|\d{1,7})\s*\)",
    re.IGNORECASE,
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _attr(element: ElementTree.Element, name: str) -> str | None:
    direct = element.attrib.get(name)
    if direct is not None:
        return direct
    return next(
        (value for key, value in element.attrib.items() if _local(key) == name),
        None,
    )


def _truthy(value: str | None, *, default: bool = True) -> bool:
    if value is None:
        return default
    return value.lower() not in {"0", "false", "off", "no"}


def _element_text(element: ElementTree.Element) -> str:
    parts: list[str] = []
    used = 0
    for node in element.iter():
        if _local(node.tag) not in _TEXT_TAGS or not node.text:
            continue
        remaining = MAX_XML_TEXT_CHARS - used
        if remaining <= 0:
            break
        piece = node.text[:remaining]
        parts.append(piece)
        used += len(piece)
    return "".join(parts)


def _generic_xml_text(element: ElementTree.Element) -> str:
    """Collect bounded leaf text from property/custom XML members."""
    parts: list[str] = []
    used = 0
    for node in element.iter():
        if not node.text or not node.text.strip():
            continue
        remaining = MAX_XML_TEXT_CHARS - used
        if remaining <= 0:
            break
        value = node.text[:remaining]
        parts.append(value)
        used += len(value)
    return "\n".join(parts)


def _parse_xml(data: bytes, member: str) -> ElementTree.Element:
    if len(data) > MAX_XML_MEMBER_BYTES:
        raise UnsafeOpenXML(f"XML member limit exceeded: {member}")
    if _XML_FORBIDDEN.search(data):
        raise UnsafeOpenXML(f"DTD/entity declarations rejected: {member}")
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise UnsafeOpenXML(f"malformed XML member: {member}") from exc
    nodes = 0
    text_chars = 0
    pending = [(root, 1)]
    while pending:
        element, depth = pending.pop()
        if depth > MAX_XML_DEPTH:
            raise UnsafeOpenXML(f"XML depth limit exceeded: {member}")
        nodes += 1
        if nodes > MAX_XML_NODES:
            raise UnsafeOpenXML(f"XML node limit exceeded: {member}")
        text_chars += len(element.text or "") + len(element.tail or "")
        if text_chars > MAX_XML_TEXT_CHARS:
            raise UnsafeOpenXML(f"XML text limit exceeded: {member}")
        pending.extend((child, depth + 1) for child in element)
    return root


class OpenXMLPackage:
    """Explicit-member ZIP reader enforcing document package limits."""

    def __init__(self, path: Path):
        self.path = path
        self.archive: zipfile.ZipFile | None = None
        self.members: tuple[zipfile.ZipInfo, ...] = ()
        self.by_name: dict[str, zipfile.ZipInfo] = {}

    def __enter__(self) -> "OpenXMLPackage":
        archive = zipfile.ZipFile(self.path)
        try:
            members = validate_zip_members(archive)
        except BaseException:
            archive.close()
            raise
        self.archive = archive
        self.members = members
        self.by_name = {member.filename: member for member in members}
        return self

    def __exit__(self, *_args: object) -> None:
        if self.archive is not None:
            self.archive.close()
        self.archive = None

    def read(self, name: str, *, limit: int) -> bytes:
        if self.archive is None:
            raise RuntimeError("OpenXML package is closed")
        info = self.by_name[name]
        if info.is_dir() or info.file_size > limit:
            raise UnsafeOpenXML(f"member read limit exceeded: {name}")
        output = bytearray()
        with self.archive.open(info) as source:
            while True:
                chunk = source.read(min(COPY_CHUNK_BYTES, limit + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > limit:
                    raise UnsafeOpenXML(f"member expanded beyond limit: {name}")
        if len(output) != info.file_size:
            raise UnsafeOpenXML(f"member size mismatch: {name}")
        return bytes(output)

    def xml(self, name: str) -> ElementTree.Element:
        return _parse_xml(self.read(name, limit=MAX_XML_MEMBER_BYTES), name)

    def extract(self, name: str, root: Path) -> Path:
        if self.archive is None:
            raise RuntimeError("OpenXML package is closed")
        info = self.by_name[name]
        member_path = safe_member_name(name)
        destination = root.joinpath(*member_path.parts)
        root_resolved = root.resolve()
        if not destination.resolve(strict=False).is_relative_to(root_resolved):
            raise UnsafeOpenXML("extracted member escaped workspace")
        destination.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        try:
            with self.archive.open(info) as source, destination.open("xb") as target:
                while True:
                    chunk = source.read(COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_EXTRACTED_ARTIFACT_BYTES or written > info.file_size:
                        raise UnsafeOpenXML("artifact extraction limit exceeded")
                    target.write(chunk)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        if written != info.file_size:
            destination.unlink(missing_ok=True)
            raise UnsafeOpenXML("artifact size mismatch")
        return destination


@dataclass
class _Budget:
    bytes_written: int = 0
    object_count: int = 0
    digests: set[str] = field(default_factory=set)
    package_count: int = 0


class _FindingCollector:
    def __init__(self, pattern: re.Pattern):
        self.pattern = pattern
        self.findings: dict[tuple[object, ...], DocumentFinding] = {}
        self.artifacts: list[ArtifactFinding] = []
        self.text_sections = 0
        self.limits: set[str] = set()

    def add(
        self,
        category: str,
        mechanism: str,
        member: str,
        value: str,
        confidence: str,
        *,
        evidence: Iterable[str] = (),
        decoder_chain: Iterable[str] = (),
        flags: Iterable[str] | None = None,
        related_artifact: str | None = None,
    ) -> None:
        if not value:
            return
        bounded_raw = value[:MAX_FINDING_VALUE_CHARS]
        raw_flags = tuple(dict.fromkeys(
            scan_text(bounded_raw, self.pattern) if flags is None else flags
        ))
        safe_flags = tuple(
            safe_document_value(flag, 2048) for flag in raw_flags
        )
        if safe_flags:
            confidence = "confirmed"
        safe_value = safe_document_value(bounded_raw, MAX_FINDING_VALUE_CHARS)
        preview = " ".join(
            safe_document_value(bounded_raw, MAX_FINDING_PREVIEW_CHARS * 2).split()
        )
        preview = preview[:MAX_FINDING_PREVIEW_CHARS]
        key = (
            category, mechanism, member, safe_value, tuple(decoder_chain), safe_flags,
        )
        if key in self.findings:
            return
        if len(self.findings) >= MAX_FINDINGS:
            self.limits.add("finding-count")
            if not safe_flags:
                return
            confidence_rank = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
            replaceable = [
                (confidence_rank[item.confidence], index, existing_key)
                for index, (existing_key, item) in enumerate(self.findings.items())
                if not item.flags_found
            ]
            if not replaceable:
                return
            _rank, _index, victim = min(replaceable)
            del self.findings[victim]
        finding = DocumentFinding(
            category=category,
            mechanism=mechanism,
            source_member=safe_document_value(member, 1024),
            value=safe_value,
            confidence=confidence,  # type: ignore[arg-type]
            evidence=tuple(safe_document_value(item, 512) for item in evidence),
            decoder_chain=tuple(decoder_chain),
            flags_found=safe_flags,
            related_artifact=(
                safe_document_value(related_artifact, 1024)
                if related_artifact is not None else None
            ),
            preview=preview,
        )
        self.findings[key] = finding

    def add_artifacts(self, text: str, source: str) -> None:
        existing = {
            (item.artifact_type, item.preview, item.source, item.decoded_preview)
            for item in self.artifacts
        }
        for item in scan_artifacts(text, source=source):
            key = (item.artifact_type, item.preview, item.source, item.decoded_preview)
            if key not in existing:
                existing.add(key)
                self.artifacts.append(item)

    def text_stego(self, text: str, category: str, member: str) -> None:
        if self.text_sections >= MAX_TEXT_STEGO_SECTIONS or len(text.strip()) < 4:
            if self.text_sections >= MAX_TEXT_STEGO_SECTIONS:
                self.limits.add("text-stego-section-count")
            return
        self.text_sections += 1
        source = detect_text_bytes(text.encode("utf-8", errors="replace"))
        analysis = analyze_text_input(source, self.pattern)
        for candidate in analysis.candidates:
            if candidate.confidence not in {"confirmed", "high", "medium"}:
                continue
            self.add(
                category,
                "text-stego",
                member,
                candidate.value,
                candidate.confidence,
                evidence=candidate.evidence,
                decoder_chain=("text_stego", *candidate.chain),
                flags=candidate.flags_found,
            )

    def finish(self) -> tuple[DocumentFinding, ...]:
        rank = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}
        return tuple(sorted(
            self.findings.values(),
            key=lambda item: (
                rank[item.confidence], item.category, item.source_member,
                item.mechanism, item.preview, item.decoder_chain,
            ),
        ))


def _property_map(properties: ElementTree.Element | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if properties is None:
        return result
    for child in properties:
        name = _local(child.tag)
        value = _attr(child, "val")
        if name in {"vanish", "webHidden", "b", "i", "u"}:
            result[name] = "1" if _truthy(value) else "0"
        elif name == "rFonts":
            result["font"] = (
                _attr(child, "ascii") or _attr(child, "hAnsi") or ""
            )
        elif name in {"color", "sz", "w", "spacing", "position", "vertAlign"}:
            result[name] = value or ""
        elif name == "shd":
            result["background"] = _attr(child, "fill") or ""
    return result


class _Styles:
    def __init__(self, root: ElementTree.Element | None):
        self.default: dict[str, str] = {}
        self.styles: dict[str, tuple[str | None, dict[str, str]]] = {}
        if root is None:
            return
        for element in root.iter():
            name = _local(element.tag)
            if name == "rPrDefault":
                rpr = next((node for node in element if _local(node.tag) == "rPr"), None)
                self.default.update(_property_map(rpr))
            elif name == "style":
                style_id = _attr(element, "styleId")
                if not style_id:
                    continue
                based_on = next(
                    (_attr(node, "val") for node in element if _local(node.tag) == "basedOn"),
                    None,
                )
                rpr = next((node for node in element if _local(node.tag) == "rPr"), None)
                self.styles[style_id] = (based_on, _property_map(rpr))

    def resolve(
        self,
        style_id: str | None,
        *,
        include_defaults: bool = True,
    ) -> dict[str, str]:
        result = dict(self.default) if include_defaults else {}
        chain: list[dict[str, str]] = []
        seen: set[str] = set()
        current = style_id
        while current and current not in seen and len(seen) < MAX_STYLE_DEPTH:
            seen.add(current)
            based_on, properties = self.styles.get(current, (None, {}))
            chain.append(properties)
            current = based_on
        for properties in reversed(chain):
            result.update(properties)
        return result


def _run_properties(
    run: ElementTree.Element,
    styles: _Styles,
    paragraph: ElementTree.Element | None = None,
) -> dict[str, str]:
    rpr = next((child for child in run if _local(child.tag) == "rPr"), None)
    style_id = None
    if rpr is not None:
        style_id = next(
            (_attr(child, "val") for child in rpr if _local(child.tag) == "rStyle"),
            None,
        )
    paragraph_style = None
    paragraph_rpr = None
    if paragraph is not None:
        ppr = next(
            (child for child in paragraph if _local(child.tag) == "pPr"), None
        )
        if ppr is not None:
            paragraph_style = next(
                (_attr(child, "val") for child in ppr if _local(child.tag) == "pStyle"),
                None,
            )
            paragraph_rpr = next(
                (child for child in ppr if _local(child.tag) == "rPr"), None
            )
    properties = dict(styles.default)
    properties.update(
        styles.resolve(paragraph_style, include_defaults=False)
    )
    properties.update(_property_map(paragraph_rpr))
    if style_id is not None:
        properties.update(styles.resolve(style_id, include_defaults=False))
    properties.update(_property_map(rpr))
    return properties


def _hidden_mechanism(properties: dict[str, str]) -> tuple[str, str] | None:
    if properties.get("vanish") == "1":
        return "vanish", "explicit w:vanish"
    if properties.get("webHidden") == "1":
        return "web-hidden", "explicit w:webHidden"
    color = properties.get("color", "").lstrip("#").upper()
    background = properties.get("background", "").lstrip("#").upper()
    if color in {"FFFFFF", "FFF"} and background in {"", "FFFFFF", "FFF", "AUTO"}:
        return "white-on-white", "explicit white foreground"
    if color and background and color == background:
        return "matching-foreground-background", "explicit equal colors"
    try:
        size = int(properties.get("sz", ""))
    except ValueError:
        size = 999
    if size == 0:
        return "zero-font-size", "explicit zero font size"
    if 0 < size <= 4:
        return "tiny-font-size", "explicit font size at most 2pt"
    try:
        scale = int(properties.get("w", ""))
    except ValueError:
        scale = 100
    if scale == 0:
        return "zero-character-scale", "explicit zero character scale"
    try:
        spacing = int(properties.get("spacing", ""))
    except ValueError:
        spacing = 0
    if spacing <= -100:
        return "negative-character-spacing", "explicit compressed spacing"
    return None


def _member_category(name: str) -> tuple[str, str]:
    if name.startswith("word/comments"):
        return "comment", "comment"
    if re.fullmatch(r"word/header\d*\.xml", name):
        return "header_footer", "header"
    if re.fullmatch(r"word/footer\d*\.xml", name):
        return "header_footer", "footer"
    if name == "word/footnotes.xml":
        return "footnote_endnote", "footnote"
    if name == "word/endnotes.xml":
        return "footnote_endnote", "endnote"
    if name.startswith("word/glossary/"):
        return "orphan_content", "glossary"
    if name.startswith("customXml/"):
        return "orphan_content", "custom-xml"
    if name.startswith("docProps/"):
        return "metadata", "package-property"
    return "visible_text", "wordprocessingml"


def _revision_findings(
    root: ElementTree.Element,
    member: str,
    collector: _FindingCollector,
) -> None:
    for element in root.iter():
        mechanism = _local(element.tag)
        if mechanism not in _REVISION_TAGS:
            continue
        text = _element_text(element)
        if not text.strip():
            continue
        hits = scan_text(text, collector.pattern)
        collector.add(
            "revision", mechanism, member, text,
            "confirmed" if hits else "medium",
            evidence=("retained revision XML",), flags=hits,
        )
        if not hits:
            collector.text_stego(text, "revision", member)


def _empty_style_streams() -> dict[str, list[tuple[str, str]]]:
    return {
        "bold-vs-normal": [], "italic-vs-normal": [],
        "underline-vs-normal": [], "font-family": [], "font-size": [],
        "font-color": [], "vertical-position": [], "character-spacing": [],
    }


def _append_style_values(
    streams: dict[str, list[tuple[str, str]]],
    text: str,
    properties: dict[str, str],
) -> None:
    streams["bold-vs-normal"].append((text, properties.get("b", "0")))
    streams["italic-vs-normal"].append((text, properties.get("i", "0")))
    streams["underline-vs-normal"].append((text, properties.get("u", "0")))
    for stream, prop in (
        ("font-family", "font"), ("font-size", "sz"),
        ("font-color", "color"), ("vertical-position", "vertAlign"),
        ("character-spacing", "spacing"),
    ):
        if properties.get(prop):
            streams[stream].append((text, properties[prop]))


def _style_binary_findings(
    streams: dict[str, list[tuple[str, str]]],
    member: str,
    collector: _FindingCollector,
) -> None:
    generated = 0
    for mechanism in sorted(streams):
        values = streams[mechanism]
        if len(values) < 16 or generated >= MAX_STYLE_STREAMS:
            continue
        classes = Counter(style for _text, style in values)
        if len(classes) != 2 or min(classes.values()) < 4:
            continue
        ordered = sorted(classes)
        bits = "".join("0" if style == ordered[0] else "1" for _text, style in values)
        source = detect_text_bytes(bits.encode("ascii"))
        analysis = analyze_text_input(source, collector.pattern)
        for candidate in analysis.candidates:
            if candidate.confidence not in {"confirmed", "high", "medium"}:
                continue
            collector.add(
                "style_encoding", mechanism, member, candidate.value,
                candidate.confidence,
                evidence=(f"explicit classes: {ordered[0]} / {ordered[1]}",),
                decoder_chain=(f"document_style:{mechanism}", *candidate.chain),
                flags=candidate.flags_found,
            )
        generated += 1


def _analyze_xml_member(
    root: ElementTree.Element,
    member: str,
    styles: _Styles,
    collector: _FindingCollector,
) -> None:
    category, mechanism = _member_category(member)
    all_text = (
        _generic_xml_text(root)
        if category in {"metadata", "orphan_content"}
        else _element_text(root)
    )
    if all_text.strip():
        hits = scan_text(all_text, collector.pattern)
        if hits:
            collector.add(category, mechanism, member, all_text, "confirmed", flags=hits)
        elif category != "visible_text":
            collector.add(category, mechanism, member, all_text, "low")
        if not hits:
            collector.text_stego(all_text, category, member)
        collector.add_artifacts(all_text, f"document/{member}")

    _revision_findings(root, member, collector)
    streams = _empty_style_streams()
    paragraph_streams: dict[ElementTree.Element, dict[str, list[tuple[str, str]]]] = {}
    parents = {
        child: parent for parent in root.iter() for child in parent
    }
    for element in root.iter():
        local = _local(element.tag)
        if category == "metadata" and _attr(element, "name"):
            property_value = _generic_xml_text(element)
            if property_value:
                named_value = f"{_attr(element, 'name')}={property_value}"
                hits = scan_text(named_value, collector.pattern)
                collector.add(
                    "metadata", "custom-property", member, named_value,
                    "confirmed" if hits else "low", flags=hits,
                )
        for attribute in ("descr", "title", "name", "alt"):
            if category == "metadata" and attribute == "name":
                continue
            value = _attr(element, attribute)
            if not value or _GENERIC_OBJECT_NAME.fullmatch(value.strip()):
                continue
            hits = scan_text(value, collector.pattern)
            collector.add(
                "alt_text", attribute, member, value,
                "confirmed" if hits else "medium", flags=hits,
            )
            if not hits:
                collector.text_stego(value, "alt_text", member)
            collector.add_artifacts(value, f"document/alt-text/{member}")

        if local in {"instrText", "fldSimple"}:
            value = (
                element.text or ""
                if local == "instrText"
                else _attr(element, "instr") or _element_text(element)
            )
            if value.strip():
                hits = scan_text(value, collector.pattern)
                collector.add(
                    "field_code", "active-field" if _ACTIVE_FIELD.search(value) else "field-instruction",
                    member, value,
                    "confirmed" if hits else "high" if _ACTIVE_FIELD.search(value) else "medium",
                    evidence=("passive inspection; field was not executed",), flags=hits,
                )
                if not hits:
                    collector.text_stego(value, "field_code", member)
                collector.add_artifacts(value, f"document/field/{member}")

        style_attribute = (_attr(element, "style") or "").lower()
        if "visibility:hidden" in style_attribute or "display:none" in style_attribute:
            concealed = _element_text(element)
            if concealed:
                collector.add(
                    "hidden_text", "hidden-text-box", member, concealed, "high",
                    evidence=("explicit hidden VML/CSS property",),
                )
        if local == "alpha" and (_attr(element, "val") or "") == "0":
            ancestor = parents.get(element)
            while ancestor is not None and _local(ancestor.tag) not in {
                "txbxContent", "drawing", "p",
            }:
                ancestor = parents.get(ancestor)
            concealed = _element_text(ancestor) if ancestor is not None else ""
            if concealed:
                collector.add(
                    "hidden_text", "transparent-drawing-text", member,
                    concealed, "high", evidence=("explicit DrawingML alpha=0",),
                )
        if local == "anchor" and _truthy(_attr(element, "behindDoc"), default=False):
            concealed = _element_text(element)
            if concealed:
                collector.add(
                    "hidden_text", "text-behind-shape", member, concealed, "low",
                    evidence=("explicit behindDoc layout hint; no rendering attempted",),
                )

        if local != "r":
            continue
        text = _element_text(element)
        if not text:
            continue
        ancestor = parents.get(element)
        while ancestor is not None and _local(ancestor.tag) != "p":
            ancestor = parents.get(ancestor)
        properties = _run_properties(element, styles, ancestor)
        hidden = _hidden_mechanism(properties)
        if hidden is not None:
            hidden_mechanism, evidence = hidden
            hits = scan_text(text, collector.pattern)
            collector.add(
                "hidden_text", hidden_mechanism, member, text,
                "confirmed" if hits else "high",
                evidence=(evidence,), flags=hits,
            )
            if not hits:
                collector.text_stego(text, "hidden_text", member)

        _append_style_values(streams, text, properties)
        if ancestor is not None:
            paragraph = paragraph_streams.setdefault(ancestor, _empty_style_streams())
            _append_style_values(paragraph, text, properties)

    for paragraph in paragraph_streams.values():
        _style_binary_findings(paragraph, member, collector)
    _style_binary_findings(streams, member, collector)


def _relationship_source(name: str) -> str:
    if name == "_rels/.rels":
        return ""
    prefix, rel_name = name.rsplit("/_rels/", 1)
    return f"{prefix}/{rel_name[:-5]}" if rel_name.endswith(".rels") else prefix


def _normalize_internal_target(source: str, target: str) -> str | None:
    if not target or "\x00" in target or "\\" in target:
        return None
    try:
        parsed = urllib.parse.urlsplit(target)
    except ValueError:
        return None
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    path = parsed.path
    if path.startswith("/"):
        candidate = posixpath.normpath(path.lstrip("/"))
    else:
        candidate = posixpath.normpath(
            posixpath.join(posixpath.dirname(source), path)
        )
    if candidate == ".." or candidate.startswith("../") or candidate.startswith("/"):
        return None
    try:
        safe_member_name(candidate)
    except UnsafeOpenXML:
        return None
    return candidate


def _analyze_relationships(
    package: OpenXMLPackage,
    collector: _FindingCollector,
    errors: list[str],
) -> set[str]:
    referenced: set[str] = set()
    count = 0
    names = set(package.by_name)
    for member in sorted(name for name in names if name.endswith(".rels")):
        try:
            root = package.xml(member)
        except UnsafeOpenXML as exc:
            errors.append(str(exc))
            continue
        source = _relationship_source(member)
        for relationship in root.iter():
            if _local(relationship.tag) != "Relationship":
                continue
            count += 1
            if count > MAX_RELATIONSHIPS:
                collector.limits.add("relationship-count")
                return referenced
            target = _attr(relationship, "Target") or ""
            rel_type = (_attr(relationship, "Type") or "").rsplit("/", 1)[-1]
            external = (_attr(relationship, "TargetMode") or "").lower() == "external"
            if external:
                confidence = "medium" if rel_type.lower() == "hyperlink" else "high"
                collector.add(
                    "relationship", "external", member, target, confidence,
                    evidence=(f"relationship type: {rel_type}", "target was not fetched"),
                    related_artifact=source or "package",
                )
                collector.add_artifacts(target, f"document/relationship/{member}")
                continue
            normalized = _normalize_internal_target(source, target)
            if normalized is None:
                collector.add(
                    "suspicious_package", "unsafe-internal-relationship", member,
                    target or "<empty target>", "high",
                    evidence=("internal target normalization failed",),
                )
                continue
            referenced.add(normalized)
            if normalized not in names:
                collector.add(
                    "relationship", "missing-internal-target", member,
                    normalized, "medium", evidence=(f"relationship type: {rel_type}",),
                )
    return referenced


def _analyze_odf_references(
    package: OpenXMLPackage,
    collector: _FindingCollector,
    errors: list[str],
) -> set[str]:
    """Resolve bounded ODF URI attributes without fetching any target."""
    referenced: set[str] = set()
    names = set(package.by_name)
    count = 0
    for member in (
        "content.xml",
        "styles.xml",
        "META-INF/manifest.xml",
    ):
        if member not in names:
            continue
        try:
            root = package.xml(member)
        except UnsafeOpenXML as exc:
            errors.append(str(exc))
            continue
        for element in root.iter():
            for key, raw_target in element.attrib.items():
                if _local(key) not in {"href", "full-path"} or not raw_target:
                    continue
                count += 1
                if count > MAX_RELATIONSHIPS:
                    collector.limits.add("relationship-count")
                    return referenced
                target = raw_target.strip()
                try:
                    parsed = urllib.parse.urlsplit(target)
                except ValueError:
                    parsed = None
                if parsed is None or parsed.scheme or parsed.netloc or target.startswith("\\\\"):
                    collector.add(
                        "relationship", "external", member, target, "medium",
                        evidence=("ODF target was not fetched",),
                    )
                    collector.add_artifacts(target, f"document/odf/{member}")
                    continue
                if target.startswith("#") or parsed.path in {"", "/", "."}:
                    continue
                decoded_path = urllib.parse.unquote(parsed.path)
                if decoded_path.endswith("/"):
                    continue
                source = "" if member == "META-INF/manifest.xml" else member
                normalized = _normalize_internal_target(source, decoded_path)
                if normalized is None:
                    collector.add(
                        "suspicious_package", "unsafe-odf-reference", member,
                        target, "high",
                        evidence=("ODF target normalization failed",),
                    )
                    continue
                referenced.add(normalized)
                if normalized not in names:
                    collector.add(
                        "relationship", "missing-internal-target", member,
                        normalized, "medium",
                        evidence=("ODF internal reference",),
                    )
    return referenced


def _magic_kind(data: bytes) -> str:
    for magic, kind in _IMAGE_MAGICS.items():
        if data.startswith(magic):
            return kind
    if data.startswith(b"PK\x03\x04"):
        return "ZIP"
    if data.startswith(b"%PDF-"):
        return "PDF"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE"
    if data.startswith(_EXECUTABLE_MAGICS):
        return "EXECUTABLE"
    detected = detect_text_bytes(data)
    return "TEXT" if detected.classification == "probable-text" else "BINARY"


def _scan_embedded_content(
    data: bytes,
    member: str,
    kind: str,
    collector: _FindingCollector,
    related: str,
) -> None:
    bounded = data[:MAX_STATIC_STRINGS_BYTES]
    text = bounded.decode("latin-1", errors="replace")
    hits = scan_text(text, collector.pattern)
    if hits:
        collector.add(
            "embedded_media" if kind in _IMAGE_MAGICS.values() else "embedded_object",
            "bounded-static-strings", member, text, "confirmed",
            evidence=(f"magic type: {kind}",), flags=hits,
            related_artifact=related,
        )
    collector.add_artifacts(text, f"document/embedded/{member}")
    if kind == "TEXT" and not hits:
        collector.text_stego(text, "embedded_object", member)
    if kind == "EXECUTABLE":
        collector.add(
            "suspicious_package", "executable-like-object", member,
            f"Executable-like embedded object ({len(data)} bytes)", "high",
            evidence=("identified only; content was not executed",),
            related_artifact=related,
        )


def _scan_vba_static(
    data: bytes,
    member: str,
    collector: _FindingCollector,
) -> None:
    """Recover only bounded, explicit VBA literals without evaluating code."""
    source = data[:MAX_STATIC_STRINGS_BYTES].decode("latin-1", errors="replace")
    literals_seen = 0
    for raw_line in source.splitlines()[:MAX_MACRO_LINES]:
        line = raw_line[:MAX_MACRO_LINE_CHARS]
        literals = [
            value.replace('""', '"')
            for value in _VBA_STRING.findall(line)
        ]
        if literals:
            for literal in literals[:MAX_MACRO_LITERALS - literals_seen]:
                literals_seen += 1
                if scan_text(literal, collector.pattern):
                    collector.add(
                        "macro_string", "vba-string-literal", member, literal,
                        "confirmed", evidence=("passive VBA literal recovery",),
                    )
                elif len(literal) >= 8:
                    collector.text_stego(literal, "macro_string", member)
                if literals_seen >= MAX_MACRO_LITERALS:
                    break
        if len(literals) >= 2 and re.search(r'["\)]\s*[&+]\s*"', line):
            joined = "".join(literals)[:MAX_FINDING_VALUE_CHARS]
            hits = scan_text(joined, collector.pattern)
            if hits:
                collector.add(
                    "macro_string", "vba-string-concatenation", member, joined,
                    "confirmed", evidence=("passive literal concatenation",),
                    flags=hits,
                )
        calls = _VBA_CHR.findall(line)
        if len(calls) >= 4:
            decoded: list[str] = []
            for token in calls[:MAX_FINDING_VALUE_CHARS]:
                try:
                    value = int(token[2:], 16) if token.lower().startswith("&h") else int(token)
                    if value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                        decoded = []
                        break
                    decoded.append(chr(value))
                except ValueError:
                    decoded = []
                    break
            reconstructed = "".join(decoded)
            hits = scan_text(reconstructed, collector.pattern)
            if hits:
                collector.add(
                    "macro_string", "vba-chr-sequence", member, reconstructed,
                    "confirmed", evidence=("passive Chr/ChrW reconstruction",),
                    flags=hits,
                )
        if literals_seen >= MAX_MACRO_LITERALS:
            collector.limits.add("macro-literal-count")
            break


def _merge_nested(
    nested: DocumentAnalysis,
    parent_member: str,
    collector: _FindingCollector,
) -> None:
    for finding in nested.findings:
        collector.add(
            finding.category,
            f"embedded-document>{finding.mechanism}",
            f"{parent_member}>{finding.source_member}",
            finding.value,
            finding.confidence,
            evidence=("recursive local document analysis", *finding.evidence),
            decoder_chain=finding.decoder_chain,
            flags=finding.flags_found,
            related_artifact=parent_member,
        )


def _merge_nested_artifacts(
    nested: DocumentAnalysis,
    parent_member: str,
    extracted: list[ExtractedDocumentArtifact],
) -> None:
    """Propagate nested artifacts once while retaining their member chain."""
    existing = {
        (artifact.path, artifact.sha256)
        for artifact in extracted
    }
    for artifact in nested.extracted_artifacts:
        identity = (artifact.path, artifact.sha256)
        if identity in existing:
            continue
        existing.add(identity)
        extracted.append(ExtractedDocumentArtifact(
            source_member=f"{parent_member}>{artifact.source_member}",
            path=artifact.path,
            kind=artifact.kind,
            size=artifact.size,
            sha256=artifact.sha256,
            depth=artifact.depth,
        ))


def _scan_generic_embedded_zip(
    path: Path,
    parent_member: str,
    collector: _FindingCollector,
) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            members = validate_zip_members(archive)
            for info in members[:MAX_EMBEDDED_OBJECTS]:
                if info.is_dir() or info.file_size > MAX_STATIC_STRINGS_BYTES:
                    continue
                data = archive.read(info)
                text = data.decode("latin-1", errors="replace")
                hits = scan_text(text, collector.pattern)
                if hits:
                    collector.add(
                        "embedded_object", "embedded-zip-member",
                        f"{parent_member}>{info.filename}", text, "confirmed",
                        evidence=("bounded ZIP member inspection",), flags=hits,
                        related_artifact=parent_member,
                    )
    except Exception:
        collector.add(
            "suspicious_package", "invalid-embedded-zip", parent_member,
            "Embedded ZIP could not be safely inspected", "medium",
            related_artifact=parent_member,
        )


def _package_digest(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while True:
            chunk = source.read(COPY_CHUNK_BYTES)
            if not chunk:
                return digest.hexdigest()
            total += len(chunk)
            if total > MAX_PACKAGE_BYTES:
                raise UnsafeOpenXML("document package size exceeds safety limit")
            digest.update(chunk)


def _prepare_extraction_root(
    workspace: Path,
    package_path: Path,
    depth: int,
    package_index: int,
) -> Path:
    if workspace.is_symlink():
        raise UnsafeOpenXML("document workspace must not be a symlink")
    workspace.mkdir(parents=True, exist_ok=True)
    parent = workspace / "document_extracted"
    if parent.exists():
        if parent.is_symlink() or not parent.is_dir():
            raise UnsafeOpenXML("document extraction root is unsafe")
    else:
        parent.mkdir(mode=0o700)
    if parent.resolve().parent != workspace.resolve():
        raise UnsafeOpenXML("document extraction root escaped workspace")
    digest = _package_digest(package_path)[:16]
    root = parent / f"package-{package_index:03d}-depth-{depth}-{digest}"
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise UnsafeOpenXML("document package extraction root is unsafe")
    else:
        root.mkdir(mode=0o700)
    if root.resolve().parent != parent.resolve():
        raise UnsafeOpenXML("document package extraction root escaped workspace")
    return root


def _extract_artifacts(
    package: OpenXMLPackage,
    workspace: Path,
    document_type: DocumentType,
    referenced: set[str],
    collector: _FindingCollector,
    errors: list[str],
    budget: _Budget,
    depth: int,
    package_index: int,
) -> tuple[list[ExtractedDocumentArtifact], Path | None]:
    artifact_prefixes = {
        DocumentType.DOCX: ("word/media/", "word/embeddings/"),
        DocumentType.DOCM: ("word/media/", "word/embeddings/"),
        DocumentType.XLSX: ("xl/media/", "xl/embeddings/"),
        DocumentType.XLSM: ("xl/media/", "xl/embeddings/"),
        DocumentType.PPTX: ("ppt/media/", "ppt/embeddings/"),
        DocumentType.PPTM: ("ppt/media/", "ppt/embeddings/"),
        DocumentType.ODT: ("Pictures/", "ObjectReplacements/", "Objects/"),
        DocumentType.ODS: ("Pictures/", "ObjectReplacements/", "Objects/"),
        DocumentType.ODP: ("Pictures/", "ObjectReplacements/", "Objects/"),
        DocumentType.OPENDOCUMENT_GENERIC: (
            "Pictures/", "ObjectReplacements/", "Objects/",
        ),
    }.get(document_type, ())
    candidates = [
        name for name in sorted(package.by_name)
        if any(name.startswith(prefix) for prefix in artifact_prefixes)
        and not package.by_name[name].is_dir()
    ]
    macro_member = {
        DocumentType.DOCM: "word/vbaProject.bin",
        DocumentType.XLSM: "xl/vbaProject.bin",
        DocumentType.PPTM: "ppt/vbaProject.bin",
    }.get(document_type)
    if macro_member and macro_member in package.by_name:
        candidates.append(macro_member)
    if not candidates:
        return [], None
    root = _prepare_extraction_root(workspace, package.path, depth, package_index)
    extracted: list[ExtractedDocumentArtifact] = []
    media_count = 0
    object_count = 0
    for member in dict.fromkeys(candidates):
        is_media = "/media/" in member or member.startswith(("Pictures/", "Thumbnails/"))
        if is_media:
            media_count += 1
            if media_count > MAX_MEDIA_OBJECTS:
                collector.limits.add("media-count")
                continue
        else:
            object_count += 1
            if object_count > MAX_EMBEDDED_OBJECTS:
                collector.limits.add("embedded-object-count")
                continue
        info = package.by_name[member]
        if budget.object_count >= MAX_RECURSIVE_OBJECTS:
            collector.limits.add("recursive-object-count")
            break
        if budget.bytes_written + info.file_size > MAX_RECURSIVE_EXTRACTED_BYTES:
            collector.limits.add("recursive-extracted-bytes")
            break
        try:
            data = package.read(member, limit=MAX_EXTRACTED_ARTIFACT_BYTES)
        except UnsafeOpenXML as exc:
            errors.append(str(exc))
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in budget.digests:
            collector.add(
                "orphan_content", "duplicate-embedded-content", member,
                f"Duplicate content SHA-256 {digest}", "low",
            )
            continue
        budget.digests.add(digest)
        budget.object_count += 1
        budget.bytes_written += len(data)
        try:
            path = package.extract(member, root)
        except (OSError, UnsafeOpenXML) as exc:
            errors.append(f"artifact extraction failed: {member}: {exc}")
            continue
        kind = _magic_kind(data[:MAX_STATIC_STRINGS_BYTES])
        artifact = ExtractedDocumentArtifact(
            safe_document_value(member, 1024), path, kind, len(data), digest, depth,
        )
        extracted.append(artifact)
        _scan_embedded_content(data, member, kind, collector, str(path))
        if member.endswith("vbaProject.bin"):
            _scan_vba_static(data, member, collector)
        if member not in referenced and (
            is_media or "/embeddings/" in member
            or member.startswith(("ObjectReplacements/", "Objects/"))
        ):
            collector.add(
                "orphan_content", "unreferenced-media" if is_media else "unreferenced-object",
                member, f"Unreferenced {kind} object ({len(data)} bytes)", "medium",
                evidence=("not targeted by an internal relationship",),
                related_artifact=str(path),
            )
        if kind == "ZIP" and depth < MAX_RECURSION_DEPTH:
            nested_type = detect_document_type(path)
            if nested_type not in {
                DocumentType.NOT_DOCUMENT, DocumentType.INVALID_DOCUMENT,
                DocumentType.OLE_DOCUMENT, DocumentType.RTF,
            }:
                nested = analyze_document(
                    path, collector.pattern, workspace=workspace,
                    depth=depth + 1, budget=budget,
                )
                _merge_nested(nested, member, collector)
                _merge_nested_artifacts(nested, member, extracted)
            else:
                _scan_generic_embedded_zip(path, member, collector)
        elif kind == "TEXT" and data.lstrip().lower().startswith(b"{\\rtf"):
            if depth < MAX_RECURSION_DEPTH:
                nested = analyze_document(
                    path, collector.pattern, workspace=workspace,
                    depth=depth + 1, budget=budget,
                )
                _merge_nested(nested, member, collector)
                _merge_nested_artifacts(nested, member, extracted)
            else:
                collector.limits.add("recursion-depth")
        elif kind == "ZIP":
            collector.limits.add("recursion-depth")
    if not extracted:
        try:
            root.rmdir()
        except OSError:
            pass
        return [], None
    return extracted, root.parent


def _xml_members(package: OpenXMLPackage) -> list[str]:
    selected: list[str] = []
    for name in sorted(package.by_name):
        if not name.endswith(".xml"):
            continue
        if (
            name == "word/document.xml"
            or re.fullmatch(r"word/(?:header|footer)\d*\.xml", name)
            or name in {
                "word/footnotes.xml", "word/endnotes.xml", "word/comments.xml",
                "word/settings.xml", "word/numbering.xml",
                "word/glossary/document.xml", "docProps/core.xml",
                "docProps/app.xml", "docProps/custom.xml",
            }
            or name.startswith("customXml/")
        ):
            selected.append(name)
    return selected


def _suspicious_extra_members(
    package: OpenXMLPackage,
    collector: _FindingCollector,
) -> None:
    for name in sorted(package.by_name):
        top = name.split("/", 1)[0]
        if top in _NORMAL_TOP_LEVEL or name == "[Content_Types].xml":
            continue
        info = package.by_name[name]
        if info.is_dir():
            continue
        suffix = PurePosixPath(name).suffix.lower()
        if suffix in {".exe", ".dll", ".js", ".vbs", ".ps1", ".sh", ".bat"}:
            collector.add(
                "suspicious_package", "unusual-executable-member", name,
                f"Executable-like extra package member ({info.file_size} bytes)",
                "high", evidence=("member was not executed",),
            )


PackageAnalyzer = Callable[[OpenXMLPackage, _FindingCollector, list[str]], None]


def _analyze_package_document(
    path: Path,
    flag_pattern: re.Pattern,
    *,
    workspace: Path,
    document_type: DocumentType,
    analyzer: PackageAnalyzer,
    depth: int,
    budget: _Budget | None,
) -> DocumentAnalysis:
    """Run shared safe ZIP, relationship, extraction, and recursion handling."""
    if depth > MAX_RECURSION_DEPTH:
        return DocumentAnalysis(
            document_type.value, (), (), (), ("recursion-depth",), 0, 0,
        )
    active_budget = budget if budget is not None else _Budget()
    package_index = active_budget.package_count
    active_budget.package_count += 1
    collector = _FindingCollector(flag_pattern)
    errors: list[str] = []
    extracted: list[ExtractedDocumentArtifact] = []
    extracted_dir: Path | None = None
    package_members = 0
    expanded_bytes = 0
    try:
        with OpenXMLPackage(path) as package:
            package_members = len(package.members)
            expanded_bytes = sum(member.file_size for member in package.members)
            referenced = _analyze_relationships(package, collector, errors)
            if document_type in {
                DocumentType.ODT,
                DocumentType.ODS,
                DocumentType.ODP,
                DocumentType.OPENDOCUMENT_GENERIC,
            }:
                referenced.update(
                    _analyze_odf_references(package, collector, errors)
                )
            analyzer(package, collector, errors)
            _suspicious_extra_members(package, collector)
            extracted, extracted_dir = _extract_artifacts(
                package, workspace, document_type, referenced, collector,
                errors, active_budget, depth, package_index,
            )
            macro_member = {
                DocumentType.XLSM: "xl/vbaProject.bin",
                DocumentType.PPTM: "ppt/vbaProject.bin",
            }.get(document_type)
            if macro_member and macro_member in package.by_name:
                collector.add(
                    "macro_string", "vba-project-presence", macro_member,
                    f"{document_type.value} contains a VBA project; static analysis "
                    "is optional and no macro was executed.",
                    "medium",
                )
    except Exception as exc:
        errors.append(f"Document package analysis failed safely: {exc}")
    return DocumentAnalysis(
        document_type=document_type.value,
        findings=collector.finish(),
        extracted_artifacts=tuple(extracted),
        errors=tuple(safe_document_value(error, 1024) for error in errors),
        limits_reached=tuple(sorted(collector.limits)),
        package_members=package_members,
        expanded_bytes=expanded_bytes,
        extracted_dir=extracted_dir,
    )


def analyze_document(
    path: Path,
    flag_pattern: re.Pattern,
    *,
    workspace: Path,
    depth: int = 0,
    budget: _Budget | None = None,
) -> DocumentAnalysis:
    """Dispatch one content-detected document under central safety budgets."""
    document_type = detect_document_type(path)
    if document_type in {DocumentType.XLSX, DocumentType.XLSM}:
        from dayi.document.spreadsheet import analyze_spreadsheet
        return analyze_spreadsheet(
            path, flag_pattern, workspace=workspace, document_type=document_type,
            depth=depth, budget=budget,
        )
    if document_type in {DocumentType.PPTX, DocumentType.PPTM}:
        from dayi.document.presentation import analyze_presentation
        return analyze_presentation(
            path, flag_pattern, workspace=workspace, document_type=document_type,
            depth=depth, budget=budget,
        )
    if document_type in {
        DocumentType.ODT, DocumentType.ODS, DocumentType.ODP,
        DocumentType.OPENDOCUMENT_GENERIC,
    }:
        from dayi.document.opendocument import analyze_opendocument
        return analyze_opendocument(
            path, flag_pattern, workspace=workspace, document_type=document_type,
            depth=depth, budget=budget,
        )
    if document_type == DocumentType.RTF:
        from dayi.document.rtf import analyze_rtf_document
        return analyze_rtf_document(
            path, flag_pattern, workspace=workspace, depth=depth, budget=budget,
        )
    if document_type not in {
        DocumentType.DOCX, DocumentType.DOCM, DocumentType.OPENXML_GENERIC,
    }:
        return DocumentAnalysis(document_type.value, (), (), (), (), 0, 0)
    if depth > MAX_RECURSION_DEPTH:
        return DocumentAnalysis(
            document_type.value, (), (), (), ("recursion-depth",), 0, 0,
        )
    active_budget = budget if budget is not None else _Budget()
    package_index = active_budget.package_count
    active_budget.package_count += 1
    collector = _FindingCollector(flag_pattern)
    errors: list[str] = []
    extracted: list[ExtractedDocumentArtifact] = []
    extracted_dir: Path | None = None
    package_members = 0
    expanded_bytes = 0
    try:
        with OpenXMLPackage(path) as package:
            package_members = len(package.members)
            expanded_bytes = sum(member.file_size for member in package.members)
            styles_root = None
            if "word/styles.xml" in package.by_name:
                try:
                    styles_root = package.xml("word/styles.xml")
                except UnsafeOpenXML as exc:
                    errors.append(str(exc))
            styles = _Styles(styles_root)
            referenced = _analyze_relationships(package, collector, errors)
            parsed_roots: dict[str, ElementTree.Element] = {}
            for member in _xml_members(package):
                try:
                    root = package.xml(member)
                except UnsafeOpenXML as exc:
                    errors.append(str(exc))
                    continue
                parsed_roots[member] = root
                _analyze_xml_member(root, member, styles, collector)
            document_root = parsed_roots.get("word/document.xml")
            comments_root = parsed_roots.get("word/comments.xml")
            if document_root is not None and comments_root is not None:
                anchored = {
                    _attr(element, "id")
                    for element in document_root.iter()
                    if _local(element.tag) in {"commentRangeStart", "commentReference"}
                }
                for comment in comments_root:
                    comment_id = _attr(comment, "id")
                    if comment_id not in anchored:
                        text = _element_text(comment)
                        if text:
                            collector.add(
                                "orphan_content", "unanchored-comment",
                                "word/comments.xml", text, "medium",
                                evidence=(f"comment id {comment_id or 'unknown'} has no anchor",),
                            )
            _suspicious_extra_members(package, collector)
            extracted, extracted_dir = _extract_artifacts(
                package, workspace, document_type, referenced, collector,
                errors, active_budget, depth, package_index,
            )
            if document_type == DocumentType.DOCM:
                collector.add(
                    "macro_string", "vba-project-presence", "word/vbaProject.bin",
                    "DOCM contains a VBA project; static macro analysis is delegated "
                    "to the optional oletools scanner and no macro was executed.",
                    "medium",
                )
    except Exception as exc:
        errors.append(f"OpenXML analysis failed safely: {exc}")
    return DocumentAnalysis(
        document_type=document_type.value,
        findings=collector.finish(),
        extracted_artifacts=tuple(extracted),
        errors=tuple(safe_document_value(error, 1024) for error in errors),
        limits_reached=tuple(sorted(collector.limits)),
        package_members=package_members,
        expanded_bytes=expanded_bytes,
        extracted_dir=extracted_dir,
    )
