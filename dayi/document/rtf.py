"""Small bounded state-machine parser for defensive RTF analysis."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import Path

from dayi.document.limits import (
    MAX_RECURSION_DEPTH,
    MAX_RECURSIVE_EXTRACTED_BYTES,
    MAX_RECURSIVE_OBJECTS,
    MAX_RTF_BINARY_BYTES,
    MAX_RTF_BYTES,
    MAX_RTF_CONTROL_WORDS,
    MAX_RTF_GROUP_DEPTH,
    MAX_RTF_GROUPS,
    MAX_RTF_OBJECTS,
    MAX_RTF_PICTURES,
    MAX_RTF_TEXT_CHARS,
)
from dayi.document.model import DocumentAnalysis, ExtractedDocumentArtifact, safe_document_value
from dayi.document.detect import DocumentType, detect_document_type
from dayi.document.openxml import (
    _Budget,
    _FindingCollector,
    _magic_kind,
    _merge_nested,
    _merge_nested_artifacts,
    _scan_embedded_content,
    analyze_document,
)
from dayi.scanner import scan_text


class UnsafeRTF(ValueError):
    """Raised when bounded RTF syntax or resource limits are violated."""


@dataclass
class _State:
    hidden: bool = False
    destination: str = "visible"
    font_size: int = 24
    foreground: int = 0
    background: int = -1
    skip: bool = False
    binary: bytearray | None = None
    code_page: str = "cp1252"
    unicode_skip: int = 1


_DESTINATIONS = {
    "annotation": "annotation",
    "atnauthor": "annotation",
    "atndate": "annotation",
    "fldinst": "field-code",
    "info": "metadata",
    "title": "metadata",
    "subject": "metadata",
    "author": "metadata",
    "keywords": "metadata",
    "comment": "metadata",
    "pict": "picture",
    "objdata": "object",
    "object": "object",
}
_IGNORED_DESTINATIONS = {
    "colortbl", "fonttbl", "stylesheet", "generator", "listtable",
    "listoverridetable", "datastore", "themedata",
}
_FALLBACK_CHARACTER_WORDS = {
    "bullet", "emdash", "emspace", "endash", "enspace", "ldblquote",
    "line", "lquote", "rdblquote", "rquote", "tab",
}


def _white_color_indexes(data: bytes) -> set[int]:
    text = data[: min(len(data), 256 * 1024)].decode("latin-1", errors="ignore")
    match = re.search(r"\\colortbl\s*;?([^}]*)", text)
    if not match:
        return set()
    colors = match.group(1).split(";")
    return {
        index + 1 for index, color in enumerate(colors)
        if "\\red255" in color and "\\green255" in color and "\\blue255" in color
    }


def _safe_root(workspace: Path, depth: int) -> Path:
    if workspace.is_symlink():
        raise UnsafeRTF("RTF workspace symlink rejected")
    workspace.mkdir(parents=True, exist_ok=True)
    parent = workspace / "document_extracted"
    parent.mkdir(mode=0o700, exist_ok=True)
    root = parent / f"rtf-{depth}"
    root.mkdir(mode=0o700, exist_ok=True)
    if not root.resolve().is_relative_to(workspace.resolve()):
        raise UnsafeRTF("RTF extraction root escaped workspace")
    return root


def _decode_hex_payload(raw: bytearray) -> bytes:
    compact = bytes(character for character in raw if chr(character).lower() in "0123456789abcdef")
    if len(compact) % 2:
        compact = compact[:-1]
    if len(compact) // 2 > MAX_RTF_BINARY_BYTES:
        raise UnsafeRTF("RTF binary payload limit exceeded")
    try:
        return bytes.fromhex(compact.decode("ascii"))
    except ValueError as exc:
        raise UnsafeRTF("malformed RTF hex payload") from exc


def _decode_character(value: int, code_page: str) -> str:
    try:
        return bytes([value]).decode(code_page, errors="replace")
    except LookupError:
        return bytes([value]).decode("cp1252", errors="replace")


def _normalize_rtf_surrogates(value: str) -> str:
    """Combine UTF-16 surrogate pairs and replace isolated code units."""
    normalized: list[str] = []
    index = 0
    while index < len(value):
        code_unit = ord(value[index])
        if 0xD800 <= code_unit <= 0xDBFF:
            if index + 1 < len(value):
                low = ord(value[index + 1])
                if 0xDC00 <= low <= 0xDFFF:
                    normalized.append(chr(
                        0x10000
                        + ((code_unit - 0xD800) << 10)
                        + (low - 0xDC00)
                    ))
                    index += 2
                    continue
            normalized.append("\ufffd")
        elif 0xDC00 <= code_unit <= 0xDFFF:
            normalized.append("\ufffd")
        else:
            normalized.append(value[index])
        index += 1
    return "".join(normalized)


def _consume_rtf_fallback_token(data: bytes, offset: int) -> int:
    """Return the offset after one complete Unicode fallback character."""
    if offset >= len(data):
        return offset
    first = data[offset]
    if first != 0x5C:
        if first in b"{}":
            return offset
        return offset + 1
    if offset + 1 >= len(data):
        return offset
    symbol = data[offset + 1]
    if symbol == 0x27:
        if offset + 3 >= len(data):
            raise UnsafeRTF("malformed RTF Unicode hexadecimal fallback")
        try:
            int(data[offset + 2:offset + 4].decode("ascii"), 16)
        except ValueError as exc:
            raise UnsafeRTF("malformed RTF Unicode hexadecimal fallback") from exc
        return offset + 4
    if symbol in b"{}\\~-_":
        return offset + 2
    if not chr(symbol).isalpha():
        return offset

    cursor = offset + 1
    while cursor < len(data) and chr(data[cursor]).isalpha():
        cursor += 1
    word = data[offset + 1:cursor].decode("ascii", errors="ignore").lower()
    if cursor < len(data) and data[cursor] == 0x2D:
        cursor += 1
    while cursor < len(data) and chr(data[cursor]).isdigit():
        cursor += 1
    if cursor < len(data) and data[cursor] == 0x20:
        cursor += 1
    return cursor if word in _FALLBACK_CHARACTER_WORDS else offset


def analyze_rtf_document(
    path: Path,
    flag_pattern: re.Pattern,
    *,
    workspace: Path,
    depth: int = 0,
    budget: _Budget | None = None,
) -> DocumentAnalysis:
    collector = _FindingCollector(flag_pattern)
    errors: list[str] = []
    extracted: list[ExtractedDocumentArtifact] = []
    extracted_dir: Path | None = None
    active_budget = budget if budget is not None else _Budget()
    if depth > MAX_RECURSION_DEPTH:
        return DocumentAnalysis(
            "RTF", (), (), (), ("recursion-depth",), 0, 0,
        )
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RTF_BYTES:
            raise UnsafeRTF("RTF file size or type limit rejected")
        data = path.read_bytes()
        if not data.lstrip().lower().startswith(b"{\\rtf"):
            raise UnsafeRTF("invalid RTF signature")
        white_indexes = _white_color_indexes(data)
        stack: list[_State] = []
        state = _State()
        chunks: dict[tuple[str, str], list[str]] = {}
        text_count = 0
        group_count = 0
        control_count = 0
        picture_count = 0
        object_count = 0
        binary_total = 0

        def append_text(value: str) -> None:
            nonlocal text_count
            if not value or state.skip:
                return
            text_count += len(value)
            if text_count > MAX_RTF_TEXT_CHARS:
                raise UnsafeRTF("RTF decoded text limit exceeded")
            mechanism = state.destination
            if state.hidden:
                mechanism = "hidden-text"
            elif state.foreground in white_indexes:
                mechanism = "white-text"
            elif state.background >= 0 and state.foreground == state.background:
                mechanism = "matching-color"
            elif state.font_size <= 4:
                mechanism = "tiny-text"
            category = "visible_text" if mechanism == "visible" else "rtf"
            chunks.setdefault((category, mechanism), []).append(value)

        i = 0
        while i < len(data):
            byte = data[i]
            if byte == 0x7B:
                group_count += 1
                if group_count > MAX_RTF_GROUPS or len(stack) >= MAX_RTF_GROUP_DEPTH:
                    raise UnsafeRTF("RTF group limit exceeded")
                stack.append(state)
                state = replace(state, binary=None)
                i += 1
                continue
            if byte == 0x7D:
                if not stack:
                    raise UnsafeRTF("malformed RTF group closure")
                if state.binary is not None:
                    payload = _decode_hex_payload(state.binary)
                    binary_total += len(payload)
                    if binary_total > MAX_RTF_BINARY_BYTES:
                        raise UnsafeRTF("RTF aggregate binary limit exceeded")
                    is_picture = state.destination == "picture"
                    picture_count += int(is_picture)
                    object_count += int(not is_picture)
                    if picture_count > MAX_RTF_PICTURES or object_count > MAX_RTF_OBJECTS:
                        raise UnsafeRTF("RTF picture/object count limit exceeded")
                    digest = hashlib.sha256(payload).hexdigest()
                    if payload and digest not in active_budget.digests:
                        if active_budget.object_count >= MAX_RECURSIVE_OBJECTS:
                            collector.limits.add("recursive-object-count")
                            state = stack.pop()
                            i += 1
                            continue
                        if (
                            active_budget.bytes_written + len(payload)
                            > MAX_RECURSIVE_EXTRACTED_BYTES
                        ):
                            collector.limits.add("recursive-extracted-bytes")
                            state = stack.pop()
                            i += 1
                            continue
                        active_budget.digests.add(digest)
                        active_budget.object_count += 1
                        active_budget.bytes_written += len(payload)
                        root = _safe_root(workspace, depth)
                        suffix = picture_count if is_picture else object_count
                        destination = root / (
                            f"{'pict' if is_picture else 'object'}-{suffix}-"
                            f"{digest[:12]}.bin"
                        )
                        try:
                            with destination.open("xb") as output:
                                output.write(payload)
                        except BaseException:
                            destination.unlink(missing_ok=True)
                            raise
                        kind = _magic_kind(payload)
                        source = f"{'pict' if is_picture else 'object'}-{suffix}"
                        extracted.append(ExtractedDocumentArtifact(source, destination, kind, len(payload), digest, depth))
                        _scan_embedded_content(payload, source, kind, collector, str(destination))
                        nested_type = detect_document_type(destination)
                        if nested_type not in {
                            DocumentType.NOT_DOCUMENT,
                            DocumentType.INVALID_DOCUMENT,
                            DocumentType.OLE_DOCUMENT,
                        }:
                            if depth < MAX_RECURSION_DEPTH:
                                nested = analyze_document(
                                    destination,
                                    flag_pattern,
                                    workspace=workspace,
                                    depth=depth + 1,
                                    budget=active_budget,
                                )
                                _merge_nested(nested, source, collector)
                                _merge_nested_artifacts(
                                    nested, source, extracted
                                )
                            else:
                                collector.limits.add("recursion-depth")
                        extracted_dir = root.parent
                state = stack.pop()
                i += 1
                continue
            if byte != 0x5C:
                if state.binary is not None:
                    state.binary.append(byte)
                elif byte not in b"\r\n":
                    append_text(_decode_character(byte, state.code_page))
                i += 1
                continue

            i += 1
            if i >= len(data):
                break
            symbol = data[i]
            if symbol in b"{}\\":
                append_text(chr(symbol))
                i += 1
                continue
            if symbol == 0x27 and i + 2 < len(data):
                try:
                    append_text(_decode_character(
                        int(data[i + 1:i + 3].decode("ascii"), 16),
                        state.code_page,
                    ))
                except ValueError:
                    raise UnsafeRTF("malformed RTF hexadecimal escape")
                i += 3
                continue
            if symbol == 0x2A:
                state.skip = True
                i += 1
                continue
            start = i
            while i < len(data) and chr(data[i]).isalpha():
                i += 1
            word = data[start:i].decode("ascii", errors="ignore").lower()
            sign = 1
            if i < len(data) and data[i] == 0x2D:
                sign = -1
                i += 1
            number_start = i
            while i < len(data) and chr(data[i]).isdigit():
                i += 1
            number = sign * int(data[number_start:i] or b"0")
            has_number = i > number_start
            if i < len(data) and data[i] == 0x20:
                i += 1
            control_count += 1
            if control_count > MAX_RTF_CONTROL_WORDS:
                raise UnsafeRTF("RTF control-word limit exceeded")
            if word in _DESTINATIONS:
                state.destination = _DESTINATIONS[word]
                state.skip = False
                if state.destination in {"picture", "object"}:
                    state.binary = bytearray()
            elif word in _IGNORED_DESTINATIONS:
                state.skip = True
            elif word == "v":
                state.hidden = not has_number or number != 0
            elif word == "fs" and has_number:
                state.font_size = number
            elif word == "cf" and has_number:
                state.foreground = number
            elif word in {"highlight", "cb"} and has_number:
                state.background = number
            elif word == "u" and has_number:
                append_text(chr(number % 65536))
                for _ in range(state.unicode_skip):
                    next_offset = _consume_rtf_fallback_token(data, i)
                    if next_offset <= i:
                        break
                    i = next_offset
            elif word == "uc" and has_number:
                state.unicode_skip = min(max(number, 0), 8)
            elif word == "ansi":
                state.code_page = "cp1252"
            elif word == "mac":
                state.code_page = "mac_roman"
            elif word == "pc":
                state.code_page = "cp437"
            elif word == "pca":
                state.code_page = "cp850"
            elif word == "ansicpg" and has_number:
                state.code_page = {
                    1250: "cp1250", 1251: "cp1251", 1252: "cp1252",
                    1253: "cp1253", 1254: "cp1254", 1255: "cp1255",
                    1256: "cp1256", 1257: "cp1257", 1258: "cp1258",
                }.get(number, "cp1252")
            elif word == "bin" and has_number:
                if number < 0 or number > MAX_RTF_BINARY_BYTES or i + number > len(data):
                    raise UnsafeRTF("RTF binary declaration rejected")
                payload = data[i:i + number]
                if state.binary is None:
                    state.binary = bytearray()
                    state.destination = "object"
                state.binary.extend(payload.hex().encode("ascii"))
                i += number
            elif word in {"par", "line", "tab"}:
                append_text("\n" if word != "tab" else "\t")

        if stack:
            raise UnsafeRTF("malformed RTF nesting")
        for (category, mechanism), values in sorted(chunks.items()):
            text = _normalize_rtf_surrogates("".join(values)).strip()
            if not text:
                continue
            hits = scan_text(text, flag_pattern)
            suspicious = category != "visible_text"
            if hits or suspicious:
                collector.add(
                    category, mechanism, f"rtf:{mechanism}", text,
                    "confirmed" if hits else "high" if mechanism in {"hidden-text", "white-text"} else "medium",
                    flags=hits,
                )
            if not hits:
                collector.text_stego(text, "rtf", f"rtf:{mechanism}")
            collector.add_artifacts(text, f"document/rtf/{mechanism}")
    except UnsafeRTF as exc:
        errors.append(f"RTF analysis failed safely: {safe_document_value(str(exc), 512)}")
    except Exception:
        errors.append("RTF analysis failed safely: internal parser error")
    try:
        expanded_bytes = path.stat().st_size
    except OSError:
        expanded_bytes = 0
    return DocumentAnalysis(
        document_type="RTF", findings=collector.finish(),
        extracted_artifacts=tuple(extracted), errors=tuple(errors),
        limits_reached=tuple(sorted(collector.limits)), package_members=0,
        expanded_bytes=expanded_bytes,
        extracted_dir=extracted_dir,
    )
