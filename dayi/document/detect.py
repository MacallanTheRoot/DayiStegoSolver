"""Content-based document type detection with bounded ZIP inspection."""
from __future__ import annotations

import re
import stat
import zipfile
from enum import Enum
from pathlib import Path, PurePosixPath

from dayi.document.limits import (
    MAX_COMPRESSION_RATIO,
    MAX_MEMBER_BYTES,
    MAX_PACKAGE_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    MAX_XML_MEMBER_BYTES,
    MAX_ZIP_MEMBERS,
)

OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
RTF_MAGIC = b"{\\rtf"
DOCX_MAIN_TYPE = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document."
    "main+xml"
)
DOCM_MAIN_TYPE = "application/vnd.ms-word.document.macroenabled.main+xml"
XLSX_MAIN_TYPE = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
)
XLSM_MAIN_TYPE = "application/vnd.ms-excel.sheet.macroenabled.main+xml"
PPTX_MAIN_TYPE = (
    "application/vnd.openxmlformats-officedocument.presentationml.presentation."
    "main+xml"
)
PPTM_MAIN_TYPE = "application/vnd.ms-powerpoint.presentation.macroenabled.main+xml"
ODF_TYPES = {
    "application/vnd.oasis.opendocument.text": "ODT",
    "application/vnd.oasis.opendocument.spreadsheet": "ODS",
    "application/vnd.oasis.opendocument.presentation": "ODP",
}


class DocumentType(str, Enum):
    DOCX = "DOCX"
    DOCM = "DOCM"
    XLSX = "XLSX"
    XLSM = "XLSM"
    PPTX = "PPTX"
    PPTM = "PPTM"
    ODT = "ODT"
    ODS = "ODS"
    ODP = "ODP"
    OPENXML_GENERIC = "OPENXML_GENERIC"
    OPENDOCUMENT_GENERIC = "OPENDOCUMENT_GENERIC"
    OLE_DOCUMENT = "OLE_DOCUMENT"
    RTF = "RTF"
    NOT_DOCUMENT = "NOT_DOCUMENT"
    INVALID_DOCUMENT = "INVALID_DOCUMENT"


class UnsafeOpenXML(ValueError):
    """Raised for malformed or unsafe package metadata."""


def safe_member_name(filename: str) -> PurePosixPath:
    """Reject absolute, traversal, platform, and ambiguous ZIP names."""
    if not filename or "\x00" in filename or "\\" in filename:
        raise UnsafeOpenXML("unsafe member name")
    path = PurePosixPath(filename)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or re.match(r"^[A-Za-z]:", path.parts[0]) is not None
    ):
        raise UnsafeOpenXML("unsafe member path")
    return path


def validate_zip_members(archive: zipfile.ZipFile) -> tuple[zipfile.ZipInfo, ...]:
    """Validate central-directory metadata before reading a package member."""
    members = archive.infolist()
    if len(members) > MAX_ZIP_MEMBERS:
        raise UnsafeOpenXML("OpenXML member count limit exceeded")
    total = 0
    seen: set[str] = set()
    for member in members:
        path = safe_member_name(member.filename)
        identity = path.as_posix().casefold()
        if identity in seen:
            raise UnsafeOpenXML("duplicate or colliding member path")
        seen.add(identity)
        mode = (member.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise UnsafeOpenXML("symbolic-link member rejected")
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise UnsafeOpenXML("special-file member rejected")
        if member.flag_bits & 0x1:
            raise UnsafeOpenXML("encrypted OpenXML member rejected")
        if member.compress_type not in {
            zipfile.ZIP_STORED,
            zipfile.ZIP_DEFLATED,
            zipfile.ZIP_BZIP2,
            zipfile.ZIP_LZMA,
        }:
            raise UnsafeOpenXML("unsupported member compression rejected")
        if member.file_size > MAX_MEMBER_BYTES:
            raise UnsafeOpenXML("single-member size limit exceeded")
        total += member.file_size
        if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise UnsafeOpenXML("expanded package size limit exceeded")
        if member.file_size:
            if member.compress_size <= 0:
                raise UnsafeOpenXML("invalid compressed member size")
            if member.file_size / member.compress_size > MAX_COMPRESSION_RATIO:
                raise UnsafeOpenXML("unsafe compression ratio")
    return tuple(members)


def _read_content_types(archive: zipfile.ZipFile) -> str | None:
    try:
        info = archive.getinfo("[Content_Types].xml")
    except KeyError:
        return None
    if info.file_size > MAX_XML_MEMBER_BYTES:
        raise UnsafeOpenXML("content-types XML limit exceeded")
    data = archive.read(info)
    if len(data) > MAX_XML_MEMBER_BYTES:
        raise UnsafeOpenXML("content-types XML exceeded declared limit")
    return data.decode("utf-8", errors="replace").lower()


def _read_odf_mimetype(archive: zipfile.ZipFile) -> str | None:
    try:
        info = archive.getinfo("mimetype")
    except KeyError:
        return None
    if info.file_size > 512:
        raise UnsafeOpenXML("OpenDocument mimetype limit exceeded")
    return archive.read(info).decode("ascii", errors="replace").strip().lower()


def detect_document_type(path: Path) -> DocumentType:
    """Classify a local document from bytes and package declarations."""
    if path.is_symlink() or not path.is_file():
        return DocumentType.NOT_DOCUMENT
    try:
        size = path.stat().st_size
        with path.open("rb") as source:
            header = source.read(16)
    except OSError:
        return DocumentType.INVALID_DOCUMENT
    if size <= 0:
        return DocumentType.NOT_DOCUMENT
    if header.startswith(OLE_MAGIC):
        return DocumentType.OLE_DOCUMENT
    if header.lstrip().lower().startswith(RTF_MAGIC):
        return DocumentType.RTF
    if not header.startswith(ZIP_MAGICS):
        return DocumentType.NOT_DOCUMENT
    if size > MAX_PACKAGE_BYTES:
        return DocumentType.INVALID_DOCUMENT
    try:
        with zipfile.ZipFile(path) as archive:
            members = validate_zip_members(archive)
            names = {member.filename for member in members}
            content_types = _read_content_types(archive)
            odf_mimetype = _read_odf_mimetype(archive)
    except Exception:
        return DocumentType.INVALID_DOCUMENT
    if odf_mimetype:
        mapped = ODF_TYPES.get(odf_mimetype)
        if mapped is not None:
            return DocumentType(mapped)
        if odf_mimetype.startswith("application/vnd.oasis.opendocument."):
            return DocumentType.OPENDOCUMENT_GENERIC
        return DocumentType.INVALID_DOCUMENT
    if content_types is None or "_rels/.rels" not in names:
        return DocumentType.NOT_DOCUMENT
    if DOCM_MAIN_TYPE in content_types or "word/vbaProject.bin" in names:
        return DocumentType.DOCM
    if DOCX_MAIN_TYPE in content_types and "word/document.xml" in names:
        return DocumentType.DOCX
    if XLSM_MAIN_TYPE in content_types or "xl/vbaProject.bin" in names:
        return DocumentType.XLSM
    if XLSX_MAIN_TYPE in content_types and "xl/workbook.xml" in names:
        return DocumentType.XLSX
    if PPTM_MAIN_TYPE in content_types or "ppt/vbaProject.bin" in names:
        return DocumentType.PPTM
    if PPTX_MAIN_TYPE in content_types and "ppt/presentation.xml" in names:
        return DocumentType.PPTX
    return DocumentType.OPENXML_GENERIC
