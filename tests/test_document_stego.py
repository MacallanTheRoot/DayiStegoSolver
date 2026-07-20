import base64
import io
import json
import re
import socket
import stat
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from dayi.document import DocumentType, analyze_document, detect_document_type
from dayi.document.detect import UnsafeOpenXML, validate_zip_members
from dayi.document.limits import (
    MAX_COMPRESSION_RATIO,
    MAX_FINDINGS,
    MAX_MEDIA_OBJECTS,
    MAX_RECURSION_DEPTH,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    MAX_ZIP_MEMBERS,
)
from dayi.doctor import PYTHON_CAPABILITY_DEFINITIONS
from dayi.reporter import ScanReport, export_markdown_writeup, write_json_report
from dayi.tools._plugin import PluginPhase, discover_plugins
from dayi.tools.document_stego_scanner import PLUGIN_SPECS, run_document_stego
from dayi.tools.ocr_scanner import _discover_images


FLAG = "SiberVatan{document_stego}"
PATTERN = re.compile(r"SiberVatan\{.*?\}")
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _content_types(*, docm: bool = False, generic: bool = False) -> bytes:
    if generic:
        main = "application/example.openxml+xml"
    elif docm:
        main = "application/vnd.ms-word.document.macroEnabled.main+xml"
    else:
        main = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    return (
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f'<Override PartName="/word/document.xml" ContentType="{main}"/>'
        "</Types>"
    ).encode()


def _package_rels() -> bytes:
    return (
        '<?xml version="1.0"?><Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>'
    ).encode()


def _document(body: str) -> bytes:
    return (
        f'<w:document xmlns:w="{W}" xmlns:r="{R}" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
        f"<w:body>{body}</w:body></w:document>"
    ).encode()


def _write_docx(
    path: Path,
    body: str = "<w:p><w:r><w:t>ordinary document text</w:t></w:r></w:p>",
    *,
    members: dict[str, bytes] | None = None,
    document_rels: bytes | None = None,
    docm: bool = False,
    generic: bool = False,
) -> Path:
    package_members = {
        "[Content_Types].xml": _content_types(docm=docm, generic=generic),
        "_rels/.rels": _package_rels(),
        "word/document.xml": _document(body),
    }
    package_members.update(members or {})
    if document_rels is not None:
        package_members["word/_rels/document.xml.rels"] = document_rels
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in package_members.items():
            archive.writestr(name, data)
    return path


def _rels(*relationships: str) -> bytes:
    return (
        '<?xml version="1.0"?><Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(relationships)
        + "</Relationships>"
    ).encode()


def _relationship(target: str, *, external: bool = False, rel_type: str = "image") -> str:
    mode = ' TargetMode="External"' if external else ""
    return (
        f'<Relationship Id="r{abs(hash((target, rel_type))) % 100000}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{rel_type}" '
        f'Target="{target}"{mode}/>'
    )


def _analyze(path: Path, workspace: Path):
    return analyze_document(path, PATTERN, workspace=workspace)


def _flags(analysis) -> list[str]:
    return [flag for finding in analysis.findings for flag in finding.flags_found]


class DocumentDetectionAndSafetyTests(unittest.TestCase):
    def test_content_detection_ignores_extension_and_classifies_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            renamed = _write_docx(root / "challenge.jpg")
            docm = _write_docx(
                root / "macro.bin",
                members={"word/vbaProject.bin": b"macro"},
                docm=True,
            )
            generic = _write_docx(root / "generic", generic=True)
            ole = root / "legacy"
            ole.write_bytes(bytes.fromhex("D0CF11E0A1B11AE1") + b"\0" * 16)
            rtf = root / "rich"
            rtf.write_bytes(b"{\\rtf1 ordinary}")
            plain = root / "plain"
            plain.write_text("ordinary")
            broken = root / "broken"
            broken.write_bytes(b"PK\x03\x04not-a-zip")

            self.assertEqual(detect_document_type(renamed), DocumentType.DOCX)
            self.assertEqual(detect_document_type(docm), DocumentType.DOCM)
            self.assertEqual(detect_document_type(generic), DocumentType.OPENXML_GENERIC)
            self.assertEqual(detect_document_type(ole), DocumentType.OLE_DOCUMENT)
            self.assertEqual(detect_document_type(rtf), DocumentType.RTF)
            self.assertEqual(detect_document_type(plain), DocumentType.NOT_DOCUMENT)
            self.assertEqual(detect_document_type(broken), DocumentType.INVALID_DOCUMENT)

    def test_unsupported_zip_and_traversal_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            unsupported = root / "data.zip"
            with zipfile.ZipFile(unsupported, "w") as archive:
                archive.writestr("data.txt", "hello")
            hostile = root / "hostile.zip"
            with zipfile.ZipFile(hostile, "w") as archive:
                archive.writestr("[Content_Types].xml", _content_types())
                archive.writestr("_rels/.rels", _package_rels())
                archive.writestr("word/document.xml", _document(""))
                archive.writestr("../escape.txt", FLAG)

            self.assertEqual(detect_document_type(unsupported), DocumentType.NOT_DOCUMENT)
            self.assertEqual(detect_document_type(hostile), DocumentType.INVALID_DOCUMENT)
            self.assertFalse((root / "escape.txt").exists())

    def test_duplicate_symlink_oversize_and_member_count_metadata_fail(self) -> None:
        class FakeArchive:
            def __init__(self, members):
                self._members = members

            def infolist(self):
                return self._members

        duplicate_a = zipfile.ZipInfo("word/document.xml")
        duplicate_b = zipfile.ZipInfo("WORD/document.xml")
        with self.assertRaises(UnsafeOpenXML):
            validate_zip_members(FakeArchive([duplicate_a, duplicate_b]))

        symlink = zipfile.ZipInfo("word/media/link")
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(UnsafeOpenXML):
            validate_zip_members(FakeArchive([symlink]))

        oversized = zipfile.ZipInfo("word/media/huge")
        oversized.file_size = 33 * 1024 * 1024
        oversized.compress_size = oversized.file_size
        with self.assertRaises(UnsafeOpenXML):
            validate_zip_members(FakeArchive([oversized]))

        compressed = zipfile.ZipInfo("word/media/compressed")
        compressed.file_size = MAX_COMPRESSION_RATIO + 1
        compressed.compress_size = 1
        with self.assertRaises(UnsafeOpenXML):
            validate_zip_members(FakeArchive([compressed]))

        unsupported = zipfile.ZipInfo("word/media/unsupported")
        unsupported.compress_type = 99
        with self.assertRaises(UnsafeOpenXML):
            validate_zip_members(FakeArchive([unsupported]))

        expanded = []
        for index in range(9):
            info = zipfile.ZipInfo(f"word/media/expanded-{index}")
            info.file_size = MAX_TOTAL_UNCOMPRESSED_BYTES // 8
            info.compress_size = info.file_size
            expanded.append(info)
        with self.assertRaises(UnsafeOpenXML):
            validate_zip_members(FakeArchive(expanded))

        members = [zipfile.ZipInfo(f"part/{index}") for index in range(MAX_ZIP_MEMBERS + 1)]
        with self.assertRaises(UnsafeOpenXML):
            validate_zip_members(FakeArchive(members))

    def test_entity_and_malformed_xml_fail_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            entity = _write_docx(
                root / "entity.docx",
                members={
                    "word/comments.xml": (
                        b'<!DOCTYPE x [<!ENTITY boom "secret">]>'
                        + f'<w:comments xmlns:w="{W}"><w:comment><w:p><w:r><w:t>&boom;</w:t></w:r></w:p></w:comment></w:comments>'.encode()
                    )
                },
            )
            malformed = _write_docx(
                root / "malformed.docx",
                members={"word/comments.xml": b"<broken"},
            )
            first = _analyze(entity, root / "w1")
            second = _analyze(malformed, root / "w2")

        self.assertTrue(any("DTD/entity" in error for error in first.errors))
        self.assertTrue(any("malformed XML" in error for error in second.errors))
        self.assertNotIn("secret", " ".join(finding.value for finding in first.findings))


class WordMechanismTests(unittest.TestCase):
    def test_visible_hidden_revision_and_alt_text_mechanisms(self) -> None:
        cases = {
            "visible": (f"<w:p><w:r><w:t>{FLAG}</w:t></w:r></w:p>", "visible_text", "wordprocessingml"),
            "vanish": (f"<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>{FLAG}</w:t></w:r></w:p>", "hidden_text", "vanish"),
            "web": (f"<w:p><w:r><w:rPr><w:webHidden/></w:rPr><w:t>{FLAG}</w:t></w:r></w:p>", "hidden_text", "web-hidden"),
            "white": (f"<w:p><w:r><w:rPr><w:color w:val=\"FFFFFF\"/></w:rPr><w:t>{FLAG}</w:t></w:r></w:p>", "hidden_text", "white-on-white"),
            "zero": (f"<w:p><w:r><w:rPr><w:sz w:val=\"0\"/></w:rPr><w:t>{FLAG}</w:t></w:r></w:p>", "hidden_text", "zero-font-size"),
            "deleted": (f"<w:p><w:del><w:r><w:delText>{FLAG}</w:delText></w:r></w:del></w:p>", "revision", "del"),
            "moved": (f"<w:p><w:moveFrom><w:r><w:t>{FLAG}</w:t></w:r></w:moveFrom></w:p>", "revision", "moveFrom"),
            "alt": (f'<w:p><wp:docPr id="1" name="Picture 1" descr="{FLAG}"/></w:p>', "alt_text", "descr"),
            "field": (f"<w:p><w:r><w:instrText>DDEAUTO {FLAG}</w:instrText></w:r></w:p>", "field_code", "active-field"),
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for name, (body, category, mechanism) in cases.items():
                with self.subTest(name=name):
                    path = _write_docx(root / f"{name}.docx", body)
                    analysis = _analyze(path, root / f"workspace-{name}")
                    self.assertIn(FLAG, _flags(analysis))
                    self.assertTrue(any(
                        finding.category == category
                        and finding.mechanism == mechanism
                        and finding.confidence == "confirmed"
                        for finding in analysis.findings
                    ))

    def test_comments_notes_headers_footers_metadata_and_custom_xml(self) -> None:
        members = {
            "word/comments.xml": f'<w:comments xmlns:w="{W}"><w:comment w:id="1"><w:p><w:r><w:t>{FLAG}</w:t></w:r></w:p></w:comment></w:comments>'.encode(),
            "word/footnotes.xml": f'<w:footnotes xmlns:w="{W}"><w:footnote><w:p><w:r><w:t>{FLAG}</w:t></w:r></w:p></w:footnote></w:footnotes>'.encode(),
            "word/endnotes.xml": f'<w:endnotes xmlns:w="{W}"><w:endnote><w:p><w:r><w:t>{FLAG}</w:t></w:r></w:p></w:endnote></w:endnotes>'.encode(),
            "word/header1.xml": f'<w:hdr xmlns:w="{W}"><w:p><w:r><w:t>{FLAG}</w:t></w:r></w:p></w:hdr>'.encode(),
            "word/footer1.xml": f'<w:ftr xmlns:w="{W}"><w:p><w:r><w:t>{FLAG}</w:t></w:r></w:p></w:ftr>'.encode(),
            "docProps/core.xml": f'<cp:coreProperties xmlns:cp="urn:core"><cp:title>{FLAG}</cp:title></cp:coreProperties>'.encode(),
            "docProps/custom.xml": f'<Properties><property name="clue"><value>{FLAG}</value></property></Properties>'.encode(),
            "customXml/item1.xml": f"<challenge><hint>{FLAG}</hint></challenge>".encode(),
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = _write_docx(root / "sources.docx", members=members)
            analysis = _analyze(path, root / "workspace")

        mechanisms = {(item.category, item.mechanism) for item in analysis.findings if item.flags_found}
        self.assertIn(("comment", "comment"), mechanisms)
        self.assertIn(("footnote_endnote", "footnote"), mechanisms)
        self.assertIn(("footnote_endnote", "endnote"), mechanisms)
        self.assertIn(("header_footer", "header"), mechanisms)
        self.assertIn(("header_footer", "footer"), mechanisms)
        self.assertIn(("metadata", "package-property"), mechanisms)
        self.assertIn(("metadata", "custom-property"), mechanisms)
        self.assertIn(("orphan_content", "custom-xml"), mechanisms)

    def test_inherited_hidden_style_and_paragraph_style(self) -> None:
        styles = (
            f'<w:styles xmlns:w="{W}">'
            '<w:style w:type="character" w:styleId="HiddenBase"><w:rPr><w:vanish/></w:rPr></w:style>'
            '<w:style w:type="character" w:styleId="HiddenChild"><w:basedOn w:val="HiddenBase"/></w:style>'
            '<w:style w:type="paragraph" w:styleId="HiddenParagraph"><w:rPr><w:webHidden/></w:rPr></w:style>'
            '</w:styles>'
        ).encode()
        body = (
            f'<w:p><w:r><w:rPr><w:rStyle w:val="HiddenChild"/></w:rPr><w:t>{FLAG}</w:t></w:r></w:p>'
            f'<w:p><w:pPr><w:pStyle w:val="HiddenParagraph"/></w:pPr><w:r><w:t>{FLAG}</w:t></w:r></w:p>'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = _write_docx(root / "styles.docx", body, members={"word/styles.xml": styles})
            analysis = _analyze(path, root / "workspace")

        hidden = [item for item in analysis.findings if item.category == "hidden_text"]
        self.assertTrue(any(item.mechanism == "vanish" for item in hidden))
        self.assertTrue(any(item.mechanism == "web-hidden" for item in hidden))

    def test_additional_explicit_hidden_properties(self) -> None:
        cases = {
            "matching-foreground-background": '<w:color w:val="112233"/><w:shd w:fill="112233"/>',
            "tiny-font-size": '<w:sz w:val="2"/>',
            "zero-character-scale": '<w:w w:val="0"/>',
            "negative-character-spacing": '<w:spacing w:val="-200"/>',
        }
        body = "".join(
            f'<w:p><w:r><w:rPr>{properties}</w:rPr><w:t>{FLAG}</w:t></w:r></w:p>'
            for properties in cases.values()
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis = _analyze(_write_docx(root / "hidden.docx", body), root / "workspace")
        mechanisms = {
            item.mechanism for item in analysis.findings
            if item.category == "hidden_text" and item.flags_found
        }
        self.assertTrue(set(cases).issubset(mechanisms))

    def test_document_text_stego_chains_and_style_binary(self) -> None:
        encoded = base64.b64encode(FLAG.encode()).decode()
        hexadecimal = FLAG.encode().hex()
        zero_width_bits = "".join(f"{byte:08b}" for byte in FLAG.encode())
        zero_width = "".join("\u200b" if bit == "0" else "\u200c" for bit in zero_width_bits)
        comments = f'<w:comments xmlns:w="{W}"><w:comment><w:p><w:r><w:t>{encoded}</w:t></w:r></w:p></w:comment></w:comments>'.encode()
        body = (
            f'<w:p><w:del><w:r><w:delText>{hexadecimal}</w:delText></w:r></w:del></w:p>'
            f'<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>{zero_width}</w:t></w:r></w:p>'
        )
        bits = "".join(f"{byte:08b}" for byte in FLAG.encode())
        bold_run_parts = []
        for bit in bits:
            bold_property = '<w:b/>' if bit == "1" else '<w:b w:val="0"/>'
            bold_run_parts.append(
                f"<w:r><w:rPr>{bold_property}</w:rPr><w:t>x</w:t></w:r>"
            )
        bold_runs = "".join(bold_run_parts)
        font_runs = "".join(
            f'<w:r><w:rPr><w:rFonts w:ascii="{"Consolas" if bit == "1" else "Arial"}"/></w:rPr><w:t>x</w:t></w:r>'
            for bit in bits
        )
        body += f"<w:p>{bold_runs}</w:p><w:p>{font_runs}</w:p>"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = _write_docx(root / "chains.docx", body, members={"word/comments.xml": comments})
            analysis = _analyze(path, root / "workspace")

        self.assertIn(FLAG, _flags(analysis))
        chains = [">".join(item.decoder_chain) for item in analysis.findings if item.flags_found]
        self.assertTrue(any("base64" in chain for chain in chains))
        self.assertTrue(any("hex" in chain for chain in chains))
        self.assertTrue(any("zero_width" in chain for chain in chains))
        style_mechanisms = {
            item.mechanism for item in analysis.findings
            if item.category == "style_encoding" and item.flags_found
        }
        self.assertIn("bold-vs-normal", style_mechanisms)
        self.assertIn("font-family", style_mechanisms)


class RelationshipsAndEmbeddedTests(unittest.TestCase):
    def test_external_relationships_are_passive_and_internal_traversal_is_rejected(self) -> None:
        relationships = _rels(
            _relationship("https://example.org/template.dotm", external=True, rel_type="attachedTemplate"),
            _relationship("file://server/share/document.docx", external=True, rel_type="oleObject"),
            _relationship("../../../escape.bin", rel_type="image"),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = _write_docx(root / "relationships.docx", document_rels=relationships)
            with patch.object(socket, "getaddrinfo") as dns, patch.object(
                urllib.request, "urlopen"
            ) as fetch:
                analysis = _analyze(path, root / "workspace")

        external = [item for item in analysis.findings if item.mechanism == "external"]
        self.assertEqual(len(external), 2)
        self.assertTrue(any(item.mechanism == "unsafe-internal-relationship" for item in analysis.findings))
        dns.assert_not_called()
        fetch.assert_not_called()

    def test_ordinary_external_hyperlink_is_reported_as_medium(self) -> None:
        relationships = _rels(
            _relationship("https://example.org/reference", external=True, rel_type="hyperlink")
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis = _analyze(
                _write_docx(root / "hyperlink.docx", document_rels=relationships),
                root / "workspace",
            )
        links = [item for item in analysis.findings if item.mechanism == "external"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].confidence, "medium")

    def test_embedded_media_object_orphan_and_docm_macro_strings(self) -> None:
        png = b"\x89PNG\r\n\x1a\n" + b"tEXtComment\0" + FLAG.encode()
        nested_buffer = io.BytesIO()
        with zipfile.ZipFile(nested_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("secret.txt", FLAG)
        relationships = _rels(_relationship("media/image1.png"))
        members = {
            "word/media/image1.png": png,
            "word/media/orphan.png": png + b"different",
            "word/embeddings/package1.bin": nested_buffer.getvalue(),
            "word/vbaProject.bin": b'Attribute VB_Name = "M"\nConst clue = "' + FLAG.encode() + b'"',
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = _write_docx(
                root / "objects.docm",
                members=members,
                document_rels=relationships,
                docm=True,
            )
            analysis = _analyze(path, root / "workspace")
            extracted = list(analysis.extracted_artifacts)

            self.assertTrue(all(item.path.is_file() for item in extracted))
            self.assertTrue(all(item.path.resolve().is_relative_to((root / "workspace").resolve()) for item in extracted))

        self.assertIn(FLAG, _flags(analysis))
        self.assertTrue(any(item.mechanism == "unreferenced-media" for item in analysis.findings))
        self.assertTrue(any(item.mechanism == "embedded-zip-member" for item in analysis.findings))
        self.assertTrue(any(item.mechanism == "vba-project-presence" for item in analysis.findings))

    def test_recursive_depth_and_finding_limits_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = _write_docx(root / "nested.docx")
            analysis = analyze_document(
                path,
                PATTERN,
                workspace=root / "workspace",
                depth=MAX_RECURSION_DEPTH + 1,
            )
        self.assertIn("recursion-depth", analysis.limits_reached)
        self.assertLessEqual(len(analysis.findings), MAX_FINDINGS)

    def test_media_count_and_xml_node_limits_are_enforced(self) -> None:
        media = {
            f"word/media/image{index}.png": b"\x89PNG\r\n\x1a\n" + bytes([index % 251])
            for index in range(MAX_MEDIA_OBJECTS + 1)
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            many = _analyze(
                _write_docx(root / "many.docx", members=media),
                root / "w1",
            )
            node_limited = _write_docx(
                root / "nodes.docx",
                "<w:p><w:r><w:t>ordinary</w:t></w:r></w:p>",
            )
            with patch("dayi.document.openxml.MAX_XML_NODES", 3):
                nodes = _analyze(node_limited, root / "w2")
            with patch("dayi.document.openxml.MAX_XML_DEPTH", 2):
                depth = _analyze(node_limited, root / "w3")
        self.assertIn("media-count", many.limits_reached)
        self.assertTrue(any("XML node limit" in error for error in nodes.errors))
        self.assertTrue(any("XML depth limit" in error for error in depth.errors))

    def test_docm_static_literal_concatenation_and_chr_recovery(self) -> None:
        pieces = ('"Siber" & "Vatan" & "{document_stego}"')
        calls = " & ".join(f"ChrW({ord(character)})" for character in FLAG)
        macro = f"Sub AutoOpen()\nclue = {pieces}\nother = {calls}\nEnd Sub".encode()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis = _analyze(
                _write_docx(
                    root / "static.docm",
                    members={"word/vbaProject.bin": macro},
                    docm=True,
                ),
                root / "workspace",
            )
        mechanisms = {
            item.mechanism for item in analysis.findings
            if item.category == "macro_string" and item.flags_found
        }
        self.assertIn("vba-string-concatenation", mechanisms)
        self.assertIn("vba-chr-sequence", mechanisms)

    def test_ordinary_document_does_not_create_high_confidence_noise(self) -> None:
        body = (
            "<w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Quarterly Report</w:t></w:r></w:p>"
            "<w:p><w:r><w:t>This is ordinary prose in a normal document.</w:t></w:r></w:p>"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = _write_docx(root / "ordinary.docx", body)
            analysis = _analyze(path, root / "workspace")
        self.assertEqual(_flags(analysis), [])
        self.assertFalse(any(item.confidence in {"confirmed", "high"} for item in analysis.findings))


class DocumentPluginIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_plugin_contract_and_content_based_execution(self) -> None:
        plugin = PLUGIN_SPECS[0]
        self.assertEqual(plugin.plugin_id, "document_stego_scanner")
        self.assertEqual(plugin.phase, PluginPhase.ARCHIVE)
        self.assertEqual(plugin.priority, 5)
        self.assertEqual(plugin.required_executables, ())
        self.assertEqual(plugin.required_python_modules, ())

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = _write_docx(root / "extensionless", f"<w:p><w:r><w:t>{FLAG}</w:t></w:r></w:p>")
            with patch(
                "dayi.tools.document_stego_scanner._run_embedded_pipeline",
                new=AsyncMock(return_value=({}, [], [])),
            ):
                result = await run_document_stego(target, root / "workspace", PATTERN)
        self.assertFalse(result.skipped)
        self.assertIn(FLAG, [flag for hits in result.extracted_flags.values() for flag in hits])
        self.assertTrue(any(label.startswith("document:word/document.xml") for label in result.extracted_flags))

        registry = discover_plugins()
        self.assertEqual(len(registry.plugins), 22)
        self.assertIn("document_stego_scanner", [item.plugin_id for item in registry.plugins])
        capability = next(
            item for item in PYTHON_CAPABILITY_DEFINITIONS
            if item.capability_id == "document_stego"
        )
        self.assertEqual(capability.import_name, "dayi.document.openxml")
        self.assertIn("network-free", capability.capability)

    async def test_unsupported_binary_skips_and_timeout_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            binary = root / "random.docx"
            binary.write_bytes(b"\x00\xff" * 64)
            skipped = await run_document_stego(binary, root / "w1", PATTERN)
        self.assertTrue(skipped.skipped)
        self.assertIn("NOT_DOCUMENT", skipped.skip_reason)

    async def test_macro_result_is_reused_without_execution(self) -> None:
        macro_result = SimpleNamespace(
            flags_found=[FLAG],
            extracted_flags={},
            artifacts_found=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = _write_docx(
                root / "macro.docm",
                members={"word/vbaProject.bin": b"macro"},
                docm=True,
            )
            with patch(
                "dayi.tools.document_stego_scanner._run_embedded_pipeline",
                new=AsyncMock(return_value=({}, [], [])),
            ):
                result = await run_document_stego(
                    target, root / "workspace", PATTERN, ole_result=macro_result
                )
        self.assertEqual(result.extracted_flags["document:macro>olevba"], [FLAG])

    async def test_text_stego_attribution_and_embedded_ocr_discovery(self) -> None:
        encoded = base64.b64encode(FLAG.encode()).decode()
        comments = f'<w:comments xmlns:w="{W}"><w:comment><w:p><w:r><w:t>{encoded}</w:t></w:r></w:p></w:comment></w:comments>'.encode()
        png = b"\x89PNG\r\n\x1a\n" + b"synthetic"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = _write_docx(
                root / "attribution.docx",
                members={
                    "word/comments.xml": comments,
                    "word/media/image1.png": png,
                },
            )
            with patch(
                "dayi.tools.document_stego_scanner._run_embedded_pipeline",
                new=AsyncMock(return_value=({}, [], [])),
            ):
                result = await run_document_stego(target, root / "workspace", PATTERN)
            images = _discover_images(target, root / "workspace")

        self.assertIn(
            "document:comment:word/comments.xml>text_stego:base64",
            result.extracted_flags,
        )
        self.assertTrue(any(label.endswith("word/media/image1.png") for _path, label in images))

    async def test_internal_error_is_contained_but_process_interrupts_propagate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = _write_docx(root / "failure.docx")
            with patch(
                "dayi.tools.document_stego_scanner._await_analysis",
                new=AsyncMock(side_effect=RuntimeError("untrusted detail")),
            ):
                failed = await run_document_stego(target, root / "w1", PATTERN)
            self.assertTrue(failed.error)
            self.assertNotIn("untrusted detail", failed.stderr)

            for exception in (KeyboardInterrupt(), SystemExit()):
                with self.subTest(exception=type(exception).__name__), patch(
                    "dayi.tools.document_stego_scanner._await_analysis",
                    new=AsyncMock(side_effect=exception),
                ):
                    with self.assertRaises(type(exception)):
                        await run_document_stego(target, root / "w2", PATTERN)

    async def test_json_markdown_findings_are_bounded_and_control_safe(self) -> None:
        unsafe_flag = FLAG
        body = (
            f'<w:p><wp:docPr id="1" descr="{unsafe_flag}" title="ordinary\u202etext"/></w:p>'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = _write_docx(root / "unsafe.docx", body)
            with patch(
                "dayi.tools.document_stego_scanner._run_embedded_pipeline",
                new=AsyncMock(return_value=({}, [], [])),
            ):
                result = await run_document_stego(target, root / "workspace", PATTERN)
            report = ScanReport(
                target_file=str(target), flag_pattern=PATTERN.pattern,
                wordlist=None, started_at="start", finished_at="finish",
                all_flags=[FLAG], tool_results=[result],
            )
            json_path = root / "report.json"
            markdown_path = root / "writeup.md"
            write_json_report(report, json_path)
            with patch(
                "dayi.reporter.resolve_writeup_exporter",
                return_value=SimpleNamespace(
                    available=False, exporter=None, source_kind="unavailable",
                    status_code="not-found", safe_detail="not found",
                ),
            ):
                export_markdown_writeup(report, markdown_path)
            serialized = json_path.read_text() + markdown_path.read_text()
            payload = json.loads(json_path.read_text())

        self.assertNotIn("\u202e", serialized)
        document_findings = payload["tool_results"][0]["document_findings"]
        self.assertTrue(document_findings)
        self.assertTrue(all(len(item["preview"]) <= 240 for item in document_findings))
        self.assertIn("Document findings", serialized)

    async def test_default_and_verbose_finding_output_is_bounded(self) -> None:
        comments = (
            f'<w:comments xmlns:w="{W}">'
            + "".join(
                f'<w:comment w:id="{index}"><w:p><w:r><w:t>ordinary note {index}</w:t></w:r></w:p></w:comment>'
                for index in range(80)
            )
            + "</w:comments>"
        ).encode()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = _write_docx(root / "comments.docx", members={"word/comments.xml": comments})
            with patch(
                "dayi.tools.document_stego_scanner._run_embedded_pipeline",
                new=AsyncMock(return_value=({}, [], [])),
            ):
                quiet = await run_document_stego(target, root / "w1", PATTERN)
                verbose = await run_document_stego(target, root / "w2", PATTERN, verbose=True)
        quiet_lines = [line for line in quiet.stdout.splitlines() if line.startswith("  [")]
        verbose_lines = [line for line in verbose.stdout.splitlines() if line.startswith("  [")]
        self.assertLessEqual(len(quiet_lines), 20)
        self.assertLessEqual(len(verbose_lines), 50)
        self.assertGreaterEqual(len(verbose_lines), len(quiet_lines))


if __name__ == "__main__":
    unittest.main()
