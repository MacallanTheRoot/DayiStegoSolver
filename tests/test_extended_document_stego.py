import base64
import re
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from dayi.document import DocumentType, analyze_document, detect_document_type
from dayi.document.limits import MAX_RTF_GROUP_DEPTH
from dayi.tools._plugin import discover_plugins
from dayi.tools.document_stego_scanner import run_document_stego


FLAG = "SiberVatan{extended_document}"
PATTERN = re.compile(r"SiberVatan\{.*?\}")
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _zip(path: Path, members: dict[str, bytes | str]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def _rels(*items: str) -> str:
    return f'<Relationships xmlns="{REL_NS}">{"".join(items)}</Relationships>'


def _relationship(
    rel_id: str,
    target: str,
    rel_type: str,
    *,
    external: bool = False,
) -> str:
    mode = ' TargetMode="External"' if external else ""
    return (
        f'<Relationship Id="{rel_id}" Type="{OFFICE_REL}/{rel_type}" '
        f'Target="{target}"{mode}/>'
    )


def _content_type(part: str, content_type: str) -> str:
    return (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f'<Override PartName="/{part}" ContentType="{content_type}"/></Types>'
    )


def _xlsx(
    path: Path,
    *,
    macro: bool = False,
    style_flag: bool = False,
    include_evidence: bool = True,
) -> Path:
    main_type = (
        "application/vnd.ms-excel.sheet.macroEnabled.main+xml"
        if macro else
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    )
    bits = "".join(f"{byte:08b}" for byte in FLAG.encode())
    if style_flag:
        cells = "<row r=\"1\">" + "".join(
            f'<c r="A{index}" t="inlineStr" s="{bit}"><is><t>x</t></is></c>'
            for index, bit in enumerate(bits, 1)
        ) + "</row>"
    else:
        encoded = base64.b64encode(FLAG.encode()).decode()
        cells = (
            f'<row r="1" hidden="1"><c r="A1" t="inlineStr"><is><t>{encoded}</t></is></c></row>'
            f'<row r="2"><c r="B2" t="s"><v>0</v></c></row>'
        )
    workbook = (
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        f'xmlns:r="{OFFICE_REL}"><sheets>'
        '<sheet name="Secrets" sheetId="1" state="veryHidden" r:id="rId1"/>'
        '</sheets>'
        + (
            f'<definedNames><definedName hidden="1">{FLAG}</definedName></definedNames>'
            if include_evidence else ""
        )
        + '</workbook>'
    )
    worksheet = (
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<cols><col min="2" max="2" hidden="1"/></cols>'
        f'<sheetData>{cells}</sheetData></worksheet>'
    )
    styles = (
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><b val="0"/><name val="A"/></font>'
        '<font><b/><name val="B"/></font></fonts>'
        '<fills count="1"><fill><patternFill/></fill></fills>'
        '<cellXfs count="2"><xf fontId="0" fillId="0" numFmtId="0"/>'
        '<xf fontId="1" fillId="0" numFmtId="0"/></cellXfs></styleSheet>'
    )
    members: dict[str, bytes | str] = {
        "[Content_Types].xml": _content_type("xl/workbook.xml", main_type),
        "_rels/.rels": _rels(_relationship("root", "xl/workbook.xml", "officeDocument")),
        "xl/workbook.xml": workbook,
        "xl/_rels/workbook.xml.rels": _rels(
            _relationship("rId1", "worksheets/sheet1.xml", "worksheet"),
            _relationship("external", "https://example.invalid/book.xlsx", "externalLink", external=True),
        ),
        "xl/worksheets/sheet1.xml": worksheet,
        "xl/styles.xml": styles,
    }
    if include_evidence:
        members.update({
            "xl/sharedStrings.xml": (
                '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                f'<si><t>{FLAG}</t></si></sst>'
            ),
            "xl/comments1.xml": (
                '<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                f'<comment ref="A1"><text><t>{FLAG}</t></text></comment></comments>'
            ),
            "xl/media/image1.png": b"\x89PNG\r\n\x1a\n" + FLAG.encode(),
            "xl/embeddings/object1.bin": FLAG.encode(),
        })
    if macro:
        members["xl/vbaProject.bin"] = f'Sub x()\nMsgBox "{FLAG}"\nEnd Sub'.encode()
    return _zip(path, members)


def _pptx(
    path: Path,
    *,
    macro: bool = False,
    style_flag: bool = False,
    hidden: bool = True,
    transparent: bool = False,
) -> Path:
    main_type = (
        "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml"
        if macro else
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
    )
    bits = "".join(f"{byte:08b}" for byte in FLAG.encode())
    if style_flag:
        runs = "".join(
            f'<a:r><a:rPr b="{bit}"/><a:t>x</a:t></a:r>' for bit in bits
        )
    else:
        runs = f'<a:r><a:rPr/><a:t>{FLAG}</a:t></a:r>'
    color = (
        '<a:solidFill><a:srgbClr val="FFFFFF">'
        '<a:alpha val="0"/></a:srgbClr></a:solidFill>'
        if transparent else ""
    )
    slide = (
        '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        f'show="{0 if hidden else 1}">'
        f'<p:cSld><p:spTree><p:sp><p:nvSpPr><p:cNvPr id="1" name="Shape 1" descr="{FLAG}"/>'
        f'</p:nvSpPr><p:spPr><a:xfrm><a:off x="{0 if transparent else -1}" y="0"/>'
        f'</a:xfrm>{color}</p:spPr>'
        f'<p:txBody><a:p>{runs}</a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>'
    )
    members: dict[str, bytes | str] = {
        "[Content_Types].xml": _content_type("ppt/presentation.xml", main_type),
        "_rels/.rels": _rels(_relationship("root", "ppt/presentation.xml", "officeDocument")),
        "ppt/presentation.xml": (
            '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            f'xmlns:r="{OFFICE_REL}"><p:sldIdLst><p:sldId id="1" r:id="rId1" '
            '/>'
            '</p:sldIdLst></p:presentation>'
        ),
        "ppt/_rels/presentation.xml.rels": _rels(
            _relationship("rId1", "slides/slide1.xml", "slide"),
            _relationship("external", "file:///tmp/linked.pptx", "externalLink", external=True),
        ),
        "ppt/slides/slide1.xml": slide,
        "ppt/notesSlides/notesSlide1.xml": (
            '<p:notes xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
            f'<a:t>{base64.b64encode(FLAG.encode()).decode()}</a:t></p:notes>'
        ),
        "ppt/comments/comment1.xml": f'<p:cmLst xmlns:p="x"><p:cm><p:text>{FLAG}</p:text></p:cm></p:cmLst>',
        "ppt/slideMasters/slideMaster1.xml": f'<p:sldMaster xmlns:p="x" xmlns:a="y"><a:t>{FLAG}</a:t></p:sldMaster>',
        "ppt/media/image1.png": b"\x89PNG\r\n\x1a\n" + FLAG.encode(),
        "ppt/embeddings/object1.bin": FLAG.encode(),
    }
    if macro:
        members["ppt/vbaProject.bin"] = f'Sub x()\nMsgBox "{FLAG}"\nEnd Sub'.encode()
    return _zip(path, members)


def _odf(path: Path, kind: DocumentType) -> Path:
    mime = {
        DocumentType.ODT: "application/vnd.oasis.opendocument.text",
        DocumentType.ODS: "application/vnd.oasis.opendocument.spreadsheet",
        DocumentType.ODP: "application/vnd.oasis.opendocument.presentation",
    }[kind]
    body = {
        DocumentType.ODT: '<text:section text:display="none"><text:p>{}</text:p></text:section>',
        DocumentType.ODS: '<table:table table:visibility="collapse"><table:table-row><table:table-cell><text:p>{}</text:p></table:table-cell></table:table-row></table:table>',
        DocumentType.ODP: '<draw:page presentation:visibility="hidden"><presentation:notes><text:p>{}</text:p></presentation:notes></draw:page>',
    }[kind].format(FLAG)
    content = (
        '<office:document-content '
        'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
        'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
        'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
        'xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0">'
        f'<office:body>{body}<office:annotation><text:p>{FLAG}</text:p></office:annotation>'
        f'<text:tracked-changes><text:changed-region>{FLAG}</text:changed-region></text:tracked-changes>'
        '</office:body></office:document-content>'
    )
    return _zip(path, {
        "mimetype": mime,
        "content.xml": content,
        "meta.xml": f'<office:document-meta xmlns:office="x"><office:meta>{FLAG}</office:meta></office:document-meta>',
        "META-INF/manifest.xml": '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>',
        "Pictures/image1.png": b"\x89PNG\r\n\x1a\n" + FLAG.encode(),
        "Objects/object1.bin": FLAG.encode(),
    })


def _flags(analysis) -> list[str]:
    return [flag for finding in analysis.findings for flag in finding.flags_found]


class ExtendedDocumentDetectionTests(unittest.TestCase):
    def test_wrong_extensions_are_classified_from_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            samples = {
                _xlsx(root / "sheet.bin"): DocumentType.XLSX,
                _xlsx(root / "macro.bin", macro=True): DocumentType.XLSM,
                _pptx(root / "slides.bin"): DocumentType.PPTX,
                _pptx(root / "deck.bin", macro=True): DocumentType.PPTM,
                _odf(root / "text.bin", DocumentType.ODT): DocumentType.ODT,
                _odf(root / "calc.bin", DocumentType.ODS): DocumentType.ODS,
                _odf(root / "show.bin", DocumentType.ODP): DocumentType.ODP,
            }
            rtf = root / "rich.bin"
            rtf.write_bytes(b"{\\rtf1 ordinary}")
            samples[rtf] = DocumentType.RTF
            self.assertEqual(
                {path.name: detect_document_type(path) for path in samples},
                {path.name: expected for path, expected in samples.items()},
            )

    def test_generic_odf_and_unsupported_zip_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            generic = _zip(root / "generic", {"mimetype": "application/vnd.oasis.opendocument.chart"})
            unsupported = _zip(root / "unsupported", {"data.txt": "ordinary"})
            self.assertEqual(detect_document_type(generic), DocumentType.OPENDOCUMENT_GENERIC)
            self.assertEqual(detect_document_type(unsupported), DocumentType.NOT_DOCUMENT)


class SpreadsheetAnalysisTests(unittest.TestCase):
    def test_hidden_comments_names_external_media_objects_and_macro_are_passive(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("network forbidden")
        ):
            root = Path(tmpdir)
            analysis = analyze_document(_xlsx(root / "book", macro=True), PATTERN, workspace=root / "w")
        self.assertIn(FLAG, _flags(analysis))
        mechanisms = {item.mechanism for item in analysis.findings}
        self.assertTrue({"veryhidden-sheet", "hidden-defined-name", "external", "vba-string-literal"} <= mechanisms)
        self.assertTrue(any(item.source_member.startswith("xl/media/") for item in analysis.extracted_artifacts))
        self.assertTrue(any(item.source_member.startswith("xl/embeddings/") for item in analysis.extracted_artifacts))

    def test_spreadsheet_style_binary_reaches_text_decoder(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis = analyze_document(
                _xlsx(root / "style", style_flag=True, include_evidence=False),
                PATTERN,
                workspace=root / "w",
            )
        self.assertIn(FLAG, _flags(analysis))
        self.assertTrue(any(item.category == "style_encoding" for item in analysis.findings))

    def test_row_column_color_size_and_number_format_concealment(self) -> None:
        workbook = (
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            f'xmlns:r="{OFFICE_REL}"><sheets><sheet name="Visible" sheetId="1" '
            'r:id="rId1"/></sheets></workbook>'
        )
        sheet = (
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<cols><col min="2" max="2" hidden="1"/></cols><sheetData>'
            f'<row hidden="1"><c r="A1" t="inlineStr"><is><t>{FLAG}</t></is></c></row>'
            f'<row><c r="B2" t="inlineStr"><is><t>{FLAG}</t></is></c>'
            f'<c r="C2" t="inlineStr" s="1"><is><t>{FLAG}</t></is></c>'
            f'<c r="D2" t="inlineStr" s="2"><is><t>{FLAG}</t></is></c>'
            f'<c r="E2" t="inlineStr" s="3"><is><t>{FLAG}</t></is></c></row>'
            '</sheetData></worksheet>'
        )
        styles = (
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<numFmts count="1"><numFmt numFmtId="164" formatCode=";;;"/></numFmts>'
            '<fonts count="3"><font/><font><color rgb="FFFFFFFF"/></font>'
            '<font><sz val="0"/></font></fonts><fills count="1"><fill/></fills>'
            '<cellXfs count="4"><xf fontId="0" fillId="0" numFmtId="0"/>'
            '<xf fontId="1" fillId="0" numFmtId="0"/>'
            '<xf fontId="0" fillId="0" numFmtId="164"/>'
            '<xf fontId="2" fillId="0" numFmtId="0"/></cellXfs></styleSheet>'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = _zip(root / "concealed", {
                "[Content_Types].xml": _content_type(
                    "xl/workbook.xml",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
                ),
                "_rels/.rels": _rels(_relationship("root", "xl/workbook.xml", "officeDocument")),
                "xl/workbook.xml": workbook,
                "xl/_rels/workbook.xml.rels": _rels(_relationship("rId1", "worksheets/sheet1.xml", "worksheet")),
                "xl/worksheets/sheet1.xml": sheet,
                "xl/styles.xml": styles,
            })
            analysis = analyze_document(target, PATTERN, workspace=root / "w")
        mechanisms = {item.mechanism for item in analysis.findings}
        self.assertTrue({
            "hidden-row", "hidden-column", "white-text-cell",
            "hidden-number-format", "zero-font-cell",
        } <= mechanisms)


class PresentationAnalysisTests(unittest.TestCase):
    def test_hidden_slide_notes_alt_text_external_and_macro_are_passive(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("network forbidden")
        ):
            root = Path(tmpdir)
            analysis = analyze_document(_pptx(root / "deck", macro=True), PATTERN, workspace=root / "w")
        self.assertIn(FLAG, _flags(analysis))
        mechanisms = {item.mechanism for item in analysis.findings}
        self.assertTrue({"hidden-slide", "speaker-notes", "alt-text", "external", "vba-string-literal"} <= mechanisms)
        self.assertEqual(analysis.document_type, "PPTM")

    def test_presentation_style_binary_reaches_text_decoder(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis = analyze_document(_pptx(root / "style", style_flag=True), PATTERN, workspace=root / "w")
        self.assertIn(FLAG, _flags(analysis))
        self.assertTrue(any(item.category == "style_encoding" for item in analysis.findings))

    def test_explicit_transparency_is_reported_without_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis = analyze_document(
                _pptx(root / "transparent", hidden=False, transparent=True),
                PATTERN,
                workspace=root / "w",
            )
        self.assertTrue(any(item.mechanism == "transparent-text" for item in analysis.findings))


class OpenDocumentAnalysisTests(unittest.TestCase):
    def test_odf_hidden_content_notes_annotations_metadata_and_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for kind in (DocumentType.ODT, DocumentType.ODS, DocumentType.ODP):
                with self.subTest(kind=kind):
                    analysis = analyze_document(_odf(root / kind.value, kind), PATTERN, workspace=root / f"w-{kind.value}")
                    self.assertIn(FLAG, _flags(analysis))
                    self.assertTrue(analysis.extracted_artifacts)
                    self.assertFalse(any("failed safely" in error for error in analysis.errors))

    def test_odf_style_binary_reaches_text_decoder(self) -> None:
        bits = "".join(f"{byte:08b}" for byte in FLAG.encode())
        spans = "".join(
            f'<text:span text:style-name="S{bit}">x</text:span>' for bit in bits
        )
        content = (
            '<office:document-content '
            'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
            'xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" '
            'xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0">'
            '<office:automatic-styles><style:style style:name="S0"><style:text-properties '
            'fo:font-weight="normal"/></style:style><style:style style:name="S1">'
            '<style:text-properties fo:font-weight="bold"/></style:style></office:automatic-styles>'
            f'<office:body><text:p>{spans}</text:p></office:body></office:document-content>'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = _zip(root / "style-odt", {
                "mimetype": "application/vnd.oasis.opendocument.text",
                "content.xml": content,
            })
            analysis = analyze_document(target, PATTERN, workspace=root / "w")
        self.assertIn(FLAG, _flags(analysis))
        self.assertTrue(any(item.category == "style_encoding" for item in analysis.findings))


class RTFAnalysisTests(unittest.TestCase):
    def test_hidden_white_tiny_annotation_field_hex_and_unicode(self) -> None:
        rtf_flag = FLAG.replace("{", r"\{").replace("}", r"\}")
        escaped = "".join(f"\\'{byte:02x}" for byte in FLAG.encode())
        rtf = (
            r"{\rtf1{\colortbl;\red255\green255\blue255;}"
            + rf"{{\v {rtf_flag}}}{{\cf1 {rtf_flag}}}{{\fs2 {rtf_flag}}}"
            + rf"{{\annotation {rtf_flag}}}{{\*\fldinst HYPERLINK {rtf_flag}}}"
            + escaped + r" \u83?iberVatan{extended_document}}"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "rich.bin"
            path.write_bytes(rtf.encode("latin-1"))
            analysis = analyze_document(path, PATTERN, workspace=root / "w")
        self.assertIn(FLAG, _flags(analysis))
        mechanisms = {item.mechanism for item in analysis.findings}
        self.assertTrue({"hidden-text", "white-text", "tiny-text", "annotation", "field-code"} <= mechanisms)

    def test_pictures_objects_nested_decoder_and_hostile_nesting_are_bounded(self) -> None:
        encoded = base64.b64encode(FLAG[::-1].encode()).decode()
        picture = (b"\x89PNG\r\n\x1a\n" + FLAG.encode()).hex()
        payload = FLAG.encode().hex()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "embedded.rtf"
            path.write_text(
                rf"{{\rtf1 {{\v {encoded}}}{{\pict\pngblip {picture}}}{{\object\objdata {payload}}}}}",
                encoding="ascii",
            )
            analysis = analyze_document(path, PATTERN, workspace=root / "w")
            hostile = root / "hostile.rtf"
            hostile.write_bytes(b"{\\rtf1" + b"{" * (MAX_RTF_GROUP_DEPTH + 1) + b"x")
            rejected = analyze_document(hostile, PATTERN, workspace=root / "w2")
        self.assertIn(FLAG, _flags(analysis))
        self.assertGreaterEqual(len(analysis.extracted_artifacts), 2)
        self.assertTrue(any("reverse" in item.decoder_chain for item in analysis.findings))
        self.assertTrue(rejected.errors)
        self.assertEqual(rejected.findings, ())

    def test_ordinary_rtf_has_no_high_confidence_noise(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "ordinary"
            path.write_bytes(b"{\\rtf1\\ansi This is an ordinary multilingual report.}")
            analysis = analyze_document(path, PATTERN, workspace=root / "w")
        self.assertFalse(any(item.confidence in {"confirmed", "high"} for item in analysis.findings))

    def test_embedded_rtf_recursion_and_duplicate_hashes_are_bounded(self) -> None:
        inner_flag = FLAG.replace("{", r"\{").replace("}", r"\}")
        inner = rf"{{\rtf1{{\v {inner_flag}}}}}".encode("ascii")
        encoded = inner.hex()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "nested.rtf"
            target.write_text(
                rf"{{\rtf1{{\object\objdata {encoded}}}"
                rf"{{\object\objdata {encoded}}}}}",
                encoding="ascii",
            )
            analysis = analyze_document(target, PATTERN, workspace=root / "w")
        self.assertIn(FLAG, _flags(analysis))
        self.assertEqual(len(analysis.extracted_artifacts), 1)
        self.assertTrue(any("embedded-document" in item.mechanism for item in analysis.findings))


class ExtendedDocumentPluginTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_plugin_handles_extensionless_formats_without_count_change(self) -> None:
        self.assertEqual(len(discover_plugins().plugins), 22)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for target in (
                _xlsx(root / "book"), _pptx(root / "deck"),
                _odf(root / "text", DocumentType.ODT),
            ):
                with self.subTest(target=target.name), patch(
                    "dayi.tools.document_stego_scanner._run_embedded_pipeline",
                    new=AsyncMock(return_value=({}, [], [])),
                ):
                    result = await run_document_stego(target, root / f"w-{target.name}", PATTERN)
                    self.assertFalse(result.skipped)
                    self.assertIn(FLAG, [flag for values in result.extracted_flags.values() for flag in values])
                    self.assertIn(f"Document type: {detect_document_type(target).value}", result.stdout)

    async def test_extended_attribution_has_one_format_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = _xlsx(root / "style", style_flag=True, include_evidence=False)
            with patch(
                "dayi.tools.document_stego_scanner._run_embedded_pipeline",
                new=AsyncMock(return_value=({}, [], [])),
            ):
                result = await run_document_stego(target, root / "w", PATTERN)
        labels = set(result.extracted_flags)
        self.assertTrue(any(label.startswith("document:xlsx:bold>binary") for label in labels))
        self.assertFalse(any("document:xlsx:xlsx:" in label for label in labels))


if __name__ == "__main__":
    unittest.main()
