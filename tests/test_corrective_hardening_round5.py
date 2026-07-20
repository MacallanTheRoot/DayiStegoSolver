import json
import re
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from dayi.document import analyze_document
from dayi.image_analysis import OCRFinding, OCRVariant, discover_images
from dayi.reporter import (
    ScanReport,
    ToolResult,
    _build_flag_attribution,
    _fallback_markdown,
    write_json_report,
)
from dayi.tools.document_stego_scanner import _run_embedded_pipeline


FLAG_PATTERN = re.compile(r"SiberVatan\{.*?\}")
PNG_PAYLOAD = b"\x89PNG\r\n\x1a\n" + b"synthetic nested image"


def _rtf_picture(payload: bytes = PNG_PAYLOAD) -> bytes:
    return (
        b"{\\rtf1\\ansi{\\pict\\pngblip "
        + payload.hex().encode("ascii")
        + b"}}"
    )


def _docx_with_embedded_rtf(path: Path, nested_rtf: bytes) -> Path:
    content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
    relationships = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>"""
    document = """<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>ordinary</w:t></w:r></w:p></w:body>
</w:document>"""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", relationships)
        archive.writestr("word/document.xml", document)
        archive.writestr("word/embeddings/nested.rtf", nested_rtf)
    return path


def _successful_tool_result(name: str) -> ToolResult:
    return ToolResult(name, [], 0, "", "", [], 0.01)


class NestedRTFArtifactPropagationTests(unittest.IsolatedAsyncioTestCase):
    async def test_docx_nested_rtf_picture_reaches_image_and_embedded_pipelines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workspace = root / "workspace"
            target = _docx_with_embedded_rtf(
                root / "nested.docx", _rtf_picture()
            )
            analysis = analyze_document(
                target, FLAG_PATTERN, workspace=workspace
            )

            nested_images = [
                item for item in analysis.extracted_artifacts
                if item.kind == "PNG" and ">pict-" in item.source_member
            ]
            self.assertEqual(len(nested_images), 1)
            discovered = {item.path for item in discover_images(target, workspace)}
            self.assertIn(nested_images[0].path.resolve(), discovered)

            calls: list[Path] = []
            downstream_flag = "SiberVatan{nested_pipeline}"

            async def record(path: Path, *_args, **_kwargs) -> ToolResult:
                calls.append(path)
                result = _successful_tool_result("synthetic")
                if path == nested_images[0].path:
                    result.flags_found = [downstream_flag]
                return result

            with (
                patch("dayi.tools.exiftool.run_exiftool", new=record),
                patch("dayi.tools.strings.run_strings", new=record),
                patch("dayi.tools.lsb.run_lsb", new=record),
                patch("dayi.tools.zsteg.run_zsteg", new=record),
                patch("dayi.tools.binwalk.run_binwalk", new=AsyncMock(
                    return_value=_successful_tool_result("binwalk")
                )),
            ):
                extracted_flags, _artifacts, _summaries = await _run_embedded_pipeline(
                    analysis, FLAG_PATTERN, workspace, 10.0, document_type=None
                )

            self.assertIn(nested_images[0].path, calls)
            self.assertIn(
                downstream_flag,
                [flag for flags in extracted_flags.values() for flag in flags],
            )

    async def test_recursive_rtf_propagates_child_picture_once(self) -> None:
        inner = _rtf_picture()
        outer = (
            b"{\\rtf1\\ansi"
            + b"{\\object\\objdata " + inner.hex().encode("ascii") + b"}"
            + b"{\\object\\objdata " + inner.hex().encode("ascii") + b"}"
            + b"}"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "outer.rtf"
            target.write_bytes(outer)
            analysis = analyze_document(
                target, FLAG_PATTERN, workspace=root / "workspace"
            )

        child_pictures = [
            item for item in analysis.extracted_artifacts
            if item.kind == "PNG" and ">pict-" in item.source_member
        ]
        self.assertEqual(len(child_pictures), 1)
        identities = [
            (item.path, item.sha256) for item in analysis.extracted_artifacts
        ]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertEqual(
            [item.source_member for item in analysis.extracted_artifacts],
            sorted(
                (item.source_member for item in analysis.extracted_artifacts),
                key=lambda value: (value.count(">"), value),
            ),
        )


class PerFlagOCRAttributionTests(unittest.TestCase):
    def _result(self) -> tuple[ToolResult, str, str]:
        first = "SiberVatan{first_variant}"
        second = "SiberVatan{second_chain}"
        source = "document_extracted/media.png"
        findings = [
            OCRFinding(
                text=first,
                sanitized_text=first,
                confidence="confirmed",
                mean_word_confidence=91.0,
                source=source,
                variant=OCRVariant("original-psm6", psm=6),
                flags_found=(first,),
                decoder_chain=("base64",),
                evidence=("direct-first",),
            ),
            OCRFinding(
                text=second,
                sanitized_text=second,
                confidence="confirmed",
                mean_word_confidence=82.0,
                source=source,
                variant=OCRVariant("rot90-psm11", rotation=90, psm=11),
                flags_found=(second,),
                decoder_chain=("hex", "reverse"),
                evidence=("decoded-second",),
            ),
        ]
        result = ToolResult(
            "ocr_scanner", [], 0, "", "", [first, second], 0.1,
            extracted_flags={source: [first, second]},
            ocr_findings=findings,
        )
        return result, first, second

    def test_each_flag_uses_its_own_variant_and_decoder_chain(self) -> None:
        result, first, second = self._result()
        attribution = _build_flag_attribution([result])
        self.assertEqual(
            attribution[first],
            ["document:ocr:document_extracted/media.png:original-psm6>base64"],
        )
        self.assertEqual(
            attribution[second],
            [
                "document:ocr:document_extracted/media.png:"
                "rot90-psm11>hex>reverse"
            ],
        )

    def test_json_and_markdown_keep_per_flag_ocr_details(self) -> None:
        result, first, second = self._result()
        report = ScanReport(
            "sample.png", "SiberVatan", None, "a", "b",
            [first, second], [result],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            json_path = root / "report.json"
            markdown_path = root / "report.md"
            write_json_report(report, json_path)
            _fallback_markdown(report, markdown_path)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")

        self.assertIn("original-psm6>base64", payload["flag_attribution"][first][0])
        self.assertIn(
            "rot90-psm11>hex>reverse",
            payload["flag_attribution"][second][0],
        )
        self.assertIn("PSM 6", markdown)
        self.assertIn("direct-first", markdown)
        self.assertIn("PSM 11", markdown)
        self.assertIn("decoded-second", markdown)

    def test_identical_flag_duplicates_remain_deduplicated(self) -> None:
        result, first, _second = self._result()
        result.flags_found = [first, first]
        result.extracted_flags = {
            "document_extracted/media.png": [first, first]
        }
        result.ocr_findings.append(result.ocr_findings[0])

        attribution = _build_flag_attribution([result])

        self.assertEqual(list(attribution), [first])
        self.assertEqual(len(attribution[first]), 1)


if __name__ == "__main__":
    unittest.main()
