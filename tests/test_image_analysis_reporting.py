import json
import tempfile
import unittest
from pathlib import Path

from dayi.image_analysis import OCRFinding, OCRVariant, QRFinding
from dayi.reporter import (
    ScanReport,
    ToolResult,
    _build_flag_attribution,
    _fallback_markdown,
    write_json_report,
)


class ImageAnalysisReportingTests(unittest.TestCase):
    def test_json_preserves_tool_error_and_extraction_state(self) -> None:
        results = [
            ToolResult(
                "extractor", [], 0, "", "", [], 0.1,
                extraction_succeeded=True,
            ),
            ToolResult(
                "parser", [], None, "", "", [], 0.2,
                skipped=True,
                error=True,
                skip_reason="bounded parser failure",
            ),
        ]
        report = ScanReport("sample.bin", "FLAG", None, "a", "b", [], results)

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            write_json_report(report, output)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertTrue(payload["tool_results"][0]["extraction_succeeded"])
        self.assertFalse(payload["tool_results"][0]["error"])
        self.assertTrue(payload["tool_results"][1]["error"])
        self.assertFalse(payload["tool_results"][1]["extraction_succeeded"])

    def test_json_markdown_and_attribution_include_bounded_image_findings(self) -> None:
        flag = "SiberVatan{reported}"
        ocr = OCRFinding(
            text=flag,
            sanitized_text=flag,
            confidence="confirmed",
            mean_word_confidence=92.0,
            source="document_extracted/media.png",
            variant=OCRVariant("grayscale-psm6", psm=6),
            flags_found=(flag,),
            decoder_chain=("base64",),
        )
        qr = QRFinding(
            payload_type="text",
            payload_text="<U+202E RIGHT-TO-LEFT OVERRIDE>",
            payload_bytes_preview=None,
            backend="opencv",
            variant="original",
            source="document_extracted/media.png",
            flags_found=(flag,),
        )
        results = [
            ToolResult(
                "ocr_scanner", [], 0, "", "", [flag], 0.1,
                extracted_flags={"document_extracted/media.png": [flag]},
                ocr_findings=[ocr],
            ),
            ToolResult(
                "qr_scanner", [], 0, "", "", [flag], 0.1,
                extracted_flags={"document_extracted/media.png>qr:opencv:original": [flag]},
                qr_findings=[qr],
            ),
        ]
        report = ScanReport("sample.bin", "SiberVatan", None, "a", "b", [flag], results)
        attribution = _build_flag_attribution(results)[flag]
        self.assertTrue(any("grayscale-psm6>base64" in item for item in attribution))
        self.assertIn("document_extracted/media.png>qr:opencv:original", attribution)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            json_path = root / "report.json"
            markdown_path = root / "writeup.md"
            write_json_report(report, json_path)
            _fallback_markdown(report, markdown_path)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")
        self.assertTrue(payload["tool_results"][0]["ocr_findings"])
        self.assertTrue(payload["tool_results"][1]["qr_findings"])
        self.assertIn("OCR findings", markdown)
        self.assertIn("QR findings", markdown)
        self.assertNotIn("\u202e", markdown)


if __name__ == "__main__":
    unittest.main()
