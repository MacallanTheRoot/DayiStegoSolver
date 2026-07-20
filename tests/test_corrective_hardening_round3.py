import json
import re
import tempfile
import unittest
import zipfile
from pathlib import Path

from dayi.document import analyze_document
from dayi.document.rtf import analyze_rtf_document
from dayi.reporter import ScanReport, ToolResult, write_json_report, write_txt_report


DEFAULT_PATTERN = re.compile(r"SiberVatan\{.*?\}")
EMOJI = chr(0x1F600)
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _rtf_analysis(payload: bytes, pattern: re.Pattern = DEFAULT_PATTERN):
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        target = root / "sample.rtf"
        target.write_bytes(payload)
        return analyze_rtf_document(
            target,
            pattern,
            workspace=root / "workspace",
        )


def _annotation_values(payload: bytes, pattern: re.Pattern = DEFAULT_PATTERN) -> list[str]:
    return [
        finding.value
        for finding in _rtf_analysis(payload, pattern).findings
        if finding.mechanism == "annotation"
    ]


def _pptx(
    path: Path,
    *,
    target: str = "slides/slide1.xml",
    show: str | None = None,
    text: str = "ordinary slide text",
) -> Path:
    show_attribute = "" if show is None else f' show="{show}"'
    members = {
        "[Content_Types].xml": (
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/ppt/presentation.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.'
            'presentationml.presentation.main+xml"/></Types>'
        ),
        "_rels/.rels": (
            f'<Relationships xmlns="{REL_NS}"><Relationship Id="root" '
            f'Type="{OFFICE_REL}/officeDocument" '
            'Target="ppt/presentation.xml"/></Relationships>'
        ),
        "ppt/presentation.xml": (
            '<p:presentation xmlns:p="http://schemas.openxmlformats.org/'
            f'presentationml/2006/main" xmlns:r="{OFFICE_REL}">'
            '<p:sldIdLst><p:sldId id="1" r:id="rId1"/>'
            '</p:sldIdLst></p:presentation>'
        ),
        "ppt/_rels/presentation.xml.rels": (
            f'<Relationships xmlns="{REL_NS}"><Relationship Id="rId1" '
            f'Type="{OFFICE_REL}/slide" Target="{target}"/></Relationships>'
        ),
        "ppt/slides/slide1.xml": (
            '<p:sld xmlns:p="http://schemas.openxmlformats.org/'
            'presentationml/2006/main" '
            'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
            f'{show_attribute}><p:cSld><a:t>{text}</a:t></p:cSld></p:sld>'
        ),
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    return path


def _presentation_analysis(
    *,
    target: str = "slides/slide1.xml",
    show: str | None = None,
    text: str = "ordinary slide text",
    pattern: re.Pattern = DEFAULT_PATTERN,
):
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        return analyze_document(
            _pptx(root / "deck.bin", target=target, show=show, text=text),
            pattern,
            workspace=root / "workspace",
        )


class RTFSurrogateTests(unittest.TestCase):
    def test_valid_surrogate_pair_is_combined(self) -> None:
        values = _annotation_values(
            br"{\rtf1\ansi{\annotation face \u-10179?\u-8704? done}}"
        )
        self.assertTrue(values)
        self.assertIn(f"face {EMOJI} done", values[0])
        self.assertFalse(any(0xD800 <= ord(char) <= 0xDFFF for char in values[0]))

    def test_isolated_high_surrogate_is_replaced(self) -> None:
        values = _annotation_values(
            br"{\rtf1\ansi{\annotation before \u-10179? after}}"
        )
        self.assertIn("before � after", values[0])
        self.assertFalse(any(0xD800 <= ord(char) <= 0xDFFF for char in values[0]))

    def test_isolated_low_surrogate_is_replaced(self) -> None:
        values = _annotation_values(
            br"{\rtf1\ansi{\annotation before \u-8704? after}}"
        )
        self.assertIn("before � after", values[0])
        self.assertFalse(any(0xD800 <= ord(char) <= 0xDFFF for char in values[0]))

    def test_surrogate_pair_in_annotation_preserves_custom_flag(self) -> None:
        pattern = re.compile(f"SiberVatan\\{{emoji_{EMOJI}\\}}")
        analysis = _rtf_analysis(
            br"{\rtf1\ansi{\annotation SiberVatan\{emoji_\u-10179?\u-8704?\}}}",
            pattern,
        )
        flags = [flag for finding in analysis.findings for flag in finding.flags_found]
        self.assertIn(f"SiberVatan{{emoji_{EMOJI}}}", flags)

    def test_txt_report_writes_normalized_supplementary_unicode(self) -> None:
        self._assert_report_writes("txt")

    def test_json_report_writes_normalized_supplementary_unicode(self) -> None:
        self._assert_report_writes("json")

    def test_normal_bmp_unicode_and_fallback_behavior_are_unchanged(self) -> None:
        values = _annotation_values(
            br"{\rtf1\ansi\uc1{\annotation caf\u233\'e9 next}}"
        )
        self.assertIn("café next", values[0])
        self.assertNotIn("'e9", values[0])

    def _assert_report_writes(self, report_format: str) -> None:
        analysis = _rtf_analysis(
            br"{\rtf1\ansi{\annotation face \u-10179?\u-8704?}}"
        )
        result = ToolResult(
            tool_name="document_stego_scanner",
            command=[],
            return_code=0,
            stdout="",
            stderr="",
            flags_found=[],
            elapsed_seconds=0.0,
            document_findings=list(analysis.findings),
        )
        report = ScanReport(
            target_file="synthetic.rtf",
            flag_pattern=DEFAULT_PATTERN.pattern,
            wordlist=None,
            started_at="start",
            finished_at="finish",
            all_flags=[],
            tool_results=[result],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / f"report.{report_format}"
            if report_format == "json":
                write_json_report(report, output)
                json.loads(output.read_text(encoding="utf-8"))
            else:
                write_txt_report(report, output)
            rendered = output.read_text(encoding="utf-8")
        self.assertIn(EMOJI, rendered)


class PPTXHiddenSlideTests(unittest.TestCase):
    def test_slide_root_show_zero_is_hidden(self) -> None:
        analysis = _presentation_analysis(show="0")
        self.assertTrue(any(
            finding.mechanism == "hidden-slide"
            for finding in analysis.findings
        ))

    def test_slide_root_show_one_is_visible(self) -> None:
        analysis = _presentation_analysis(show="1")
        self.assertFalse(any(
            finding.mechanism == "hidden-slide"
            for finding in analysis.findings
        ))

    def test_slide_root_without_show_is_visible(self) -> None:
        analysis = _presentation_analysis()
        self.assertFalse(any(
            finding.mechanism == "hidden-slide"
            for finding in analysis.findings
        ))

    def test_root_relative_slide_relationship_keeps_hidden_state(self) -> None:
        analysis = _presentation_analysis(
            target="/ppt/slides/slide1.xml",
            show="0",
        )
        self.assertTrue(any(
            finding.mechanism == "hidden-slide"
            for finding in analysis.findings
        ))

    def test_relative_slide_relationship_keeps_hidden_state(self) -> None:
        analysis = _presentation_analysis(
            target="slides/slide1.xml",
            show="0",
        )
        self.assertTrue(any(
            finding.mechanism == "hidden-slide"
            for finding in analysis.findings
        ))

    def test_hidden_slide_preserves_custom_regex_flag(self) -> None:
        pattern = re.compile(r"CustomFlag\{.*?\}")
        analysis = _presentation_analysis(
            show="0",
            text="CustomFlag{hidden_slide}",
            pattern=pattern,
        )
        findings = [
            finding for finding in analysis.findings
            if finding.mechanism == "hidden-slide"
        ]
        self.assertTrue(findings)
        self.assertIn("CustomFlag{hidden_slide}", findings[0].flags_found)


if __name__ == "__main__":
    unittest.main()
