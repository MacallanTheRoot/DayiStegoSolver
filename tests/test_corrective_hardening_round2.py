import asyncio
import importlib.util
import multiprocessing
import re
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from dayi import integrations
from dayi.document import analyze_document
from dayi.document.openxml import _Styles, _run_properties
from dayi.document.rtf import (
    UnsafeRTF,
    _consume_rtf_fallback_token,
    analyze_rtf_document,
)
from dayi.image_analysis import MAX_DECODED_PIXELS
from dayi.text_stego import (
    MAX_ANALYSIS_CHARACTERS,
    MAX_CANDIDATE_OUTPUT,
    MAX_DIRECT_FLAGS,
    _Collector,
    analyze_text_input,
    detect_text_bytes,
)
from dayi.tools import qr_scanner


PATTERN = re.compile(r"SiberVatan\{.*?\}")
WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


class _Array:
    def __init__(self, height: int, width: int, channels: int = 3):
        self.shape = (height, width, channels) if channels > 1 else (height, width)


class _CV2:
    COLOR_BGR2GRAY = 1
    THRESH_BINARY = 2
    THRESH_OTSU = 4
    INTER_CUBIC = 8
    ROTATE_90_CLOCKWISE = 9
    ROTATE_180 = 10
    ROTATE_90_COUNTERCLOCKWISE = 11

    @staticmethod
    def cvtColor(image, _mode):
        return _Array(image.shape[0], image.shape[1], 1)

    @staticmethod
    def bitwise_not(image):
        return _Array(image.shape[0], image.shape[1], 1)

    @staticmethod
    def threshold(image, *_args):
        return 0, _Array(image.shape[0], image.shape[1], 1)

    @staticmethod
    def resize(image, _size, *, fx, fy, interpolation):
        del interpolation
        return _Array(int(image.shape[0] * fy), int(image.shape[1] * fx), 3)

    @staticmethod
    def rotate(image, _rotation):
        return _Array(image.shape[1], image.shape[0], 3)


def _slow_notification_worker(*_args):
    time.sleep(5.0)


def _notification_response_worker(*_args):
    return integrations._HttpResponse(
        200,
        b'{"data":{"status":"correct"}}',
        False,
    )


def _write_zip(path: Path, members: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    return path


def _relationships(rel_id: str, target: str, rel_type: str) -> str:
    return (
        f'<Relationships xmlns="{REL_NS}">'
        f'<Relationship Id="{rel_id}" Type="{OFFICE_REL}/{rel_type}" '
        f'Target="{target}"/></Relationships>'
    )


def _xlsx(path: Path, target: str) -> Path:
    return _write_zip(path, {
        "[Content_Types].xml": (
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.'
            'spreadsheetml.sheet.main+xml"/></Types>'
        ),
        "_rels/.rels": _relationships("root", "xl/workbook.xml", "officeDocument"),
        "xl/workbook.xml": (
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            f'xmlns:r="{OFFICE_REL}"><sheets><sheet name="Hidden" sheetId="1" '
            'state="veryHidden" r:id="rId1"/></sheets></workbook>'
        ),
        "xl/_rels/workbook.xml.rels": _relationships(
            "rId1", target, "worksheet"
        ),
        "xl/worksheets/sheet1.xml": (
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData><row><c r="A1" t="inlineStr"><is><t>'
            'ordinary hidden value</t></is></c></row></sheetData></worksheet>'
        ),
    })


def _pptx(path: Path, target: str) -> Path:
    return _write_zip(path, {
        "[Content_Types].xml": (
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/ppt/presentation.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.'
            'presentationml.presentation.main+xml"/></Types>'
        ),
        "_rels/.rels": _relationships("root", "ppt/presentation.xml", "officeDocument"),
        "ppt/presentation.xml": (
            '<p:presentation xmlns:p="http://schemas.openxmlformats.org/'
            f'presentationml/2006/main" xmlns:r="{OFFICE_REL}"><p:sldIdLst>'
            '<p:sldId id="1" r:id="rId1"/></p:sldIdLst></p:presentation>'
        ),
        "ppt/_rels/presentation.xml.rels": _relationships(
            "rId1", target, "slide"
        ),
        "ppt/slides/slide1.xml": (
            '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" show="0">'
            '<a:t>ordinary hidden slide text</a:t></p:sld>'
        ),
    })


class QRVariantBudgetTests(unittest.TestCase):
    def test_opencv_variants_are_lazy_and_budgeted(self) -> None:
        budget_type = getattr(qr_scanner, "_QRVariantBudget", None)
        self.assertIsNotNone(budget_type)
        image = _Array(1000, 1000)
        budget = budget_type(max_variants=16, max_generated_pixels=2_000_000)
        variants = qr_scanner._opencv_variants(_CV2, image, budget=budget)
        self.assertIs(iter(variants), variants)
        names = [name for name, _variant in variants]
        self.assertEqual(names[:2], ["original", "grayscale"])
        self.assertLess(len(names), 8)
        self.assertLessEqual(budget.generated_pixels, 2_000_000)

    def test_near_limit_image_does_not_generate_every_transform(self) -> None:
        budget_type = getattr(qr_scanner, "_QRVariantBudget", None)
        self.assertIsNotNone(budget_type)
        image = _Array(5000, 9999)
        budget = budget_type()
        names = [
            name for name, _variant in
            qr_scanner._opencv_variants(_CV2, image, budget=budget)
        ]
        self.assertLess(len(names), qr_scanner.MAX_QR_VARIANTS_PER_IMAGE)
        self.assertLessEqual(image.shape[0] * image.shape[1], MAX_DECODED_PIXELS)
        self.assertLessEqual(budget.generated_pixels, budget.max_generated_pixels)

    def test_small_image_variant_order_keeps_inversion_scaling_and_rotation(self) -> None:
        names = [
            name for name, _variant in
            qr_scanner._opencv_variants(_CV2, _Array(100, 100))
        ]
        self.assertEqual(
            names[:7],
            [
                "original", "grayscale", "inverted", "threshold",
                "scale-2x", "scale-4x", "rot90",
            ],
        )

    @unittest.skipUnless(
        importlib.util.find_spec("PIL"), "Pillow is optional"
    )
    def test_pillow_variants_are_lazy_and_share_the_same_budget(self) -> None:
        from PIL import Image, ImageOps

        image = Image.new("RGB", (100, 100), "white")
        budget = qr_scanner._QRVariantBudget(
            max_variants=3,
            max_generated_pixels=20_000,
        )
        variants = qr_scanner._pillow_qr_variants(
            image, Image, ImageOps, budget=budget
        )
        self.assertIs(iter(variants), variants)
        self.assertEqual(
            [name for name, _variant in variants],
            ["original", "grayscale", "autocontrast"],
        )
        image.close()


class UrllibDeadlineTests(unittest.TestCase):
    def test_isolated_urllib_deadline_reaps_worker(self) -> None:
        runner = getattr(integrations, "_run_urllib_post_isolated", None)
        self.assertIsNotNone(runner)
        before = {child.pid for child in multiprocessing.active_children()}
        started = time.monotonic()
        with self.assertRaises(asyncio.TimeoutError):
            asyncio.run(runner(
                "https://ctfd.invalid/api/v1/challenges/attempt",
                {"challenge_id": 1, "submission": "SiberVatan{redacted}"},
                {"Authorization": "Token redacted"},
                True,
                timeout=0.05,
                worker=_slow_notification_worker,
            ))
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(
            {child.pid for child in multiprocessing.active_children()}, before
        )

    def test_isolated_urllib_normal_response_remains_bounded(self) -> None:
        runner = getattr(integrations, "_run_urllib_post_isolated", None)
        self.assertIsNotNone(runner)
        response = asyncio.run(runner(
            "https://ctfd.invalid/api/v1/challenges/attempt",
            {"challenge_id": 1, "submission": "SiberVatan{redacted}"},
            {"Authorization": "Token redacted"},
            True,
            timeout=1.0,
            worker=_notification_response_worker,
        ))
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(response.body or b""), integrations.CTFD_RESPONSE_LIMIT)

    def test_isolated_urllib_cancellation_is_not_swallowed(self) -> None:
        before = {child.pid for child in multiprocessing.active_children()}

        async def cancel_request() -> None:
            task = asyncio.create_task(integrations._run_urllib_post_isolated(
                "https://ctfd.invalid/api/v1/challenges/attempt",
                {"challenge_id": 1, "submission": "SiberVatan{redacted}"},
                {"Authorization": "Token redacted"},
                True,
                timeout=5.0,
                worker=_slow_notification_worker,
            ))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(cancel_request())
        self.assertEqual(
            {child.pid for child in multiprocessing.active_children()}, before
        )


class LateFlagTests(unittest.TestCase):
    @staticmethod
    def _collect_direct(text: str, pattern: re.Pattern = PATTERN):
        collector = _Collector(pattern)
        collector.add(
            text,
            ("source_decode", "utf-8"),
            "direct-decoded-text",
            depth=1,
            evidence=("active-flag-regex",),
            source="source",
        )
        return collector.finish()

    def test_direct_flag_after_candidate_prefix_is_preserved(self) -> None:
        flag = "SiberVatan{late_direct_flag}"
        text = "ordinary prose " + "x" * MAX_CANDIDATE_OUTPUT + flag
        analysis = analyze_text_input(detect_text_bytes(text.encode()), PATTERN)
        confirmed = [
            candidate for candidate in analysis.candidates
            if flag in candidate.flags_found
            and candidate.decoder.startswith("source_decode")
        ]
        self.assertTrue(confirmed)
        self.assertLessEqual(len(confirmed[0].value), MAX_CANDIDATE_OUTPUT)

    def test_long_ordinary_text_does_not_create_a_flag(self) -> None:
        text = ("This is ordinary local text. " * 4000)[:200_000]
        analysis = analyze_text_input(detect_text_bytes(text.encode()), PATTERN)
        self.assertFalse(any(item.flags_found for item in analysis.candidates))

    def test_late_flags_are_bounded_deduplicated_and_near_limit_safe(self) -> None:
        flag = "SiberVatan{near_analysis_limit}"
        text = "x" * (MAX_ANALYSIS_CHARACTERS - len(flag) - 1) + flag
        candidates = self._collect_direct(text)
        self.assertEqual(candidates[0].flags_found, (flag,))
        self.assertLessEqual(len(candidates[0].value), MAX_CANDIDATE_OUTPUT)

        flags = [f"SiberVatan{{bounded_{index}}}" for index in range(80)]
        many = "x" * (MAX_CANDIDATE_OUTPUT + 1) + " ".join(flags + flags)
        found = self._collect_direct(many)[0].flags_found
        self.assertEqual(len(found), MAX_DIRECT_FLAGS)
        self.assertEqual(len(found), len(set(found)))

    def test_oversized_direct_flag_is_not_reported_as_a_truncated_flag(self) -> None:
        oversized = "SiberVatan{" + "x" * 3000 + "}"
        candidates = self._collect_direct(oversized)
        self.assertFalse(any(item.flags_found for item in candidates))


class WordStylePrecedenceTests(unittest.TestCase):
    def test_paragraph_style_is_not_overwritten_without_run_style(self) -> None:
        styles = ElementTree.fromstring(
            f'<w:styles xmlns:w="{WORD_NS}">'
            '<w:docDefaults><w:rPrDefault><w:rPr><w:sz w:val="22"/>'
            '</w:rPr></w:rPrDefault></w:docDefaults>'
            '<w:style w:type="paragraph" w:styleId="Zero">'
            '<w:rPr><w:sz w:val="0"/></w:rPr></w:style></w:styles>'
        )
        paragraph = ElementTree.fromstring(
            f'<w:p xmlns:w="{WORD_NS}"><w:pPr><w:pStyle w:val="Zero"/>'
            '</w:pPr><w:r><w:t>hidden</w:t></w:r></w:p>'
        )
        run = next(node for node in paragraph if node.tag.endswith("}r"))
        properties = _run_properties(run, _Styles(styles), paragraph)
        self.assertEqual(properties["sz"], "0")

    def test_explicit_run_style_and_properties_keep_precedence(self) -> None:
        styles = ElementTree.fromstring(
            f'<w:styles xmlns:w="{WORD_NS}">'
            '<w:docDefaults><w:rPrDefault><w:rPr><w:sz w:val="22"/>'
            '</w:rPr></w:rPrDefault></w:docDefaults>'
            '<w:style w:type="paragraph" w:styleId="Small">'
            '<w:rPr><w:sz w:val="2"/></w:rPr></w:style>'
            '<w:style w:type="character" w:styleId="Large">'
            '<w:rPr><w:sz w:val="30"/></w:rPr></w:style></w:styles>'
        )
        paragraph = ElementTree.fromstring(
            f'<w:p xmlns:w="{WORD_NS}"><w:pPr><w:pStyle w:val="Small"/>'
            '</w:pPr><w:r><w:rPr><w:rStyle w:val="Large"/><w:sz w:val="4"/>'
            '</w:rPr><w:t>text</w:t></w:r></w:p>'
        )
        run = next(node for node in paragraph if node.tag.endswith("}r"))
        self.assertEqual(_run_properties(run, _Styles(styles), paragraph)["sz"], "4")


class RootRelativeRelationshipTests(unittest.TestCase):
    def test_root_relative_xlsx_target_preserves_very_hidden_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis = analyze_document(
                _xlsx(root / "book.bin", "/xl/worksheets/sheet1.xml"),
                PATTERN,
                workspace=root / "workspace",
            )
        self.assertTrue(any(
            finding.mechanism == "veryhidden-sheet"
            for finding in analysis.findings
        ))

    def test_root_relative_pptx_target_preserves_hidden_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            analysis = analyze_document(
                _pptx(root / "deck.bin", "/ppt/slides/slide1.xml"),
                PATTERN,
                workspace=root / "workspace",
            )
        self.assertTrue(any(
            finding.mechanism == "hidden-slide"
            for finding in analysis.findings
        ))


class RTFFallbackTests(unittest.TestCase):
    def _visible_text(self, payload: bytes) -> str:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "sample.rtf"
            path.write_bytes(payload)
            analysis = analyze_rtf_document(
                path, re.compile(r".+"), workspace=root / "workspace"
            )
        return "".join(
            finding.value for finding in analysis.findings
            if finding.category == "visible_text"
        )

    def test_hex_fallback_is_consumed_as_one_rtf_character(self) -> None:
        visible = self._visible_text(br"{\rtf1\ansi\uc1 \u233\'e9 next}")
        self.assertIn("é next", visible)
        self.assertNotIn("'e9", visible)

    def test_uc_zero_and_multiple_complete_fallback_tokens(self) -> None:
        no_skip = self._visible_text(br"{\rtf1\ansi\uc0 \u233?}")
        self.assertIn("é?", no_skip)
        two = self._visible_text(br"{\rtf1\ansi\uc2 \u233\{\'e9 next}")
        self.assertIn("é next", two)
        self.assertNotIn("'e9", two)

    def test_literal_brace_backslash_and_malformed_fallback_tokens(self) -> None:
        self.assertEqual(_consume_rtf_fallback_token(b"?next", 0), 1)
        self.assertEqual(_consume_rtf_fallback_token(br"\{next", 0), 2)
        self.assertEqual(_consume_rtf_fallback_token(br"\\next", 0), 2)
        with self.assertRaises(UnsafeRTF):
            _consume_rtf_fallback_token(br"\'zz", 0)

    def test_unicode_flag_survives_hex_fallback_removal(self) -> None:
        pattern = re.compile(r"SiberVatan\{café\}")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "unicode-flag.rtf"
            path.write_bytes(
                br"{\rtf1\ansi\uc1 SiberVatan\{caf\u233\'e9\}}"
            )
            analysis = analyze_rtf_document(
                path, pattern, workspace=root / "workspace"
            )
        self.assertIn(
            "SiberVatan{café}",
            [flag for finding in analysis.findings for flag in finding.flags_found],
        )


if __name__ == "__main__":
    unittest.main()
