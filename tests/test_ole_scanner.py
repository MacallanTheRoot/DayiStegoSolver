import asyncio
import importlib.util
import re
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from dayi.tools._plugin import PluginPhase
from dayi.tools.ole_scanner import (
    MAX_MACRO_BYTES,
    OLEDependencies,
    PLUGIN_SPECS,
    _extract_ole_sync,
    run_ole_scanner,
)

_OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")


def _write_ole_fixture(path: Path, marker: bytes = b"fixture") -> None:
    """Write an OLE-signature fixture consumed by the mocked parser."""
    path.write_bytes(_OLE_MAGIC + marker)


def _write_macro_free_openxml_fixture(path: Path) -> None:
    """Generate a minimal, inert Word OpenXML container using stdlib ZIP."""
    content_types = b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
    relationships = b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
    document = b"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Safe fixture</w:t></w:r></w:p></w:body>
</w:document>"""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", relationships)
        archive.writestr("word/document.xml", document)


def _oletools_available() -> bool:
    try:
        return importlib.util.find_spec("oletools.olevba") is not None
    except ModuleNotFoundError:
        return False


class _FakeParser:
    def __init__(
        self,
        *,
        parser_type: str = "OLE",
        macros_detected: bool | BaseException = True,
        macro_records: list[object] | BaseException | None = None,
    ) -> None:
        self.type = parser_type
        self.macros_detected = macros_detected
        self.macro_records = [] if macro_records is None else macro_records
        self.detect_calls = 0
        self.extract_calls = 0
        self.closed = False

    def detect_vba_macros(self) -> bool:
        self.detect_calls += 1
        if isinstance(self.macros_detected, BaseException):
            raise self.macros_detected
        return self.macros_detected

    def extract_macros(self):
        self.extract_calls += 1
        if isinstance(self.macro_records, BaseException):
            raise self.macro_records
        return iter(self.macro_records)

    def close(self) -> None:
        self.closed = True


class _FakeOlevba:
    TYPE_OLE = "OLE"
    TYPE_OpenXML = "OpenXML"

    def __init__(self, parser: _FakeParser | BaseException) -> None:
        self.parser = parser
        self.calls: list[str] = []

    def VBA_Parser(self, filename: str) -> _FakeParser:
        self.calls.append(filename)
        if isinstance(self.parser, BaseException):
            raise self.parser
        return self.parser


class OLEScannerTests(unittest.TestCase):
    def _run_with_parser(
        self,
        target: Path,
        parser: _FakeParser | BaseException,
        *,
        progress: list[tuple[int, int | None]] | None = None,
        artifacts: list[str] | None = None,
    ):
        fake_module = _FakeOlevba(parser)
        dependencies = OLEDependencies(olevba=fake_module)
        progress_callback = (
            None
            if progress is None
            else lambda done, total: progress.append((done, total))
        )
        with patch(
            "dayi.tools.ole_scanner._load_ole_dependencies",
            return_value=dependencies,
        ):
            result = asyncio.run(
                run_ole_scanner(
                    target,
                    re.compile(r"FLAG\{.*?\}"),
                    progress_callback=progress_callback,
                    artifact_callback=(
                        None if artifacts is None else artifacts.append
                    ),
                )
            )
        return result, fake_module

    def test_plugin_is_concurrent_with_priority_46(self) -> None:
        self.assertEqual(len(PLUGIN_SPECS), 1)
        plugin = PLUGIN_SPECS[0]
        self.assertEqual(plugin.plugin_id, "ole_scanner")
        self.assertEqual(plugin.phase, PluginPhase.CONCURRENT)
        self.assertEqual(plugin.priority, 46)
        self.assertTrue(plugin.contributes_to_mini_wordlist)

    def test_non_office_file_skips_before_loading_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "plain.txt"
            target.write_text("not an Office file", encoding="utf-8")
            with patch(
                "dayi.tools.ole_scanner._load_ole_dependencies",
                side_effect=AssertionError("dependency loader must not run"),
            ):
                result = asyncio.run(
                    run_ole_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("not an OLE or ZIP-based OpenXML", result.skip_reason)

    def test_missing_optional_dependency_skips_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.doc"
            _write_ole_fixture(target)
            with patch(
                "dayi.tools.ole_scanner._load_ole_dependencies",
                return_value=None,
            ):
                result = asyncio.run(
                    run_ole_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("optional oletools dependency", result.skip_reason)

    def test_unsupported_parser_type_skips_and_closes(self) -> None:
        parser = _FakeParser(parser_type="MHTML")
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.doc"
            _write_ole_fixture(target)
            result, _module = self._run_with_parser(target, parser)

        self.assertTrue(result.skipped)
        self.assertIn("unsupported olevba parser type", result.skip_reason)
        self.assertTrue(parser.closed)

    def test_parser_exception_skips_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "broken.doc"
            _write_ole_fixture(target)
            result, _module = self._run_with_parser(
                target,
                ValueError("unsupported file type"),
            )

        self.assertTrue(result.skipped)
        self.assertIn("OLE/VBA parsing failed", result.skip_reason)

    def test_supported_macro_free_document_returns_clean_result(self) -> None:
        parser = _FakeParser(macros_detected=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "clean.doc"
            _write_ole_fixture(target)
            result, fake_module = self._run_with_parser(target, parser)

        self.assertFalse(result.skipped)
        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.flags_found, [])
        self.assertIn("VBA macros detected: no", result.stdout)
        self.assertEqual(parser.extract_calls, 0)
        self.assertEqual(fake_module.calls, [str(target)])
        self.assertTrue(parser.closed)

    def test_extracts_macro_flags_artifacts_and_progress(self) -> None:
        parser = _FakeParser(
            macro_records=[
                (
                    "word/vbaProject.bin",
                    "VBA/Module1",
                    "Module1.bas",
                    "Sub AutoOpen()\n' FLAG{ole_macro_success}\n"
                    "x = \"https://example.org/macro-stage\"\nEnd Sub",
                ),
                (
                    "word/vbaProject.bin",
                    "VBA/Module2",
                    "Module2.bas",
                    b"x = \"c2VjcmV0LW1hY3JvLXBhc3M=\"",
                ),
            ]
        )
        progress: list[tuple[int, int | None]] = []
        messages: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "macro.docm"
            _write_macro_free_openxml_fixture(target)
            result, _module = self._run_with_parser(
                target,
                parser,
                progress=progress,
                artifacts=messages,
            )

        self.assertFalse(result.skipped)
        self.assertEqual(result.flags_found, ["FLAG{ole_macro_success}"])
        self.assertEqual(progress, [(1, None), (2, None)])
        self.assertEqual(
            [finding.artifact_type for finding in result.artifacts_found],
            ["url", "base64"],
        )
        self.assertTrue(any("2 kaynak modülü" in item for item in messages))
        self.assertTrue(any("example.org/macro-stage" in item for item in messages))
        self.assertTrue(any("secret-macro-pass" in item for item in messages))
        self.assertIn("[Macro 1]", result.stdout)
        self.assertIn("Module2.bas", result.stdout)
        self.assertTrue(parser.closed)

    def test_invalid_macro_tuple_does_not_hide_later_macro(self) -> None:
        parser = _FakeParser(
            macro_records=[
                ("too", "short"),
                ("file", "stream", "Good.bas", "FLAG{ole_partial_success}"),
            ]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "partial.doc"
            _write_ole_fixture(target)
            result, _module = self._run_with_parser(target, parser)

        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.flags_found, ["FLAG{ole_partial_success}"])
        self.assertIn("invalid extract_macros tuple", result.stderr)

    def test_macro_limit_bounds_extraction(self) -> None:
        parser = _FakeParser(
            macro_records=[
                ("file", "stream1", "One.bas", "FLAG{inside_macro_limit}"),
                ("file", "stream2", "Two.bas", "FLAG{outside_macro_limit}"),
            ]
        )
        progress: list[tuple[int, int | None]] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "many.doc"
            _write_ole_fixture(target)
            with patch("dayi.tools.ole_scanner.MAX_MACROS", 1):
                result, _module = self._run_with_parser(
                    target,
                    parser,
                    progress=progress,
                )

        self.assertEqual(result.flags_found, ["FLAG{inside_macro_limit}"])
        self.assertNotIn("outside_macro_limit", result.stdout)
        self.assertIn("macro limit reached (1)", result.stderr)
        self.assertEqual(progress, [(1, None)])

    def test_combined_macro_source_is_truncated_at_512_kib(self) -> None:
        hidden_after_limit = "FLAG{outside_byte_limit}"
        parser = _FakeParser(
            macro_records=[
                ("file", "stream1", "One.bas", "A" * (MAX_MACRO_BYTES - 4)),
                (
                    "file",
                    "stream2",
                    "Two.bas",
                    "ç" * 8 + hidden_after_limit,
                ),
            ]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "bounded.doc"
            _write_ole_fixture(target)
            extraction = _extract_ole_sync(
                target,
                OLEDependencies(olevba=_FakeOlevba(parser)),
                timeout=60.0,
                progress_callback=None,
            )

        self.assertLessEqual(
            len(extraction.macro_text.encode("utf-8")),
            MAX_MACRO_BYTES,
        )
        self.assertNotIn(hidden_after_limit, extraction.macro_text)
        self.assertTrue(
            any(
                f"combined VBA source truncated at {MAX_MACRO_BYTES} bytes"
                in error
                for error in extraction.errors
            )
        )
        self.assertTrue(parser.closed)

    def test_oversized_office_file_skips_before_loading_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "large.doc"
            _write_ole_fixture(target, marker=b"too-large")
            with (
                patch("dayi.tools.ole_scanner.MAX_OFFICE_BYTES", 8),
                patch(
                    "dayi.tools.ole_scanner._load_ole_dependencies",
                    side_effect=AssertionError("dependency loader must not run"),
                ),
            ):
                result = asyncio.run(
                    run_ole_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("exceeds safety limit", result.skip_reason)

    def test_openxml_expanded_size_limit_blocks_zip_bomb_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "oversized.docm"
            with zipfile.ZipFile(
                target, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                archive.writestr("word/document.xml", b"A" * 32)
            with (
                patch(
                    "dayi.tools.ole_scanner.MAX_OPENXML_UNCOMPRESSED_BYTES",
                    16,
                ),
                patch(
                    "dayi.tools.ole_scanner._load_ole_dependencies",
                    side_effect=AssertionError("dependency loader must not run"),
                ),
            ):
                result = asyncio.run(
                    run_ole_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("OpenXML expanded size", result.skip_reason)

    @unittest.skipUnless(
        _oletools_available(),
        "optional oletools dependency is not installed",
    )
    def test_real_oletools_generated_macro_free_openxml_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "generated.docx"
            _write_macro_free_openxml_fixture(target)
            result = asyncio.run(
                run_ole_scanner(target, re.compile(r"FLAG\{.*?\}"))
            )

        self.assertFalse(result.skipped)
        self.assertEqual(result.return_code, 0)
        self.assertIn("VBA macros detected: no", result.stdout)


if __name__ == "__main__":
    unittest.main()
