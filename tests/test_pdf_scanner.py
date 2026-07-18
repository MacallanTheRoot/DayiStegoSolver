import asyncio
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dayi.tools._plugin import PluginPhase
from dayi.tools.pdf_scanner import (
    PDFDependencies,
    PLUGIN_SPECS,
    run_pdf_scanner,
)


def _write_pdf_fixture(path: Path, marker: bytes = b"fixture") -> None:
    """Write a tiny PDF-signature fixture consumed by the mocked reader."""
    path.write_bytes(b"%PDF-1.7\n%" + marker + b"\n%%EOF\n")


class _FakePage:
    def __init__(self, output: str | BaseException | None) -> None:
        self.output = output

    def extract_text(self) -> str | None:
        if isinstance(self.output, BaseException):
            raise self.output
        return self.output


class _FakeReader:
    def __init__(
        self,
        *,
        metadata: dict[str, str] | None = None,
        pages: list[_FakePage] | None = None,
        encrypted: bool = False,
        decrypt_result: int | BaseException = 1,
    ) -> None:
        self.metadata = metadata
        self.pages = [] if pages is None else pages
        self.is_encrypted = encrypted
        self.decrypt_result = decrypt_result
        self.decrypt_calls: list[str] = []
        self.closed = False

    def decrypt(self, password: str) -> int:
        self.decrypt_calls.append(password)
        if isinstance(self.decrypt_result, BaseException):
            raise self.decrypt_result
        return self.decrypt_result

    def close(self) -> None:
        self.closed = True


class _FakePypdf:
    def __init__(self, reader: _FakeReader) -> None:
        self.reader = reader
        self.calls: list[tuple[Path, bool]] = []

    def PdfReader(self, target: Path, strict: bool = False) -> _FakeReader:
        self.calls.append((Path(target), strict))
        return self.reader


class PDFScannerTests(unittest.TestCase):
    def _run_with_reader(
        self,
        target: Path,
        reader: _FakeReader,
        *,
        progress: list[tuple[int, int | None]] | None = None,
        artifacts: list[str] | None = None,
    ):
        fake_module = _FakePypdf(reader)
        dependencies = PDFDependencies(pypdf=fake_module)
        progress_callback = (
            None
            if progress is None
            else lambda done, total: progress.append((done, total))
        )
        with patch(
            "dayi.tools.pdf_scanner._load_pdf_dependencies",
            return_value=dependencies,
        ):
            result = asyncio.run(
                run_pdf_scanner(
                    target,
                    re.compile(r"FLAG\{.*?\}"),
                    progress_callback=progress_callback,
                    artifact_callback=(
                        None if artifacts is None else artifacts.append
                    ),
                )
            )
        return result, fake_module

    def test_plugin_is_concurrent_with_priority_45(self) -> None:
        self.assertEqual(len(PLUGIN_SPECS), 1)
        plugin = PLUGIN_SPECS[0]
        self.assertEqual(plugin.plugin_id, "pdf_scanner")
        self.assertEqual(plugin.phase, PluginPhase.CONCURRENT)
        self.assertEqual(plugin.priority, 45)
        self.assertTrue(plugin.contributes_to_mini_wordlist)

    def test_non_pdf_skips_before_loading_optional_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "fake.pdf"
            target.write_bytes(b"not a PDF")
            with patch(
                "dayi.tools.pdf_scanner._load_pdf_dependencies",
                side_effect=AssertionError("dependency loader must not run"),
            ):
                result = asyncio.run(
                    run_pdf_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("PDF magic bytes", result.skip_reason)

    def test_missing_optional_dependency_skips_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.pdf"
            _write_pdf_fixture(target)
            with patch(
                "dayi.tools.pdf_scanner._load_pdf_dependencies",
                return_value=None,
            ):
                result = asyncio.run(
                    run_pdf_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("optional pypdf dependency", result.skip_reason)

    def test_oversized_pdf_skips_before_loading_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "large.pdf"
            _write_pdf_fixture(target, marker=b"too-large")
            with (
                patch("dayi.tools.pdf_scanner.MAX_PDF_BYTES", 5),
                patch(
                    "dayi.tools.pdf_scanner._load_pdf_dependencies",
                    side_effect=AssertionError("dependency loader must not run"),
                ),
            ):
                result = asyncio.run(
                    run_pdf_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("exceeds safety limit", result.skip_reason)

    def test_extracts_metadata_text_flags_artifacts_and_progress(self) -> None:
        reader = _FakeReader(
            metadata={
                "/Title": "FLAG{pdf_metadata_success}",
                "/Subject": "next=https://example.org/pdf-stage",
            },
            pages=[
                _FakePage("ordinary first page"),
                _FakePage(
                    "FLAG{pdf_text_success} c2VjcmV0LXBhc3N3b3Jk"
                ),
            ],
        )
        progress: list[tuple[int, int | None]] = []
        messages: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.pdf"
            _write_pdf_fixture(target)
            result, fake_module = self._run_with_reader(
                target,
                reader,
                progress=progress,
                artifacts=messages,
            )

        self.assertFalse(result.skipped)
        self.assertEqual(
            result.flags_found,
            ["FLAG{pdf_metadata_success}", "FLAG{pdf_text_success}"],
        )
        self.assertEqual(progress, [(1, 2), (2, 2)])
        self.assertEqual(
            [finding.artifact_type for finding in result.artifacts_found],
            ["url", "base64"],
        )
        self.assertTrue(any("example.org/pdf-stage" in item for item in messages))
        self.assertTrue(any("secret-password" in item for item in messages))
        self.assertIn("[Metadata]", result.stdout)
        self.assertIn("[Page 2]", result.stdout)
        self.assertEqual(fake_module.calls[0][1], False)
        self.assertTrue(reader.closed)

    def test_empty_password_unlocks_encrypted_pdf(self) -> None:
        reader = _FakeReader(
            pages=[_FakePage("FLAG{empty_password_pdf}")],
            encrypted=True,
            decrypt_result=1,
        )
        messages: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "locked.pdf"
            _write_pdf_fixture(target)
            result, _module = self._run_with_reader(
                target,
                reader,
                artifacts=messages,
            )

        self.assertFalse(result.skipped)
        self.assertEqual(reader.decrypt_calls, [""])
        self.assertEqual(result.flags_found, ["FLAG{empty_password_pdf}"])
        self.assertTrue(any("boş anahtar kapıyı açtı" in item for item in messages))

    def test_nonempty_password_pdf_skips_gracefully(self) -> None:
        reader = _FakeReader(encrypted=True, decrypt_result=0)
        messages: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "locked.pdf"
            _write_pdf_fixture(target)
            result, _module = self._run_with_reader(
                target,
                reader,
                artifacts=messages,
            )

        self.assertTrue(result.skipped)
        self.assertIn("rejects the empty password", result.skip_reason)
        self.assertTrue(any("PDF kilitli çıktı" in item for item in messages))
        self.assertTrue(reader.closed)

    def test_bad_page_does_not_hide_later_page_flag(self) -> None:
        reader = _FakeReader(
            pages=[
                _FakePage(RuntimeError("broken content stream")),
                _FakePage("FLAG{pdf_partial_success}"),
            ]
        )
        progress: list[tuple[int, int | None]] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "partial.pdf"
            _write_pdf_fixture(target)
            result, _module = self._run_with_reader(
                target,
                reader,
                progress=progress,
            )

        self.assertEqual(result.flags_found, ["FLAG{pdf_partial_success}"])
        self.assertIn("page 1: RuntimeError", result.stderr)
        self.assertEqual(progress, [(1, 2), (2, 2)])

    def test_page_limit_bounds_extraction(self) -> None:
        reader = _FakeReader(
            pages=[
                _FakePage("FLAG{within_pdf_page_limit}"),
                _FakePage("FLAG{outside_pdf_page_limit}"),
            ]
        )
        progress: list[tuple[int, int | None]] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "many-pages.pdf"
            _write_pdf_fixture(target)
            with patch("dayi.tools.pdf_scanner.MAX_PAGES", 1):
                result, _module = self._run_with_reader(
                    target,
                    reader,
                    progress=progress,
                )

        self.assertEqual(result.flags_found, ["FLAG{within_pdf_page_limit}"])
        self.assertNotIn("outside_pdf_page_limit", result.stdout)
        self.assertIn("scanning 1 of 2 pages", result.stderr)
        self.assertEqual(progress, [(1, 1)])

    @unittest.skipUnless(
        importlib.util.find_spec("pypdf") is not None,
        "optional pypdf dependency is not installed",
    )
    def test_real_pypdf_generated_metadata_fixture(self) -> None:
        from pypdf import PdfWriter

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "generated.pdf"
            writer = PdfWriter()
            writer.add_blank_page(width=72, height=72)
            writer.add_metadata(
                {
                    "/Title": "FLAG{real_pypdf_metadata_success}",
                    "/Subject": "https://example.org/real-pdf-stage",
                }
            )
            with target.open("wb") as output:
                writer.write(output)

            result = asyncio.run(
                run_pdf_scanner(target, re.compile(r"FLAG\{.*?\}"))
            )

        self.assertFalse(result.skipped)
        self.assertEqual(
            result.flags_found,
            ["FLAG{real_pypdf_metadata_success}"],
        )
        self.assertTrue(
            any(
                finding.preview == "https://example.org/real-pdf-stage"
                for finding in result.artifacts_found
            )
        )


if __name__ == "__main__":
    unittest.main()
