import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from dayi import reporter
from dayi.ctfshit_resolver import CtfshitResolution
from dayi.reporter import ScanReport, ToolResult, export_markdown_writeup


def _report() -> ScanReport:
    tool_result = ToolResult(
        tool_name="strings",
        command=["strings", "odd target!.jpg"],
        return_code=0,
        stdout="target evidence",
        stderr="",
        flags_found=["CTF{reporter_resolver}"],
        elapsed_seconds=0.1,
    )
    return ScanReport(
        target_file="/fixtures/odd target!.jpg",
        flag_pattern=r"CTF\{.*?\}",
        wordlist=None,
        started_at="2026-07-19T12:00:00",
        finished_at="2026-07-19T12:00:01",
        all_flags=["CTF{reporter_resolver}"],
        tool_results=[tool_result],
    )


def _resolution(
    *,
    available: bool,
    source_kind: str = "unavailable",
    status_code: str = "not-found",
    exporter=None,
) -> CtfshitResolution:
    return CtfshitResolution(
        available=available,
        source_kind=source_kind,
        status_code=status_code,
        exporter=exporter,
        safe_detail="deterministic test resolution",
    )


class ReporterResolverIntegrationTests(unittest.TestCase):
    def test_available_exporter_receives_workspace_output_and_project_root(self) -> None:
        observed: dict[str, object] = {}

        def exporter(*, workspace_root: Path, output_file: Path):
            observed["workspace_root"] = workspace_root
            observed["output_file"] = output_file
            challenge_dir = workspace_root / "odd_target_"
            observed["metadata"] = json.loads(
                (challenge_dir / ".challenge.json").read_text(encoding="utf-8")
            )
            observed["notes"] = (challenge_dir / "notes.txt").read_text(
                encoding="utf-8"
            )
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text("rich exporter output", encoding="utf-8")
            return True, 1, {"Steganography": 1}

        resolution = _resolution(
            available=True,
            source_kind="installed",
            status_code="ok",
            exporter=exporter,
        )
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "dayi.reporter.resolve_writeup_exporter",
            return_value=resolution,
        ) as resolver:
            requested = Path(tmpdir) / "nested" / "writeup.txt"
            result = export_markdown_writeup(_report(), requested)
            normalized = requested.with_suffix(".md")

            self.assertIsNone(result)
            self.assertEqual(normalized.read_text(encoding="utf-8"), "rich exporter output")
            resolver.assert_called_once_with(
                explicit_path=None,
                project_root=reporter._DAYI_PROJECT_ROOT,
            )

        self.assertEqual(observed["output_file"], normalized)
        self.assertFalse(Path(observed["workspace_root"]).exists())
        self.assertEqual(
            observed["metadata"],
            {
                "name": "odd target!.jpg",
                "category": "Steganography",
                "solved": True,
                "flag": "CTF{reporter_resolver}",
                "points": 0,
            },
        )
        self.assertIn("CTF{reporter_resolver}", observed["notes"])
        self.assertIn("target evidence", observed["notes"])
        self.assertTrue((reporter._DAYI_PROJECT_ROOT / "pyproject.toml").is_file())
        self.assertTrue((reporter._DAYI_PROJECT_ROOT / "dayi").is_dir())

    def test_unavailable_resolution_uses_real_builtin_fallback(self) -> None:
        resolution = _resolution(available=False)
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "dayi.reporter.resolve_writeup_exporter",
            return_value=resolution,
        ):
            output = Path(tmpdir) / "nested" / "writeup.md"
            export_markdown_writeup(_report(), output)

            rendered = output.read_text(encoding="utf-8")

        self.assertIn("# CTF Writeups", rendered)
        self.assertIn("odd target\\!\\.jpg", rendered)
        self.assertIn("CTF\\{reporter\\_resolver\\}", rendered)

    def test_explicit_path_is_passed_unchanged_to_resolver(self) -> None:
        resolution = _resolution(available=False)
        configured_path = Path("relative-ctfshit-checkout")
        with patch(
            "dayi.reporter.resolve_writeup_exporter",
            return_value=resolution,
        ) as resolver, patch("dayi.reporter._fallback_markdown"):
            export_markdown_writeup(
                _report(),
                Path("writeup.md"),
                ctfshit_path=configured_path,
            )

        resolver.assert_called_once_with(
            explicit_path=configured_path,
            project_root=reporter._DAYI_PROJECT_ROOT,
        )

    def test_invalid_explicit_path_warns_without_disclosing_path_or_running_exporter(self) -> None:
        exporter = Mock(side_effect=AssertionError("must not be invoked"))
        resolution = _resolution(
            available=False,
            source_kind="explicit-path",
            status_code="invalid-path",
            exporter=exporter,
        )
        secret_path = Path("/private/example/ctfshitcli")
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "dayi.reporter.resolve_writeup_exporter",
            return_value=resolution,
        ):
            output = Path(tmpdir) / "writeup.md"
            with self.assertLogs("dayi", level="WARNING") as captured:
                export_markdown_writeup(
                    _report(),
                    output,
                    ctfshit_path=secret_path,
                )
            rendered = output.read_text(encoding="utf-8")

        exporter.assert_not_called()
        self.assertIn("# CTF Writeups", rendered)
        self.assertIn("yerleşik Markdown", "\n".join(captured.output))
        self.assertNotIn(str(secret_path), "\n".join(captured.output))

    def test_direct_call_without_path_remains_compatible(self) -> None:
        resolution = _resolution(available=False)
        with patch(
            "dayi.reporter.resolve_writeup_exporter",
            return_value=resolution,
        ) as resolver, patch("dayi.reporter._fallback_markdown"):
            export_markdown_writeup(_report(), Path("writeup.md"))

        resolver.assert_called_once_with(
            explicit_path=None,
            project_root=reporter._DAYI_PROJECT_ROOT,
        )

    def test_invalid_path_resolution_uses_fallback(self) -> None:
        resolution = _resolution(
            available=False,
            source_kind="explicit-path",
            status_code="invalid-path",
        )
        with patch(
            "dayi.reporter.resolve_writeup_exporter", return_value=resolution
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            export_markdown_writeup(_report(), Path("writeup.md"))

        fallback.assert_called_once()

    def test_import_failed_resolution_uses_fallback(self) -> None:
        resolution = _resolution(
            available=False,
            source_kind="installed",
            status_code="import-failed",
        )
        with patch(
            "dayi.reporter.resolve_writeup_exporter", return_value=resolution
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            export_markdown_writeup(_report(), Path("writeup.md"))

        fallback.assert_called_once()

    def test_resolver_runtime_exception_uses_fallback(self) -> None:
        with patch(
            "dayi.reporter.resolve_writeup_exporter",
            side_effect=RuntimeError("resolver failure"),
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            export_markdown_writeup(_report(), Path("writeup.md"))

        fallback.assert_called_once()

    def test_exporter_runtime_exception_uses_fallback(self) -> None:
        exporter = Mock(side_effect=RuntimeError("export failure"))
        resolution = _resolution(
            available=True,
            source_kind="installed",
            status_code="ok",
            exporter=exporter,
        )
        with patch(
            "dayi.reporter.resolve_writeup_exporter", return_value=resolution
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            export_markdown_writeup(_report(), Path("writeup.md"))

        exporter.assert_called_once()
        fallback.assert_called_once()

    def test_exporter_false_result_uses_fallback(self) -> None:
        exporter = Mock(return_value=(False, 0, {}))
        resolution = _resolution(
            available=True,
            source_kind="installed",
            status_code="ok",
            exporter=exporter,
        )
        with patch(
            "dayi.reporter.resolve_writeup_exporter", return_value=resolution
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            export_markdown_writeup(_report(), Path("writeup.md"))

        exporter.assert_called_once()
        fallback.assert_called_once()

    def test_non_callable_exporter_is_not_invoked(self) -> None:
        resolution = _resolution(
            available=True,
            source_kind="installed",
            status_code="ok",
            exporter="not callable",
        )
        with patch(
            "dayi.reporter.resolve_writeup_exporter", return_value=resolution
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            export_markdown_writeup(_report(), Path("writeup.md"))

        fallback.assert_called_once()

    def test_unavailable_callable_exporter_is_not_invoked(self) -> None:
        exporter = Mock(side_effect=AssertionError("must not be invoked"))
        resolution = _resolution(available=False, exporter=exporter)
        with patch(
            "dayi.reporter.resolve_writeup_exporter", return_value=resolution
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            export_markdown_writeup(_report(), Path("writeup.md"))

        exporter.assert_not_called()
        fallback.assert_called_once()

    def test_keyboard_interrupt_from_resolver_propagates(self) -> None:
        with patch(
            "dayi.reporter.resolve_writeup_exporter", side_effect=KeyboardInterrupt
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            with self.assertRaises(KeyboardInterrupt):
                export_markdown_writeup(_report(), Path("writeup.md"))

        fallback.assert_not_called()

    def test_system_exit_from_resolver_propagates(self) -> None:
        with patch(
            "dayi.reporter.resolve_writeup_exporter", side_effect=SystemExit(2)
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            with self.assertRaises(SystemExit):
                export_markdown_writeup(_report(), Path("writeup.md"))

        fallback.assert_not_called()

    def test_keyboard_interrupt_from_exporter_propagates(self) -> None:
        resolution = _resolution(
            available=True,
            source_kind="installed",
            status_code="ok",
            exporter=Mock(side_effect=KeyboardInterrupt),
        )
        with patch(
            "dayi.reporter.resolve_writeup_exporter", return_value=resolution
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            with self.assertRaises(KeyboardInterrupt):
                export_markdown_writeup(_report(), Path("writeup.md"))

        fallback.assert_not_called()

    def test_system_exit_from_exporter_propagates(self) -> None:
        resolution = _resolution(
            available=True,
            source_kind="installed",
            status_code="ok",
            exporter=Mock(side_effect=SystemExit(2)),
        )
        with patch(
            "dayi.reporter.resolve_writeup_exporter", return_value=resolution
        ), patch("dayi.reporter._fallback_markdown") as fallback:
            with self.assertRaises(SystemExit):
                export_markdown_writeup(_report(), Path("writeup.md"))

        fallback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
