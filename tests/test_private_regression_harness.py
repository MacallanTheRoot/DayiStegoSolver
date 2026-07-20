import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.run_private_regression import (
    HarnessConfig,
    HarnessConfigurationError,
    ManifestEntry,
    ScanExecution,
    _render_markdown,
    execute_scan,
    load_manifest,
    main,
    run_harness,
    summarize_execution,
    validate_paths,
)


FLAG = "SiberVatan{synthetic_regression}"


def _report(
    *,
    flags: list[str] | None = None,
    tool: str = "strings",
    skipped: bool = False,
    reason: str = "",
    timed_out: bool = False,
    error: bool = False,
) -> dict:
    return {
        "all_flags_found": flags or [],
        "flag_attribution": {},
        "artifacts_found": [],
        "tool_results": [{
            "tool": tool,
            "return_code": None if skipped else 0,
            "timed_out": timed_out,
            "skipped": skipped,
            "error": error,
            "skip_reason": reason,
            "document_findings": [],
            "ocr_findings": [],
            "qr_findings": [],
            "stdout": "",
        }],
    }


class PrivateRegressionPathTests(unittest.TestCase):
    def test_corpus_inside_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repository = root / "repository"
            corpus = repository / "corpus"
            output = root / "output"
            corpus.mkdir(parents=True)
            with self.assertRaisesRegex(HarnessConfigurationError, "outside"):
                validate_paths(corpus, output, repository_root=repository)

    def test_corpus_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repository = root / "repository"
            real_corpus = root / "corpus"
            link = root / "corpus-link"
            repository.mkdir()
            real_corpus.mkdir()
            link.symlink_to(real_corpus, target_is_directory=True)
            with self.assertRaisesRegex(HarnessConfigurationError, "symlink"):
                validate_paths(link, root / "output", repository_root=repository)

    def test_output_inside_repository_or_corpus_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repository = root / "repository"
            corpus = root / "corpus"
            repository.mkdir()
            corpus.mkdir()
            for output in (repository / "output", corpus / "output"):
                with self.subTest(output=output), self.assertRaises(HarnessConfigurationError):
                    validate_paths(corpus, output, repository_root=repository)

    def test_relative_corpus_is_rejected(self) -> None:
        with self.assertRaisesRegex(HarnessConfigurationError, "absolute"):
            validate_paths(Path("relative"), Path("/tmp/output"))


class PrivateRegressionManifestTests(unittest.TestCase):
    def _manifest(self, root: Path, payload: object) -> Path:
        path = root / "manifest.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_manifest_traversal_and_absolute_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for invalid in ("../escape.bin", "/absolute.bin", "nested/../../escape"):
                path = self._manifest(root, {invalid: {}})
                with self.subTest(path=invalid), self.assertRaises(HarnessConfigurationError):
                    load_manifest(path)

    def test_manifest_malformed_regex_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._manifest(
                Path(temp_dir),
                {"challenge.bin": {"expected_patterns": ["("]}},
            )
            with self.assertRaisesRegex(HarnessConfigurationError, "malformed regex"):
                load_manifest(path)

    def test_manifest_malformed_json_and_duplicate_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            malformed = root / "manifest.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(HarnessConfigurationError, "JSON"):
                load_manifest(malformed)
            duplicate = self._manifest(root, {"A.bin": {}, "a.bin": {}})
            with self.assertRaisesRegex(HarnessConfigurationError, "duplicate"):
                load_manifest(duplicate)
            duplicate.write_text(
                '{"same.bin": {}, "same.bin": {}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(HarnessConfigurationError, "duplicate"):
                load_manifest(duplicate)


class PrivateRegressionSummaryTests(unittest.TestCase):
    def test_timeout_unsupported_and_missing_tool_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.bin"
            path.write_bytes(b"fixture")
            cases = (
                (ScanExecution(None, 1.0, None, True, "timeout"), "timeout"),
                (ScanExecution(_report(skipped=True, reason="unsupported format"), 1.0, 0), "unsupported"),
                (ScanExecution(_report(skipped=True, reason="tool unavailable"), 1.0, 0), "tool_missing"),
            )
            for execution, expected in cases:
                with self.subTest(expected=expected):
                    summary = summarize_execution(
                        path=path,
                        relative="sample.bin",
                        detected_type="UNKNOWN",
                        execution=execution,
                        entry=None,
                        anonymize=True,
                        show_flags=False,
                    )
                    self.assertEqual(summary.classification, expected)

    def test_optional_missing_tool_does_not_override_completed_core_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.bin"
            path.write_bytes(b"fixture")
            report = _report()
            report["tool_results"].append({
                **_report(skipped=True, reason="optional tool unavailable")["tool_results"][0],
                "tool": "optional_scanner",
            })
            summary = summarize_execution(
                path=path,
                relative="sample.bin",
                detected_type="UNKNOWN",
                execution=ScanExecution(report, 0.5, 0),
                entry=None,
                anonymize=True,
                show_flags=False,
            )
            self.assertEqual(summary.classification, "missed")
            self.assertEqual(summary.error_category, "dependency_error")

    def test_expected_plugin_without_expected_result_is_not_solved(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.bin"
            path.write_bytes(b"fixture")
            summary = summarize_execution(
                path=path,
                relative="sample.bin",
                detected_type="UNKNOWN",
                execution=ScanExecution(_report(), 0.5, 0),
                entry=ManifestEntry("sample.bin", expected_plugins=("strings",)),
                anonymize=True,
                show_flags=False,
            )
            self.assertEqual(summary.classification, "missed")

    def test_exact_flags_patterns_and_false_positives_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.bin"
            path.write_bytes(b"fixture")
            execution = ScanExecution(_report(flags=[FLAG]), 0.5, 0)
            solved = summarize_execution(
                path=path,
                relative="sample.bin",
                detected_type="UNKNOWN",
                execution=execution,
                entry=ManifestEntry(
                    "sample.bin",
                    expected_patterns=(r"SiberVatan\{.*?\}",),
                    expected_flags=(FLAG,),
                    expected_plugins=("strings",),
                ),
                anonymize=True,
                show_flags=False,
            )
            false_positive = summarize_execution(
                path=path,
                relative="sample.bin",
                detected_type="UNKNOWN",
                execution=execution,
                entry=ManifestEntry("sample.bin"),
                anonymize=True,
                show_flags=False,
            )
            self.assertEqual(solved.classification, "solved")
            self.assertEqual(false_positive.classification, "false_positive")

    def test_anonymization_and_default_redaction_hide_private_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "private-name.bin"
            path.write_bytes(b"fixture")
            summary = summarize_execution(
                path=path,
                relative="private-name.bin",
                detected_type="UNKNOWN",
                execution=ScanExecution(_report(flags=[FLAG]), 0.5, 0),
                entry=None,
                anonymize=True,
                show_flags=False,
            )
            serialized = json.dumps(summary.to_dict())
            self.assertNotIn("private-name", serialized)
            self.assertNotIn(FLAG, serialized)
            self.assertRegex(summary.file_id, r"file-[0-9a-f]{12}\Z")
            self.assertEqual(summary.flag_count, 1)
            self.assertTrue(summary.flags[0].startswith("<redacted:"))

    def test_show_flags_is_explicit_and_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.bin"
            path.write_bytes(b"fixture")
            summary = summarize_execution(
                path=path,
                relative="sample.bin",
                detected_type="UNKNOWN",
                execution=ScanExecution(_report(flags=[FLAG + "\x1b[31m"]), 0.5, 0),
                entry=None,
                anonymize=False,
                show_flags=True,
            )
            self.assertIn(FLAG, summary.flags[0])
            self.assertNotIn("\x1b", summary.flags[0])

    def test_markdown_escapes_controls_and_markup(self) -> None:
        payload = {
            "aggregate": {
                "total_files": 1, "solved": 0, "probable_candidate": 0,
                "partial": 0, "missed": 1, "false_positive": 0,
                "timeout": 0, "unsupported": 0, "parser_error": 0,
                "tool_missing": 0, "scan_error": 0, "average_runtime": 0.1,
                "median_runtime": 0.1, "maximum_runtime": 0.1,
            },
            "files": [{
                "file_id": "unsafe|name\x1b[31m",
                "classification": "missed",
                "detected_type": "TEXT",
                "flag_count": 0,
                "candidate_count": 0,
                "runtime_seconds": 0.1,
            }],
            "missing_manifest_entries": [],
        }
        rendered = _render_markdown(payload)
        self.assertNotIn("\x1b", rendered)
        self.assertIn(r"unsafe\|name\\x1b", rendered)


class PrivateRegressionHarnessTests(unittest.TestCase):
    def _config(self, corpus: Path, output: Path, manifest: Path | None = None) -> HarnessConfig:
        return HarnessConfig(corpus, output, manifest, 2.0, 10, True, False)

    def test_empty_synthetic_corpus_writes_deterministic_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            output = root / "output"
            corpus.mkdir()
            payload = run_harness(self._config(corpus, output))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["aggregate"]["total_files"], 0)
            self.assertFalse(payload["settings"]["network_access"])
            self.assertTrue((output / "summary.json").is_file())
            self.assertTrue((output / "summary.md").is_file())

    def test_deterministic_order_no_network_and_no_source_modification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            corpus.mkdir()
            first = corpus / "z-last.bin"
            second = corpus / "a-first.bin"
            first.write_bytes(b"last")
            second.write_bytes(b"first")
            original = {path.name: path.read_bytes() for path in (first, second)}
            calls: list[str] = []

            def executor(path, report, workspace, timeout, pattern):
                calls.append(path.name)
                self.assertFalse(report.exists())
                self.assertIsNone(pattern)
                return ScanExecution(_report(), 0.01, 0)

            with patch("socket.create_connection", side_effect=AssertionError("network")):
                payload = run_harness(
                    self._config(corpus, root / "output"),
                    scan_executor=executor,
                )
            self.assertEqual(calls, ["a-first.bin", "z-last.bin"])
            self.assertEqual(
                {path.name: path.read_bytes() for path in (first, second)},
                original,
            )
            serialized = json.dumps(payload)
            self.assertNotIn("a-first.bin", serialized)
            self.assertNotIn("z-last.bin", serialized)

    def test_file_limit_and_missing_manifest_entries_are_reported_anonymously(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "one.bin").write_bytes(b"one")
            (corpus / "two.bin").write_bytes(b"two")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"missing.bin": {}}), encoding="utf-8")
            config = HarnessConfig(corpus, root / "output", manifest, 2.0, 1, True, False)
            payload = run_harness(
                config,
                scan_executor=lambda *_args: ScanExecution(_report(), 0.01, 0),
            )
            self.assertTrue(payload["aggregate"]["file_limit_reached"])
            self.assertEqual(len(payload["missing_manifest_entries"]), 1)
            self.assertNotIn("missing.bin", json.dumps(payload))

    def test_existing_summary_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            output = root / "output"
            corpus.mkdir()
            output.mkdir()
            (output / "summary.json").write_text("existing", encoding="utf-8")
            with self.assertRaisesRegex(HarnessConfigurationError, "already exist"):
                run_harness(self._config(corpus, output))

    def test_environment_is_not_mutated_by_harness_configuration(self) -> None:
        before = dict(os.environ)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            corpus.mkdir()
            run_harness(self._config(corpus, root / "output"))
        self.assertEqual(dict(os.environ), before)

    def test_environment_corpus_is_used_when_input_argument_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            output = root / "output"
            corpus.mkdir()
            with patch.dict(os.environ, {"DAYI_PRIVATE_CORPUS": str(corpus)}):
                exit_code = main([
                    "--output", str(output),
                    "--anonymize",
                    "--redact-flags",
                ])
            payload = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["aggregate"]["total_files"], 0)
        self.assertTrue(payload["settings"]["flags_redacted"])

    def test_child_timeout_is_classified_and_termination_is_requested(self) -> None:
        process = Mock(pid=12345, returncode=None)
        process.wait.side_effect = subprocess.TimeoutExpired(["dayi"], 0.01)
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "scripts.run_private_regression.subprocess.Popen",
            return_value=process,
        ), patch("scripts.run_private_regression._terminate_process") as terminate:
            root = Path(temp_dir)
            target = root / "target.bin"
            target.write_bytes(b"fixture")
            result = execute_scan(
                target,
                root / "report",
                root / "workspace",
                0.01,
                None,
            )
        self.assertTrue(result.timed_out)
        self.assertEqual(result.error_category, "timeout")
        terminate.assert_called_once_with(process)


if __name__ == "__main__":
    unittest.main()
