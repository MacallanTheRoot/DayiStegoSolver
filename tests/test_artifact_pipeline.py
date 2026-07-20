import asyncio
import json
import re
import tempfile
import unittest
from pathlib import Path

from dayi.reporter import ToolResult, write_json_report, write_txt_report
from dayi.runner import DayiRunner


class ArtifactPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = DayiRunner(Path("sample.png"), re.compile(r"FLAG\{.*?\}"))

    def _result(self, stdout: str, stderr: str = "") -> ToolResult:
        return ToolResult(
            tool_name="strings",
            command=["strings", "sample.png"],
            return_code=0,
            stdout=stdout,
            stderr=stderr,
            flags_found=[],
            elapsed_seconds=0.1,
        )

    def test_async_wrapper_attaches_artifacts(self) -> None:
        async def produce_result() -> ToolResult:
            return self._result("next=https://example.org/stage2")

        result = asyncio.run(self.runner._wrap_notify(produce_result()))

        self.assertEqual(len(result.artifacts_found), 1)
        self.assertEqual(result.artifacts_found[0].source, "strings/stdout")

    def test_report_aggregates_and_serializes_artifacts(self) -> None:
        result = self._result("password=dayi-secret")
        self.runner._attach_artifacts(result)
        self.runner._partial_results.append(result)
        report = self.runner._build_report()

        self.assertEqual(len(report.all_artifacts), 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "report.json"
            txt_path = Path(tmpdir) / "report.txt"
            write_json_report(report, json_path)
            write_txt_report(report, txt_path)

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["artifacts_found"][0]["type"], "credential")
            self.assertIn("SONRAKİ AŞAMA", txt_path.read_text(encoding="utf-8"))

    def test_verbose_runner_includes_possible_domain_findings(self) -> None:
        quiet_result = self._result("abc.dev")
        self.runner._attach_artifacts(quiet_result)
        self.assertEqual(quiet_result.artifacts_found, [])

        verbose_runner = DayiRunner(
            Path("sample.png"),
            re.compile(r"FLAG\{.*?\}"),
            include_possible_artifacts=True,
        )
        verbose_result = self._result("abc.dev")
        verbose_runner._attach_artifacts(verbose_result)
        self.assertEqual(
            [(finding.artifact_type, finding.preview) for finding in verbose_result.artifacts_found],
            [("domain", "abc.dev")],
        )


if __name__ == "__main__":
    unittest.main()
