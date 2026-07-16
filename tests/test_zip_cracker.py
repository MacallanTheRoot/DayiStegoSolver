import asyncio
import base64
import re
import tempfile
import unittest
import zipfile
from pathlib import Path

from dayi.reporter import ToolResult
from dayi.runner import DayiRunner, _extract_mini_wordlist
from dayi.tools.zip_cracker import run_zip_cracker


_ZIPCRYPTO_FIXTURE = base64.b64decode(
    "UEsDBAoACQAAANG271wlB0oBMgAAACYAAAAIABwAZmxhZy50eHRVVAkAA3rlV2p65Vdq"
    "dXgLAAEE6AMAAAToAwAA8Y1aGP1I+KYBLDqmwojxqsu25usyYS+aHwsGPClaGha1STcT"
    "q5fWPqrQMqLe22XhPbtQSwcIJQdKATIAAAAmAAAAUEsBAh4DCgAJAAAA0bbvXCUHSgEy"
    "AAAAJgAAAAgAGAAAAAAAAQAAALSBAAAAAGZsYWcudHh0VVQFAAN65VdqdXgLAAEE6AMA"
    "AAToAwAAUEsFBgAAAAABAAEATgAAAIQAAAAAAA=="
)


class ZipCrackerTests(unittest.TestCase):
    def _write_fixture(self, workspace: Path) -> Path:
        archive = workspace / "locked.zip"
        archive.write_bytes(_ZIPCRYPTO_FIXTURE)
        return archive

    def test_cracks_zipcrypto_with_mini_wordlist_and_scans_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            self._write_fixture(workspace)

            result = asyncio.run(
                run_zip_cracker(
                    workspace,
                    re.compile(r"FLAG\{.*?\}"),
                    mini_wordlist=["wrong", "dayi123", "unused"],
                )
            )

            self.assertEqual(result.return_code, 0)
            self.assertFalse(result.skipped)
            self.assertEqual(
                result.flags_found,
                ["FLAG{zipcrypto_mini_wordlist_success}"],
            )
            self.assertIn("password 'dayi123'", result.stdout)
            self.assertEqual(len(result.extracted_flags), 1)
            self.assertTrue(Path(result.extracted_dir).is_dir())

    def test_falls_back_to_global_wordlist_with_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            self._write_fixture(workspace)
            wordlist = workspace / "wordlist.txt"
            wordlist.write_text("wrong\ndayi123\nunused\n", encoding="utf-8")

            result = asyncio.run(
                run_zip_cracker(
                    workspace,
                    re.compile(r"FLAG\{.*?\}"),
                    mini_wordlist=["also-wrong"],
                    wordlist_path=wordlist,
                    bf_limit=2,
                )
            )

            self.assertEqual(
                result.flags_found,
                ["FLAG{zipcrypto_mini_wordlist_success}"],
            )

    def test_respects_global_wordlist_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            self._write_fixture(workspace)
            wordlist = workspace / "wordlist.txt"
            wordlist.write_text("wrong\ndayi123\n", encoding="utf-8")

            result = asyncio.run(
                run_zip_cracker(
                    workspace,
                    re.compile(r"FLAG\{.*?\}"),
                    mini_wordlist=[],
                    wordlist_path=wordlist,
                    bf_limit=1,
                )
            )

            self.assertEqual(result.flags_found, [])
            self.assertIsNone(result.extracted_dir)

    def test_extensionless_unencrypted_zip_is_extracted_and_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            carved_archive = workspace / "20713"
            with zipfile.ZipFile(carved_archive, "w") as archive:
                archive.writestr("flag.txt", "FLAG{extensionless_plain_zip}")

            messages: list[str] = []

            result = asyncio.run(
                run_zip_cracker(
                    workspace,
                    re.compile(r"FLAG\{.*?\}"),
                    mini_wordlist=["dayi123"],
                    artifact_callback=messages.append,
                )
            )

            self.assertFalse(result.skipped)
            self.assertEqual(
                result.flags_found,
                ["FLAG{extensionless_plain_zip}"],
            )
            self.assertIn("Extracted unencrypted ZIP 20713", result.stdout)
            self.assertEqual(
                messages,
                [
                    "[zip_cracker] Binwalk'un çıkaramadığı şifresiz ZIP "
                    "dosyasını Dayı özel olarak çıkartıyor..."
                ],
            )
            self.assertTrue(Path(result.extracted_dir).is_dir())

    def test_extensionless_zipcrypto_is_discovered_by_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "20713").write_bytes(_ZIPCRYPTO_FIXTURE)

            result = asyncio.run(
                run_zip_cracker(
                    workspace,
                    re.compile(r"FLAG\{.*?\}"),
                    mini_wordlist=["dayi123"],
                )
            )

            self.assertEqual(
                result.flags_found,
                ["FLAG{zipcrypto_mini_wordlist_success}"],
            )
            self.assertIn("Cracked 20713", result.stdout)

    def test_unencrypted_fallback_still_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workspace = root / "workspace"
            workspace.mkdir()
            with zipfile.ZipFile(workspace / "carved", "w") as archive:
                archive.writestr("../escape.txt", "FLAG{must_not_escape}")

            result = asyncio.run(
                run_zip_cracker(
                    workspace,
                    re.compile(r"FLAG\{.*?\}"),
                    mini_wordlist=[],
                )
            )

            self.assertEqual(result.return_code, 1)
            self.assertEqual(result.flags_found, [])
            self.assertIn("unsafe member path", result.stderr)
            self.assertFalse((root / "escape.txt").exists())

    def test_runner_chains_binwalk_output_after_mini_wordlist_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            extraction_root = Path(tmpdir)
            self._write_fixture(extraction_root)
            runner = DayiRunner(
                extraction_root / "target.bin",
                re.compile(r"FLAG\{.*?\}"),
            )
            runner._partial_results.extend(
                [
                    ToolResult(
                        tool_name="binwalk",
                        command=["binwalk"],
                        return_code=0,
                        stdout="",
                        stderr="",
                        flags_found=[],
                        elapsed_seconds=0.01,
                        extracted_dir=str(extraction_root),
                    ),
                    ToolResult(
                        tool_name="strings",
                        command=["strings"],
                        return_code=0,
                        stdout="dayi123",
                        stderr="",
                        flags_found=[],
                        elapsed_seconds=0.01,
                    ),
                ]
            )

            mini_wordlist = _extract_mini_wordlist(runner._partial_results)
            asyncio.run(runner._run_archive_phase(mini_wordlist))

            result = next(
                item
                for item in runner._partial_results
                if item.tool_name == "zip_cracker"
            )
            self.assertEqual(result.tool_name, "zip_cracker")
            self.assertEqual(
                result.flags_found,
                ["FLAG{zipcrypto_mini_wordlist_success}"],
            )


if __name__ == "__main__":
    unittest.main()
