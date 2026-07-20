import gzip
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from dayi import cli
from dayi.reporter import ScanReport
from dayi.tools._base import iter_wordlist_lines
from dayi.wordlists import KALI_ROCKYOU_CANDIDATES, resolve_wordlist


def _report(target: Path) -> ScanReport:
    return ScanReport(
        target_file=str(target),
        flag_pattern="built-in",
        wordlist=None,
        started_at="start",
        finished_at="finish",
        all_flags=[],
        tool_results=[],
    )


class WordlistResolverTests(unittest.TestCase):
    def test_exact_path_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist = Path(tmpdir) / "custom.txt"
            wordlist.write_text("password\n", encoding="utf-8")

            resolution = resolve_wordlist(wordlist)

        self.assertEqual(resolution.requested, wordlist)
        self.assertEqual(resolution.resolved, wordlist.resolve())
        self.assertEqual(resolution.candidates_checked, (wordlist,))

    def test_current_directory_rockyou_resolves_after_exact_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = Path(tmpdir)
            wordlist = cwd / "rockyou.txt"
            wordlist.write_text("password\n", encoding="utf-8")

            resolution = resolve_wordlist(Path("rockyou.txt"), cwd=cwd)

        self.assertEqual(resolution.resolved, wordlist.resolve())
        self.assertEqual(
            resolution.candidates_checked,
            (Path("rockyou.txt"), wordlist),
        )

    def test_kali_plain_and_gzip_candidates_are_controlled_and_ordered(self) -> None:
        self.assertEqual(
            KALI_ROCKYOU_CANDIDATES,
            (
                Path("/usr/share/wordlists/rockyou.txt"),
                Path("/usr/share/wordlists/rockyou.txt.gz"),
            ),
        )
        cwd = Path("/controlled/current")
        for available in KALI_ROCKYOU_CANDIDATES:
            with self.subTest(available=available), patch(
                "dayi.wordlists._resolve_regular_wordlist",
                side_effect=lambda candidate, selected=available: (
                    selected if candidate == selected else None
                ),
            ):
                resolution = resolve_wordlist(Path("rockyou.txt"), cwd=cwd)
            self.assertEqual(resolution.resolved, available)
            self.assertIn(available, resolution.candidates_checked)
            if available.suffix == ".gz":
                self.assertLess(
                    resolution.candidates_checked.index(KALI_ROCKYOU_CANDIDATES[0]),
                    resolution.candidates_checked.index(available),
                )

    def test_unresolved_and_unsafe_names_do_not_guess_other_locations(self) -> None:
        injected = (Path("/controlled/rockyou.txt"),)
        with patch(
            "dayi.wordlists._resolve_regular_wordlist", return_value=None
        ) as resolver:
            unrelated = resolve_wordlist(
                Path("missing.txt"), system_candidates=injected
            )
            traversal = resolve_wordlist(
                Path("nested/../rockyou.txt"), system_candidates=injected
            )

        self.assertIsNone(unrelated.resolved)
        self.assertEqual(unrelated.candidates_checked, (Path("missing.txt"),))
        self.assertIsNone(traversal.resolved)
        self.assertEqual(
            traversal.candidates_checked,
            (Path("nested/../rockyou.txt"),),
        )
        self.assertEqual(resolver.call_count, 2)

    def test_gzip_wordlist_is_streamed_with_line_and_count_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist = Path(tmpdir) / "rockyou.txt.gz"
            with gzip.open(wordlist, "wt", encoding="utf-8") as output:
                output.write("first\nsecond\nthird\n")

            words = list(iter_wordlist_lines(wordlist, limit=2))

        self.assertEqual(words, ["first", "second"])


class WordlistCliTests(unittest.IsolatedAsyncioTestCase):
    def test_help_and_legacy_parser_accept_require_wordlist(self) -> None:
        help_text = cli._build_scan_parent_parser().format_help()
        args = cli.parse_cli_args([
            "target.bin", "--wordlist", "rockyou.txt", "--require-wordlist"
        ])

        self.assertIn("--require-wordlist", help_text)
        self.assertTrue(args.require_wordlist)

    async def test_unresolved_wordlist_keeps_degraded_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"target")
            args = cli.parse_cli_args([
                str(target), "--wordlist", "definitely-missing.txt"
            ])
            logger = Mock(spec=logging.Logger)
            runner = Mock()
            runner.run_all = AsyncMock(return_value=_report(target))
            with patch("dayi.cli.build_integration", return_value=None), patch(
                "dayi.cli.DayiRunner", return_value=runner
            ) as runner_factory:
                report, exit_code = await cli._run_analysis(args, logger)

        self.assertIsNotNone(report)
        self.assertEqual(exit_code, 0)
        self.assertIsNone(runner_factory.call_args.kwargs["wordlist"])
        messages = "\n".join(
            str(call.args[0]) for call in logger.method_calls if call.args
        )
        self.assertIn("İstenen wordlist: definitely-missing.txt", messages)
        self.assertIn("Çözülen wordlist: yok", messages)
        self.assertIn("steghide_main_bf", messages)
        self.assertIn("outguess_main_bf", messages)

    async def test_require_wordlist_fails_before_runtime_setup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"target")
            args = cli.parse_cli_args([
                str(target),
                "--wordlist",
                "definitely-missing.txt",
                "--require-wordlist",
            ])
            logger = Mock(spec=logging.Logger)
            with patch("dayi.cli.build_integration") as integration, patch(
                "dayi.cli.DayiRunner"
            ) as runner:
                report, exit_code = await cli._run_analysis(args, logger)

        self.assertIsNone(report)
        self.assertEqual(exit_code, 1)
        integration.assert_not_called()
        runner.assert_not_called()
        error = logger.error.call_args.args[0]
        self.assertIn("--require-wordlist", error)
        self.assertIn("--wordlist", error)


if __name__ == "__main__":
    unittest.main()
