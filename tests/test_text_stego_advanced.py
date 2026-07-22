import asyncio
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dayi.text_stego as engine
from dayi.reporter import write_json_report
from dayi.runner import DayiRunner
from dayi.text_stego import analyze_text_input, detect_text_bytes
from dayi.tools._plugin import PluginRegistry
from dayi.tools.text_stego_scanner import PLUGIN_SPECS, run_text_stego


CASE_FLAG = "CTF{bacon_stego}"
WHITESPACE_FLAG = "CTF{whitespace_stego}"
GHOST_FLAG = "CTF{b4km4_g0r}"
PATTERN = re.compile(r"CTF\{.*?\}")


def _bits(value: str, width: int = 8, *, lsb_first: bool = False) -> str:
    groups = [f"{byte:0{width}b}" for byte in value.encode("ascii")]
    if lsb_first:
        groups = [group[::-1] for group in groups]
    return "".join(groups)


def _case_carrier(
    value: str,
    *,
    uppercase_is_one: bool = True,
    punctuation: bool = False,
) -> str:
    bits = _bits(value)
    cover = ("thequickbrownfoxjumpsoverthelazydog" * 64)[:len(bits)]
    output: list[str] = []
    for index, (letter, bit) in enumerate(zip(cover, bits)):
        uppercase = (bit == "1") == uppercase_is_one
        output.append(letter.upper() if uppercase else letter.lower())
        if punctuation and index % 5 == 4:
            output.append("!, 7-")
    return "".join(output)


def _whitespace(
    bits: str,
    *,
    space_is_zero: bool = True,
) -> str:
    zero, one = (" ", "\t") if space_is_zero else ("\t", " ")
    return "".join(zero if bit == "0" else one for bit in bits)


def _snow_carrier(value: str) -> str:
    codes = {
        "C": "101100011", "T": "10101110", "F": "001010010",
        "{": "1010011110000", "}": "0100111011101", "_": "10111111100",
        "a": "0101", "c": "110110", "e": "1100", "g": "011101",
        "i": "0011", "n": "0001", "o": "0110", "r": "11010",
        "s": "0000", "w": "001011",
    }
    bits = "".join(codes[character] for character in value)
    bits += "0" * (-len(bits) % 3)
    values = [
        int(bits[index:index + 3][::-1], 2)
        for index in range(0, len(bits), 3)
    ]
    groups = [" " * value + "\t" for value in values]
    lines = ["".join(groups[index:index + 12]) for index in range(0, len(groups), 12)]
    return "ordinary visible cover" + "\t" + "\n".join(lines)


def _analysis(text: str):
    return analyze_text_input(detect_text_bytes(text.encode("utf-8")), PATTERN)


def _flag_candidates(analysis, flag: str):
    return [
        candidate
        for candidate in analysis.candidates
        if candidate.flags_found == (flag,)
    ]


class CaseBinaryAsciiRegressionTests(unittest.TestCase):
    def test_mixed_case_carrier_ignores_nonletters_and_matches_exactly(self) -> None:
        analysis = _analysis(_case_carrier(CASE_FLAG, punctuation=True))
        candidates = _flag_candidates(analysis, CASE_FLAG)

        self.assertTrue(candidates)
        self.assertEqual(candidates[0].value, CASE_FLAG)
        self.assertEqual(candidates[0].decoder, "case_binary_ascii")
        self.assertEqual(candidates[0].confidence, "confirmed")

    def test_reversed_mapping_and_trailing_nul_padding(self) -> None:
        reversed_analysis = _analysis(
            _case_carrier(CASE_FLAG, uppercase_is_one=False)
        )
        padded_analysis = _analysis(_case_carrier(CASE_FLAG + "\x00\x00"))

        reversed_candidates = _flag_candidates(reversed_analysis, CASE_FLAG)
        padded_candidates = _flag_candidates(padded_analysis, CASE_FLAG)
        self.assertTrue(reversed_candidates)
        self.assertIn("mapping=one-zero", reversed_candidates[0].variant)
        self.assertTrue(padded_candidates)
        self.assertEqual(padded_candidates[0].value, CASE_FLAG)

    def test_embedded_nul_is_rejected(self) -> None:
        analysis = _analysis(_case_carrier("CTF{bacon\x00_stego}"))

        self.assertEqual(_flag_candidates(analysis, CASE_FLAG), [])
        self.assertFalse(
            any(
                candidate.decoder == "case_binary_ascii"
                and candidate.flags_found
                for candidate in analysis.candidates
            )
        )

    def test_random_mixed_case_prose_has_no_high_confidence_case_result(self) -> None:
        prose = (
            "ThIs deTERminisTic Mixed CASE Prose Is ordinary formatting and "
            "contains no encoded challenge payload whatsoever. "
        ) * 8
        analysis = _analysis(prose)

        self.assertEqual(_flag_candidates(analysis, CASE_FLAG), [])
        self.assertFalse(
            any(
                candidate.decoder == "case_binary_ascii"
                and candidate.confidence in {"confirmed", "high"}
                for candidate in analysis.candidates
            )
        )

    def test_analysis_and_candidate_limits_still_bound_case_decoding(self) -> None:
        carrier = _case_carrier(CASE_FLAG) * 20
        with patch.object(engine, "MAX_ANALYSIS_CHARACTERS", 64), patch.object(
            engine, "MAX_TOTAL_CANDIDATES", 5
        ):
            analysis = _analysis(carrier)

        self.assertLessEqual(analysis.total_generated, 5)
        self.assertEqual(_flag_candidates(analysis, CASE_FLAG), [])


class WhitespaceBinaryRegressionTests(unittest.TestCase):
    def test_snow_style_multiline_space_counts_decode(self) -> None:
        flag = "CTF{snow_regression}"
        candidates = _flag_candidates(_analysis(_snow_carrier(flag)), flag)

        self.assertTrue(candidates)
        self.assertEqual(candidates[0].decoder, "whitespace>snow")
        self.assertIn("snow-huffman", candidates[0].variant)

    def test_multiline_per_line_payload_uses_boundaries(self) -> None:
        lines = [
            _whitespace("0" + _bits(character))
            for character in WHITESPACE_FLAG
        ]
        analysis = _analysis("\n".join(lines))
        candidates = _flag_candidates(analysis, WHITESPACE_FLAG)

        self.assertTrue(candidates)
        self.assertEqual(candidates[0].decoder, "whitespace>binary")
        self.assertIn("per-line", candidates[0].variant)
        self.assertIn("offset=1", candidates[0].variant)

    def test_inline_payload_isolated_after_final_visible_character(self) -> None:
        bits = _bits(WHITESPACE_FLAG)
        carrier = "\n".join((
            "visible         cover" + _whitespace(bits[:16]),
            *(
                "left" + _whitespace(bits[index:index + 16]) + "right"
                for index in range(16, len(bits), 16)
            ),
        ))
        analysis = _analysis(carrier)
        candidates = _flag_candidates(analysis, WHITESPACE_FLAG)

        self.assertTrue(candidates)
        self.assertIn("inline-after-first-carrier", candidates[0].variant)

    def test_reversed_mapping_lsb_order_and_nonzero_offset(self) -> None:
        variants = (
            _whitespace(_bits(WHITESPACE_FLAG), space_is_zero=False),
            _whitespace(_bits(WHITESPACE_FLAG, lsb_first=True)),
            _whitespace("00000" + _bits(WHITESPACE_FLAG)),
        )
        expected_markers = ("mapping=one-zero", "lsb-first", "offset=5")
        for carrier, marker in zip(variants, expected_markers):
            with self.subTest(marker=marker):
                candidates = _flag_candidates(_analysis(carrier), WHITESPACE_FLAG)
                self.assertTrue(candidates)
                self.assertIn(marker, candidates[0].variant)

    def test_seven_bit_ascii_uses_strict_filter(self) -> None:
        carrier = _whitespace(_bits(WHITESPACE_FLAG, width=7))
        candidates = _flag_candidates(_analysis(carrier), WHITESPACE_FLAG)

        self.assertTrue(candidates)
        self.assertIn("7-bit", candidates[0].variant)

    def test_crlf_and_incomplete_final_group_are_ignored(self) -> None:
        trailing_lines = [
            f"line-{index}" + _whitespace(bit)
            for index, bit in enumerate(_bits(WHITESPACE_FLAG) + "10101")
        ]
        source = detect_text_bytes("\r\n".join(trailing_lines).encode("ascii"))
        candidates = _flag_candidates(
            analyze_text_input(source, PATTERN),
            WHITESPACE_FLAG,
        )

        self.assertTrue(candidates)
        self.assertEqual(candidates[0].value, WHITESPACE_FLAG)

    def test_random_formatting_whitespace_has_no_high_confidence_result(self) -> None:
        text = "\r\n".join(
            f"ordinary column {index}\tvalue {index % 7}   "
            for index in range(80)
        )
        analysis = _analysis(text)

        self.assertFalse(
            any(
                candidate.decoder == "whitespace>binary"
                and candidate.confidence in {"confirmed", "high"}
                for candidate in analysis.candidates
            )
        )


class TextStegoReportingRegressionTests(unittest.TestCase):
    def test_case_binary_exact_attribution_and_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "mixed-case-carrier"
            target.write_text(
                _case_carrier(CASE_FLAG, punctuation=True),
                encoding="utf-8",
            )
            runner = DayiRunner(
                target,
                PATTERN,
                registry=PluginRegistry(PLUGIN_SPECS),
                pattern_display=PATTERN.pattern,
            )
            report = asyncio.run(runner.run_all())
            report_path = root / "report.json"
            write_json_report(report, report_path)
            payload = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report.all_flags, [CASE_FLAG])
        self.assertEqual(
            payload["flag_attribution"][CASE_FLAG],
            ["text_stego:case_binary_ascii"],
        )
        self.assertIn(CASE_FLAG, json.dumps(payload))

    def test_whitespace_plugin_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "whitespace-carrier"
            target.write_text(
                _whitespace(_bits(WHITESPACE_FLAG)),
                encoding="ascii",
            )
            result = asyncio.run(run_text_stego(target, PATTERN))

        self.assertEqual(
            result.extracted_flags,
            {"text_stego:whitespace>binary": [WHITESPACE_FLAG]},
        )

    def test_zero_width_ghost_flag_remains_supported(self) -> None:
        encoded = _bits(GHOST_FLAG)
        carrier = "cover:" + "".join(
            "\u200b" if bit == "0" else "\u200c" for bit in encoded
        )
        analysis = _analysis(carrier)

        self.assertTrue(_flag_candidates(analysis, GHOST_FLAG))
        self.assertTrue(
            any(
                candidate.decoder.startswith("zero_width>binary")
                for candidate in _flag_candidates(analysis, GHOST_FLAG)
            )
        )


if __name__ == "__main__":
    unittest.main()
