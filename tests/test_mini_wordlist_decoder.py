import unittest

from dayi.reporter import ToolResult
from dayi.runner import _extract_mini_wordlist


def _tool_result(stdout: str, tool_name: str = "strings") -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        return_code=0,
        stdout=stdout,
        stderr="",
        flags_found=[],
        elapsed_seconds=0.01,
    )


class MiniWordlistDecoderTests(unittest.TestCase):
    def test_injects_original_hex_and_printable_ascii_decoding(self) -> None:
        token = "70617373776f7264"

        candidates = _extract_mini_wordlist([_tool_result(token)])

        self.assertEqual(candidates, [token, "password"])

    def test_hex_decoding_preserves_short_and_spaced_passwords(self) -> None:
        candidates = _extract_mini_wordlist(
            [_tool_result("70617373 6f70656e20736573616d65")]
        )

        self.assertEqual(
            candidates,
            ["70617373", "pass", "6f70656e20736573616d65", "open sesame"],
        )

    def test_binary_and_odd_length_hex_are_not_decoded(self) -> None:
        binary = "000102030405"
        odd_length = "7061737"

        candidates = _extract_mini_wordlist(
            [_tool_result(f"{binary} {odd_length}")]
        )

        self.assertEqual(candidates, [binary, odd_length])

    def test_injects_original_base64_and_strict_printable_decoding(self) -> None:
        token = "U3RlZ29QYXNzd29yZDEyMw=="

        candidates = _extract_mini_wordlist([_tool_result(token)])

        self.assertEqual(candidates, [token, "StegoPassword123"])

    def test_rejects_short_or_binary_base64_decodings(self) -> None:
        short = "U2hvcnQ="
        binary = "AAECAwQFBgcICQoLDA0ODxAREhM="

        candidates = _extract_mini_wordlist(
            [_tool_result(f"{short} {binary}")]
        )

        self.assertEqual(candidates, [short, binary])

    def test_deduplicates_raw_and_decoded_candidates(self) -> None:
        token = "70617373776f7264"

        candidates = _extract_mini_wordlist(
            [_tool_result(f"{token} {token} password")]
        )

        self.assertEqual(candidates, [token, "password"])

    def test_ignores_outputs_from_non_source_tools(self) -> None:
        candidates = _extract_mini_wordlist(
            [_tool_result("70617373776f7264", tool_name="lsb")]
        )

        self.assertEqual(candidates, [])

    def test_preserves_three_hundred_candidate_cap(self) -> None:
        tokens = " ".join(f"token{index:04d}" for index in range(350))

        candidates = _extract_mini_wordlist([_tool_result(tokens)])

        self.assertEqual(len(candidates), 300)
        self.assertEqual(candidates[0], "token0000")
        self.assertEqual(candidates[-1], "token0299")

    def test_cap_does_not_split_encoded_and_decoded_pair(self) -> None:
        raw_tokens = " ".join(f"token{index:04d}" for index in range(299))
        encoded = "70617373776f7264"

        candidates = _extract_mini_wordlist(
            [_tool_result(f"{raw_tokens} {encoded}")]
        )

        self.assertEqual(len(candidates), 299)
        self.assertNotIn(encoded, candidates)
        self.assertNotIn("password", candidates)


if __name__ == "__main__":
    unittest.main()
