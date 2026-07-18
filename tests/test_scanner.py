import re
import unittest

from dayi.scanner import (
    BUILTIN_FLAG_PATTERN_DISPLAY,
    MAX_BUILTIN_FLAG_CONTENT_CHARS,
    build_flag_pattern_config,
    scan_text,
)


class BuiltinFlagPatternTests(unittest.TestCase):
    def setUp(self) -> None:
        config = build_flag_pattern_config(None)
        assert config is not None
        self.config = config

    def test_common_prefixes_and_deterministic_deduplication(self) -> None:
        text = (
            "CTF{example} FLAG{example_123} HTB{a-b-c} "
            "picoCTF{mixed_CASE_123} THM{value} CTF{example}"
        )
        self.assertEqual(
            scan_text(text, self.config.compiled),
            [
                "CTF{example}",
                "FLAG{example_123}",
                "HTB{a-b-c}",
                "picoCTF{mixed_CASE_123}",
                "THM{value}",
            ],
        )
        self.assertEqual(self.config.display, BUILTIN_FLAG_PATTERN_DISPLAY)
        self.assertEqual(self.config.source, "builtin")

    def test_rejects_malformed_unknown_lowercase_and_control_content(self) -> None:
        cases = [
            "CTF{}",
            "TEST{value}",
            "ctf{lowercase}",
            "CTF{line\nbreak}",
            "CTF{{nested}}",
            "CTF{control\x01character}",
            "XCTF{embedded-prefix}",
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(scan_text(value, self.config.compiled), [])

    def test_length_bound_and_trailing_punctuation(self) -> None:
        maximum = "x" * MAX_BUILTIN_FLAG_CONTENT_CHARS
        too_long = "x" * (MAX_BUILTIN_FLAG_CONTENT_CHARS + 1)
        self.assertEqual(
            scan_text(f"CTF{{{maximum}}}.", self.config.compiled),
            [f"CTF{{{maximum}}}"],
        )
        self.assertEqual(scan_text(f"CTF{{{too_long}}}", self.config.compiled), [])


class CustomFlagPatternTests(unittest.TestCase):
    def test_custom_pattern_overrides_builtin_and_returns_full_capture_match(self) -> None:
        raw = r"(CUSTOM)\{([A-Z0-9_]+)\}"
        config = build_flag_pattern_config(raw)
        assert config is not None
        self.assertEqual(config.compiled.pattern, raw)
        self.assertEqual(config.display, raw)
        self.assertEqual(config.source, "user")
        self.assertEqual(
            scan_text("CTF{ignored} CUSTOM{FULL_MATCH}", config.compiled),
            ["CUSTOM{FULL_MATCH}"],
        )

    def test_invalid_and_pathological_user_patterns_are_rejected(self) -> None:
        self.assertIsNone(build_flag_pattern_config("("))
        self.assertIsNone(build_flag_pattern_config(r"(a+)+$"))

    def test_shared_scanner_returns_group_zero(self) -> None:
        self.assertEqual(
            scan_text("HTB{abc}", re.compile(r"(HTB)\{(abc)\}")),
            ["HTB{abc}"],
        )


if __name__ == "__main__":
    unittest.main()
