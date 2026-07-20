import base64
import codecs
import gzip
import hashlib
import re
import tempfile
import unittest
import urllib.parse
import zlib
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

import dayi.text_stego as engine
from dayi.text_stego import (
    MAX_AGGREGATE_DECODED_BYTES,
    MAX_DECODE_DEPTH,
    MAX_TOTAL_CANDIDATES,
    analyze_text_input,
    detect_text_bytes,
    escape_unsafe_text,
    read_text_input,
)


CUSTOM_FLAG = "SiberVatan{metin_stego}"
CUSTOM_PATTERN = re.compile(r"SiberVatan\{.*?\}")


def _bits(value: str) -> str:
    return "".join(f"{byte:08b}" for byte in value.encode("utf-8"))


def _analysis(text: str, pattern: re.Pattern = CUSTOM_PATTERN):
    return analyze_text_input(detect_text_bytes(text.encode("utf-8")), pattern)


def _flags(analysis) -> list[str]:
    return [
        flag
        for candidate in analysis.candidates
        for flag in candidate.flags_found
    ]


def _bacon_stream(value: str) -> str:
    encoded = base64.b32encode(value.encode("utf-8")).decode("ascii").rstrip("=")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(f"{alphabet.index(character):05b}" for character in encoded)


class TextInputDetectionTests(unittest.TestCase):
    def test_supported_unicode_encodings_are_detected_from_bytes(self) -> None:
        samples = (
            (CUSTOM_FLAG.encode("ascii"), "ascii"),
            (CUSTOM_FLAG.encode("utf-8-sig"), "utf-8-bom"),
            (b"\xff\xfe" + CUSTOM_FLAG.encode("utf-16-le"), "utf-16-le-bom"),
            (b"\xfe\xff" + CUSTOM_FLAG.encode("utf-16-be"), "utf-16-be-bom"),
            (b"\xff\xfe\x00\x00" + CUSTOM_FLAG.encode("utf-32-le"), "utf-32-le-bom"),
            (b"\x00\x00\xfe\xff" + CUSTOM_FLAG.encode("utf-32-be"), "utf-32-be-bom"),
            (CUSTOM_FLAG.encode("utf-16-le"), "utf-16-le"),
            (CUSTOM_FLAG.encode("utf-16-be"), "utf-16-be"),
            (CUSTOM_FLAG.encode("utf-32-le"), "utf-32-le"),
            (CUSTOM_FLAG.encode("utf-32-be"), "utf-32-be"),
            ("SiberVatan{utf8_ç}".encode("utf-8"), "utf-8"),
        )
        for data, expected in samples:
            with self.subTest(encoding=expected):
                detected = detect_text_bytes(data)
                self.assertEqual(detected.classification, "probable-text")
                self.assertEqual(detected.encoding, expected)
                self.assertIn("SiberVatan{", detected.text)

    def test_latin1_is_only_used_for_textlike_data(self) -> None:
        latin = detect_text_bytes("café résumé metni".encode("latin-1"))
        binary = detect_text_bytes(b"\xff" * 128)

        self.assertEqual(latin.encoding, "latin-1")
        self.assertEqual(latin.classification, "probable-text")
        self.assertEqual(binary.classification, "binary")

    def test_binary_with_printable_fragment_is_not_probable_text(self) -> None:
        detected = detect_text_bytes(
            b"\x89PNG\r\n\x1a\n\x00\xff" + b"visible-fragment" + b"\x00\xff" * 40
        )
        self.assertNotEqual(detected.classification, "probable-text")

        fragments = detect_text_bytes(
            b"\x81\x82\x83" * 20 + b"visible ordinary text fragment " * 3
        )
        self.assertEqual(fragments.classification, "text-fragments")

    def test_source_and_character_limits_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.object(
            engine, "MAX_SOURCE_BYTES", 64
        ), patch.object(engine, "MAX_DECODED_CHARACTERS", 32):
            source = Path(tmpdir) / "large.txt"
            source.write_bytes(b"A" * 100)
            detected = read_text_input(source)

        self.assertEqual(len(detected.raw_bytes), 64)
        self.assertEqual(len(detected.text), 32)
        self.assertTrue(detected.truncated)


class BaconDecoderTests(unittest.TestCase):
    def test_literal_ab_lowercase_and_binary_variants(self) -> None:
        bitstream = _bacon_stream(CUSTOM_FLAG)
        variants = (
            "".join("A" if bit == "0" else "B" for bit in bitstream),
            "".join("a" if bit == "0" else "b" for bit in bitstream),
            bitstream,
        )
        for text in variants:
            with self.subTest(sample=text[:8]):
                analysis = _analysis(text)
                self.assertIn(CUSTOM_FLAG, _flags(analysis))
                self.assertTrue(any(candidate.decoder.startswith("bacon") for candidate in analysis.candidates))

    def test_uppercase_lowercase_pattern_decodes(self) -> None:
        bitstream = _bacon_stream(CUSTOM_FLAG)
        cover = "".join("x" if bit == "0" else "X" for bit in bitstream)
        analysis = _analysis(cover)

        self.assertIn(CUSTOM_FLAG, _flags(analysis))
        self.assertTrue(any("letter-case" in candidate.variant for candidate in analysis.candidates))

    def test_two_symbol_and_two_word_classes_are_bounded(self) -> None:
        bitstream = _bacon_stream(CUSTOM_FLAG)
        symbol_text = "".join("." if bit == "0" else "-" for bit in bitstream)
        word_text = " ".join("alpha" if bit == "0" else "beta" for bit in bitstream)

        self.assertIn(CUSTOM_FLAG, _flags(_analysis(symbol_text)))
        self.assertIn(CUSTOM_FLAG, _flags(_analysis(word_text)))

    def test_repeated_bacon_noise_is_not_a_confirmed_or_high_candidate(self) -> None:
        analysis = _analysis("AB" * 100)

        self.assertEqual(_flags(analysis), [])
        self.assertFalse(any(candidate.confidence == "high" for candidate in analysis.candidates))


class WhitespaceAndUnicodeDecoderTests(unittest.TestCase):
    def test_space_tab_stream_and_trailing_whitespace_decode(self) -> None:
        bitstream = _bits(CUSTOM_FLAG)
        raw_stream = "".join(" " if bit == "0" else "\t" for bit in bitstream)
        trailing = "\n".join(
            f"line{index}" + (" " if bit == "0" else "\t")
            for index, bit in enumerate(bitstream)
        )

        self.assertIn(CUSTOM_FLAG, _flags(_analysis(raw_stream)))
        trailing_analysis = _analysis(trailing)
        self.assertIn(CUSTOM_FLAG, _flags(trailing_analysis))
        self.assertTrue(any("trailing-space-vs-tab" in candidate.variant for candidate in trailing_analysis.candidates))

    def test_reversed_whitespace_payload_uses_recursive_reverse(self) -> None:
        bitstream = _bits(CUSTOM_FLAG[::-1])
        text = "".join(" " if bit == "0" else "\t" for bit in bitstream)
        analysis = _analysis(text)

        self.assertIn(CUSTOM_FLAG, _flags(analysis))
        self.assertTrue(any(candidate.decoder.endswith(">reverse") for candidate in analysis.candidates if candidate.flags_found))

    def test_zero_width_binary_and_swapped_mapping_decode(self) -> None:
        payload = base64.b64encode(CUSTOM_FLAG.encode("utf-8")).decode("ascii")
        bitstream = _bits(payload)
        normal = "cover:" + "".join("\u200b" if bit == "0" else "\u200c" for bit in bitstream)
        swapped = "cover:" + "".join("\u200c" if bit == "0" else "\u200b" for bit in bitstream)

        for text in (normal, swapped):
            analysis = _analysis(text)
            self.assertIn(CUSTOM_FLAG, _flags(analysis))
            self.assertTrue(any(candidate.decoder == "zero_width>binary>base64" for candidate in analysis.candidates if candidate.flags_found))

    def test_homoglyph_latin_cyrillic_stream_decodes(self) -> None:
        text = "".join("a" if bit == "0" else "а" for bit in _bits(CUSTOM_FLAG))
        analysis = _analysis(text)

        self.assertIn(CUSTOM_FLAG, _flags(analysis))
        self.assertTrue(any(candidate.decoder.startswith("homoglyph>binary") for candidate in analysis.candidates if candidate.flags_found))

    def test_fullwidth_ascii_stream_decodes(self) -> None:
        text = "".join("A" if bit == "0" else "Ａ" for bit in _bits(CUSTOM_FLAG))
        analysis = _analysis(text)

        self.assertIn(CUSTOM_FLAG, _flags(analysis))
        self.assertTrue(any("ascii-vs-fullwidth" in candidate.variant for candidate in analysis.candidates if candidate.flags_found))

    def test_legitimate_cyrillic_and_bidi_without_payload_stay_unconfirmed(self) -> None:
        cyrillic = _analysis("Это обычный русский текст без скрытого сообщения.")
        bidi = _analysis("ordinary\u202etext\u202c without a hidden payload")

        self.assertEqual(_flags(cyrillic), [])
        self.assertFalse(any(candidate.decoder.startswith("homoglyph") for candidate in cyrillic.candidates))
        self.assertEqual(_flags(bidi), [])
        self.assertFalse(any(candidate.confidence == "high" for candidate in bidi.candidates))


class StructuralAndCommonDecoderTests(unittest.TestCase):
    def test_line_first_and_last_character_acrostics(self) -> None:
        first = "\n".join(character + " ordinary line" for character in CUSTOM_FLAG)
        last = "\n".join("ordinary line " + character for character in CUSTOM_FLAG)

        first_analysis = _analysis(first)
        last_analysis = _analysis(last)
        self.assertIn(CUSTOM_FLAG, _flags(first_analysis))
        self.assertIn(CUSTOM_FLAG, _flags(last_analysis))
        self.assertTrue(any("line-first-character" in candidate.decoder for candidate in first_analysis.candidates if candidate.flags_found))
        self.assertTrue(any("line-last-character" in candidate.decoder for candidate in last_analysis.candidates if candidate.flags_found))

    def test_uppercase_anomaly_uses_active_pattern(self) -> None:
        pattern = re.compile(r"HIDDEN")
        text = " ".join(f"ordinary{character}" for character in "HIDDEN") + " lowercase cover words"
        analysis = _analysis(text, pattern)

        self.assertIn("HIDDEN", _flags(analysis))
        self.assertTrue(any("uppercase" in candidate.decoder for candidate in analysis.candidates if candidate.flags_found))

    def test_nested_base64_and_acrostic_hex_chains(self) -> None:
        nested = base64.b64encode(base64.b64encode(CUSTOM_FLAG.encode("utf-8"))).decode("ascii")
        nested_analysis = _analysis(nested)
        hexadecimal = CUSTOM_FLAG.encode("utf-8").hex()
        acrostic = "\n".join(character + " filler" for character in hexadecimal)
        acrostic_analysis = _analysis(acrostic)

        self.assertIn(CUSTOM_FLAG, _flags(nested_analysis))
        self.assertTrue(any(candidate.decoder == "base64>base64" for candidate in nested_analysis.candidates if candidate.flags_found))
        self.assertIn(CUSTOM_FLAG, _flags(acrostic_analysis))
        self.assertTrue(any(candidate.decoder.endswith(">hex") for candidate in acrostic_analysis.candidates if candidate.flags_found))

    def test_common_decoder_family_recovers_active_flag(self) -> None:
        def atbash(value: str) -> str:
            return "".join(
                chr(ord("Z") - ord(character) + ord("A"))
                if "A" <= character <= "Z"
                else chr(ord("z") - ord(character) + ord("a"))
                if "a" <= character <= "z"
                else character
                for character in value
            )

        raw = CUSTOM_FLAG.encode("utf-8")
        samples = {
            "reverse": CUSTOM_FLAG[::-1],
            "rot13": codecs.decode(CUSTOM_FLAG, "rot_13"),
            "atbash": atbash(CUSTOM_FLAG),
            "hex": raw.hex(),
            "binary": " ".join(f"{byte:08b}" for byte in raw),
            "octal": " ".join(f"{byte:03o}" for byte in raw),
            "decimal": " ".join(str(byte) for byte in raw),
            "base32": base64.b32encode(raw).decode("ascii"),
            "base64": base64.b64encode(raw).decode("ascii"),
            "base85": base64.b85encode(raw).decode("ascii"),
            "ascii85": base64.a85encode(raw, adobe=True).decode("ascii"),
            "url-percent": urllib.parse.quote(CUSTOM_FLAG, safe=""),
            "html-entity": CUSTOM_FLAG.replace("{", "&#123;").replace("}", "&#125;"),
            "unicode-escape": CUSTOM_FLAG.replace("{", r"\u007b").replace("}", r"\u007d"),
        }
        for decoder, encoded in samples.items():
            with self.subTest(decoder=decoder):
                analysis = _analysis(encoded)
                self.assertIn(CUSTOM_FLAG, _flags(analysis))

    def test_morse_xor_and_magic_gzip_decoding_are_bounded(self) -> None:
        morse_pattern = re.compile(r"HIDDEN")
        morse = ".... .. -.. -.. . -."
        self.assertIn("HIDDEN", _flags(_analysis(morse, morse_pattern)))

        xored = bytes(byte ^ 0x5A for byte in CUSTOM_FLAG.encode("utf-8"))
        xor_analysis = _analysis(xored.hex())
        self.assertIn(CUSTOM_FLAG, _flags(xor_analysis))
        self.assertTrue(any("xor-0x5a" in candidate.decoder for candidate in xor_analysis.candidates if candidate.flags_found))

        compressed = base64.b64encode(gzip.compress(CUSTOM_FLAG.encode("utf-8"))).decode("ascii")
        gzip_analysis = _analysis(compressed)
        self.assertIn(CUSTOM_FLAG, _flags(gzip_analysis))
        self.assertTrue(any(candidate.decoder == "base64>gzip" for candidate in gzip_analysis.candidates if candidate.flags_found))

        zlib_encoded = base64.b64encode(zlib.compress(CUSTOM_FLAG.encode("utf-8"))).decode("ascii")
        zlib_analysis = _analysis(zlib_encoded)
        self.assertIn(CUSTOM_FLAG, _flags(zlib_analysis))
        self.assertTrue(any(candidate.decoder == "base64>zlib" for candidate in zlib_analysis.candidates if candidate.flags_found))

    def test_urlsafe_base64_variant_with_non_ascii_flag(self) -> None:
        flag = "X{𐀿}"
        pattern = re.compile(r"X\{.*?\}")
        encoded = base64.urlsafe_b64encode(flag.encode("utf-8")).decode("ascii")
        self.assertTrue("-" in encoded or "_" in encoded)

        analysis = _analysis(encoded, pattern)
        self.assertIn(flag, _flags(analysis))
        self.assertTrue(any(candidate.decoder == "urlsafe-base64" for candidate in analysis.candidates if candidate.flags_found))


class GhostTextAndSafetyTests(unittest.TestCase):
    def test_null_bytes_and_utf16_direct_decode_find_custom_flag(self) -> None:
        source = detect_text_bytes(CUSTOM_FLAG.encode("utf-16-le"))
        analysis = analyze_text_input(source, CUSTOM_PATTERN)

        self.assertEqual(source.encoding, "utf-16-le")
        self.assertIn(CUSTOM_FLAG, _flags(analysis))

    def test_carriage_return_and_ansi_reconstruction(self) -> None:
        carriage = _analysis("decoy text\r" + CUSTOM_FLAG)
        ansi_hidden = "".join(f"\x1b[31m{character}\x1b[0m" for character in CUSTOM_FLAG)
        ansi = _analysis(ansi_hidden)

        self.assertIn(CUSTOM_FLAG, _flags(carriage))
        self.assertIn(CUSTOM_FLAG, _flags(ansi))
        self.assertTrue(any("carriage-return" in candidate.decoder for candidate in carriage.candidates if candidate.flags_found))
        self.assertTrue(any("ansi-removal" in candidate.decoder for candidate in ansi.candidates if candidate.flags_found))

    def test_backspace_reconstruction_recovers_hidden_text(self) -> None:
        analysis = _analysis("DECOY\b\b\b\b\b" + CUSTOM_FLAG)

        self.assertIn(CUSTOM_FLAG, _flags(analysis))
        self.assertTrue(any("backspace-reconstruction" in candidate.decoder for candidate in analysis.candidates if candidate.flags_found))

    def test_terminal_and_bidi_controls_are_escaped(self) -> None:
        unsafe = "before\x1b[31mred\x1b[0m\u202eafter\rhidden"
        escaped = escape_unsafe_text(unsafe)
        analysis = _analysis(unsafe)

        self.assertNotIn("\x1b", escaped)
        self.assertNotIn("\u202e", escaped)
        self.assertNotIn("\r", escaped)
        self.assertIn("U+202E", escaped)
        self.assertTrue(all("\x1b" not in candidate.value and "\u202e" not in candidate.value for candidate in analysis.candidates))

    def test_ordinary_prose_code_markdown_tabs_and_malformed_encodings_are_noise(self) -> None:
        samples = (
            "This is ordinary prose with several normal words and no hidden payload.",
            "\n".join("    value = value + 1" if index % 2 else "        value += 2" for index in range(24)),
            "Türkçe ve English birlikte kullanılan sıradan çok dilli bir metindir.",
            "# Heading\n\n- ordinary item\n- second item\n\n`inline code`",
            "\tordinary\tcolumns\n\twithout\thidden\tdata",
            "not-base64=== 01012 0xGG 9999 8888",
            "ABAB",
            "".join(
                hashlib.sha256(f"seed-{index}".encode()).hexdigest()
                for index in range(8)
            ),
        )
        for text in samples:
            with self.subTest(text=text[:20]):
                analysis = _analysis(text)
                self.assertEqual(_flags(analysis), [])
                self.assertFalse(any(candidate.confidence == "high" for candidate in analysis.candidates))

    def test_candidate_order_deduplication_and_limits_are_deterministic(self) -> None:
        pathological = ("AB" * 5000) + "\n" + ("ordinary words " * 1000)
        first = _analysis(pathological)
        second = _analysis(pathological)

        self.assertEqual(first.candidates, second.candidates)
        self.assertLessEqual(first.total_generated, MAX_TOTAL_CANDIDATES)
        self.assertLessEqual(first.aggregate_decoded_bytes, MAX_AGGREGATE_DECODED_BYTES)
        self.assertTrue(all(candidate.depth <= MAX_DECODE_DEPTH for candidate in first.candidates))
        self.assertEqual(len({candidate.value for candidate in first.candidates}), len(first.candidates))
        if first.candidates:
            with self.assertRaises(FrozenInstanceError):
                first.candidates[0].score = 999

    def test_analysis_never_uses_network(self) -> None:
        with patch("socket.getaddrinfo") as dns, patch("urllib.request.urlopen") as fetch:
            analysis = _analysis("https://example.org ordinary local text")

        self.assertEqual(_flags(analysis), [])
        dns.assert_not_called()
        fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
