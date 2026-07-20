import unittest
from unittest.mock import patch

from dayi.scanner import classify_domain_confidence, scan_artifacts


class ArtifactScannerTests(unittest.TestCase):
    def _by_type(
        self,
        content: str,
        *,
        source: str = "test/stdout",
        include_possible: bool = False,
    ) -> dict[str, list]:
        findings = scan_artifacts(
            content,
            source=source,
            include_possible=include_possible,
        )
        grouped: dict[str, list] = {}
        for finding in findings:
            grouped.setdefault(finding.artifact_type, []).append(finding)
        return grouped

    def test_detects_url_without_fetching_or_trailing_punctuation(self) -> None:
        grouped = self._by_type("next: https://pastebin.com/AbCd1234).")

        self.assertEqual(grouped["url"][0].preview, "https://pastebin.com/AbCd1234")
        self.assertNotIn("domain", grouped)

    def test_validates_ipv4_and_ipv6(self) -> None:
        grouped = self._by_type(
            "valid: 192.168.1.5 2001:db8::1 ::1 ::ffff:192.0.2.128 "
            "invalid: 999.1.1.1"
        )

        self.assertEqual([item.preview for item in grouped["ipv4"]], ["192.168.1.5"])
        self.assertEqual(
            [item.preview for item in grouped["ipv6"]],
            ["2001:db8::1", "::ffff:192.0.2.128"],
        )

    def test_rejects_short_ipv6_like_binary_noise(self) -> None:
        grouped = self._by_type(
            "noise: :: ::1 e:: abcd::12 valid: 2001:db8:abcd::42"
        )

        self.assertEqual(
            [item.preview for item in grouped.get("ipv6", [])],
            ["2001:db8:abcd::42"],
        )

    def test_detects_credential_hints_and_standalone_domains(self) -> None:
        grouped = self._by_type(
            'password=hunter2 secret: "open sesame" key=stage-two pastebin.com'
        )

        self.assertEqual(len(grouped["credential"]), 3)
        self.assertEqual(grouped["domain"][0].preview, "pastebin.com")

    def test_discards_common_filename_as_domain(self) -> None:
        grouped = self._by_type("files: mystery.png notes.txt but hint.example.org")

        self.assertEqual([item.preview for item in grouped["domain"]], ["hint.example.org"])

    def test_rejects_short_binary_like_domains(self) -> None:
        grouped = self._by_type(
            "noise: l.tt b.up a.jr ab.zzz valid: go.dev stage.zz pastebin.com"
        )

        self.assertEqual(
            [item.preview for item in grouped.get("domain", [])],
            ["go.dev", "stage.zz", "pastebin.com"],
        )

    def test_rejects_known_random_jpeg_domain_tokens(self) -> None:
        noise = "t7s.tymb ugc9.efy iej.pk nvg.qx wcs.mx rzd.ro"

        grouped = self._by_type(
            noise,
            source="strings/stdout",
            include_possible=True,
        )

        self.assertNotIn("domain", grouped)

    def test_source_confidence_and_verbose_possible_domains(self) -> None:
        self.assertEqual(
            classify_domain_confidence("abc.dev", source="target/text"),
            "probable",
        )
        self.assertEqual(
            classify_domain_confidence("abc.dev", source="strings/stdout"),
            "possible",
        )
        default = self._by_type("abc.dev", source="strings/stdout")
        verbose = self._by_type(
            "abc.dev",
            source="strings/stdout",
            include_possible=True,
        )

        self.assertNotIn("domain", default)
        self.assertEqual(
            [item.preview for item in verbose["domain"]],
            ["abc.dev"],
        )

    def test_real_domains_urls_and_context_are_preserved_without_network(self) -> None:
        content = (
            "Host: stage.example.org email=user@example.com "
            "http://plain.example.net/a https://secure.example.com/b"
        )
        with patch(
            "socket.getaddrinfo", side_effect=AssertionError("DNS used")
        ), patch(
            "urllib.request.urlopen", side_effect=AssertionError("network used")
        ):
            grouped = self._by_type(content, source="target/text")

        self.assertEqual(
            [item.preview for item in grouped["url"]],
            ["http://plain.example.net/a", "https://secure.example.com/b"],
        )
        self.assertEqual(
            [item.preview for item in grouped["domain"]],
            ["stage.example.org", "example.com"],
        )

    def test_base64_requires_twenty_chars_and_printable_utf8(self) -> None:
        printable = "U29ucmFraSBhc2FtYSBidXJhZGE="
        binary = "AAECAwQFBgcICQoLDA0ODxAREhM="
        grouped = self._by_type(f"{printable} {binary} U2hvcnQ=")

        self.assertEqual(len(grouped["base64"]), 1)
        self.assertEqual(grouped["base64"][0].preview, printable)
        self.assertEqual(
            grouped["base64"][0].decoded_preview,
            "Sonraki asama burada",
        )

    def test_detects_decimal_and_dms_coordinates(self) -> None:
        grouped = self._by_type(
            '41.0082, 28.9784 and 41° 00\' 29.5" N, 28° 58\' 42.2" E'
        )

        self.assertEqual(grouped["coordinates_decimal"][0].preview, "41.0082, 28.9784")
        self.assertIn("41° 00", grouped["coordinates_dms"][0].preview)

    def test_rejects_out_of_range_dms_boundary(self) -> None:
        grouped = self._by_type('90° 01\' 00" N, 180° 00\' 00" E')

        self.assertNotIn("coordinates_dms", grouped)

    def test_terminal_controls_are_escaped_in_preview(self) -> None:
        grouped = self._by_type("https://example.org/path\x1b[31m\u202e")

        preview = grouped["url"][0].preview
        self.assertNotIn("\x1b", preview)
        self.assertIn(r"\x1b", preview)
        self.assertNotIn("\u202e", preview)
        self.assertIn(r"\u202e", preview)


if __name__ == "__main__":
    unittest.main()
