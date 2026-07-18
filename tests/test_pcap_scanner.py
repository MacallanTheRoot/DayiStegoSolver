import asyncio
import base64
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dayi.tools._plugin import PluginPhase
from dayi.tools.pcap_scanner import (
    PCAPDependencies,
    PLUGIN_SPECS,
    _has_pcap_magic,
    run_pcap_scanner,
)

_PCAP_FIXTURE_B64 = (
    "1MOyoQIABAAAAAAAAAAAAP//AAABAAAAHStaakq6BAB7AAAAewAAAP///////5wv"
    "nVB12wgARQAAbQABAABABmaICgAAAQoAAAIwOQBQAAAAAAAAAABQGCAAcb8AAEdF"
    "VCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLm9yZw0KWC1GbGFnOiBGTEFHe3Jl"
    "YWxfcGNhcF9zdHJlYW19DQoNCg=="
)
_PCAPNG_FIXTURE_B64 = (
    "Cg0NChwAAABNPCsaAQAAAP//////////HAAAAAEAAAAUAAAAAQAAAAAABAAUAAAA"
    "BgAAAIwAAAAAAAAAzlYGAPry7lxpAAAAaQAAAAARIjNEVWZ3iJmquwgARQAAWwAB"
    "AABABmaaCgAAAQoAAAIwOQBQAAAAAAAAAABQGCAA2FgAAEROUyBoaW50IHN0YWdl"
    "LmV4YW1wbGUub3JnIEZMQUd7cmVhbF9wY2Fwbmdfc3RyZWFtfQAAAIwAAAA="
)


class _IP:
    pass


class _TCP:
    pass


class _UDP:
    pass


class _DNS:
    pass


class _DNSQR:
    pass


class _DNSRR:
    pass


class _ICMP:
    pass


class _Raw:
    pass


class _FakePacket:
    def __init__(self, layers: dict[type, object]) -> None:
        self.layers = layers

    def haslayer(self, layer: type) -> bool:
        return layer in self.layers

    def __getitem__(self, layer: type):
        return self.layers[layer]


class _BrokenPacket:
    def haslayer(self, layer: type) -> bool:
        del layer
        raise ValueError("broken packet")


class _FakeReader:
    def __init__(self, packets: list[object]) -> None:
        self.packets = packets
        self.closed = False

    def __iter__(self):
        return iter(self.packets)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        self.closed = True


class _FakeScapy:
    IP = _IP
    TCP = _TCP
    UDP = _UDP
    DNS = _DNS
    DNSQR = _DNSQR
    DNSRR = _DNSRR
    ICMP = _ICMP
    Raw = _Raw

    def __init__(self, reader: _FakeReader | BaseException) -> None:
        self.reader = reader
        self.calls: list[str] = []

    def PcapReader(self, filename: str) -> _FakeReader:
        self.calls.append(filename)
        if isinstance(self.reader, BaseException):
            raise self.reader
        return self.reader


def _write_fixture(path: Path, encoded: str = _PCAP_FIXTURE_B64) -> None:
    path.write_bytes(base64.b64decode(encoded))


class PCAPScannerTests(unittest.TestCase):
    def _run_with_reader(
        self,
        target: Path,
        reader: _FakeReader | BaseException,
        *,
        progress: list[tuple[int, int | None]] | None = None,
        artifacts: list[str] | None = None,
    ):
        fake_scapy = _FakeScapy(reader)
        dependencies = PCAPDependencies(scapy=fake_scapy)
        progress_callback = (
            None
            if progress is None
            else lambda done, total: progress.append((done, total))
        )
        with patch(
            "dayi.tools.pcap_scanner._load_pcap_dependencies",
            return_value=dependencies,
        ):
            result = asyncio.run(
                run_pcap_scanner(
                    target,
                    re.compile(r"FLAG\{.*?\}"),
                    workspace=target.parent,
                    progress_callback=progress_callback,
                    artifact_callback=(
                        None if artifacts is None else artifacts.append
                    ),
                )
            )
        return result, fake_scapy

    def test_plugin_is_concurrent_with_priority_47(self) -> None:
        self.assertEqual(len(PLUGIN_SPECS), 1)
        plugin = PLUGIN_SPECS[0]
        self.assertEqual(plugin.plugin_id, "pcap_scanner")
        self.assertEqual(plugin.phase, PluginPhase.CONCURRENT)
        self.assertEqual(plugin.priority, 47)
        self.assertTrue(plugin.contributes_to_mini_wordlist)

    def test_recognizes_pcap_endianness_and_pcapng_magic(self) -> None:
        magics = (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x0a\x0d\x0d\x0a",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for index, magic in enumerate(magics):
                target = root / f"capture-{index}.bin"
                target.write_bytes(magic + b"fixture")
                self.assertTrue(_has_pcap_magic(target))

    def test_non_capture_skips_before_loading_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "plain.bin"
            target.write_bytes(b"not a capture")
            with patch(
                "dayi.tools.pcap_scanner._load_pcap_dependencies",
                side_effect=AssertionError("dependency loader must not run"),
            ):
                result = asyncio.run(
                    run_pcap_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("PCAP or PCAPNG magic", result.skip_reason)

    def test_missing_optional_dependency_skips_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "capture.pcap"
            _write_fixture(target)
            with patch(
                "dayi.tools.pcap_scanner._load_pcap_dependencies",
                return_value=None,
            ):
                result = asyncio.run(
                    run_pcap_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("optional Scapy dependency", result.skip_reason)

    def test_extracts_raw_dns_flags_artifacts_and_progress(self) -> None:
        http_payload = (
            b"GET /stage HTTP/1.1\r\n"
            b"Host: example.org\r\n"
            b"X-Flag: FLAG{pcap_mock_success}\r\n"
            b"X-Token: c2VjcmV0LW5ldHdvcmstcGFzcw==\r\n\r\n"
        )
        packets = [
            _FakePacket(
                {
                    _IP: SimpleNamespace(src="10.0.0.1", dst="10.0.0.2"),
                    _TCP: SimpleNamespace(sport=4242, dport=80),
                    _Raw: SimpleNamespace(load=http_payload),
                }
            ),
            _FakePacket(
                {
                    _IP: SimpleNamespace(src="8.8.8.8", dst="10.0.0.1"),
                    _UDP: SimpleNamespace(sport=53, dport=53000),
                    _DNS: SimpleNamespace(),
                    _DNSQR: SimpleNamespace(qname=b"stage.example.net."),
                }
            ),
        ]
        reader = _FakeReader(packets)
        progress: list[tuple[int, int | None]] = []
        messages: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "capture.pcap"
            _write_fixture(target)
            result, fake_scapy = self._run_with_reader(
                target,
                reader,
                progress=progress,
                artifacts=messages,
            )

        self.assertFalse(result.skipped)
        self.assertEqual(result.flags_found, ["FLAG{pcap_mock_success}"])
        self.assertEqual(progress, [])
        artifact_types = {item.artifact_type for item in result.artifacts_found}
        self.assertTrue({"base64", "domain"}.issubset(artifact_types))
        self.assertTrue(any("secret-network-pass" in item for item in messages))
        self.assertTrue(any("stage.example.net" in item for item in messages))
        self.assertIn("Raw payload", result.stdout)
        self.assertIn("DNS query: stage.example.net", result.stdout)
        self.assertEqual(fake_scapy.calls, [str(target)])
        self.assertTrue(reader.closed)

    def test_broken_packet_does_not_hide_later_packet_flag(self) -> None:
        reader = _FakeReader(
            [
                _BrokenPacket(),
                _FakePacket(
                    {
                        _UDP: SimpleNamespace(sport=1000, dport=1001),
                        _Raw: SimpleNamespace(load=b"FLAG{pcap_partial_success}"),
                    }
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "partial.pcap"
            _write_fixture(target)
            result, _module = self._run_with_reader(target, reader)

        self.assertEqual(result.flags_found, ["FLAG{pcap_partial_success}"])
        self.assertIn("packet 1: ValueError", result.stderr)

    def test_packet_limit_prevents_processing_later_packets(self) -> None:
        reader = _FakeReader(
            [
                _FakePacket(
                    {
                        _TCP: SimpleNamespace(sport=1, dport=2),
                        _Raw: SimpleNamespace(load=b"FLAG{inside_packet_limit}"),
                    }
                ),
                _FakePacket(
                    {
                        _TCP: SimpleNamespace(sport=3, dport=4),
                        _Raw: SimpleNamespace(load=b"FLAG{outside_packet_limit}"),
                    }
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "limited.pcap"
            _write_fixture(target)
            with patch("dayi.tools.pcap_scanner.MAX_PACKETS", 1):
                result, _module = self._run_with_reader(target, reader)

        self.assertEqual(result.flags_found, ["FLAG{inside_packet_limit}"])
        self.assertNotIn("outside_packet_limit", result.stdout)
        self.assertIn("packet limit reached (1)", result.stderr)

    def test_oversized_capture_skips_before_loading_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "large.pcap"
            _write_fixture(target)
            with (
                patch("dayi.tools.pcap_scanner.MAX_PCAP_BYTES", 4),
                patch(
                    "dayi.tools.pcap_scanner._load_pcap_dependencies",
                    side_effect=AssertionError("dependency loader must not run"),
                ),
            ):
                result = asyncio.run(
                    run_pcap_scanner(target, re.compile(r"FLAG\{.*?\}"))
                )

        self.assertTrue(result.skipped)
        self.assertIn("exceeds safety limit", result.skip_reason)

    def test_reader_exception_skips_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "broken.pcap"
            _write_fixture(target)
            result, _module = self._run_with_reader(
                target,
                ValueError("invalid capture header"),
            )

        self.assertTrue(result.skipped)
        self.assertIn("PCAP parsing failed", result.skip_reason)

    @unittest.skipUnless(
        importlib.util.find_spec("scapy") is not None,
        "optional Scapy dependency is not installed",
    )
    def test_real_scapy_streams_base64_pcap_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "fixture.pcap"
            _write_fixture(target)
            result = asyncio.run(
                run_pcap_scanner(target, re.compile(r"FLAG\{.*?\}"))
            )

        self.assertFalse(result.skipped)
        self.assertEqual(result.flags_found, ["FLAG{real_pcap_stream}"])
        self.assertIn("Packets scanned: 1", result.stdout)

    @unittest.skipUnless(
        importlib.util.find_spec("scapy") is not None,
        "optional Scapy dependency is not installed",
    )
    def test_real_scapy_streams_base64_pcapng_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "fixture.pcapng"
            _write_fixture(target, _PCAPNG_FIXTURE_B64)
            result = asyncio.run(
                run_pcap_scanner(target, re.compile(r"FLAG\{.*?\}"))
            )

        self.assertFalse(result.skipped)
        self.assertEqual(result.flags_found, ["FLAG{real_pcapng_stream}"])
        self.assertIn("Packets scanned: 1", result.stdout)


if __name__ == "__main__":
    unittest.main()
