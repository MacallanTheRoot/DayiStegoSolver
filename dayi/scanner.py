"""
Scanning utilities for flags and passive next-stage artifacts.

Artifact detection is deliberately passive: matches are reported from text
that the existing tools already produced. URLs are never fetched, hostnames
are never resolved, and artifact matches never trigger file traversal.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("dayi")

_PREVIEW_LIMIT = 180

_URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
_IPV4_CANDIDATE_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)
_IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9A-Za-z:.])\[?[0-9A-Fa-f:.]{2,45}\]?(?![0-9A-Za-z:.])"
)
_DOMAIN_PATTERN = re.compile(
    r"(?<![@\w.-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![\w.-])",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERN = re.compile(
    r"\b(?:password|passwd|pwd|secret|api[_-]?key|key)\s*[:=]\s*"
    r"(?:\"[^\"\r\n]{1,128}\"|'[^'\r\n]{1,128}'|[^\s,;]{1,128})",
    re.IGNORECASE,
)
_BASE64_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,4096}={0,2}"
    r"(?![A-Za-z0-9+/=])"
)
_DECIMAL_COORDINATE_PATTERN = re.compile(
    r"(?<![\d.])"
    r"([+-]?(?:90(?:\.0+)?|[0-8]?\d(?:\.\d+)?))"
    r"\s*[,;]\s*"
    r"([+-]?(?:180(?:\.0+)?|1[0-7]\d(?:\.\d+)?|[0-9]?\d(?:\.\d+)?))"
    r"(?![\d.])"
)
_DMS_COORDINATE_PATTERN = re.compile(
    r"(?<!\w)"
    r"(\d{1,2})\s*[°º]\s*(\d{1,2})\s*['′]\s*"
    r"(\d{1,2}(?:\.\d+)?)\s*(?:[\"″]\s*)?([NS])"
    r"\s*[,;]?\s*"
    r"(\d{1,3})\s*[°º]\s*(\d{1,2})\s*['′]\s*"
    r"(\d{1,2}(?:\.\d+)?)\s*(?:[\"″]\s*)?([EW])"
    r"(?!\w)",
    re.IGNORECASE,
)
_COMMON_FILE_SUFFIXES = frozenset({
    "bmp", "csv", "gif", "jpeg", "jpg", "json", "log", "md", "pdf",
    "png", "py", "rar", "tar", "tif", "tiff", "txt", "wav", "xml", "zip",
})
_COMMON_DOMAIN_TLDS = frozenset({
    "ai", "app", "au", "biz", "ca", "cc", "ch", "cloud", "cn", "co",
    "com", "de", "dev", "edu", "fr", "gg", "gov", "in", "info", "io",
    "it", "jp", "me", "mil", "net", "nl", "online", "org", "ru", "site",
    "tech", "tr", "tv", "uk", "us", "xyz",
})


@dataclass(frozen=True)
class ArtifactFinding:
    """A bounded, terminal-safe preview of a possible next-stage artifact."""

    artifact_type: str
    preview: str
    source: str
    decoded_preview: str | None = None


def _safe_preview(value: str, limit: int = _PREVIEW_LIMIT) -> str:
    """Make untrusted tool output safe to print without terminal controls."""
    escaped: list[str] = []
    for char in value.strip():
        codepoint = ord(char)
        if char == "\n":
            escaped.append(r"\n")
        elif char == "\r":
            escaped.append(r"\r")
        elif char == "\t":
            escaped.append(r"\t")
        elif unicodedata.category(char).startswith("C"):
            if codepoint <= 0xFF:
                escaped.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                escaped.append(f"\\u{codepoint:04x}")
            else:
                escaped.append(f"\\U{codepoint:08x}")
        else:
            escaped.append(char)

    preview = "".join(escaped)
    if len(preview) <= limit:
        return preview
    return preview[: limit - 1] + "…"


def _overlaps(span: tuple[int, int], occupied: list[tuple[int, int]]) -> bool:
    """Return whether a match overlaps an already classified text span."""
    start, end = span
    return any(start < used_end and end > used_start for used_start, used_end in occupied)


def _is_plausible_domain(domain: str) -> bool:
    """Reject short binary-like labels while retaining useful CTF domains."""
    if len(domain) < 6:
        return False
    labels = domain.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    return tld in _COMMON_DOMAIN_TLDS or any(
        len(label) > 2 for label in labels[:-1]
    )


def decode_base64_text(candidate: str) -> str | None:
    """Strictly decode Base64 and accept only printable UTF-8 text."""
    if len(candidate) < 20 or len(candidate) % 4 == 1:
        return None

    padded = candidate + ("=" * (-len(candidate) % 4))
    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded_text = decoded_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None

    if not decoded_text:
        return None
    if any(not (char.isprintable() or char in "\r\n\t") for char in decoded_text):
        return None

    # Reject non-canonical lookalikes that happen to decode successfully.
    canonical = base64.b64encode(decoded_bytes).decode("ascii").rstrip("=")
    if canonical != candidate.rstrip("="):
        return None
    return decoded_text


def scan_artifacts(content: str, source: str) -> list[ArtifactFinding]:
    """
    Detect passive next-stage artifacts in existing textual output.

    The scanner performs no I/O. Returned values are bounded and stripped of
    terminal control characters so callers can safely display the previews.
    """
    findings: list[ArtifactFinding] = []
    seen: set[tuple[str, str, str | None]] = set()
    occupied_urls: list[tuple[int, int]] = []

    def add(artifact_type: str, value: str, decoded: str | None = None) -> None:
        preview = _safe_preview(value)
        decoded_preview = _safe_preview(decoded) if decoded is not None else None
        key = (artifact_type, preview, decoded_preview)
        if preview and key not in seen:
            seen.add(key)
            findings.append(
                ArtifactFinding(
                    artifact_type=artifact_type,
                    preview=preview,
                    source=source,
                    decoded_preview=decoded_preview,
                )
            )

    for match in _URL_PATTERN.finditer(content):
        value = match.group(0).rstrip(".,;:!?)]}")
        if value:
            add("url", value)
            occupied_urls.append((match.start(), match.start() + len(value)))

    for match in _CREDENTIAL_PATTERN.finditer(content):
        add("credential", match.group(0).rstrip(".])}"))

    for match in _DMS_COORDINATE_PATTERN.finditer(content):
        lat_deg, lat_min, lat_sec, _lat_dir, lon_deg, lon_min, lon_sec, _lon_dir = (
            match.groups()
        )
        latitude_boundary_valid = int(lat_deg) < 90 or (
            int(lat_min) == 0 and float(lat_sec) == 0
        )
        longitude_boundary_valid = int(lon_deg) < 180 or (
            int(lon_min) == 0 and float(lon_sec) == 0
        )
        if (
            int(lat_deg) <= 90
            and int(lon_deg) <= 180
            and int(lat_min) < 60
            and int(lon_min) < 60
            and float(lat_sec) < 60
            and float(lon_sec) < 60
            and latitude_boundary_valid
            and longitude_boundary_valid
        ):
            add("coordinates_dms", match.group(0))

    for match in _DECIMAL_COORDINATE_PATTERN.finditer(content):
        latitude, longitude = match.groups()
        # A decimal coordinate must contain a fractional component. This avoids
        # classifying common comma-separated integer output as a location.
        if "." not in latitude and "." not in longitude:
            continue
        if -90 <= float(latitude) <= 90 and -180 <= float(longitude) <= 180:
            add("coordinates_decimal", match.group(0))

    valid_ipv6: list[tuple[re.Match[str], ipaddress.IPv6Address]] = []
    occupied_ipv6: list[tuple[int, int]] = []
    for match in _IPV6_CANDIDATE_PATTERN.finditer(content):
        candidate = match.group(0).strip("[]")
        if (
            len(candidate) <= 7
            or candidate.count(":") < 3
            or _overlaps(match.span(), occupied_urls)
        ):
            continue
        try:
            address_v6 = ipaddress.IPv6Address(candidate)
        except ipaddress.AddressValueError:
            continue
        if address_v6.is_unspecified or address_v6.is_loopback:
            continue
        valid_ipv6.append((match, address_v6))
        occupied_ipv6.append(match.span())

    for match in _IPV4_CANDIDATE_PATTERN.finditer(content):
        if _overlaps(match.span(), occupied_urls) or _overlaps(match.span(), occupied_ipv6):
            continue
        try:
            address_v4 = ipaddress.IPv4Address(match.group(0))
        except ipaddress.AddressValueError:
            continue
        add("ipv4", str(address_v4))

    for _match, address_v6 in valid_ipv6:
        add("ipv6", str(address_v6))

    for match in _BASE64_CANDIDATE_PATTERN.finditer(content):
        candidate = match.group(0)
        decoded = decode_base64_text(candidate)
        if decoded is not None:
            add("base64", candidate, decoded)

    for match in _DOMAIN_PATTERN.finditer(content):
        if _overlaps(match.span(), occupied_urls):
            continue
        domain = match.group(0).lower()
        if (
            domain.rsplit(".", 1)[-1] in _COMMON_FILE_SUFFIXES
            or not _is_plausible_domain(domain)
        ):
            continue
        add("domain", domain)

    return findings


def _collect_matches(pattern: re.Pattern, text: str) -> list[str]:
    """Extract unique full-match strings while preserving insertion order."""
    seen: dict[str, None] = {}
    for match in pattern.finditer(text):
        seen[match.group(0)] = None
    return list(seen)


def scan_text(content: str, pattern: re.Pattern) -> list[str]:
    """Search text for all occurrences of a compiled flag pattern."""
    return _collect_matches(pattern, content)


def scan_file(filepath: Path, pattern: re.Pattern) -> list[str]:
    """Read one file as text and return unique flag matches."""
    try:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = filepath.read_text(encoding="latin-1", errors="replace")
        return _collect_matches(pattern, content)
    except Exception as exc:
        logger.debug(f"[scan_file] Could not read {filepath}: {exc}")
        return []


def scan_directory(directory: Path, pattern: re.Pattern) -> dict[str, list[str]]:
    """Recursively scan a directory for flags only, never for artifacts."""
    results: dict[str, list[str]] = {}
    if not directory.exists():
        return results

    for root, _dirs, files in os.walk(directory):
        for filename in files:
            filepath = Path(root) / filename
            found = scan_file(filepath, pattern)
            if found:
                results[str(filepath.relative_to(directory))] = found
    return results


def compile_pattern(flag_regex: str) -> Optional[re.Pattern]:
    """Safely compile a user-supplied flag regex pattern."""
    try:
        return re.compile(flag_regex)
    except re.error as exc:
        logger.error(f"[scanner] Invalid regex pattern '{flag_regex}': {exc}")
        return None
