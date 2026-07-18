"""
Scanning utilities for flags and passive next-stage artifacts.

Artifact detection is deliberately passive: matches are reported from text
that the existing tools already produced. URLs are never fetched, hostnames
are never resolved, and artifact matches never trigger file traversal.
"""
from __future__ import annotations

import base64
import binascii
import bisect
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
MAX_ARTIFACT_INPUT_CHARS = 4 * 1024 * 1024
MAX_ARTIFACT_FINDINGS = 512
MAX_SCAN_FILE_BYTES = 8 * 1024 * 1024
MAX_SCAN_FILES = 4_096
MAX_SCAN_DIRECTORY_BYTES = 128 * 1024 * 1024
MAX_FLAG_REGEX_CHARS = 512
MAX_FLAG_MATCHES = 1_024

_URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']{1,2048}", re.IGNORECASE)
_IPV4_CANDIDATE_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)
_IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9A-Za-z:.])\[?[0-9A-Fa-f:.]{2,45}\]?(?![0-9A-Za-z:.])"
)
_DOMAIN_PATTERN = re.compile(
    r"(?<![@\w.-])(?=[\w.-]{1,253}(?![\w.-]))"
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
    r"([+-]?(?:90(?:\.0{1,12})?|[0-8]?\d(?:\.\d{1,12})?))"
    r"\s*[,;]\s*"
    r"([+-]?(?:180(?:\.0{1,12})?|1[0-7]\d(?:\.\d{1,12})?|[0-9]?\d(?:\.\d{1,12})?))"
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
    rendered_length = 0
    for char in value.strip():
        codepoint = ord(char)
        if char == "\n":
            rendered = r"\n"
        elif char == "\r":
            rendered = r"\r"
        elif char == "\t":
            rendered = r"\t"
        elif unicodedata.category(char).startswith("C"):
            if codepoint <= 0xFF:
                rendered = f"\\x{codepoint:02x}"
            elif codepoint <= 0xFFFF:
                rendered = f"\\u{codepoint:04x}"
            else:
                rendered = f"\\U{codepoint:08x}"
        else:
            rendered = char
        if rendered_length + len(rendered) >= limit:
            remaining = max(0, limit - rendered_length - 1)
            if remaining:
                escaped.append(rendered[:remaining])
            escaped.append("…")
            return "".join(escaped)
        escaped.append(rendered)
        rendered_length += len(rendered)

    preview = "".join(escaped)
    if len(preview) <= limit:
        return preview
    return preview[: limit - 1] + "…"


def _overlaps(span: tuple[int, int], occupied: list[tuple[int, int]]) -> bool:
    """Return whether a match overlaps an already classified text span."""
    start, end = span
    index = bisect.bisect_right(occupied, (start, float("inf")))
    if index and occupied[index - 1][1] > start:
        return True
    return index < len(occupied) and occupied[index][0] < end


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


def scan_artifacts(
    content: str,
    source: str,
    max_findings: int = MAX_ARTIFACT_FINDINGS,
) -> list[ArtifactFinding]:
    """
    Detect passive next-stage artifacts in existing textual output.

    The scanner performs no I/O. Returned values are bounded and stripped of
    terminal control characters so callers can safely display the previews.
    """
    content = content[:MAX_ARTIFACT_INPUT_CHARS]
    findings: list[ArtifactFinding] = []
    seen: set[tuple[str, str, str | None]] = set()
    occupied_urls: list[tuple[int, int]] = []

    def add(artifact_type: str, value: str, decoded: str | None = None) -> None:
        preview = _safe_preview(value)
        decoded_preview = _safe_preview(decoded) if decoded is not None else None
        key = (artifact_type, preview, decoded_preview)
        if preview and key not in seen and len(findings) < max_findings:
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
        if len(findings) >= max_findings:
            break
        value = match.group(0).rstrip(".,;:!?)]}")
        if value:
            add("url", value)
            occupied_urls.append((match.start(), match.start() + len(value)))

    for match in _CREDENTIAL_PATTERN.finditer(content):
        if len(findings) >= max_findings:
            break
        add("credential", match.group(0).rstrip(".])}"))

    for match in _DMS_COORDINATE_PATTERN.finditer(content):
        if len(findings) >= max_findings:
            break
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
        if len(findings) >= max_findings:
            break
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
        if len(findings) >= max_findings:
            break
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
        if len(findings) >= max_findings:
            break
        if _overlaps(match.span(), occupied_urls) or _overlaps(match.span(), occupied_ipv6):
            continue
        try:
            address_v4 = ipaddress.IPv4Address(match.group(0))
        except ipaddress.AddressValueError:
            continue
        add("ipv4", str(address_v4))

    for _match, address_v6 in valid_ipv6:
        if len(findings) >= max_findings:
            break
        add("ipv6", str(address_v6))

    for match in _BASE64_CANDIDATE_PATTERN.finditer(content):
        if len(findings) >= max_findings:
            break
        candidate = match.group(0)
        decoded = decode_base64_text(candidate)
        if decoded is not None:
            add("base64", candidate, decoded)

    for match in _DOMAIN_PATTERN.finditer(content):
        if len(findings) >= max_findings:
            break
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
        if len(seen) >= MAX_FLAG_MATCHES:
            break
    return list(seen)


def scan_text(content: str, pattern: re.Pattern) -> list[str]:
    """Search text for all occurrences of a compiled flag pattern."""
    return _collect_matches(pattern, content)


def scan_file(filepath: Path, pattern: re.Pattern) -> list[str]:
    """Read a bounded regular file and return unique flag matches."""
    try:
        if filepath.is_symlink() or not filepath.is_file():
            return []
        with filepath.open("rb") as source:
            raw = source.read(MAX_SCAN_FILE_BYTES + 1)
        if len(raw) > MAX_SCAN_FILE_BYTES:
            logger.debug(
                f"[scan_file] {filepath} güvenli tarama sınırını aştı; atlandı."
            )
            return []
        content = raw.decode("utf-8", errors="replace")
        return _collect_matches(pattern, content)
    except Exception as exc:
        logger.debug(f"[scan_file] {filepath} okunamadı yeğenim: {exc}")
        return []


def scan_directory(directory: Path, pattern: re.Pattern) -> dict[str, list[str]]:
    """Recursively scan a directory for flags only, never for artifacts."""
    results: dict[str, list[str]] = {}
    if not directory.exists():
        return results

    scanned_files = 0
    scanned_bytes = 0
    for root, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(root) / name).is_symlink()]
        for filename in files:
            filepath = Path(root) / filename
            if filepath.is_symlink():
                continue
            try:
                file_size = filepath.stat().st_size
            except OSError:
                continue
            if (
                scanned_files >= MAX_SCAN_FILES
                or scanned_bytes + file_size > MAX_SCAN_DIRECTORY_BYTES
            ):
                logger.warning(
                    "[scanner] Yeğenim çıkarılan dosya tarama sınırına ulaştı; "
                    "kalanları güvenlik için es geçiyorum."
                )
                return results
            scanned_files += 1
            scanned_bytes += file_size
            found = scan_file(filepath, pattern)
            if found:
                results[str(filepath.relative_to(directory))] = found
    return results


def compile_pattern(flag_regex: str) -> Optional[re.Pattern]:
    """Safely compile a user-supplied flag regex pattern."""
    unsafe_patterns = (
        r"\\[1-9]",
        r"\(\?(?:[=!]|<[=!])",
        r"\((?:[^()\\]|\\.)*[*+](?:[^()\\]|\\.)*\)\s*[*+{]",
        r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)\s*[*+{]",
    )
    if len(flag_regex) > MAX_FLAG_REGEX_CHARS or any(
        re.search(unsafe, flag_regex) for unsafe in unsafe_patterns
    ):
        logger.error(
            "[scanner] Yeğenim bu flag deseni güvenli regex sınırlarını aşıyor; "
            "iç içe tekrar, geri referans ve lookaround kullanma."
        )
        return None
    try:
        return re.compile(flag_regex)
    except re.error as exc:
        logger.error(f"[scanner] Flag regex deseni geçersiz yeğenim: {exc}")
        return None
