"""Bounded, dependency-free text steganography analysis primitives."""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import math
import re
import unicodedata
import urllib.parse
import zlib
from collections import Counter, deque
from dataclasses import dataclass
from itertools import permutations
from pathlib import Path
from typing import Literal


MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_DECODED_CHARACTERS = 4_000_000
MAX_ANALYSIS_CHARACTERS = 1024 * 1024
MAX_CANDIDATE_OUTPUT = 64 * 1024
MAX_CANDIDATE_PREVIEW = 240
MAX_STRUCTURAL_CANDIDATES = 256
MAX_DECODE_DEPTH = 3
MAX_CHILDREN_PER_CANDIDATE = 32
MAX_TOTAL_CANDIDATES = 512
MAX_DECODED_BYTES_PER_CANDIDATE = 1024 * 1024
MAX_AGGREGATE_DECODED_BYTES = 16 * 1024 * 1024
MAX_DIRECT_FLAGS = 64
MAX_DIRECT_FLAG_CHARACTERS = 64 * 1024
MAX_DIRECT_FLAG_LENGTH = 2048
MAX_BINARY_ASCII_CANDIDATES = 32
DEFAULT_HINT_LIMIT = 10
VERBOSE_HINT_LIMIT = 25

TextClassification = Literal["probable-text", "text-fragments", "binary"]
CandidateConfidence = Literal["confirmed", "high", "medium", "low"]

_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-_])")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9'_-]{2,}")
_CTF_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,31}\{[^{}\r\n]{1,512}\}")
_COMMON_WORDS = frozenset({
    "a", "and", "are", "as", "at", "be", "bir", "bu", "by", "decode",
    "flag", "for", "from", "hidden", "in", "is", "it", "message", "of",
    "on", "or", "secret", "stego", "text", "that", "the", "this", "to",
    "ve", "with", "you",
})

_INVISIBLE_NAMES = {
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    **{chr(value): unicodedata.name(chr(value), "FORMAT CHARACTER")
       for value in range(0x2061, 0x2065)},
    **{chr(value): unicodedata.name(chr(value), "BIDI CONTROL")
       for value in range(0x202A, 0x202F)},
    **{chr(value): unicodedata.name(chr(value), "BIDI ISOLATE")
       for value in range(0x2066, 0x206A)},
}
_BIDI_CHARACTERS = frozenset(
    chr(value) for value in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))
)

_CYRILLIC_HOMOGLYPHS = frozenset("асеорхуіј")
_LATIN_HOMOGLYPHS = frozenset("aceopxyij")
_GREEK_HOMOGLYPHS = frozenset("ΑΒΕΗΙΚΜΝΟΡΤΧΥο")
_GREEK_LATIN_EQUIVALENTS = frozenset("ABEHIKMNOPTXYo")

_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
}

# Printable flag-oriented subset of SNOW 1.1's fixed Huffman table. The
# whitespace unpacking and prefix decoding remain bounded and dependency-free.
_SNOW_HUFFMAN_CODES = {
    "0101": "a", "001001": "b", "110110": "c", "01000": "d",
    "1100": "e", "101010": "f", "011101": "g", "10001": "h",
    "0011": "i", "1010011111": "j", "0100110": "k", "01111": "l",
    "101110": "m", "0001": "n", "0110": "o", "100001": "p",
    "10111111101": "q", "11010": "r", "0000": "s", "1001": "t",
    "110111": "u", "0111001": "v", "001011": "w", "10101111": "x",
    "100000": "y", "1010011000": "z", "01001111": "A",
    "1011110110": "B", "101100011": "C", "101001101": "D",
    "00100010": "E", "001010010": "F", "1011000000": "G",
    "1011001101": "H", "0111000": "I", "10110000011": "J",
    "10110001011": "K", "001010100": "L", "101100111": "M",
    "101001011": "N", "101100001": "O", "010011100": "P",
    "1010011110001": "Q", "101001110": "R", "10100100": "S",
    "10101110": "T", "1011110101": "U", "10100111101": "V",
    "1011000100": "W", "10110000010": "X", "0100111010": "Y",
    "010011101111": "Z", "0010000": "0", "01001011": "1",
    "101100101": "2", "001010101": "3", "001010011": "4",
    "1011110111": "5", "1011001100": "6", "0100101001": "7",
    "1010011001": "8", "001010000": "9", "10111111100": "_",
    "1010011110000": "{", "0100111011101": "}", "10111110": "-",
    "0100101000": "!", "1010010100": "?", "101111110": "(",
    "00100011": ")", "1010110": ",", "101000": ".",
    "101111001": "/", "101111000": ":", "10111111110": ";",
    "10100101010": "=", "101001111001": "[", "101001010111": "]",
    "101001010110": "|", "111": " ",
}
_MAX_SNOW_HUFFMAN_CODE = max(map(len, _SNOW_HUFFMAN_CODES))


@dataclass(frozen=True)
class TextInput:
    """One bounded source decode selected from byte-level evidence."""

    raw_bytes: bytes
    text: str
    encoding: str | None
    classification: TextClassification
    printable_ratio: float
    control_ratio: float
    truncated: bool


@dataclass(frozen=True)
class DecodeCandidate:
    """Immutable, bounded text-stego candidate suitable for reporting."""

    decoder: str
    variant: str
    value: str
    confidence: CandidateConfidence
    score: int
    depth: int
    evidence: tuple[str, ...]
    source: str
    normalized_preview: str
    flags_found: tuple[str, ...]
    chain: tuple[str, ...]


@dataclass(frozen=True)
class TextStegoAnalysis:
    """Complete deterministic result from one bounded input."""

    source: TextInput
    candidates: tuple[DecodeCandidate, ...]
    total_generated: int
    aggregate_decoded_bytes: int
    limits_reached: tuple[str, ...]


@dataclass
class _Seed:
    value: str
    chain: tuple[str, ...]
    variant: str
    depth: int
    evidence: tuple[str, ...]
    source: str
    independent_sources: set[str]
    direct_flags: tuple[str, ...] = ()


def escape_unsafe_text(value: str, *, limit: int = MAX_CANDIDATE_OUTPUT) -> str:
    """Escape terminal controls and bidi/format characters deterministically."""
    pieces: list[str] = []
    used = 0
    for character in value[:limit]:
        category = unicodedata.category(character)
        if character in _INVISIBLE_NAMES or character in _BIDI_CHARACTERS:
            rendered = f"<U+{ord(character):04X} {unicodedata.name(character, 'FORMAT CHARACTER')}>"
        elif character == "\x1b":
            rendered = "\\x1b"
        elif category == "Cc" and character not in "\n\t":
            rendered = f"\\x{ord(character):02x}"
        elif category == "Cf":
            rendered = f"<U+{ord(character):04X} {unicodedata.name(character, 'FORMAT CHARACTER')}>"
        else:
            rendered = character
        if used + len(rendered) > limit:
            break
        pieces.append(rendered)
        used += len(rendered)
    return "".join(pieces)


def _ratios(text: str) -> tuple[float, float]:
    if not text:
        return 0.0, 1.0
    printable = 0
    controls = 0
    for character in text:
        category = unicodedata.category(character)
        if character in "\n\r\t" or character in _INVISIBLE_NAMES:
            printable += 1
        elif category.startswith("C"):
            controls += 1
        elif character.isprintable():
            printable += 1
    length = len(text)
    return printable / length, controls / length


def _decode_score(text: str) -> float:
    printable, controls = _ratios(text)
    null_penalty = min(0.5, text.count("\x00") / max(1, len(text)))
    return printable - controls - null_penalty


def _null_layout_supports(data: bytes, codec: str) -> bool:
    """Require the expected bounded null-byte layout for BOM-less UTF data."""
    if "16" in codec:
        even = data[0::2]
        odd = data[1::2]
        expected, other = (odd, even) if codec.endswith("le") else (even, odd)
        expected_ratio = expected.count(0) / max(1, len(expected))
        other_ratio = other.count(0) / max(1, len(other))
        payload_printable = sum(
            byte in (9, 10, 13) or 32 <= byte <= 126 for byte in other
        ) / max(1, len(other))
        return (
            expected_ratio >= 0.25
            and expected_ratio >= other_ratio * 2
            and payload_printable >= 0.40
        )
    lanes = [data[index::4] for index in range(4)]
    zero_ratios = [lane.count(0) / max(1, len(lane)) for lane in lanes]
    expected = (1, 2, 3) if codec.endswith("le") else (0, 1, 2)
    payload_lane = 0 if codec.endswith("le") else 3
    payload_printable = sum(
        byte in (9, 10, 13) or 32 <= byte <= 126 for byte in lanes[payload_lane]
    ) / max(1, len(lanes[payload_lane]))
    return (
        min(zero_ratios[index] for index in expected) >= 0.50
        and max(zero_ratios[index] for index in expected)
        >= zero_ratios[payload_lane] * 2
        and payload_printable >= 0.40
    )


def detect_text_bytes(data: bytes, *, truncated: bool = False) -> TextInput:
    """Select a probable source decoding without trusting filename extensions."""
    bounded = data[:MAX_SOURCE_BYTES]
    decodes: list[tuple[float, str, str]] = []
    bom_decoders = (
        (b"\x00\x00\xfe\xff", "utf-32-be", "utf-32-be-bom"),
        (b"\xff\xfe\x00\x00", "utf-32-le", "utf-32-le-bom"),
        (b"\xef\xbb\xbf", "utf-8-sig", "utf-8-bom"),
        (b"\xfe\xff", "utf-16-be", "utf-16-be-bom"),
        (b"\xff\xfe", "utf-16-le", "utf-16-le-bom"),
    )
    for marker, codec, label in bom_decoders:
        if not bounded.startswith(marker):
            continue
        try:
            decoded = bounded.decode(codec)
        except UnicodeDecodeError:
            break
        if decoded.startswith("\ufeff"):
            decoded = decoded[1:]
        decodes.append((_decode_score(decoded) + 1.0, label, decoded))
        break

    if not decodes:
        try:
            decoded_utf8 = bounded.decode("utf-8")
        except UnicodeDecodeError:
            decoded_utf8 = None
        if decoded_utf8 is not None:
            label = "ascii" if all(byte < 128 for byte in bounded) else "utf-8"
            decodes.append((_decode_score(decoded_utf8) + 0.5, label, decoded_utf8))

        null_ratio = bounded.count(0) / max(1, len(bounded))
        if null_ratio >= 0.10:
            for codec in ("utf-32-le", "utf-32-be", "utf-16-le", "utf-16-be"):
                unit = 4 if "32" in codec else 2
                if (
                    len(bounded) < unit * 2
                    or len(bounded) % unit
                    or not _null_layout_supports(bounded, codec)
                ):
                    continue
                try:
                    decoded = bounded.decode(codec)
                except UnicodeDecodeError:
                    continue
                decodes.append((_decode_score(decoded), codec, decoded))

        if not decodes and b"\x00" not in bounded:
            decoded_latin1 = bounded.decode("latin-1")
            ascii_printable = sum(
                byte in (9, 10, 13) or 32 <= byte <= 126 for byte in bounded
            ) / max(1, len(bounded))
            has_structure = (
                len(bounded) < 16
                or any(byte in (9, 10, 13, 32) for byte in bounded)
            )
            if (
                ascii_printable >= 0.55
                and has_structure
                and _decode_score(decoded_latin1) >= 0.85
            ):
                decodes.append((_decode_score(decoded_latin1) - 0.15, "latin-1", decoded_latin1))

    if not decodes:
        printable_bytes = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in bounded)
        ratio = printable_bytes / max(1, len(bounded))
        classification: TextClassification = "text-fragments" if ratio >= 0.55 else "binary"
        return TextInput(bounded, "", None, classification, ratio, 1.0 - ratio, truncated)

    _score, encoding, selected = max(decodes, key=lambda item: (item[0], item[1]))
    decoded_truncated = len(selected) > MAX_DECODED_CHARACTERS
    selected = selected[:MAX_DECODED_CHARACTERS]
    classification_view = _apply_carriage_returns(
        _apply_backspaces(_ANSI_ESCAPE.sub("", selected))
    )
    printable, controls = _ratios(classification_view)
    if selected and printable >= 0.82 and controls <= 0.12:
        classification = "probable-text"
    elif selected and printable >= 0.55 and controls <= 0.30:
        classification = "text-fragments"
    else:
        classification = "binary"
    return TextInput(
        bounded,
        selected,
        encoding,
        classification,
        printable,
        controls,
        truncated or decoded_truncated,
    )


def read_text_input(path: Path) -> TextInput:
    """Read and classify at most ``MAX_SOURCE_BYTES`` from one local file."""
    try:
        with path.open("rb") as source:
            data = source.read(MAX_SOURCE_BYTES + 1)
    except OSError:
        return detect_text_bytes(b"")
    return detect_text_bytes(
        data[:MAX_SOURCE_BYTES],
        truncated=len(data) > MAX_SOURCE_BYTES,
    )


def _find_flags(value: str, pattern: re.Pattern) -> tuple[str, ...]:
    found: dict[str, None] = {}
    total_characters = 0
    for match in pattern.finditer(value):
        raw_flag = match.group(0)
        if len(raw_flag) > MAX_DIRECT_FLAG_LENGTH:
            continue
        flag = escape_unsafe_text(
            raw_flag, limit=MAX_DIRECT_FLAG_LENGTH
        )
        if not flag or flag in found:
            continue
        if total_characters + len(flag) > MAX_DIRECT_FLAG_CHARACTERS:
            break
        found[flag] = None
        total_characters += len(flag)
        if len(found) >= MAX_DIRECT_FLAGS:
            break
    return tuple(found)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _has_short_period(value: str) -> bool:
    if len(value) < 16:
        return False
    for period in range(1, min(9, len(value) // 2 + 1)):
        if all(character == value[index % period] for index, character in enumerate(value)):
            return True
    return False


def _candidate_score(value: str, pattern: re.Pattern) -> tuple[int, tuple[str, ...]]:
    flags = _find_flags(value, pattern)
    score = 100 if flags else 0
    if _CTF_PREFIX.search(value):
        score += 50
    printable, controls = _ratios(value)
    if printable >= 0.95:
        score += 30
    elif printable >= 0.80:
        score += 15
    if value.isascii() and printable >= 0.90:
        score += 35
    words = [word.lower() for word in _WORD.findall(value)]
    common = sum(word in _COMMON_WORDS for word in words)
    if common >= 2 or (common >= 1 and len(words) <= 5):
        score += 25
    elif len(words) >= 3 and 0.25 <= sum(ch.lower() in "aeiou" for ch in value) / max(1, len(value)) <= 0.55:
        score += 10
    if "{" in value and "}" in value:
        score += 10
    if re.search(r"https?://[^\s]+", value):
        score += 20
    if len(value.strip()) < 4:
        score -= 25
    if controls > 0.10:
        score -= 30
    if value and max(Counter(value).values()) / len(value) > 0.70:
        score -= 20
    if _has_short_period(value):
        score -= 35
    if len(value) >= 24 and _entropy(value) >= 5.5 and not words:
        score -= 40
    return score, flags


def _confidence(
    score: int,
    flags: tuple[str, ...],
    value: str,
) -> CandidateConfidence:
    if flags:
        return "confirmed"
    if score >= 90 and len(value.strip()) >= 12 and len(_WORD.findall(value)) >= 2:
        return "high"
    if score >= 80:
        return "medium"
    return "low"


def _preview(value: str) -> str:
    safe = escape_unsafe_text(value, limit=MAX_CANDIDATE_OUTPUT)
    collapsed = " ".join(safe.split())
    if len(collapsed) <= MAX_CANDIDATE_PREVIEW:
        return collapsed
    return collapsed[:MAX_CANDIDATE_PREVIEW - 1] + "…"


class _Collector:
    def __init__(self, pattern: re.Pattern) -> None:
        self.pattern = pattern
        self.seeds: dict[str, _Seed] = {}
        self.queue: deque[_Seed] = deque()
        self.aggregate_bytes = 0
        self.limits: set[str] = set()
        self.blocked_identities: set[str] = set()
        self.direct_flags: set[str] = set()
        self.direct_flag_characters = 0

    @staticmethod
    def _identity(value: str) -> str:
        return hashlib.sha256(
            value.encode("utf-8", errors="surrogatepass")
        ).hexdigest()

    def block(self, value: str) -> None:
        """Prevent an unchanged source from reappearing through reversible loops."""
        self.blocked_identities.add(self._identity(value[:MAX_CANDIDATE_OUTPUT]))

    def add(
        self,
        value: str,
        chain: tuple[str, ...],
        variant: str,
        *,
        depth: int,
        evidence: tuple[str, ...],
        source: str,
        known_direct_flags: tuple[str, ...] | None = None,
    ) -> bool:
        if not value:
            return False
        direct_flags: list[str] = []
        for flag in (
            known_direct_flags
            if known_direct_flags is not None
            else _find_flags(value, self.pattern)
        ):
            if flag in self.direct_flags:
                direct_flags.append(flag)
                continue
            if len(self.direct_flags) >= MAX_DIRECT_FLAGS or (
                self.direct_flag_characters + len(flag)
                > MAX_DIRECT_FLAG_CHARACTERS
            ):
                self.limits.add("direct-flags")
                break
            self.direct_flags.add(flag)
            self.direct_flag_characters += len(flag)
            direct_flags.append(flag)
        bounded = value[:MAX_CANDIDATE_OUTPUT]
        encoded_size = len(bounded.encode("utf-8", errors="replace"))
        if encoded_size > MAX_DECODED_BYTES_PER_CANDIDATE:
            self.limits.add("candidate-bytes")
            return False
        identity = self._identity(bounded)
        if identity in self.blocked_identities:
            return False
        independent = chain[0] if chain else source
        existing = self.seeds.get(identity)
        if existing is not None:
            existing.independent_sources.add(independent)
            existing.direct_flags = tuple(dict.fromkeys(
                (*existing.direct_flags, *direct_flags)
            ))
            return False
        if len(self.seeds) >= MAX_TOTAL_CANDIDATES:
            self.limits.add("candidate-count")
            return False
        if self.aggregate_bytes + encoded_size > MAX_AGGREGATE_DECODED_BYTES:
            self.limits.add("aggregate-bytes")
            return False
        seed = _Seed(
            bounded,
            chain,
            variant,
            depth,
            evidence,
            source,
            {independent},
            tuple(direct_flags),
        )
        self.seeds[identity] = seed
        self.queue.append(seed)
        self.aggregate_bytes += encoded_size
        return True

    def finish(self) -> tuple[DecodeCandidate, ...]:
        candidates: list[DecodeCandidate] = []
        for seed in self.seeds.values():
            score, flags = _candidate_score(seed.value, self.pattern)
            combined_flags = tuple(dict.fromkeys((*flags, *seed.direct_flags)))
            if combined_flags and not flags:
                score += 100
            flags = combined_flags
            if seed.chain[:1] == ("structural",):
                if seed.chain[1].startswith("every-"):
                    score -= 35
                elif seed.chain[1] in {"line-first-word", "line-last-word"}:
                    score -= 25
                elif seed.chain[1] in {"uppercase-sequence", "lowercase-anomalies", "uppercase-anomalies"}:
                    score -= 10
            if seed.chain[:1] == ("ghost_text",) and not flags:
                score -= 20
            if seed.chain[:2] in {
                ("ghost_text", "escaped-view"),
                ("ghost_text", "control-code-sequence"),
            }:
                score -= 40
            if len(seed.independent_sources) > 1:
                score += 15
            confidence = _confidence(score, flags, seed.value)
            candidates.append(DecodeCandidate(
                decoder=">".join(seed.chain),
                variant=seed.variant,
                value=escape_unsafe_text(seed.value),
                confidence=confidence,
                score=score,
                depth=seed.depth,
                evidence=seed.evidence + (
                    f"independent-producers:{len(seed.independent_sources)}",
                ) + (("active-flag-regex",) if flags and
                     "active-flag-regex" not in seed.evidence else ()),
                source=seed.source,
                normalized_preview=_preview(seed.value),
                flags_found=flags,
                chain=seed.chain,
            ))
        rank = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}
        candidates.sort(key=lambda item: (
            rank[item.confidence], -item.score, item.depth, item.decoder,
            item.variant, item.normalized_preview,
        ))
        return tuple(candidates)


def _useful_decoded(value: str) -> bool:
    printable, controls = _ratios(value)
    return len(value.strip()) >= 4 and printable >= 0.72 and controls <= 0.15


def _bits_to_text(bits: str, width: int, offset: int) -> str | None:
    usable = bits[offset:]
    usable = usable[:len(usable) - (len(usable) % width)]
    if len(usable) < width * 4:
        return None
    values = [int(usable[index:index + width], 2) for index in range(0, len(usable), width)]
    if width < 7:
        text = "".join(chr(value + 32) if value < 64 else "?" for value in values)
    else:
        text = "".join(chr(value) for value in values)
    return text if _useful_decoded(text) else None


def _decode_binary_ascii(
    bit_streams: tuple[str, ...],
    width: int,
    offset: int,
    *,
    lsb_first: bool,
) -> str | None:
    """Decode bounded ASCII groups while preserving meaningful NUL evidence."""
    output: list[str] = []
    for bits in bit_streams:
        usable = bits[offset:]
        usable = usable[:len(usable) - (len(usable) % width)]
        for index in range(0, len(usable), width):
            group = usable[index:index + width]
            if lsb_first:
                group = group[::-1]
            value = int(group, 2)
            if value > 0x7f:
                return None
            output.append(chr(value))
    if not output:
        return None
    decoded = "".join(output).rstrip("\x00")
    if not decoded or "\x00" in decoded:
        return None
    return decoded


def _strict_binary_candidate(
    value: str,
    pattern: re.Pattern,
) -> tuple[str, ...] | None:
    """Retain flags or strongly printable text, never control-heavy gibberish."""
    flags = _find_flags(value, pattern)
    printable, controls = _ratios(value)
    if controls > 0.02 or printable < 0.90:
        return None
    if flags:
        return flags
    if _find_flags(value[::-1], pattern):
        return ()
    score, _unused_flags = _candidate_score(value, pattern)
    if printable < 0.95 or score < 80:
        return None
    return ()


def _emit_binary_ascii_variants(
    bit_streams: tuple[str, ...],
    collector: _Collector,
    decoder: str,
    source_variant: str,
    *,
    source: str,
) -> None:
    """Try bounded mappings, bit orders, widths, and offsets with strict filtering."""
    symbol_count = sum(len(bits) for bits in bit_streams)
    if (
        not bit_streams
        or symbol_count < 32
        or symbol_count > MAX_ANALYSIS_CHARACTERS
    ):
        return
    emitted = 0
    for width in (8, 7):
        for inverted, mapping in (
            (False, "zero-one"),
            (True, "one-zero"),
        ):
            streams = tuple(
                "".join("1" if bit == "0" else "0" for bit in bits)
                if inverted else bits
                for bits in bit_streams
            )
            for lsb_first, bit_order in (
                (False, "msb-first"),
                (True, "lsb-first"),
            ):
                for offset in range(8):
                    decoded = _decode_binary_ascii(
                        streams,
                        width,
                        offset,
                        lsb_first=lsb_first,
                    )
                    if decoded is None:
                        continue
                    direct_flags = _strict_binary_candidate(
                        decoded, collector.pattern
                    )
                    if direct_flags is None:
                        continue
                    if collector.add(
                        decoded,
                        (decoder,) if decoder == "case_binary_ascii" else (
                            decoder,
                            "binary",
                        ),
                        (
                            f"{source_variant};{width}-bit;{bit_order};"
                            f"mapping={mapping};offset={offset}"
                        ),
                        depth=1,
                        evidence=(
                            f"symbols:{symbol_count}",
                            f"group-size:{width}",
                            f"bit-order:{bit_order}",
                            "strict-printable-filter",
                        ),
                        source=source,
                        known_direct_flags=direct_flags,
                    ):
                        emitted += 1
                    if emitted >= MAX_BINARY_ASCII_CANDIDATES:
                        return


def _emit_bit_variants(
    bits: str,
    collector: _Collector,
    decoder: str,
    source_variant: str,
    *,
    source: str,
) -> None:
    if len(bits) < 16 or len(bits) > MAX_ANALYSIS_CHARACTERS:
        return
    emitted = 0
    for width in (8, 7, 6, 5):
        streams = (
            (bits, "normal"),
            ("".join("1" if bit == "0" else "0" for bit in bits), "inverted"),
            (bits[::-1], "reversed"),
            ("".join("1" if bit == "0" else "0" for bit in bits[::-1]), "reversed-inverted"),
        )
        for stream, order in streams:
            for offset in range(width):
                decoded = _bits_to_text(stream, width, offset)
                if decoded is None:
                    continue
                if collector.add(
                    decoded,
                    (decoder, "binary"),
                    f"{source_variant};{width}-bit;{order};offset={offset}",
                    depth=1,
                    evidence=(f"symbols:{len(bits)}", f"group-size:{width}"),
                    source=source,
                ):
                    emitted += 1
                if emitted >= MAX_CHILDREN_PER_CANDIDATE:
                    return


def _bacon_decode(bits: str, alphabet: str, *, reverse_groups: bool) -> str:
    output: list[str] = []
    for index in range(0, len(bits) - 4, 5):
        group = bits[index:index + 5]
        if reverse_groups:
            group = group[::-1]
        value = int(group, 2)
        if value >= len(alphabet):
            return ""
        output.append(alphabet[value])
    return "".join(output)


def _emit_bacon(bits: str, collector: _Collector, variant: str) -> None:
    if len(bits) < 20 or len(bits) > MAX_ANALYSIS_CHARACTERS:
        return
    alphabets = (
        ("base32-32", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
        ("modern-26", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("classic-24", "ABCDEFGHIKLMNOPQRSTUWXYZ"),
    )
    emitted = 0
    for offset in range(5):
        stream = bits[offset:]
        for swapped in (False, True):
            mapped = (
                "".join("1" if bit == "0" else "0" for bit in stream)
                if swapped else stream
            )
            for reversed_groups in (False, True):
                for alphabet_name, alphabet in alphabets:
                    decoded = _bacon_decode(
                        mapped,
                        alphabet,
                        reverse_groups=reversed_groups,
                    )
                    if len(decoded) < 4:
                        continue
                    if collector.add(
                        decoded,
                        ("bacon",),
                        (
                            f"{variant};{alphabet_name};offset={offset};"
                            f"swap={swapped};bit-reversal={reversed_groups}"
                        ),
                        depth=1,
                        evidence=(f"symbols:{len(bits)}", "group-size:5"),
                        source="text",
                    ):
                        emitted += 1
                    if emitted >= MAX_CHILDREN_PER_CANDIDATE * 2:
                        return


def _bacon_candidates(text: str, collector: _Collector) -> None:
    compact = "".join(character for character in text if not character.isspace())
    if compact and len(compact) >= 20:
        lowered = compact.lower()
        if set(lowered) == {"a", "b"}:
            _emit_bacon("".join("0" if char == "a" else "1" for char in lowered), collector, "literal-ab")
        if set(compact) == {"0", "1"}:
            _emit_bacon(compact, collector, "literal-01")
        if len(set(compact)) == 2 and all(not char.isalnum() for char in compact):
            first, second = sorted(set(compact))
            _emit_bacon("".join("0" if char == first else "1" for char in compact), collector, "two-symbol")

    letters = [character for character in text if character.isalpha()]
    if len(letters) >= 20:
        upper = sum(character.isupper() for character in letters)
        lower = len(letters) - upper
        if min(upper, lower) / len(letters) >= 0.15:
            _emit_bacon("".join("1" if char.isupper() else "0" for char in letters), collector, "letter-case")

    words = re.findall(r"\b[^\W\d_]+\b", text, re.UNICODE)
    unique_words = list(dict.fromkeys(words))
    if len(words) >= 20 and len(unique_words) == 2:
        counts = Counter(words)
        if min(counts.values()) / len(words) >= 0.20:
            _emit_bacon("".join("0" if word == unique_words[0] else "1" for word in words), collector, "two-word-classes")


def _case_binary_ascii_candidates(text: str, collector: _Collector) -> None:
    """Decode direct case-as-bit ASCII independently from classical Bacon."""
    letters = [
        character
        for character in text
        if character.isalpha()
        and (character.isupper() or character.islower())
    ]
    if len(letters) < 32 or len(letters) > MAX_ANALYSIS_CHARACTERS:
        return
    bits = "".join("1" if character.isupper() else "0" for character in letters)
    _emit_binary_ascii_variants(
        (bits,),
        collector,
        "case_binary_ascii",
        "alphabetic-case",
        source="text",
    )


def _snow_whitespace_bits(text: str) -> str | None:
    """Unpack bounded SNOW-style trailing runs into three-bit values."""
    output: list[str] = []
    bit_count = 0
    started = False
    for line in text.splitlines():
        match = re.search(r"([ \t]+)$", line)
        if match is None:
            continue
        run = match.group(1)
        if not started:
            if not run.startswith("\t"):
                continue
            started = True
            run = run[1:]
        spaces = 0
        for character in run:
            if character == " ":
                spaces += 1
                continue
            if spaces > 7:
                return None
            output.append(f"{spaces:03b}"[::-1])
            bit_count += 3
            spaces = 0
        if spaces:
            if spaces > 7:
                return None
            output.append(f"{spaces:03b}"[::-1])
            bit_count += 3
        if bit_count > MAX_ANALYSIS_CHARACTERS:
            return None
    bits = "".join(output)
    return bits if started and len(bits) >= 24 else None


def _snow_huffman_decode(bits: str) -> str | None:
    """Decode SNOW's fixed printable Huffman subset with strict prefix bounds."""
    output: list[str] = []
    prefix = ""
    for bit in bits:
        prefix += bit
        character = _SNOW_HUFFMAN_CODES.get(prefix)
        if character is not None:
            output.append(character)
            prefix = ""
            if len(output) >= MAX_CANDIDATE_OUTPUT:
                break
        elif len(prefix) > _MAX_SNOW_HUFFMAN_CODE:
            return None
    return "".join(output) or None


def _snow_candidates(text: str, collector: _Collector) -> None:
    bits = _snow_whitespace_bits(text)
    if bits is None:
        return
    variants: list[tuple[str, str]] = []
    uncompressed = _decode_binary_ascii(
        (bits,), 8, 0, lsb_first=False
    )
    if uncompressed is not None:
        variants.append((uncompressed, "snow-uncompressed"))
    compressed = _snow_huffman_decode(bits)
    if compressed is not None:
        variants.append((compressed, "snow-huffman"))
    for decoded, variant in variants:
        direct_flags = _strict_binary_candidate(decoded, collector.pattern)
        if direct_flags is None:
            continue
        collector.add(
            decoded,
            ("whitespace", "snow"),
            variant,
            depth=1,
            evidence=(
                f"symbols:{len(bits)}",
                "three-bit-space-counts",
                "strict-printable-filter",
            ),
            source="raw-whitespace",
            known_direct_flags=direct_flags,
        )


def _whitespace_candidates(raw: bytes, text: str, collector: _Collector) -> None:
    spaces_tabs = "".join(character for character in text if character in " \t")
    trailing: list[str] = []
    lines = text.splitlines()
    trailing_by_line: list[str] = []
    whitespace_by_line: list[str] = []
    for line in lines:
        whitespace = "".join(character for character in line if character in " \t")
        if whitespace:
            whitespace_by_line.append(whitespace)
        match = re.search(r"([ \t]+)$", line)
        if match:
            run = match.group(1)
            trailing.extend(run)
            trailing_by_line.append(run)
    trailing_stream = "".join(trailing)
    if len(trailing_stream) >= 32:
        _emit_binary_ascii_variants(
            ("".join("0" if char == " " else "1" for char in trailing_stream),),
            collector,
            "whitespace",
            "trailing-space-vs-tab",
            source="raw-whitespace",
        )

    first_carrier = next(
        (
            index
            for index, line in enumerate(lines)
            if any(character not in " \t" for character in line)
        ),
        None,
    )
    if first_carrier is not None:
        carrier_line = lines[first_carrier]
        last_visible = max(
            index
            for index, character in enumerate(carrier_line)
            if character not in " \t"
        )
        inline_region = carrier_line[last_visible + 1:] + "\n".join(
            lines[first_carrier + 1:]
        )
        inline_stream = "".join(
            character for character in inline_region if character in " \t"
        )
        if len(inline_stream) >= 32:
            _emit_binary_ascii_variants(
                ("".join("0" if char == " " else "1" for char in inline_stream),),
                collector,
                "whitespace",
                "inline-after-first-carrier",
                source="raw-whitespace",
            )

    for streams, variant in (
        (whitespace_by_line, "per-line-space-tab"),
        (trailing_by_line, "per-line-trailing-space-tab"),
    ):
        bit_streams = tuple(
            "".join("0" if char == " " else "1" for char in stream)
            for stream in streams
        )
        if sum(map(len, bit_streams)) >= 32:
            _emit_binary_ascii_variants(
                bit_streams,
                collector,
                "whitespace",
                variant,
                source="raw-whitespace",
            )

    if len(spaces_tabs) >= 32:
        _emit_binary_ascii_variants(
            ("".join("0" if char == " " else "1" for char in spaces_tabs),),
            collector,
            "whitespace",
            "all-space-tab",
            source="raw-whitespace",
        )

    runs = re.findall(r"(?<! )[ ]{1,2}(?! )", text)
    if len(runs) >= 16 and {len(run) for run in runs} == {1, 2}:
        _emit_bit_variants("".join("0" if len(run) == 1 else "1" for run in runs), collector, "whitespace", "one-vs-two-spaces", source="text")

    indents = [len(match.group(0).expandtabs(4)) for line in text.splitlines() if (match := re.match(r"^[ \t]+", line))]
    if len(indents) >= 16 and len(set(indents)) == 2:
        low, _high = sorted(set(indents))
        _emit_bit_variants("".join("0" if value == low else "1" for value in indents), collector, "whitespace", "indentation-level", source="text")

    blank_runs: list[int] = []
    pending_blanks = 0
    seen_content = False
    for line in text.splitlines():
        if not line.strip():
            if seen_content:
                pending_blanks += 1
            continue
        if seen_content and pending_blanks:
            blank_runs.append(pending_blanks)
        seen_content = True
        pending_blanks = 0
    if len(blank_runs) >= 16 and len(set(blank_runs)) == 2:
        low, _high = sorted(set(blank_runs))
        _emit_bit_variants(
            "".join("0" if value == low else "1" for value in blank_runs),
            collector,
            "whitespace",
            "blank-line-pattern",
            source="text",
        )

    endings = re.findall(rb"\r\n|\n", raw)
    if len(endings) >= 16 and len(set(endings)) == 2:
        _emit_bit_variants("".join("1" if ending == b"\r\n" else "0" for ending in endings), collector, "whitespace", "crlf-vs-lf", source="raw-whitespace")


def _zero_width_candidates(text: str, collector: _Collector) -> None:
    positioned = [
        (index, character)
        for index, character in enumerate(text)
        if character in _INVISIBLE_NAMES
    ]
    symbols = [character for _index, character in positioned]
    if len(symbols) < 16:
        return
    unique = list(dict.fromkeys(symbols))
    if len(unique) == 2:
        bits = "".join("0" if character == unique[0] else "1" for character in symbols)
        labels = f"U+{ord(unique[0]):04X}/U+{ord(unique[1]):04X}"
        _emit_bit_variants(bits, collector, "zero_width", labels, source="unicode-format")
    elif len(unique) == 3:
        for order in permutations(unique):
            mapping = {character: index for index, character in enumerate(order)}
            trits = "".join(str(mapping[character]) for character in symbols)
            for width in (5, 4):
                for offset in range(width):
                    usable = trits[offset:]
                    usable = usable[:len(usable) - len(usable) % width]
                    values = [int(usable[index:index + width], 3) for index in range(0, len(usable), width)]
                    if values and max(values) <= 255:
                        decoded = "".join(chr(value) for value in values)
                        if _useful_decoded(decoded):
                            collector.add(decoded, ("zero_width", "base3"), f"{width}-trit;offset={offset};mapping={''.join(f'U+{ord(char):04X}' for char in order)}", depth=1, evidence=(f"symbols:{len(symbols)}",), source="unicode-format")

    gaps = [
        positioned[index][0] - positioned[index - 1][0]
        for index in range(1, len(positioned))
    ]
    if len(gaps) >= 16 and len(set(gaps)) == 2:
        low, _high = sorted(set(gaps))
        _emit_bit_variants(
            "".join("0" if gap == low else "1" for gap in gaps),
            collector,
            "zero_width",
            "position-gap-classes",
            source="unicode-position",
        )


def _homoglyph_candidates(text: str, collector: _Collector) -> None:
    bits: list[str] = []
    classes: set[str] = set()
    for character in text:
        if character in _LATIN_HOMOGLYPHS or character in _GREEK_LATIN_EQUIVALENTS:
            bits.append("0")
            classes.add("latin")
        elif character in _CYRILLIC_HOMOGLYPHS:
            bits.append("1")
            classes.add("cyrillic")
        elif character in _GREEK_HOMOGLYPHS:
            bits.append("1")
            classes.add("greek")
    if len(bits) >= 16 and "latin" in classes and len(classes) >= 2:
        _emit_bit_variants("".join(bits), collector, "homoglyph", "latin-vs-lookalike", source="mixed-script")

    width_bits: list[str] = []
    width_classes: set[str] = set()
    for character in text:
        codepoint = ord(character)
        if 0x21 <= codepoint <= 0x7E:
            width_bits.append("0")
            width_classes.add("ascii")
        elif 0xFF01 <= codepoint <= 0xFF5E:
            width_bits.append("1")
            width_classes.add("fullwidth")
    if len(width_bits) >= 16 and width_classes == {"ascii", "fullwidth"}:
        _emit_bit_variants("".join(width_bits), collector, "homoglyph", "ascii-vs-fullwidth", source="mixed-width")


def _add_structural(
    collector: _Collector,
    value: str,
    variant: str,
    count: list[int],
) -> None:
    if count[0] >= MAX_STRUCTURAL_CANDIDATES or not _useful_decoded(value):
        return
    count[0] += 1
    collector.add(value, ("structural", variant), variant, depth=1, evidence=("bounded-structural-extraction",), source="text")


def _structural_candidates(text: str, collector: _Collector) -> None:
    lines = [line for line in text.splitlines()[:4096] if line.strip()]
    count = [0]
    if len(lines) >= 4:
        stripped = [line.strip() for line in lines]
        _add_structural(collector, "".join(line[0] for line in stripped), "line-first-character", count)
        _add_structural(collector, "".join(line[-1] for line in stripped), "line-last-character", count)
        first_words = [line.split()[0] for line in stripped]
        last_words = [line.split()[-1] for line in stripped]
        _add_structural(collector, " ".join(first_words), "line-first-word", count)
        _add_structural(collector, " ".join(last_words), "line-last-word", count)
        _add_structural(collector, "".join(word[0] for word in first_words), "first-word-first-letter", count)
        _add_structural(collector, "".join(word[-1] for word in last_words), "last-word-last-letter", count)
        line_parity = "".join(str(len(line) % 2) for line in stripped)
        _emit_bit_variants(line_parity, collector, "structural", "line-length-parity", source="text")

    letters = [character for character in text if character.isalpha()]
    if len(letters) >= 16:
        uppercase = "".join(character for character in letters if character.isupper())
        lower = "".join(character for character in letters if character.islower())
        _add_structural(collector, uppercase, "uppercase-sequence", count)
        if sum(character.isupper() for character in letters) / len(letters) >= 0.80:
            _add_structural(collector, lower, "lowercase-anomalies", count)
        if sum(character.islower() for character in letters) / len(letters) >= 0.80:
            _add_structural(collector, uppercase, "uppercase-anomalies", count)

    words = _WORD.findall(text[:MAX_ANALYSIS_CHARACTERS])
    if len(words) >= 16:
        parity = "".join(str(len(word) % 2) for word in words)
        _emit_bit_variants(parity, collector, "structural", "word-length-parity", source="text")

    punctuation = [
        character for character in text
        if unicodedata.category(character).startswith("P")
    ]
    if (
        len(punctuation) >= 16
        and len(set(punctuation)) == 2
        and min(Counter(punctuation).values()) >= 4
    ):
        first = next(iter(dict.fromkeys(punctuation)))
        _emit_bit_variants(
            "".join("0" if character == first else "1" for character in punctuation),
            collector,
            "structural",
            "punctuation-class",
            source="text",
        )

    bounded = text[:256 * 1024]
    compact = "".join(character for character in bounded if not character.isspace())
    for step in range(2, 33):
        _add_structural(collector, compact[step - 1::step], f"every-{step}-character", count)
        _add_structural(collector, " ".join(words[step - 1::step]), f"every-{step}-word", count)


def _apply_backspaces(text: str) -> str:
    output: list[str] = []
    for character in text:
        if character == "\b":
            if output:
                output.pop()
        else:
            output.append(character)
    return "".join(output)


def _apply_carriage_returns(text: str) -> str:
    rebuilt: list[str] = []
    for line in text.split("\n"):
        rebuilt.append(line.split("\r")[-1])
    return "\n".join(rebuilt)


def _ghost_candidates(text: str, collector: _Collector) -> None:
    variants = (
        ("null-removal", text.replace("\x00", "")),
        ("backspace-reconstruction", _apply_backspaces(text)),
        ("carriage-return-reconstruction", _apply_carriage_returns(text)),
        ("ansi-removal", _ANSI_ESCAPE.sub("", text)),
        ("soft-hyphen-removal", text.replace("\u00ad", "")),
        ("nonbreaking-space", text.replace("\u00a0", " ")),
        ("format-removal", "".join(character for character in text if unicodedata.category(character) != "Cf")),
        ("combining-mark-removal", "".join(character for character in unicodedata.normalize("NFD", text) if not unicodedata.combining(character))),
        ("variation-selector-removal", "".join(character for character in text if not (0xFE00 <= ord(character) <= 0xFE0F or 0xE0100 <= ord(character) <= 0xE01EF))),
    )
    for variant, rebuilt in variants:
        if rebuilt != text and _useful_decoded(rebuilt):
            collector.add(rebuilt, ("ghost_text", variant), variant, depth=1, evidence=("deterministic-control-reconstruction",), source="text")

    controls = [
        character for character in text
        if unicodedata.category(character).startswith("C")
    ][:256]
    if controls:
        collector.add(
            escape_unsafe_text(text),
            ("ghost_text", "escaped-view"),
            "terminal-safe",
            depth=1,
            evidence=(f"control-count:{len(controls)}",),
            source="text",
        )
        sequence = " ".join(
            f"U+{ord(character):04X} {unicodedata.name(character, 'CONTROL CHARACTER')}"
            for character in controls
        )
        collector.add(
            sequence,
            ("ghost_text", "control-code-sequence"),
            "unicode-names",
            depth=1,
            evidence=(f"control-count:{len(controls)}",),
            source="text",
        )


def _bounded_decompress(data: bytes, *, gzip_stream: bool) -> bytes | None:
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS if gzip_stream else zlib.MAX_WBITS)
        output = decompressor.decompress(data, MAX_DECODED_BYTES_PER_CANDIDATE + 1)
        if len(output) > MAX_DECODED_BYTES_PER_CANDIDATE or decompressor.unconsumed_tail:
            return None
        output += decompressor.flush(MAX_DECODED_BYTES_PER_CANDIDATE + 1 - len(output))
    except zlib.error:
        return None
    return output if len(output) <= MAX_DECODED_BYTES_PER_CANDIDATE else None


def _bytes_text_with_decoder(data: bytes) -> tuple[str | None, str | None]:
    if len(data) > MAX_DECODED_BYTES_PER_CANDIDATE:
        return None, None
    if data.startswith(b"\x1f\x8b"):
        expanded = _bounded_decompress(data, gzip_stream=True)
        if expanded is None:
            return None, None
        text, nested = _bytes_text_with_decoder(expanded)
        return text, "gzip" if nested is None else f"gzip>{nested}"
    if len(data) >= 2 and data[0] == 0x78:
        expanded = _bounded_decompress(data, gzip_stream=False)
        if expanded is not None:
            text, nested = _bytes_text_with_decoder(expanded)
            return text, "zlib" if nested is None else f"zlib>{nested}"
    for codec in ("utf-8", "ascii"):
        try:
            decoded = data.decode(codec)
        except UnicodeDecodeError:
            continue
        if _useful_decoded(decoded):
            return decoded, None
    return None, None


def _bytes_text(data: bytes) -> str | None:
    text, _decoder = _bytes_text_with_decoder(data)
    return text


def _xor_texts(data: bytes, pattern: re.Pattern) -> list[tuple[str, str]]:
    if not 4 <= len(data) <= 128:
        return []
    scored: list[tuple[int, int, str]] = []
    for key in range(1, 256):
        decoded = bytes(byte ^ key for byte in data)
        text = _bytes_text(decoded)
        if text is None:
            continue
        printable, _controls = _ratios(text)
        candidate_score, _flags = _candidate_score(text, pattern)
        score = int(printable * 100) + candidate_score
        if score >= 95:
            scored.append((score, key, text))
    scored.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [(text, f"xor-0x{key:02x}") for _score, key, text in scored[:2]]


def _decode_radix_bytes(value: str) -> list[tuple[str, bytes]]:
    compact = "".join(value.split())
    results: list[tuple[str, bytes]] = []
    if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
        try:
            results.append(("hex", bytes.fromhex(compact)))
        except ValueError:
            pass
    if len(compact) >= 8 and re.fullmatch(r"[A-Z2-7=]+", compact.upper()):
        try:
            results.append(("base32", base64.b32decode(compact.upper() + "=" * (-len(compact) % 8), casefold=True)))
        except (binascii.Error, ValueError):
            pass
    if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
        try:
            results.append(("base64", base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)))
        except (binascii.Error, ValueError):
            pass
    if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", compact) and ("-" in compact or "_" in compact):
        try:
            results.append(("urlsafe-base64", base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True)))
        except (binascii.Error, ValueError):
            pass
    if 5 <= len(compact) <= 4096:
        try:
            decoded85 = base64.b85decode(compact)
        except (ValueError, binascii.Error):
            decoded85 = b""
        if decoded85:
            results.append(("base85", decoded85))
    if value.strip().startswith("<~") and value.strip().endswith("~>"):
        try:
            results.append(("ascii85", base64.a85decode(value.strip(), adobe=True)))
        except (ValueError, binascii.Error):
            pass
    return results


def _common_children(seed: _Seed, pattern: re.Pattern) -> list[tuple[str, str, str]]:
    value = seed.value.strip()
    children: list[tuple[str, str, str]] = []
    for decoder, data in _decode_radix_bytes(value):
        decoded, nested_decoder = _bytes_text_with_decoder(data)
        if decoded is not None:
            chain = decoder if nested_decoder is None else f"{decoder}>{nested_decoder}"
            children.append((chain, decoded, "bounded-radix"))
            direct_score, direct_flags = _candidate_score(decoded, pattern)
        else:
            direct_score, direct_flags = -50, ()
        if not direct_flags and direct_score < 80:
            children.extend(
                (f"{decoder}>{variant}", text, "single-byte-xor")
                for text, variant in _xor_texts(data, pattern)
            )

    compact_binary = re.sub(r"[\s,_-]", "", value)
    if len(compact_binary) >= 32 and re.fullmatch(r"[01]+", compact_binary):
        for width in (8, 7):
            if len(compact_binary) % width == 0:
                decoded = _bits_to_text(compact_binary, width, 0)
                if decoded is not None:
                    children.append(("binary", decoded, f"{width}-bit"))

    octal_parts = re.findall(r"(?<!\d)[0-7]{2,3}(?!\d)", value)
    if len(octal_parts) >= 4 and re.sub(r"[0-7\s,]+", "", value) == "":
        decoded = "".join(chr(int(part, 8)) for part in octal_parts)
        if _useful_decoded(decoded):
            children.append(("octal", decoded, "ascii-sequence"))
    decimal_parts = re.findall(r"(?<!\d)\d{1,3}(?!\d)", value)
    if len(decimal_parts) >= 4 and all(int(part) <= 255 for part in decimal_parts) and re.sub(r"[\d\s,]+", "", value) == "":
        decoded = "".join(chr(int(part)) for part in decimal_parts)
        if _useful_decoded(decoded):
            children.append(("decimal", decoded, "ascii-sequence"))

    if re.search(r"%[0-9A-Fa-f]{2}", value):
        decoded = urllib.parse.unquote(value)
        if decoded != value:
            children.append(("url-percent", decoded, "percent-encoding"))
    if re.search(r"&(?:#\d+|#x[0-9A-Fa-f]+|[A-Za-z]+);", value):
        decoded = html.unescape(value)
        if decoded != value:
            children.append(("html-entity", decoded, "entity"))
    if re.search(r"\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2})", value):
        try:
            decoded = value.encode("ascii").decode("unicode_escape")
        except (UnicodeEncodeError, UnicodeDecodeError):
            decoded = value
        if decoded != value:
            children.append(("unicode-escape", decoded, "escape-sequence"))

    morse_tokens = value.replace("/", " / ").split()
    if len(morse_tokens) >= 4 and all(token == "/" or token in _MORSE for token in morse_tokens):
        decoded = "".join(" " if token == "/" else _MORSE[token] for token in morse_tokens)
        children.append(("morse", decoded, "dot-dash"))

    if len(value) >= 4:
        children.append(("reverse", value[::-1], "character-order"))
        score, flags = _candidate_score(value, pattern)
        allow_classical = seed.depth == 0 or bool(flags) or (
            score >= 70 and "{" in value and "}" in value
        )
        if allow_classical and any(
            character.isalpha() and character.isascii() for character in value
        ):
            atbash = "".join(
                chr(ord("Z") - (ord(character) - ord("A"))) if "A" <= character <= "Z"
                else chr(ord("z") - (ord(character) - ord("a"))) if "a" <= character <= "z"
                else character
                for character in value
            )
            children.append(("atbash", atbash, "latin"))
            for shift in range(1, 26):
                rotated = "".join(
                    chr((ord(character) - ord("A") + shift) % 26 + ord("A")) if "A" <= character <= "Z"
                    else chr((ord(character) - ord("a") + shift) % 26 + ord("a")) if "a" <= character <= "z"
                    else character
                    for character in value
                )
                children.append((f"rot{shift}", rotated, "latin"))
    return children[:MAX_CHILDREN_PER_CANDIDATE]


def analyze_text_input(source: TextInput, flag_pattern: re.Pattern) -> TextStegoAnalysis:
    """Run all bounded text-stego methods and recursive common decoders."""
    if source.classification != "probable-text":
        return TextStegoAnalysis(source, (), 0, 0, ())
    text = source.text[:MAX_ANALYSIS_CHARACTERS]
    collector = _Collector(flag_pattern)

    direct_flags = _find_flags(source.text, flag_pattern)
    if direct_flags:
        collector.add(
            text,
            ("source_decode", source.encoding or "unknown"),
            "direct-decoded-text",
            depth=1,
            evidence=(f"encoding:{source.encoding}", "active-flag-regex"),
            source="source",
            known_direct_flags=direct_flags,
        )
    collector.block(text)
    collector.block(text.strip())

    _bacon_candidates(text, collector)
    _case_binary_ascii_candidates(text, collector)
    _whitespace_candidates(source.raw_bytes, text, collector)
    _snow_candidates(text, collector)
    _zero_width_candidates(text, collector)
    _homoglyph_candidates(text, collector)
    _structural_candidates(text, collector)
    _ghost_candidates(text, collector)

    root = _Seed(text, (), "source", 0, (f"encoding:{source.encoding}",), "source", {"source"})
    collector.queue.appendleft(root)
    while collector.queue:
        seed = collector.queue.popleft()
        if seed.depth >= MAX_DECODE_DEPTH:
            continue
        children = _common_children(seed, flag_pattern)
        for decoder, decoded, variant in children:
            if not _useful_decoded(decoded):
                continue
            collector.add(
                decoded,
                seed.chain + tuple(decoder.split(">")),
                variant,
                depth=seed.depth + 1,
                evidence=seed.evidence + (f"decoder:{decoder}",),
                source=seed.source,
            )

    candidates = collector.finish()
    return TextStegoAnalysis(
        source,
        candidates,
        len(collector.seeds),
        collector.aggregate_bytes,
        tuple(sorted(collector.limits)),
    )


def analyze_text_file(path: Path, flag_pattern: re.Pattern) -> TextStegoAnalysis:
    """Read and analyze a local file using the bounded text engine."""
    return analyze_text_input(read_text_input(path), flag_pattern)
