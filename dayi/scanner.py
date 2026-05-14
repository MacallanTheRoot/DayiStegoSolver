"""
dayi/scanner.py
~~~~~~~~~~~~~~~
Flag scanning utilities.

Searches text content (stdout/stderr/file contents) for a user-supplied
regular expression and returns all unique full-match strings.

FIX: Replaced pattern.findall() with pattern.finditer() + match.group(0)
     to correctly handle capture-group regexes (e.g. "CTF{(.*?)}") without
     returning tuples or partial strings.
"""
import re
import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("dayi")


def _collect_matches(pattern: re.Pattern, text: str) -> list[str]:
    """
    Extract all unique full-match strings using finditer.

    Using finditer + group(0) guarantees we always get the complete matched
    string regardless of how many capture groups the pattern contains.
    findall() breaks when groups are present (returns tuples or group strings).

    Args:
        pattern: Pre-compiled regex pattern.
        text:    Text to search.

    Returns:
        Ordered list of unique full matches.
    """
    seen: dict[str, None] = {}
    for m in pattern.finditer(text):
        seen[m.group(0)] = None
    return list(seen)


def scan_text(content: str, pattern: re.Pattern) -> list[str]:
    """
    Search a string for all occurrences of a compiled regex pattern.

    Args:
        content: The raw text to search.
        pattern: Pre-compiled regex pattern representing the flag format.

    Returns:
        List of unique matched full strings (preserves insertion order).
    """
    return _collect_matches(pattern, content)


def scan_file(filepath: Path, pattern: re.Pattern) -> list[str]:
    """
    Attempt to read a file as text and scan it for flag matches.

    Falls back to latin-1 on UTF-8 decode errors. All matches are full
    strings via group(0) to survive user-supplied capture-group patterns.

    Args:
        filepath: Path to the file to scan.
        pattern:  Pre-compiled regex flag pattern.

    Returns:
        List of unique matched strings found in the file.
    """
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
    """
    Recursively scan all files in a directory for flag matches.

    Args:
        directory: Root directory to walk.
        pattern:   Pre-compiled regex flag pattern.

    Returns:
        Dictionary mapping relative file paths to lists of matched flag strings.
    """
    results: dict[str, list[str]] = {}
    if not directory.exists():
        return results

    for root, _dirs, files in os.walk(directory):
        for filename in files:
            fpath = Path(root) / filename
            found = scan_file(fpath, pattern)
            if found:
                rel_key = str(fpath.relative_to(directory))
                results[rel_key] = found

    return results


def compile_pattern(flag_regex: str) -> Optional[re.Pattern]:
    """
    Safely compile a user-supplied flag regex pattern.

    Args:
        flag_regex: Raw regex string from CLI argument.

    Returns:
        Compiled Pattern on success, None on invalid regex.
    """
    try:
        return re.compile(flag_regex)
    except re.error as exc:
        logger.error(f"[scanner] Invalid regex pattern '{flag_regex}': {exc}")
        return None
