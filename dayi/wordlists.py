"""Controlled local wordlist resolution for scan commands."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


KALI_ROCKYOU_CANDIDATES = (
    Path("/usr/share/wordlists/rockyou.txt"),
    Path("/usr/share/wordlists/rockyou.txt.gz"),
)


@dataclass(frozen=True)
class WordlistResolution:
    """Result of a bounded, network-free wordlist lookup."""

    requested: Path | None
    resolved: Path | None
    candidates_checked: tuple[Path, ...]


def _resolve_regular_wordlist(candidate: Path) -> Path | None:
    try:
        if not candidate.is_file():
            return None
        return candidate.resolve(strict=True)
    except OSError:
        return None


def resolve_wordlist(
    requested: Path | None,
    *,
    cwd: Path | None = None,
    system_candidates: tuple[Path, ...] = KALI_ROCKYOU_CANDIDATES,
) -> WordlistResolution:
    """Resolve only the requested path and controlled rockyou locations."""
    if requested is None:
        return WordlistResolution(None, None, ())

    requested_path = requested.expanduser()
    active_cwd = Path.cwd() if cwd is None else cwd
    candidates: list[Path] = [requested_path]
    is_plain_rockyou_name = (
        not requested_path.is_absolute()
        and requested_path.parent == Path(".")
        and requested_path.name == "rockyou.txt"
    )
    if is_plain_rockyou_name:
        candidates.append(active_cwd / requested_path.name)
        candidates.extend(system_candidates)

    checked: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        identity = str(candidate)
        if identity in seen:
            continue
        seen.add(identity)
        checked.append(candidate)
        resolved = _resolve_regular_wordlist(candidate)
        if resolved is not None:
            return WordlistResolution(requested, resolved, tuple(checked))

    return WordlistResolution(requested, None, tuple(checked))
