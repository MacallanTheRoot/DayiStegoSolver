"""Tool package with dynamic plugin discovery and lazy legacy exports."""
from __future__ import annotations

import importlib
from typing import Any

# Backward-compatible public functions. These are resolved lazily so importing
# ``dayi.tools`` does not eagerly import every plugin module. The dynamic
# registry does not use this mapping; new modules are found via pkgutil.
_LEGACY_EXPORTS: dict[str, tuple[str, str]] = {
    "run_exiftool": ("dayi.tools.exiftool", "run_exiftool"),
    "run_binwalk": ("dayi.tools.binwalk", "run_binwalk"),
    "run_strings": ("dayi.tools.strings", "run_strings"),
    "run_zsteg": ("dayi.tools.zsteg", "run_zsteg"),
    "run_lsb": ("dayi.tools.lsb", "run_lsb"),
    "run_chi_square": ("dayi.tools.chi_square", "run_chi_square"),
    "run_steghide": ("dayi.tools.steghide", "run_steghide"),
    "run_steghide_bruteforce": (
        "dayi.tools.steghide",
        "run_steghide_bruteforce",
    ),
    "run_stegseek": ("dayi.tools.stegseek", "run_stegseek"),
    "run_outguess": ("dayi.tools.outguess", "run_outguess"),
    "run_outguess_bruteforce": (
        "dayi.tools.outguess",
        "run_outguess_bruteforce",
    ),
    "run_exiv2": ("dayi.tools.exiv2", "run_exiv2"),
    "run_zip_cracker": ("dayi.tools.zip_cracker", "run_zip_cracker"),
}

__all__ = sorted(_LEGACY_EXPORTS)


def __getattr__(name: str) -> Any:
    """Resolve a legacy tool function only when it is requested."""
    try:
        module_name, attribute_name = _LEGACY_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc

    value = getattr(importlib.import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
