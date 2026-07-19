#!/usr/bin/env python3
"""Validate Dayı wheel and source-distribution contents without extraction."""
from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence

EXPECTED_NAME = "dayi-stego-solver"
EXPECTED_VERSION = "4.1.0"
EXPECTED_AUTHOR = "MacallanTheRoot"
EXPECTED_REQUIRES_PYTHON = ">=3.10"
EXPECTED_ENTRY_POINT = "dayi = dayi.cli:main"
EXPECTED_URLS = {
    "Repository": "https://github.com/MacallanTheRoot/DayiStegoSolver",
    "Bug Tracker": "https://github.com/MacallanTheRoot/DayiStegoSolver/issues",
}

WHEEL_REQUIRED = {
    "dayi/__init__.py",
    "dayi/__main__.py",
    "dayi/cli.py",
    "dayi/doctor.py",
    "dayi/plugin_inspector.py",
    "dayi/reporter.py",
    "dayi/runner.py",
    "dayi/scanner.py",
    "dayi/tools/__init__.py",
    "dayi/tools/_plugin.py",
}
SDIST_REQUIRED = {
    "CHANGELOG.md",
    "LICENSE",
    "MANIFEST.in",
    "README.md",
    "RELEASE_CHECKLIST.md",
    "RELEASE_NOTES_v4.0.0.md",
    "pyproject.toml",
    "scripts/check.sh",
    "scripts/validate_distribution.py",
    "tests/test_distribution_contents.py",
    "tests/test_package_metadata.py",
    *WHEEL_REQUIRED,
}
FORBIDDEN_COMPONENTS = {
    ".git",
    ".github",
    "__pycache__",
    "build",
    "dist",
    "tests",
}
PLACEHOLDER_URLS = (
    "your-org",
    "example.com",
    "MacallanTheRoot/dayi-stego-solver",
)


class DistributionValidationError(ValueError):
    """Raised when a built distribution violates a packaging invariant."""


def _normalize_member(name: str) -> str:
    """Return a safe POSIX archive member name or reject it."""
    if not name or "\x00" in name or "\\" in name:
        raise DistributionValidationError(f"unsafe archive member: {name!r}")
    raw_parts = name.rstrip("/").split("/")
    if not raw_parts or any(part in {"", ".", ".."} for part in raw_parts):
        raise DistributionValidationError(f"unsafe archive member: {name!r}")
    path = PurePosixPath(*raw_parts)
    if path.is_absolute() or ":" in raw_parts[0]:
        raise DistributionValidationError(f"unsafe archive member: {name!r}")
    return path.as_posix()


def _normalized_members(names: Iterable[str]) -> tuple[str, ...]:
    members = tuple(_normalize_member(name) for name in names)
    if len(members) != len(set(members)):
        raise DistributionValidationError("archive contains duplicate member names")
    return members


def _require_members(actual: set[str], required: set[str], archive: Path) -> None:
    missing = sorted(required - actual)
    if missing:
        raise DistributionValidationError(
            f"{archive.name} is missing required members: {', '.join(missing)}"
        )


def _wheel_metadata_names(members: Sequence[str], filename: str) -> tuple[str, str]:
    metadata = [name for name in members if name.endswith(".dist-info/METADATA")]
    entry_points = [
        name for name in members if name.endswith(".dist-info/entry_points.txt")
    ]
    if len(metadata) != 1 or len(entry_points) != 1:
        raise DistributionValidationError(
            f"{filename} must contain one METADATA and one entry_points.txt"
        )
    return metadata[0], entry_points[0]


def _validate_metadata(raw: bytes, archive: Path) -> None:
    try:
        message = Parser().parsestr(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise DistributionValidationError(
            f"{archive.name} has unreadable METADATA: {exc}"
        ) from exc

    expected_fields = {
        "Name": EXPECTED_NAME,
        "Version": EXPECTED_VERSION,
        "Author": EXPECTED_AUTHOR,
        "Requires-Python": EXPECTED_REQUIRES_PYTHON,
    }
    for field, expected in expected_fields.items():
        values = message.get_all(field, [])
        if values != [expected]:
            raise DistributionValidationError(
                f"{archive.name} metadata {field!r} must be {expected!r}"
            )

    classifiers = message.get_all("Classifier", [])
    if "Development Status :: 4 - Beta" not in classifiers:
        raise DistributionValidationError(
            f"{archive.name} metadata is missing the Beta classifier"
        )

    license_values = message.get_all("License-Expression", []) + message.get_all(
        "License", []
    )
    if "MIT" not in license_values:
        raise DistributionValidationError(
            f"{archive.name} metadata does not identify the MIT license"
        )

    project_urls: dict[str, str] = {}
    for value in message.get_all("Project-URL", []):
        label, separator, url = value.partition(",")
        if not separator:
            raise DistributionValidationError(
                f"{archive.name} contains malformed Project-URL metadata"
            )
        label = label.strip()
        if label in project_urls:
            raise DistributionValidationError(
                f"{archive.name} contains duplicate Project-URL {label!r}"
            )
        project_urls[label] = url.strip()
    if project_urls != EXPECTED_URLS:
        raise DistributionValidationError(
            f"{archive.name} has unexpected project URLs: {project_urls!r}"
        )

    metadata_text = raw.decode("utf-8", errors="replace").partition("\n\n")[0]
    for placeholder in PLACEHOLDER_URLS:
        if placeholder in metadata_text:
            raise DistributionValidationError(
                f"{archive.name} metadata contains placeholder URL {placeholder!r}"
            )


def validate_wheel(path: Path) -> tuple[str, ...]:
    """Validate one wheel and return its normalized member names."""
    try:
        with zipfile.ZipFile(path) as archive:
            members = _normalized_members(info.filename for info in archive.infolist())
            actual = set(members)
            _require_members(actual, WHEEL_REQUIRED, path)

            for name in members:
                member = PurePosixPath(name)
                if (
                    FORBIDDEN_COMPONENTS.intersection(member.parts)
                    or member.suffix == ".pyc"
                ):
                    raise DistributionValidationError(
                        f"{path.name} contains forbidden wheel member: {name}"
                    )

            metadata_name, entry_points_name = _wheel_metadata_names(
                members, path.name
            )
            _validate_metadata(archive.read(metadata_name), path)
            entry_points = archive.read(entry_points_name).decode(
                "utf-8", errors="strict"
            )
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError) as exc:
        raise DistributionValidationError(
            f"cannot read wheel {path.name}: {exc}"
        ) from exc

    entry_lines = {
        line.strip()
        for line in entry_points.splitlines()
        if line.strip() and not line.lstrip().startswith("[")
    }
    if entry_lines != {EXPECTED_ENTRY_POINT}:
        raise DistributionValidationError(
            f"{path.name} has unexpected console entry points: {sorted(entry_lines)!r}"
        )
    return members


def _strip_sdist_root(members: Sequence[str], archive: Path) -> tuple[str, ...]:
    roots = {PurePosixPath(name).parts[0] for name in members}
    expected_root = f"dayi_stego_solver-{EXPECTED_VERSION}"
    if roots != {expected_root}:
        raise DistributionValidationError(
            f"{archive.name} must have the single root {expected_root!r}"
        )
    stripped = []
    for name in members:
        parts = PurePosixPath(name).parts
        if len(parts) > 1:
            stripped.append(PurePosixPath(*parts[1:]).as_posix())
    return tuple(stripped)


def validate_sdist(path: Path) -> tuple[str, ...]:
    """Validate one source distribution and return root-relative members."""
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            infos = archive.getmembers()
            members = _normalized_members(info.name for info in infos)
            for info in infos:
                if info.issym() or info.islnk():
                    raise DistributionValidationError(
                        f"{path.name} contains an archive link: {info.name}"
                    )
            relative = _strip_sdist_root(members, path)
    except (OSError, tarfile.TarError) as exc:
        raise DistributionValidationError(
            f"cannot read source distribution {path.name}: {exc}"
        ) from exc

    _require_members(set(relative), SDIST_REQUIRED, path)
    return relative


def validate_dist_directory(dist_dir: Path) -> tuple[Path, Path]:
    """Validate the one expected wheel and sdist in a build directory."""
    wheel_pattern = f"dayi_stego_solver-{EXPECTED_VERSION}-*.whl"
    sdist_pattern = f"dayi_stego_solver-{EXPECTED_VERSION}.tar.gz"
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if (
        len(wheels) != 1
        or len(sdists) != 1
        or not wheels[0].match(wheel_pattern)
        or sdists[0].name != sdist_pattern
    ):
        raise DistributionValidationError(
            f"{dist_dir} must contain exactly one {wheel_pattern!r} and one "
            f"{sdist_pattern!r}"
        )
    validate_wheel(wheels[0])
    validate_sdist(sdists[0])
    return wheels[0], sdists[0]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=Path("dist"),
        help="directory containing exactly one Dayı wheel and sdist",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        wheel, sdist = validate_dist_directory(args.dist_dir)
    except DistributionValidationError as exc:
        print(f"distribution validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Validated wheel: {wheel}")
    print(f"Validated sdist: {sdist}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
