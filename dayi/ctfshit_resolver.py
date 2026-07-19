"""Resolve the optional CSL-CtfShitCli writeup exporter safely."""
from __future__ import annotations

import importlib
import importlib.metadata as importlib_metadata
import importlib.util
import json
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Literal
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname


CTFSHIT_DISTRIBUTION = "csl-ctfshitcli"
CTFSHIT_IMPORT_NAME = "src.writeup_exporter"
_PRIVATE_MODULE_PREFIX = "_dayi_ctfshit_writeup_exporter_"
_CANDIDATE_NAMES = ("ctfshitcli", "ctfshit")
_MAX_PYPROJECT_BYTES = 256 * 1024
_MAX_INIT_BYTES = 256 * 1024
_MAX_EXPORTER_BYTES = 1024 * 1024
_MAX_DIRECT_URL_BYTES = 64 * 1024

SourceKind = Literal[
    "explicit-path",
    "installed",
    "sibling",
    "child",
    "unavailable",
]
StatusCode = Literal[
    "ok",
    "invalid-path",
    "distribution-mismatch",
    "exporter-missing",
    "import-failed",
    "not-found",
]
WriteupExporter = Callable[..., object]


@dataclass(frozen=True)
class CtfshitResolution:
    """Deterministic result of one writeup-exporter resolution attempt."""

    available: bool
    source_kind: SourceKind
    status_code: StatusCode
    exporter: WriteupExporter | None
    safe_detail: str
    resolved_root: Path | None = None


@dataclass(frozen=True)
class _CheckoutValidation:
    status_code: StatusCode
    root: Path | None = None
    exporter_path: Path | None = None


@dataclass(frozen=True)
class _InstalledPaths:
    exporter_path: Path
    package_root: Path
    resolved_root: Path
    editable_namespace: bool = False


def _canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _read_project_name(pyproject_path: Path) -> str | None:
    """Read only ``project.name`` from a bounded TOML file."""
    try:
        if pyproject_path.is_symlink() or not pyproject_path.is_file():
            return None
        if pyproject_path.stat().st_size > _MAX_PYPROJECT_BYTES:
            return None
        text = pyproject_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None

    in_project = False
    name_pattern = re.compile(
        r"^name\s*=\s*(?P<quote>['\"])(?P<name>[^'\"]+)"
        r"(?P=quote)\s*(?:#.*)?$"
    )
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_project = line == "[project]"
            continue
        if not in_project:
            continue
        match = name_pattern.fullmatch(line)
        if match is not None:
            return match.group("name").strip()
    return None


def _bounded_file_within(
    path: Path,
    root: Path,
    *,
    max_bytes: int,
) -> Path | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if resolved.stat().st_size > max_bytes:
            return None
        return resolved
    except (OSError, RuntimeError, ValueError):
        return None


def _validate_checkout(candidate: Path) -> _CheckoutValidation:
    try:
        root = candidate.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return _CheckoutValidation("invalid-path")
    if not root.is_dir():
        return _CheckoutValidation("invalid-path")

    pyproject = _bounded_file_within(
        root / "pyproject.toml",
        root,
        max_bytes=_MAX_PYPROJECT_BYTES,
    )
    if pyproject is None:
        return _CheckoutValidation("invalid-path", root=root)
    project_name = _read_project_name(pyproject)
    if project_name is None or (
        _canonical_distribution_name(project_name) != CTFSHIT_DISTRIBUTION
    ):
        return _CheckoutValidation("distribution-mismatch", root=root)

    package_init = _bounded_file_within(
        root / "src" / "__init__.py",
        root,
        max_bytes=_MAX_INIT_BYTES,
    )
    if package_init is None:
        return _CheckoutValidation("invalid-path", root=root)

    exporter = root / "src" / "writeup_exporter.py"
    if not exporter.exists():
        return _CheckoutValidation("exporter-missing", root=root)
    resolved_exporter = _bounded_file_within(
        exporter,
        root,
        max_bytes=_MAX_EXPORTER_BYTES,
    )
    if resolved_exporter is None:
        return _CheckoutValidation("invalid-path", root=root)
    return _CheckoutValidation("ok", root=root, exporter_path=resolved_exporter)


def _safe_detail(source_kind: SourceKind, status_code: StatusCode) -> str:
    if status_code == "ok":
        return {
            "explicit-path": "validated explicit ctfshitcli checkout",
            "installed": "installed csl-ctfshitcli exporter",
            "sibling": "validated sibling ctfshitcli checkout",
            "child": "validated child ctfshitcli checkout",
        }.get(source_kind, "ctfshit writeup exporter available")
    if source_kind == "explicit-path":
        if status_code == "distribution-mismatch":
            return "explicit path is not a csl-ctfshitcli project"
        if status_code == "exporter-missing":
            return "explicit ctfshitcli checkout has no writeup exporter"
        if status_code == "import-failed":
            return "explicit ctfshitcli exporter import failed"
        return "explicit path is not a valid csl-ctfshitcli checkout"
    if source_kind == "installed":
        if status_code == "distribution-mismatch":
            return "installed src exporter does not belong to csl-ctfshitcli"
        if status_code == "exporter-missing":
            return "installed csl-ctfshitcli has no callable writeup exporter"
        return "csl-ctfshitcli distribution is installed but exporter import failed"
    return "ctfshit writeup exporter was not found"


def _resolution(
    source_kind: SourceKind,
    status_code: StatusCode,
    *,
    exporter: WriteupExporter | None = None,
    resolved_root: Path | None = None,
) -> CtfshitResolution:
    return CtfshitResolution(
        available=status_code == "ok" and exporter is not None,
        source_kind=source_kind,
        status_code=status_code,
        exporter=exporter,
        safe_detail=_safe_detail(source_kind, status_code),
        resolved_root=resolved_root,
    )


def _load_local_exporter(
    validation: _CheckoutValidation,
    source_kind: SourceKind,
) -> CtfshitResolution:
    if validation.status_code != "ok":
        return _resolution(
            source_kind,
            validation.status_code,
            resolved_root=validation.root,
        )
    assert validation.root is not None
    assert validation.exporter_path is not None

    module_name = f"{_PRIVATE_MODULE_PREFIX}{uuid.uuid4().hex}"
    previous = sys.modules.get(module_name)
    try:
        spec = importlib.util.spec_from_file_location(
            module_name,
            validation.exporter_path,
        )
        if spec is None or spec.loader is None:
            return _resolution(
                source_kind,
                "import-failed",
                resolved_root=validation.root,
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        exporter = getattr(module, "export_writeups", None)
        if not callable(exporter):
            return _resolution(
                source_kind,
                "exporter-missing",
                resolved_root=validation.root,
            )
        return _resolution(
            source_kind,
            "ok",
            exporter=exporter,
            resolved_root=validation.root,
        )
    except Exception:
        return _resolution(
            source_kind,
            "import-failed",
            resolved_root=validation.root,
        )
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous


def _direct_url_root(distribution: object) -> Path | None:
    try:
        raw = distribution.read_text("direct_url.json")  # type: ignore[attr-defined]
    except Exception:
        return None
    if not raw or len(raw) > _MAX_DIRECT_URL_BYTES:
        return None
    try:
        payload = json.loads(raw)
        parsed = urlparse(payload.get("url", ""))
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return None
    if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
        return None
    try:
        return Path(url2pathname(unquote(parsed.path))).resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _installed_paths(distribution: object) -> _InstalledPaths | None:
    editable_root = _direct_url_root(distribution)
    if editable_root is not None:
        validation = _validate_checkout(editable_root)
        if (
            validation.status_code == "ok"
            and validation.root is not None
            and validation.exporter_path is not None
        ):
            return _InstalledPaths(
                validation.exporter_path,
                validation.exporter_path.parent,
                validation.root,
                editable_namespace=True,
            )

    try:
        files = distribution.files or ()  # type: ignore[attr-defined]
    except Exception:
        files = ()
    exporter_path: Path | None = None
    init_path: Path | None = None
    for item in files:
        relative = PurePosixPath(str(item)).as_posix()
        if relative not in {"src/__init__.py", "src/writeup_exporter.py"}:
            continue
        try:
            located = Path(distribution.locate_file(item))  # type: ignore[attr-defined]
        except Exception:
            continue
        if relative == "src/__init__.py":
            init_path = located
        else:
            exporter_path = located
    if exporter_path is None or init_path is None:
        return None
    try:
        resolved_exporter = exporter_path.resolve(strict=True)
        resolved_init = init_path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    package_root = resolved_init.parent
    if (
        resolved_exporter.parent != package_root
        or resolved_exporter.is_symlink()
        or not resolved_exporter.is_file()
        or resolved_exporter.stat().st_size > _MAX_EXPORTER_BYTES
    ):
        return None
    return _InstalledPaths(
        resolved_exporter,
        package_root,
        package_root.parent,
    )


def _module_matches_path(module: object, expected: Path) -> bool:
    origin = getattr(module, "__file__", None)
    if not origin:
        return False
    try:
        return Path(origin).resolve(strict=True) == expected
    except (OSError, RuntimeError):
        return False


def _package_matches_root(module: object, expected: Path) -> bool:
    package_paths = getattr(module, "__path__", None)
    if package_paths is not None:
        for value in package_paths:
            try:
                if Path(value).resolve(strict=True) == expected:
                    return True
            except (OSError, RuntimeError):
                continue
    origin = getattr(module, "__file__", None)
    if origin:
        try:
            return Path(origin).resolve(strict=True).parent == expected
        except (OSError, RuntimeError):
            return False
    return False


def _is_namespace_package(module: object) -> bool:
    return (
        getattr(module, "__file__", None) is None
        and getattr(module, "__path__", None) is not None
    )


def _restore_module(name: str, previous: object | None) -> None:
    if previous is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = previous  # type: ignore[assignment]


def _resolve_installed() -> CtfshitResolution | None:
    try:
        distribution = importlib_metadata.distribution(CTFSHIT_DISTRIBUTION)
    except importlib_metadata.PackageNotFoundError:
        return None
    except Exception:
        return _resolution("installed", "import-failed")

    try:
        metadata_name = distribution.metadata.get("Name")
    except Exception:
        metadata_name = None
    if not isinstance(metadata_name, str) or (
        _canonical_distribution_name(metadata_name) != CTFSHIT_DISTRIBUTION
    ):
        return _resolution("installed", "distribution-mismatch")

    try:
        owners = importlib_metadata.packages_distributions().get("src", ())
    except Exception:
        owners = ()
    canonical_owners = {
        _canonical_distribution_name(owner)
        for owner in owners
        if isinstance(owner, str)
    }
    if CTFSHIT_DISTRIBUTION not in canonical_owners:
        return _resolution("installed", "distribution-mismatch")

    paths = _installed_paths(distribution)
    if paths is None:
        return _resolution("installed", "exporter-missing")

    previous_src = sys.modules.get("src")
    previous_exporter = sys.modules.get(CTFSHIT_IMPORT_NAME)
    if previous_src is not None and not (
        _package_matches_root(previous_src, paths.package_root)
        or (paths.editable_namespace and _is_namespace_package(previous_src))
    ):
        return _resolution(
            "installed",
            "distribution-mismatch",
            resolved_root=paths.resolved_root,
        )
    if previous_exporter is not None and not _module_matches_path(
        previous_exporter, paths.exporter_path
    ):
        return _resolution(
            "installed",
            "distribution-mismatch",
            resolved_root=paths.resolved_root,
        )

    try:
        module = importlib.import_module(CTFSHIT_IMPORT_NAME)
    except Exception:
        _restore_module("src", previous_src)
        _restore_module(CTFSHIT_IMPORT_NAME, previous_exporter)
        return _resolution(
            "installed",
            "import-failed",
            resolved_root=paths.resolved_root,
        )
    if not _module_matches_path(module, paths.exporter_path):
        _restore_module("src", previous_src)
        _restore_module(CTFSHIT_IMPORT_NAME, previous_exporter)
        return _resolution(
            "installed",
            "distribution-mismatch",
            resolved_root=paths.resolved_root,
        )
    loaded_src = sys.modules.get("src")
    if loaded_src is None or not (
        _package_matches_root(loaded_src, paths.package_root)
        or (paths.editable_namespace and _is_namespace_package(loaded_src))
    ):
        _restore_module("src", previous_src)
        _restore_module(CTFSHIT_IMPORT_NAME, previous_exporter)
        return _resolution(
            "installed",
            "distribution-mismatch",
            resolved_root=paths.resolved_root,
        )

    exporter = getattr(module, "export_writeups", None)
    if not callable(exporter):
        return _resolution(
            "installed",
            "exporter-missing",
            resolved_root=paths.resolved_root,
        )
    return _resolution(
        "installed",
        "ok",
        exporter=exporter,
        resolved_root=paths.resolved_root,
    )


def _validated_dayi_root(candidate: Path) -> Path | None:
    try:
        root = candidate.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not root.is_dir():
        return None
    pyproject = _bounded_file_within(
        root / "pyproject.toml",
        root,
        max_bytes=_MAX_PYPROJECT_BYTES,
    )
    package_init = _bounded_file_within(
        root / "dayi" / "__init__.py",
        root,
        max_bytes=_MAX_INIT_BYTES,
    )
    if pyproject is None or package_init is None:
        return None
    name = _read_project_name(pyproject)
    if name is None or _canonical_distribution_name(name) != "dayi-stego-solver":
        return None
    return root


def _automatic_resolution(project_root: Path | None) -> CtfshitResolution:
    inferred = (
        Path(__file__).resolve().parents[1]
        if project_root is None
        else Path(project_root)
    )
    root = _validated_dayi_root(inferred)
    if root is None:
        return _resolution("unavailable", "not-found")

    groups = (
        ("sibling", root.parent),
        ("child", root),
    )
    for source_kind, parent in groups:
        for name in _CANDIDATE_NAMES:
            candidate = parent / name
            if not candidate.exists():
                continue
            validation = _validate_checkout(candidate)
            if validation.status_code != "ok":
                continue
            return _load_local_exporter(validation, source_kind)
    return _resolution("unavailable", "not-found")


def resolve_writeup_exporter(
    explicit_path: Path | str | None = None,
    *,
    project_root: Path | None = None,
) -> CtfshitResolution:
    """Resolve the exporter without network, subprocesses, or path mutation."""
    if explicit_path is not None:
        validation = _validate_checkout(Path(explicit_path))
        return _load_local_exporter(validation, "explicit-path")

    installed = _resolve_installed()
    if installed is not None:
        return installed
    return _automatic_resolution(project_root)


__all__ = ["CtfshitResolution", "resolve_writeup_exporter"]
