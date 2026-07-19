"""Dependency-free installation diagnostics for Dayı Stego Solver."""
from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import site
import subprocess
import sys
import threading
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from dayi import MIN_SUPPORTED_PYTHON, __version__
from dayi.ctfshit_resolver import resolve_writeup_exporter
from dayi.integrations import inspect_native_notification_configuration

DOCTOR_SCHEMA_VERSION = 1
VERSION_PROBE_TIMEOUT_SECONDS = 3.0
VERSION_PROBE_STREAM_BYTES = 8 * 1024
VERSION_TEXT_CHARS = 240
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-_])")
_DAYI_PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ExternalToolDefinition:
    """Static allowlisted executable diagnostic definition."""

    tool_id: str
    command: str
    version_args: tuple[str, ...]
    category: str
    capability: str


@dataclass(frozen=True)
class PythonCapabilityDefinition:
    """Static optional Python capability definition."""

    capability_id: str
    import_name: str
    distribution: str
    display_name: str
    capability: str


@dataclass(frozen=True)
class CoreDiagnostic:
    """Core runtime and package health fields."""

    status: str
    dayi_version: str | None
    python_implementation: str
    python_version: str
    python_supported: bool
    minimum_python: str
    platform: str
    architecture: str
    python_executable: str
    package_path: str | None
    cli_operational: bool


@dataclass(frozen=True)
class ExternalToolDiagnostic:
    """One external executable discovery and version result."""

    tool_id: str
    command: str
    found: bool
    path: str | None
    version: str | None
    probe_status: str
    category: str
    capability: str
    core_required: bool = False


@dataclass(frozen=True)
class PythonCapabilityDiagnostic:
    """One optional Python module discovery result."""

    capability_id: str
    import_name: str
    distribution: str
    display_name: str
    available: bool
    version: str | None
    metadata_status: str
    capability: str
    location: str | None
    location_status: str
    core_required: bool = False


@dataclass(frozen=True)
class DoctorReport:
    """Complete deterministic doctor result."""

    overall_status: str
    core_usable: bool
    core: CoreDiagnostic
    external_tools: tuple[ExternalToolDiagnostic, ...]
    python_capabilities: tuple[PythonCapabilityDiagnostic, ...]
    schema_version: int = DOCTOR_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON-compatible diagnostics schema."""
        return {
            "schema_version": self.schema_version,
            "overall_status": self.overall_status,
            "core_usable": self.core_usable,
            "core": asdict(self.core),
            "external_tools": [asdict(item) for item in self.external_tools],
            "python_capabilities": [
                asdict(item) for item in self.python_capabilities
            ],
        }


EXTERNAL_TOOL_DEFINITIONS = (
    ExternalToolDefinition(
        "exiftool", "exiftool", ("-ver",), "format-specific", "metadata analysis"
    ),
    ExternalToolDefinition(
        "exiv2", "exiv2", ("--version",), "format-specific", "image metadata analysis"
    ),
    ExternalToolDefinition(
        "strings", "strings", ("--version",), "core-optional", "printable string extraction"
    ),
    ExternalToolDefinition(
        "binwalk", "binwalk", ("-h",), "format-specific", "embedded-file analysis"
    ),
    ExternalToolDefinition(
        "zsteg", "zsteg", ("--version",), "format-specific", "PNG/BMP steganography"
    ),
    ExternalToolDefinition(
        "steghide", "steghide", ("--version",), "brute-force", "steghide extraction"
    ),
    ExternalToolDefinition(
        "outguess", "outguess", ("-h",), "brute-force", "JPEG outguess extraction"
    ),
    ExternalToolDefinition(
        "stegseek", "stegseek", ("--version",), "brute-force", "fast steghide cracking"
    ),
    ExternalToolDefinition(
        "tesseract", "tesseract", ("--version",), "OCR runtime", "visible-text OCR"
    ),
)

PYTHON_CAPABILITY_DEFINITIONS = (
    PythonCapabilityDefinition("rich", "rich", "rich", "Rich", "terminal UI"),
    PythonCapabilityDefinition(
        "aiohttp",
        "aiohttp",
        "aiohttp",
        "aiohttp",
        "preferred native notification transport; urllib fallback is built in",
    ),
    PythonCapabilityDefinition(
        "native_notifications",
        "urllib.request",
        "Python standard library",
        "native notifications",
        "native CTFd and Discord notifications",
    ),
    PythonCapabilityDefinition("pillow", "PIL", "Pillow", "Pillow", "OCR image loading"),
    PythonCapabilityDefinition(
        "pytesseract", "pytesseract", "pytesseract", "pytesseract", "OCR bridge"
    ),
    PythonCapabilityDefinition("pypdf", "pypdf", "pypdf", "pypdf", "PDF analysis"),
    PythonCapabilityDefinition(
        "oletools", "oletools", "oletools", "oletools", "OLE/VBA macro analysis"
    ),
    PythonCapabilityDefinition("scapy", "scapy", "scapy", "Scapy", "PCAP analysis"),
    PythonCapabilityDefinition(
        "ctfshit",
        "src.writeup_exporter",
        "csl-ctfshitcli",
        "ctfshit",
        "rich ctfshit writeup exporter",
    ),
)


def _drain_bounded(stream: Any, destination: bytearray) -> None:
    """Drain a subprocess pipe while retaining only a bounded prefix."""
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(1024)
            if not chunk:
                break
            remaining = VERSION_PROBE_STREAM_BYTES - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
    except (OSError, ValueError):
        return
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _normalize_version_text(stdout: bytes, stderr: bytes) -> str | None:
    """Return one concise control-free line from bounded probe output."""
    raw = stdout if stdout.strip() else stderr
    text = _ANSI_ESCAPE_PATTERN.sub("", raw.decode("utf-8", errors="replace"))
    for line in text.splitlines():
        cleaned = "".join(
            " " if unicodedata.category(char).startswith("C") else char
            for char in line
        )
        normalized = " ".join(cleaned.split())
        if normalized:
            return normalized[:VERSION_TEXT_CHARS]
    return None


def diagnose_external_tool(
    definition: ExternalToolDefinition,
    *,
    which: Callable[[str], str | None] | None = None,
    popen: Callable[..., Any] | None = None,
) -> ExternalToolDiagnostic:
    """Discover and safely probe one static executable definition."""
    which_func = shutil.which if which is None else which
    popen_func = subprocess.Popen if popen is None else popen
    resolved = which_func(definition.command)
    if resolved is None:
        return ExternalToolDiagnostic(
            definition.tool_id,
            definition.command,
            False,
            None,
            None,
            "missing",
            definition.category,
            definition.capability,
        )

    command = [resolved, *definition.version_args]
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    try:
        process = popen_func(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return ExternalToolDiagnostic(
            definition.tool_id,
            definition.command,
            True,
            resolved,
            None,
            "failed",
            definition.category,
            definition.capability,
        )

    readers = (
        threading.Thread(
            target=_drain_bounded,
            args=(process.stdout, stdout_buffer),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_bounded,
            args=(process.stderr, stderr_buffer),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    probe_status = "failed"
    return_code: int | None = None
    try:
        return_code = process.wait(timeout=VERSION_PROBE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        probe_status = "timeout"
        try:
            process.kill()
            process.wait(timeout=1.0)
        except (OSError, subprocess.SubprocessError):
            pass
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass
    finally:
        for reader in readers:
            reader.join(timeout=1.0)

    version = _normalize_version_text(bytes(stdout_buffer), bytes(stderr_buffer))
    if probe_status != "timeout":
        if version is not None:
            probe_status = "ok"
        elif return_code in (None, 0):
            probe_status = "unavailable"

    return ExternalToolDiagnostic(
        definition.tool_id,
        definition.command,
        True,
        resolved,
        version,
        probe_status,
        definition.category,
        definition.capability,
    )


def _normal_site_roots() -> tuple[Path, ...]:
    """Return resolved site-package roots without reading environment values."""
    roots: list[Path] = []
    try:
        candidates = [*site.getsitepackages(), site.getusersitepackages()]
    except (AttributeError, OSError):
        candidates = []
    for candidate in candidates:
        try:
            roots.append(Path(candidate).resolve())
        except (OSError, RuntimeError):
            continue
    return tuple(dict.fromkeys(roots))


def _spec_location(spec: Any) -> str | None:
    """Extract one non-executing origin path from an import specification."""
    origin = getattr(spec, "origin", None)
    if origin and origin not in {"built-in", "frozen"}:
        return str(origin)
    locations = getattr(spec, "submodule_search_locations", None)
    if locations:
        try:
            return str(next(iter(locations)))
        except StopIteration:
            return None
    return origin


def _location_status(location: str | None, site_roots: Sequence[Path]) -> str:
    """Qualify whether a discovered module resides in normal site-packages."""
    if not location or location in {"built-in", "frozen"}:
        return "unknown"
    try:
        resolved = Path(location).resolve()
    except (OSError, RuntimeError):
        return "unknown"
    for root in site_roots:
        try:
            resolved.relative_to(root)
            return "site-packages"
        except ValueError:
            continue
    return "outside-site-packages"


def diagnose_python_capability(
    definition: PythonCapabilityDefinition,
    *,
    find_spec: Callable[[str], Any] | None = None,
    distribution_version: Callable[[str], str] | None = None,
    site_roots: Sequence[Path] | None = None,
) -> PythonCapabilityDiagnostic:
    """Discover an optional module without importing or executing it."""
    find_spec_func = importlib.util.find_spec if find_spec is None else find_spec
    version_func = (
        importlib.metadata.version
        if distribution_version is None
        else distribution_version
    )
    roots = _normal_site_roots() if site_roots is None else tuple(site_roots)
    try:
        spec = find_spec_func(definition.import_name)
    except (ImportError, AttributeError, ValueError, ModuleNotFoundError):
        spec = None
        discovery_error = True
    else:
        discovery_error = False

    if spec is None:
        return PythonCapabilityDiagnostic(
            definition.capability_id,
            definition.import_name,
            definition.distribution,
            definition.display_name,
            False,
            None,
            "discovery-error" if discovery_error else "not-installed",
            definition.capability,
            None,
            "unknown",
        )

    location = _spec_location(spec)
    try:
        version = version_func(definition.distribution)
        metadata_status = "ok"
    except importlib.metadata.PackageNotFoundError:
        version = None
        metadata_status = "missing"
    except Exception:
        version = None
        metadata_status = "broken"

    return PythonCapabilityDiagnostic(
        definition.capability_id,
        definition.import_name,
        definition.distribution,
        definition.display_name,
        True,
        version,
        metadata_status,
        definition.capability,
        location,
        _location_status(location, roots),
    )


def diagnose_ctfshit_capability(
    explicit_path: Path | str | None = None,
    *,
    path_source: str | None = None,
    project_root: Path = _DAYI_PROJECT_ROOT,
) -> PythonCapabilityDiagnostic:
    """Resolve the optional ctfshit exporter without invoking it."""
    try:
        resolution = resolve_writeup_exporter(
            explicit_path=explicit_path,
            project_root=project_root,
        )
    except Exception:
        source = (
            "environment-configured"
            if path_source == "environment"
            else "explicit-path"
            if explicit_path is not None
            else "unavailable"
        )
        return PythonCapabilityDiagnostic(
            capability_id="ctfshit",
            import_name="src.writeup_exporter",
            distribution="csl-ctfshitcli",
            display_name="ctfshit writeup exporter",
            available=False,
            version=None,
            metadata_status="import-failed",
            capability=(
                "built-in Markdown fallback active — "
                "ctfshit exporter resolution failed"
            ),
            location=None,
            location_status=source,
        )

    source = resolution.source_kind
    if source == "explicit-path" and path_source == "environment":
        source = "environment-configured"
    capability = (
        "rich ctfshit writeup exporter available"
        if resolution.available
        else "built-in Markdown fallback active"
    )
    return PythonCapabilityDiagnostic(
        capability_id="ctfshit",
        import_name="src.writeup_exporter",
        distribution="csl-ctfshitcli",
        display_name="ctfshit writeup exporter",
        available=resolution.available,
        version=None,
        metadata_status=resolution.status_code,
        capability=f"{capability} — {resolution.safe_detail}",
        location=None,
        location_status=source,
    )


def diagnose_native_notification_capability() -> PythonCapabilityDiagnostic:
    """Inspect native notification transport and environment without networking."""
    diagnostic = inspect_native_notification_configuration()
    transport_label = (
        "aiohttp" if diagnostic.transport == "aiohttp" else "urllib fallback"
    )
    return PythonCapabilityDiagnostic(
        capability_id="native_notifications",
        import_name=(
            "aiohttp" if diagnostic.transport == "aiohttp" else "urllib.request"
        ),
        distribution=(
            "aiohttp"
            if diagnostic.transport == "aiohttp"
            else "Python standard library"
        ),
        display_name="native notifications",
        available=True,
        version=None,
        metadata_status="ok",
        capability=(
            f"native notifications available via {transport_label}; "
            f"CTFd configuration: {diagnostic.ctfd_status}; "
            f"Discord configuration: {diagnostic.discord_status}; "
            "local validation only — reachability and credentials were not tested"
        ),
        location=None,
        location_status=(
            "aiohttp" if diagnostic.transport == "aiohttp" else "urllib-fallback"
        ),
    )


def diagnose_core(
    *,
    version_info: Sequence[int] | None = None,
    dayi_version: str | None = __version__,
    package_path: str | None = None,
    cli_operational: bool | None = None,
) -> CoreDiagnostic:
    """Inspect the dependency-free runtime invariants required for scans."""
    active_version = sys.version_info if version_info is None else version_info
    python_supported = tuple(active_version[:2]) >= MIN_SUPPORTED_PYTHON
    if package_path is None:
        try:
            package_path = str(Path(__file__).resolve().parent)
        except (OSError, RuntimeError):
            package_path = None
    if cli_operational is None:
        try:
            cli_operational = importlib.util.find_spec("dayi.cli") is not None
        except (ImportError, AttributeError, ValueError):
            cli_operational = False
    status = (
        "healthy"
        if python_supported and bool(dayi_version) and package_path is not None
        and cli_operational
        else "unhealthy"
    )
    return CoreDiagnostic(
        status=status,
        dayi_version=dayi_version or None,
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        python_supported=python_supported,
        minimum_python=".".join(str(item) for item in MIN_SUPPORTED_PYTHON),
        platform=platform.system() or os.name,
        architecture=platform.machine() or "unknown",
        python_executable=sys.executable,
        package_path=package_path,
        cli_operational=bool(cli_operational),
    )


def build_doctor_report(
    core: CoreDiagnostic,
    external_tools: Sequence[ExternalToolDiagnostic],
    python_capabilities: Sequence[PythonCapabilityDiagnostic],
) -> DoctorReport:
    """Calculate overall health without making optional tools core requirements."""
    core_usable = core.status == "healthy"
    optional_issue = any(
        not item.found or item.probe_status != "ok" for item in external_tools
    ) or any(
        not item.available or item.metadata_status != "ok"
        for item in python_capabilities
    )
    overall_status = (
        "unhealthy" if not core_usable else "degraded" if optional_issue else "healthy"
    )
    return DoctorReport(
        overall_status=overall_status,
        core_usable=core_usable,
        core=core,
        external_tools=tuple(external_tools),
        python_capabilities=tuple(python_capabilities),
    )


def run_diagnostics(
    *,
    ctfshit_path: Path | str | None = None,
    ctfshit_path_source: str | None = None,
) -> DoctorReport:
    """Collect diagnostics without network access or invoking optional exporters."""
    core = diagnose_core()
    external = tuple(
        diagnose_external_tool(definition)
        for definition in EXTERNAL_TOOL_DEFINITIONS
    )
    capabilities_list: list[PythonCapabilityDiagnostic] = []
    for definition in PYTHON_CAPABILITY_DEFINITIONS:
        if definition.capability_id == "ctfshit":
            capability = diagnose_ctfshit_capability(
                ctfshit_path,
                path_source=ctfshit_path_source,
                project_root=_DAYI_PROJECT_ROOT,
            )
        elif definition.capability_id == "native_notifications":
            capability = diagnose_native_notification_capability()
        else:
            capability = diagnose_python_capability(definition)
        capabilities_list.append(capability)
    capabilities = tuple(capabilities_list)
    return build_doctor_report(core, external, capabilities)


def doctor_exit_code(report: DoctorReport) -> int:
    """Return zero for usable core installations and one for unhealthy core."""
    return 0 if report.core_usable else 1


def render_plain(report: DoctorReport) -> str:
    """Render precise zero-dependency diagnostics with a restrained Dayı voice."""
    supported = "supported" if report.core.python_supported else "unsupported"
    lines = [
        "Dayı Doctor",
        "",
        "Core",
        f"  Status: {report.core.status}",
        f"  Dayı: {report.core.dayi_version or 'unavailable'}",
        (
            f"  Python: {report.core.python_implementation} "
            f"{report.core.python_version} — {supported}"
        ),
        f"  Minimum Python: {report.core.minimum_python}",
        f"  Platform: {report.core.platform} {report.core.architecture}",
        f"  Python executable: {report.core.python_executable}",
        f"  Package: {report.core.package_path or 'unavailable'}",
        f"  CLI entry point: {'operational' if report.core.cli_operational else 'broken'}",
        "",
        "External tools",
    ]
    for item in report.external_tools:
        state = "found" if item.found else "missing"
        version = item.version or item.probe_status
        path = item.path or "optional"
        lines.append(
            f"  {item.tool_id:<10} {state:<7} {path} — {version} "
            f"[{item.category}; {item.capability}]"
        )
    lines.extend(("", "Python capabilities"))
    for item in report.python_capabilities:
        state = "available" if item.available else "missing"
        version = item.version or item.metadata_status
        location_status = (
            item.location_status.replace("-", " ")
            if item.capability_id == "ctfshit"
            else item.location_status
        )
        location_note = (
            f"; {location_status}"
            if item.available or item.capability_id == "ctfshit"
            else ""
        )
        if item.capability_id in {"ctfshit", "native_notifications"}:
            lines.append(
                f"  {item.display_name}: {item.capability}{location_note}"
            )
            continue
        lines.append(
            f"  {item.display_name:<12} {state:<9} {version} — "
            f"{item.capability}{location_note}"
        )
    lines.extend(("", f"Overall: {report.overall_status}"))
    if report.core_usable:
        lines.append(
            "[+] Yeğenim çekirdek CLI çalışır durumda; eksikler yalnızca "
            "isteğe bağlı kabiliyetleri etkiler."
        )
    else:
        lines.append(
            "[✗] Yeğenim çekirdek kurulum sağlıklı değil; Python ve paket "
            "bilgilerini düzeltmeden taramaya güvenme."
        )
    return "\n".join(lines)


def render_json(report: DoctorReport) -> str:
    """Render deterministic diagnostics JSON without terminal decoration."""
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
