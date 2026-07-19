import contextlib
import importlib.metadata
import json
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import Mock, patch

from dayi import ctfshit_resolver
from dayi.ctfshit_resolver import resolve_writeup_exporter


_MISSING = object()


class FakeDistribution:
    def __init__(
        self,
        root: Path,
        *,
        name: str = "csl-ctfshitcli",
        editable: bool = False,
        include_files: bool = True,
    ) -> None:
        self.root = root
        self.metadata = {"Name": name}
        self.files = (
            [
                PurePosixPath("src/__init__.py"),
                PurePosixPath("src/writeup_exporter.py"),
            ]
            if include_files
            else []
        )
        self._editable = editable

    def read_text(self, filename: str) -> str | None:
        if filename == "direct_url.json" and self._editable:
            return json.dumps(
                {"url": self.root.as_uri(), "dir_info": {"editable": True}}
            )
        return None

    def locate_file(self, relative: PurePosixPath) -> Path:
        return self.root / Path(str(relative))


def _write_pyproject(root: Path, name: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "1.0"\n',
        encoding="utf-8",
    )


def _write_ctfshit_checkout(
    root: Path,
    *,
    name: str = "csl-ctfshitcli",
    exporter: str = (
        "def export_writeups(workspace_root, output_file):\n"
        "    return True\n"
    ),
) -> Path:
    _write_pyproject(root, name)
    package = root / "src"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "writeup_exporter.py").write_text(exporter, encoding="utf-8")
    return root


def _write_dayi_checkout(root: Path) -> Path:
    _write_pyproject(root, "dayi-stego-solver")
    package = root / "dayi"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    return root


def _module_pair(root: Path, *, callable_exporter: bool = True):
    package = types.ModuleType("src")
    package.__file__ = str(root / "src" / "__init__.py")
    package.__path__ = [str(root / "src")]
    exporter_module = types.ModuleType("src.writeup_exporter")
    exporter_module.__file__ = str(root / "src" / "writeup_exporter.py")
    exporter_module.export_writeups = (
        (lambda workspace_root, output_file: True)
        if callable_exporter
        else "not callable"
    )
    return package, exporter_module


@contextlib.contextmanager
def _preserve_src_modules():
    previous_src = sys.modules.get("src", _MISSING)
    previous_exporter = sys.modules.get("src.writeup_exporter", _MISSING)
    try:
        sys.modules.pop("src", None)
        sys.modules.pop("src.writeup_exporter", None)
        yield
    finally:
        if previous_src is _MISSING:
            sys.modules.pop("src", None)
        else:
            sys.modules["src"] = previous_src
        if previous_exporter is _MISSING:
            sys.modules.pop("src.writeup_exporter", None)
        else:
            sys.modules["src.writeup_exporter"] = previous_exporter


def _installed_patches(
    distribution: FakeDistribution,
    package: types.ModuleType,
    exporter_module: types.ModuleType,
    *,
    owners: list[str] | None = None,
):
    def load(name: str):
        if name != "src.writeup_exporter":
            raise AssertionError(f"unexpected import: {name}")
        sys.modules.setdefault("src", package)
        sys.modules[name] = exporter_module
        return exporter_module

    return (
        patch(
            "dayi.ctfshit_resolver.importlib_metadata.distribution",
            return_value=distribution,
        ),
        patch(
            "dayi.ctfshit_resolver.importlib_metadata.packages_distributions",
            return_value={"src": owners or ["csl-ctfshitcli"]},
        ),
        patch("dayi.ctfshit_resolver.importlib.import_module", side_effect=load),
    )


class ExplicitPathTests(unittest.TestCase):
    def test_valid_explicit_repository_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(Path(tmpdir) / "ctfshitcli")

            result = resolve_writeup_exporter(root)

        self.assertTrue(result.available)
        self.assertEqual(result.source_kind, "explicit-path")
        self.assertEqual(result.status_code, "ok")
        self.assertTrue(callable(result.exporter))

    def test_explicit_path_has_highest_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(Path(tmpdir) / "explicit")
            with patch(
                "dayi.ctfshit_resolver.importlib_metadata.distribution",
                side_effect=AssertionError("installed lookup must not run"),
            ):
                result = resolve_writeup_exporter(root)

        self.assertEqual(result.source_kind, "explicit-path")

    def test_missing_explicit_path_stops_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing"
            with patch(
                "dayi.ctfshit_resolver.importlib_metadata.distribution",
                side_effect=AssertionError("installed lookup must not run"),
            ):
                result = resolve_writeup_exporter(missing)

        self.assertFalse(result.available)
        self.assertEqual(result.source_kind, "explicit-path")
        self.assertEqual(result.status_code, "invalid-path")

    def test_explicit_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "writeup_exporter.py"
            target.write_text("", encoding="utf-8")

            result = resolve_writeup_exporter(target)

        self.assertEqual(result.status_code, "invalid-path")

    def test_missing_pyproject_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "candidate"
            (root / "src").mkdir(parents=True)
            (root / "src" / "__init__.py").write_text("", encoding="utf-8")
            (root / "src" / "writeup_exporter.py").write_text("", encoding="utf-8")

            result = resolve_writeup_exporter(root)

        self.assertEqual(result.status_code, "invalid-path")

    def test_wrong_project_name_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(
                Path(tmpdir) / "candidate",
                name="unrelated-project",
            )

            result = resolve_writeup_exporter(root)

        self.assertEqual(result.status_code, "distribution-mismatch")

    def test_missing_package_init_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(Path(tmpdir) / "candidate")
            (root / "src" / "__init__.py").unlink()

            result = resolve_writeup_exporter(root)

        self.assertEqual(result.status_code, "invalid-path")

    def test_missing_exporter_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(Path(tmpdir) / "candidate")
            (root / "src" / "writeup_exporter.py").unlink()

            result = resolve_writeup_exporter(root)

        self.assertEqual(result.status_code, "exporter-missing")

    def test_symlinked_exporter_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(Path(tmpdir) / "candidate")
            exporter = root / "src" / "writeup_exporter.py"
            exporter.unlink()
            target = root / "real_exporter.py"
            target.write_text("def export_writeups(*args): return True\n", encoding="utf-8")
            try:
                exporter.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            result = resolve_writeup_exporter(root)

        self.assertEqual(result.status_code, "invalid-path")

    def test_exporter_resolving_outside_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            root = _write_ctfshit_checkout(base / "candidate")
            exporter = root / "src" / "writeup_exporter.py"
            exporter.unlink()
            outside = base / "outside.py"
            outside.write_text("def export_writeups(*args): return True\n", encoding="utf-8")
            try:
                exporter.symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            result = resolve_writeup_exporter(root)

        self.assertEqual(result.status_code, "invalid-path")

    def test_non_callable_exporter_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(
                Path(tmpdir) / "candidate",
                exporter="export_writeups = 'nope'\n",
            )

            result = resolve_writeup_exporter(root)

        self.assertEqual(result.status_code, "exporter-missing")

    def test_import_time_exception_is_contained(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(
                Path(tmpdir) / "candidate",
                exporter="raise RuntimeError('broken importer')\n",
            )

            result = resolve_writeup_exporter(root)

        self.assertEqual(result.status_code, "import-failed")

    def test_system_exit_from_local_module_is_not_masked(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(
                Path(tmpdir) / "candidate",
                exporter="raise SystemExit(7)\n",
            )

            with self.assertRaises(SystemExit) as raised:
                resolve_writeup_exporter(root)

        self.assertEqual(raised.exception.code, 7)


class LocalLoadingIsolationTests(unittest.TestCase):
    def test_existing_unrelated_src_module_is_unchanged(self) -> None:
        unrelated = types.ModuleType("src")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(Path(tmpdir) / "candidate")
            previous = sys.modules.get("src", _MISSING)
            sys.modules["src"] = unrelated
            try:
                result = resolve_writeup_exporter(root)
                self.assertIs(sys.modules["src"], unrelated)
            finally:
                if previous is _MISSING:
                    sys.modules.pop("src", None)
                else:
                    sys.modules["src"] = previous

        self.assertTrue(result.available)

    def test_sys_path_is_unchanged_after_success(self) -> None:
        before = list(sys.path)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(Path(tmpdir) / "candidate")
            resolve_writeup_exporter(root)
        self.assertEqual(sys.path, before)

    def test_sys_path_is_unchanged_after_failure(self) -> None:
        before = list(sys.path)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(
                Path(tmpdir) / "candidate",
                exporter="raise ValueError('boom')\n",
            )
            resolve_writeup_exporter(root)
        self.assertEqual(sys.path, before)

    def test_private_module_does_not_leak_after_success(self) -> None:
        before = {
            name for name in sys.modules
            if name.startswith(ctfshit_resolver._PRIVATE_MODULE_PREFIX)
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(Path(tmpdir) / "candidate")
            resolve_writeup_exporter(root)
        after = {
            name for name in sys.modules
            if name.startswith(ctfshit_resolver._PRIVATE_MODULE_PREFIX)
        }
        self.assertEqual(after, before)

    def test_private_module_does_not_leak_after_failure(self) -> None:
        before = set(sys.modules)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(
                Path(tmpdir) / "candidate",
                exporter="raise LookupError('boom')\n",
            )
            resolve_writeup_exporter(root)
        leaked = {
            name for name in set(sys.modules) - before
            if name.startswith(ctfshit_resolver._PRIVATE_MODULE_PREFIX)
        }
        self.assertEqual(leaked, set())


class InstalledDistributionTests(unittest.TestCase):
    def test_correct_distribution_and_exporter_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, _preserve_src_modules():
            root = _write_ctfshit_checkout(Path(tmpdir) / "installed")
            distribution = FakeDistribution(root)
            package, exporter = _module_pair(root)
            patches = _installed_patches(
                distribution,
                package,
                exporter,
                owners=["unrelated", "csl-ctfshitcli"],
            )
            with patches[0], patches[1], patches[2]:
                result = resolve_writeup_exporter(project_root=Path("missing"))

        self.assertTrue(result.available)
        self.assertEqual(result.source_kind, "installed")
        self.assertEqual(result.status_code, "ok")

    def test_distribution_absent_proceeds_to_automatic_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            dayi_root = _write_dayi_checkout(base / "DayiStegoSolver")
            _write_ctfshit_checkout(base / "ctfshitcli")
            with patch(
                "dayi.ctfshit_resolver.importlib_metadata.distribution",
                side_effect=importlib.metadata.PackageNotFoundError,
            ):
                result = resolve_writeup_exporter(project_root=dayi_root)

        self.assertEqual(result.source_kind, "sibling")
        self.assertTrue(result.available)

    def test_unrelated_loaded_src_package_is_rejected_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, _preserve_src_modules():
            root = _write_ctfshit_checkout(Path(tmpdir) / "installed")
            distribution = FakeDistribution(root)
            unrelated = types.ModuleType("src")
            unrelated.__file__ = str(Path(tmpdir) / "other" / "src" / "__init__.py")
            unrelated.__path__ = [str(Path(tmpdir) / "other" / "src")]
            sys.modules["src"] = unrelated
            importer = Mock(side_effect=AssertionError("must not import"))
            with patch(
                "dayi.ctfshit_resolver.importlib_metadata.distribution",
                return_value=distribution,
            ), patch(
                "dayi.ctfshit_resolver.importlib_metadata.packages_distributions",
                return_value={"src": ["csl-ctfshitcli"]},
            ), patch(
                "dayi.ctfshit_resolver.importlib.import_module", importer
            ):
                result = resolve_writeup_exporter(project_root=Path("missing"))

            self.assertIs(sys.modules["src"], unrelated)
        self.assertEqual(result.status_code, "distribution-mismatch")
        importer.assert_not_called()

    def test_src_claimed_only_by_another_distribution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, _preserve_src_modules():
            root = _write_ctfshit_checkout(Path(tmpdir) / "installed")
            distribution = FakeDistribution(root)
            with patch(
                "dayi.ctfshit_resolver.importlib_metadata.distribution",
                return_value=distribution,
            ), patch(
                "dayi.ctfshit_resolver.importlib_metadata.packages_distributions",
                return_value={"src": ["other-project"]},
            ):
                result = resolve_writeup_exporter(project_root=Path("missing"))

        self.assertEqual(result.status_code, "distribution-mismatch")

    def test_installed_non_callable_exporter_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, _preserve_src_modules():
            root = _write_ctfshit_checkout(Path(tmpdir) / "installed")
            distribution = FakeDistribution(root)
            package, exporter = _module_pair(root, callable_exporter=False)
            patches = _installed_patches(distribution, package, exporter)
            with patches[0], patches[1], patches[2]:
                result = resolve_writeup_exporter(project_root=Path("missing"))

        self.assertEqual(result.status_code, "exporter-missing")

    def test_installed_import_exception_is_contained(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, _preserve_src_modules():
            root = _write_ctfshit_checkout(Path(tmpdir) / "installed")
            distribution = FakeDistribution(root)
            with patch(
                "dayi.ctfshit_resolver.importlib_metadata.distribution",
                return_value=distribution,
            ), patch(
                "dayi.ctfshit_resolver.importlib_metadata.packages_distributions",
                return_value={"src": ["csl-ctfshitcli"]},
            ), patch(
                "dayi.ctfshit_resolver.importlib.import_module",
                side_effect=RuntimeError("broken import"),
            ):
                result = resolve_writeup_exporter(project_root=Path("missing"))

            self.assertNotIn("src", sys.modules)

        self.assertEqual(result.status_code, "import-failed")

    def test_editable_install_metadata_shape_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, _preserve_src_modules():
            root = _write_ctfshit_checkout(Path(tmpdir) / "editable")
            distribution = FakeDistribution(
                root,
                editable=True,
                include_files=False,
            )
            package, exporter = _module_pair(root)
            package.__file__ = None
            package.__path__ = [str(Path(tmpdir) / "site-packages" / "src")]
            patches = _installed_patches(distribution, package, exporter)
            with patches[0], patches[1], patches[2]:
                result = resolve_writeup_exporter(project_root=Path("missing"))

        self.assertTrue(result.available)
        self.assertEqual(result.resolved_root, root.resolve())

    def test_installed_distribution_missing_exporter_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, _preserve_src_modules():
            root = _write_ctfshit_checkout(Path(tmpdir) / "installed")
            distribution = FakeDistribution(root, include_files=False)
            with patch(
                "dayi.ctfshit_resolver.importlib_metadata.distribution",
                return_value=distribution,
            ), patch(
                "dayi.ctfshit_resolver.importlib_metadata.packages_distributions",
                return_value={"src": ["csl-ctfshitcli"]},
            ):
                result = resolve_writeup_exporter(project_root=Path("missing"))

        self.assertEqual(result.status_code, "exporter-missing")


class AutomaticDiscoveryTests(unittest.TestCase):
    def _resolve_without_install(self, project_root: Path):
        with patch(
            "dayi.ctfshit_resolver.importlib_metadata.distribution",
            side_effect=importlib.metadata.PackageNotFoundError,
        ):
            return resolve_writeup_exporter(project_root=project_root)

    def test_exact_sibling_ctfshitcli_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            dayi_root = _write_dayi_checkout(base / "DayiStegoSolver")
            checkout = _write_ctfshit_checkout(base / "ctfshitcli")
            result = self._resolve_without_install(dayi_root)

        self.assertEqual(result.source_kind, "sibling")
        self.assertEqual(result.resolved_root, checkout.resolve())

    def test_legacy_sibling_resolves_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            dayi_root = _write_dayi_checkout(base / "DayiStegoSolver")
            checkout = _write_ctfshit_checkout(base / "ctfshit")
            result = self._resolve_without_install(dayi_root)

        self.assertEqual(result.source_kind, "sibling")
        self.assertEqual(result.resolved_root, checkout.resolve())

    def test_child_ctfshitcli_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dayi_root = _write_dayi_checkout(Path(tmpdir) / "DayiStegoSolver")
            checkout = _write_ctfshit_checkout(dayi_root / "ctfshitcli")
            result = self._resolve_without_install(dayi_root)

        self.assertEqual(result.source_kind, "child")
        self.assertEqual(result.resolved_root, checkout.resolve())

    def test_sibling_precedes_child(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            dayi_root = _write_dayi_checkout(base / "DayiStegoSolver")
            sibling = _write_ctfshit_checkout(base / "ctfshitcli")
            _write_ctfshit_checkout(dayi_root / "ctfshitcli")
            result = self._resolve_without_install(dayi_root)

        self.assertEqual(result.resolved_root, sibling.resolve())

    def test_ctfshitcli_name_precedes_legacy_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            dayi_root = _write_dayi_checkout(base / "DayiStegoSolver")
            preferred = _write_ctfshit_checkout(base / "ctfshitcli")
            _write_ctfshit_checkout(base / "ctfshit")
            result = self._resolve_without_install(dayi_root)

        self.assertEqual(result.resolved_root, preferred.resolve())

    def test_no_recursive_lookup_occurs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dayi_root = _write_dayi_checkout(Path(tmpdir) / "DayiStegoSolver")
            _write_ctfshit_checkout(dayi_root / "nested" / "ctfshitcli")
            result = self._resolve_without_install(dayi_root)

        self.assertEqual(result.source_kind, "unavailable")
        self.assertEqual(result.status_code, "not-found")

    def test_invalid_dayi_root_disables_automatic_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            invalid_root = base / "not-dayi"
            invalid_root.mkdir()
            _write_ctfshit_checkout(base / "ctfshitcli")
            result = self._resolve_without_install(invalid_root)

        self.assertEqual(result.source_kind, "unavailable")

    def test_invalid_automatic_candidate_does_not_execute_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            dayi_root = _write_dayi_checkout(base / "DayiStegoSolver")
            candidate = _write_ctfshit_checkout(
                base / "ctfshitcli",
                name="unrelated-project",
            )
            marker = candidate / "executed"
            (candidate / "src" / "writeup_exporter.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
                encoding="utf-8",
            )
            result = self._resolve_without_install(dayi_root)

            self.assertFalse(marker.exists())

        self.assertEqual(result.source_kind, "unavailable")

    def test_valid_installed_source_precedes_local_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, _preserve_src_modules():
            base = Path(tmpdir)
            dayi_root = _write_dayi_checkout(base / "DayiStegoSolver")
            _write_ctfshit_checkout(base / "ctfshitcli")
            installed_root = _write_ctfshit_checkout(base / "installed")
            distribution = FakeDistribution(installed_root)
            package, exporter = _module_pair(installed_root)
            patches = _installed_patches(distribution, package, exporter)
            with patches[0], patches[1], patches[2]:
                result = resolve_writeup_exporter(project_root=dayi_root)

        self.assertEqual(result.source_kind, "installed")


class ResultContractAndBoundaryTests(unittest.TestCase):
    def test_status_and_source_values_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing"
            explicit = resolve_writeup_exporter(missing)
            with patch(
                "dayi.ctfshit_resolver.importlib_metadata.distribution",
                side_effect=importlib.metadata.PackageNotFoundError,
            ):
                unavailable = resolve_writeup_exporter(
                    project_root=Path(tmpdir) / "invalid-dayi"
                )

        self.assertEqual(
            (explicit.available, explicit.source_kind, explicit.status_code),
            (False, "explicit-path", "invalid-path"),
        )
        self.assertEqual(
            (unavailable.available, unavailable.source_kind, unavailable.status_code),
            (False, "unavailable", "not-found"),
        )

    def test_safe_detail_does_not_disclose_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "sensitive" / "missing"
            result = resolve_writeup_exporter(missing)

        self.assertNotIn(str(missing), result.safe_detail)
        self.assertEqual(
            result.safe_detail,
            "explicit path is not a valid csl-ctfshitcli checkout",
        )

    def test_resolution_uses_no_network_subprocess_setup_or_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = _write_ctfshit_checkout(Path(tmpdir) / "candidate")
            setup_marker = root / "setup-ran"
            (root / "setup.py").write_text(
                f"from pathlib import Path\nPath({str(setup_marker)!r}).touch()\n",
                encoding="utf-8",
            )
            with patch.object(
                socket, "create_connection", side_effect=AssertionError("network")
            ), patch.object(
                subprocess, "run", side_effect=AssertionError("subprocess")
            ), patch.object(
                subprocess, "Popen", side_effect=AssertionError("subprocess")
            ):
                result = resolve_writeup_exporter(root)

            self.assertFalse(setup_marker.exists())

        self.assertTrue(result.available)


if __name__ == "__main__":
    unittest.main()
