import contextlib
import io
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import dayi
from dayi import cli


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
REPOSITORY_URL = "https://github.com/MacallanTheRoot/DayiStegoSolver"
VERSION = "4.5.0"


def _load_project_metadata() -> dict:
    """Load the project table with a dependency-free Python 3.10 fallback."""
    raw = PYPROJECT.read_bytes()
    try:
        import tomllib
    except ModuleNotFoundError:
        text = raw.decode("utf-8")

        def scalar(name: str) -> str:
            match = re.search(
                rf"(?m)^{re.escape(name)}\s*=\s*\"([^\"]+)\"\s*$",
                text,
            )
            if match is None:
                raise AssertionError(f"missing project field: {name}")
            return match.group(1)

        author_match = re.search(
            r"(?s)authors\s*=\s*\[\s*\{\s*name\s*=\s*\"([^\"]+)\"",
            text,
        )
        classifiers_match = re.search(
            r"(?s)classifiers\s*=\s*\[(.*?)\]",
            text,
        )
        urls_match = re.search(
            r"(?s)\[project\.urls\](.*?)(?:\n\[|\Z)",
            text,
        )
        if author_match is None or classifiers_match is None or urls_match is None:
            raise AssertionError("incomplete project metadata")
        classifiers = re.findall(r'\"([^\"]+)\"', classifiers_match.group(1))
        urls = dict(
            re.findall(
                r'(?m)^\s*\"?([^\"=]+?)\"?\s*=\s*\"([^\"]+)\"\s*$',
                urls_match.group(1),
            )
        )
        return {
            "name": scalar("name"),
            "version": scalar("version"),
            "requires-python": scalar("requires-python"),
            "authors": [{"name": author_match.group(1)}],
            "classifiers": classifiers,
            "urls": urls,
            "scripts": {"dayi": "dayi.cli:main"},
        }
    return tomllib.loads(raw.decode("utf-8"))["project"]


class PackageMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project = _load_project_metadata()

    def test_project_identity_and_urls(self) -> None:
        self.assertEqual(self.project["name"], "dayi-stego-solver")
        self.assertEqual(self.project["scripts"]["dayi"], "dayi.cli:main")
        self.assertEqual(self.project["urls"]["Repository"], REPOSITORY_URL)
        self.assertEqual(
            self.project["urls"]["Bug Tracker"],
            f"{REPOSITORY_URL}/issues",
        )
        packaging_text = PYPROJECT.read_text(encoding="utf-8")
        self.assertNotIn("your" + "-org", packaging_text)

    def test_author_beta_classifier_and_python_requirement(self) -> None:
        self.assertEqual(self.project["authors"], [{"name": "MacallanTheRoot"}])
        self.assertEqual(self.project["requires-python"], ">=3.10,<3.14")
        self.assertEqual(dayi.MIN_SUPPORTED_PYTHON, (3, 10))
        self.assertIn(
            "Development Status :: 4 - Beta",
            self.project["classifiers"],
        )
        self.assertNotIn(
            "Development Status :: 5 - Production/Stable",
            self.project["classifiers"],
        )
        for minor in range(10, 14):
            self.assertIn(
                f"Programming Language :: Python :: 3.{minor}",
                self.project["classifiers"],
            )

    def test_runtime_and_package_metadata_versions_match(self) -> None:
        self.assertEqual(self.project["version"], VERSION)
        self.assertEqual(dayi.__version__, self.project["version"])
        self.assertEqual(dayi.__author__, "MacallanTheRoot")

    def test_release_documents_follow_authoritative_identity(self) -> None:
        release_notes = ROOT / "RELEASE_NOTES_v4.5.0.md"
        documents = {
            "README.md": (ROOT / "README.md").read_text(encoding="utf-8"),
            "CHANGELOG.md": (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
            "RELEASE_CHECKLIST.md": (ROOT / "RELEASE_CHECKLIST.md").read_text(
                encoding="utf-8"
            ),
            release_notes.name: release_notes.read_text(encoding="utf-8"),
        }

        self.assertTrue(release_notes.is_file())
        self.assertIn("# Dayı Stego Solver 4.5.0", documents[release_notes.name])
        self.assertIn(f"## [{VERSION}] - 2026-07-20", documents["CHANGELOG.md"])
        self.assertIn("v4.0.0", documents["RELEASE_CHECKLIST.md"])
        self.assertIn(f"Version-{VERSION}", documents["README.md"])
        for text in documents.values():
            self.assertIn(REPOSITORY_URL, text)
            self.assertNotIn("MacallanTheRoot/" + "testrepo", text)

    def test_version_mode_needs_no_target_flag_or_runtime_initialization(self) -> None:
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["dayi", "--version"]),
            patch("dayi.cli.asyncio.run") as asyncio_run,
            patch("dayi.cli.build_integration") as build_integration,
            patch("dayi.tools._plugin.discover_plugins") as discover_plugins,
            contextlib.redirect_stdout(output),
        ):
            with self.assertRaises(SystemExit) as raised:
                cli.main()

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue(), f"dayi {VERSION}\n")
        asyncio_run.assert_not_called()
        build_integration.assert_not_called()
        discover_plugins.assert_not_called()

    def test_pyproject_runtime_and_module_cli_versions_match(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "dayi", "--version"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(dayi.__version__, self.project["version"])
        self.assertEqual(completed.stdout, f"dayi {self.project['version']}\n")
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
