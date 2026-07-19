import io
import tarfile
import unittest
import warnings
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.validate_distribution import (
    SDIST_REQUIRED,
    WHEEL_REQUIRED,
    DistributionValidationError,
    validate_dist_directory,
    validate_sdist,
    validate_wheel,
)


DIST_INFO = "dayi_stego_solver-4.1.0.dist-info"
METADATA = """\
Metadata-Version: 2.4
Name: dayi-stego-solver
Version: 4.1.0
Author: MacallanTheRoot
License-Expression: MIT
Requires-Python: >=3.10
Classifier: Development Status :: 4 - Beta
Project-URL: Repository, https://github.com/MacallanTheRoot/DayiStegoSolver
Project-URL: Bug Tracker, https://github.com/MacallanTheRoot/DayiStegoSolver/issues

Dayı test metadata.
"""
ENTRY_POINTS = """\
[console_scripts]
dayi = dayi.cli:main
"""


def _write_wheel(
    path: Path,
    *,
    omitted: str | None = None,
    extra: str | None = None,
    metadata: str = METADATA,
) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        for name in sorted(WHEEL_REQUIRED):
            if name != omitted:
                archive.writestr(name, "# fixture\n")
        archive.writestr(f"{DIST_INFO}/METADATA", metadata)
        archive.writestr(f"{DIST_INFO}/entry_points.txt", ENTRY_POINTS)
        if extra is not None:
            archive.writestr(extra, "fixture\n")


def _add_tar_bytes(archive: tarfile.TarFile, name: str, data: bytes = b"fixture\n") -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


def _write_sdist(path: Path, *, extra: str | None = None) -> None:
    root = "dayi_stego_solver-4.1.0"
    with tarfile.open(path, mode="w:gz") as archive:
        for name in sorted(SDIST_REQUIRED):
            _add_tar_bytes(archive, f"{root}/{name}")
        if extra is not None:
            _add_tar_bytes(archive, extra)


class DistributionContentsTests(unittest.TestCase):
    def test_valid_wheel_content_and_metadata(self) -> None:
        with TemporaryDirectory() as temp_dir:
            wheel = Path(temp_dir) / "dayi_stego_solver-4.1.0-py3-none-any.whl"
            _write_wheel(wheel)

            members = validate_wheel(wheel)

        self.assertTrue(WHEEL_REQUIRED.issubset(set(members)))

    def test_missing_required_wheel_file_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            wheel = Path(temp_dir) / "missing.whl"
            _write_wheel(wheel, omitted="dayi/doctor.py")

            with self.assertRaisesRegex(
                DistributionValidationError, "dayi/doctor.py"
            ):
                validate_wheel(wheel)

    def test_forbidden_wheel_path_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            wheel = Path(temp_dir) / "forbidden.whl"
            _write_wheel(wheel, extra="tests/test_leaked.py")

            with self.assertRaisesRegex(
                DistributionValidationError, "forbidden wheel member"
            ):
                validate_wheel(wheel)

    def test_valid_sdist_content(self) -> None:
        with TemporaryDirectory() as temp_dir:
            sdist = Path(temp_dir) / "dayi_stego_solver-4.1.0.tar.gz"
            _write_sdist(sdist)

            members = validate_sdist(sdist)

        self.assertTrue(SDIST_REQUIRED.issubset(set(members)))

    def test_path_traversal_archive_entry_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            sdist = Path(temp_dir) / "traversal.tar.gz"
            _write_sdist(
                sdist,
                extra="dayi_stego_solver-4.1.0/../outside.txt",
            )

            with self.assertRaisesRegex(
                DistributionValidationError, "unsafe archive member"
            ):
                validate_sdist(sdist)

    def test_duplicate_wheel_member_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            wheel = Path(temp_dir) / "duplicate.whl"
            _write_wheel(wheel)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(wheel, mode="a") as archive:
                    archive.writestr("dayi/cli.py", "# duplicate\n")

            with self.assertRaisesRegex(
                DistributionValidationError, "duplicate member names"
            ):
                validate_wheel(wheel)

    def test_malformed_metadata_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            wheel = Path(temp_dir) / "metadata.whl"
            _write_wheel(wheel, metadata=METADATA.replace("Version: 4.1.0\n", ""))

            with self.assertRaisesRegex(
                DistributionValidationError, "metadata 'Version'"
            ):
                validate_wheel(wheel)

    def test_unrelated_stale_distribution_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            dist_dir = Path(temp_dir)
            wheel = dist_dir / "dayi_stego_solver-4.1.0-py3-none-any.whl"
            sdist = dist_dir / "dayi_stego_solver-4.1.0.tar.gz"
            _write_wheel(wheel)
            _write_sdist(sdist)
            _write_wheel(dist_dir / "stale-2.0.0-py3-none-any.whl")

            with self.assertRaisesRegex(
                DistributionValidationError, "exactly one"
            ):
                validate_dist_directory(dist_dir)


if __name__ == "__main__":
    unittest.main()
