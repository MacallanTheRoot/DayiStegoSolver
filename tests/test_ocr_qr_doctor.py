import unittest
from types import SimpleNamespace
from unittest.mock import patch

from dayi.doctor import diagnose_ocr_capability, diagnose_qr_capability
from dayi.tools.qr_scanner import QRBackend


class ImageCapabilityDoctorTests(unittest.TestCase):
    def test_qr_reports_selected_passive_backend_without_scanning(self) -> None:
        with patch(
            "dayi.tools.qr_scanner.select_qr_backend",
            return_value=QRBackend("opencv", object()),
        ):
            result = diagnose_qr_capability()
        self.assertTrue(result.available)
        self.assertEqual(result.location_status, "opencv")
        self.assertIn("never opened or executed", result.capability)

    def test_qr_missing_backends_are_optional_degradation(self) -> None:
        with patch("dayi.tools.qr_scanner.select_qr_backend", return_value=None):
            result = diagnose_qr_capability()
        self.assertFalse(result.available)
        self.assertEqual(result.metadata_status, "backend-unavailable")

    def test_ocr_reports_installed_and_missing_language_safely(self) -> None:
        def process():
            return SimpleNamespace(
                stdout=__import__("io").BytesIO(b"List of available languages (2):\neng\ntur\n"),
                stderr=__import__("io").BytesIO(),
                wait=lambda timeout: 0,
                kill=lambda: None,
            )
        with (
            patch("dayi.doctor.importlib.util.find_spec", return_value=object()),
            patch("dayi.doctor.shutil.which", return_value="/usr/bin/tesseract"),
            patch("dayi.doctor.subprocess.Popen", side_effect=lambda *_a, **_kw: process()),
        ):
            available = diagnose_ocr_capability("eng+tur")
            missing = diagnose_ocr_capability("deu")
        self.assertTrue(available.available)
        self.assertIn("eng, tur", available.capability)
        self.assertFalse(missing.available)
        self.assertEqual(missing.metadata_status, "language-missing")
        self.assertNotIn("/usr/bin", missing.capability)

    def test_ocr_diagnostic_never_opens_an_image(self) -> None:
        with (
            patch("dayi.doctor.importlib.util.find_spec", return_value=None),
            patch("dayi.doctor.shutil.which", return_value=None),
            patch("pathlib.Path.open", side_effect=AssertionError("must not open target")),
        ):
            result = diagnose_ocr_capability()
        self.assertFalse(result.available)


if __name__ == "__main__":
    unittest.main()
