import asyncio
import binascii
import multiprocessing
import re
import struct
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from unittest.mock import AsyncMock, patch

from dayi.image_analysis import ImageSource, MAX_DECODED_PIXELS
from dayi.tools import ocr_scanner, qr_scanner
from dayi.tools.ocr_scanner import OCRDependencies
from dayi.tools.qr_scanner import QRBackend, _DecodedSymbol, run_qr_scanner


PATTERN = re.compile(r"SiberVatan\{.*?\}")


def _slow_native_qr_worker(_path: str, _backend: str, _verbose: bool):
    time.sleep(5.0)
    return []


def _png(path: Path) -> ImageSource:
    def chunk(name: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + name
            + data
            + struct.pack(">I", binascii.crc32(name + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
        + chunk(b"IEND", b"")
    )
    return ImageSource(
        path,
        f"target:{path.name}",
        "PNG",
        path.stat().st_size,
        binascii.hexlify(path.name.encode()).decode().ljust(64, "0")[:64],
    )


class _TrackedImage:
    alive = 0
    peak = 0

    def __init__(
        self,
        size: tuple[int, int],
        mode: str = "RGB",
        *,
        transformed: bool = False,
    ) -> None:
        self.size = size
        self.mode = mode
        self.transformed = transformed
        self.closed = False
        if transformed:
            type(self).alive += 1
            type(self).peak = max(type(self).peak, type(self).alive)

    @classmethod
    def reset(cls) -> None:
        cls.alive = 0
        cls.peak = 0

    def _new(
        self,
        *,
        size: tuple[int, int] | None = None,
        mode: str | None = None,
    ) -> "_TrackedImage":
        return _TrackedImage(size or self.size, mode or self.mode, transformed=True)

    def copy(self):
        return self._new()

    def convert(self, mode: str):
        return self._new(mode=mode)

    def point(self, _function):
        return self._new(mode="L")

    def filter(self, _filter):
        return self._new(mode="L")

    def resize(self, size, _filter):
        return self._new(size=size)

    def rotate(self, angle: int, *, expand: bool):
        size = self.size[::-1] if expand and angle in {90, 270} else self.size
        return self._new(size=size)

    def getchannel(self, _name: str):
        return self._new(mode="L")

    def getextrema(self):
        return ((0, 255), (8, 240), (16, 220))

    def getbands(self):
        return tuple(self.mode) if self.mode in {"RGB", "RGBA"} else (self.mode,)

    def close(self) -> None:
        if self.transformed and not self.closed:
            type(self).alive -= 1
        self.closed = True


class _ImageOps:
    @staticmethod
    def grayscale(image):
        return image._new(mode="L")

    @staticmethod
    def autocontrast(image):
        return image._new(mode="L")

    @staticmethod
    def invert(image):
        return image._new(mode="L")


class _Contrast:
    def __init__(self, image) -> None:
        self.image = image

    def enhance(self, _factor: float):
        return self.image._new(mode="L")


class _Enhance:
    Contrast = _Contrast


class _Filter:
    SHARPEN = object()


class _Resampling:
    LANCZOS = object()


class _ImageModule:
    Resampling = _Resampling

    @staticmethod
    def new(_mode: str, size: tuple[int, int], _color: str):
        return _TrackedImage(size, "RGBA", transformed=True)


OCR_DEPS = OCRDependencies(
    image_module=_ImageModule,
    pytesseract=object(),
    image_ops=_ImageOps,
    image_enhance=_Enhance,
    image_filter=_Filter,
)


class NativeQRIsolationTests(unittest.TestCase):
    def test_slow_opencv_decode_is_killed_at_remaining_deadline(self) -> None:
        self._assert_worker_timeout("opencv")

    def test_slow_pyzbar_decode_is_killed_at_remaining_deadline(self) -> None:
        self._assert_worker_timeout("pyzbar")

    def test_native_decode_cancellation_leaves_no_worker(self) -> None:
        runner = getattr(qr_scanner, "_decode_native_isolated", None)
        self.assertIsNotNone(runner)
        before = {child.pid for child in multiprocessing.active_children()}

        async def cancel_decode() -> None:
            task = asyncio.create_task(runner(
                Path("unused.png"),
                "opencv",
                False,
                timeout=5.0,
                worker=_slow_native_qr_worker,
            ))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(cancel_decode())
        self.assertEqual(
            {child.pid for child in multiprocessing.active_children()}, before
        )

    def test_completed_qr_result_survives_later_native_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = _png(root / "first.png")
            second = _png(root / "second.png")
            decoder = AsyncMock(side_effect=[
                [("original", _DecodedSymbol(b"SiberVatan{earlier_qr}"))],
                asyncio.TimeoutError(),
            ])
            with (
                patch(
                    "dayi.tools.qr_scanner.discover_images",
                    return_value=(first, second),
                ),
                patch(
                    "dayi.tools.qr_scanner._decode_native_isolated",
                    decoder,
                    create=True,
                ),
            ):
                result = asyncio.run(run_qr_scanner(
                    first.path,
                    root / "workspace",
                    PATTERN,
                    timeout=2.0,
                    backend=QRBackend("opencv", object()),
                ))
        self.assertIn("SiberVatan{earlier_qr}", result.flags_found)
        self.assertTrue(result.timed_out)
        self.assertEqual(decoder.await_count, 2)

    def _assert_worker_timeout(self, backend: str) -> None:
        runner = getattr(qr_scanner, "_decode_native_isolated", None)
        self.assertIsNotNone(runner)
        before = {child.pid for child in multiprocessing.active_children()}
        started = time.monotonic()
        with self.assertRaises(asyncio.TimeoutError):
            asyncio.run(runner(
                Path("unused.png"),
                backend,
                False,
                timeout=0.05,
                worker=_slow_native_qr_worker,
            ))
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(
            {child.pid for child in multiprocessing.active_children()}, before
        )


class LazyOCRVariantTests(unittest.TestCase):
    def setUp(self) -> None:
        _TrackedImage.reset()

    def test_ocr_variants_are_lazy_iterators(self) -> None:
        image = _TrackedImage((100, 80))
        variants = ocr_scanner._build_variants(image, OCR_DEPS, True)
        self.assertIs(iter(variants), variants)
        self.assertEqual(_TrackedImage.alive, 0)
        name, returned = next(variants)
        self.assertEqual(name, "original")
        self.assertIs(returned, image)
        variants.close()

    def test_near_limit_image_obeys_aggregate_pixel_and_byte_budgets(self) -> None:
        budget_type = getattr(ocr_scanner, "_OCRVariantBudget", None)
        self.assertIsNotNone(budget_type)
        image = _TrackedImage((7000, 7000))
        budget = budget_type()
        variants = ocr_scanner._build_variants(
            image, OCR_DEPS, True, budget=budget
        )
        names = [name for name, _variant in variants]
        self.assertLess(len(names), ocr_scanner.MAX_OCR_VARIANTS_PER_IMAGE)
        self.assertLessEqual(7000 * 7000, MAX_DECODED_PIXELS)
        self.assertLessEqual(budget.generated_pixels, budget.max_generated_pixels)
        self.assertLessEqual(budget.estimated_bytes, budget.max_estimated_bytes)
        self.assertEqual(_TrackedImage.alive, 0)

    def test_only_current_transformed_variant_remains_live(self) -> None:
        image = _TrackedImage((100, 80))
        variants = ocr_scanner._build_variants(image, OCR_DEPS, True)
        self.assertEqual(next(variants)[0], "original")
        first_name, first = next(variants)
        self.assertEqual(first_name, "grayscale")
        self.assertEqual(_TrackedImage.alive, 1)
        second_name, _second = next(variants)
        self.assertEqual(second_name, "autocontrast")
        self.assertTrue(first.closed)
        self.assertEqual(_TrackedImage.alive, 1)
        variants.close()
        self.assertEqual(_TrackedImage.alive, 0)

    def test_existing_affordable_variant_order_remains_supported(self) -> None:
        image = _TrackedImage((100, 80))
        names = [
            name for name, _variant in
            ocr_scanner._build_variants(image, OCR_DEPS, True)
        ]
        self.assertEqual(names[:5], [
            "original", "grayscale", "autocontrast", "inverted", "threshold",
        ])
        self.assertIn("rot90", names)
        self.assertEqual(_TrackedImage.alive, 0)


if __name__ == "__main__":
    unittest.main()
