"""Worker-local OpenCV runtime configuration for image analyzers."""
from __future__ import annotations

import importlib
import os
from typing import Any


def configure_opencv_runtime(cv2_module: Any | None = None) -> Any | None:
    """Keep optional OpenCV native pools bounded inside an isolated worker.

    Reapplying these settings is safe and intentional: isolated workers have
    independent process state, and supported OpenCV setters are idempotent.
    Missing modules, optional APIs, and build-specific setter failures do not
    prevent analyzers that can otherwise continue from running.
    """
    os.environ["OPENBLAS_NUM_THREADS"] = "1"
    os.environ["OMP_NUM_THREADS"] = "1"
    os.environ["MKL_NUM_THREADS"] = "1"

    cv2 = cv2_module
    if cv2 is None:
        try:
            cv2 = importlib.import_module("cv2")
        except Exception:
            return None

    set_threads = getattr(cv2, "setNumThreads", None)
    if callable(set_threads):
        try:
            set_threads(1)
        except Exception:
            pass

    opencl = getattr(cv2, "ocl", None)
    set_opencl = getattr(opencl, "setUseOpenCL", None)
    if callable(set_opencl):
        try:
            set_opencl(False)
        except Exception:
            pass
    return cv2
