"""
dayi/__init__.py
~~~~~~~~~~~~~~~~
Dayı Stego Solver — CTF Steganography Brute-force & Analysis Tool.

The top-level package exposes version metadata and the public CLI entry point.
All heavy imports (runner, tools, integrations) are deferred to avoid
slowing down simple `import dayi` calls.
"""

__version__ = "4.5.0"
MIN_SUPPORTED_PYTHON = (3, 10)
__author__ = "MacallanTheRoot"
__license__ = "MIT"
__description__ = (
    "CTF Steganography Brute-force & Analysis CLI — "
    "'Hallederiz Yeğenim' Edition"
)
