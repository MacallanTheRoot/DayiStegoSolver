"""Bounded, local-only document steganography analysis."""
from dayi.document.detect import DocumentType, detect_document_type
from dayi.document.model import DocumentAnalysis, DocumentFinding
from dayi.document.openxml import analyze_document

__all__ = (
    "DocumentAnalysis",
    "DocumentFinding",
    "DocumentType",
    "analyze_document",
    "detect_document_type",
)
