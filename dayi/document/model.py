"""Immutable document-analysis results and terminal-safe previews."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dayi.text_stego import escape_unsafe_text

DocumentConfidence = Literal["confirmed", "high", "medium", "low"]


@dataclass(frozen=True)
class DocumentFinding:
    """One bounded finding with its precise package provenance."""

    category: str
    mechanism: str
    source_member: str
    value: str
    confidence: DocumentConfidence
    evidence: tuple[str, ...] = ()
    decoder_chain: tuple[str, ...] = ()
    flags_found: tuple[str, ...] = ()
    related_artifact: str | None = None
    preview: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return only JSON-safe bounded primitives."""
        return {
            "category": self.category,
            "mechanism": self.mechanism,
            "source_member": self.source_member,
            "value": self.value,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "decoder_chain": list(self.decoder_chain),
            "flags_found": list(self.flags_found),
            "related_artifact": self.related_artifact,
            "preview": self.preview,
        }


@dataclass(frozen=True)
class ExtractedDocumentArtifact:
    """One safely persisted media/object for downstream local analysis."""

    source_member: str
    path: Path
    kind: str
    size: int
    sha256: str
    depth: int


@dataclass(frozen=True)
class DocumentAnalysis:
    """Deterministic result of one bounded document analysis."""

    document_type: str
    findings: tuple[DocumentFinding, ...]
    extracted_artifacts: tuple[ExtractedDocumentArtifact, ...]
    errors: tuple[str, ...]
    limits_reached: tuple[str, ...]
    package_members: int
    expanded_bytes: int
    extracted_dir: Path | None = None


def safe_document_value(value: str, limit: int) -> str:
    """Bound and escape all untrusted document-controlled text."""
    return escape_unsafe_text(value, limit=limit)
