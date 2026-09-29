"""
BaseNormalizer — abstract base class for all input normalizers.

Each normalizer takes raw input (string, bytes, or file path) and returns a
fully-populated Artifact ready for the detector pipeline.

Contract:
  1. ``normalize()`` MUST NOT raise unhandled exceptions.
  2. If parsing fails, populate ``metadata["parse_error"]`` and return the
     best partial Artifact possible (so downstream detectors still see data).
  3. Normalizers MUST NOT make outbound network calls themselves — they pass
     URLs to SafeFetcher via the caller (WebpageNormalizer is the only
     exception, and it receives a pre-fetched FetchResult).
  4. Binary attachments become child Artifact objects stored in the caller's
     context, not embedded in the parent.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.schemas.schemas import Artifact, ArtifactType


class BaseNormalizer(ABC):
    """Abstract normalizer.

    Each subclass handles exactly one ArtifactType.
    """

    artifact_type: ArtifactType

    @abstractmethod
    def normalize(self, raw: str | bytes, **kwargs: object) -> Artifact:
        """Produce a canonical Artifact from raw input.

        Args:
            raw:    The raw content — str for text types, bytes for binary.
            kwargs: Type-specific extra arguments (e.g. filename, mime_type).

        Returns:
            A fully-populated Artifact.  Never raises.
        """
