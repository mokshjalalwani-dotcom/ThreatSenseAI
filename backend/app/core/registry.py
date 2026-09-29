"""
THREAT-SENSE AI — central detector registry.

How registration works
----------------------
1.  A detector class decorates itself with ``@register_detector``.
2.  The decorator instantiates the class and inserts it into ``_REGISTRY``
    keyed by ``detector_id``.
3.  All 22 detector modules are imported by ``app.detectors`` at startup,
    triggering their ``@register_detector`` decorators.

Invariants (enforced at import time)
-------------------------------------
- No two detectors may share a ``detector_id``.
- Every detector must have a non-empty ``detector_id``, ``name``, and
  ``domain_id`` (d1 … d5).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

# The single source of truth: detector_id → detector instance
_REGISTRY: dict[str, BaseDetector] = {}

# Domain metadata (id → human-readable name)
DOMAIN_NAMES: dict[str, str] = {
    "d1": "Phishing & Social Engineering",
    "d2": "URL & Domain Security",
    "d3": "Web & Credential Security",
    "d4": "Email & Communication Security",
    "d5": "Multimedia & Image-Based",
}


def register_detector(cls: type[BaseDetector]) -> type[BaseDetector]:
    """Class decorator — instantiates and registers a detector.

    Args:
        cls: A concrete subclass of ``BaseDetector``.

    Returns:
        The unchanged class (so it can still be used normally).

    Raises:
        ValueError: If ``detector_id`` is empty or already registered.
    """
    instance: BaseDetector = cls()

    if not instance.detector_id:
        raise ValueError(f"{cls.__name__} has an empty detector_id.")

    if instance.detector_id in _REGISTRY:
        raise ValueError(
            f"Duplicate detector_id {instance.detector_id!r} in {cls.__name__}. "
            "Each detector must have a unique id."
        )

    _REGISTRY[instance.detector_id] = instance
    logger.debug("Registered detector %s (%s)", instance.detector_id, instance.name)
    return cls


def get_all_detectors() -> list[BaseDetector]:
    """Return all registered detector instances, ordered by detector_id."""
    return sorted(_REGISTRY.values(), key=lambda d: d.detector_id)


def get_detector(detector_id: str) -> BaseDetector | None:
    """Look up a single detector by its id, or None if not found."""
    return _REGISTRY.get(detector_id)


def get_detectors_for_domain(domain_id: str) -> list[BaseDetector]:
    """Return all detectors belonging to a given domain (d1 … d5)."""
    return [d for d in get_all_detectors() if d.domain_id == domain_id]


def registry_stats() -> dict[str, int]:
    """Return a {domain_id: count} summary — useful for health checks."""
    from collections import Counter

    return dict(Counter(d.domain_id for d in _REGISTRY.values()))
