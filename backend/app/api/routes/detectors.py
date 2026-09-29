"""GET /detectors — list all 22 registered detectors grouped by domain."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.registry import DOMAIN_NAMES, get_all_detectors
from app.schemas.schemas import DetectorInfo, DetectorListResponse, DomainInfo

router = APIRouter()


@router.get("/detectors", response_model=DetectorListResponse, tags=["Detectors"])
async def list_detectors() -> DetectorListResponse:
    """Return all registered detectors, grouped by detection domain.

    The response always contains exactly 22 detectors across 5 domains:
      - d1: Phishing & Social Engineering        (9)
      - d2: URL & Domain Security                (5)
      - d3: Web & Credential Security            (3)
      - d4: Email & Communication Security       (3)
      - d5: Multimedia & Image-Based             (2)

    Detectors that are stubs (not yet fully implemented) are included with
    their correct metadata so the registry is always complete and listable.
    """
    all_detectors = get_all_detectors()

    # Group by domain_id, preserving d1 → d5 order
    domains_map: dict[str, list[DetectorInfo]] = {did: [] for did in DOMAIN_NAMES}

    for det in all_detectors:
        info = DetectorInfo(
            detector_id=det.detector_id,
            name=det.name,
            domain=det.domain,
            domain_id=det.domain_id,
            accepted_artifact_types=det.accepted_artifact_types,
            required_engines=det.required_engines,
            version=det.version,
        )
        domains_map.setdefault(det.domain_id, []).append(info)

    domains = [
        DomainInfo(
            domain_id=did,
            domain_name=DOMAIN_NAMES[did],
            detectors=sorted(detectors, key=lambda d: d.detector_id),
        )
        for did, detectors in domains_map.items()
        if detectors  # Only include domains that have detectors registered
    ]

    return DetectorListResponse(
        total=len(all_detectors),
        domains=domains,
    )
