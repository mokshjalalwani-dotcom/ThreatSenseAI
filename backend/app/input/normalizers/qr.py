"""QR code image normalizer.

Same validation as ImageNormalizer plus a stub for QR decoding.
Actual QR decode (via pyzbar/OpenCV) happens in the MediaEngine in Stage 8.
The normalizer just validates the image and sets type=QR.
"""

from __future__ import annotations

from app.input.normalizers.base import BaseNormalizer
from app.input.normalizers.image import ImageNormalizer
from app.schemas.schemas import Artifact, ArtifactType


class QRNormalizer(BaseNormalizer):
    """Validates QR code images.  Decoding deferred to MediaEngine (Stage 8)."""

    artifact_type = ArtifactType.QR

    def normalize(self, raw: str | bytes, **kwargs: object) -> Artifact:
        # Re-use the ImageNormalizer for all validation
        img_artifact = ImageNormalizer().normalize(raw, **kwargs)

        # Override the type to QR
        return img_artifact.model_copy(
            update={
                "type": ArtifactType.QR,
                "metadata": {
                    **img_artifact.metadata,
                    "qr_decoded": None,  # Populated by MediaEngine in Stage 8
                },
            }
        )
