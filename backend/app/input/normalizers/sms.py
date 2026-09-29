"""SMS / message input normalizer."""

from __future__ import annotations

from app.input.normalizers.base import BaseNormalizer
from app.input.normalizers.utils import extract_phone_numbers, extract_urls
from app.schemas.schemas import Artifact, ArtifactType


class SMSNormalizer(BaseNormalizer):
    """Normalizer for SMS messages and short text messages.

    Extracts:
      - All URLs found in the message body.
      - Phone number patterns (sender ID, premium numbers, etc.).
      - Optional ``sender_id`` kwarg from gateway metadata.
    """

    artifact_type = ArtifactType.SMS

    def normalize(self, raw: str | bytes, **kwargs: object) -> Artifact:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        text = raw.strip()
        sender_id = str(kwargs.get("sender_id", ""))

        urls = extract_urls(text)
        phones = extract_phone_numbers(text)

        return Artifact(
            type=ArtifactType.SMS,
            raw_content=text,
            extracted_urls=urls,
            metadata={
                "sender_id": sender_id,
                "phone_numbers_found": phones,
                "char_length": len(text),
                "url_count": len(urls),
            },
        )
