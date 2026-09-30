import pytest
from app.schemas.schemas import Artifact, ArtifactType
from app.engines.media.engine import MediaEngine
from app.core.context import AnalysisContext

@pytest.mark.asyncio
async def test_media_engine_no_bytes():
    engine = MediaEngine()
    artifact = Artifact(type=ArtifactType.QR)
    payloads = await engine.decode_qr(artifact)
    assert payloads == []

@pytest.mark.asyncio
async def test_media_engine_ocr_no_bytes():
    engine = MediaEngine()
    artifact = Artifact(type=ArtifactType.IMAGE)
    text = await engine.extract_text_ocr(artifact)
    assert text == ""

# A 1x1 white pixel PNG
WHITE_PIXEL = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de"
    "0000000c4944415408d763f8cfc000000301010018dd8d6a0000000049454e44ae"
    "426082"
)

@pytest.mark.asyncio
async def test_media_engine_empty_image():
    engine = MediaEngine()
    artifact = Artifact(type=ArtifactType.QR, raw_bytes=WHITE_PIXEL)
    payloads = await engine.decode_qr(artifact)
    assert payloads == []
    
    text = await engine.extract_text_ocr(artifact)
    assert text == ""
