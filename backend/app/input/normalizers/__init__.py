"""Input normalizers package."""

from app.input.normalizers.email import EmailNormalizer
from app.input.normalizers.file import FileNormalizer
from app.input.normalizers.image import ImageNormalizer
from app.input.normalizers.qr import QRNormalizer
from app.input.normalizers.sms import SMSNormalizer
from app.input.normalizers.url import URLNormalizer
from app.input.normalizers.webpage import WebpageNormalizer

__all__ = [
    "EmailNormalizer",
    "FileNormalizer",
    "ImageNormalizer",
    "QRNormalizer",
    "SMSNormalizer",
    "URLNormalizer",
    "WebpageNormalizer",
]
