from urllib.parse import urlparse

import cv2
import numpy as np


MAX_QR_IMAGE_BYTES = 10 * 1024 * 1024
MAX_QR_PIXELS = 20_000_000
ALLOWED_QR_CONTENT_TYPES = {"image/png", "image/jpeg", "image/webp"}


class QRDecodeError(ValueError):
    pass


def decode_qr_url(image_bytes: bytes) -> str:
    if not image_bytes:
        raise QRDecodeError("QR görseli boş olamaz.")
    if len(image_bytes) > MAX_QR_IMAGE_BYTES:
        raise QRDecodeError("QR görseli en fazla 10 MB olabilir.")

    encoded = np.frombuffer(image_bytes, dtype=np.uint8)
    image = cv2.imdecode(encoded, cv2.IMREAD_GRAYSCALE)
    if image is None:
        raise QRDecodeError("Dosya geçerli bir QR görseli olarak okunamadı.")
    if image.shape[0] * image.shape[1] > MAX_QR_PIXELS:
        raise QRDecodeError("QR görselinin çözünürlüğü çok yüksek.")

    value, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    value = value.strip()
    if not value:
        raise QRDecodeError("Görselde okunabilir bir QR kod bulunamadı.")

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise QRDecodeError("QR kod geçerli bir HTTP/HTTPS URL içermiyor.")
    if len(value) > 2048:
        raise QRDecodeError("QR kod içindeki URL çok uzun.")
    return value
