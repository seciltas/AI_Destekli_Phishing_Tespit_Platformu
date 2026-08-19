from io import BytesIO

import qrcode

from qr_analyzer import QRDecodeError, decode_qr_url


def make_qr(value: str) -> bytes:
    image = qrcode.make(value)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def test_decode_qr_url_reads_http_url():
    assert decode_qr_url(make_qr("https://example.com/login")) == "https://example.com/login"


def test_decode_qr_url_rejects_non_url_content():
    try:
        decode_qr_url(make_qr("yalnızca metin"))
    except QRDecodeError as exc:
        assert "HTTP/HTTPS URL" in str(exc)
        return
    raise AssertionError("QRDecodeError bekleniyordu")


def test_decode_qr_url_rejects_invalid_image():
    try:
        decode_qr_url(b"not-an-image")
    except QRDecodeError as exc:
        assert "okunamadı" in str(exc)
        return
    raise AssertionError("QRDecodeError bekleniyordu")
