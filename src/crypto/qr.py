"""Cryptographic and Verifiable QR Code Generator.

Encodes authentic verification URLs into scannable QR Code images
(Base64 PNG Data URI and SVG) conforming to standard ISO/IEC 18004.
"""
import io
import base64
import qrcode
import qrcode.image.svg


def generate_qr_data_uri(content_url: str, box_size: int = 8, border: int = 2) -> str:
    """
    Generate a standard scannable QR Code as a Base64-encoded PNG Data URI.
    Can be directly embedded in HTML <img src="..."> tags.
    """
    qr = qrcode.QRCode(
        version=None,  # Automatic version selection based on content length
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(content_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    # Save the underlying PIL image to PNG buffer
    if hasattr(img, "get_image"):
        pil_img = img.get_image()
    else:
        pil_img = img
    pil_img.save(buffer, format="PNG")
    b64_str = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64_str}"


def generate_qr_svg(content_url: str) -> str:
    """
    Generate a standard scannable QR Code as an SVG XML string.
    """
    factory = qrcode.image.svg.SvgPathImage
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
        image_factory=factory
    )
    qr.add_data(content_url)
    qr.make(fit=True)

    img = qr.make_image()
    buffer = io.BytesIO()
    img.save(buffer)
    return buffer.getvalue().decode("utf-8")
