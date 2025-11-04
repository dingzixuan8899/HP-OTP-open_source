import qrcode
from io import BytesIO
from PIL import Image


def generate_qr_code(auth1_str: str) -> str:
    """Generate a QR code from the server's AUTH1 string (returns base64 for display)."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(auth1_str)
    qr.make(fit=True)

    # Render QR code to a bytes buffer
    img_buffer = BytesIO()
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(img_buffer, format="PNG")
    img_buffer.seek(0)

    # Encode to base64 (for display in web apps)
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    print(f"[Client] QR code generated (base64 preview: {img_base64[:20]}...)")
    return img_base64