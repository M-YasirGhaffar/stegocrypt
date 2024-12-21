# core/encryption.py
import io
from stegano.lsb import hide
from PIL import Image
from django.core.files.base import ContentFile
from .utils import derive_key_from_password, aes_encrypt

def encrypt_and_embed_message(original_image_path: str, message: str, password: str) -> bytes:
    """
    1) Derive AES key from 'password'.
    2) Encrypt 'message'.
    3) Embed the (iv+ciphertext) in the image using Stegano.
    4) Return stego PNG bytes.
    """
    salt = b'some_fixed_salt'  # For demonstration. Use a random salt per user or message in production.
    key = derive_key_from_password(password, salt)

    # Encrypt
    iv, ciphertext = aes_encrypt(message.encode('utf-8'), key)
    combined_data = iv + ciphertext
    combined_hex = combined_data.hex()

    # Embed with Stegano
    stego_image = hide(original_image_path, combined_hex)

    # Convert to PNG bytes
    img_io = io.BytesIO()
    stego_image.save(img_io, format='PNG')
    return img_io.getvalue()

def create_stego_django_file(stego_bytes: bytes, filename="stego.png"):
    """
    Wrap raw bytes in a Django ContentFile to store in an ImageField.
    """
    return ContentFile(stego_bytes, name=filename)
