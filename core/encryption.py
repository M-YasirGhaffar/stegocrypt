# core/encryption.py
import io
import secrets
from stegano.lsb import hide
from PIL import Image
from django.core.files.base import ContentFile
from .utils import aes_encrypt
from .utils_rsa import rsa_encrypt_with_public_key

def encrypt_and_embed_message(original_image_path: str, message: str):
    """
    1) Generate a random AES key.
    2) Encrypt 'message' with that AES key.
    3) Hide the IV+ciphertext in the original_image using Stegano.
    4) Return stego image bytes, plus the AES key (for sharing).
    """
    # 1) Generate random AES key
    aes_key = secrets.token_bytes(32)

    # 2) AES-encrypt the message
    iv, ciphertext = aes_encrypt(message.encode('utf-8'), aes_key)
    combined_data = iv + ciphertext
    combined_hex = combined_data.hex()

    # 3) Stegano hide
    stego_image = hide(original_image_path, combined_hex)

    # Save to bytes
    img_io = io.BytesIO()
    stego_image.save(img_io, format='PNG')
    stego_bytes = img_io.getvalue()

    return stego_bytes, aes_key

def create_stego_django_file(stego_bytes: bytes, filename="stego.png"):
    return ContentFile(stego_bytes, name=filename)
