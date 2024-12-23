# core/encryption.py
import io
from django.core.files.base import ContentFile
from stegano.lsb import hide
from .utils import aes_encrypt, sha256_hash

def encrypt_and_embed_message(original_image_path: str, secret_message: str, pass_key: str) -> bytes:
    """
    1) Derive AES key from pass_key => (sha256 of pass_key).
    2) AES-encrypt 'secret_message'.
    3) Embed IV+ciphertext in LSB.
    """
    import hashlib, secrets
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    aes_key = hashlib.sha256(pass_key.encode('utf-8')).digest()
    iv, ciphertext = aes_encrypt(secret_message.encode('utf-8'), aes_key)
    combined = iv + ciphertext
    combined_hex = combined.hex()

    stego_image = hide(original_image_path, combined_hex)
    img_io = io.BytesIO()
    stego_image.save(img_io, format='PNG')
    return img_io.getvalue()

def create_stego_django_file(stego_bytes: bytes, filename="stego.png"):
    return ContentFile(stego_bytes, name=filename)
