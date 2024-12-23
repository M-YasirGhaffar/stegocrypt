# core/utils.py

import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings

from PIL import Image
import io
import base64
from django.core.files.base import ContentFile

def aes_encrypt(plaintext: bytes, key: bytes):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext)

def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_with_master_key(data: bytes):
    """
    Encrypt 'data' with the system-level master key derived from settings.SECRET_KEY.
    """
    from steganography.settings import get_master_key
    master_key = get_master_key()
    iv, ciphertext = aes_encrypt(data, master_key)
    return iv, ciphertext

def decrypt_with_master_key(iv: bytes, ciphertext: bytes):
    """
    Decrypt 'ciphertext' with the system-level master key from settings.SECRET_KEY.
    """
    from steganography.settings import get_master_key
    master_key = get_master_key()
    return aes_decrypt(iv, ciphertext, master_key)

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def create_thumbnail(image_path, size=(200, 200)):
    """Create a thumbnail from an image file"""
    try:
        with Image.open(image_path) as img:
            # Convert to RGB if needed
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            
            # Calculate aspect ratio
            aspect = img.width / img.height
            if aspect > 1:
                new_width = size[0]
                new_height = int(size[0] / aspect)
            else:
                new_height = size[1]
                new_width = int(size[1] * aspect)
                
            img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
            
            # Save to bytes
            thumb_io = io.BytesIO()
            img.save(thumb_io, format='JPEG', quality=85)
            return thumb_io.getvalue()
    except Exception as e:
        print(f"Thumbnail creation error: {e}")
        return None

def get_image_data(encrypted_image):
    """Get formatted image data including preview"""
    try:
        thumb_data = create_thumbnail(encrypted_image.original_image.path)
        if thumb_data:
            preview = base64.b64encode(thumb_data).decode('utf-8')
            return {
                'id': encrypted_image.id,
                'preview': f"data:image/jpeg;base64,{preview}",
                'filename': encrypted_image.original_image.name,
                'created_at': encrypted_image.created_at.isoformat(),
                'is_public': encrypted_image.is_public,
                'owner': encrypted_image.user.username
            }
    except Exception as e:
        print(f"Image data error: {e}")
    return None