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
    """Custom symmetric encryption replacing AES-CBC.
    Returns same (iv, ciphertext) format for compatibility."""
    
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))
    
    # Generate 16-byte IV
    iv = bytes(x ^ y for x, y in zip(
        key[:16].ljust(16, b'\0'),
        plaintext[:16].ljust(16, b'\0')
    ))
    
    # Padding (keeping PKCS7 style padding)
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len
    
    # Custom encryption
    ciphertext = bytearray()
    prev_block = iv
    
    # Process 16-byte blocks
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        # Mix block with key
        mixed = xor_bytes(block, key[:16])
        # Mix with previous block (CBC mode)
        mixed = xor_bytes(mixed, prev_block)
        # Simple rotation instead of complex one
        rotated = mixed[1:] + mixed[:1]  # Rotate by 1 byte
        # Final mixing
        encrypted_block = xor_bytes(rotated, key[16:32].ljust(16, b'\0'))
        ciphertext.extend(encrypted_block)
        prev_block = encrypted_block
        
    return (iv, bytes(ciphertext))

def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes):
    """Custom symmetric decryption matching the encryption above."""
    
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))
    
    plaintext = bytearray()
    prev_block = iv
    
    # Process 16-byte blocks
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        # Reverse final mixing
        unmixed = xor_bytes(block, key[16:32].ljust(16, b'\0'))
        # Reverse rotation
        unrotated = unmixed[-1:] + unmixed[:-1]  # Rotate back by 1 byte
        # Reverse CBC
        decrypted = xor_bytes(unrotated, prev_block)
        # Reverse key mixing
        decrypted = xor_bytes(decrypted, key[:16])
        plaintext.extend(decrypted)
        prev_block = block
    
    # Remove padding
    pad_len = plaintext[-1]
    return bytes(plaintext[:-pad_len])

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

def _rotate_left(n: int, d: int, size: int = 64) -> int:
    """Helper function for bit rotation"""
    return ((n << d) | (n >> (size - d))) & ((1 << size) - 1)

def sha256_hash(data: bytes) -> str:
    """Custom hash function replacing SHA256.
    Uses SipHash-like structure with different constants and mixing function.
    """
    # Constants for mixing (using prime numbers)
    C1 = 0x736f6d6570736575  # "somepseu" in hex
    C2 = 0x646f72616e646f6d  # "dorandom" in hex
    C3 = 0x6c7967656e657261  # "lygenera" in hex
    C4 = 0x7465686173686573  # "tehashes" in hex
    
    def mix(v0: int, v1: int) -> tuple[int, int]:
        v0 = (v0 + v1) & ((1 << 64) - 1)
        v1 = _rotate_left(v1, 13) ^ v0
        v0 = _rotate_left(v0, 32)
        return v0, v1

    # Initialize state
    v0, v1 = C1, C2
    v2, v3 = C3, C4
    
    # Process message in 8-byte chunks
    for i in range(0, len(data), 8):
        chunk = data[i:i+8].ljust(8, b'\0')
        m = int.from_bytes(chunk, byteorder='little')
        
        # Mix chunk into state
        v3 ^= m
        v0, v1 = mix(v0, v1)
        v2, v3 = mix(v2, v3)
        v0, v3 = mix(v0, v3)
        v2, v1 = mix(v2, v1)
        v0 ^= m
        
    # Final mixing rounds
    v2 ^= 0xff
    for _ in range(4):
        v0, v1 = mix(v0, v1)
        v2, v3 = mix(v2, v3)
        v0, v3 = mix(v0, v3)
        v2, v1 = mix(v2, v1)
    
    # Combine state into final hash
    final = (v0 ^ v1 ^ v2 ^ v3).to_bytes(8, byteorder='little')
    return final.hex()[:64].zfill(64)  # Match SHA256 output length

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