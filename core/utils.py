# core/utils.py

import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings

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
