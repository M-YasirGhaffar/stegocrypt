# core/utils_rsa.py
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from .utils import derive_key_from_password, aes_encrypt, aes_decrypt

def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_keypair(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def encrypt_private_key_with_user_password(private_pem: bytes, user_password: str) -> bytes:
    """
    Symmetric AES encryption of the private key PEM with the user’s password.
    This is a simple demonstration approach. In real systems, you might do more robust key management.
    """
    salt = b'store_some_user_specific_salt'  # Or generate per user
    aes_key = derive_key_from_password(user_password, salt)
    iv, ciphertext = aes_encrypt(private_pem, aes_key)
    return iv + ciphertext  # We can store iv+ciphertext combined

def decrypt_private_key_with_user_password(encrypted_private_key: bytes, user_password: str):
    """
    Decrypt private key using user’s password.
    """
    salt = b'store_some_user_specific_salt'
    aes_key = derive_key_from_password(user_password, salt)
    iv = encrypted_private_key[:16]
    ciphertext = encrypted_private_key[16:]
    plaintext_pem = aes_decrypt(iv, ciphertext, aes_key)
    private_key = serialization.load_pem_private_key(
        plaintext_pem,
        password=None
    )
    return private_key

def rsa_encrypt_with_public_key(public_pem: bytes, data: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_pem)
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt_with_private_key(private_key, ciphertext: bytes) -> bytes:
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
