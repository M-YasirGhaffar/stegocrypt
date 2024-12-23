# core/decryption.py
import hashlib
from stegano.lsb import reveal
from .utils import aes_decrypt

def decrypt_message_from_stego(stego_image_path: str, pass_or_pw: str):
    """
    Derive AES key from pass_or_pw => embed in image.
    """
    try:
        hidden_data_hex = reveal(stego_image_path)
        if not hidden_data_hex:
            return (False, "No hidden data found in this image.")
    except Exception as e:
        return (False, f"Error revealing data: {e}")

    combined_data = bytes.fromhex(hidden_data_hex)
    iv = combined_data[:16]
    ciphertext = combined_data[16:]
    aes_key = hashlib.sha256(pass_or_pw.encode('utf-8')).digest()
    try:
        plaintext = aes_decrypt(iv, ciphertext, aes_key).decode('utf-8')
        return (True, plaintext)
    except Exception as ex:
        return (False, f"Decryption failed: {ex}")
