# core/decryption.py
from stegano.lsb import reveal
from .utils import aes_decrypt

def decrypt_message_from_stego(stego_image_path: str, aes_key: bytes):
    """
    1) Reveal the hidden hex data (IV+ciphertext).
    2) Decrypt with the provided aes_key.
    3) Return plaintext message.
    """
    try:
        hidden_data_hex = reveal(stego_image_path)
        if not hidden_data_hex:
            return (False, "No hidden data found in image.")
    except Exception as e:
        return (False, f"Error revealing data: {e}")

    combined_data = bytes.fromhex(hidden_data_hex)
    iv = combined_data[:16]
    ciphertext = combined_data[16:]

    try:
        plaintext = aes_decrypt(iv, ciphertext, aes_key).decode('utf-8')
        return (True, plaintext)
    except Exception as e:
        return (False, f"Decryption failed: {e}")
