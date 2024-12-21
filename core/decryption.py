# core/decryption.py
from stegano.lsb import reveal
from .utils import derive_key_from_password, aes_decrypt

def decrypt_message_from_stego(stego_image_path: str, password: str) -> (bool, str):
    """
    1) Reveal hidden hex data from the stego image.
    2) Parse iv + ciphertext from that hex.
    3) Decrypt using the derived key from 'password'.
    4) Return success or error message.
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

    salt = b'some_fixed_salt'  # same as in encryption
    key = derive_key_from_password(password, salt)

    try:
        decrypted_bytes = aes_decrypt(iv, ciphertext, key)
        return (True, decrypted_bytes.decode('utf-8'))
    except Exception as e:
        return (False, f"Decryption failed: {e}")
