# core/decryption.py
import base64
import hashlib
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet

def generate_key_from_password(pass_key: str) -> bytes:
    """Generate a consistent Fernet key from password"""
    key = hashlib.sha256(pass_key.encode()).digest()
    return base64.urlsafe_b64encode(key)

def decrypt_message_from_gif(gif_file, pass_key: str) -> tuple[bool, str]:
    """Extract and decrypt message from first frame of GIF"""
    try:
        # Open GIF and get first frame
        with Image.open(gif_file) as gif:
            if not getattr(gif, "is_animated", False):
                return False, "Not an animated GIF"

            # Get first frame
            gif.seek(0)
            first_frame = gif.copy()

            # Convert to RGB if necessary
            if first_frame.mode != 'RGB':
                first_frame = first_frame.convert('RGB')

            try:
                # Extract hidden data
                encrypted_hex = lsb.reveal(first_frame)
                if not encrypted_hex:
                    return False, "No hidden data found"

                # Convert hex to bytes
                encrypted_message = bytes.fromhex(encrypted_hex)
                
                # Generate same key from pass_key
                key = generate_key_from_password(pass_key)
                fernet = Fernet(key)
                
                # Decrypt message
                decrypted_message = fernet.decrypt(encrypted_message)
                return True, decrypted_message.decode('utf-8')
                
            except ValueError as ve:
                return False, "Invalid encrypted data format"
            except Exception as e:
                return False, f"Decryption failed: {str(e)}"

    except Exception as e:
        return False, f"Error processing GIF: {str(e)}"