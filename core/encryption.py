# core/encryption.py
import io
import base64
import hashlib
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
from django.core.files.base import ContentFile

def generate_key_from_password(pass_key: str) -> bytes:
    """Generate a consistent Fernet key from password"""
    key = hashlib.sha256(pass_key.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_and_embed_message(gif_file, secret_message: str, pass_key: str) -> bytes:
    """Encrypt and embed message in first frame of animated GIF"""
    try:
        # Generate encryption key from pass_key
        key = generate_key_from_password(pass_key)
        fernet = Fernet(key)
        
        # Encrypt the message
        encrypted_message = fernet.encrypt(secret_message.encode())
        
        # Open GIF and get frames
        with Image.open(gif_file) as gif:
            if not getattr(gif, "is_animated", False):
                raise ValueError("Not an animated GIF")

            frames = []
            durations = []
            
            # Get all frames and their durations
            try:
                while True:
                    durations.append(gif.info.get('duration', 100))
                    frames.append(gif.copy())
                    gif.seek(gif.tell() + 1)
            except EOFError:
                pass

            # Convert first frame to RGB if necessary
            if frames[0].mode != 'RGB':
                frames[0] = frames[0].convert('RGB')

            # Embed encrypted message in first frame
            frames[0] = lsb.hide(frames[0], encrypted_message.hex())

            # Save as animated GIF
            output = io.BytesIO()
            frames[0].save(
                output,
                format='GIF',
                save_all=True,
                append_images=frames[1:],
                duration=durations,
                loop=0,
                optimize=False
            )
            
            return output.getvalue()

    except Exception as e:
        raise ValueError(f"GIF encryption failed: {str(e)}")