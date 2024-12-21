# core/models.py
from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField(blank=True, null=True)
    encrypted_private_key = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Profile of {self.user.username}"

class EncryptedImage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original_image = models.ImageField(upload_to='original_images/')
    stego_image = models.ImageField(upload_to='stego_images/', blank=True, null=True)
    message_hash = models.CharField(max_length=64, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # For optional "public gallery" listing
    is_public = models.BooleanField(default=False)

    def __str__(self):
        return f"EncryptedImage #{self.id} by {self.user.username}"

class SharedKey(models.Model):
    """Stores an AES key (encrypted with recipient's public key) for a specific EncryptedImage."""
    image = models.ForeignKey(EncryptedImage, on_delete=models.CASCADE)
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_aes_key = models.BinaryField()  # RSA-encrypted AES key

    def __str__(self):
        return f"AES key for Image #{self.image.id} shared with {self.shared_with.username}"
