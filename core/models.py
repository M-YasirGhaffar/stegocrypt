# core/models.py
from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    """
    Stores each user's RSA key pair:
    - public_key (PEM)
    - encrypted_private_key (base64 of AES-encrypted PEM)
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField(blank=True, null=True)
    encrypted_private_key = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Profile of {self.user.username}"

class EncryptedImage(models.Model):
    """
    The main record for an encrypted/stego image.
    - is_public=False => private, can't be shared
    - is_public=True  => shareable, but only accessible if user has a SharedKey
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original_image = models.ImageField(upload_to='original_images/')
    stego_image = models.ImageField(upload_to='stego_images/', blank=True, null=True)
    message_hash = models.CharField(max_length=64, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_public = models.BooleanField(default=False)

    def __str__(self):
        return f"EncryptedImage #{self.id} by {self.user.username}"

class SharedKey(models.Model):
    """
    Stores an RSA-encrypted AES key for a specific user (shared_with).
    Only a user with a SharedKey can decrypt that EncryptedImage.
    """
    image = models.ForeignKey(EncryptedImage, on_delete=models.CASCADE)
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_aes_key = models.BinaryField()

    def __str__(self):
        return f"SharedKey for Image #{self.image.id} -> {self.shared_with.username}"
