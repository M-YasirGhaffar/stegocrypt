# core/models.py

from django.db import models
from django.contrib.auth.models import User
import hashlib
import secrets

def hash_key_with_salt(key: str, salt: str) -> str:
    return hashlib.sha256((key + salt).encode('utf-8')).hexdigest()

class EncryptedImage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original_image = models.ImageField(upload_to='original_images/')
    stego_image = models.ImageField(upload_to='stego_images/', blank=True, null=True)
    message_hash = models.CharField(max_length=64, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # If True => can be shared. If False => private
    is_public = models.BooleanField(default=False)

    # pass-key hash approach
    pass_key_salt = models.CharField(max_length=32, blank=True, null=True)
    pass_key_hash = models.CharField(max_length=64, blank=True, null=True)

    # The actual AES pass-key is stored encrypted with the system-level master key
    encrypted_key_for_owner = models.BinaryField(blank=True, null=True)
    encrypted_key_iv = models.BinaryField(blank=True, null=True)

    # shared with other users
    shared_with = models.ManyToManyField(User, related_name='shared_images', blank=True)

    def __str__(self):
        return f"EncryptedImage #{self.id} by {self.user.username}"

    def verify_pass_key(self, typed_pass_key: str) -> bool:
        if not self.pass_key_salt or not self.pass_key_hash:
            return False
        test_hash = hash_key_with_salt(typed_pass_key, self.pass_key_salt)
        return test_hash == self.pass_key_hash
