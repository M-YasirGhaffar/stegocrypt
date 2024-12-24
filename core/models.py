# core/models.py
from django.db import models
from django.contrib.auth.models import User
import hashlib
from .utils import decrypt_with_master_key, encrypt_with_master_key

def hash_key_with_salt(key: str, salt: str) -> str:
    return hashlib.sha256((key + salt).encode('utf-8')).hexdigest()

class EncryptedImage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original_image = models.ImageField(upload_to='original_images/')
    stego_image = models.ImageField(upload_to='stego_images/', blank=True, null=True)
    message_hash = models.CharField(max_length=64, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_public = models.BooleanField(default=False)
    
    # Pass-key verification
    pass_key_salt = models.CharField(max_length=32, blank=True, null=True)
    pass_key_hash = models.CharField(max_length=64, blank=True, null=True)
    
    # Encrypted pass-key for owner
    encrypted_key_for_owner = models.BinaryField(blank=True, null=True)
    encrypted_key_iv = models.BinaryField(blank=True, null=True)
    
    # Users with access
    shared_with = models.ManyToManyField(User, related_name='shared_images', blank=True)

    def __str__(self):
        return f"EncryptedImage #{self.id} by {self.user.username}"

    def verify_pass_key(self, typed_pass_key: str) -> bool:
        if not self.pass_key_salt or not self.pass_key_hash:
            return False
        test_hash = hash_key_with_salt(typed_pass_key, self.pass_key_salt)
        return test_hash == self.pass_key_hash

    def share_with_user(self, recipient: User) -> bool:
        """Share image and encrypt pass-key for recipient"""
        if not self.is_public:
            return False
        
        try:
            # Get original pass-key
            real_pass_key = decrypt_with_master_key(
                self.encrypted_key_iv,
                self.encrypted_key_for_owner
            ).decode('utf-8')
            
            # Create new encrypted key for recipient
            iv, encrypted_key = encrypt_with_master_key(real_pass_key.encode('utf-8'))
            
            # Store encrypted key for recipient
            SharedImageKey.objects.create(
                image=self,
                user=recipient,
                encrypted_key=encrypted_key,
                key_iv=iv
            )
            
            # Add to shared_with
            self.shared_with.add(recipient)
            return True
            
        except Exception:
            return False

class SharedImageKey(models.Model):
    image = models.ForeignKey(EncryptedImage, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_key = models.BinaryField()
    key_iv = models.BinaryField()
    
    class Meta:
        unique_together = ['image', 'user']