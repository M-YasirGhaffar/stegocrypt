# core/forms.py
import re
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

def validate_strong_password(value):
    # Example advanced checks
    errs = []
    if len(value) < 8:
        errs.append("Password must be >= 8 chars.")
    if not re.search(r'[A-Z]', value):
        errs.append("At least 1 uppercase letter required.")
    if not re.search(r'[a-z]', value):
        errs.append("At least 1 lowercase letter required.")
    if not re.search(r'[0-9]', value):
        errs.append("At least 1 digit required.")
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', value):
        errs.append("At least 1 special character required.")

    if errs:
        raise ValidationError(errs)

class RegisterForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Your username'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'placeholder': 'Your email'}), required=False)
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Account password'}),
        validators=[validate_strong_password]
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm password'})
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def clean(self):
        cd = super().clean()
        pw = cd.get('password')
        cpw = cd.get('confirm_password')
        if pw != cpw:
            self.add_error('confirm_password', "Passwords do not match!")
        return cd

class LoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Username'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Account password'}))

class EncryptionForm(forms.Form):
    original_image = forms.ImageField(label="Select an image", required=True)
    secret_message = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'Secret message...'}),
        required=True, label="Message"
    )
    pass_key = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Pass-Key for encryption'}),
        required=True, label="Pass-Key"
    )
    is_public = forms.BooleanField(required=False, label="Allow sharing?")
    
        # Add to EncryptionForm
    def clean_original_image(self):
        image = self.cleaned_data.get('original_image')
        if image:
            if image.size > 10 * 1024 * 1024:
                raise ValidationError("Image too large")
            if not image.content_type.startswith('image/'):
                raise ValidationError("Invalid file type")
        return image

class DecryptSingleFieldForm(forms.Form):
    pass_or_pw = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Pass-Key or Account Password'}),
        required=True, label="Enter Pass-Key or Account Password"
    )

class ShareForm(forms.Form):
    recipient_username = forms.CharField(label="Recipient Username")

class DecryptionUploadForm(forms.Form):
    stego_image_file = forms.ImageField(label="Encrypted Image", required=True)
    pass_or_pw = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Pass-Key or Account Password'}),
        required=True, label="Pass-Key/Password"
    )
