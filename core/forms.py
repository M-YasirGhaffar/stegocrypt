# core/forms.py
from django import forms
from django.contrib.auth.models import User

class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'password']

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm = cleaned_data.get('confirm_password')
        if password != confirm:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

class EncryptionForm(forms.Form):
    original_image = forms.ImageField(required=True)
    secret_message = forms.CharField(widget=forms.Textarea, required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=True,
        label="(For demonstration) A pass to confirm you typed something")
    is_public = forms.BooleanField(
        required=False, 
        label="Make image shareable?"
    )

class DecryptionPasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput, required=True, 
        label="Your private key password")

class ShareForm(forms.Form):
    recipient_username = forms.CharField(required=True, label="Recipient Username")
    owner_password = forms.CharField(
        required=True, 
        label="Owner's Private Key Password",
        widget=forms.PasswordInput
    )

# Optional: Upload a stego image directly to decode
class DecryptionUploadForm(forms.Form):
    stego_image_file = forms.ImageField(required=True, label="Upload Stego Image")
    password = forms.CharField(widget=forms.PasswordInput, required=True,
        label="Your private key password (if you have a key) or shared pass")
