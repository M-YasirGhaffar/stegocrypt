# core/forms.py
from django import forms
from django.core.exceptions import ValidationError

class EncryptionForm(forms.Form):
    """Form for encrypting messages in GIF files"""
    gif_file = forms.FileField(
        label="Select a GIF",
        help_text="Only animated GIF files up to 10MB are allowed",
        required=True
    )
    secret_message = forms.CharField(
        widget=forms.Textarea(attrs={
            'placeholder': 'Enter your secret message...',
            'class': 'w-full px-4 py-3 rounded-lg border'
        }),
        required=True,
        label="Secret Message"
    )
    pass_key = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Enter pass key for encryption',
            'class': 'w-full px-4 py-3 rounded-lg border'
        }),
        required=True,
        label="Pass Key"
    )

    def clean_gif_file(self):
        """Validate the uploaded GIF file"""
        gif = self.cleaned_data.get('gif_file')
        if gif:
            # Check file size (10MB limit)
            if gif.size > 10 * 1024 * 1024:
                raise ValidationError("GIF file too large (max 10MB)")

            # Verify it's a GIF file
            if not gif.content_type == 'image/gif':
                raise ValidationError("Only GIF files are allowed")

            # Try opening it as a GIF to verify it's animated
            from PIL import Image
            try:
                with Image.open(gif) as img:
                    if not getattr(img, "is_animated", False):
                        raise ValidationError("Only animated GIFs are allowed")
            except Exception as e:
                raise ValidationError(f"Invalid GIF file: {str(e)}")

        return gif

class DecryptionForm(forms.Form):
    """Form for decrypting messages from GIF files"""
    gif_file = forms.FileField(
        label="Select encrypted GIF",
        help_text="Upload the GIF containing the hidden message",
        required=True
    )
    pass_key = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Enter pass key for decryption',
            'class': 'w-full px-4 py-3 rounded-lg border'
        }),
        required=True,
        label="Pass Key"
    )

    def clean_gif_file(self):
        """Validate the uploaded GIF file"""
        gif = self.cleaned_data.get('gif_file')
        if gif:
            # Check file size
            if gif.size > 10 * 1024 * 1024:
                raise ValidationError("GIF file too large (max 10MB)")

            # Verify it's a GIF
            if not gif.content_type == 'image/gif':
                raise ValidationError("Only GIF files are allowed")

        return gif