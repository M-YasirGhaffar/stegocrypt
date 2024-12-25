# core/views.py
from django.shortcuts import render
from django.http import HttpResponse
from .forms import EncryptionForm, DecryptionForm
from .encryption import encrypt_and_embed_message
from .decryption import decrypt_message_from_gif
import tempfile

def index(request):
    """Handle both encryption and decryption in a single view"""
    encrypt_form = EncryptionForm()
    decrypt_form = DecryptionForm()
    context = {
        'encrypt_form': encrypt_form,
        'decrypt_form': decrypt_form
    }

    if request.method == 'POST':
        if 'encrypt' in request.POST:
            encrypt_form = EncryptionForm(request.POST, request.FILES)
            if encrypt_form.is_valid():
                try:
                    # Get form data
                    gif_file = encrypt_form.cleaned_data['gif_file']
                    secret_message = encrypt_form.cleaned_data['secret_message']
                    pass_key = encrypt_form.cleaned_data['pass_key']
                    
                    # Encrypt and embed message
                    encrypted_gif = encrypt_and_embed_message(gif_file, secret_message, pass_key)
                    
                    # Return encrypted GIF as download
                    response = HttpResponse(encrypted_gif, content_type='image/gif')
                    response['Content-Disposition'] = 'attachment; filename="encrypted.gif"'
                    return response
                    
                except Exception as e:
                    encrypt_form.add_error(None, f"Encryption failed: {str(e)}")
            context['encrypt_form'] = encrypt_form

        elif 'decrypt' in request.POST:
            decrypt_form = DecryptionForm(request.POST, request.FILES)
            if decrypt_form.is_valid():
                try:
                    # Get form data
                    gif_file = decrypt_form.cleaned_data['gif_file']
                    pass_key = decrypt_form.cleaned_data['pass_key']
                    
                    # Create temporary file for GIF processing
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.gif') as tmp:
                        for chunk in gif_file.chunks():
                            tmp.write(chunk)
                        temp_path = tmp.name
                    
                    try:
                        # Decrypt message
                        success, message = decrypt_message_from_gif(temp_path, pass_key)
                        if success:
                            context['decrypted_message'] = message
                        else:
                            decrypt_form.add_error(None, message)
                    finally:
                        # Clean up temp file
                        import os
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                            
                except Exception as e:
                    decrypt_form.add_error(None, f"Decryption failed: {str(e)}")
            context['decrypt_form'] = decrypt_form
    
    return render(request, 'core/index.html', context)