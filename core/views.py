# core/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

from .forms import (
    RegisterForm, 
    LoginForm, 
    EncryptionForm,
    DecryptionPasswordForm
)

from .models import EncryptedImage
from .encryption import encrypt_and_embed_message, create_stego_django_file
from .decryption import decrypt_message_from_stego
from .utils import sha256_hash

def index(request):
    """ Show a welcome page or a listing of user images if logged in. """
    if request.user.is_authenticated:
        images = EncryptedImage.objects.filter(user=request.user)
        return render(request, 'core/index.html', {'images': images})
    else:
        return render(request, 'core/index.html')

def register_view(request):
    """ Register a new user. """
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            raw_password = form.cleaned_data['password']
            user.set_password(raw_password)
            user.save()
            messages.success(request, "Registration successful! You can now log in.")
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'core/register.html', {'form': form})

def login_view(request):
    """ Login an existing user. """
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, "Logged in successfully.")
                return redirect('index')
            else:
                messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()
    return render(request, 'core/login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('index')

@login_required
def encrypt_view(request):
    """ Upload an original image, specify message & password, produce stego image. """
    if request.method == 'POST':
        form = EncryptionForm(request.POST, request.FILES)
        if form.is_valid():
            original_image = form.cleaned_data['original_image']
            secret_message = form.cleaned_data['secret_message']
            password = form.cleaned_data['password']

            # Create an EncryptedImage row with the original image
            eimg = EncryptedImage.objects.create(
                user=request.user,
                original_image=original_image
            )
            try:
                # Create stego
                stego_bytes = encrypt_and_embed_message(
                    eimg.original_image.path,
                    secret_message,
                    password
                )
                # Wrap in Django file
                stego_file = create_stego_django_file(stego_bytes, f"stego_{eimg.id}.png")
                eimg.stego_image.save(f"stego_{eimg.id}.png", stego_file, save=True)

                # Optionally store message hash
                eimg.message_hash = sha256_hash(secret_message.encode('utf-8'))
                eimg.save()

                messages.success(request, f"Encryption successful! Stego image ID: {eimg.id}")
                return redirect('index')
            except Exception as e:
                # If something fails, remove the partial record
                eimg.delete()
                messages.error(request, f"Encryption failed: {e}")
    else:
        form = EncryptionForm()
    return render(request, 'core/encrypt.html', {'form': form})

@login_required
def decrypt_list_view(request):
    """
    Show a list of available stego images (EncryptedImage with `stego_image`) 
    for the current user.
    """
    images = EncryptedImage.objects.filter(user=request.user).exclude(stego_image='')
    return render(request, 'core/decrypt_list.html', {'images': images})

@login_required
def decrypt_detail_view(request, image_id):
    """
    Show a form to input the password for a chosen stego image.
    Decrypt the message upon submission.
    """
    eimg = get_object_or_404(EncryptedImage, id=image_id, user=request.user)
    if request.method == 'POST':
        form = DecryptionPasswordForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            success, message = decrypt_message_from_stego(eimg.stego_image.path, password)
            if success:
                messages.success(request, f"Decrypted message: {message}")
            else:
                messages.error(request, message)
            return redirect('decrypt-list')
    else:
        form = DecryptionPasswordForm()
    return render(request, 'core/decrypt_detail.html', {'eimg': eimg, 'form': form})
