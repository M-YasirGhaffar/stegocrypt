# core/views.py

import base64
import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import FileResponse, HttpResponseForbidden
from django.core.files.temp import NamedTemporaryFile

from .models import Profile, EncryptedImage, SharedKey
from .forms import (
    RegisterForm,
    LoginForm,
    EncryptionForm,
    DecryptionPasswordForm,
    ShareForm,
    DecryptionUploadForm
)
from .utils_rsa import (
    generate_rsa_keypair,
    serialize_keypair,
    encrypt_private_key_with_user_password,
    decrypt_private_key_with_user_password,
    rsa_encrypt_with_public_key,
    rsa_decrypt_with_private_key
)
from .utils import sha256_hash
from .encryption import encrypt_and_embed_message, create_stego_django_file
from .decryption import decrypt_message_from_stego

def index(request):
    """
    Show a list of user's own images.
    """
    if request.user.is_authenticated:
        images = EncryptedImage.objects.filter(user=request.user)
        return render(request, 'core/index.html', {'images': images})
    return render(request, 'core/index.html')

def register_view(request):
    """
    Register a new user and store RSA keys.
    """
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            raw_password = form.cleaned_data['password']
            user.set_password(raw_password)
            user.save()

            # Generate RSA Keypair
            privkey, pubkey = generate_rsa_keypair()
            private_pem, public_pem = serialize_keypair(privkey, pubkey)

            # Encrypt private key with the user’s password
            encrypted_priv = encrypt_private_key_with_user_password(private_pem, raw_password)

            Profile.objects.create(
                user=user,
                public_key=public_pem.decode('utf-8'),
                encrypted_private_key=base64.b64encode(encrypted_priv).decode('utf-8')
            )

            messages.success(request, "Registration successful. You can now log in.")
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'core/register.html', {'form': form})

def login_view(request):
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
                messages.error(request, "Invalid credentials.")
    else:
        form = LoginForm()
    return render(request, 'core/login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.success(request, "Logged out.")
    return redirect('index')

@login_required
def encrypt_view(request):
    """
    Upload an original image + message, embed stego, store + share AES key w/owner.
    """
    if request.method == 'POST':
        form = EncryptionForm(request.POST, request.FILES)
        if form.is_valid():
            original_image = form.cleaned_data['original_image']
            secret_message = form.cleaned_data['secret_message']
            is_public = form.cleaned_data['is_public']
            pass_for_hash = form.cleaned_data['password']  # demonstration only

            # 1) Create record
            eimg = EncryptedImage.objects.create(
                user=request.user,
                original_image=original_image,
                is_public=is_public
            )
            try:
                # 2) Do stego
                stego_bytes, aes_key = encrypt_and_embed_message(
                    eimg.original_image.path,
                    secret_message
                )
                # 3) Save stego image
                stego_file = create_stego_django_file(stego_bytes, f"stego_{eimg.id}.png")
                eimg.stego_image.save(f"stego_{eimg.id}.png", stego_file, save=True)

                # 4) message hash
                eimg.message_hash = sha256_hash(secret_message.encode('utf-8'))
                eimg.save()

                # 5) store AES key for owner
                owner_profile = Profile.objects.get(user=request.user)
                pub_pem = owner_profile.public_key.encode('utf-8')
                enc_aes_key = rsa_encrypt_with_public_key(pub_pem, aes_key)
                SharedKey.objects.create(
                    image=eimg,
                    shared_with=request.user,
                    encrypted_aes_key=enc_aes_key
                )

                messages.success(request, f"Encrypted image saved (ID #{eimg.id}).")
                return redirect('index')
            except Exception as e:
                eimg.delete()
                messages.error(request, f"Encryption failed: {e}")
        else:
            messages.error(request, "Form invalid.")
    else:
        form = EncryptionForm()
    return render(request, 'core/encrypt.html', {'form': form})

@login_required
def decrypt_list_view(request):
    """
    List images user can decrypt (has a SharedKey).
    """
    shared_keys = SharedKey.objects.filter(shared_with=request.user)
    images = set()
    for sk in shared_keys:
        if sk.image.stego_image:
            images.add(sk.image)
    return render(request, 'core/decrypt_list.html', {'images': list(images)})

@login_required
def decrypt_detail_view(request, image_id):
    """
    Decrypt a chosen stego image by unlocking user's private key + retrieving AES key.
    """
    eimg = get_object_or_404(EncryptedImage, id=image_id)
    # Ensure user has a SharedKey
    try:
        sk = SharedKey.objects.get(image=eimg, shared_with=request.user)
    except SharedKey.DoesNotExist:
        messages.error(request, "You do not have permission to decrypt this image.")
        return redirect('decrypt-list')

    if request.method == 'POST':
        form = DecryptionPasswordForm(request.POST)
        if form.is_valid():
            user_password = form.cleaned_data['password']
            # Decrypt user's private key
            prof = Profile.objects.get(user=request.user)
            enc_priv_b64 = prof.encrypted_private_key
            enc_priv = base64.b64decode(enc_priv_b64)
            try:
                privkey = decrypt_private_key_with_user_password(enc_priv, user_password)
            except Exception as exc:
                messages.error(request, f"Could not unlock your private key: {exc}")
                return redirect('decrypt-list')

            # RSA-decrypt AES key
            try:
                aes_key = rsa_decrypt_with_private_key(privkey, sk.encrypted_aes_key)
            except Exception as exc:
                messages.error(request, f"Failed to retrieve AES key: {exc}")
                return redirect('decrypt-list')

            # Decrypt message from stego
            success, plaintext = decrypt_message_from_stego(eimg.stego_image.path, aes_key)
            if success:
                # Optional integrity check
                if eimg.message_hash and eimg.message_hash != sha256_hash(plaintext.encode('utf-8')):
                    messages.warning(request, "Message hash mismatch! Possible tampering.")
                else:
                    messages.success(request, f"Decrypted message: {plaintext}")
            else:
                messages.error(request, plaintext)
            return redirect('decrypt-list')
    else:
        form = DecryptionPasswordForm()

    return render(request, 'core/decrypt_detail.html', {'eimg': eimg, 'form': form})

@login_required
def share_image_view(request, image_id):
    """
    Owner re-enters password, retrieves AES key, re-encrypts for the recipient.
    Only allowed if is_public=True.
    """
    eimg = get_object_or_404(EncryptedImage, id=image_id, user=request.user)
    if not eimg.is_public:
        messages.error(request, "This image is private and cannot be shared.")
        return redirect('index')

    try:
        owner_sk = SharedKey.objects.get(image=eimg, shared_with=request.user)
    except SharedKey.DoesNotExist:
        messages.error(request, "No AES key found for your own image. Cannot share.")
        return redirect('index')

    if request.method == 'POST':
        form = ShareForm(request.POST)
        if form.is_valid():
            recipient_username = form.cleaned_data['recipient_username']
            owner_password = form.cleaned_data['owner_password']
            # Validate recipient
            try:
                recipient_user = User.objects.get(username=recipient_username)
            except User.DoesNotExist:
                messages.error(request, "Recipient user not found.")
                return redirect('index')

            # Decrypt owner's private key
            owner_profile = Profile.objects.get(user=request.user)
            enc_priv_b64 = owner_profile.encrypted_private_key
            enc_priv = base64.b64decode(enc_priv_b64)
            try:
                owner_privkey = decrypt_private_key_with_user_password(enc_priv, owner_password)
            except Exception as ex:
                messages.error(request, f"Could not unlock your private key: {ex}")
                return redirect('index')

            # Retrieve AES key
            try:
                aes_key = rsa_decrypt_with_private_key(owner_privkey, owner_sk.encrypted_aes_key)
            except Exception as ex:
                messages.error(request, f"Failed to retrieve your AES key: {ex}")
                return redirect('index')

            # Encrypt for recipient
            rec_profile = Profile.objects.get(user=recipient_user)
            pub_pem = rec_profile.public_key.encode('utf-8')
            try:
                enc_aes_key_for_recipient = rsa_encrypt_with_public_key(pub_pem, aes_key)
            except Exception as ex:
                messages.error(request, f"Could not encrypt AES key: {ex}")
                return redirect('index')

            # Create SharedKey
            SharedKey.objects.create(
                image=eimg,
                shared_with=recipient_user,
                encrypted_aes_key=enc_aes_key_for_recipient
            )
            messages.success(request, f"Image #{eimg.id} shared with {recipient_username}!")
            return redirect('index')
        else:
            messages.error(request, "Form invalid.")
    else:
        form = ShareForm()

    return render(request, 'core/share_image.html', {'form': form, 'image': eimg})

@login_required
def download_stego_image(request, image_id):
    """
    Let user download stego image if owner or has SharedKey.
    """
    eimg = get_object_or_404(EncryptedImage, id=image_id)
    # Check permissions
    if eimg.user != request.user:
        try:
            SharedKey.objects.get(image=eimg, shared_with=request.user)
        except SharedKey.DoesNotExist:
            return HttpResponseForbidden("You do not have permission to download this image.")
    if not eimg.stego_image:
        messages.error(request, "No stego image found.")
        return redirect('index')

    return FileResponse(eimg.stego_image.open('rb'), as_attachment=True,
                        filename=f"stego_{eimg.id}.png")

@login_required
def shared_gallery_view(request):
    """
    Lists images that are is_public=True AND user has a SharedKey for them.
    Renamed from 'public_gallery_view'.
    """
    shared_keys = SharedKey.objects.filter(shared_with=request.user, image__is_public=True)
    images = set(sk.image for sk in shared_keys if sk.image.stego_image)
    return render(request, 'core/public_gallery.html', {'images': list(images)})

@login_required
def decrypt_upload_view(request):
    """
    Allows user to upload a stego image (not from DB) and attempt to decrypt 
    by either a user private key or a shared pass. 
    This is an optional scenario if you want to support external stego files.
    """
    if request.method == 'POST':
        form = DecryptionUploadForm(request.POST, request.FILES)
        if form.is_valid():
            stego_file = form.cleaned_data['stego_image_file']
            password = form.cleaned_data['password']

            # In many setups, you'd need an actual AES key or a user key. For demonstration,
            # we might handle it differently. If user is using their private key, 
            # they'd do the same RSA approach. 
            # Or we do a simpler approach: if you used a "shared password" for stego embedding.

            # Example: Save the stego temporarily, then do a direct LSB reveal if we used
            # a "shared password" (but that conflicts with the RSA approach). 
            # For demonstration, we can just show how you'd handle the file:
            temp_file = NamedTemporaryFile(delete=False, suffix=".png")
            for chunk in stego_file.chunks():
                temp_file.write(chunk)
            temp_file.close()

            # If your system is purely RSA-based, 
            # you'd also need the user's private key here. 
            messages.warning(request, "Decrypting externally uploaded images not fully implemented in RSA approach.")
            return redirect('index')
        else:
            messages.error(request, "Invalid form.")
    else:
        form = DecryptionUploadForm()

    return render(request, 'core/decrypt_upload.html', {'form': form})
