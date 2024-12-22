# core/views.py

import base64
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

from .models import Profile, EncryptedImage, SharedKey
from .forms import (
    RegisterForm, 
    LoginForm, 
    EncryptionForm,
    DecryptionPasswordForm,
    ShareForm
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
    Show a list of user's own images (and optional link to Public Gallery).
    """
    if request.user.is_authenticated:
        images = EncryptedImage.objects.filter(user=request.user)
        return render(request, 'core/index.html', {'images': images})
    return render(request, 'core/index.html')


def register_view(request):
    """
    Register a new user, generate RSA keys, store the private key encrypted with user password.
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

            # Store in Profile
            Profile.objects.create(
                user=user,
                public_key=public_pem.decode('utf-8'),
                encrypted_private_key=base64.b64encode(encrypted_priv).decode('utf-8')
            )

            messages.success(request, "Registration successful. You can now login.")
            return redirect('login')
        else:
            messages.error(request, "Registration failed. Please correct the errors below.")
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
    Upload an original image, embed a message, store stego image, 
    keep AES key in SharedKey for the owner.
    """
    if request.method == 'POST':
        form = EncryptionForm(request.POST, request.FILES)
        if form.is_valid():
            original_image = form.cleaned_data['original_image']
            secret_message = form.cleaned_data['secret_message']
            is_public = form.cleaned_data['is_public']
            # For demonstration, user-supplied "password" can be used for hashing/integrity? 
            # But we now rely on RSA for encryption. We'll still store a message_hash.

            # 1) Create a record
            eimg = EncryptedImage.objects.create(
                user=request.user,
                original_image=original_image,
                is_public=is_public
            )
            try:
                # 2) Perform stego with a random AES key
                stego_bytes, aes_key = encrypt_and_embed_message(
                    eimg.original_image.path,
                    secret_message
                )
                # 3) Save stego image
                stego_file = create_stego_django_file(stego_bytes, f"stego_{eimg.id}.png")
                eimg.stego_image.save(f"stego_{eimg.id}.png", stego_file, save=True)

                # 4) Store message hash for integrity
                eimg.message_hash = sha256_hash(secret_message.encode('utf-8'))
                eimg.save()

                # 5) Also store the AES key for the owner
                #    We RSA-encrypt the AES key with the owner's public key
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
    Show images that this user can decrypt 
    (i.e. images that have a SharedKey row for user).
    """
    # Filter SharedKey for this user
    shared_keys = SharedKey.objects.filter(shared_with=request.user)
    # Extract the images
    images = [sk.image for sk in shared_keys if sk.image.stego_image]
    # Could also exclude duplicates with a set
    return render(request, 'core/decrypt_list.html', {'images': images})


@login_required
def decrypt_detail_view(request, image_id):
    """
    Use RSA to decrypt the AES key from SharedKey, 
    then decrypt the stego image with that AES key.
    """
    eimg = get_object_or_404(EncryptedImage, id=image_id)
    # Ensure user is in SharedKey
    try:
        sk = SharedKey.objects.get(image=eimg, shared_with=request.user)
    except SharedKey.DoesNotExist:
        messages.error(request, "You do not have permission to decrypt this image.")
        return redirect('decrypt-list')

    if request.method == 'POST':
        form = DecryptionPasswordForm(request.POST)
        if form.is_valid():
            user_password = form.cleaned_data['password']
            # 1) Decrypt user's private key
            try:
                prof = Profile.objects.get(user=request.user)
            except Profile.DoesNotExist:
                messages.error(request, "Your profile does not exist. Please contact support.")
                return redirect('decrypt-list')

            enc_priv_b64 = prof.encrypted_private_key
            enc_priv = base64.b64decode(enc_priv_b64)
            try:
                privkey = decrypt_private_key_with_user_password(enc_priv, user_password)
            except Exception as exc:
                messages.error(request, f"Could not unlock your private key: {exc}")
                return redirect('decrypt-list')

            # 2) RSA-decrypt the AES key
            try:
                aes_key = rsa_decrypt_with_private_key(privkey, sk.encrypted_aes_key)
            except Exception as ex:
                messages.error(request, f"Failed to decrypt AES key: {ex}")
                return redirect('decrypt-list')

            # 3) Decrypt the message from stego image
            success, plaintext = decrypt_message_from_stego(eimg.stego_image.path, aes_key)
            if success:
                # Optional integrity check
                if eimg.message_hash and eimg.message_hash != sha256_hash(plaintext.encode('utf-8')):
                    messages.warning(request, "Warning: Message hash mismatch. Possible tampering!")
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
    Let the owner share an image with another user by RSA-encrypting the AES key 
    for the recipient's public key. The owner must re-enter their password to unlock 
    their private key so we can retrieve the AES key from SharedKey.
    """
    eimg = get_object_or_404(EncryptedImage, id=image_id, user=request.user)

    # The owner should have a SharedKey row for themselves, containing the RSA-encrypted AES key.
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

            # Step 1: Look up the recipient user
            try:
                recipient_user = User.objects.get(username=recipient_username)
            except User.DoesNotExist:
                messages.error(request, "Recipient user not found.")
                return redirect('index')

            # Prevent sharing with oneself
            if recipient_user == request.user:
                messages.error(request, "You cannot share an image with yourself.")
                return redirect('index')

            # Step 2: Decrypt the owner's private key using the provided password
            try:
                owner_profile = Profile.objects.get(user=request.user)
            except Profile.DoesNotExist:
                messages.error(request, "Your profile does not exist. Please contact support.")
                return redirect('index')

            enc_priv_b64 = owner_profile.encrypted_private_key
            if not enc_priv_b64:
                messages.error(request, "Your private key is not available. Please contact support.")
                return redirect('index')

            try:
                enc_priv = base64.b64decode(enc_priv_b64)
            except Exception as ex:
                messages.error(request, f"Failed to decode your encrypted private key: {ex}")
                return redirect('index')

            try:
                owner_privkey = decrypt_private_key_with_user_password(enc_priv, owner_password)
            except Exception as ex:
                messages.error(request, f"Could not unlock your private key with the provided password: {ex}")
                return redirect('index')

            # Step 3: RSA-decrypt the AES key from the owner's SharedKey
            try:
                aes_key = rsa_decrypt_with_private_key(owner_privkey, owner_sk.encrypted_aes_key)
            except Exception as ex:
                messages.error(request, f"Failed to decrypt AES key: {ex}")
                return redirect('index')

            # Step 4: Encrypt the AES key with the recipient's public key
            try:
                recipient_profile = Profile.objects.get(user=recipient_user)
            except Profile.DoesNotExist:
                messages.error(request, "Recipient user's profile does not exist.")
                return redirect('index')

            recipient_pub_pem = recipient_profile.public_key.encode('utf-8')
            try:
                enc_aes_key_for_recipient = rsa_encrypt_with_public_key(recipient_pub_pem, aes_key)
            except Exception as ex:
                messages.error(request, f"Could not encrypt AES key for {recipient_username}: {ex}")
                return redirect('index')

            # Step 5: Create a SharedKey for the recipient
            SharedKey.objects.create(
                image=eimg,
                shared_with=recipient_user,
                encrypted_aes_key=enc_aes_key_for_recipient
            )

            messages.success(request, f"Image #{eimg.id} shared with {recipient_username} successfully!")
            return redirect('index')
        else:
            messages.error(request, "Form invalid. Please correct the errors below.")
    else:
        form = ShareForm()

    return render(request, 'core/share_image.html', {'form': form, 'image': eimg})


def public_gallery_view(request):
    """Show publicly visible images."""
    images = EncryptedImage.objects.filter(is_public=True)
    return render(request, 'core/public_gallery.html', {'images': images})
