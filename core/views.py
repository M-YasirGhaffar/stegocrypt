# core/views.py
import os
import hashlib
import secrets
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponseForbidden
from django.core.files.temp import NamedTemporaryFile
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.http import JsonResponse
from .utils import create_thumbnail, get_image_data


from .models import EncryptedImage
from .forms import (
    RegisterForm,
    LoginForm,
    EncryptionForm,
    DecryptSingleFieldForm,
    ShareForm,
    DecryptionUploadForm
)
from .utils import (
    sha256_hash,
    encrypt_with_master_key,
    decrypt_with_master_key,
    aes_encrypt,
    aes_decrypt
)
from .encryption import encrypt_and_embed_message, create_stego_django_file
from .decryption import decrypt_message_from_stego

@login_required
def index(request):
    """Modified index view to include image previews"""
    if not request.user.is_authenticated:
        return render(request, 'core/index.html')

    my_images = EncryptedImage.objects.filter(user=request.user)
    shared_images = EncryptedImage.objects.filter(shared_with=request.user).exclude(user=request.user)

    # Generate image data with previews
    my_images_data = []
    for img in my_images:
        img_data = get_image_data(img)
        if img_data:
            my_images_data.append(img_data)

    shared_images_data = []
    for img in shared_images:
        img_data = get_image_data(img)
        if img_data:
            shared_images_data.append(img_data)

    context = {
        'user_info': {
            'username': request.user.username,
            'email': request.user.email,
            'date_joined': request.user.date_joined.isoformat(),
            'total_images': len(my_images_data),
            'shared_with_me': len(shared_images_data)
        },
        'my_images': my_images_data,
        'shared_images': shared_images_data,
        'enc_form': EncryptionForm(),
        'dec_form': DecryptSingleFieldForm(),
        'last_decrypted_msg': request.session.pop('last_decrypted_msg', None),
        'last_decrypted_img_id': request.session.pop('last_decrypted_img_id', None),
        'last_decrypted_error': request.session.pop('last_decrypted_error', None)
    }

    # Return JSON for AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse(context)
    return render(request, 'core/index.html', context)

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            raw_password = form.cleaned_data['password']
            user.set_password(raw_password)
            user.email = form.cleaned_data['email']
            user.save()
            messages.success(request, "Registration successful! Please log in.")
            return redirect('login')
        else:
            for field, errs in form.errors.items():
                messages.error(request, f"{field}: {errs}")
    else:
        form = RegisterForm()
    return render(request, 'core/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            uname = form.cleaned_data['username']
            pwd = form.cleaned_data['password']
            user = authenticate(request, username=uname, password=pwd)
            if user:
                login(request, user)
                messages.success(request, "Logged in successfully.")
                return redirect('index')
            else:
                messages.error(request, "Invalid username/password.")
    else:
        form = LoginForm()
    return render(request, 'core/login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('index')

@login_required
def post_encrypt(request):
    if request.method == 'POST':
        form = EncryptionForm(request.POST, request.FILES)
        if form.is_valid():
            original_image = form.cleaned_data['original_image']
            secret_message = form.cleaned_data['secret_message']
            pass_key = form.cleaned_data['pass_key']
            is_public = form.cleaned_data['is_public']

            import secrets
            import hashlib
            eimg = EncryptedImage.objects.create(user=request.user, original_image=original_image, is_public=is_public)
            try:
                # 1) build stego
                stego_bytes = encrypt_and_embed_message(eimg.original_image.path, secret_message, pass_key)
                stfile = create_stego_django_file(stego_bytes, f"stego_{eimg.id}.png")
                eimg.stego_image.save(f"stego_{eimg.id}.png", stfile, save=True)

                # 2) store pass_key hashed
                salt = secrets.token_hex(8)
                pass_key_hash = hashlib.sha256((pass_key + salt).encode('utf-8')).hexdigest()
                eimg.pass_key_salt = salt
                eimg.pass_key_hash = pass_key_hash

                # 3) store pass_key for owner in DB, encrypted with system-level master key
                from .utils import encrypt_with_master_key
                iv, ciph = encrypt_with_master_key(pass_key.encode('utf-8'))
                eimg.encrypted_key_for_owner = ciph
                eimg.encrypted_key_iv = iv

                # 4) store message_hash
                eimg.message_hash = sha256_hash(secret_message.encode('utf-8'))
                eimg.save()

                messages.success(request, f"Image {eimg.id} encrypted & saved!")
            except Exception as ex:
                eimg.delete()
                messages.error(request, f"Encryption failed: {ex}")
        else:
            for field, errs in form.errors.items():
                messages.error(request, f"{field}: {errs}")
    return redirect('index')

@login_required
def post_decrypt(request, image_id):
    eimg = get_object_or_404(EncryptedImage, id=image_id)
    # check permission
    if eimg.user != request.user and request.user not in eimg.shared_with.all():
        messages.error(request, "No permission to decrypt.")
        return redirect('index')

    pass_or_pw = request.POST.get('pass_or_pw', '').strip()
    if not pass_or_pw:
        messages.error(request, "Please provide pass-key or account password.")
        return redirect('index')

    import hashlib

    # 1) pass-key approach
    salt = eimg.pass_key_salt or ''
    test_hash = hashlib.sha256((pass_or_pw + salt).encode('utf-8')).hexdigest()
    if test_hash == eimg.pass_key_hash:
        # correct pass-key
        success, plaintext = decrypt_message_from_stego(eimg.stego_image.path, pass_or_pw)
        if success:
            if eimg.message_hash and eimg.message_hash != sha256_hash(plaintext.encode('utf-8')):
                request.session['last_decrypted_error'] = "Hash mismatch! Possibly tampered."
            else:
                request.session['last_decrypted_msg'] = plaintext
                request.session['last_decrypted_img_id'] = eimg.id
        else:
            request.session['last_decrypted_error'] = plaintext
        return redirect('index')

    # 2) else if user == owner => try account password approach
    if eimg.user == request.user:
        # Check if typed pass_or_pw is the correct user password
        from django.contrib.auth.hashers import check_password
        if check_password(pass_or_pw, request.user.password):
            # decrypt real pass-key from DB
            from .utils import decrypt_with_master_key
            iv = eimg.encrypted_key_iv
            ciph = eimg.encrypted_key_for_owner
            if not iv or not ciph:
                request.session['last_decrypted_error'] = "No pass-key stored for the owner."
                return redirect('index')

            try:
                real_pass_key = decrypt_with_master_key(iv, ciph).decode('utf-8')
                success, plaintext = decrypt_message_from_stego(eimg.stego_image.path, real_pass_key)
                if success:
                    if eimg.message_hash and eimg.message_hash != sha256_hash(plaintext.encode('utf-8')):
                        request.session['last_decrypted_error'] = "Hash mismatch! Possibly tampered."
                    else:
                        request.session['last_decrypted_msg'] = plaintext
                        request.session['last_decrypted_img_id'] = eimg.id
                else:
                    request.session['last_decrypted_error'] = plaintext
            except Exception as ex:
                request.session['last_decrypted_error'] = f"Could not decrypt the pass-key: {ex}"
        else:
            request.session['last_decrypted_error'] = "Incorrect account password."
    else:
        request.session['last_decrypted_error'] = "Incorrect pass-key."

    return redirect('index')

@login_required
def download_stego_image(request, image_id):
    eimg = get_object_or_404(EncryptedImage, id=image_id)
    if eimg.user != request.user and request.user not in eimg.shared_with.all():
        return HttpResponseForbidden("No permission to download.")
    if not eimg.stego_image:
        messages.error(request, "No stego image found.")
        return redirect('index')
    return FileResponse(eimg.stego_image.open('rb'), as_attachment=True, filename=f"stego_{eimg.id}.png")

@login_required
def share_image_view(request, image_id):
    eimg = get_object_or_404(EncryptedImage, id=image_id)
    if eimg.user != request.user:
        messages.error(request, "Only the owner can share.")
        return redirect('index')
    if not eimg.is_public:
        messages.error(request, "This image is private and cannot be shared.")
        return redirect('index')

    if request.method == 'POST':
        form = ShareForm(request.POST)
        if form.is_valid():
            rec_user = form.cleaned_data['recipient_username']
            try:
                recipient = User.objects.get(username=rec_user)
            except User.DoesNotExist:
                messages.error(request, "User not found.")
                return redirect('index')
            eimg.shared_with.add(recipient)
            eimg.save()
            messages.success(request, f"Image #{eimg.id} shared with {rec_user}!")
        else:
            messages.error(request, "Form invalid.")
        return redirect('index')
    else:
        form = ShareForm()
    return render(request, 'core/share_image.html', {'image': eimg, 'form': form})

@login_required
def decrypt_upload_view(request):
    if request.method == 'POST':
        form = DecryptionUploadForm(request.POST, request.FILES)
        if form.is_valid():
            stego_file = form.cleaned_data['stego_image_file']
            pass_or_pw = form.cleaned_data['pass_or_pw'].strip()
            if not pass_or_pw:
                messages.error(request, "Please provide a pass-key.")
                return redirect('index')

            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
                for chunk in stego_file.chunks():
                    tmp.write(chunk)
            temp_path = tmp.name

            try:
                success, plaintext = decrypt_message_from_stego(temp_path, pass_or_pw)
                if success:
                    messages.success(request, f"Decrypted message: {plaintext}")
                else:
                    messages.error(request, plaintext)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

            return redirect('index')
        else:
            messages.error(request, "Form invalid.")
            return redirect('index')
    else:
        form = DecryptionUploadForm()
    return render(request, 'core/decrypt_upload.html', {'form': form})

@login_required
def get_user_info(request):
    """Return current user information"""
    user = request.user
    return JsonResponse({
        'username': user.username,
        'email': user.email,
        'date_joined': user.date_joined.isoformat(),
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'total_images': EncryptedImage.objects.filter(user=user).count(),
        'shared_with_me': EncryptedImage.objects.filter(shared_with=user).count()
    })
    
@login_required
def get_image_preview(request, image_id):
    """Return image preview and metadata"""
    eimg = get_object_or_404(EncryptedImage, id=image_id)
    
    # Check permissions
    if eimg.user != request.user and request.user not in eimg.shared_with.all():
        return HttpResponseForbidden("No permission to view this image.")
    
    image_data = get_image_data(eimg)
    if image_data:
        return JsonResponse(image_data)
    return JsonResponse({'error': 'Could not generate preview'}, status=400)
