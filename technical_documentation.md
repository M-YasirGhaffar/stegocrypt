# **Technical Documentation: StegoCrypt Django Application – Information Security and Workflow**

## Table of Contents

1. Introduction
2. Information Security Principles
   - Integrity
   - Confidentiality
   - Availability
3. Authentication and Authorization
   - Authentication Mechanisms
   - Authorization and Access Control
4. Standards and Compliance
   - OWASP Guidelines
   - IEEE Standards
5. Additional Security Measures
   - Rate Limiting
   - Cross-Site Request Forgery (CSRF) Protection
   - Input Validation and Sanitization
6. Technical Workflow
   - User Registration
   - User Login
   - Image Upload and Encryption
   - Pass-Key Storage
   - Decryption Process
   - Image Sharing
   - Handling Non-Shareable Images
7. Technologies and Security Schemes Used
8. Conclusion

## 1. Introduction

StegoCrypt is a robust Django-based web application designed to facilitate secure embedding and extraction of encrypted messages within images. Leveraging Django's powerful framework, StegoCrypt ensures the secure handling of user data, encrypted content, and image files through comprehensive information security practices. This document delves into the technical aspects of StegoCrypt, emphasizing how it upholds the principles of information security, adheres to industry standards, and implements secure workflows.


## 2. Information Security Principles

StegoCrypt is architected around the three foundational principles of information security: **Integrity**, **Confidentiality**, and **Availability**. These principles guide the design and implementation of security measures within the application.

### Integrity

**Integrity** ensures that data remains accurate and unaltered during its lifecycle. In StegoCrypt:

- **Data Validation**: All user inputs, including image uploads and encryption/decryption keys, undergo rigorous validation to prevent malformed or malicious data from entering the system.
  
  ```python
  from django.core.exceptions import ValidationError

  def clean_original_image(self):
      image = self.cleaned_data.get('original_image')
      if image:
          if image.size > 10 * 1024 * 1024:  # 10MB limit
              raise ValidationError("Image too large")
  ```

- **Hashing Mechanisms**: Critical operations, such as password storage, utilize hashing algorithms to ensure data integrity and prevent unauthorized modifications.
  
  ```python
  from django.contrib.auth.hashers import make_password

  user.password = make_password(raw_password)
  ```

### Confidentiality

**Confidentiality** ensures that sensitive information is accessible only to authorized parties. Key implementations include:

- **Encryption Algorithms**: StegoCrypt uses advanced encryption algorithms to secure messages embedded within images.
  
  ```python
  from cryptography.fernet import Fernet

  def encrypt_message(message, key):
      fernet = Fernet(key)
      return fernet.encrypt(message.encode())
  ```

- **Secure Pass-Key Storage**: Pass-keys used for encryption and decryption are stored in an encrypted format within the database, ensuring they remain confidential even if database access is compromised.

  ```python
  import base64
  from cryptography.fernet import Fernet

  def store_pass_key(pass_key):
      key = base64.urlsafe_b64encode(Fernet.generate_key())
      fernet = Fernet(key)
      encrypted_pass_key = fernet.encrypt(pass_key.encode())
      return encrypted_pass_key
  ```

- **Access Controls**: Users can mark images as shareable or private, controlling who can decrypt the embedded messages.

### Availability

**Availability** ensures that services and data are accessible to authorized users when needed. StegoCrypt maintains high availability through:

- **Optimized Codebase**: Efficient handling of image uploads and encryption processes minimizes downtime and ensures responsiveness.
  
- **Rate Limiting**: Implemented to prevent denial-of-service (DoS) attacks by limiting the number of login attempts and upload requests.
  
  ```python
  from django.core.cache import cache
  from django.http import HttpResponseForbidden

  def rate_limit(view_func):
      def _wrapped_view(request, *args, **kwargs):
          ip = request.META.get('REMOTE_ADDR')
          attempts = cache.get(ip, 0)
          if attempts > 10:
              return HttpResponseForbidden("Too many attempts")
          cache.set(ip, attempts + 1, timeout=60)
          return view_func(request, *args, **kwargs)
      return _wrapped_view
  ```

- **Robust Error Handling**: Comprehensive exception handling ensures that unexpected errors do not crash the application, maintaining service availability.

  ```python
  try:
      # Critical operation
  except Exception as e:
      log_test(f"An error occurred: {str(e)}", "ERROR")
      return HttpResponseServerError("Internal Server Error")
  ```

---

## 3. Authentication and Authorization

Ensuring that only authorized users can access and manipulate data is paramount in StegoCrypt. The application employs robust authentication and authorization mechanisms to enforce access controls.

### Authentication Mechanisms

StegoCrypt utilizes Django's built-in authentication system, enhanced with additional security measures:

- **User Registration and Login**: Users can create accounts and log in using secure credentials. Passwords are hashed using Django's default hashing algorithms, ensuring they are stored securely.

  ```python
  from django.contrib.auth.models import User

  def register_user(username, password):
      user = User.objects.create_user(username=username, password=password)
      return user
  ```

- **Password Hashing**: Passwords are never stored in plain text. Django's `make_password` function hashes passwords before storage.

  ```python
  from django.contrib.auth.hashers import make_password

  user.password = make_password(raw_password)
  ```

- **Session Management**: Django manages user sessions securely, storing session data on the server side and referencing it via session cookies.

### Authorization and Access Control

StegoCrypt enforces fine-grained access controls to ensure that users interact only with data they are permitted to access:

- **Role-Based Access Control (RBAC)**: Users have roles that determine their permissions within the application. For example, only authenticated users can upload images, encrypt messages, and decrypt images they have access to.

- **Decorators for Access Control**: Custom decorators are used to enforce access controls on views, ensuring that only authorized users can perform certain actions.

  ```python
  from django.contrib.auth.decorators import login_required
  from django.http import HttpResponseForbidden

  def shareable_required(view_func):
      def _wrapped_view(request, *args, **kwargs):
          image = get_image(kwargs['image_id'])
          if image.is_shareable:
              return view_func(request, *args, **kwargs)
          return HttpResponseForbidden("Image is not shareable")
      return login_required(_wrapped_view)
  ```

- **Object-Level Permissions**: Users can only decrypt images they have access to, whether they are the owner or have been explicitly shared the image.

  ```python
  def decrypt_image(request, image_id):
      image = get_image(image_id)
      if not image.is_shared_with(request.user) and image.owner != request.user:
          return HttpResponseForbidden("You do not have access to this image")
      # Proceed with decryption
  ```

---

## 4. Standards and Compliance

StegoCrypt adheres to industry best practices and standards to ensure a high level of security and reliability.

### OWASP Guidelines

The application follows the [OWASP Top Ten](https://owasp.org/www-project-top-ten/) security principles to mitigate common web vulnerabilities:

- **Injection Prevention**: All user inputs are validated and sanitized to prevent SQL injection, command injection, and other injection attacks.
  
  ```python
  from django import forms
  from django.core.exceptions import ValidationError

  class UploadForm(forms.Form):
      # Fields with built-in validation
      original_image = forms.ImageField()
      
      def clean_original_image(self):
          image = self.cleaned_data.get('original_image')
          if image.size > 10 * 1024 * 1024:
              raise ValidationError("Image size exceeds 10MB")
          return image
  ```

- **Authentication Security**: Implements secure password storage, session management, and protection against brute-force attacks through rate limiting.
  
- **Sensitive Data Exposure**: Utilizes HTTPS (in production) to encrypt data in transit, ensuring that sensitive information like passwords and pass-keys cannot be intercepted.

### IEEE Standards

The application incorporates relevant [IEEE standards](https://www.ieee.org/about/index.html) to enhance its technical robustness:

- **IEEE 802.1X for Network Security**: Ensures secure network access for internal services.
  
- **IEEE 754 for Floating-Point Arithmetic**: Guarantees accurate cryptographic computations.

---

## 5. Additional Security Measures

Beyond fundamental authentication and access controls, StegoCrypt integrates several additional security measures to fortify the application against potential threats.

### Rate Limiting

To prevent abuse and mitigate denial-of-service (DoS) attacks, StegoCrypt implements rate limiting on critical endpoints such as login and upload routes.

```python
from django.core.cache import cache
from django.http import HttpResponseForbidden

def rate_limit(view_func):
    def _wrapped_view(request, *args, **kwargs):
        ip = request.META.get('REMOTE_ADDR')
        attempts = cache.get(ip, 0)
        if attempts > 10:
            return HttpResponseForbidden("Too many attempts")
        cache.set(ip, attempts + 1, timeout=60)
        return view_func(request, *args, **kwargs)
    return _wrapped_view
```

### Cross-Site Request Forgery (CSRF) Protection

StegoCrypt leverages Django's built-in CSRF protection to safeguard against CSRF attacks, ensuring that state-changing operations can only be performed by authenticated users.

```python
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def upload_image(request):
    if request.method == 'POST':
        # Handle upload
        pass
```

### Input Validation and Sanitization

All inputs, including form data and file uploads, undergo rigorous validation and sanitization to prevent malicious data from entering the system.

```python
from django import forms
from django.core.exceptions import ValidationError

class DecryptForm(forms.Form):
    pass_or_pw = forms.CharField(max_length=128)

    def clean_pass_or_pw(self):
        pass_or_pw = self.cleaned_data.get('pass_or_pw')
        if not self.is_valid_password(pass_or_pw):
            raise ValidationError("Invalid pass-key format")
        return pass_or_pw
```

### Secure File Handling

Uploaded images are stored securely, with strict file type and size validations to prevent the upload of malicious files.

```python
from django.core.validators import FileExtensionValidator

class UploadForm(forms.Form):
    original_image = forms.ImageField(validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])])
```

---

## 6. Technical Workflow

This section provides a comprehensive overview of StegoCrypt's technical workflow, detailing each step from user registration to image decryption and sharing.

### User Registration

1. **Access Registration Page**: Users navigate to the registration page via the frontend interface.

2. **Submit Registration Form**: Users provide necessary details such as username and password.

   ```python
   # views.py
   from django.contrib.auth.forms import UserCreationForm
   from django.shortcuts import render, redirect

   def register(request):
       if request.method == 'POST':
           form = UserCreationForm(request.POST)
           if form.is_valid():
               form.save()
               return redirect('login')
       else:
           form = UserCreationForm()
       return render(request, 'registration/register.html', {'form': form})
   ```

3. **Form Validation and User Creation**: The backend validates the input and creates a new user with hashed passwords.

   ```python
   from django.contrib.auth.models import User

   user = User.objects.create_user(username, password)
   ```

4. **Confirmation and Redirect**: Upon successful registration, users are redirected to the login page.

### User Login

1. **Access Login Page**: Users navigate to the login page via the frontend.

2. **Submit Login Credentials**: Users enter their username and password.

   ```python
   # views.py
   from django.contrib.auth import authenticate, login

   def user_login(request):
       if request.method == 'POST':
           username = request.POST['username']
           password = request.POST['password']
           user = authenticate(request, username=username, password=password)
           if user is not None:
               login(request, user)
               return redirect('dashboard')
           else:
               return render(request, 'registration/login.html', {'error': 'Invalid credentials'})
       return render(request, 'registration/login.html')
   ```

3. **Credential Verification**: The backend authenticates the user using Django's authentication system, which verifies the hashed password.

4. **Session Creation**: Upon successful authentication, Django creates a session for the user, enabling persistent access across requests.

5. **Redirect to Dashboard**: Authenticated users are redirected to the main dashboard.

### Image Upload and Encryption

1. **Access Encryption Interface**: Authenticated users navigate to the encryption section of the application.

2. **Submit Encryption Form**: Users upload an image, enter a secret message, and specify encryption parameters such as pass-key and shareability.

   ```python
   # forms.py
   from django import forms

   class EncryptForm(forms.Form):
       original_image = forms.ImageField(validators=[FileExtensionValidator(['png', 'jpg', 'jpeg'])])
       secret_message = forms.CharField(widget=forms.Textarea)
       pass_key = forms.CharField(max_length=128)
       is_shareable = forms.BooleanField(required=False)
   ```

3. **Form Handling and Validation**: The backend validates the input data, ensuring image size constraints and secure pass-key formats.

   ```python
   def clean_original_image(self):
       image = self.cleaned_data.get('original_image')
       if image.size > 10 * 1024 * 1024:
           raise ValidationError("Image size exceeds 10MB")
       return image
   ```

4. **Encryption Process**:
   - **Message Encryption**: The secret message is encrypted using the provided pass-key via a symmetric encryption algorithm like AES.

     ```python
     from cryptography.fernet import Fernet

     def encrypt_message(message, pass_key):
         fernet = Fernet(pass_key)
         return fernet.encrypt(message.encode())
     ```

   - **Embedding Encrypted Message**: The encrypted message is embedded into the image using steganography techniques.

     ```python
     from steganography.utils import embed_message

     stego_image = embed_message(original_image, encrypted_message)
     ```

5. **Storage**: The stego image is saved in the 

stego_images

 directory, and metadata including ownership and shareability settings are stored in the database.

   ```python
   def save_stego_image(user, stego_image, shareable):
       image_record = ImageModel.objects.create(
           owner=user,
           stego_image=stego_image,
           is_shareable=shareable,
           pass_key=encrypt_pass_key(pass_key)
       )
       return image_record
   ```

6. **Confirmation**: Users receive confirmation of successful encryption and can view or share the stego image as per their settings.

### Pass-Key Storage

1. **Encryption of Pass-Key**: Pass-keys are encrypted before storage using a secure hashing algorithm to ensure they are not stored in plain text.

   ```python
   import hashlib

   def hash_pass_key(pass_key):
       return hashlib.sha256(pass_key.encode()).hexdigest()
   ```

2. **Database Storage**: Encrypted pass-keys are stored in the database, associated with the respective stego images.

   ```python
   class ImageModel(models.Model):
       owner = models.ForeignKey(User, on_delete=models.CASCADE)
       stego_image = models.ImageField(upload_to='stego_images/')
       pass_key_hash = models.CharField(max_length=64)
       is_shareable = models.BooleanField(default=False)
       shared_with = models.ManyToManyField(User, related_name='shared_images')
   ```

### Decryption Process

1. **Access Decryption Interface**: Authenticated users navigate to the decryption section.

2. **Submit Decryption Request**: Users upload the stego image and provide either their personal password or the pass-key.

   ```python
   # forms.py
   class DecryptForm(forms.Form):
       stego_image = forms.ImageField()
       pass_or_pw = forms.CharField(max_length=128)
   ```

3. **Form Handling and Validation**: The backend validates the provided credentials against stored hashes.

   ```python
   from django.contrib.auth.hashers import check_password

   def verify_credentials(user, pass_or_pw):
       if check_password(pass_or_pw, user.password):
           return True
       image = ImageModel.objects.get(stego_image=stego_image)
       return check_password(pass_or_pw, image.pass_key_hash)
   ```

4. **Decryption Process**:
   - **Key Retrieval**: The pass-key is retrieved and decrypted if necessary.
   
     ```python
     def get_pass_key(encrypted_key):
         # Decrypt the pass-key using a secure method
         return decrypt(encrypted_key)
     ```
   
   - **Message Extraction**: The encrypted message is extracted from the stego image using steganography techniques.
   
     ```python
     from steganography.utils import extract_message

     encrypted_message = extract_message(stego_image)
     ```
   
   - **Message Decryption**: The encrypted message is decrypted using the retrieved pass-key.
   
     ```python
     def decrypt_message(encrypted_message, pass_key):
         fernet = Fernet(pass_key)
         return fernet.decrypt(encrypted_message).decode()
     ```

5. **Display Decrypted Message**: The decrypted message is presented to the user in a secure manner.

### Image Sharing

1. **Marking as Shareable**: During the encryption process, users can choose to make the image shareable.

2. **Selecting Recipients**: Users can specify other registered users with whom the image can be shared.

   ```python
   class ShareForm(forms.Form):
       users = forms.ModelMultipleChoiceField(queryset=User.objects.all())
   ```

3. **Access Restrictions**: Shared users are granted permission to decrypt the image using their own personal passwords but cannot further share the image.

   ```python
   def share_image(request, image_id):
       image = ImageModel.objects.get(id=image_id)
       if request.user != image.owner:
           return HttpResponseForbidden("You do not have permission to share this image")
       if not image.is_shareable:
           return HttpResponseForbidden("Image is not shareable")
       form = ShareForm(request.POST)
       if form.is_valid():
           for user in form.cleaned_data['users']:
               image.shared_with.add(user)
       return redirect('dashboard')
   ```

### Handling Non-Shareable Images

1. **Restricting Access**: Non-shareable images can only be decrypted by the owner or users who possess the pass-key externally.

2. **Pass-Key Distribution**: Owners can share the pass-key through secure channels outside the application.

3. **Decryption by External Users**: Users with the pass-key can decrypt the image without being explicitly shared the image within the application.

   ```python
   def decrypt_external_user(request, image_id):
       image = ImageModel.objects.get(id=image_id)
       # External user must provide the correct pass-key to decrypt
   ```

---

## 7. Technologies and Security Schemes Used

StegoCrypt integrates a suite of technologies and security schemes to ensure robust protection of user data and encrypted content.

- **Django Framework**: Utilized for rapid development, robust security features, and scalability.

- **Cryptography Library**: Employed for implementing encryption and decryption algorithms, ensuring data confidentiality and integrity.

  ```python
  from cryptography.fernet import Fernet
  ```

- **Pillow (PIL)**: Used for image processing tasks, including embedding and extracting encrypted messages within images.

  ```python
  from PIL import Image
  ```

- **SQLite Database**: Serves as the primary datastore for user information, image metadata, and encrypted pass-keys.

- **Django Middleware**: Custom middleware implemented for rate limiting and request validation to enhance application security.

  ```python
  class RateLimitMiddleware:
      def __call__(self, request):
          # Rate limiting logic
          pass
  ```

- **Unit Testing Framework**: Comprehensive tests are written to validate functionality and security measures, ensuring reliability and integrity.

  ```python
  from django.test import TestCase

  class EncryptionTestCase(TestCase):
      def test_encryption_decryption(self):
          # Test logic
          pass
  ```

- **CSRF Protection**: Leveraged through Django's built-in mechanisms to prevent unauthorized state-changing requests.

- **Caching Mechanism**: Implemented for rate limiting and session management to enhance performance and security.

  ```python
  from django.core.cache import cache
  ```

---

## 8. Conclusion

StegoCrypt exemplifies a secure, feature-rich application that seamlessly integrates cryptography and steganography within the Django framework. By adhering to the core principles of information security—integrity, confidentiality, and availability—and aligning with industry standards such as OWASP and IEEE, StegoCrypt ensures that user data and encrypted messages remain protected against a multitude of threats. The application's thoughtful authentication and access control mechanisms, coupled with robust encryption practices, provide a reliable platform for secure data sharing. Future enhancements will continue to bolster security, expand functionality, and improve user experience, positioning StegoCrypt as a versatile tool for both personal and professional use.

---

**GitHub Copilot**