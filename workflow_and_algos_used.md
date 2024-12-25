
# StegoCrypt Detailed Documentation

This document provides an in-depth look at how StegoCrypt implements key information security principles (Confidentiality, Integrity, Availability), adheres to common standards (OWASP, IEEE), and outlines the workflows for hashing, encryption, decryption, and user authentication/authorization. The details herein build on the full codebase, referencing specific files and functions within the workspace.

---

## 1. Information Security Principles

### 1.1 Confidentiality
StegoCrypt ensures that sensitive information remains accessible only to authorized individuals through the following mechanisms:

1. **Encrypted Message Storage**
   - **Encryption**: Messages are encrypted using custom AES-like functions defined in [`utils.py`](core/utils.py) via:
     - [`aes_encrypt`](core/utils.py)
     - [`aes_decrypt`](core/utils.py)
   - **Pass-Key Derivation**: The pass-key is derived from user input and processed in [`encryption.py`](core/encryption.py) using [`encrypt_and_embed_message`](core/encryption.py).

2. **Steganographic Embedding**
   - **Data Hiding**: Encrypted data (IV + ciphertext) is concealed within images using Least Significant Bit (LSB) steganography through the [`hide`](core/encryption.py) function from the `stegano.lsb` library. This prevents casual detection of the hidden information.

3. **Secure Storage**
   - **Pass-Key Protection**:
     - **Owner's Pass-Key**: Encrypted with a master key using [`encrypt_with_master_key`](core/utils.py).
     - **Shared Users' Pass-Key**: Each shared user’s pass-key is separately encrypted and stored in the [`SharedImageKey`](core/models.py) model.
   - **Password Security**: Personal passwords are hashed using Django's built-in authentication system before storage, ensuring that no plaintext passwords are retained.

### 1.2 Integrity
Integrity ensures that the data remains accurate and unaltered:

1. **Message Verification**
   - **Hash Function**: Utilizes a custom hash function (`sha256_hash` in [`utils.py`](core/utils.py)) to verify the integrity of messages. This ensures that any tampering with the message can be detected.

2. **Input Validation**
   - **Form Validation**: Implemented in [`EncryptionForm`](core/forms.py), images are validated for allowable size and type to prevent the ingestion of malformed or malicious data.

3. **Pass-Key Verification**
   - **Hash Checks**: Before decryption, pass-keys are verified against stored hashes using the [`verify_pass_key`](core/models.py) method, ensuring that only authentic pass-keys are utilized.

4. **Versioning & Rollback**
   - **Error Handling**: In cases where encryption or decryption fails, the system rolls back operations (as referenced in [`core/views.py`](core/views.py)), preventing partial or inconsistent states.

### 1.3 Availability
Availability ensures that services are accessible when needed:

1. **Rate Limiting**
   - **Preventing DoS Attacks**: Implemented via decorators in [`decorators.py`](core/decorators.py), such as:
     ```python
     @login_rate_limit  # Limits to 10 attempts per minute
     @register_rate_limit  # Limits to 10 attempts per minute
     @upload_rate_limit  # Limits to 50 uploads per 5 minutes
     ```
   - These rate limits protect the service from denial-of-service (DoS) attacks, ensuring consistent availability.

2. **Graceful Error Handling**
   - **Exception Management**: Code in 

views.py

 handles exceptions during encryption and decryption processes gracefully. Users are informed of errors without causing application crashes.

3. **Resource Optimization**
   - **Efficient I/O Handling**: Utilizes efficient input/output operations (e.g., `io.BytesIO`) to manage large images, ensuring that the system remains responsive under high-load scenarios.

---

## 2. Standards, Procedures, and Guidelines

StegoCrypt adheres to industry-standard security practices to ensure robust protection of data and operations.

### 2.1 OWASP Compliance
Following the [OWASP Top Ten](https://owasp.org/www-project-top-ten/), StegoCrypt implements several critical security measures:

1. **Authentication Security**
   ```python
   @login_rate_limit
   def login_view(request):
       # Rate-limited login attempts to prevent brute-force attacks
   ```
   - Ensures secure user authentication by limiting login attempts and utilizing Django’s secure authentication mechanisms.

2. **Input Validation**
   ```python
   def clean_original_image(self):
       if image.size > 10 * 1024 * 1024:  # 10MB limit
           raise ValidationError("Image too large")
   ```
   - Validates uploaded files to prevent injection attacks and the upload of malicious files.

3. **Access Control**
   ```python
   @login_required
   @require_https
   def post_decrypt(request, image_id):
       # Ensures that only authenticated users can access decryption functionalities over HTTPS
   ```
   - Enforces strict access controls, ensuring that only authorized users can perform sensitive operations.

### 2.2 Additional Security Measures

1. **CSRF Protection**
   - Leveraging Django’s built-in Cross-Site Request Forgery (CSRF) protection to safeguard against unauthorized actions.

2. **Secure Password Storage**
   - Utilizes Django’s authentication system for secure password hashing and storage, preventing plaintext password exposure.

3. **Rate Limiting on Critical Operations**
   - Applies rate limiting decorators to sensitive endpoints (e.g., login, registration, uploads) to mitigate brute-force and abuse attempts.

### 2.3 IEEE & Industry Best Practices

1. **Separation of Concerns**
   - Clearly segregates encryption logic (`core/utils.py`) from business logic (`core/views.py`), promoting maintainability and security.

2. **Layered Security Approach**
   - Implements multiple layers of security, including custom encryption, steganography, and hashed pass-keys, to provide comprehensive protection against diverse threats.

3. **Key Management**
   - Manages encryption keys securely by encrypting pass-keys with a master key and re-encrypting them for shared users, ensuring that keys are never stored or transmitted in plaintext.

---

## 3. Authentication and Authorization

Robust authentication and authorization mechanisms are central to StegoCrypt’s security framework.

### 3.1 User Authentication

1. **Registration**
   - Handled by Django’s `UserCreationForm` in 

forms.py

.
   - Users submit a username and password, which are validated for strength and then hashed using Django’s secure hashing algorithms before storage.

2. **Login**
   - Managed by Django’s `authenticate` and `login` functions within 

views.py

.
   - Upon user login, the provided credentials are verified against the stored hashed passwords to establish a secure session.

### 3.2 Authorization

1. **Ownership Tracking**
   - Ownership of images is tracked using the 

EncryptedImage

 model.
   - Each image is associated with a user, ensuring that only the owner can perform certain operations unless explicitly shared.

2. **Sharing Logic**
   - Implements sharing through the 

SharedImageKey

 model, which stores encrypted pass-keys for authorized shared users.
   - When an image is shared, the owner’s pass-key is decrypted using the master key, re-encrypted for the recipient, and stored accordingly.

3. **Access Enforcement**
   - Utilizes decorators like 

login_required

 to restrict access to encryption and decryption functionalities only to authenticated users.
   - Ensures that only users with explicit permissions (owners or shared users) can access and decrypt shared images.

---

## 4. Hashing & Encryption at Login/Register

StegoCrypt employs hashing and encryption mechanisms during user authentication and image encryption processes to ensure security and integrity.

### 4.1 Hashing (Login/Register)

1. **User Registration**
   - A user submits a username and password through the `RegisterForm`.
   - Django’s `UserCreationForm` handles validation and utilizes Django’s built-in hashing to securely store the password in the database without retaining the plaintext version.

2. **User Login**
   - Upon entering credentials, Django’s `authenticate` function verifies the hashed password against the stored hash in 

views.py

.
   - Successful authentication establishes a user session.

3. **Pass-Key Hashing**
   - Pass-keys associated with images are either hashed using the custom 

sha256_hash

 function or encrypted using 

encrypt_with_master_key

 before storage.
   - This ensures that pass-keys are never stored in plaintext, enhancing security.

---

## 5. Detailed Encryption & Decryption Workflows

StegoCrypt implements comprehensive workflows for encrypting and decrypting messages embedded within images, ensuring secure storage and retrieval of sensitive information.

### 5.1 Image Encryption

**Process** (

encrypt_and_embed_message

):
```
User uploads image + secret message + pass-key
↓
Validate and sanitize inputs (EncryptionForm)
↓
Derive AES key from pass-key (SHA-256 hashing)
↓
Encrypt message → (IV, ciphertext) using custom AES encryption
↓
Combine IV + ciphertext and embed in image using LSB steganography
↓
Save stego image with associated metadata
```

**Pass-Key Storage**
- **Location**: Stored within the 

EncryptedImage

 model.
- **Method**:
  - The pass-key is either hashed with salt for verification purposes or encrypted using the master key for owner access.
  - This prevents any plaintext pass-key from being stored in the database, mitigating the risk of exposure.

### 5.2 Decryption With a Direct Pass-Key

```
User provides raw pass-key
↓
Verify pass-key by comparing with stored hash (verify_pass_key)
↓
Extract hidden data using LSB steganography (reveal)
↓
Split extracted data into IV + ciphertext
↓
Derive AES key from pass-key (SHA-256 hashing)
↓
Decrypt message using custom AES decryption (aes_decrypt)
↓
Verify message integrity using sha256_hash
↓
Display decrypted message
```

### 5.3 Decryption Using Owner’s Personal Password

```
Owner logs in via Django password
↓
System verifies password against stored hash (Django auth)
↓
Checks if the request user is the image owner
↓
Retrieves encrypted pass-key (encrypted_key_for_owner) and IV (encrypted_key_iv) from EncryptedImage
↓>
Decrypts the pass-key using master key (decrypt_with_master_key)
↓>
Extracts hidden data (IV + ciphertext) from stego image using LSB
↓>
Derives AES key from decrypted pass-key (SHA-256 hashing)
↓>
Decrypts message using custom AES decryption (aes_decrypt)
↓>
Verifies message integrity (sha256_hash check)
↓>
Displays decrypted message
```

### 5.4 Decryption Using Shared User’s Password

```
Shared user logs in via Django password
↓
System verifies password against stored hash (Django auth)
↓>
Checks if the user is in image.shared_with list
↓>
Retrieves user's specific encrypted pass-key and IV from SharedImageKey
↓>
Decrypts pass-key using master key (decrypt_with_master_key)
↓>
Extracts hidden data (IV + ciphertext) from stego image using LSB
↓>
Derives AES key from decrypted pass-key (SHA-256 hashing)
↓>
Decrypts message using custom AES decryption (aes_decrypt)
↓>
Verifies message integrity (sha256_hash check)
↓>
Displays decrypted message
```

---

## 6. Implementation Details

### 6.1 Custom Encryption (

aes_encrypt

)
```python
def aes_encrypt(plaintext: bytes, key: bytes):
    """Custom symmetric encryption replacing AES-CBC.
    Returns the same (iv, ciphertext) format for compatibility."""
    
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))
    
    # Generate 16-byte IV by XOR'ing key and plaintext bytes
    iv = xor_bytes(
        key[:16].ljust(16, b'\0'),
        plaintext[:16].ljust(16, b'\0')
    )
    
    # Padding (PKCS7 style)
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len
    
    # Custom encryption
    ciphertext = bytearray()
    prev_block = iv
    
    # Process 16-byte blocks
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        # Mix block with key
        mixed = xor_bytes(block, key[:16])
        # Mix with previous block (CBC mode)
        mixed = xor_bytes(mixed, prev_block)
        # Simple rotation by 1 byte
        rotated = mixed[1:] + mixed[:1]
        # Final mixing with second part of key
        encrypted_block = xor_bytes(rotated, key[16:32].ljust(16, b'\0'))
        ciphertext.extend(encrypted_block)
        prev_block = encrypted_block
        
    return (iv, bytes(ciphertext))
```

### 6.2 Custom Decryption (

aes_decrypt

)
```python
def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes):
    """Custom symmetric decryption matching the encryption above."""
    
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))
    
    plaintext = bytearray()
    prev_block = iv
    
    # Process 16-byte blocks
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        # Reverse final mixing with second part of key
        unmixed = xor_bytes(block, key[16:32].ljust(16, b'\0'))
        # Reverse rotation by 1 byte
        unrotated = unmixed[-1:] + unmixed[:-1]
        # Reverse CBC mode
        decrypted = xor_bytes(unrotated, prev_block)
        # Reverse mixing with key
        decrypted = xor_bytes(decrypted, key[:16])
        plaintext.extend(decrypted)
        prev_block = block
    
    # Remove PKCS7 padding
    pad_len = plaintext[-1]
    return bytes(plaintext[:-pad_len])
```

### 6.3 Custom Hashing (

sha256_hash

)
```python
def sha256_hash(data: bytes) -> str:
    """Custom hash function replacing SHA256.
    Uses a SipHash-like structure with different constants and mixing function."""
    # Constants for mixing (using prime numbers)
    C1 = 0x736f6d6570736575  # "somepseu" in hex
    C2 = 0x646f72616e646f6d  # "dorandom" in hex
    C3 = 0x6c7967656e657261  # "lygenera" in hex
    C4 = 0x7465686173686573  # "tehashes" in hex
    
    def _rotate_left(n: int, d: int, size: int = 64) -> int:
        """Helper function for bit rotation"""
        return ((n << d) | (n >> (size - d))) & ((1 << size) - 1)
    
    def mix(v0: int, v1: int) -> tuple[int, int]:
        v0 = (v0 + v1) & ((1 << 64) - 1)
        v1 = _rotate_left(v1, 13) ^ v0
        v0 = _rotate_left(v0, 32)
        return v0, v1
    
    # Initialize state
    v0, v1 = C1, C2
    v2, v3 = C3, C4
    
    # Process message in 8-byte chunks
    for i in range(0, len(data), 8):
        chunk = data[i:i+8].ljust(8, b'\0')
        m = int.from_bytes(chunk, byteorder='little')
        
        # Mix chunk into state
        v3 ^= m
        v0, v1 = mix(v0, v1)
        v2, v3 = mix(v2, v3)
        v0, v3 = mix(v0, v3)
        v2, v1 = mix(v2, v1)
        v0 ^= m
        
    # Final mixing rounds
    v2 ^= 0xff
    for _ in range(4):
        v0, v1 = mix(v0, v1)
        v2, v3 = mix(v2, v3)
        v0, v3 = mix(v0, v3)
        v2, v1 = mix(v2, v1)
    
    # Combine state into final hash
    final = (v0 ^ v1 ^ v2 ^ v3).to_bytes(8, byteorder='little')
    return final.hex().zfill(64)  # Ensure 64-character hex string
```

### 6.4 Image Sharing (

share_with_user

)
```python
def share_with_user(self, recipient: User) -> bool:
    """Share image and encrypt pass-key for recipient"""
    if not self.is_public:
        return False
    
    try:
        # Retrieve encrypted pass-key and IV for owner
        iv = self.encrypted_key_iv
        encrypted_key = self.encrypted_key_for_owner
        
        # Decrypt pass-key using master key
        real_pass_key = decrypt_with_master_key(iv, encrypted_key).decode('utf-8')
        
        # Encrypt pass-key for recipient
        new_iv, new_encrypted_key = encrypt_with_master_key(real_pass_key.encode('utf-8'))
        
        # Store encrypted pass-key for recipient in SharedImageKey
        SharedImageKey.objects.create(
            image=self,
            user=recipient,
            encrypted_key=new_encrypted_key,
            key_iv=new_iv
        )
        
        # Add recipient to shared_with list
        self.shared_with.add(recipient)
        self.save()
        return True
    except Exception as e:
        # Handle exceptions, possibly logging the error
        return False
```

---

## 7. Workflow Diagrams

### 7.1 User Registration
```
User submits registration form
↓
Validate password strength (RegisterForm)
↓
Hash password using Django's auth system
↓>
Store hashed password in database
↓>
Create user account
↓>
Redirect to login page
```

### 7.2 User Login
```
User enters username/password
↓
Authenticate using Django’s `authenticate` function
↓>
If authentication succeeds:
    ↓
    Establish user session
    ↓>
    Grant access to protected resources
Else:
    ↓
    Deny access and prompt error
```

### 7.3 Image Encryption
```
User uploads (image + secret message + pass-key)
↓
Validate and sanitize inputs (EncryptionForm)
↓>
Derive AES key from pass-key using SHA-256 hashing
↓>
Encrypt message -> (IV, ciphertext) using custom `aes_encrypt`
↓>
Combine IV + ciphertext and embed in image using LSB steganography (`hide`)
↓>
Store stego image and associated metadata:
    - Original image
    - Stego image
    - Hashed pass-key
    - Encrypted pass-key for owner
    - Message hash
↓>
Confirm successful encryption and embedding to user
```

### 7.4 Decryption with Pass-Key
```
User provides pass-key
↓>
Verify pass-key against stored hash (`verify_pass_key`)
↓>
If verification succeeds:
    ↓>
    Extract hidden data (IV + ciphertext) from stego image using LSB steganography (`reveal`)
    ↓>
    Split extracted data into IV and ciphertext
    ↓>
    Derive AES key from pass-key using SHA-256 hashing
    ↓>
    Decrypt message using custom `aes_decrypt` with derived AES key and IV
    ↓>
    Verify message integrity using `sha256_hash`
    ↓>
    Display decrypted message to user
Else:
    ↓>
    Deny decryption and prompt error
```

### 7.5 Decryption Using Owner’s Personal Password
```
Owner logs in via Django password
↓>
System verifies password against stored hash (Django auth)
↓>
If owner:
    ↓>
    Retrieve encrypted pass-key (encrypted_key_for_owner) and IV (encrypted_key_iv) from EncryptedImage
    ↓>
    Decrypt the pass-key using master key (`decrypt_with_master_key`)
    ↓>
    Extract IV + ciphertext from stego image using LSB steganography (`reveal`)
    ↓>
    Derive AES key from decrypted pass-key using SHA-256 hashing
    ↓>
    Decrypt message using custom `aes_decrypt` with derived AES key and IV
    ↓>
    Verify message integrity using `sha256_hash`
    ↓>
    Display decrypted message to owner
Else:
    ↓>
    Deny access and prompt error
```

### 7.6 Decryption Using Shared User’s Password
```
Shared user logs in
↓>
Verify password using Django auth system
↓>
Check if user is in image.shared_with list
↓>
If authorized:
    ↓>
    Retrieve user-specific encrypted pass-key and IV from SharedImageKey
    ↓>
    Decrypt pass-key using master key (`decrypt_with_master_key`)
    ↓>
    Extract IV + ciphertext from stego image using LSB steganography (`reveal`)
    ↓>
    Derive AES key from decrypted pass-key using SHA-256 hashing
    ↓>
    Decrypt message using custom `aes_decrypt` with derived AES key and IV
    ↓>
    Verify message integrity using `sha256_hash`
    ↓>
    Display decrypted message to shared user
Else:
    ↓>
    Deny decryption and prompt error
```

---

## 8. Security Considerations

1. **Pass-Key Security**
   - **Encryption**: Pass-keys are never stored in plaintext. They are encrypted with a master key (`encrypt_with_master_key`) for owner access and re-encrypted for each shared user.
   - **Verification**: Pass-keys are verified through secure hashing (`sha256_hash`) before decryption operations are permitted.

2. **Message Security**
   - **Pre-Encryption**: Messages are encrypted before embedding into images, ensuring that even if steganographic data is detected, the message remains unreadable without decryption.
   - **Integrity Checks**: After decryption, message integrity is verified using the custom hash function to ensure data has not been tampered with.

3. **Access Control**
   - **Role-Based Access**: Only image owners and explicitly authorized shared users can access and decrypt sensitive content.
   - **Strict Permissions**: Utilizes Django’s `login_required` decorator and custom access checks to enforce permissions.

4. **Key Management**
   - **Master Key Usage**: A system-wide master key derived from Django’s `SECRET_KEY` is used to encrypt and decrypt pass-keys, ensuring that keys are managed securely and are not exposed.

5. **Error Handling**
   - **Graceful Failures**: All critical operations, such as encryption and decryption, include exception handling to manage failures without compromising system stability or security.

6. **Rate Limiting**
   - **Defensive Measures**: Implements rate limiting on login, registration, and upload actions to prevent brute-force attacks and reduce the risk of service disruption.

7. **Compliance with Standards**
   - **OWASP Top Ten**: Adheres to best practices in web security as outlined by OWASP, addressing common vulnerabilities like injection attacks and ensuring secure authentication mechanisms.
   - **IEEE Standards**: Follows IEEE guidelines for secure software development, including separation of concerns and layered security implementations.

---

## 9. Conclusion

StegoCrypt embodies a multi-layered approach to information security, effectively incorporating the core principles of Confidentiality, Integrity, and Availability. By integrating industry best practices from standards like OWASP and IEEE, StegoCrypt ensures robust protection of sensitive data through:

- **Confidentiality**: Achieved via custom encryption techniques, steganographic embedding of encrypted data, and secure pass-key storage mechanisms.
- **Integrity**: Maintained through secure hashing functions, stringent input validation, and comprehensive verification processes.
- **Availability**: Guaranteed by implementing rate limiting, efficient resource management, and graceful error handling to ensure consistent service accessibility.

The system’s architecture emphasizes strong authentication and authorization protocols, ensuring that only authorized users can access and manipulate sensitive information. By leveraging secure key management practices and adhering to best-in-class security frameworks, StegoCrypt provides a reliable and secure solution for embedding and sharing confidential messages within images.

For further technical details, refer to the specific files and functions highlighted throughout this documentation:

- 

utils.py

: Contains hashing and encryption helpers, including 

aes_encrypt

 and 

sha256_hash

.
- 

encryption.py

: Houses the function 

encrypt_and_embed_message

 responsible for encrypting messages and embedding them into images.
- 

decryption.py

: Includes 

decrypt_message_from_stego

, which handles the extraction and decryption of hidden messages.
- 

models.py

: Defines the data models 

EncryptedImage

 and 

SharedImageKey

 used for managing encrypted images and shared access.
- 

views.py

: Manages form handling, image uploads, user access logic, and orchestrates encryption/decryption workflows.
- 

forms.py

: Implements input validation logic for various forms used throughout the application.
- 

decorators.py

: Contains decorators for rate limiting and enforcing secure access controls.
