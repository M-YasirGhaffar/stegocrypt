
# **Project Document: StegoCrypt Django Application – Features, Usage, and Future Roadmap**


## 1. Introduction
StegoCrypt is a Django-based web application that enables users to embed encrypted messages within images. This platform ensures secure data sharing through a combination of user authentication, granular access controls, and optional shareability settings.


## 2. Key Features
1. **User Authentication and Registration**  
   - Users can create accounts or log in with existing credentials.  
   - Access to encryption and decryption tools requires authentication.

2. **Image Encryption**  
   - Users upload source images (PNG/JPG) to embed secret messages.  
   - Encryption can be locked with a user’s personal password or a general pass-key.  

3. **Configurable Shareability**  
   - Each image can be marked as “shareable” or “private.”  
   - “Shareable” images remain accessible only to specifically shared users; those users cannot re-share further.  
   - “Private” images stay accessible to the owner only (or to anyone who obtains the file and pass-key out of band).

4. **Encrypted Message Decryption**  
   - Users can decrypt images using their own personal password or the pass-key.  
   - Shared users (if permitted) can also decrypt using their password.  
   - If the image is non-shareable, acquiring the pass-key from the owner is necessary to decrypt.

5. **Minimal Frontend**  
   - A simple UI is provided to:  
     - Log in and register.  
     - Upload images for encryption with file size checking.  
     - Decrypt images with pass-keys or personal passwords.

6. **Security Layers**  
   - Rate-limiting decorators prevent excessive login attempts.  
   - Only recognized image file types (up to 10MB) are allowed.  
   - All critical requests secured by Django’s CSRF mechanism.


## 3. Usage
1. **Running the Server**  
   - Navigate to the project directory.  
   - Run:  
     ```sh
     python manage.py runserver
     ```  
   - Open your browser at http://127.0.0.1:8000/login to access the application.

2. **Registering / Logging In**  
   - Create an account if you do not have one.  
   - After logging in, you will see the main dashboard.

3. **Encrypting an Image**  
   - Upload an original image (PNG/JPG) along with a secret message.  
   - Specify a pass-key or rely on your personal password.  
   - Decide whether to make the image shareable or not.

4. **Decrypting an Image**  
   - Provide the stego image, enter either your personal password or the pass-key.  
   - If you are a “shared” user of a shareable image, you can also decrypt it with your own password.

5. **Access Controls**  
   - If shareable, other authorized users can decrypt but cannot pass it on to new users.  
   - If non-shareable, only the original user (or someone who was given the pass-key externally) can decrypt.

6. **Testing**  
   - Run built-in test suite:  
     ```sh
     python manage.py test
     ```  
   - Or execute specific scripts in the "tests" folder (e.g., run_all.py).


## 4. Future Implementations
1. **Enhanced File Support**  
   - Add support for multiple image formats or attachments (e.g., GIF, BMP).

2. **Advanced Encryption Algorithms**  
   - Option to choose between AES, RSA, or hybrid encryption methods.

3. **Audit Logs and Notifications**  
   - Keep a detailed record of all encryption/decryption attempts.  
   - Notify the owner if a shared user decrypts an image.

4. **Scalability and Performance**  
   - Integrate with a more robust backend storage for images.  
   - Explore Docker/Container deployments for easy scaling.

5. **UI Improvements**  
   - Provide drag-and-drop uploads, progress bars, image previews.  
   - Expand customizable sharing rules (e.g., shareable for a limited time).


## 5. Conclusion
StegoCrypt combines cryptography with steganography under an easy-to-use Django application. It offers secure encryption, user access controls, and rate-limiting, making it suitable for both personal and classroom use. Further expansions could enhance encryption algorithms, sharing capabilities, and performance to adapt to larger production environments.