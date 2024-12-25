# StegoCrypt Django Application

A secure image steganography platform with multi-layer encryption, user authentication, and granular access control.

## Table of Contents
1. [Project Overview](#project-overview)
2. [Folder Structure](#folder-structure)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Testing](#testing)
6. [How It Works](#how-it-works)
7. [Use Cases](#use-cases)

## Project Overview
StegoCrypt allows you to hide sensitive messages in image files (PNG/JPG/GIF) and later extract them, providing a secure way to share information. It uses Django’s framework capabilities for authentication, routing, and database handling.

## Folder Structure

```
### /

- **manage.py** – Django’s CLI tool for migrations, running the server, and other commands.  
- **readme.md** – This documentation file.  
- **requirements.txt** – Python dependencies required by the project.  
- **db.sqlite3** – SQLite database file (generated after migrations).  
- **env** – Python virtual environment folder (not committed to version control).  

### steganography/  
- __init__.py – Marks this directory as a Python package.  
- asgi.py – ASGI configuration.  
- settings.py – Main Django settings (INSTALLED_APPS, MIDDLEWARE, DB config, etc.).  
- urls.py – Project-level URL mapping.  
- wsgi.py – WSGI configuration for deployments.

### core/  
- __init__.py – Marks this directory as a Python package.  
- admin.py – Django admin configurations.  
- apps.py – App configuration.  
- decorators.py – Custom decorators (e.g. rate-limiting).  
- decryption.py – Decryption logic.  
- encryption.py – Encryption logic.  
- forms.py – Django forms for registration, login, file validation, etc.  
- middleware.py – Custom middleware (e.g. rate limiting).  
- models.py – Database models for images and user data.  
- templates/ – HTML templates, including the main index.html.  
- tests.py – Unit tests.  
- urls.py – App-level URL routes.  
- utils.py – Helper functions (e.g. hashing).  
- views.py – All view functions for encrypt/decrypt operations.

### theme/  
- static/ – Compiled static files (CSS, JS).  
- static_src/ – Source for Tailwind and PostCSS.  
- templates/ – Shared base templates (e.g. base.html).  
- apps.py – Theme app configuration.

### media/  
- original_images/ – Stores user-uploaded images.  
- stego_images/ – Stores stego-embedded images (post-encryption).
```

## Installation

1. Clone (or download) this repository.  
2. Create a virtual environment from your project folder:
   ```bash
   python -m venv env
   ```
3. Activate the virtual environment (Windows):
   ```bash
   env\Scripts\activate
   ```
4. Install project dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Apply database migrations:
   ```bash
   python manage.py migrate
   ```
6. Note: In case of changes to database model run this before `Step 5`:
   ```bash
   python manage.py makemigrations
   ```

## Usage

1. Run the development server:
   ```bash
   python manage.py runserver
   ```
2. Open your browser at:
   ```
   http://127.0.0.1:8000/login
   ```
3. Register or log in to access the dashboard.  
4. Upload an image along with a secret message — encryption occurs automatically, and a stego image file is saved.  
5. Download or share stego images; decrypt to reveal hidden messages.


## Testing

Run all tests with Django’s built-in test runner:
```bash
python manage.py test
```
Tests are located in core/tests.py. These cover view logic, encryption/decryption correctness, and form validations.


## How It Works

1. **Encryption**: The user uploads an image and enters a secret message. The app uses cryptographic methods (AES or similar) and steganography to embed text in the image. The resulting stego image is stored under media/stego_images.  
2. **Decryption**: When requested, the project extracts the hidden data from the stego image and reveals the hidden message (requires the correct pass key).  
3. **Security**: 
   - Rate limiting is done via middleware to prevent spam.  
   - Strict file validation to ensure only image files up to 10MB are allowed.  
   - Django’s built-in CSRF protection for all form submissions.  

## Use Cases

- **Secure Image Sharing**: Hiding sensitive messages within everyday images.  
- **Educational Demonstrations**: Teaching steganography and encryption basics with a functional Django app.  
- **Classroom Projects**: Illustrating Python’s cryptographic and web development techniques.  

Thanks for checking out StegoCrypt! Feel free to open issues or contribute via pull requests.
