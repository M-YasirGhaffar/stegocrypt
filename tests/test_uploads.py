# tests/test_uploads.py
import requests
from PIL import Image
import io
import math
from test_utils import BASE_URL, log_test, login_user, get_csrf_token

def create_large_image(size_mb=12):
    """Create test image larger than 10MB limit."""
    log_test(f"Creating ~{size_mb}MB test image")
    
    # Calculate dimensions needed for target size
    # Each pixel is 3 bytes (RGB)
    # Total bytes = width * height * 3
    bytes_needed = size_mb * 1024 * 1024
    pixel_count = bytes_needed // 3
    width = height = int((pixel_count ** 0.5) + 1)
    
    log_test(f"Creating {width}x{height} image")
    
    try:
        # Create large image with random pixel data
        img = Image.new('RGB', (width, height))
        pixels = img.load()
        
        # Fill with some pattern to prevent compression from reducing size too much
        for x in range(width):
            for y in range(height):
                pixels[x, y] = (
                    (x*y) % 256,
                    (x+y) % 256,
                    (x^y) % 256
                )
        
        # Save with minimal compression
        buf = io.BytesIO()
        img.save(buf, format='PNG', optimize=False, compress_level=0)
        image_data = buf.getvalue()
        
        actual_size_mb = len(image_data) / (1024 * 1024)
        log_test(f"Created image of {actual_size_mb:.2f}MB")
        
        if actual_size_mb < 10:
            log_test("Warning: Generated image smaller than intended", "WARN")
            
        return image_data
        
    except Exception as e:
        log_test(f"Error creating test image: {str(e)}", "ERROR")
        return None

def test_file_upload():
    """Test file upload restrictions."""
    log_test("Starting file upload test")
    session = requests.Session()
    
    if not login_user(session):
        return False
    
    try:
        r = session.get(f"{BASE_URL}/")
        csrf = get_csrf_token(r)
        if not csrf:
            return False
            
        large_image = create_large_image(size_mb=12)
        if not large_image:
            log_test("Failed to create test image", "ERROR")
            return False
            
        image_size_mb = len(large_image) / (1024 * 1024)
        log_test(f"Attempting to upload file of {image_size_mb:.2f}MB")
        
        files = {'original_image': ('large.png', large_image, 'image/png')}
        data = {
            'secret_message': 'test message',
            'pass_key': 'test123',
            'is_public': False,
            'csrfmiddlewaretoken': csrf
        }
        headers = {
            'X-CSRFToken': csrf,
            'Cookie': f'csrftoken={csrf}',
            'Referer': BASE_URL
        }
        
        resp = session.post(
            f"{BASE_URL}/post-encrypt/",
            files=files,
            data=data,
            headers=headers,
            allow_redirects=False
        )
        
        log_test(f"Upload response status: {resp.status_code}")
        
        # The upload should be blocked with 400 (form validation) or 403 (middleware)
        if resp.status_code in [400, 403]:
            log_test("Large file upload correctly blocked", "SUCCESS")
            return True
        else:
            log_test(f"Upload unexpectedly succeeded with status {resp.status_code}", "FAIL")
            log_test("Response preview: ...", "DEBUG")
            return False
            
    except Exception as e:
        log_test(f"Test failed: {str(e)}", "ERROR")
        return False

if __name__ == "__main__":
    test_file_upload()