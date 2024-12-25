# tests/test_utils.py
import requests
import time
from datetime import datetime
import re

TEST_USER = {
    'username': 'test',
    'password': 'Test1@test'
}

BASE_URL = "http://localhost:8000"

def log_test(message, status="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{status}] {message}")

def get_csrf_token(response):
    """Extract CSRF token from cookie or HTML form."""
    # Try cookies first
    if 'csrftoken' in response.cookies:
        return response.cookies['csrftoken']
    # Fallback to searching HTML
    match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', response.text)
    return match.group(1) if match else None

def login_user(session):
    """Helper logic to log in with the test user."""
    try:
        # Get the login page to grab CSRF
        r = session.get(f"{BASE_URL}/login/")
        if r.status_code != 200:
            log_test(f"Could not reach /login/ (status: {r.status_code})", "ERROR")
            return False
        
        csrf = get_csrf_token(r)
        if not csrf:
            log_test("No CSRF token found on /login/ page", "ERROR")
            return False
        
        headers = {
            'X-CSRFToken': csrf,
            'Cookie': f'csrftoken={csrf}'
        }
        data = {
            'username': TEST_USER['username'],
            'password': TEST_USER['password'],
            'csrfmiddlewaretoken': csrf
        }
        # Attempt login
        r = session.post(f"{BASE_URL}/login/", data=data, headers=headers, allow_redirects=True)
        # After a successful login, we expect a redirect (302 to /) or a 200 if no redirect
        if r.status_code in (200, 302):
            log_test(f"Login successful: {r.status_code}", "SUCCESS")
            return True
        else:
            log_test(f"Login failed: {r.status_code}", "ERROR")
            return False
    except Exception as e:
        log_test(f"Login failed with exception: {str(e)}", "ERROR")
        return False