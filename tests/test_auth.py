# tests/test_auth.py
import requests
from concurrent.futures import ThreadPoolExecutor
from test_utils import BASE_URL, log_test

def test_login_rate_limit():
    """Test login rate-limiting by spamming wrong credentials."""
    log_test("Starting login rate limit test")
    session = requests.Session()
    
    # Fetch the login page; get csrf
    r = session.get(f"{BASE_URL}/login/")
    if r.status_code != 200:
        log_test(f"Failed to load /login/ page: {r.status_code}", "ERROR")
        return False
    csrf = None
    for cookie in r.cookies:
        if cookie.name == 'csrftoken':
            csrf = cookie.value
            break
    
    def attempt_login(i):
        headers = {}
        if csrf:
            headers = {
                'X-CSRFToken': csrf,
                'Cookie': f'csrftoken={csrf}'
            }
        data = {
            'username': f"wrong_user_{i}",
            'password': 'wrong_pass',
            'csrfmiddlewaretoken': csrf or ''
        }
        resp = session.post(f"{BASE_URL}/login/", data=data, headers=headers)
        log_test(f"Login attempt {i}: Status {resp.status_code}")
        return resp.status_code
    
    try:
        # Try multiple login attempts with wrong password
        attempts_count = 10
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(attempt_login, range(attempts_count)))
        
        # If we see a 403 in the mix, it implies the rate limit triggered
        if 403 in results:
            log_test("Rate limiting working properly", "SUCCESS")
            return True
        else:
            log_test("Rate limiting not triggered", "FAIL")
            return False
    except Exception as e:
        log_test(f"Test failed: {str(e)}", "ERROR")
        return False

if __name__ == "__main__":
    test_login_rate_limit()