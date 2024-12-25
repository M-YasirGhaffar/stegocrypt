# tests/test_decryption.py
import requests
import time
from test_utils import BASE_URL, TEST_USER, log_test, login_user

def test_decryption_brute_force():
    """Test decryption brute force limiting on image #7."""
    log_test("Starting decryption brute force test")
    session = requests.Session()
    
    # Log in first
    if not login_user(session):
        log_test("Login failed", "ERROR")
        return False
    
    try:
        image_id = 7  # Specifically test image #7
        common_passwords = ['password123', 'admin123', '123456', 'qwerty']
        
        for i, password in enumerate(common_passwords, start=1):
            data = {'pass_or_pw': password}
            r = session.post(f"{BASE_URL}/post-decrypt/{image_id}/", data=data)
            log_test(f"Attempt {i} with '{password}': {r.status_code}")
            
            # 403 indicates blocking or rate limiting triggered
            if r.status_code == 403:
                log_test("Rate limiting working properly", "SUCCESS")
                return True
            
            time.sleep(0.5)
        
        # If we never got 403, limit didn't trigger
        log_test("Rate limiting not triggered", "FAIL")
        return False
        
    except Exception as e:
        log_test(f"Decryption test crashed: {str(e)}", "ERROR")
        return False

if __name__ == "__main__":
    test_decryption_brute_force()