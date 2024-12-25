# tests/test_headers.py
import requests
from test_utils import BASE_URL, log_test

def check_security_headers():
    """Test security headers"""
    log_test("Starting security headers check")
    
    try:
        r = requests.get(BASE_URL)
        headers = r.headers
        
        required_headers = {
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000',
            'X-XSS-Protection': '1; mode=block'
        }
        
        success = True
        for header, expected_value in required_headers.items():
            if header not in headers:
                log_test(f"Missing header: {header}", "FAIL")
                success = False
            elif headers[header] != expected_value:
                log_test(f"Invalid {header}: {headers[header]}", "FAIL")
                success = False
            else:
                log_test(f"Header {header} OK", "SUCCESS")
        
        return success
        
    except Exception as e:
        log_test(f"Test failed: {str(e)}", "ERROR")
        return False

if __name__ == "__main__":
    check_security_headers()