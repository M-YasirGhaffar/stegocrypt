# tests/run_all.py
import sys
import time
from datetime import datetime
from test_utils import log_test
from test_auth import test_login_rate_limit
from test_uploads import test_file_upload
from test_decryption import test_decryption_brute_force
# We are NOT importing test_headers now

def run_all_tests():
    """
    Run all security tests in a specific order:
    1. Test login rate-limiting.
    2. If rate-limiting happens, wait for the window to reset.
    3. Test file upload restrictions (requires successful login).
    4. Test decryption brute force (requires successful login).
    5. Print summary of results.
    """
    start_time = time.time()
    log_test("Starting all security tests", "INFO")

    # 1. Rate-limit test
    log_test("==== Phase 1: Testing Login Rate Limit ====", "INFO")
    login_limit_passed = test_login_rate_limit()
    
    # 2. If triggered, wait to reset the rate-limit window
    if login_limit_passed:
        log_test("Login rate-limit test passed. Waiting 60 seconds...", "INFO")
        time.sleep(60)
    else:
        log_test("Rate limit test failed or did not trigger. Proceeding anyway...", "INFO")

    # 3. File upload test
    log_test("==== Phase 2: Testing File Upload Restrictions ====", "INFO")
    upload_passed = test_file_upload()

    # 4. Decryption brute force test
    log_test("==== Phase 3: Testing Decryption Brute Force ====", "INFO")
    decryption_passed = test_decryption_brute_force()

    # Collate results
    results = {
        "Authentication Rate Limit": login_limit_passed,
        "File Upload Restrictions": upload_passed,
        "Decryption Brute Force": decryption_passed
    }

    # Print summary
    print("\n" + "="*50)
    print("TEST RESULTS SUMMARY")
    print("="*50)
    
    all_passed = True
    for test_name, passed in results.items():
        status = "PASSED" if passed else "FAILED"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False

    duration = time.time() - start_time
    print(f"\nTotal duration: {duration:.2f} seconds")

    if all_passed:
        log_test("All tests passed successfully!", "SUCCESS")
        return 0
    else:
        log_test("Some tests failed!", "FAIL")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())