import os
import sys
import time
from unittest.mock import MagicMock, patch

# Mock heavy modules before importing model/controller
class MockWhoisObject(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.creation_date = None
        self.updated_date = None
        self.expiration_date = None

sys.modules['whois'] = MagicMock()
sys.modules['whois'].whois = MagicMock(return_value=MockWhoisObject())

sys.modules['dotenv'] = MagicMock()

class MockExtractResult:
    def __init__(self, domain, suffix):
        self.domain = domain
        self.suffix = suffix

sys.modules['tldextract'] = MagicMock()
sys.modules['tldextract'].extract = MagicMock(return_value=MockExtractResult("google", "com"))

sys.modules['tensorflow'] = MagicMock()
sys.modules['tensorflow.keras'] = MagicMock()

# Mock requests.get and requests.post
mock_requests = MagicMock()
mock_resp = MagicMock()
mock_resp.status_code = 200
mock_resp.headers = {'Strict-Transport-Security': 'max-age=63072000'}
mock_resp.text = "<html><body><form></form></body></html>"
mock_resp.content = b"<html><body><form></form></body></html>"
mock_resp.history = []
mock_requests.get.return_value = mock_resp

mock_post_resp = MagicMock()
mock_post_resp.content = b'{"results": {"valid": false}}'
mock_post_resp.status_code = 200
mock_post_resp.json.return_value = {"google_verified": "no"}
mock_requests.post.return_value = mock_post_resp

sys.modules['requests'] = mock_requests

# Mock MLmodel API get_prediction
sys.modules['MLmodel'] = MagicMock()
sys.modules['MLmodel.Feature_Extractor'] = MagicMock()
sys.modules['MLmodel.API'] = MagicMock()
sys.modules['MLmodel.API'].get_prediction = MagicMock(return_value=12.5)

# Add Camillo-API-main to paths
backend_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Camillo-API-main")
sys.path.append(backend_path)

print("[TEST] Importing backend modules with mocked dependencies...")
try:
    import model
    import controller
    import cscore
    import googleVerify
    print("[TEST] Import SUCCESS.")
except Exception as e:
    print(f"[TEST] Import FAILED: {e}")
    sys.exit(1)

def run_tests():
    print("\n--- Running Mocked Heuristic & Integrity Tests ---")
    
    # 1. Check preloaded variables
    print(f"[TEST] Top 1M domains list size: {len(model.TOP_1M_LIST)}")
    print(f"[TEST] Domain rankings dictionary size: {len(model.DOMAIN_RANK_DICT)}")
    print(f"[TEST] URL shorteners list size: {len(model.URL_SHORTENERS_LIST)}")
    
    assert len(model.TOP_1M_LIST) > 0, "Top 1M list should not be empty"
    assert len(model.DOMAIN_RANK_DICT) > 0, "Domain rank dict should not be empty"
    assert len(model.URL_SHORTENERS_LIST) > 0, "URL shorteners list should not be empty"
    print("[TEST] Preloaded lists checks: PASSED")

    # 2. Test URL metadata pre-fetching
    test_url = "https://google.com"
    print(f"\n[TEST] Fetching metadata for: {test_url}")
    meta = model.fetch_url_metadata(test_url)
    print(f"[TEST] Status code: {meta['status_code']}")
    print(f"[TEST] Headers count: {len(meta['headers'])}")
    print(f"[TEST] Redirects count: {len(meta['redirects'])}")
    
    assert meta['status_code'] == 200, "Should get 200 status code"
    print("[TEST] Fetch URL metadata check: PASSED")

    # 3. Test binary search for domain rank
    print("\n[TEST] Checking domain rank for google.com...")
    rank = model.get_domain_rank("google.com")
    print(f"[TEST] google.com rank: {rank}")
    assert rank > 0 and rank <= 100, "Google should have a highly popular rank (1-100)"
    
    # 4. Test main controller analysis logic
    print("\n[TEST] Running full analysis on: https://google.com")
    res = controller.main("https://google.com")
    print(f"[TEST] Status: {res.get('status')}")
    print(f"[TEST] Trust Score: {res.get('trust_score')}")
    print(f"[TEST] Model Score: {res.get('model_score')}")
    print(f"[TEST] Final Verdict: {res.get('final_verdict')}")
    print(f"[TEST] Heuristic Breakdown items count: {len(res.get('breakdown', []))}")
    
    assert res.get('status') == 'SUCCESS', "Status should be SUCCESS"
    assert res.get('trust_score') > 50, "Google trust score should be high"
    assert res.get('final_verdict') is False, "Google should not be classified as phishing"
    assert len(res.get('breakdown', [])) > 0, "Should have breakdown list details"
    print("[TEST] Full URL analysis check: PASSED")

    # 5. Check Google verification conditional fix validation
    print("\n[TEST] Verifying conditional Safe Browsing check logic...")
    google_verification_result = {"google_verified": "yes", "threat_type": "MALWARE", "platform_type": "ANY_PLATFORM", "threat_entry_type": "URL"}
    # Force googleVerify.google_verification to return "yes"
    with patch('googleVerify.google_verification', return_value=google_verification_result):
        res_flagged = controller.main("https://malicious-site.com")
        print(f"[TEST] Google Safe Browsing Flagged Verdict: {res_flagged.get('final_verdict')}")
        assert res_flagged.get('final_verdict') is True, "Phishing verdict must be True when Safe Browsing flags it"
        print("[TEST] Google Safe Browsing warning bypass fix check: PASSED")

    print("\n[TEST] All tests PASSED successfully!")

if __name__ == "__main__":
    run_tests()
