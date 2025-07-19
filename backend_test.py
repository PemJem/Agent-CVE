import requests
import unittest
import sys
from datetime import datetime
import json

class CVEAgentAPITester:
    def __init__(self, base_url="https://030feba8-624b-414f-aa2e-929b047cd90f.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def run_test(self, name, method, endpoint, expected_status, data=None, allow_404=False):
        """Run a single API test"""
        url = f"{self.base_url}{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers)
            elif method == 'DELETE':
                response = requests.delete(url, json=data, headers=headers)

            success = response.status_code == expected_status or (allow_404 and response.status_code == 404)
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    print(f"Response data: {response_data}")
                    self.test_results.append({
                        "name": name,
                        "status": "PASS",
                        "response": response_data
                    })
                    return success, response_data
                except:
                    print("Response is not JSON")
                    self.test_results.append({
                        "name": name,
                        "status": "PASS",
                        "response": response.text[:100] + "..."
                    })
                    return success, response.text
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"Error response: {error_data}")
                except:
                    print(f"Error response: {response.text[:200]}")
                self.test_results.append({
                    "name": name,
                    "status": "FAIL",
                    "error": f"Expected status {expected_status}, got {response.status_code}"
                })
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            self.test_results.append({
                "name": name,
                "status": "ERROR",
                "error": str(e)
            })
            return False, {}

    def test_api_root(self):
        """Test API root endpoint"""
        return self.run_test(
            "API Root",
            "GET",
            "/api/",
            200
        )

    def test_scraping_status(self):
        """Test scraping status endpoint"""
        return self.run_test(
            "Scraping Status",
            "GET",
            "/api/status",
            200
        )

    def test_latest_summary(self):
        """Test latest summary endpoint"""
        return self.run_test(
            "Latest Summary",
            "GET",
            "/api/summaries/latest",
            200
        )

    def test_summaries_history(self):
        """Test summaries history endpoint"""
        return self.run_test(
            "Summaries History",
            "GET",
            "/api/summaries",
            200
        )

    def test_recent_cves(self):
        """Test recent CVEs endpoint"""
        return self.run_test(
            "Recent CVEs",
            "GET",
            "/api/cves/recent",
            200
        )

    def test_cves_by_severity(self):
        """Test CVEs by severity endpoint for each severity level"""
        results = {}
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            success, response = self.run_test(
                f"CVEs by Severity ({severity})",
                "GET",
                f"/api/cves/by-severity/{severity}",
                200
            )
            results[severity] = {"success": success, "data": response}
        return results

    def test_manual_scrape(self):
        """Test manual scraping endpoint"""
        return self.run_test(
            "Manual Scrape",
            "POST",
            "/api/scrape/manual",
            200
        )

    # CVE Timeline System Tests
    def test_cve_timeline(self):
        """Test CVE timeline endpoint for high severity CVEs (CVSS >= 7.0)"""
        return self.run_test(
            "CVE Timeline (High Severity)",
            "GET",
            "/api/cves/timeline",
            200
        )

    def test_cve_timeline_latest(self):
        """Test latest CVE timeline entry"""
        return self.run_test(
            "CVE Timeline Latest",
            "GET",
            "/api/cves/timeline/latest",
            200
        )

    def test_cve_timeline_generate(self):
        """Test manual timeline generation"""
        return self.run_test(
            "CVE Timeline Generate",
            "POST",
            "/api/cves/timeline/generate",
            200
        )

    def test_cve_timeline_stats(self):
        """Test CVE timeline statistics"""
        return self.run_test(
            "CVE Timeline Stats",
            "GET",
            "/api/cves/timeline/stats",
            200
        )

    # Email Management System Tests
    def test_email_config_status(self):
        """Test Gmail configuration status"""
        return self.run_test(
            "Email Config Status",
            "GET",
            "/api/emails/config/status",
            200
        )

    def test_email_subscribe(self):
        """Test email subscription"""
        test_email = "test.cve@example.com"
        return self.run_test(
            "Email Subscribe",
            "POST",
            "/api/emails/subscribe",
            200,
            {"email": test_email}
        )

    def test_email_subscribers_list(self):
        """Test getting email subscribers list"""
        return self.run_test(
            "Email Subscribers List",
            "GET",
            "/api/emails/subscribers",
            200
        )

    def test_email_unsubscribe(self):
        """Test email unsubscription"""
        test_email = "test.cve@example.com"
        return self.run_test(
            "Email Unsubscribe",
            "DELETE",
            "/api/emails/unsubscribe",
            200,
            {"email": test_email},
            allow_404=True
        )

    def test_email_send_test(self):
        """Test sending test email (will fail gracefully if Gmail not configured)"""
        test_email = "test.cve@example.com"
        success, response = self.run_test(
            "Email Send Test",
            "POST",
            "/api/emails/send-test",
            200,
            {"email": test_email}
        )
        # This might fail if Gmail is not configured, which is expected
        if not success:
            print("⚠️  Email test failed - likely Gmail not configured (expected)")
            self.test_results[-1]["status"] = "EXPECTED_FAIL"
            self.test_results[-1]["note"] = "Gmail not configured - graceful handling expected"
        return success, response

    def test_email_reports_status(self):
        """Test email reports status"""
        return self.run_test(
            "Email Reports Status",
            "GET",
            "/api/emails/reports/status",
            200
        )

    # User Visit Tracking Tests
    def test_user_visit_tracking(self):
        """Test user visit tracking"""
        return self.run_test(
            "User Visit Tracking",
            "POST",
            "/api/user/visit?session_id=test_session_123",
            200
        )

    def test_user_visit_get(self):
        """Test getting user visit data"""
        return self.run_test(
            "User Visit Get",
            "GET",
            "/api/user/visit/test_session_123",
            200
        )

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting CVE Agent API Tests...")
        
        # Test API root
        self.test_api_root()
        
        # Test scraping status
        self.test_scraping_status()
        
        # Test latest summary
        self.test_latest_summary()
        
        # Test summaries history
        self.test_summaries_history()
        
        # Test recent CVEs
        self.test_recent_cves()
        
        # Test CVEs by severity
        self.test_cves_by_severity()
        
        # Test manual scrape (run this last as it might take time)
        self.test_manual_scrape()
        
        # Print results
        print(f"\n📊 Tests passed: {self.tests_passed}/{self.tests_run}")
        return self.test_results

def main():
    # Setup
    tester = CVEAgentAPITester()
    
    # Run tests
    results = tester.run_all_tests()
    
    # Determine exit code
    return 0 if tester.tests_passed == tester.tests_run else 1

if __name__ == "__main__":
    sys.exit(main())