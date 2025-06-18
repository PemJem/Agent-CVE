import requests
import unittest
import sys
from datetime import datetime

class CVEAgentAPITester:
    def __init__(self, base_url="https://654780bb-6344-4fb7-88e9-4e213b1250ed.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def run_test(self, name, method, endpoint, expected_status, data=None):
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

            success = response.status_code == expected_status
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