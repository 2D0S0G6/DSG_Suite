"""
Response Analyzer - Detects subtle vulnerabilities through response comparison.

Key insight: Vulnerability doesn't always mean error or exception.
It's often hidden in subtle response differences:
- Status codes
- Response timing
- Content length differences
- JSON field variations
- Error message leakage
"""

import requests
import json
import logging
import difflib
import time
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ResponseAnalyzer:
    """
    Compares responses to detect subtle vulnerabilities.
    """
    
    def __init__(self):
        self.response_cache: Dict[str, Dict] = {}
    
    def parse_response(self, response: requests.Response) -> Dict:
        """
        Extract structured information from response.
        """
        parsed = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "text_length": len(response.text),
            "content_type": response.headers.get("Content-Type", ""),
            "execution_time": response.elapsed.total_seconds() if response.elapsed else 0,
            "text_hash": hash(response.text),
            "body_text": response.text[:1000],  # First 1000 chars
            "body_json": None
        }
        
        # Try to parse JSON
        try:
            parsed["body_json"] = response.json()
        except:
            pass
        
        return parsed
    
    def compare_responses(self, resp1: requests.Response, resp2: requests.Response, 
                         name1: str = "Response1", name2: str = "Response2") -> Dict:
        """
        Deep comparison of two responses.
        
        Detects:
        - Content differences
        - Timing differences (timing attacks)
        - Error message leakage
        - Sensitive data in responses
        """
        parsed1 = self.parse_response(resp1)
        parsed2 = self.parse_response(resp2)
        
        comparison = {
            "responses": {name1: parsed1, name2: parsed2},
            "differences": {}
        }
        
        # Compare status codes
        if parsed1["status_code"] != parsed2["status_code"]:
            comparison["differences"]["status_code"] = {
                name1: parsed1["status_code"],
                name2: parsed2["status_code"]
            }
        
        # Compare content length
        if abs(parsed1["text_length"] - parsed2["text_length"]) > 10:  # More than 10 chars diff
            comparison["differences"]["content_length"] = {
                name1: parsed1["text_length"],
                name2: parsed2["text_length"],
                "difference": abs(parsed1["text_length"] - parsed2["text_length"])
            }
        
        # Compare execution time (timing attack indicator)
        time_diff = abs(parsed1["execution_time"] - parsed2["execution_time"])
        if time_diff > 0.1:  # More than 100ms difference
            comparison["differences"]["timing"] = {
                name1: round(parsed1["execution_time"], 3),
                name2: round(parsed2["execution_time"], 3),
                "difference_ms": round(time_diff * 1000, 2)
            }
        
        # Compare JSON structure
        if parsed1["body_json"] and parsed2["body_json"]:
            json_diff = self._compare_json(parsed1["body_json"], parsed2["body_json"])
            if json_diff:
                comparison["differences"]["json_fields"] = json_diff
        
        # Detect error messages or sensitive info leakage
        error_patterns = self._extract_error_patterns(resp1.text)
        if error_patterns:
            comparison["error_leakage"] = {
                name1: error_patterns
            }
        
        error_patterns2 = self._extract_error_patterns(resp2.text)
        if error_patterns2:
            if "error_leakage" not in comparison:
                comparison["error_leakage"] = {}
            comparison["error_leakage"][name2] = error_patterns2
        
        return comparison
    
    def _compare_json(self, json1: Dict, json2: Dict) -> Dict:
        """
        Compare two JSON objects and return differences.
        """
        differences = {}
        
        all_keys = set(json1.keys()) | set(json2.keys())
        
        for key in all_keys:
            v1 = json1.get(key)
            v2 = json2.get(key)
            
            if v1 != v2:
                differences[key] = {"response1": v1, "response2": v2}
        
        return differences
    
    def _extract_error_patterns(self, text: str) -> List[str]:
        """
        Extract error messages and stack traces that might leak info.
        """
        patterns = [
            r"(Error|Exception):\s*([^\n]+)",
            r"(File|line|at).*?:\s*(\d+)",
            r"(password|secret|token|api_key|apikey).*?[=:]\s*['\"]?([^\s'\"]+)['\"]?",
            r"(username|user_id|email).*?[=:]\s*([^\s,\n]+)",
            r"stack trace|traceback|Exception in",
            r"SQL error|Database error|mysql_|sqlite_|postgresql"
        ]
        
        found = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
            if matches:
                found.extend([str(m) for m in matches])
        
        return found[:10]  # Return first 10 matches
    
    def test_boolean_condition(self, test_func, true_param: str, false_param: str) -> Dict:
        """
        Boolean-based detection test.
        
        Example: Test if SQL injection works via boolean conditions
        - Query with TRUE condition vs FALSE condition
        - Compare responses
        
        Returns indicators of vulnerability
        """
        resp_true = test_func(true_param)
        resp_false = test_func(false_param)
        
        if not resp_true or not resp_false:
            return {"vulnerable": False, "reason": "Could not get responses"}
        
        comparison = self.compare_responses(resp_true, resp_false, "true_condition", "false_condition")
        
        # If content is significantly different, boolean condition works
        if "content_length" in comparison["differences"]:
            diff = comparison["differences"]["content_length"]["difference"]
            if diff > 50:  # More than 50 chars difference
                return {
                    "vulnerable": True,
                    "method": "Boolean-based detection",
                    "evidence": f"Responses differ by {diff} characters",
                    "comparison": comparison
                }
        
        return {"vulnerable": False, "comparison": comparison}
    
    def test_time_based_condition(self, test_url: str, payload_with_delay: str, 
                                  normal_payload: str, delay_seconds: int = 3) -> Dict:
        """
        Time-based detection test (SQL injection, command injection).
        
        Makes two requests:
        - One that should delay by <delay_seconds>
        - One that should be fast
        
        Returns vulnerability indicator
        """
        
        def make_request(payload: str) -> float:
            start = time.time()
            try:
                requests.get(test_url + payload, timeout=delay_seconds + 5, verify=False)
            except requests.exceptions.Timeout:
                pass
            except:
                pass
            return time.time() - start
        
        time_with_delay = make_request(payload_with_delay)
        time_normal = make_request(normal_payload)
        
        return {
            "payload_with_delay": {
                "time_seconds": round(time_with_delay, 2),
                "indication": "Likely vulnerable" if time_with_delay >= delay_seconds else "Not vulnerable"
            },
            "normal_payload": {
                "time_seconds": round(time_normal, 2)
            },
            "time_difference": round(time_with_delay - time_normal, 2),
            "conclusion": "Time-based attack likely works" if (time_with_delay - time_normal) > (delay_seconds * 0.5) else "No timing attack detected"
        }
    
    def analyze_leakage(self, response: requests.Response) -> List[Dict]:
        """
        Analyze response for information leakage.
        """
        leakages = []
        
        # Check for stack traces
        if any(x in response.text.lower() for x in ["traceback", "stacktrace", "at line"]):
            leakages.append({
                "type": "Information Leakage - Stack Trace",
                "severity": "Medium",
                "evidence": "Stack trace or exception information visible in response",
                "remediation": "Disable debug mode in production and handle exceptions silently."
            })
        
        # Check for database errors
        db_patterns = ["SQL error", "mysql", "postgre", "sqlite", "ORA-", "SQLSTATE"]
        if any(x in response.text for x in db_patterns):
            leakages.append({
                "type": "Information Leakage - Database Error",
                "severity": "High",
                "evidence": "Database error messages visible in response",
                "remediation": "Catch database exceptions and return generic error messages."
            })
        
        # Check for file paths
        if re.search(r"/home/|/var/|C:\\|/app/", response.text):
            leakages.append({
                "type": "Information Leakage - File Path",
                "severity": "Medium",
                "evidence": "Absolute file paths visible in response",
                "remediation": "Remove file paths from error messages."
            })
        
        # Check for API keys in response
        if re.search(r"(['\"])?(api[_-]?key|secret|token|password)(['\"])?[=:]\s*['\"]?[a-zA-Z0-9_-]+['\"]?", response.text, re.IGNORECASE):
            leakages.append({
                "type": "Information Leakage - Secrets in Response",
                "severity": "Critical",
                "evidence": "Potential API keys or secrets visible in response",
                "remediation": "Never expose secrets in responses. Use environment variables and secure vaults."
            })
        
        return leakages
    
    def detect_authentication_bypass(self, test_url: str, auth_header_values: List[str]) -> List[Dict]:
        """
        Test various authentication bypass techniques.
        """
        findings = []
        
        bypass_tests = {
            "empty_auth": {"Authorization": ""},
            "null_auth": {"Authorization": "null"},
            "none_auth": {"Authorization": "none"},
            "basic_mock": {"Authorization": "Basic dXNlcjpwYXNzd2Qx"},  # user:passwd1
            "bearer_mock": {"Authorization": "Bearer fake-token"},
            "no_auth": {}  # No auth header at all
        }
        
        for bypass_name, headers in bypass_tests.items():
            try:
                resp = requests.get(test_url, headers=headers, verify=False, timeout=10)
                
                if resp.status_code in [200, 201]:
                    findings.append({
                        "type": "Authentication Bypass",
                        "severity": "Critical",
                        "method": bypass_name,
                        "status_code": resp.status_code,
                        "evidence": f"Endpoint returned {resp.status_code} with {bypass_name} header",
                        "remediation": "Validate authentication token/credentials before processing request."
                    })
            
            except:
                pass
        
        return findings
