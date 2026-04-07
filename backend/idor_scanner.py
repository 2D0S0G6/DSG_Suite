"""
IDOR Scanner - Detects Insecure Direct Object References and Authorization Flaws.

The #1 vulnerability in education platforms:
- Sequential IDs (student IDs, roll numbers)
- Predictable object references
- Missing authorization checks on resource access
"""

import requests
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Tuple
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IDORScanner:
    """
    Tests for Insecure Direct Object Reference by:
    1. Identifying numeric parameters
    2. Testing ID mutation (increment, decrement, swap)
    3. Comparing responses for content differences
    4. Testing cross-user access
    """
    
    def __init__(self, session_manager=None):
        self.session_manager = session_manager
        self.findings: List[Dict] = []
    
    def extract_numeric_ids(self, url: str) -> List[Tuple[str, str]]:
        """
        Extract numeric parameters that might be object IDs.
        Returns list of (param_name, value) tuples.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        numeric_ids = []
        
        # Check query parameters
        for key, values in params.items():
            if values and values[0].isdigit():
                numeric_ids.append(("query", key, values[0]))
        
        # Check URL path for numeric patterns (e.g., /user/123, /student/456)
        path_segments = parsed.path.split("/")
        for i, segment in enumerate(path_segments):
            if segment.isdigit() and i > 0:
                numeric_ids.append(("path", f"segment_{i}", segment))
        
        return numeric_ids
    
    def mutate_id(self, value: str, mutation_type: str = "increment") -> str:
        """
        Generate mutations of an ID for testing.
        
        Types:
        - increment: 123 -> 124
        - decrement: 123 -> 122
        - double: 123 -> 246
        - halve: 124 -> 62
        - rotate: 123 -> 321
        """
        try:
            num = int(value)
            
            if mutation_type == "increment":
                return str(num + 1)
            elif mutation_type == "decrement":
                return str(num - 1)
            elif mutation_type == "double":
                return str(num * 2)
            elif mutation_type == "halve":
                return str(num // 2)
            elif mutation_type == "zero":
                return "0"
            elif mutation_type == "rotate":
                return value[::-1]
            
        except:
            pass
        
        return value
    
    def build_mutated_url(self, url: str, id_location: Tuple, 
                         param_name: str, new_value: str) -> str:
        """Build a URL with a mutated ID parameter."""
        parsed = urlparse(url)
        
        if id_location == "query":
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param_name] = [new_value]
            new_query = urlencode(params, doseq=True)
            parsed = parsed._replace(query=new_query)
            return urlunparse(parsed)
        
        elif id_location == "path":
            # Simple path replacement
            path = parsed.path.replace(param_name.split("_")[-1], new_value)
            parsed = parsed._replace(path=path)
            return urlunparse(parsed)
        
        return url
    
    def compare_responses(self, resp1: requests.Response, resp2: requests.Response) -> Dict:
        """
        Compare two responses to detect if different content is returned.
        Returns similarity metrics.
        """
        result = {
            "status_same": resp1.status_code == resp2.status_code,
            "length_diff": abs(len(resp1.text) - len(resp2.text)),
            "content_different": resp1.text != resp2.text,
            "status_codes": (resp1.status_code, resp2.status_code),
            "response_sizes": (len(resp1.text), len(resp2.text))
        }
        
        return result
    
    def test_idor(self, base_url: str, session_name: str = None, 
                  num_mutations: int = 5) -> List[Dict]:
        """
        Test a URL for IDOR vulnerabilities.
        
        Logic:
        1. Extract numeric IDs
        2. Mutate them (increment, decrement, etc.)
        3. Compare responses
        4. If different user data returned → IDOR!
        """
        findings = []
        
        numeric_ids = self.extract_numeric_ids(base_url)
        
        if not numeric_ids:
            logger.info(f"[*] No numeric IDs found in: {base_url}")
            return findings
        
        # Initial request
        if self.session_manager and session_name:
            resp1 = self.session_manager.request_with_context(session_name, "GET", base_url)
        else:
            resp1 = requests.get(base_url, verify=False, timeout=10)
        
        if not resp1 or resp1.status_code != 200:
            logger.warning(f"[!] Cannot access base URL: {base_url}")
            return findings
        
        original_content = resp1.text
        
        # Test each numeric ID parameter
        for location, param_name, original_value in numeric_ids:
            logger.info(f"[*] Testing IDOR on {param_name} = {original_value}")
            
            # Try different mutations
            mutations = ["increment", "decrement"]
            
            for mutation in mutations:
                mutated_value = self.mutate_id(original_value, mutation)
                
                if mutated_value == original_value:
                    continue
                
                # Build mutated URL
                mutated_url = base_url.replace(original_value, mutated_value)
                
                # Test with same session (same user)
                if self.session_manager and session_name:
                    resp2 = self.session_manager.request_with_context(session_name, "GET", mutated_url)
                else:
                    resp2 = requests.get(mutated_url, verify=False, timeout=10)
                
                if not resp2:
                    continue
                
                # Compare responses
                comparison = self.compare_responses(resp1, resp2)
                
                # Suspicious if:
                # 1. Status is same but content is different (different user data)
                # 2. Very different response sizes
                if comparison["content_different"] and comparison["status_same"]:
                    
                    # Try to detect sensitive data leakage
                    sensitive_patterns = [
                        r"(student|user|email|phone|ssn|roll|id|name).*?:\s*([^\",\n}]+)",
                        r"(password|secret|token|key).*?:\s*([^\",\n}]+)",
                        r"marks?.*?:\s*(\d+)",
                        r"grade.*?:\s*([A-F])",
                    ]
                    
                    resp1_sensitive = []
                    resp2_sensitive = []
                    
                    for pattern in sensitive_patterns:
                        resp1_sensitive.extend(re.findall(pattern, resp1.text, re.IGNORECASE))
                        resp2_sensitive.extend(re.findall(pattern, resp2.text, re.IGNORECASE))
                    
                    # If different sensitive data, definitely IDOR
                    if resp1_sensitive != resp2_sensitive and resp2_sensitive:
                        findings.append({
                            "type": "IDOR",
                            "severity": "Critical",
                            "parameter": param_name,
                            "original_value": original_value,
                            "mutated_value": mutated_value,
                            "mutation_type": mutation,
                            "url": mutated_url,
                            "evidence": "Different user data returned for modified ID",
                            "response_size_diff": comparison["length_diff"],
                            "explanation": f"The parameter '{param_name}' is not properly validated. Changing {original_value} to {mutated_value} returns different user's data.",
                            "remediation": "Implement proper authorization checks. Verify that the current user owns/can access the requested resource ID."
                        })
                        logger.info(f"[!] IDOR FOUND: {param_name}")
        
        return findings
    
    def test_idor_with_different_users(self, url: str, user_sessions: Dict[str, str]) -> List[Dict]:
        """
        Advanced IDOR test: Try accessing resources as different users.
        
        Args:
            url: Target URL with ID parameter
            user_sessions: Dict of user_id -> session_name
        """
        findings = []
        
        numeric_ids = self.extract_numeric_ids(url)
        
        if not numeric_ids:
            return findings
        
        responses_by_user = {}
        
        # Get responses for each user
        for user_id, session_name in user_sessions.items():
            if self.session_manager:
                resp = self.session_manager.request_with_context(session_name, "GET", url)
            else:
                resp = requests.get(url, verify=False, timeout=10)
            
            if resp:
                responses_by_user[user_id] = resp.text
        
        # Check if users can access each other's data
        user_ids = list(responses_by_user.keys())
        
        for i, user_a in enumerate(user_ids):
            if i == 0:
                continue
            
            for param_location, param_name, original_id in numeric_ids:
                # Extract ID from first user's response
                other_users_accessed = []
                
                for user_b in user_ids:
                    if user_a == user_b:
                        continue
                    
                    resp_a = responses_by_user[user_a]
                    resp_b = responses_by_user[user_b]
                    
                    # If user A sees user B's unique identifiers in response, it's IDOR
                    unique_patterns = re.findall(r"(UserID|StudentID|Roll|Email).*?:\s*([^\",\n}]+)", resp_b)
                    
                    for pattern in unique_patterns:
                        if pattern[1] in resp_a:
                            other_users_accessed.append(user_b)
                
                if other_users_accessed:
                    findings.append({
                        "type": "IDOR - Cross-User Access",
                        "severity": "Critical",
                        "current_user": user_a,
                        "accessed_users": other_users_accessed,
                        "url": url,
                        "evidence": f"User {user_a} can see {other_users_accessed}'s data",
                        "explanation": "Authorization check missing - users can access other users' data",
                        "remediation": "Add authorization checks before returning user data."
                    })
        
        return findings
    
    def scan_api_endpoints(self, endpoints: List[str], session_name: str = None) -> List[Dict]:
        """
        Scan common API endpoints that often have IDOR.
        
        Common vulnerable endpoints:
        /api/student/{id}
        /api/user/{id}/profile
        /api/result/{id}
        /api/grades/{student_id}
        """
        findings = []
        
        for endpoint in endpoints:
            results = self.test_idor(endpoint, session_name)
            findings.extend(results)
        
        return findings
