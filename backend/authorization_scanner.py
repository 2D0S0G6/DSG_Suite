"""
Authorization Scanner - Tests role-based access control (RBAC) violations.

Common education platform roles:
- Student
- Teacher
- Admin
- Moderator

Vulnerability: A student accessing /api/admin/* or teacher endpoints
"""

import requests
import logging
from typing import List, Dict, Tuple
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuthorizationScanner:
    """
    Tests for broken authorization by:
    1. Identifying role-based endpoints
    2. Testing access with lower privileges
    3. Testing access without authentication
    4. Detecting privilege escalation
    """
    
    def __init__(self, session_manager=None):
        self.session_manager = session_manager
        self.findings: List[Dict] = []
        
        # Common role-based endpoint patterns
        self.admin_patterns = [
            "/admin", "/dashboard", "/manage", "/control",
            "/api/admin", "/api/v1/admin", "/api/management",
            "/api/users", "/api/accounts", "/api/settings",
            "/api/system", "/api/config", "/api/reports",
            "/backend", "/internal", "/staff", "/moderator"
        ]
        
        self.teacher_patterns = [
            "/teacher", "/instructor", "/faculty",
            "/api/teacher", "/api/instructor",
            "/marks", "/grades", "/evaluation",
            "/api/marks", "/api/grades",
            "/student-list", "/api/students", "/api/class"
        ]
        
        self.public_patterns = [
            "/home", "/index", "/about", "/login", "/register",
            "/api/public", "/api/info"
        ]
    
    def identify_endpoints(self, crawled_urls: List[str]) -> Dict[str, List[str]]:
        """
        Categorize endpoints by access level based on URL patterns.
        """
        categorized = {
            "admin": [],
            "teacher": [],
            "student": [],
            "public": [],
            "unknown": []
        }
        
        for url in crawled_urls:
            path = urlparse(url).path.lower()
            
            is_admin = any(pattern in path for pattern in self.admin_patterns)
            is_teacher = any(pattern in path for pattern in self.teacher_patterns)
            is_public = any(pattern in path for pattern in self.public_patterns)
            
            if is_admin:
                categorized["admin"].append(url)
            elif is_teacher:
                categorized["teacher"].append(url)
            elif is_public:
                categorized["public"].append(url)
            else:
                categorized["unknown"].append(url)
        
        return categorized
    
    def test_unauthenticated_access(self, endpoint: str) -> Tuple[bool, int, str]:
        """
        Test if endpoint is accessible without authentication.
        
        Returns:
            (is_accessible, status_code, response_snippet)
        """
        try:
            # Request without any session/cookie
            session = requests.Session()
            response = session.get(endpoint, verify=False, timeout=10, allow_redirects=False)
            
            is_accessible = response.status_code in [200, 201, 202]
            response_snippet = response.text[:200]
            
            logger.info(f"[{response.status_code}] Unauthenticated: {endpoint}")
            
            return is_accessible, response.status_code, response_snippet
            
        except Exception as e:
            logger.error(f"[-] Error testing {endpoint}: {str(e)}")
            return False, 0, str(e)
    
    def test_cross_role_access(self, endpoint: str, user_sessions: Dict[str, Dict]) -> List[Dict]:
        """
        Test if different roles can access each other's endpoints.
        
        Args:
            endpoint: Target endpoint
            user_sessions: Dict of role -> session_name
        
        Returns:
            List of authorization bypass findings
        """
        findings = []
        
        responses = {}
        status_codes = {}
        
        # Get responses from each role
        for role, session_name in user_sessions.items():
            if self.session_manager:
                resp = self.session_manager.request_with_context(session_name, "GET", endpoint)
            else:
                resp = requests.get(endpoint, verify=False, timeout=10)
            
            if resp:
                responses[role] = resp.text[:500]
                status_codes[role] = resp.status_code
        
        # Check for inconsistent access patterns
        access_map = {role: status in [200, 201, 202] for role, status in status_codes.items()}
        
        # For admin endpoints, only admin should have access (200)
        if "admin" in endpoint.lower():
            for role in ["student", "teacher", "guest"]:
                if role in access_map and access_map[role]:
                    findings.append({
                        "type": "Broken Access Control - Privilege Escalation",
                        "severity": "Critical",
                        "endpoint": endpoint,
                        "unauthorized_role": role,
                        "status_code": status_codes.get(role, 0),
                        "expected_access": "admin_only",
                        "actual_access": role,
                        "evidence": f"{role} user received HTTP {status_codes.get(role, 0)} on admin endpoint",
                        "explanation": f"A {role} user can access admin-only endpoint with successful response code.",
                        "remediation": "Implement proper role-based authorization checks. Deny access to non-authenticated or unprivileged users."
                    })
        
        # For teacher endpoints, students shouldn't have access
        if "teacher" in endpoint.lower() or "grade" in endpoint.lower() or "mark" in endpoint.lower():
            for role in ["student", "guest"]:
                if role in access_map and access_map[role]:
                    findings.append({
                        "type": "Broken Access Control - Unauthorized Access",
                        "severity": "High",
                        "endpoint": endpoint,
                        "unauthorized_role": role,
                        "status_code": status_codes.get(role, 0),
                        "expected_access": "teacher_only",
                        "actual_access": role,
                        "evidence": f"{role} user received HTTP {status_codes.get(role, 0)} on teacher endpoint",
                        "explanation": f"A {role} user can access teacher-restricted endpoint.",
                        "remediation": "Add authorization checks to ensure only teachers can access grading/marking endpoints."
                    })
        
        return findings
    
    def test_missing_authorization(self, endpoint: str) -> Dict:
        """
        Test if endpoint has missing authorization (accessible to all).
        """
        finding = {
            "type": "Missing Authorization",
            "endpoint": endpoint,
            "is_vulnerable": False,
            "status_code": 0
        }
        
        try:
            resp = requests.get(endpoint, verify=False, timeout=10, allow_redirects=False)
            finding["status_code"] = resp.status_code
            
            # If admin/protected endpoint returns 200, it's likely vulnerable
            if "admin" in endpoint.lower() or "api" in endpoint.lower():
                if resp.status_code == 200:
                    finding["is_vulnerable"] = True
                    finding["severity"] = "Critical"
                    finding["evidence"] = f"Protected endpoint returned {resp.status_code}"
                    finding["remediation"] = "Add authentication and authorization checks to protect endpoints."
        
        except Exception as e:
            finding["error"] = str(e)
        
        return finding
    
    def test_method_override_bypass(self, endpoint: str, session_name: str = None) -> List[Dict]:
        """
        Test if authorization can be bypassed using HTTP method overrides.
        
        Common bypass techniques:
        - POST /api/admin/delete -> GET /api/admin/delete
        - X-HTTP-Method-Override header
        - _method parameter
        """
        findings = []
        
        methods_to_test = ["HEAD", "PATCH", "TRACE", "CONNECT"]
        
        for method in methods_to_test:
            try:
                if self.session_manager and session_name:
                    resp = self.session_manager.request_with_context(session_name, method, endpoint)
                else:
                    resp = requests.request(method, endpoint, verify=False, timeout=10)
                
                if resp and resp.status_code in [200, 201, 204]:
                    findings.append({
                        "type": "Authorization Bypass - HTTP Method Override",
                        "severity": "High",
                        "endpoint": endpoint,
                        "method": method,
                        "status_code": resp.status_code,
                        "evidence": f"Endpoint accessible via {method} when restricted to POST/GET",
                        "explanation": "Authorization check may not cover all HTTP methods.",
                        "remediation": "Ensure authorization is enforced regardless of HTTP method used."
                    })
                    logger.info(f"[!] HTTP Method bypass found: {method} {endpoint}")
            
            except:
                pass
        
        # Test X-HTTP-Method-Override header
        try:
            headers = {"X-HTTP-Method-Override": "DELETE"}
            if self.session_manager and session_name:
                resp = self.session_manager.request_with_context(session_name, "GET", endpoint, headers=headers)
            else:
                resp = requests.get(endpoint, headers=headers, verify=False, timeout=10)
            
            if resp and resp.status_code == 204:
                findings.append({
                    "type": "Authorization Bypass - X-HTTP-Method-Override",
                    "severity": "High",
                    "endpoint": endpoint,
                    "header": "X-HTTP-Method-Override: DELETE",
                    "status_code": resp.status_code,
                    "evidence": "Endpoint allowed method override via header",
                    "remediation": "Disable HTTP method override if not needed, or validate properly."
                })
        
        except:
            pass
        
        return findings
    
    def scan_all_endpoints(self, crawled_urls: List[str], 
                          user_sessions: Dict[str, str] = None) -> List[Dict]:
        """
        Comprehensive authorization scan across all endpoints.
        """
        all_findings = []
        
        # Categorize endpoints
        categorized = self.identify_endpoints(crawled_urls)
        
        logger.info(f"[*] Found {len(categorized['admin'])} admin endpoints")
        logger.info(f"[*] Found {len(categorized['teacher'])} teacher endpoints")
        
        # Test admin endpoints
        for endpoint in categorized['admin']:
            is_accessible, status, _ = self.test_unauthenticated_access(endpoint)
            
            if is_accessible:
                all_findings.append({
                    "type": "Unauthenticated Access to Admin",
                    "severity": "Critical",
                    "endpoint": endpoint,
                    "status_code": status,
                    "evidence": f"Admin endpoint returned {status} without authentication",
                    "remediation": "Require authentication for all admin endpoints."
                })
            
            # Test cross-role access if we have sessions
            if user_sessions:
                cross_role_findings = self.test_cross_role_access(endpoint, user_sessions)
                all_findings.extend(cross_role_findings)
        
        # Test teacher endpoints for student access
        for endpoint in categorized['teacher']:
            if user_sessions and 'student' in user_sessions:
                findings = self.test_cross_role_access(endpoint, {'student': user_sessions['student']})
                all_findings.extend(findings)
        
        return all_findings
