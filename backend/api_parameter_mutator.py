"""
API Parameter Mutation - Logic-based parameter fuzzing.

Instead of random payload injection, we test logical parameter variations:
- ID mutation (123 -> 124)
- Type confusion (int to string)
- Boundary conditions (0, -1, max values)
- Parameter removal
- Parameter duplication
- Parameter ordering
"""

import requests
import logging
import json
from typing import List, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class APIParameterMutator:
    """
    Intelligently mutates API parameters to find logic flaws.
    """
    
    def __init__(self, session_manager=None):
        self.session_manager = session_manager
        self.findings: List[Dict] = []
    
    def extract_parameters(self, url: str, data: Dict = None) -> Dict:
        """
        Extract parameters from URL (query) and optional POST body.
        
        Returns:
            {
                "query_params": [...],
                "body_params": [...],
                "headers": [...]
            }
        """
        params = {"query": {}, "body": {}, "headers": {}}
        
        # Extract query parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for key, values in query_params.items():
            params["query"][key] = values[0] if values else ""
        
        # Extract body parameters
        if data:
            if isinstance(data, dict):
                params["body"] = data.copy()
            elif isinstance(data, str):
                try:
                    params["body"] = json.loads(data)
                except:
                    pass
        
        return params
    
    def generate_mutations(self, value: Any, param_type: str = "string") -> List[Any]:
        """
        Generate intelligent mutations for a parameter value.
        """
        mutations = []
        
        try:
            if param_type == "numeric" or (isinstance(value, str) and value.isdigit()):
                num = int(value)
                mutations = [
                    num + 1,
                    num - 1,
                    num * 2,
                    num // 2 if num > 1 else 0,
                    -num,
                    -1,
                    0,
                    9999,
                    999999,
                ]
            
            elif param_type == "string" or isinstance(value, str):
                mutations = [
                    value + "1",
                    value.upper(),
                    value.lower(),
                    "",  # Empty
                    "admin",
                    "null",
                    "0",
                    value.replace(" ", "+"),
                    value.replace(" ", "%20"),
                ]
            
            elif param_type == "boolean":
                mutations = [True, False, 1, 0, "true", "false", "yes", "no"]
        
        except:
            pass
        
        # Convert all to appropriate types and remove duplicates
        mutations = list(set([str(m) for m in mutations]))
        
        return mutations
    
    def test_parameter_mutation(self, url: str, param_name: str, 
                               base_response: requests.Response,
                               session_name: str = None) -> List[Dict]:
        """
        Mutate a single parameter and compare responses.
        """
        findings = []
        
        parsed = urlparse(url)
        query_params = dict(parse_qs(parsed.query, keep_blank_values=True))
        
        if param_name not in query_params:
            logger.warning(f"Parameter {param_name} not in URL")
            return findings
        
        original_value = query_params[param_name][0]
        mutations = self.generate_mutations(original_value, "numeric")
        
        for mutation in mutations:
            # Build mutated URL
            query_params[param_name] = str(mutation)
            new_query = urlencode(query_params, doseq=True)
            mutated_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                     parsed.params, new_query, parsed.fragment))
            
            # Make request
            if self.session_manager and session_name:
                resp = self.session_manager.request_with_context(session_name, "GET", mutated_url)
            else:
                resp = requests.get(mutated_url, verify=False, timeout=10)
            
            if not resp:
                continue
            
            # Compare with base response
            if resp.status_code != base_response.status_code:
                findings.append({
                    "type": "Parameter-based Access Control Bypass",
                    "parameter": param_name,
                    "original_value": original_value,
                    "mutation": str(mutation),
                    "base_response_status": base_response.status_code,
                    "mutation_response_status": resp.status_code,
                    "url": mutated_url,
                    "evidence": f"Status code changed from {base_response.status_code} to {resp.status_code}",
                    "explanation": "Different status codes for different parameter values indicate logic that distinguishes users/resources.",
                    "risk": "Possible IDOR or authorization bypass"
                })
            
            # Check for content differences > 20% different
            if len(resp.text) != len(base_response.text):
                diff_percent = abs(len(resp.text) - len(base_response.text)) / len(base_response.text) * 100
                
                if diff_percent > 20:
                    findings.append({
                        "type": "Response Content Variation",
                        "parameter": param_name,
                        "mutation": str(mutation),
                        "base_response_size": len(base_response.text),
                        "mutation_response_size": len(resp.text),
                        "size_diff_percent": round(diff_percent, 2),
                        "url": mutated_url,
                        "evidence": f"Response size differs by {diff_percent}%",
                        "explanation": "Content difference suggests the parameter affects data returned.",
                        "risk": "Possible data leakage or unauthorized access"
                    })
        
        return findings
    
    def test_parameter_removal(self, url: str, session_name: str = None) -> List[Dict]:
        """
        Test what happens when required-looking parameters are removed.
        """
        findings = []
        
        parsed = urlparse(url)
        query_params = dict(parse_qs(parsed.query, keep_blank_values=True))
        
        required_param_indicators = ["id", "user", "role", "token", "auth", "session"]
        
        for param_name in query_params.keys():
            # Skip obviously non-critical params
            if any(x in param_name.lower() for x in ["utm", "tracking", "ref"]):
                continue
            
            # Try removing it
            test_params = query_params.copy()
            del test_params[param_name]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                  parsed.params, new_query, parsed.fragment))
            
            # Make request
            if self.session_manager and session_name:
                resp = self.session_manager.request_with_context(session_name, "GET", test_url)
            else:
                resp = requests.get(test_url, verify=False, timeout=10)
            
            if resp and resp.status_code == 200:
                # If endpoint still works without a critical-looking param, suspicious
                if any(x in param_name.lower() for x in required_param_indicators):
                    findings.append({
                        "type": "Missing Authorization Parameter Validation",
                        "severity": "High",
                        "parameter": param_name,
                        "url_without_param": test_url,
                        "status_code": resp.status_code,
                        "evidence": f"Endpoint returned {resp.status_code} even without '{param_name}' parameter",
                        "explanation": "Critical authorization parameter can be removed without affecting access.",
                        "remediation": "Validate all required parameters before processing."
                    })
        
        return findings
    
    def test_type_confusion(self, url: str, param_name: str, 
                           session_name: str = None) -> List[Dict]:
        """
        Test type confusion attacks on parameters.
        Example: Change ID from 123 to "123==", user to ["admin"], etc.
        """
        findings = []
        
        parsed = urlparse(url)
        query_params = dict(parse_qs(parsed.query, keep_blank_values=True))
        
        if param_name not in query_params:
            return findings
        
        original_value = query_params[param_name][0]
        
        # Type confusion tests
        type_tests = {
            "base64": lambda x: __import__('base64').b64encode(x.encode()).decode() if isinstance(x, str) else x,
            "json_array": lambda x: json.dumps([x]),
            "object_injection": lambda x: json.dumps({"value": x}),
            "null_byte": lambda x: x + "\x00",
            "sql_comment": lambda x: str(x) + "-- ",
            "unicode": lambda x: x.encode('utf-8').decode('utf-8', 'ignore'),
        }
        
        for test_name, transform in type_tests.items():
            try:
                test_value = transform(original_value)
                
                if test_value == original_value:
                    continue
                
                query_params[param_name] = test_value
                new_query = urlencode(query_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                      parsed.params, new_query, parsed.fragment))
                
                if self.session_manager and session_name:
                    resp = self.session_manager.request_with_context(session_name, "GET", test_url)
                else:
                    resp = requests.get(test_url, verify=False, timeout=10)
                
                if resp and resp.status_code in [200, 201]:
                    findings.append({
                        "type": "Type Confusion - Possible Bypass",
                        "severity": "Medium",
                        "parameter": param_name,
                        "test_type": test_name,
                        "original_value": original_value,
                        "test_value": test_value,
                        "response_status": resp.status_code,
                        "url": test_url,
                        "evidence": f"Endpoint accepted {test_name} variant of parameter",
                        "explanation": "Type confusion may bypass authorization or input validation.",
                        "remediation": "Validate data types strictly and use type hints."
                    })
            
            except:
                pass
        
        return findings
    
    def scan_api_parameters(self, api_endpoints: List[str], 
                           session_name: str = None) -> List[Dict]:
        """
        Scan all API endpoints for parameter-based vulnerabilities.
        """
        all_findings = []
        
        for endpoint in api_endpoints:
            logger.info(f"[*] Scanning API parameters: {endpoint}")
            
            # Get base response
            if self.session_manager and session_name:
                base_resp = self.session_manager.request_with_context(session_name, "GET", endpoint)
            else:
                base_resp = requests.get(endpoint, verify=False, timeout=10)
            
            if not base_resp:
                continue
            
            # Extract parameters
            params = self.extract_parameters(endpoint)
            
            # Test each parameter
            for param_name in params["query"].keys():
                mutations = self.test_parameter_mutation(endpoint, param_name, base_resp, session_name)
                all_findings.extend(mutations)
                
                removal = self.test_parameter_removal(endpoint, session_name)
                all_findings.extend(removal)
                
                confusion = self.test_type_confusion(endpoint, param_name, session_name)
                all_findings.extend(confusion)
        
        return all_findings
