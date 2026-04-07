"""
Gemini AI Integration - Intelligent Vulnerability Detection & Analysis

Uses Google Gemini API (google.genai) for:
1. Smart payload generation based on endpoint context
2. Intelligent response analysis
3. Vulnerability pattern recognition
4. Security recommendations
5. Workflow chaining detection
"""

import google.genai as genai
import logging
import json
import re
import time
from typing import List, Dict, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GeminiAnalyzer:
    """
    Leverages Google Gemini AI for intelligent vulnerability detection.
    Uses the new google.genai SDK.
    """
    
    # Model fallback chain - try in order until one works
    AVAILABLE_MODELS = [
        'gemini-2.0-flash',       # Latest, fastest
        'gemini-2.0-flash-lite',  # Lightweight option
        'gemini-1.5-flash',       # Proven stable performer
        'gemini-1.5-pro',         # Heavier model if needed
    ]
    
    def __init__(self, api_key: str = None):
        """
        Initialize Gemini with API key and model selection using new google.genai SDK.
        
        Args:
            api_key: Google Gemini API key. If None, reads from GEMINI_API_KEY env var
        """
        self.client = None
        self.model = None
        self.model_name = None
        
        # Get API key
        if api_key:
            key = api_key
        else:
            import os
            key = os.getenv("GEMINI_API_KEY")
            if not key:
                logger.warning("[!] GEMINI_API_KEY not set. Gemini features disabled.")
                return
        
        # Initialize client with the new SDK
        try:
            self.client = genai.Client(api_key=key)
            logger.debug("[+] Gemini client initialized")
        except Exception as e:
            logger.error(f"[-] Failed to initialize Gemini client: {str(e)}")
            return
        
        # Try to find an available model
        for model_name in self.AVAILABLE_MODELS:
            try:
                logger.debug(f"[*] Testing model: {model_name}")
                # In new SDK, we don't need to test the model during init
                # Just store it and test on first use
                self.model = model_name
                self.model_name = model_name
                logger.info(f"[+] Selected model: {model_name}")
                return
            except Exception as e:
                logger.debug(f"[-] Model {model_name} test failed: {str(e)}")
                continue
        
        logger.warning("[!] No suitable model selected")
        self.model = self.AVAILABLE_MODELS[0]  # Use first as fallback
        self.model_name = self.AVAILABLE_MODELS[0]
        logger.info(f"[+] Using fallback model: {self.model_name}")
    
    def is_available(self) -> bool:
        """Check if Gemini is configured and available."""
        return self.client is not None and self.model is not None
    
    def _safe_generate(self, prompt: str, max_retries: int = 2) -> Optional[str]:
        """
        Safely generate content with retry logic for rate limiting.
        
        Args:
            prompt: The prompt to send to Gemini
            max_retries: Number of retries on failure
            
        Returns:
            Response text or None if all retries failed
        """
        if not self.is_available():
            return None
        
        for attempt in range(max_retries + 1):
            try:
                # Use the new google.genai SDK API
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config={
                        "temperature": 0.7,
                        "max_output_tokens": 2048,
                        "safety_settings": [
                            {
                                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                                "threshold": "BLOCK_NONE"
                            },
                            {
                                "category": "HARM_CATEGORY_HARASSMENT",
                                "threshold": "BLOCK_NONE"
                            }
                        ]
                    }
                )
                
                if not response or not response.text:
                    logger.debug(f"[!] Empty response from Gemini")
                    return None
                
                return response.text
                
            except Exception as e:
                error_str = str(e)
                
                # Handle rate limiting
                if "429" in error_str or "quota" in error_str.lower():
                    if attempt < max_retries:
                        wait_time = (2 ** attempt) * 5  # Exponential backoff: 5s, 10s, 20s
                        logger.warning(f"[!] Rate limited. Waiting {wait_time}s before retry...")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error(f"[!] Rate limit exceeded after {max_retries} retries")
                        return None
                
                # Handle service unavailable
                elif "503" in error_str or "service unavailable" in error_str.lower():
                    if attempt < max_retries:
                        wait_time = (2 ** attempt) * 10
                        logger.warning(f"[!] Service unavailable. Waiting {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error(f"[!] Service unavailable after {max_retries} retries")
                        return None
                
                # Handle other errors
                else:
                    logger.error(f"[!] Gemini error: {error_str}")
                    return None
        
        return None
    
    def analyze_endpoint(self, endpoint: str, method: str = "GET", 
                        parameters: List[str] = None, response_sample: str = None) -> Dict:
        """
        Use Gemini to analyze an endpoint and suggest attacks.
        
        Args:
            endpoint: URL/endpoint path
            method: HTTP method
            parameters: Query/body parameters
            response_sample: Sample response content
        
        Returns:
            Analysis with suggested vulnerabilities and payloads
        """
        if not self.is_available():
            return {"error": "Gemini not available"}
        
        params_str = ", ".join(parameters) if parameters else "none"
        
        prompt = f"""
        Analyze this web API endpoint for security vulnerabilities:
        
        Endpoint: {endpoint}
        Method: {method}
        Parameters: {params_str}
        Response Sample: {response_sample[:200] if response_sample else "N/A"}
        
        Identify potential vulnerabilities that could exist here:
        1. IDOR (parameter-based access control issues)
        2. Authorization flaws (missing role checks)
        3. Parameter manipulation possibilities
        4. Information leakage
        5. Common attack vectors for this type of endpoint
        
        Return a JSON with:
        {{
            "endpoint_purpose": "what this endpoint likely does",
            "parameter_analysis": {{"param_name": "vulnerability_type", ...}},
            "potential_vulnerabilities": ["list of likely vulns"],
            "suggested_tests": ["test 1", "test 2", ...],
            "risk_level": "critical/high/medium/low",
            "notes": "any other observations"
        }}
        
        Be specific and actionable. Focus on logic flaws, not just injection.
        """
        
        try:
            text = self._safe_generate(prompt)
            if not text:
                return {"error": "Gemini unavailable or rate limited"}
            
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            
            if json_match:
                analysis = json.loads(json_match.group())
                logger.info(f"[+] Gemini analyzed endpoint: {endpoint}")
                return analysis
            else:
                logger.warning(f"[!] Could not extract JSON from Gemini response")
                return {"raw_analysis": text}
        
        except Exception as e:
            logger.error(f"[-] Gemini analysis error: {str(e)}")
            return {"error": str(e)}
    
    def generate_smart_payloads(self, endpoint: str, parameter: str, 
                               response_context: str = None) -> List[str]:
        """
        Generate smart, context-aware payloads using Gemini.
        
        Not just generic injection - tailored to the endpoint.
        """
        if not self.is_available():
            return []
        
        prompt = f"""
        Generate security testing payloads for this parameter:
        
        Endpoint: {endpoint}
        Parameter: {parameter}
        Context: {response_context or "unknown"}
        
        Generate payloads that test for:
        1. Type confusion (string vs number vs boolean)
        2. Boundary conditions (0, -1, very large numbers)
        3. Special values that might bypass filters
        4. ID manipulation patterns
        5. Authorization bypasses
        
        Return ONLY a JSON array of payloads:
        ["payload1", "payload2", ...]
        
        Be creative but realistic. Focus on logic flaws.
        """
        
        try:
            text = self._safe_generate(prompt)
            if not text:
                return []
            
            # Extract array from response
            match = re.search(r'\[.*\]', text, re.DOTALL)
            
            if match:
                payloads = json.loads(match.group())
                logger.info(f"[+] Generated {len(payloads)} smart payloads")
                return payloads
            else:
                return []
        
        except Exception as e:
            logger.error(f"[-] Payload generation error: {str(e)}")
            return []
    
    def analyze_responses(self, responses: Dict[str, Any]) -> Dict:
        """
        Compare and analyze multiple responses to find vulnerabilities.
        
        Uses Gemini to intelligently detect subtle differences.
        """
        if not self.is_available():
            return {}
        
        # Prepare response data
        resp_summary = {}
        for name, resp in responses.items():
            if isinstance(resp, dict):
                resp_summary[name] = {
                    "status": resp.get("status_code", "?"),
                    "size": len(resp.get("body", "")),
                    "content_sample": resp.get("body", "")[:300]
                }
        
        prompt = f"""
        Analyze these HTTP responses for security vulnerabilities:
        
        {json.dumps(resp_summary, indent=2)}
        
        Look for:
        1. Different status codes indicating authorization differences
        2. Content size differences suggesting data leakage
        3. Presence/absence of sensitive fields
        4. Error messages that differ
        5. Patterns indicating IDOR or broken access control
        
        Return JSON:
        {{
            "findings": ["finding1", "finding2", ...],
            "likely_vulnerability": "type of vulnerability",
            "confidence": "high/medium/low",
            "exploitation_steps": ["step1", "step2", ...],
            "severity": "critical/high/medium/low"
        }}
        """
        
        try:
            text = self._safe_generate(prompt)
            if not text:
                return {}
            
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                return analysis
            else:
                return {"raw_analysis": text}
        
        except Exception as e:
            logger.error(f"[-] Response analysis error: {str(e)}")
            return {}
    
    def detect_stored_xss_hotspots(self, forms: List[Dict], 
                                   pages_data: List[Dict]) -> List[Dict]:
        """
        Use Gemini to identify where form inputs might be stored and reflected.
        
        Detects stored XSS by analyzing form-to-display patterns.
        """
        if not self.is_available():
            return []
        
        # Prepare data
        forms_summary = json.dumps(forms[:3], indent=2) if forms else "[]"
        pages_summary = json.dumps([p.get("path") for p in pages_data[:5]]) if pages_data else "[]"
        
        prompt = f"""
        Analyze forms and website structure for stored XSS vulnerabilities:
        
        Forms on site:
        {forms_summary}
        
        Pages on site:
        {pages_summary}
        
        Identify where form data might be stored and displayed later:
        1. Admin dashboards displaying user submissions
        2. User profile pages showing editable fields
        3. Report generators using user input
        4. Comment/feedback sections
        5. Notification centers
        
        Return JSON:
        {{
            "hotspots": [
                {{
                    "form_field": "field_name",
                    "likely_storage": "where data is stored",
                    "likely_reflection": "where it might appear",
                    "attack_chain": "how to exploit",
                    "risk": "high/medium"
                }},
                ...
            ]
        }}
        
        Be specific about relationships between forms and displays.
        """
        
        try:
            text = self._safe_generate(prompt)
            if not text:
                return []
            
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                hotspots = analysis.get("hotspots", [])
                logger.info(f"[+] Identified {len(hotspots)} stored XSS hotspots")
                return hotspots
            else:
                return []
        
        except Exception as e:
            logger.error(f"[-] Stored XSS detection error: {str(e)}")
            return []
    
    def analyze_file_upload_risks(self, upload_endpoints: List[str]) -> List[Dict]:
        """
        Analyze file upload endpoints for vulnerabilities.
        """
        if not self.is_available():
            return []
        
        if not upload_endpoints:
            return []
        
        endpoints_str = "\n".join(upload_endpoints)
        
        prompt = f"""
        Analyze these file upload endpoints for vulnerabilities:
        
        {endpoints_str}
        
        For each endpoint, identify:
        1. Likely file type restrictions
        2. Possible bypass techniques
        3. Storage location of uploads
        4. Potential access paths
        5. Attack vectors (XXE, polyglots, SSRF, etc.)
        
        Return JSON array:
        [
            {{
                "endpoint": "/upload/path",
                "restrictions": "likely restrictions",
                "bypass_techniques": ["technique1", "technique2"],
                "storage_path": "estimated storage",
                "vulnerabilities": ["vuln1", "vuln2"],
                "exploit_chain": "how to exploit"
            }},
            ...
        ]
        """
        
        try:
            text = self._safe_generate(prompt)
            if not text:
                return []
            
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                analysis = json.loads(match.group())
                logger.info(f"[+] Analyzed {len(analysis)} file upload endpoints")
                return analysis
            else:
                return []
        
        except Exception as e:
            logger.error(f"[-] File upload analysis error: {str(e)}")
            return []
    
    def detect_workflow_chains(self, crawled_urls: List[str], 
                              discovered_apis: List[str]) -> List[Dict]:
        """
        Use Gemini to detect multi-step attack chains.
        
        Example: Form submission → Data storage → Admin display → Exploitation
        """
        if not self.is_available():
            return []
        
        urls_sample = "\n".join(crawled_urls[:15]) if crawled_urls else "no urls"
        apis_sample = "\n".join(discovered_apis[:15]) if discovered_apis else "no apis"
        
        prompt = f"""
        Analyze this web application for multi-step attack chains:
        
        URLs discovered:
        {urls_sample}
        
        APIs discovered:
        {apis_sample}
        
        Look for workflows like:
        1. Submit data → Data stored → Display in admin → Exploit
        2. User registration → Profile page → IDOR to other profiles
        3. File upload → Processing → Public access
        4. Form submission → Email notification → Exploit in email
        5. API data → Report generation → XSS in report
        
        Return JSON:
        {{
            "chains": [
                {{
                    "name": "chain_name",
                    "steps": ["step1", "step2", "step3"],
                    "entry_point": "/form/url",
                    "exploitation_point": "/admin/page",
                    "vulnerability_types": ["type1", "type2"],
                    "impact": "high/medium/low",
                    "proof_of_concept": "how to exploit"
                }},
                ...
            ]
        }}
        """
        
        try:
            text = self._safe_generate(prompt)
            if not text:
                return []
            
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                chains = analysis.get("chains", [])
                logger.info(f"[+] Detected {len(chains)} attack chains")
                return chains
            else:
                return []
        
        except Exception as e:
            logger.error(f"[-] Workflow chain detection error: {str(e)}")
            return []
    
    def generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """
        Generate actionable security recommendations using Gemini.
        """
        if not self.is_available():
            return []
        
        if not vulnerabilities:
            return []
        
        vuln_summary = json.dumps(vulnerabilities[:10], indent=2)
        
        prompt = f"""
        Generate security remediation recommendations for these vulnerabilities:
        
        {vuln_summary}
        
        For each vulnerability, provide:
        1. Root cause analysis
        2. Immediate fix (short-term)
        3. Proper fix (long-term)
        4. Testing to verify fix
        5. Prevention for future
        
        Return array of detailed recommendations:
        ["recommendation1", "recommendation2", ...]
        
        Be specific and actionable.
        """
        
        try:
            text = self._safe_generate(prompt)
            if not text:
                return []
            
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                recommendations = json.loads(match.group())
                return recommendations
            else:
                return [text]
        
        except Exception as e:
            logger.error(f"[-] Recommendation generation error: {str(e)}")
            return []
    
    def identify_hidden_endpoints(self, js_content: List[str]) -> List[str]:
        """
        Use Gemini to identify hidden or forgotten endpoints from JS.
        
        More intelligent than regex - understands context.
        """
        if not self.is_available():
            return []
        
        if not js_content:
            return []
        
        js_sample = "\n".join(js_content[:5])
        
        prompt = f"""
        Extract and identify API endpoints from this JavaScript:
        
        {js_sample}
        
        Look for:
        1. API endpoints (http/https paths)
        2. Hidden endpoints (debug, admin, test)
        3. Old/deprecated endpoints
        4. Internal-only endpoints
        5. Admin/developer backdoors
        6. Development/staging endpoints
        
        Return JSON array with analysis:
        [
            {{
                "endpoint": "/api/path",
                "type": "hidden/debug/admin/deprecated",
                "likely_purpose": "what it does",
                "authentication": "likely auth required",
                "exposure_risk": "high/medium/low"
            }},
            ...
        ]
        """
        
        try:
            text = self._safe_generate(prompt)
            if not text:
                return []
            
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                endpoints = json.loads(match.group())
                logger.info(f"[+] Identified {len(endpoints)} endpoints")
                return endpoints
            else:
                return []
        
        except Exception as e:
            logger.error(f"[-] Endpoint identification error: {str(e)}")
            return []
