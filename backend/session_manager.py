"""
Session Manager - Handles authentication, cookie tracking, and stateful scanning.
Critical for testing IDOR, authorization, and workflow-based vulnerabilities.
"""

import requests
import json
import logging
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SessionManager:
    """
    Maintains authenticated sessions for testing authorization and workflows.
    Supports multiple user contexts for role-based access testing.
    """
    
    def __init__(self):
        self.sessions: Dict[str, requests.Session] = {}
        self.users: Dict[str, Dict] = {}
        self.cookies: Dict[str, Dict] = {}
        self.tokens: Dict[str, str] = {}
        self.request_history: List[Dict] = []
        
    def create_session(self, session_name: str, headers: Dict = None) -> requests.Session:
        """Create a new session context."""
        session = requests.Session()
        session.verify = False
        if headers:
            session.headers.update(headers)
        self.sessions[session_name] = session
        logger.info(f"[+] Created session: {session_name}")
        return session
    
    def register_user(self, user_id: str, username: str, password: str, 
                      role: str = "user", attributes: Dict = None):
        """Register a user profile for multi-user testing."""
        self.users[user_id] = {
            "username": username,
            "password": password,
            "role": role,
            "attributes": attributes or {},
            "session_name": None
        }
        logger.info(f"[+] Registered user: {user_id} (role: {role})")
    
    def login(self, user_id: str, login_url: str, credentials: Dict = None, 
              session_name: str = None) -> Tuple[bool, str]:
        """
        Authenticate a user and establish session.
        
        Returns:
            (success, session_name)
        """
        if user_id not in self.users:
            logger.error(f"[-] User not found: {user_id}")
            return False, None
        
        session_name = session_name or f"session_{user_id}"
        session = self.create_session(session_name)
        
        user = self.users[user_id]
        login_data = credentials or {
            "username": user["username"],
            "password": user["password"]
        }
        
        try:
            response = session.post(login_url, data=login_data, timeout=10)
            
            # Extract cookies
            if session.cookies:
                self.cookies[session_name] = dict(session.cookies)
                logger.info(f"[+] Cookies captured for {session_name}")
            
            # Try to extract JWT or API token from response
            try:
                json_resp = response.json()
                for key in ["token", "access_token", "jwt", "api_key"]:
                    if key in json_resp:
                        self.tokens[session_name] = json_resp[key]
                        session.headers.update({"Authorization": f"Bearer {json_resp[key]}"})
                        logger.info(f"[+] Token captured for {session_name}")
                        break
            except:
                pass
            
            # Check if login was successful
            if response.status_code in [200, 302]:
                self.users[user_id]["session_name"] = session_name
                logger.info(f"[✓] Login successful: {user_id}")
                return True, session_name
            else:
                logger.warning(f"[!] Login may have failed (status: {response.status_code})")
                return True, session_name  # Return True anyway, might work for some apps
                
        except Exception as e:
            logger.error(f"[-] Login error for {user_id}: {str(e)}")
            return False, None
    
    def get_session(self, session_name: str) -> Optional[requests.Session]:
        """Get an authenticated session."""
        return self.sessions.get(session_name)
    
    def request_with_context(self, session_name: str, method: str, url: str, 
                            **kwargs) -> requests.Response:
        """
        Make HTTP request with a specific session context.
        Tracks request/response for workflow analysis.
        """
        session = self.get_session(session_name)
        if not session:
            logger.error(f"[-] Session not found: {session_name}")
            return None
        
        try:
            if method.upper() == "GET":
                response = session.get(url, timeout=10, **kwargs)
            elif method.upper() == "POST":
                response = session.post(url, timeout=10, **kwargs)
            elif method.upper() == "PUT":
                response = session.put(url, timeout=10, **kwargs)
            elif method.upper() == "DELETE":
                response = session.delete(url, timeout=10, **kwargs)
            else:
                response = session.request(method, url, timeout=10, **kwargs)
            
            # Track request in history
            self.request_history.append({
                "session": session_name,
                "method": method.upper(),
                "url": url,
                "status_code": response.status_code,
                "response_length": len(response.content)
            })
            
            logger.info(f"[{response.status_code}] {method.upper()} {url}")
            return response
            
        except Exception as e:
            logger.error(f"[-] Request error: {str(e)}")
            return None
    
    def get_user_by_id(self, user_id: str) -> Dict:
        """Get user information."""
        return self.users.get(user_id)
    
    def list_sessions(self) -> List[str]:
        """List all active sessions."""
        return list(self.sessions.keys())
    
    def list_users(self) -> List[str]:
        """List all registered users."""
        return list(self.users.keys())
    
    def clear_session(self, session_name: str):
        """Clear a session."""
        if session_name in self.sessions:
            del self.sessions[session_name]
            logger.info(f"[+] Cleared session: {session_name}")
    
    def export_cookies(self, session_name: str) -> Dict:
        """Export cookies from a session."""
        return self.cookies.get(session_name, {})
