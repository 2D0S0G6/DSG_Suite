"""
Groq-powered parameter generation for intelligent vulnerability scanning.
Uses AI to suggest likely parameters based on URL structure and context.
"""

import json
import os
import time
from dotenv import load_dotenv
from groq import Groq

# Load environment variables from .env file
load_dotenv()

# Initialize Groq client with API key from .env
api_key = os.getenv("GROQ_API_KEY", "")
client = Groq(api_key=api_key) if api_key else None

# Cache to avoid repeated API calls for similar URLs
PARAM_CACHE = {}

# Rate limiting - don't call Groq more than once per second
last_api_call = 0
API_RATE_LIMIT = 1.0  # seconds between calls

# Default fallback parameters if Groq is unavailable
DEFAULT_COMMON_PARAMS = [
    "id", "q", "search", "query", "url", "redirect", "page",
    "user", "username", "password", "email", "name", "file",
    "path", "cmd", "exec", "action", "data", "callback",
    "sort", "order", "filter", "category", "type", "lang"
]


def generate_parameters_with_groq(url: str, context: dict = None) -> list:
    """
    Use Groq to intelligently generate parameters based on URL analysis.
    
    Args:
        url: The target URL to analyze
        context: Optional dict with extracted forms, js endpoints, etc.
    
    Returns:
        List of likely parameters to test
    """
    if not client or not client.api_key:
        print("[!] GROQ_API_KEY not configured in .env, using default parameters")
        print("[!] Set your API key in /backend/.env - Get one from: https://console.groq.com")
        return DEFAULT_COMMON_PARAMS

    # Check cache first
    cache_key = url.split("?")[0]  # Use base URL as cache key
    if cache_key in PARAM_CACHE:
        return PARAM_CACHE[cache_key]

def generate_parameters_with_groq(url: str, context: dict = None) -> list:
    """
    Use Groq to intelligently generate parameters based on URL analysis.
    
    Args:
        url: The target URL to analyze
        context: Optional dict with extracted forms, js endpoints, etc.
    
    Returns:
        List of likely parameters to test
    """
    if not client or not client.api_key:
        print("[!] GROQ_API_KEY not configured in .env, using default parameters")
        print("[!] Set your API key in /backend/.env - Get one from: https://console.groq.com")
        return DEFAULT_COMMON_PARAMS

    # Check cache first
    cache_key = url.split("?")[0]  # Use base URL as cache key
    if cache_key in PARAM_CACHE:
        return PARAM_CACHE[cache_key]

    try:
        # Rate limiting
        global last_api_call
        current_time = time.time()
        if current_time - last_api_call < API_RATE_LIMIT:
            time.sleep(API_RATE_LIMIT - (current_time - last_api_call))
        last_api_call = time.time()

        # Build context for Groq
        context_str = ""
        if context:
            if "forms" in context:
                form_fields = []
                for form in context["forms"]:
                    for field in form.get("inputs", []):
                        if field.get("name"):
                            form_fields.append(field["name"])
                context_str += f"\nForm fields found: {form_fields}"
            
            if "js_endpoints" in context:
                context_str += f"\nJS endpoints: {context['js_endpoints']}"

        prompt = f"""Analyze this URL and suggest likely parameter names that would be tested for vulnerabilities.

URL: {url}
{context_str}

Based on the URL structure, path, and any context provided, what are the MOST LIKELY parameter names this API/endpoint accepts?
Return a JSON array of parameter names (strings only, no descriptions). Focus on:
1. RESTful resource identifiers
2. Query filters and search parameters
3. Common injection points
4. Parameters visible in form fields

Return ONLY a JSON array like: ["param1", "param2", "param3"]
Maximum 10 parameters."""

        # Try current model first, fallback to another if needed
        models_to_try = ["llama-3.1-8b-instant", "llama3-8b-8192", "mixtral-8x7b-32768"]
        
        for model in models_to_try:
            try:
                message = client.chat.completions.create(
                    model=model,
                    max_tokens=500,
                    messages=[
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    timeout=10  # 10 second timeout
                )
                break  # Success, exit loop
            except Exception as model_error:
                print(f"[!] Model {model} failed: {str(model_error)[:100]}")
                if model == models_to_try[-1]:  # Last model failed
                    raise model_error
                continue

        response_text = message.choices[0].message.content.strip()
        
        # Parse JSON response
        try:
            # Try to extract JSON array from response
            json_start = response_text.find('[')
            json_end = response_text.rfind(']') + 1
            if json_start != -1 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                params = json.loads(json_str)
                
                # Validate and clean
                params = [str(p).strip() for p in params if isinstance(p, str) and p.strip()]
                
                # Cache the result
                PARAM_CACHE[cache_key] = params
                
                print(f"[+] Groq generated {len(params)} parameters for {cache_key}")
                return params
        except json.JSONDecodeError:
            print(f"[!] Failed to parse Groq response: {response_text[:100]}")

    except Exception as e:
        print(f"[!] Groq API error: {str(e)}")

    # Fallback to defaults
    return DEFAULT_COMMON_PARAMS


def generate_parameters(url: str, forms: list = None, js_endpoints: list = None) -> list:
    """
    Main function to generate parameters - tries Groq first, falls back to defaults.
    
    Args:
        url: Target URL
        forms: List of form objects with input fields
        js_endpoints: List of JS endpoints found
    
    Returns:
        List of parameters to test
    """
    context = {}
    params = set(DEFAULT_COMMON_PARAMS)

    # Extract parameters from forms if provided
    if forms:
        context["forms"] = forms
        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("name"):
                    params.add(inp["name"])

    # Extract parameters from URL if present
    if "?" in url:
        query_string = url.split("?")[1]
        for param_pair in query_string.split("&"):
            if "=" in param_pair:
                param_name = param_pair.split("=")[0]
                params.add(param_name)

    if js_endpoints:
        context["js_endpoints"] = js_endpoints

    # Try Groq enhancement
    try:
        groq_params = generate_parameters_with_groq(url, context)
        params.update(groq_params)
    except Exception as e:
        print(f"[!] Groq generation failed, using form params only: {e}")

    return list(params)


def clear_cache():
    """Clear the parameter cache."""
    global PARAM_CACHE
    PARAM_CACHE = {}
