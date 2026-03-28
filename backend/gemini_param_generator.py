"""
Gemini-powered parameter generation for intelligent vulnerability scanning.
Uses AI to suggest likely parameters based on URL structure and context.
"""

import json
import os
import time
from dotenv import load_dotenv

# Use Google Gemini-compatible client from google.genai
# Fallback will continue using default static parameters in case the package is unavailable.
try:
    import google.genai as gemini
except ImportError:
    gemini = None

# Load environment variables from .env file
load_dotenv()

# Initialize Gemini client with API key from .env
api_key = os.getenv("GEMINI_API_KEY", "")
gemini_client = None
if gemini and api_key:
    try:
        gemini_client = gemini.Client(api_key=api_key)
    except Exception:
        pass

client_available = gemini_client is not None

# Cache to avoid repeated API calls for similar URLs
PARAM_CACHE = {}

# Rate limiting - don't call Gemini more than once per second
last_api_call = 0
API_RATE_LIMIT = 1.0  # seconds between calls

# Default fallback parameters if Gemini is unavailable
DEFAULT_COMMON_PARAMS = [
    "id", "q", "search", "query", "url", "redirect", "page",
    "user", "username", "password", "email", "name", "file",
    "path", "cmd", "exec", "action", "data", "callback",
    "sort", "order", "filter", "category", "type", "lang"
]


def generate_parameters_with_gemini(url: str, context: dict = None) -> list:
    """
    Use Gemini to intelligently generate parameters based on URL analysis.

    Args:
        url: The target URL to analyze
        context: Optional dict with extracted forms, js endpoints, etc.

    Returns:
        List of likely parameters to test
    """
    if not client_available:
        print("[!] GEMINI_API_KEY not configured in .env or generative AI package not installed, using default parameters")
        print("[!] Set your API key in /backend/.env and install the required package (e.g., google.genai).")
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

        # Build context for Gemini
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

Return ONLY a JSON array like: [\"param1\", \"param2\", \"param3\"]
Maximum 20 parameters."""

        models_to_try = []
        try:
            all_models = gemini_client.models.list()
            models_to_try = [m.name for m in all_models if 'gemini' in m.name][:5]
        except Exception:
            # If list_models fails, fallback to common names
            models_to_try = ['gemini-2.5-flash', 'gemini-1.5-flash', 'gemini-1.5-pro']

        if not models_to_try:
            models_to_try = ['gemini-2.5-flash', 'gemini-1.5-flash', 'gemini-1.5-pro']

        response_text = None
        for model_name in models_to_try:
            try:
                clean_model_name = model_name.replace('models/', '')
                response = gemini_client.models.generate_content(model=clean_model_name, contents=prompt)
                response_text = getattr(response, 'text', '')
                if not response_text:
                    response_text = str(response)
                break
            except Exception as model_error:
                print(f"[!] Model {model_name} failed: {str(model_error)[:100]}")
                continue

        if not response_text:
            raise RuntimeError("Gemini response text is empty")

        # Parse JSON response
        try:
            json_start = response_text.find('[')
            json_end = response_text.rfind(']') + 1
            if json_start != -1 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                params = json.loads(json_str)
                params = [str(p).strip() for p in params if isinstance(p, str) and p.strip()]
                PARAM_CACHE[cache_key] = params
                print(f"[+] Gemini generated {len(params)} parameters for {cache_key}")
                return params
            else:
                print(f"[!] Unable to locate JSON array in Gemini response: {response_text[:120]}")
        except json.JSONDecodeError:
            print(f"[!] Failed to parse Gemini response: {response_text[:100]}")

    except Exception as e:
        print(f"[!] Gemini API error: {str(e)}")

    return DEFAULT_COMMON_PARAMS


def generate_parameters(url: str, forms: list = None, js_endpoints: list = None) -> list:
    """
    Main function to generate parameters - tries Gemini first, falls back to defaults.

    Args:
        url: Target URL
        forms: List of form objects with input fields
        js_endpoints: List of JS endpoints found

    Returns:
        List of parameters to test
    """
    context = {}
    params = set(DEFAULT_COMMON_PARAMS)

    if forms:
        context["forms"] = forms
        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("name"):
                    params.add(inp["name"])

    if "?" in url:
        query_string = url.split("?")[1]
        for param_pair in query_string.split("&"):
            if "=" in param_pair:
                param_name = param_pair.split("=")[0]
                params.add(param_name)

    if js_endpoints:
        context["js_endpoints"] = js_endpoints

    try:
        gemini_params = generate_parameters_with_gemini(url, context)
        params.update(gemini_params)
    except Exception as e:
        print(f"[!] Gemini generation failed, using form params only: {e}")

    return list(params)


def clear_cache():
    """Clear the parameter cache."""
    global PARAM_CACHE
    PARAM_CACHE = {}
