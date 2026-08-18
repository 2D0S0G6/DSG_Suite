"""
Groq-powered parameter generation for intelligent vulnerability scanning.
Uses AI to suggest likely parameters based on URL structure and context.
"""

import json
import os
import time
from dotenv import load_dotenv

# Use the official Groq SDK (OpenAI-compatible chat completions).
# Fallback will continue using default static parameters in case the package is unavailable.
try:
    from groq import Groq
except ImportError:
    Groq = None

# Load environment variables from .env file
load_dotenv()

# Initialize Groq client with API key from .env
api_key = os.getenv("GROQ_API_KEY", "")
groq_client = None
if Groq and api_key:
    try:
        groq_client = Groq(api_key=api_key)
    except Exception:
        pass

client_available = groq_client is not None

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
    if not client_available:
        print("[!] GROQ_API_KEY not configured in .env or the groq package is not installed, using default parameters")
        print("[!] Set your API key in /backend/.env and install the required package (pip install groq).")
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

Return ONLY a JSON array like: [\"param1\", \"param2\", \"param3\"]
Maximum 20 parameters."""

        preferred_models = ['openai/gpt-oss-20b', 'openai/gpt-oss-120b', 'qwen/qwen3.6-27b']
        try:
            served = {m.id for m in groq_client.models.list().data}
            models_to_try = [m for m in preferred_models if m in served] or preferred_models
        except Exception:
            # If listing fails, fall back to the preferred ids
            models_to_try = preferred_models

        response_text = None
        for model_name in models_to_try:
            try:
                response = groq_client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.4,
                    max_tokens=512,
                )
                response_text = response.choices[0].message.content if response.choices else ''
                if not response_text:
                    continue
                break
            except Exception as model_error:
                print(f"[!] Model {model_name} failed: {str(model_error)[:100]}")
                continue

        if not response_text:
            raise RuntimeError("Groq response text is empty")

        # Parse JSON response
        try:
            json_start = response_text.find('[')
            json_end = response_text.rfind(']') + 1
            if json_start != -1 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                params = json.loads(json_str)
                params = [str(p).strip() for p in params if isinstance(p, str) and p.strip()]
                PARAM_CACHE[cache_key] = params
                print(f"[+] Groq generated {len(params)} parameters for {cache_key}")
                return params
            else:
                print(f"[!] Unable to locate JSON array in Groq response: {response_text[:120]}")
        except json.JSONDecodeError:
            print(f"[!] Failed to parse Groq response: {response_text[:100]}")

    except Exception as e:
        print(f"[!] Groq API error: {str(e)}")

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
        groq_params = generate_parameters_with_groq(url, context)
        params.update(groq_params)
    except Exception as e:
        print(f"[!] Groq generation failed, using form params only: {e}")

    return list(params)


def clear_cache():
    """Clear the parameter cache."""
    global PARAM_CACHE
    PARAM_CACHE = {}
