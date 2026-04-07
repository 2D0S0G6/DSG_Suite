# 🤖 Gemini AI Integration Setup Guide

## Overview

Your DSG Scanner now includes **AI-powered vulnerability detection** using Google Gemini!

The Gemini integration adds:
- ✅ Smart payload generation based on endpoint context
- ✅ Intelligent IDOR detection with AI analysis
- ✅ Stored XSS hotspot identification
- ✅ File upload vulnerability analysis
- ✅ Multi-step attack chain detection
- ✅ Hidden/forgotten endpoint discovery
- ✅ Smart recommendations for all findings

---

## Setup (Quick Start)

### Step 1: Get Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com/app/apikeys)
2. Click **"Create API Key"**
3. Copy your API key

### Step 2: Set Environment Variable

```bash
# Linux/Mac
export GEMINI_API_KEY="your-api-key-here"

# Or add to .env file in backend/
echo "GEMINI_API_KEY=your-api-key-here" >> .env
```

### Step 3: Install Dependencies

```bash
pip install google-generativeai
```

### Step 4: Run Scanner

```bash
python app.py http://target.edu
```

That's it! Gemini analysis will run automatically.

---

## What Each Gemini Module Does

### 1. **Gemini Endpoint Analysis**
```
What: Analyzes API endpoints for vulnerabilities
How: Examines endpoint names, parameters, responses
Finds: IDOR, auth flaws, parameter manipulation
Example: "This endpoint looks like it handles student marks - likely IDOR risk"
```

### 2. **Gemini Stored XSS Detection**
```
What: Maps form inputs to where they display
How: Analyzes forms and pages for data flow
Finds: Where stored XSS might occur
Example: "Profile bio field likely appears on public profile page"
```

### 3. **Gemini File Upload Analysis**
```
What: Analyzes file upload endpoints
How: Identifies upload types, storage, access
Finds: Unrestricted uploads, path traversal, XXE
Example: "This endpoint stores files in /uploads/public"
```

### 4. **Gemini Attack Chain Detection**
```
What: Identifies multi-step attack chains
How: Analyzes application workflow
Finds: Form → Storage → Display → Exploitation paths
Example: "Submit form → Admin reviews → Stored XSS triggered"
```

### 5. **Gemini Hidden Endpoint Detection**
```
What: Finds forgotten/debug endpoints
How: Analyzes JavaScript for endpoints
Finds: Old APIs, debug routes, admin backdoors
Example: "/api/debug/users (debug endpoint - high risk)"
```

---

## Report Output

When you run the scanner with Gemini enabled, you'll see:

```
[+] Target: http://target.edu
[+] Crawling site...

[*] Running advanced authorization tests...
[*] Running Gemini AI analysis...
[*] Running Gemini endpoint analysis...
[*] Running Gemini stored XSS detection...
[*] Running Gemini file upload analysis...
[*] Running Gemini workflow chain detection...
[*] Running Gemini hidden endpoint detection...

[+] Gemini analysis complete
```

In `reports/report.html`, you'll see new sections:

```
🤖 Gemini AI Analysis Results
├── 🔓 Endpoint Analysis
├── 📋 Stored XSS Hotspots
├── 📁 File Upload Vulnerabilities
├── ⛓️ Attack Chains
└── 🕵️ Hidden Endpoints
```

---

## Configuration

### Option 1: Environment Variable (Recommended)

```bash
export GEMINI_API_KEY="sk-..."
python app.py http://target.edu
```

### Option 2: .env File

```bash
# Create backend/.env
GEMINI_API_KEY=sk-...

# Scanner automatically loads it
python app.py http://target.edu
```

### Option 3: Programmatic

```python
from scanner import scan_url

# Pass key directly
result = scan_url("http://target.edu", gemini_api_key="sk-...")
```

---

## How It Works (Under the Hood)

### Gemini Workflow

```
1. Scanner crawls site
   ↓
2. Identifies endpoints, forms, APIs
   ↓
3. For each endpoint:
   - Extract parameters
   - Get sample response
   - Send to Gemini
   ↓
4. Gemini analyzes:
   - What the endpoint does
   - Potential vulnerabilities
   - Attack vectors
   - Suggested tests
   ↓
5. Results added to report
```

### Smart Payload Generation

```
Traditional: Test ["<script>", "' OR 1=1--"]
Gemini: Analyzes endpoint context first

Example:
Endpoint: /api/student?roll=20230001
Gemini generates:
  - "20230002" (ID increment)
  - "20230000" (boundary)
  - "-1" (negative)
  - "admin" (type confusion)
  - "0" (special value)
```

---

## Examples

### Example 1: Finding IDOR with Gemini

```
Endpoint: /api/marks?student_id=123

Gemini Analysis:
{
  "endpoint_purpose": "Get student marks",
  "potential_vulnerabilities": ["IDOR", "Missing Authorization"],
  "suggested_tests": [
    "Change student_id to 124",
    "Remove student_id parameter",
    "Try negative student_id"
  ],
  "risk_level": "critical"
}
```

### Example 2: Finding Stored XSS Hotspot

```
Form: "Bio" field in /profile
Gemini identifies:
  - Field: bio
  - Storage: User profile table
  - Display: /user/{id}/profile page
  - Risk: High (admin can see all bios)
  
Attack Chain:
  1. User submits <img onerror=alert(1)> in bio
  2. Admin views user profiles
  3. XSS executes in admin browser
```

### Example 3: Finding File Upload Issue

```
Endpoint: /api/upload/

Gemini identifies:
  - Likely storage: /uploads/ directory
  - Public access: Yes (likely)
  - Bypass: Polyglot files, null bytes
  - Risk: Files executed as PHP
  
Exploit: Upload PHP file → Execute code
```

---

## Troubleshooting

### Issue: "GEMINI_API_KEY not set"

**Solution:**
```bash
export GEMINI_API_KEY="your-key-here"
# OR
echo "GEMINI_API_KEY=your-key-here" > backend/.env
```

### Issue: "Gemini not available"

**Check:**
1. API key is correct
2. Dependencies installed: `pip install google-generativeai`
3. Network connectivity
4. API quota not exceeded

### Issue: Slow scanning with Gemini

**Normal:** Gemini adds 2-3 minutes per scan (API calls)

**Speed up:**
- Only analyze first 10 endpoints (default)
- Skip Gemini for small targets
- Increase timeout if needed

### Issue: API Rate Limit

**Happens if:** Testing multiple targets quickly

**Solution:** Wait a few minutes between scans, or

```python
# Disable Gemini for this scan
result = scan_url(url, skip_gemini=True)
```

---

## Cost

Google Gemini API has:
- **Free tier:** 60 requests/minute
- **Pricing:** Check [Google AI Pricing](https://ai.google.dev/pricing)

**Typical usage:**
- Small site (10 endpoints): ~10 API calls, ~1 minute
- Medium site (30 endpoints): ~25 API calls, ~2-3 minutes
- Large site (100+ endpoints): Limited to first 15 for cost

---

## Best Practices

✅ **DO:**
- Enable Gemini for professional assessments
- Use for complex applications (education systems)
- Let Gemini suggest tests then manually verify
- Review all findings from Gemini

❌ **DON'T:**
- Rely ONLY on Gemini (always verify)
- Share API key in reports
- Enable Gemini for casual browsing scans
- Assume Gemini findings are 100% accurate

---

## Integration with Scanner Modules

Gemini works alongside your existing modules:

```
Scanner
├── Manual Testing
│   ├── XSS/SQLi (async_scanner)
│   ├── Forms (form_scanner)
│   └── CSRF (csrf_scanner)
├── Logic-Based Testing
│   ├── IDOR (idor_scanner)
│   ├── Authorization (authorization_scanner)
│   ├── Parameters (api_parameter_mutator)
│   └── Response Analysis (response_analyzer)
└── 🤖 AI-Assisted Testing (gemini_analyzer)
    ├── Smart endpoint analysis
    ├── Workflow detection
    ├── File upload analysis
    ├── Stored XSS mapping
    └── Hidden endpoint finding
```

---

## Sample Output

```json
{
  "gemini_endpoint_analysis": [
    {
      "type": "Gemini AI: Insecure Direct Object Reference",
      "endpoint": "/api/student/marks?roll=20230001",
      "ai_analysis": "Get student marks - High IDOR risk",
      "suggested_tests": [
        "Increment roll number",
        "Try negative roll number",
        "Remove roll parameter"
      ],
      "risk_level": "critical"
    }
  ],
  "gemini_stored_xss": [
    {
      "type": "Potential Stored XSS Hotspot",
      "form_field": "profile_bio",
      "likely_reflection": "/user/profile page",
      "attack_chain": "Admin views user profile and bio XSS triggers",
      "risk_level": "high"
    }
  ],
  "gemini_hidden_endpoints": [
    {
      "type": "Hidden/Debug Endpoint - debug",
      "endpoint": "/api/debug/users",
      "purpose": "Debug endpoint for dumping all users",
      "auth_required": "none",
      "exposure_risk": "high"
    }
  ]
}
```

---

## Next Steps

1. **Setup API Key**
   ```bash
   export GEMINI_API_KEY="your-key"
   ```

2. **Test Scanner**
   ```bash
   python app.py http://test-target.edu
   ```

3. **Review Report**
   - Open `reports/report.html`
   - Check Gemini sections
   - Verify findings manually

4. **Use Findings**
   - Prioritize Gemini's suggested tests
   - Test high-risk endpoints first
   - Document all verified vulnerabilities

---

**Your scanner is now AI-powered!** 🚀
