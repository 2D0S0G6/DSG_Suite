# 🧪 Quick Start Guide - Testing IDOR & Authorization

## Overview
This guide shows practical examples of how to use the upgraded scanner to find IDOR and authorization flaws.

---

## Example 1: Testing for IDOR (Student Portal)

### Scenario
A student system where each student can view their marks via an API endpoint:
```
GET /api/student/marks?roll=20230001
```

### How the Scanner Tests It

```python
# The scanner automatically discovers this endpoint through crawling
# Then runs IDOR detection:

Original Request:
  URL: /api/student/marks?roll=20230001
  Response: {"student": "John", "marks": 85}  # 345 bytes

The scanner mutates the ID:
  URL: /api/student/marks?roll=20230002
  Response: {"student": "Jane", "marks": 92}  # 356 bytes  ← DIFFERENT!

Finding Generated:
  Type: IDOR
  Severity: Critical
  Evidence: "Different student's data returned for modified ID"
  Explanation: "Parameter 'roll' is not properly validated..."
```

### Real Output in Report
```
🔓 IDOR (Insecure Direct Object Reference)

Parameter: roll
Severity: CRITICAL
Original Value: 20230001 → Mutated Value: 20230002
Mutation Type: increment
URL: /api/student/marks?roll=20230002
Evidence: Different user data returned for modified ID
```

---

## Example 2: Testing Authorization Flaws

### Scenario 1: Unauthenticated Admin Access

```python
# Scanner discovers admin endpoints during crawl:
/api/admin/users
/api/admin/settings
/api/teacher/marks

# Tests unauthenticated access to each:

Test: GET /api/admin/users  (no login)
Response: 200 OK + List of all users
→ Critical: Admin endpoint accessible without authentication!

Test: GET /api/teacher/marks?teacher_id=1  (as student, no auth)
Response: 200 OK + All teacher's grades
→ Critical: Teacher endpoint accessible without permission!
```

### Scenario 2: Cross-Role Access

```python
# If configured with test credentials:

Student tries: GET /api/admin/delete?user_id=5
Status: 200 → Deletion successful!
→ Critical: Student can delete users (Admin function!)

Student tries: GET /teacher/bulkgrades
Status: 200 → User's class grades loaded
→ High: Student accessing teacher-only features
```

---

## Example 3: Parameter Tampering

### Scenario
Grading system checks grades via parameters:

```python
Student A views their result:
  GET /result?student_id=123&exam_id=5
  Response: 80 marks

Scanner tests parameter mutation:
  GET /result?student_id=124&exam_id=5  (changed ID)
  Response: 95 marks, different student!
  
  GET /result?exam_id=5  (removed auth)
  Response: Still works, all grades shown!

Finding:
  Type: Parameter-based Authorization Bypass
  Evidence: Response size differs by 45 characters
  Risk: Possible data leakage or unauthorized access
```

---

## Example 4: Information Leakage Detection

### Scenario
Backend error in response reveals sensitive info:

```python
Student accesses: GET /api/result?id=abc (invalid input)

Response (before fixing):
HTTP/1.1 500 Internal Server Error
{
  "error": "Database connection failed",
  "details": "Could not connect to db_server.internal:5432",
  "stack_trace": "File /var/www/app/models.py line 156..."
}

Scanner detects:
  ✗ Stack trace information leaked
  ✗ File path disclosed (/var/www/app/...)
  ✗ Database credentials in response (??)
  ✗ Internal IP exposed

Report:
  Type: Information Leakage - Stack Trace
  Evidence: Stack trace visible in error response
```

---

## Running Your Own Test

### Step 1: Simple IDOR Test
```python
# In scanner.py, the IDOR test runs automatically on discovered endpoints

# To manually test a specific endpoint:
from idor_scanner import IDORScanner

idor = IDORScanner()

# Test a suspected IDOR endpoint
findings = idor.test_idor(
    url="http://target.edu/api/student/marks?roll=20230001",
    session_name=None,  # Unauthenticated test
    num_mutations=5
)

# findings = [{
#     "type": "IDOR",
#     "severity": "Critical",
#     "parameter": "roll",
#     "original_value": "20230001",
#     "mutated_value": "20230002",
#     "mutation_type": "increment",
#     "evidence": "Different user data returned..."
# }, ...]

for finding in findings:
    print(f"[!] {finding['severity']}: {finding['evidence']}")
```

### Step 2: Authorization Test
```python
from authorization_scanner import AuthorizationScanner

auth = AuthorizationScanner()

# Test specific endpoint for unauthenticated access
is_accessible, status, snippet = auth.test_unauthenticated_access(
    endpoint="http://target.edu/api/admin/users"
)

if is_accessible:
    print("[!] CRITICAL: Admin endpoint accessible without authentication!")
    print(f"    Status: {status}")
```

### Step 3: Parameter Mutation Test
```python
from api_parameter_mutator import APIParameterMutator
import requests

mutator = APIParameterMutator()

# Get base response
base_url = "http://target.edu/api/result?student_id=123&exam_id=5"
base_resp = requests.get(base_url, verify=False)

# Test mutations
findings = mutator.test_parameter_mutation(
    url=base_url,
    param_name="student_id",
    base_response=base_resp
)

for finding in findings:
    if finding["type"] == "Response Content Variation":
        print(f"[!] Different response for mutation: {finding['mutation']}")
        print(f"    Size diff: {finding['size_diff_percent']}%")
```

---

## Understanding Report Output

After running:
```bash
python app.py http://target.edu
```

Check `reports/report.html` for:

### 1. IDOR Section
```
🔓 IDOR (Insecure Direct Object Reference)

Parameter: roll
Severity: CRITICAL
Original Value: 20230001 → Mutated Value: 20230002
Mutation Type: increment
Evidence: Different user data returned for modified ID
```

### 2. Authorization Section
```
🚫 Authorization & Access Control Flaws

Type: Unauthenticated Access to Admin
Severity: CRITICAL
Endpoint: /api/admin/users
Status Code: 200
Evidence: Admin endpoint returned 200 without authentication
Remediation: Require authentication for all admin endpoints
```

### 3. Parameter Section
```
⚙️ API Parameter Exploitation

Type: Parameter-based Access Control Bypass
Parameter: student_id
Original Value: 123 → Test Value: 124
Evidence: Status code changed from 200 to 200 (but content different!)
Risk: Possible IDOR or authorization bypass
```

### 4. Leakage Section
```
📁 Information Leakage

Type: Information Leakage - Database Error
Evidence: Database error messages visible in response
Remediation: Catch database exceptions and return generic error messages
```

---

## Severity Levels Explained

| Severity | Meaning | Example |
|----------|---------|---------|
| **CRITICAL** | Immediate exploitation possible, major data breach | IDOR, Unauth Admin Access |
| **High** | Can be exploited to gain unauthorized access | Parameter Tampering, Teacher Access |
| **Medium** | Potential for abuse, information leakage | Stack Leaks, Config Exposure |
| **Low** | Informational, limited immediate impact | Missing Security Headers |

---

## Common False Positives & How to Verify

### False Positive: Status code same, but content identical
```python
# Scanner reports "different response" but contents are same
# Usually happens when:
- Same cached response
- Server ignores parameter changes
- Parameter doesn't affect output

# To verify: Check the actual response in report
# Look for Evidence field - if content is truly identical, skip this finding
```

### How to Verify IDOR is Real

1. **Check response content differs:** Manual inspection of response bodies
2. **Check for sensitive data:** Look for names, IDs, marks in different responses
3. **Check parameter is used:** Verify that changing the param actually changes output
4. **Check authorization:** Confirm the endpoint should require permission

---

## Next Steps

1. **Run scanner:** `python app.py http://target.edu`
2. **Review findings:** Open `reports/report.html`
3. **Verify IDOR:** Manually test marked endpoints
4. **Escalate critical:** Report IDOR/Auth bypasses immediately
5. **Test in staging:** Try exploits on staging before production

---

## Pro Tips

✅ **DO:**
- Test with valid IDs from real responses first
- Increment/decrement by 1 to find nearby users
- Check if roles matter (student vs teacher)
- Look for sequential patterns in IDs

❌ **DON'T:**
- Assume all sequential IDs are vulnerable (need authorization check too)
- Test on production without permission
- Ignore "boring" status 200 responses (they may leak data!)
- Forget that IDOR often happens on IDs only visible in authenticated sessions

---

## Example: Complete Testing Workflow

```bash
# 1. Run scanner
python3 app.py http://school-system.edu

# 2. Check report
# "🔓 IDOR Found: Parameter 'roll' vulnerable"
# "🚫 Authorization: /api/admin/users accessible without auth"

# 3. Verify manually
curl "http://school-system.edu/api/student?roll=20230002"  # Should work
curl "http://school-system.edu/api/admin/users"             # Should require auth

# 4. Document findings
# Roll: 20230001 → 20230002 = Different student (IDOR)
# /api/admin unprotected (Auth bypass)

# 5. Report to vendor with proof
# "Student A can view Student B's marks by changing roll parameter"
```

Ready to find real vulnerabilities! 🎯
