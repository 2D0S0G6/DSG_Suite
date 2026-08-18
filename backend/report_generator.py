import os
import json
import re
from datetime import datetime


def sanitize_filename(url):
    """Convert URL to safe filename"""
    # Remove protocol and www
    name = url.replace("https://", "").replace("http://", "").replace("www.", "")
    # Replace non-alphanumeric chars with underscore
    name = re.sub(r'[^a-zA-Z0-9]', '_', name)
    # Truncate if too long
    if len(name) > 50:
        name = name[:50]
    return name.rstrip('_')


def generate_html_report(data):

    os.makedirs("reports", exist_ok=True)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_url = data.get("url", "unknown")
    safe_name = sanitize_filename(target_url)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    html = f"""
    <html>
    <head>
    <title>DSG Security Report</title>
    <style>
    body {{font-family: Arial; background:#f5f5f5; margin: 20px;}}
    h1 {{color:#222}}
    h2 {{background:#333; color:white; padding:10px; margin-top:30px}}
    h3 {{color:#555; margin-top:20px}}
    .box {{background:white; padding:15px; margin:10px 0; border-radius:5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1)}}
    .vuln {{color:red; font-weight:bold}}
    .critical {{color:red; background:#ffe6e6; padding:3px 6px; border-radius:3px}}
    .high {{color:#d47c00; background:#fff4e6; padding:3px 6px; border-radius:3px}}
    .medium {{color:#ff9800; background:#fff9e6; padding:3px 6px; border-radius:3px}}
    .finding {{border-left:4px solid #d32f2f; padding:10px; margin:10px 0; background:#fafafa}}
    .finding-critical {{border-left-color:#d32f2f}}
    .finding-high {{border-left-color:#f57c00}}
    .finding-medium {{border-left-color:#fbc02d}}
    table {{width:100%; border-collapse:collapse}}
    th, td {{border:1px solid #ddd; padding:8px; text-align:left}}
    th {{background:#f5f5f5}}
    .summary {{background:#e3f2fd; padding:15px; border-radius:5px; margin:15px 0}}
    .summary-item {{display:inline-block; margin-right:30px}}
    .summary-count {{font-size:24px; font-weight:bold; color:#1976d2}}
    </style>
    </head>

    <body>

    <h1>🔒 DSG Security Scan Report - Advanced Authorization Testing</h1>

    <div class="box">
    <b>Target:</b> {data['url']}<br>
    <b>Date:</b> {now}<br>
    <b>Status Code:</b> {data['status_code']}
    </div>

    <!-- SUMMARY -->
    <div class="summary">
    <h2 style="margin:0; background:none; color:#333">📊 Vulnerability Summary</h2>
    <div class="summary-item">
        <div class="summary-count" style="color:red">{len(data.get('idor_vulnerabilities', []))}</div>
        <div>IDOR Findings</div>
    </div>
    <div class="summary-item">
        <div class="summary-count" style="color:#d47c00">{len(data.get('authorization_flaws', []))}</div>
        <div>Authorization Flaws</div>
    </div>
    <div class="summary-item">
        <div class="summary-count" style="color:#ff9800">{len(data.get('parameter_exploitation', []))}</div>
        <div>Parameter Issues</div>
    </div>
    <div class="summary-item">
        <div class="summary-count" style="color:#d32f2f">{len(data.get('xss_vulnerabilities', []))}</div>
        <div>XSS Vulnerabilities</div>
    </div>
    <div class="summary-item">
        <div class="summary-count" style="color:#d32f2f">{len(data.get('sql_vulnerabilities', []))}</div>
        <div>SQL Injection</div>
    </div>
    </div>

    <!-- 🔥 NEW FINDINGS: IDOR -->
    <h2 class="vuln">🔓 IDOR (Insecure Direct Object Reference)</h2>
    <div class="box">
    {f'<p style="color:green; font-weight:bold">✓ No IDOR vulnerabilities detected</p>' if not data.get('idor_vulnerabilities') else ''.join(f"""
    <div class="finding finding-{v.get('severity', 'unknown').lower()}">
    <b>Parameter:</b> {v.get('parameter', 'N/A')}<br>
    <b>Severity:</b> <span class="{v.get('severity', 'unknown').lower()}">{v.get('severity', 'Unknown')}</span><br>
    <b>Original Value:</b> {v.get('original_value', 'N/A')} → <b>Mutated Value:</b> {v.get('mutated_value', 'N/A')}<br>
    <b>Mutation Type:</b> {v.get('mutation_type', 'N/A')}<br>
    <b>URL:</b> <a href="{v.get('url', '#')}" target="_blank">{v.get('url', 'N/A')}</a><br>
    <b>Evidence:</b> {v.get('evidence', 'N/A')}<br>
    <b>Explanation:</b> {v.get('explanation', 'N/A')}<br>
    <b>Remediation:</b> {v.get('remediation', 'N/A')}
    </div>
    """ for v in data.get('idor_vulnerabilities', []))}
    </div>

    <!-- 🔥 NEW FINDINGS: AUTHORIZATION FLAWS -->
    <h2 class="vuln">🚫 Authorization & Access Control Flaws</h2>
    <div class="box">
    {f'<p style="color:green; font-weight:bold">✓ No authorization bypasses detected</p>' if not data.get('authorization_flaws') else ''.join(f"""
    <div class="finding finding-{v.get('severity', 'unknown').lower()}">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>Severity:</b> <span class="{v.get('severity', 'unknown').lower()}">{v.get('severity', 'Unknown')}</span><br>
    <b>Endpoint:</b> <a href="{v.get('endpoint', '#')}" target="_blank">{v.get('endpoint', 'N/A')}</a><br>
    <b>Status Code:</b> {v.get('status_code', 'N/A')}<br>
    <b>Evidence:</b> {v.get('evidence', 'N/A')}<br>
    <b>Explanation:</b> {v.get('explanation', 'N/A')}<br>
    <b>Remediation:</b> {v.get('remediation', 'N/A')}
    </div>
    """ for v in data.get('authorization_flaws', []))}
    </div>

    <!-- 🔥 NEW FINDINGS: PARAMETER EXPLOITATION -->
    <h2 class="vuln">⚙️ API Parameter Exploitation</h2>
    <div class="box">
    {f'<p style="color:green; font-weight:bold">✓ No parameter-based exploits found</p>' if not data.get('parameter_exploitation') else ''.join(f"""
    <div class="finding finding-{v.get('severity', 'medium').lower()}">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>Parameter:</b> {v.get('parameter', 'N/A')}<br>
    <b>Original Value:</b> {v.get('original_value', 'N/A')} → <b>Test Value:</b> {v.get('mutation', v.get('test_value', 'N/A'))}<br>
    <b>URL:</b> <a href="{v.get('url', '#')}" target="_blank">{v.get('url', 'N/A')}</a><br>
    <b>Evidence:</b> {v.get('evidence', 'N/A')}<br>
    <b>Risk:</b> {v.get('risk', 'Possible data leakage')}
    </div>
    """ for v in data.get('parameter_exploitation', []))}
    </div>

    <!-- INFORMATION LEAKAGE -->
    <h2 class="vuln">📁 Information Leakage</h2>
    <div class="box">
    {f'<p style="color:green; font-weight:bold">✓ No information leakage detected</p>' if not data.get('information_leakage') else ''.join(f"""
    <div class="finding finding-medium">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>Evidence:</b> {v.get('evidence', 'N/A')}<br>
    <b>Remediation:</b> {v.get('remediation', 'N/A')}
    </div>
    """ for v in data.get('information_leakage', []))}
    </div>

    <h2>🔗 Discovered Links</h2>
    <div class="box">
    <p>Total links discovered: <b>{len(data['links_found'])}</b></p>
    {''.join(f"<li><a href='{l}' target='_blank'>{l}</a></li>" for l in data['links_found'][:20])}
    {f"<li style='color:#999'><i>... and {len(data['links_found']) - 20} more links</i></li>" if len(data['links_found']) > 20 else ""}
    </div>

    <h2>📂 Discovered Directories</h2>
    <div class="box">
    {''.join(f"<li>{d}</li>" for d in data['directories'])}
    </div>

    <h2>🔌 JS Endpoints</h2>
    <div class="box">
    {''.join(f"<li>{e}</li>" for e in data['js_endpoints'][:20])}
    {f"<li style='color:#999'><i>... and {len(data['js_endpoints']) - 20} more endpoints</i></li>" if len(data['js_endpoints']) > 20 else ""}
    </div>

    <h2>🌐 Subdomains</h2>
    <div class="box">
    {''.join(f"<li>{s}</li>" for s in data['subdomains'])}
    </div>

    <h2 style="background:#ff6f00; color:white;">🔐 Security Header Issues</h2>
    <div class="box">
    {''.join(f"<li>{h}</li>" for h in data.get('security_header_issues', []))}
    </div>

    <h2 style="background:#ff6f00; color:white;">🍪 Cookie Security Issues</h2>
    <div class="box">
    {''.join(f"<li>{c}</li>" for c in data.get('cookie_issues', []))}
    </div>

    <h2 class="vuln">❌ XSS Vulnerabilities</h2>
    <div class="box">
    {''.join(f"""
    <div style="border:1px solid #ccc; padding:5px; margin:5px;">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>Parameter:</b> {v.get('parameter', 'N/A')}<br>
    <b>Payload:</b> {v.get('payload', 'N/A')}<br>
    <b>URL:</b> <a href="{v.get('url', '#')}" target="_blank">{v.get('url', 'N/A')}</a><br>
    <b>Severity:</b> <span style="color:{'red' if v.get('severity') == 'Critical' else 'orange' if v.get('severity') == 'High' else 'yellow'}">{v.get('severity', 'Unknown')}</span><br>
    <b>Explanation:</b> {v.get('explanation', 'No explanation available.')}<br>
    <b>Remediation:</b> {v.get('remediation', 'No remediation advice.')}
    </div>
    """ for v in data['xss_vulnerabilities'])}
    </div>

    <h2 class="vuln">🔓 SQL Injection</h2>
    <div class="box">
    {''.join(f"""
    <div style="border:1px solid #ccc; padding:5px; margin:5px;">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>Parameter:</b> {v.get('parameter', 'N/A')}<br>
    <b>Payload:</b> {v.get('payload', 'N/A')}<br>
    <b>URL:</b> <a href="{v.get('url', '#')}" target="_blank">{v.get('url', 'N/A')}</a><br>
    <b>Evidence:</b> {v.get('evidence', 'N/A')}<br>
    <b>Severity:</b> <span style="color:{'red' if v.get('severity') == 'Critical' else 'orange' if v.get('severity') == 'High' else 'yellow'}">{v.get('severity', 'Unknown')}</span><br>
    <b>Explanation:</b> {v.get('explanation', 'No explanation available.')}<br>
    <b>Remediation:</b> {v.get('remediation', 'No remediation advice.')}
    </div>
    """ for v in data['sql_vulnerabilities'])}
    </div>

    <h2 class="vuln">DOM XSS</h2>
    <div class="box">
    {''.join(f"""
    <div style="border:1px solid #ccc; padding:5px; margin:5px;">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>Sink:</b> {v.get('sink', 'N/A')}<br>
    <b>URL:</b> <a href="{v.get('url', '#')}" target="_blank">{v.get('url', 'N/A')}</a><br>
    <b>Line:</b> {v.get('line', 'N/A')}<br>
    <b>Severity:</b> <span style="color:{'red' if v.get('severity') == 'High' else 'orange' if v.get('severity') == 'Medium' else 'yellow'}">{v.get('severity', 'Unknown')}</span><br>
    <b>Explanation:</b> {v.get('explanation', 'No explanation available.')}
    </div>
    """ for v in data.get('dom_xss', []))}
    </div>

    <h2 class="vuln">CSRF Vulnerabilities</h2>
    <div class="box">
    {''.join(f"""
    <div style="border:1px solid #ccc; padding:5px; margin:5px;">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>URL:</b> <a href="{v.get('url', '#')}" target="_blank">{v.get('url', 'N/A')}</a><br>
    <b>Method:</b> {v.get('method', 'N/A')}<br>
    <b>Severity:</b> <span style="color:{'orange' if v.get('severity') == 'Medium' else 'yellow'}">{v.get('severity', 'Unknown')}</span><br>
    <b>Explanation:</b> {v.get('explanation', 'No explanation available.')}<br>
    <b>Remediation:</b> {v.get('remediation', 'No remediation advice.')}
    </div>
    """ for v in data.get('csrf', []))}
    </div>

    <h2 class="vuln">🔀 Open Redirects</h2>
    <div class="box">
    {''.join(f"<li>{r['url']} ({r['parameter']})</li>" for r in data.get('open_redirects', []))}
    </div>

    <h2 class="vuln">🚪 SSRF Findings</h2>
    <div class="box">
    {''.join(f"<li>{s['url']} ({s['parameter']})</li>" for s in data.get('ssrf', []))}
    </div>

    <!-- ⭐ GROQ AI FINDINGS -->
    <h2 style="background:#7c3aed; color:white;">⭐ Groq AI Analysis</h2>

    <h3>🧠 Groq Endpoint Analysis</h3>
    <div class="box">
    {f'<p style="color:green; font-weight:bold">✓ No AI endpoint vulnerabilities detected</p>' if not data.get('groq_endpoint_analysis') else ''.join(f"""
    <div class="finding finding-{v.get('severity', 'medium').lower()}">
    <b>Endpoint:</b> {v.get('endpoint', 'N/A')}<br>
    <b>Vulnerability Type:</b> {v.get('vulnerability_type', 'N/A')}<br>
    <b>Severity:</b> <span class="{v.get('severity', 'unknown').lower()}">{v.get('severity', 'Unknown')}</span><br>
    <b>Analysis:</b> {v.get('analysis', 'N/A')}<br>
    <b>Payload:</b> <code>{v.get('payload', 'N/A')}</code><br>
    <b>Expected Response:</b> {v.get('expected_response', 'N/A')}<br>
    <b>Remediation:</b> {v.get('remediation', 'N/A')}
    </div>
    """ for v in data.get('groq_endpoint_analysis', []))}
    </div>

    <h3>🔍 Groq Stored XSS Hotspots</h3>
    <div class="box">
    {f'<p style="color:green; font-weight:bold">✓ No stored XSS hotspots identified</p>' if not data.get('groq_stored_xss') else ''.join(f"""
    <div class="finding finding-high">
    <b>Form Field:</b> {v.get('form_field', 'N/A')}<br>
    <b>Display Location:</b> {v.get('display_location', 'N/A')}<br>
    <b>Risk Level:</b> {v.get('risk_level', 'High')}<br>
    <b>Description:</b> {v.get('description', 'N/A')}<br>
    <b>Test Payload:</b> <code>{v.get('test_payload', 'N/A')}</code><br>
    <b>Verification Steps:</b> {v.get('verification_steps', 'N/A')}
    </div>
    """ for v in data.get('groq_stored_xss', []))}
    </div>

    <h3>📤 Groq File Upload Analysis</h3>
    <div class="box">
    {f'<p style="color:green; font-weight:bold">✓ No upload vulnerabilities detected</p>' if not data.get('groq_file_uploads') else ''.join(f"""
    <div class="finding finding-{v.get('risk_level', 'medium').lower().replace('high', 'high').replace('critical', 'critical')}">
    <b>Upload Endpoint:</b> {v.get('endpoint', 'N/A')}<br>
    <b>Vulnerability Type:</b> {v.get('vulnerability_type', 'N/A')}<br>
    <b>Risk Level:</b> {v.get('risk_level', 'Medium')}<br>
    <b>Validation Issues:</b> {v.get('validation_issues', 'N/A')}<br>
    <b>Storage Path:</b> {v.get('storage_path', 'N/A')}<br>
    <b>Bypass Technique:</b> {v.get('bypass_technique', 'N/A')}<br>
    <b>Impact:</b> {v.get('impact', 'N/A')}
    </div>
    """ for v in data.get('groq_file_uploads', []))}
    </div>

    <h3>🔗 Groq Attack Chain Detection</h3>
    <div class="box">
    {f'<p style="color:green; font-weight:bold">✓ No multi-step attack chains detected</p>' if not data.get('groq_attack_chains') else ''.join(f"""
    <div class="finding finding-critical">
    <b>Chain Name:</b> {v.get('chain_name', 'N/A')}<br>
    <b>Severity:</b> <span class="critical">{v.get('severity', 'Critical')}</span><br>
    <b>Step 1:</b> {v.get('step_1', 'N/A')}<br>
    <b>Step 2:</b> {v.get('step_2', 'N/A')}<br>
    <b>Step 3:</b> {v.get('step_3', 'N/A')}<br>
    <b>Final Impact:</b> {v.get('impact', 'N/A')}<br>
    <b>Remediation:</b> {v.get('remediation', 'N/A')}
    </div>
    """ for v in data.get('groq_attack_chains', []))}
    </div>

    <h3>🕵️ Groq Hidden Endpoints Discovery</h3>
    <div class="box">
    {f'<p style="color:green; font-weight:bold">✓ No hidden endpoints detected</p>' if not data.get('groq_hidden_endpoints') else ''.join(f"""
    <div class="finding finding-high">
    <b>Endpoint:</b> {v.get('endpoint', 'N/A')}<br>
    <b>Type:</b> {v.get('type', 'N/A')}<br>
    <b>Risk:</b> {v.get('risk', 'High')}<br>
    <b>Description:</b> {v.get('description', 'N/A')}<br>
    <b>Detection Method:</b> {v.get('detection_method', 'N/A')}<br>
    <b>Testing Recommendation:</b> {v.get('testing_recommendation', 'N/A')}
    </div>
    """ for v in data.get('groq_hidden_endpoints', []))}
    </div>

    </body>
    </html>
    """

    # Save with unique filename: report_<sanitized_url>_<timestamp>.html
    unique_filename = f"report_{safe_name}_{timestamp}.html"
    with open(f"reports/{unique_filename}", "w") as f:
        f.write(html)
    
    # Also save as report.html for backward compatibility
    with open("reports/report.html", "w") as f:
        f.write(html)
    
    return unique_filename


def generate_json_report(data):
    """Generate a comprehensive JSON report with all findings"""
    
    os.makedirs("reports", exist_ok=True)
    
    target_url = data.get("url", "unknown")
    safe_name = sanitize_filename(target_url)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    report = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "target": data.get("url", "N/A"),
            "status_code": data.get("status_code", "N/A")
        },
        "summary": {
            "total_links": len(data.get("links_found", [])),
            "xss_vulnerabilities": len(data.get("xss_vulnerabilities", [])),
            "sql_vulnerabilities": len(data.get("sql_vulnerabilities", [])),
            "idor_vulnerabilities": len(data.get("idor_vulnerabilities", [])),
            "authorization_flaws": len(data.get("authorization_flaws", [])),
            "parameter_exploitation": len(data.get("parameter_exploitation", [])),
            "csrf_vulnerabilities": len(data.get("csrf", [])),
            "open_redirects": len(data.get("open_redirects", [])),
            "ssrf_findings": len(data.get("ssrf", [])),
            "dom_xss": len(data.get("dom_xss", [])),
            "information_leakage": len(data.get("information_leakage", [])),
            "groq_endpoint_analysis": len(data.get("groq_endpoint_analysis", [])),
            "groq_stored_xss": len(data.get("groq_stored_xss", [])),
            "groq_file_uploads": len(data.get("groq_file_uploads", [])),
            "groq_attack_chains": len(data.get("groq_attack_chains", [])),
            "groq_hidden_endpoints": len(data.get("groq_hidden_endpoints", []))
        },
        "findings": {
            "xss_vulnerabilities": data.get("xss_vulnerabilities", []),
            "sql_vulnerabilities": data.get("sql_vulnerabilities", []),
            "idor_vulnerabilities": data.get("idor_vulnerabilities", []),
            "authorization_flaws": data.get("authorization_flaws", []),
            "parameter_exploitation": data.get("parameter_exploitation", []),
            "csrf_vulnerabilities": data.get("csrf", []),
            "open_redirects": data.get("open_redirects", []),
            "ssrf_findings": data.get("ssrf", []),
            "dom_xss": data.get("dom_xss", []),
            "information_leakage": data.get("information_leakage", []),
            "security_header_issues": data.get("security_header_issues", []),
            "cookie_issues": data.get("cookie_issues", [])
        },
        "groq_ai_findings": {
            "endpoint_analysis": data.get("groq_endpoint_analysis", []),
            "stored_xss_hotspots": data.get("groq_stored_xss", []),
            "file_upload_analysis": data.get("groq_file_uploads", []),
            "attack_chains": data.get("groq_attack_chains", []),
            "hidden_endpoints": data.get("groq_hidden_endpoints", [])
        },
        "discovery": {
            "links_found": data.get("links_found", []),
            "directories": data.get("directories", []),
            "js_endpoints": data.get("js_endpoints", []),
            "subdomains": data.get("subdomains", [])
        }
    }
    
    # Save with unique filename
    unique_json = f"report_{safe_name}_{timestamp}.json"
    with open(f"reports/{unique_json}", "w") as f:
        json.dump(report, f, indent=2)
    
    # Also save as report.json for backward compatibility
    with open("reports/report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    return unique_json