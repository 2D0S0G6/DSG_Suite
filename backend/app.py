import sys
import os
import json
from flask import Flask, request, jsonify, send_from_directory
from scanner import scan_url, scan_url_pipeline

app = Flask(__name__)

# Ensure reports directory exists
os.makedirs("reports", exist_ok=True)


@app.route("/")
def home():
    return jsonify({"status": "DSG_Suite running", "version": "2.0"})


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "Provide URL"}), 400

    target = data["url"]
    
    # Run the scan
    result = scan_url(target)

    # Extract vulnerabilities for API response
    vulnerabilities = []
    
    # XSS
    for v in result.get("xss_vulnerabilities", []):
        vulnerabilities.append({
            "type": "XSS",
            "severity": "high",
            "url": v.get("url", target),
            "param": v.get("parameter"),
            "description": v.get("payload", "XSS vulnerability detected")
        })
    
    # SQL Injection
    for v in result.get("sql_vulnerabilities", []):
        vulnerabilities.append({
            "type": "SQL Injection",
            "severity": "critical",
            "url": v.get("url", target),
            "param": v.get("parameter"),
            "description": v.get("payload", "SQL injection detected")
        })
    
    # IDOR
    for v in result.get("idor_vulnerabilities", []):
        vulnerabilities.append({
            "type": "IDOR",
            "severity": "high",
            "url": v.get("endpoint", target),
            "description": v.get("description", "Insecure Direct Object Reference")
        })
    
    # Authorization
    for v in result.get("authorization_flaws", []):
        vulnerabilities.append({
            "type": "Authorization Flaw",
            "severity": "critical",
            "url": v.get("endpoint", target),
            "description": v.get("evidence", "Authorization bypass detected")
        })
    
    # CSRF
    for v in result.get("csrf", []):
        vulnerabilities.append({
            "type": "CSRF",
            "severity": "medium",
            "url": v.get("url", target),
            "description": v.get("explanation", "CSRF protection missing")
        })
    
    # DOM XSS
    for v in result.get("dom_xss", []):
        vulnerabilities.append({
            "type": "DOM XSS",
            "severity": "high",
            "url": v.get("url", target),
            "description": v.get("explanation", "DOM-based XSS")
        })
    
    # Open Redirects
    for v in result.get("open_redirects", []):
        vulnerabilities.append({
            "type": "Open Redirect",
            "severity": "medium",
            "url": v.get("url", target),
            "param": v.get("parameter"),
            "description": "Open redirect vulnerability"
        })
    
    # SSRF
    for v in result.get("ssrf", []):
        vulnerabilities.append({
            "type": "SSRF",
            "severity": "critical",
            "url": v.get("url", target),
            "param": v.get("parameter"),
            "description": "Server-Side Request Forgery"
        })
    
    # Add summary to result
    result["vulnerabilities"] = vulnerabilities
    result["summary"] = {
        "total": len(vulnerabilities),
        "critical": len([v for v in vulnerabilities if v["severity"] == "critical"]),
        "high": len([v for v in vulnerabilities if v["severity"] == "high"]),
        "medium": len([v for v in vulnerabilities if v["severity"] == "medium"]),
        "low": len([v for v in vulnerabilities if v["severity"] == "low"])
    }
    result["reportPath"] = "reports/report.html"

    return jsonify(result)


@app.route("/scan/pipeline", methods=["POST"])
def scan_pipeline():
    """Run the staged analysis pipeline and return its normalised report."""
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Provide URL"}), 400

    result = scan_url_pipeline(data["url"])
    return jsonify(result)


@app.route("/reports/<path:filename>")
def serve_report(filename):
    return send_from_directory("reports", filename)


@app.route("/history", methods=["GET"])
def history():
    """Get scan history from reports folder"""
    history = []
    report_dir = "reports"
    
    if os.path.exists(report_dir):
        for f in os.listdir(report_dir):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(report_dir, f), "r") as fp:
                        data = json.load(fp)
                        history.append({
                            "url": data.get("url"),
                            "timestamp": data.get("timestamp"),
                            "vulnerabilities": data.get("summary", {}).get("total", 0)
                        })
                except:
                    pass
    
    return jsonify(history)


def run_cli():

    if len(sys.argv) < 2:
        print("Usage: python app.py http://target.com")
        return

    target = sys.argv[1]

    print("\n[+] Target:", target)

    result = scan_url(target)

    print("\n====== SUMMARY ======")
    print("[+] Links:", len(result["links_found"]))
    print("[+] XSS:", len(result["xss_vulnerabilities"]))
    print("[+] SQLi:", len(result["sql_vulnerabilities"]))
    print("[+] Directories:", len(result["directories"]))
    print("[+] JS Endpoints:", len(result["js_endpoints"]))
    print("[+] DOM XSS:", len(result["dom_xss"]))

    print("\n[+] Report: reports/report.html\n")


if __name__ == "__main__":

    if len(sys.argv) > 1:
        run_cli()
    else:
        app.run(debug=True, port=5000)