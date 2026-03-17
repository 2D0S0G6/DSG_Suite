import sys
from unittest import result
from flask import Flask, request, jsonify
from scanner import scan_url

app = Flask(__name__)


# -----------------------------
# Home route
# -----------------------------
@app.route("/")
def home():

    return jsonify({
        "name": "DSG Security Scanner",
        "status": "running",
        "scan_endpoint": "/scan",
        "method": "POST",
        "example_request": {
            "url": "http://example.com"
        }
    })


# -----------------------------
# Scan endpoint (API)
# -----------------------------
@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({
            "error": "Provide URL in JSON",
            "example": {
                "url": "http://demo.testfire.net"
            }
        }), 400

    url = data["url"]

    try:

        result = scan_url(url)

        return jsonify({
            "status": "completed",
            "target": url,
            "result": result
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# -----------------------------
# CLI Scanner
# -----------------------------
def run_cli():

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("python app.py http://target.com\n")
        sys.exit()

    target = sys.argv[1]

    print("\n===============================")
    print(" DSG SECURITY SCANNER (CLI)")
    print("===============================\n")

    print("[+] Target:", target)

    result = scan_url(target)

    print("\n====== SCAN SUMMARY ======")

    print(f"[+] Links: {len(result.get('links_found', []))}")
    print(f"[+] XSS: {len(result.get('xss_vulnerabilities', []))}")
    print(f"[+] SQLi: {len(result.get('sql_vulnerabilities', []))}")
    print(f"[+] DOM XSS: {len(result.get('dom_xss', []))}")
    print(f"[+] Directories: {len(result.get('directories', []))}")
    print(f"[+] JS Endpoints: {len(result.get('js_endpoints', []))}")
    print(f"[+] Subdomains: {len(result.get('subdomains', []))}")

    print("\n[+] Report: reports/report.html\n")


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":

    # CLI mode
    if len(sys.argv) > 1:

        run_cli()

    # API mode
    else:

        print("\n[+] DSG Scanner API started")
        print("[+] POST scans to: http://127.0.0.1:5000/scan\n")

        app.run(
            host="0.0.0.0",
            port=5000,
            debug=True
        )