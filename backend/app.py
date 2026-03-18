import sys
from flask import Flask, request, jsonify
from scanner import scan_url

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({"status": "DSG Scanner running"})


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "Provide URL"}), 400

    result = scan_url(data["url"])

    return jsonify(result)


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
        app.run(debug=True)