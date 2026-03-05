from flask import Flask, request, jsonify
from scanner import scan_url

app = Flask(__name__)

# Home route
@app.route("/")
def home():
    return jsonify({
        "message": "DSG Security Scanner API running",
        "endpoint": "/scan",
        "method": "POST"
    })


# Scan endpoint
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({
            "error": "Please provide a URL in JSON format"
        }), 400

    url = data["url"]

    result = scan_url(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)