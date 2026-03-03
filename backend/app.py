from flask import Flask, request, jsonify
from scanner import basic_scan

app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = basic_scan(url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)