import requests

def basic_scan(url):
    result = {}

    try:
        response = requests.get(url, timeout=5)
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["content_length"] = len(response.text)
        result["reachable"] = True
    except Exception as e:
        result["reachable"] = False
        result["error"] = str(e)

    return result