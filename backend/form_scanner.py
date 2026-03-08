import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from payload_tester import test_xss, test_sql


def get_forms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except:
        return []


def form_details(form):
    details = {}

    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()

    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        name = input_tag.attrs.get("name")

        inputs.append({
            "type": input_type,
            "name": name
        })

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details


def scan_forms(url):

    results = []

    forms = get_forms(url)

    for form in forms:

        details = form_details(form)

        target_url = urljoin(url, details["action"])

        parameters = []

        for input_field in details["inputs"]:
            if input_field["name"]:
                parameters.append(input_field["name"])

        if parameters:

            xss = test_xss(target_url, parameters)
            sql = test_sql(target_url, parameters)

            results.append({
                "form_action": target_url,
                "method": details["method"],
                "parameters": parameters,
                "xss": xss,
                "sql": sql
            })

    return results