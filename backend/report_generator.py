import os


def generate_html_report(data):

    os.makedirs("reports", exist_ok=True)

    html = f"""
    <html>
    <head>
    <title>DSG Scanner Report</title>
    <style>
    body {{font-family: Arial}}
    h1 {{color:#333}}
    .vuln {{color:red}}
    </style>
    </head>

    <body>

    <h1>DSG Security Scan Report</h1>

    <h2>Target</h2>
    {data['url']}

    <h2>Discovered Links</h2>
    {''.join(f"<li>{l}</li>" for l in data['links_found'])}

    <h2>Directories</h2>
    {''.join(f"<li>{d}</li>" for d in data['directories'])}

    <h2>JS Endpoints</h2>
    {''.join(f"<li>{e}</li>" for e in data['js_endpoints'])}

    <h2 class='vuln'>XSS</h2>
    {''.join(f"<li>{v}</li>" for v in data['xss_vulnerabilities'])}

    <h2 class='vuln'>SQL Injection</h2>
    {''.join(f"<li>{v}</li>" for v in data['sql_vulnerabilities'])}

    </body>
    </html>
    """

    with open("reports/report.html", "w") as f:
        f.write(html)