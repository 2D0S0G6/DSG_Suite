import os
from datetime import datetime


def generate_html_report(data):

    os.makedirs("reports", exist_ok=True)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""
    <html>
    <head>
    <title>DSG Security Report</title>
    <style>
    body {{font-family: Arial; background:#f5f5f5;}}
    h1 {{color:#222}}
    h2 {{background:#333; color:white; padding:5px}}
    .box {{background:white; padding:10px; margin:10px; border-radius:5px}}
    .vuln {{color:red}}
    </style>
    </head>

    <body>

    <h1>DSG Security Scan Report</h1>

    <div class="box">
    <b>Target:</b> {data['url']}<br>
    <b>Date:</b> {now}<br>
    <b>Status Code:</b> {data['status_code']}
    </div>

    <h2>Links</h2>
    <div class="box">
    {''.join(f"<li>{l}</li>" for l in data['links_found'])}
    </div>

    <h2>Directories</h2>
    <div class="box">
    {''.join(f"<li>{d}</li>" for d in data['directories'])}
    </div>

    <h2>JS Endpoints</h2>
    <div class="box">
    {''.join(f"<li>{e}</li>" for e in data['js_endpoints'])}
    </div>

    <h2>Subdomains</h2>
    <div class="box">
    {''.join(f"<li>{s}</li>" for s in data['subdomains'])}
    </div>

    <h2 class="vuln">XSS Vulnerabilities</h2>
    <div class="box">
    {''.join(f"""
    <div style="border:1px solid #ccc; padding:5px; margin:5px;">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>Parameter:</b> {v.get('parameter', 'N/A')}<br>
    <b>Payload:</b> {v.get('payload', 'N/A')}<br>
    <b>URL:</b> <a href="{v.get('url', '#')}">{v.get('url', 'N/A')}</a><br>
    <b>Severity:</b> <span style="color:{'red' if v.get('severity') == 'Critical' else 'orange' if v.get('severity') == 'High' else 'yellow'}">{v.get('severity', 'Unknown')}</span><br>
    <b>Explanation:</b> {v.get('explanation', 'No explanation available.')}<br>
    <b>Remediation:</b> {v.get('remediation', 'No remediation advice.')}
    </div>
    """ for v in data['xss_vulnerabilities'])}
    </div>

    <h2 class="vuln">SQL Injection</h2>
    <div class="box">
    {''.join(f"""
    <div style="border:1px solid #ccc; padding:5px; margin:5px;">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>Parameter:</b> {v.get('parameter', 'N/A')}<br>
    <b>Payload:</b> {v.get('payload', 'N/A')}<br>
    <b>URL:</b> <a href="{v.get('url', '#')}">{v.get('url', 'N/A')}</a><br>
    <b>Evidence:</b> {v.get('evidence', 'N/A')}<br>
    <b>Severity:</b> <span style="color:{'red' if v.get('severity') == 'Critical' else 'orange' if v.get('severity') == 'High' else 'yellow'}">{v.get('severity', 'Unknown')}</span><br>
    <b>Explanation:</b> {v.get('explanation', 'No explanation available.')}<br>
    <b>Remediation:</b> {v.get('remediation', 'No remediation advice.')}
    </div>
    """ for v in data['sql_vulnerabilities'])}
    </div>

    <h2 class="vuln">DOM XSS</h2>
    <div class="box">
    {''.join(f"<li>{v}</li>" for v in data['dom_xss'])}
    </div>

    <h2 class="vuln">CSRF Vulnerabilities</h2>
    <div class="box">
    {''.join(f"""
    <div style="border:1px solid #ccc; padding:5px; margin:5px;">
    <b>Type:</b> {v.get('type', 'Unknown')}<br>
    <b>URL:</b> <a href="{v.get('url', '#')}">{v.get('url', 'N/A')}</a><br>
    <b>Method:</b> {v.get('method', 'N/A')}<br>
    <b>Severity:</b> <span style="color:{'orange' if v.get('severity') == 'Medium' else 'yellow'}">{v.get('severity', 'Unknown')}</span><br>
    <b>Explanation:</b> {v.get('explanation', 'No explanation available.')}<br>
    <b>Remediation:</b> {v.get('remediation', 'No remediation advice.')}
    </div>
    """ for v in data.get('csrf', []))}
    </div>

    </body>
    </html>
    """

    with open("reports/report.html", "w") as f:
        f.write(html)