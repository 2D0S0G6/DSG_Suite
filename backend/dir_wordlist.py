from datetime import datetime

def generate_report(results):

    html = f"""
    <html>
    <head>
    <title>DSG Scanner Report</title>
    </head>

    <body>

    <h1>DSG Vulnerability Report</h1>

    <p>Target: {results["url"]}</p>
    <p>Generated: {datetime.now()}</p>

    <h2>XSS Vulnerabilities</h2>
    <pre>{results["xss_vulnerabilities"]}</pre>

    <h2>SQL Injection</h2>
    <pre>{results["sql_vulnerabilities"]}</pre>

    <h2>Missing Security Headers</h2>
    <pre>{results["missing_security_headers"]}</pre>

    </body>
    </html>
    """

    with open("reports/report.html","w") as f:
        f.write(html)