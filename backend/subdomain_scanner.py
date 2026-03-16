import requests

COMMON_SUBDOMAINS = [
    "api",
    "dev",
    "admin",
    "test",
    "staging",
    "beta",
    "portal"
]


def discover_subdomains(domain):

    found = []

    for sub in COMMON_SUBDOMAINS:

        url = f"http://{sub}.{domain}"

        try:

            r = requests.get(url, timeout=3)

            if r.status_code < 400:

                print("[+] Subdomain found:", url)

                found.append(url)

        except:
            pass

    return found