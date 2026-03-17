import asyncio
import aiohttp
from payload_tester import test_xss, test_sql

HEADERS = {
    "User-Agent": "DSG-Async-Scanner"
}

# Limit concurrency (VERY IMPORTANT)
SEM = asyncio.Semaphore(10)


# --------------------------------
# Extract parameters
# --------------------------------
def extract_params(url):

    if "?" not in url:
        return []

    params = []

    query = url.split("?", 1)[1]

    for p in query.split("&"):

        key = p.split("=")[0]

        if key not in params:
            params.append(key)

    return params


# --------------------------------
# Async scan single link
# --------------------------------
async def scan_link(session, url, visited, tested):

    # Skip duplicates
    if url in visited:
        return {"xss": [], "sql": []}

    visited.add(url)

    params = extract_params(url)

    # Skip URLs without parameters (BIG speed boost)
    if not params:
        return {"xss": [], "sql": []}

    # Prevent duplicate payload testing
    key = url + str(params)

    if key in tested:
        return {"xss": [], "sql": []}

    tested.add(key)

    print("[*] Async scanning:", url)

    results = {"xss": [], "sql": []}

    try:
        async with SEM:

            timeout = aiohttp.ClientTimeout(total=5)

            async with session.get(url, timeout=timeout) as r:
                await r.text()  # ensure request completes

        # Run payload tests AFTER request (non-blocking part)
        results["xss"].extend(test_xss(url, params))
        results["sql"].extend(test_sql(url, params))

    except Exception as e:
        print("[!] Error:", url, str(e))

    return results


# --------------------------------
# Run async scan
# --------------------------------
async def run_async_scan(links):

    visited = set()
    tested = set()

    connector = aiohttp.TCPConnector(limit=20)

    async with aiohttp.ClientSession(
        headers=HEADERS,
        connector=connector
    ) as session:

        tasks = [
            scan_link(session, link, visited, tested)
            for link in links
        ]

        results = await asyncio.gather(*tasks)

    all_xss = []
    all_sql = []

    for r in results:
        all_xss.extend(r["xss"])
        all_sql.extend(r["sql"])

    return all_xss, all_sql