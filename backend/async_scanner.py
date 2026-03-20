import asyncio
import aiohttp
import random
from payload_tester import test_error_sql, test_xss, test_sql

USER_AGENTS = [
    "Mozilla/5.0",
    "Chrome/120.0",
    "Safari/537.36"
]

SEM = asyncio.Semaphore(10)


def get_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}


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


async def smart_delay():
    await asyncio.sleep(random.uniform(0.5, 1.5))


# -----------------------------
# Run blocking code safely
# -----------------------------
async def run_blocking(func, *args):
    return await asyncio.to_thread(func, *args)


# -----------------------------
# Async scan
# -----------------------------
async def scan_link(session, url, visited, tested):

    if url in visited:
        return {"xss": [], "sql": []}

    visited.add(url)

    params = extract_params(url)
    COMMON_PARAMS = ["id", "q", "search", "query", "url"]

    if not params:
        params = COMMON_PARAMS  # 👈 force testing even if no params

    key = url + str(params)
    if key in tested:
        return {"xss": [], "sql": []}

    tested.add(key)

    print("[*] Async scanning:", url)

    results = {"xss": [], "sql": []}

    try:
        async with SEM:
            await smart_delay()

            timeout = aiohttp.ClientTimeout(total=5)

            async with session.get(
                url,
                headers=get_headers(),
                timeout=timeout
            ) as r:
                # avoid codec errors on binary content (PDF, images, etc.)
                try:
                    await r.text()
                except UnicodeDecodeError:
                    await r.read()

        # -----------------------------
        # Run payload tests in threads
        # -----------------------------
        xss = await run_blocking(test_xss, url, params)
        sql = await run_blocking(test_sql, url, params)
        err_sql = await run_blocking(test_error_sql, url, params)

        results["xss"].extend(xss)
        results["sql"].extend(sql)
        results["sql"].extend(err_sql)

    except Exception as e:
        print("[!] Error:", url, str(e))

    return results


# -----------------------------
# Main async runner
# -----------------------------
async def run_async_scan(links):

    visited = set()
    tested = set()

    connector = aiohttp.TCPConnector(limit=20)

    async with aiohttp.ClientSession(connector=connector) as session:

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