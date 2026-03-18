import asyncio
import aiohttp
import random
from payload_tester import test_xss, test_sql

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


async def scan_link(session, url, visited, tested):

    if url in visited:
        return {"xss": [], "sql": []}

    visited.add(url)

    params = extract_params(url)
    if not params:
        return {"xss": [], "sql": []}

    key = url + str(params)
    if key in tested:
        return {"xss": [], "sql": []}

    tested.add(key)

    print("[*] Async scanning:", url)

    results = {"xss": [], "sql": []}

    try:
        async with SEM:
            await smart_delay()

            async with session.get(url, headers=get_headers(), timeout=5) as r:
                await r.text()

        results["xss"].extend(test_xss(url, params))
        results["sql"].extend(test_sql(url, params))

    except Exception as e:
        print("[!] Error:", url, str(e))

    return results


async def run_async_scan(links):

    visited = set()
    tested = set()

    async with aiohttp.ClientSession() as session:

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