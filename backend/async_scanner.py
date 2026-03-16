import asyncio
import aiohttp
from payload_tester import test_xss, test_sql

HEADERS = {
    "User-Agent": "DSG-Async-Scanner"
}

visited = set()


async def scan_link(session, url):

    if url in visited:
        return {"xss": [], "sql": []}

    visited.add(url)

    print("[*] Async scanning:", url)

    results = {"xss": [], "sql": []}

    try:

        async with session.get(url, timeout=5) as r:

            text = await r.text()

            if "?" in url:

                params = []

                q = url.split("?")[1]

                for p in q.split("&"):
                    params.append(p.split("=")[0])

                results["xss"].extend(test_xss(url, params))
                results["sql"].extend(test_sql(url, params))

    except:
        pass

    return results


async def run_async_scan(links):

    async with aiohttp.ClientSession(headers=HEADERS) as session:

        tasks = []

        for link in links:
            tasks.append(scan_link(session, link))

        results = await asyncio.gather(*tasks)

        xss = []
        sql = []

        for r in results:

            xss.extend(r["xss"])
            sql.extend(r["sql"])

        return xss, sql