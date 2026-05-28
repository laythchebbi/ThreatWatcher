#!/usr/bin/env python3
"""Dark-web crawler.

Reads enabled sources from the `darkweb_sources` MongoDB collection, fetches
each `.onion` URL via the local Tor SOCKS5 proxy, parses the page body, and
upserts results into `darkweb_pages`. Designed to be run on a schedule (cron
on Linux, Task Scheduler on Windows) — not from inside the Node process.

Env:
    MONGODB_URI   Required. Same connection string used by the backend.
    TOR_PROXY     SOCKS5 proxy (default: socks5h://127.0.0.1:9050).
                  Tor itself runs as a system service, not managed here.
    KEYWORDS      Comma-separated keywords to flag in page bodies (optional).
"""
from __future__ import annotations

import hashlib
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Iterable

import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient, UpdateOne

LOG = logging.getLogger("darkweb_crawl")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")

MONGO_URI = os.environ.get("MONGODB_URI")
TOR_PROXY = os.environ.get("TOR_PROXY", "socks5h://127.0.0.1:9050")
KEYWORDS = [k.strip().lower() for k in os.environ.get("KEYWORDS", "").split(",") if k.strip()]

if not MONGO_URI:
    LOG.error("MONGODB_URI not set")
    sys.exit(1)


def fetch(url: str, timeout: int = 30) -> str | None:
    proxies = {"http": TOR_PROXY, "https": TOR_PROXY}
    try:
        res = requests.get(url, proxies=proxies, timeout=timeout, headers={"User-Agent": "ThreatWatcher/0.1"})
        if res.status_code != 200:
            LOG.warning("non-200: %s %s", res.status_code, url)
            return None
        return res.text
    except requests.RequestException as exc:
        LOG.warning("fetch failed: %s -> %s", url, exc)
        return None


def parse_page(url: str, html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.string if soup.title and soup.title.string else "").strip()[:500]
    body = soup.get_text(" ", strip=True)
    body_hash = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()
    matched = [k for k in KEYWORDS if k in body.lower()]
    return {
        "pageUrl": url,
        "title": title,
        "body": body[:50_000],
        "bodyHash": body_hash,
        "keywords": matched,
        "crawledAt": datetime.now(timezone.utc),
    }


def crawl(sources: Iterable[dict]) -> list[UpdateOne]:
    ops: list[UpdateOne] = []
    for src in sources:
        url = src.get("url")
        if not url:
            continue
        html = fetch(url)
        if html is None:
            continue
        page = parse_page(url, html)
        page["sourceUrl"] = url
        ops.append(
            UpdateOne(
                {"sourceUrl": url, "pageUrl": url},
                {"$set": page},
                upsert=True,
            )
        )
    return ops


def main() -> int:
    client = MongoClient(MONGO_URI)
    db_name = MongoClient(MONGO_URI).get_default_database().name
    db = client[db_name] if db_name else client.get_database()
    sources = list(db.darkweb_sources.find({"enabled": True}))
    LOG.info("crawling %d sources", len(sources))
    ops = crawl(sources)
    if not ops:
        LOG.info("no pages to upsert")
        return 0
    result = db.darkweb_pages.bulk_write(ops, ordered=False)
    LOG.info("upserted: %d, modified: %d", result.upserted_count, result.modified_count)

    now = datetime.now(timezone.utc)
    db.darkweb_sources.update_many(
        {"_id": {"$in": [s["_id"] for s in sources]}},
        {"$set": {"lastCrawledAt": now, "lastStatus": "ok"}},
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
