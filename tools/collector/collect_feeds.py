#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collecte flux RSS/Atom + sitemaps pour l'arsenal 2025-2026.

Sorties :
  data/feeds.jsonl         — une ligne par entrée de flux (source, title, url, published, summary)
  data/sitemap_urls.jsonl  — URLs de sitemaps filtrées (source, url, lastmod)

Usage : .venv/bin/python collect_feeds.py
"""
import json
import os
import re
import time
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import feedparser
import requests
from bs4 import BeautifulSoup

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
FEEDS_PATH = os.path.join(DATA, "feeds.jsonl")
SITEMAPS_PATH = os.path.join(DATA, "sitemap_urls.jsonl")

CUTOFF = "2025-01-01"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.8"}

SEEN = set()


def emit(out, row):
    """Écrit une ligne en évitant les doublons (url + titre)."""
    key = (row.get("url"), row.get("title"))
    if not key[0] or key in SEEN:
        return 0
    SEEN.add(key)
    out.write(json.dumps(row, ensure_ascii=False) + "\n")
    return 1

# Flux directs (testés OK)
FEEDS = [
    ("critical-thinking", "https://feeds.cohostpodcasting.com/y3zHW5ae"),
    ("infosecwriteups", "https://infosecwriteups.com/feed"),
    ("intigriti", "https://www.intigriti.com/blog/feed"),
    ("reddit-bugbounty", "https://www.reddit.com/r/bugbounty/.rss"),
    ("reddit-netsec", "https://www.reddit.com/r/netsec/.rss"),
]

# Flux à essayer (on garde le premier qui répond)
FEED_CANDIDATES = [
    ("doyensec", ["https://blog.doyensec.com/feed.xml",
                  "https://blog.doyensec.com/atom.xml",
                  "https://blog.doyensec.com/rss.xml"]),
    ("trailofbits", ["https://blog.trailofbits.com/feed/"]),
    ("nccgroup", ["https://research.nccgroup.com/feed/"]),
    ("includesecurity", ["https://blog.includesecurity.com/feed.xml"]),
    ("sonarsource", ["https://www.sonarsource.com/blog/rss.xml",
                     "https://www.sonarsource.com/rss/blog.xml"]),
    ("projectdiscovery", ["https://projectdiscovery.io/blog/rss.xml",
                          "https://projectdiscovery.io/rss.xml"]),
    ("portswigger", ["https://portswigger.net/research/rss"]),
]

# Flux WordPress paginés : ?paged=N jusqu'à dépasser CUTOFF
WP_PAGED = [
    ("detectify", "https://blog.detectify.com/feed/", 5),
]

# Sitemaps : (source, url, prédicat sur l'URL)
SITEMAPS = [
    ("logicalbreach-academy", "https://academy.logicalbreach.com/sitemap.xml",
     lambda u: "/writeups/" in u),
    ("yeswehack", "https://www.yeswehack.com/server-sitemap.xml",
     lambda u: "/news/" in u and "/fr/" not in u),
]


def get(url, timeout=25):
    r = requests.get(url, headers=HEADERS, timeout=timeout)
    r.raise_for_status()
    return r


def clean_html(html, limit=900):
    if not html:
        return ""
    txt = BeautifulSoup(html, "lxml").get_text(" ", strip=True)
    txt = re.sub(r"\s+", " ", txt)
    return txt[:limit]


def entry_date(e):
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        t = e.get(key)
        if t:
            return time.strftime("%Y-%m-%d", t)
    return None


def harvest_feed(source, url, out, min_date=CUTOFF):
    try:
        raw = get(url).content
    except Exception as ex:
        print(f"[!] {source}: échec {url} ({ex})", flush=True)
        return 0
    fp = feedparser.parse(raw)
    n = 0
    for e in fp.entries:
        d = entry_date(e)
        if min_date and d and d < min_date:
            continue
        row = {
            "source": source,
            "title": (e.get("title") or "").strip(),
            "url": e.get("link"),
            "published": d,
            "summary": clean_html(e.get("summary") or e.get("description") or ""),
        }
        n += emit(out, row)
    print(f"[ok] {source}: {n} entrées ({url})", flush=True)
    return n


def try_candidates():
    kept = []
    for source, urls in FEED_CANDIDATES:
        for u in urls:
            try:
                raw = get(u, timeout=20).content
                fp = feedparser.parse(raw)
                if fp.entries:
                    kept.append((source, u))
                    print(f"[ok] candidat {source} -> {u} ({len(fp.entries)} entrées)", flush=True)
                    break
            except Exception:
                continue
        else:
            print(f"[!] {source}: aucun flux ne répond", flush=True)
    return kept


def harvest_wp_paged(source, base, max_pages, out, min_date=CUTOFF):
    total = 0
    for p in range(1, max_pages + 1):
        url = base if p == 1 else f"{base}?paged={p}"
        try:
            raw = get(url).content
        except Exception as ex:
            print(f"[!] {source} p{p}: {ex}", flush=True)
            break
        fp = feedparser.parse(raw)
        if not fp.entries:
            break
        dates = []
        new_here = 0
        for e in fp.entries:
            d = entry_date(e)
            if d:
                dates.append(d)
            if min_date and d and d < min_date:
                continue
            new_here += emit(out, {
                "source": source,
                "title": (e.get("title") or "").strip(),
                "url": e.get("link"),
                "published": d,
                "summary": clean_html(e.get("summary") or ""),
            })
        total += new_here
        print(f"[ok] {source} p{p}: {len(fp.entries)} entrées, {new_here} nouvelles "
              f"(min {min(dates or ['?'])})", flush=True)
        if p > 1 and new_here == 0:
            print(f"[i] {source}: plus de nouveauté — arrêt du paging.", flush=True)
            break
        if dates and min(dates) < min_date:
            break
        time.sleep(0.8)
    return total


def harvest_sitemap(source, url, pred, out):
    try:
        r = get(url)
        root = ET.fromstring(r.content)
    except Exception as ex:
        print(f"[!] sitemap {source}: {ex}", flush=True)
        return 0
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    n = 0
    for url_el in root.findall(".//sm:url", ns):
        loc = url_el.findtext("sm:loc", default="", namespaces=ns).strip()
        lastmod = url_el.findtext("sm:lastmod", default="", namespaces=ns).strip()
        if loc and pred(loc):
            out.write(json.dumps({"source": source, "url": loc,
                                  "lastmod": lastmod or None}, ensure_ascii=False) + "\n")
            n += 1
    print(f"[ok] sitemap {source}: {n} URLs pertinentes", flush=True)
    return n


def main():
    os.makedirs(DATA, exist_ok=True)
    total = 0
    with open(FEEDS_PATH, "w", encoding="utf-8") as out:
        for source, url in FEEDS:
            total += harvest_feed(source, url, out)
        for source, url in try_candidates():
            total += harvest_feed(source, url, out)
        for source, base, cap in WP_PAGED:
            total += harvest_wp_paged(source, base, cap, out)
    print(f"[i] feeds.jsonl : {total} entrées au total", flush=True)

    n_sm = 0
    with open(SITEMAPS_PATH, "w", encoding="utf-8") as out:
        for source, url, pred in SITEMAPS:
            n_sm += harvest_sitemap(source, url, pred, out)
    print(f"[i] sitemap_urls.jsonl : {n_sm} URLs au total", flush=True)


if __name__ == "__main__":
    main()
