#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enrichit les pages rendues (render_pages.py) : titre réel, date, résumé.

Lecture  : data/raw/pages/<source>/<slug>.txt|.html + data/sitemap_urls.jsonl
Écriture  : data/page_meta.jsonl  {source, url, title, date, summary}

Usage : .venv/bin/python enrich_pages.py
"""
import glob
import html as htmllib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
PAGES = os.path.join(DATA, "raw", "pages")
OUT = os.path.join(DATA, "page_meta.jsonl")

DATE_PATTERNS = [
    r"(?:published|posted|updated|date)\D{0,20}(\d{4}-\d{2}-\d{2})",
    r"(?:published|posted|updated|date)\D{0,20}(\d{1,2}[/.](?:\d{1,2}|[A-Za-z]{3,9})[/.]\d{4})",
    r"\b((?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* \d{1,2},? \d{4})\b",
    r"\b(\d{1,2} (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* \d{4})\b",
]
MONTHS = {m: i + 1 for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}

JUNK_LINE = re.compile(
    r"^(Aa|Normal|Translate with Noc|Save|PRO|Back|min|Share|Menu|Search|Blog|News|Home|"
    r"Products|Researchers|Resources|About us|Contact|Get started|[A-Z][a-z]+ [a-z]+|"
    r"Cookie[s]?|Accept|Privacy|Terms)$", re.I)
DATE_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}|\d{1,2} (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* \d{4}|"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* \d{1,2},? \d{4})$", re.I)


def summarize(lines, title):
    occ = [i for i, l in enumerate(lines[:90]) if l.startswith(title[:40])]
    if not occ:
        return ""
    i = occ[-1] + 1
    buf = []
    steps = 0
    while i < len(lines) and steps < 30 and len(" ".join(buf)) < 420:
        l = lines[i]
        i += 1
        steps += 1
        if JUNK_LINE.match(l) or DATE_LINE.match(l) or len(l) < 4 or re.match(r"^\d+([.,]\d+)?$", l):
            continue
        buf.append(l)
        if len(buf) >= 2 and l.endswith((".", "!", "?", "”", '"')):
            break
    s = " ".join(buf)
    s = re.split(r"(Products Researchers|Share this article|Related articles|Table of contents|"
                 r"Cookie|Subscribe)", s)[0]
    return re.sub(r"\s+", " ", s)[:400]


def norm_date(s):
    if not s:
        return None
    s = s.strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        return s
    m = re.match(r"^(\d{1,2})[/.](\d{1,2})[/.](\d{4})$", s)
    if m:
        d, mo, y = m.groups()
        return f"{y}-{int(mo):02d}-{int(d):02d}"
    m = re.match(r"^([A-Za-z]{3,9}) (\d{1,2}),? (\d{4})$", s)
    if m:
        mo, d, y = m.groups()
        return f"{y}-{MONTHS.get(mo[:3].lower(), 1):02d}-{int(d):02d}"
    m = re.match(r"^(\d{1,2}) ([A-Za-z]{3,9}) (\d{4})$", s)
    if m:
        d, mo, y = m.groups()
        return f"{y}-{MONTHS.get(mo[:3].lower(), 1):02d}-{int(d):02d}"
    return None


def find_date(text):
    head = text[:4000]
    for pat in DATE_PATTERNS:
        m = re.search(pat, head, re.I)
        if m:
            d = norm_date(m.group(1))
            if d:
                return d
    # meta HTML : article:published_time / datePublished
    return None


def find_date_html(html):
    for pat in (r'article:published_time"\s+content="([^"]+)"',
                r'"datePublished"\s*:\s*"([^"]+)"',
                r'"date"\s*:\s*"([^"]{6,30})"'):
        m = re.search(pat, html)
        if m:
            d = norm_date(m.group(1)[:10])
            if d:
                return d
    return None


def clean_title(t):
    t = htmllib.unescape(t or "").strip()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"^\[\s*(?:bug bounty\s*)?writeup\s*\]\s*", "", t, flags=re.I)
    if " | " in t:
        t = t.split(" | ")[0].strip()
    if " - " in t and len(t.split(" - ")[0]) > 15:
        t = t.split(" - ")[0].strip()
    t = re.sub(r"^(writeup|case study|report)\s*[:—-]\s*", "", t, flags=re.I)
    return t[:200]


def main():
    if not os.path.isdir(PAGES):
        print("[!] pas de pages rendues")
        return
    rows = []
    for txt_path in sorted(glob.glob(os.path.join(PAGES, "*", "*.txt"))):
        source = os.path.basename(os.path.dirname(txt_path))
        slug = os.path.splitext(os.path.basename(txt_path))[0]
        html_path = txt_path[:-4] + ".html"
        text = open(txt_path, encoding="utf-8", errors="replace").read()
        html = open(html_path, encoding="utf-8", errors="replace").read() if os.path.exists(html_path) else ""
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        title = None
        # 1) og:title, puis <title>, puis heuristique sur le texte visible
        for pat in (r'<meta property="og:title" content="([^"]+)"',
                    r"<title[^>]*>(.*?)</title>"):
            m = re.search(pat, html, re.S) if html else None
            if m:
                t = clean_title(m.group(1))
                if t and len(t) >= 10:
                    title = t
                    break
        if not title and lines:
            for cand in lines[:8]:
                low = cand.lower()
                if low in ("home", "blog", "menu", "search", "writeups", "news", "share"):
                    continue
                if 12 <= len(cand) <= 200:
                    title = clean_title(cand)
                    break
        # résumé : og:description si propre, sinon paragraphe après le titre
        ogdesc = ""
        if html:
            m = re.search(r'<meta property="og:description" content="([^"]+)"', html)
            if not m:
                m = re.search(r'<meta name="description" content="([^"]+)"', html)
            if m:
                ogdesc = re.sub(r"\s+", " ", htmllib.unescape(m.group(1))).strip()
        summary = ogdesc if len(ogdesc) >= 60 else (summarize(lines, title) if title else "")
        if not summary and lines:
            summary = " ".join(lines[1:5])[:400]
        date = find_date(text) or find_date_html(html)
        url = None
        m = re.search(r'<link rel="canonical" href="([^"]+)"', html)
        if m:
            url = m.group(1)
        rows.append({"source": source, "slug": slug, "url": url,
                     "title": title, "date": date, "summary": summary})

    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with_titles = sum(1 for r in rows if r["title"])
    with_dates = sum(1 for r in rows if r["date"])
    print(f"[i] page_meta.jsonl : {len(rows)} pages | titres: {with_titles} | dates: {with_dates}")


if __name__ == "__main__":
    main()
