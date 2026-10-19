#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Normalise toutes les sources collectées en data/arsenal.jsonl (schéma unifié).

Sources lues :
  data/h1_meta.jsonl        — HackerOne (rapports divulgués, métadonnées + résumé)
  data/feeds.jsonl          — flux RSS/Atom (presse spé, labs, podcasts)
  data/sitemap_urls.jsonl   — LogicalBreach Academy, YesWeHack
  data/pentesterland.json   — historique 2021-2024 (agrégateur gelé)

Dédoublonnage par URL canonique. Le champ « also_on » liste les autres
sources qui référencent la même URL.

Usage : .venv/bin/python normalize.py
"""
import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
OUT = os.path.join(DATA, "arsenal.jsonl")

TRACK = re.compile(r"[?&](utm_[^=&]+|fbclid|gclid|ref|source)=[^&]*")

# Priorité en cas de doublon (plus petit = gardé en premier)
KIND_PRIORITY = {
    "report": 0,           # HackerOne
    "article": 1,          # writeups d'éditeurs (logicalbreach, yeswehack...)
    "blog": 2,             # posts de labs
    "episode": 3,          # podcast
    "history": 9,          # pentester.land
}


def canon_url(u):
    if not u:
        return None
    u = u.strip()
    u = TRACK.sub("", u)
    u = re.sub(r"\?&", "?", u).rstrip("?")
    u = re.sub(r"^http://", "https://", u)
    u = re.sub(r"^https://www\.", "https://", u)
    # supprime les slashs dupliqués hors schéma (ex : academy.x//writeups)
    scheme, sep, rest = u.partition("://")
    if sep:
        rest = re.sub(r"/{2,}", "/", rest)
        u = scheme + sep + rest
    return u.rstrip("/")


def uid(u):
    return hashlib.sha1((u or "").encode()).hexdigest()[:12]


def mk(title, url, date, source, kind, **kw):
    u = canon_url(url)
    if not u or not title:
        return None
    entry = {
        "uid": uid(u),
        "title": re.sub(r"\s+", " ", title).strip()[:300],
        "url": u,
        "date": (date or None),
        "year": int(date[:4]) if date and date[:4].isdigit() else None,
        "source": source,
        "kind": kind,
        "also_on": [],
        "severity": kw.get("severity"),
        "bounty": kw.get("bounty"),
        "votes": kw.get("votes"),
        "program": kw.get("program"),
        "weakness": kw.get("weakness"),
        "cve_ids": kw.get("cve_ids") or [],
        "summary": (kw.get("summary") or "")[:600],
        "extra": kw.get("extra") or {},
    }
    return entry


def load_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    return rows


def main():
    entries = []

    # 1) HackerOne (dédupliqué par id, les lignes d'erreur sont ignorées)
    h1_by_id = {}
    for m in load_jsonl(os.path.join(DATA, "h1_meta.jsonl")):
        if m.get("error"):
            continue
        h1_by_id[str(m.get("id"))] = m
    for m in h1_by_id.values():
        e = mk(m.get("title"), m.get("url"), (m.get("disclosed_at") or "")[:10],
               "hackerone", "report",
               severity=(m.get("severity") or "").capitalize() or None,
               bounty=m.get("bounty") or None,
               votes=m.get("votes"),
               program=m.get("team") or m.get("team_handle"),
               weakness=m.get("weakness"),
               cve_ids=m.get("cve_ids"),
               summary=m.get("summary"),
               extra={"h1_id": m.get("id"), "submitted_at": (m.get("submitted_at") or "")[:10]})
        if e:
            entries.append(e)

    # 2) Flux RSS/Atom
    for f in load_jsonl(os.path.join(DATA, "feeds.jsonl")):
        src = f["source"]
        kind = "episode" if src in ("critical-thinking",) else "blog"
        e = mk(f.get("title"), f.get("url"), f.get("published"), src, kind,
               summary=f.get("summary"))
        if e:
            entries.append(e)

    # 3) Sitemaps (titre/date/résumé enrichis par enrich_pages.py si dispo)
    page_meta = {}
    for pm in load_jsonl(os.path.join(DATA, "page_meta.jsonl")):
        page_meta[(pm.get("source"), pm.get("slug"))] = pm
    SRCMAP = {"logicalbreach-academy": "logicalbreach", "yeswehack": "yeswehack"}
    for s in load_jsonl(os.path.join(DATA, "sitemap_urls.jsonl")):
        src = s["source"]
        url = s.get("url") or ""
        slug = url.rstrip("/").split("/")[-1]
        pm = page_meta.get((SRCMAP.get(src), slug), {})
        title = pm.get("title") or (slug.replace("-", " ").replace("_", " ")).strip()
        title = (title[:1].upper() + title[1:]) if title else src
        if pm:
            date = pm.get("date") or None
        else:
            date = (s.get("lastmod") or "")[:10] or None
        summary = pm.get("summary") or ""
        e = mk(title, url, date, src,
               "article" if src == "logicalbreach-academy" else "blog",
               summary=summary)
        if e:
            e["extra"]["from_sitemap"] = True
            entries.append(e)

    # 4) Historique pentester.land
    pl_path = os.path.join(DATA, "pentesterland.json")
    if os.path.exists(pl_path):
        with open(pl_path, encoding="utf-8") as f:
            pl = json.load(f)["data"]
        for it in pl:
            date = (it.get("PublicationDate") or it.get("AddedDate") or "")[:10] or None
            for l in it.get("Links") or []:
                e = mk(l.get("Title"), l.get("Link"), date, "pentester.land", "history",
                       summary="", extra={"bugs": it.get("Bugs") or [],
                                          "authors": it.get("Authors") or [],
                                          "programs": it.get("Programs") or [],
                                          "bounty": it.get("Bounty")})
                if e:
                    entries.append(e)

    # Dédoublonnage par URL canonique
    # (les épisodes de podcast partagent la même URL : clé url+titre)
    by_url = {}
    for e in sorted(entries, key=lambda x: KIND_PRIORITY.get(x["kind"], 5)):
        u = e["url"]
        key = u if e["kind"] != "episode" else f"{u}#{e['title'][:80]}"
        if key in by_url:
            keep = by_url[key]
            if e["source"] not in keep["also_on"] and e["source"] != keep["source"]:
                keep["also_on"].append(e["source"])
            # complète les champs manquants
            for k in ("severity", "bounty", "votes", "program", "weakness", "summary"):
                if not keep.get(k) and e.get(k):
                    keep[k] = e[k]
            if not keep.get("date") and e.get("date"):
                keep["date"] = e["date"]
                keep["year"] = e["year"]
            continue
        by_url[key] = e

    merged = list(by_url.values())
    merged.sort(key=lambda x: (x.get("date") or "0000-00-00"), reverse=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for e in merged:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"[i] arsenal.jsonl : {len(merged)} entrées uniques "
          f"(à partir de {len(entries)} brutes)")


if __name__ == "__main__":
    main()
