#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Récupère hackerone.com/reports/<id>.json pour chaque carte collectée.

Sorties :
  data/raw/h1/<id>.json   — réponse brute (texte intégral du rapport inclus)
  data/h1_meta.jsonl      — champs essentiels + résumé court (pour l'index)

Reprise : les ids déjà présents dans h1_meta.jsonl sont ignorés.

Usage : .venv/bin/python h1_fetch_json.py [--workers 3] [--limit N]
"""
import argparse
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
RAW_DIR = os.path.join(DATA, "raw", "h1")
CARDS_PATH = os.path.join(DATA, "h1_cards.jsonl")
META_PATH = os.path.join(DATA, "h1_meta.jsonl")
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept": "application/json"}
lock = threading.Lock()


def clean_md(text, limit=500):
    text = re.sub(r"```.*?```", "[code]", text, flags=re.S)
    text = re.sub(r"[#*_>`]+", " ", text)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def extract_summary(vi):
    """Essaie de récupérer la section Summary/Description du rapport."""
    if not vi:
        return None
    m = re.search(r"(?:^|\n)#{1,4}\s*(?:summary|description|details|impact)[^\n]*\n+(.{0,600})",
                  vi, flags=re.I | re.S)
    if m:
        return clean_md(m.group(1), 420)
    return clean_md(vi, 420)


def fetch_one(rid):
    url = f"https://hackerone.com/reports/{rid}.json"
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
    except Exception as ex:
        return {"id": rid, "error": f"net:{type(ex).__name__}"}
    if r.status_code != 200:
        return {"id": rid, "error": f"http:{r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"id": rid, "error": "badjson"}
    with open(os.path.join(RAW_DIR, f"{rid}.json"), "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False)
    team = d.get("team") or {}
    weakness = d.get("weakness") or {}
    meta = {
        "id": str(d.get("id") or rid),
        "url": d.get("url") or f"https://hackerone.com/reports/{rid}",
        "title": d.get("title"),
        "severity": d.get("severity_rating"),
        "disclosed_at": d.get("disclosed_at"),
        "submitted_at": d.get("submitted_at"),
        "team": team.get("profile", {}).get("name") if isinstance(team.get("profile"), dict) else None,
        "team_handle": team.get("handle"),
        "weakness": weakness.get("name"),
        "cve_ids": d.get("cve_ids") or [],
        "bounty": d.get("bounty_amount") or 0,
        "votes": d.get("vote_count") or 0,
        "summary": extract_summary(d.get("vulnerability_information")),
        "source": "hackerone",
        "source_type": "report",
    }
    return meta


def load_done():
    """Ids déjà récupérés avec succès (les lignes d'erreur ne comptent pas — à réessayer)."""
    done = set()
    if os.path.exists(META_PATH):
        with open(META_PATH, encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                    if not row.get("error"):
                        done.add(str(row["id"]))
                except Exception:
                    pass
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    os.makedirs(RAW_DIR, exist_ok=True)
    ids = []
    seen = set()
    with open(CARDS_PATH, encoding="utf-8") as f:
        for line in f:
            try:
                rid = str(json.loads(line)["id"])
            except Exception:
                continue
            if rid not in seen:
                seen.add(rid)
                ids.append(rid)
    done = load_done()
    todo = [i for i in ids if i not in done]
    if args.limit:
        todo = todo[: args.limit]
    print(f"[i] {len(ids)} ids uniques, {len(done)} déjà faits → {len(todo)} à traiter", flush=True)
    if not todo:
        return

    ok = err = 0
    with open(META_PATH, "a", encoding="utf-8") as out:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(fetch_one, rid): rid for rid in todo}
            for i, fut in enumerate(as_completed(futs), 1):
                meta = fut.result()
                with lock:
                    out.write(json.dumps(meta, ensure_ascii=False) + "\n")
                    out.flush()
                if "error" in meta:
                    err += 1
                else:
                    ok += 1
                if i % 25 == 0 or i == len(todo):
                    print(f"[{i}/{len(todo)}] ok={ok} err={err}", flush=True)
                time.sleep(0.05)
    print(f"[i] terminé : ok={ok} err={err}", flush=True)


if __name__ == "__main__":
    main()
