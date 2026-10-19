#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fetch statique + extraction de contenu pour les pages SPA (logicalbreach, yeswehack).

Le HTML SSR contient le contenu (payload Next.js/Framer dans les <script>) :
inutile de faire tourner un navigateur. Extraction = texte visible + chaînes
longues décodées depuis les scripts (filtrées du bruit JavaScript).

Entrée : data/render_targets.jsonl
Sorties : data/raw/pages/<source>/<slug>.txt et .html
Usage : .venv/bin/python fetch_static.py [--targets f] [--limit N] [--redo]
"""
import argparse
import html as htmllib
import json
import os
import re
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
PAGES = os.path.join(DATA, "raw", "pages")
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}

JS_NOISE = re.compile(
    r"(function|=>|\$[A-Z]|var |let |const |document\.|window\.|prototype|"
    r"application/json|text/html|requestAnimationFrame|appendChild|"
    r"nextSibling|parentNode|addEventListener|onclick|querySelector)", re.I)


def visible_text(raw):
    body = re.sub(r"<script[^>]*>.*?</script>", " ", raw, flags=re.S)
    body = re.sub(r"<style[^>]*>.*?</style>", " ", body, flags=re.S)
    body = re.sub(r"<noscript[^>]*>.*?</noscript>", " ", body, flags=re.S)
    body = re.sub(r"<[^>]+>", "\n", body)
    body = htmllib.unescape(body)
    lines = [re.sub(r"\s+", " ", l).strip() for l in body.splitlines()]
    return "\n".join(l for l in lines if l)


def flight_strings(raw, min_len=90):
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", raw, re.S)
    joined = "\n".join(scripts)
    dec = joined.replace('\\"', '"').replace("\\n", "\n").replace("\\u0026", "&")
    dec = re.sub(r"\\u003c", "<", dec)
    dec = re.sub(r"\\u003e", ">", dec)
    cands = []
    cands += re.findall(r'"([^"\\\n]{90,2000})"', joined)
    cands += re.findall(r'"([^"\\\n]{90,2000})"', dec)
    out, seen = [], set()
    for s in cands:
        s = htmllib.unescape(s).strip()
        if len(s) < min_len or s in seen:
            continue
        if JS_NOISE.search(s):
            continue
        letters = sum(c.isalpha() or c.isspace() for c in s) / max(len(s), 1)
        if letters < 0.72:
            continue
        if len(s.split()) < 10:
            continue
        seen.add(s)
        out.append(s)
    return out


def extract(raw):
    title = None
    m = re.search(r"<title[^>]*>(.*?)</title>", raw, re.S)
    if m:
        title = re.sub(r"\s+", " ", htmllib.unescape(m.group(1))).strip()
    desc = None
    m = re.search(r'<meta name="description" content="([^"]*)"', raw)
    if m:
        desc = htmllib.unescape(m.group(1))
    return title, desc, visible_text(raw), flight_strings(raw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default=os.path.join(DATA, "render_targets.jsonl"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--redo", action="store_true")
    args = ap.parse_args()

    targets = []
    with open(args.targets, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                targets.append(json.loads(line))
    if args.limit:
        targets = targets[: args.limit]

    todo = []
    for t in targets:
        outdir = os.path.join(PAGES, t.get("source", "misc"))
        os.makedirs(outdir, exist_ok=True)
        t["_txt"] = os.path.join(outdir, f"{t['slug']}.txt")
        t["_html"] = os.path.join(outdir, f"{t['slug']}.html")
        if args.redo or not os.path.exists(t["_txt"]):
            todo.append(t)

    print(f"[i] {len(targets)} cibles, {len(todo)} à traiter", flush=True)
    ok = err = 0
    for i, t in enumerate(todo, 1):
        try:
            r = requests.get(t["url"], headers=HEADERS, timeout=30)
            raw = r.text
            title, desc, vis, fs = extract(raw)
            parts = [title or t["slug"], "", vis]
            if fs:
                parts += ["", "=== CONTENU EXTRAIT (payload) ===", ""]
                parts += fs
            txt = "\n".join(parts)
            with open(t["_html"], "w", encoding="utf-8") as f:
                f.write(raw)
            with open(t["_txt"], "w", encoding="utf-8") as f:
                f.write(txt)
            ok += 1
            flag = "" if len(vis) > 1500 or len(fs) > 5 else "  (contenu faible — vérifier)"
            print(f"[{i}/{len(todo)}] ok {t['slug'][:58]} | visible {len(vis)} | payload {len(fs)}{flag}", flush=True)
        except Exception as ex:
            err += 1
            print(f"[{i}/{len(todo)}] ERR {t['slug'][:58]} : {type(ex).__name__} {ex}", flush=True)
        time.sleep(0.9)
    print(f"[i] terminé : ok={ok} err={err}", flush=True)


if __name__ == "__main__":
    main()
