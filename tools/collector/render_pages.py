#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rend des pages JS (Selenium) et sauvegarde texte + HTML.

Cibles : fichier JSONL fourni par --targets (défaut data/render_targets.jsonl),
lignes du type : {"url": "...", "slug": "...", "source": "..."}

Sorties : data/raw/pages/<source>/<slug>.txt et .html
Reprise : les cibles dont le .txt existe déjà sont sautées.

Usage : .venv/bin/python render_pages.py [--targets f] [--limit N]
"""
import argparse
import json
import os
import re
import time

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
PAGES = os.path.join(DATA, "raw", "pages")
CHROME = "/usr/bin/google-chrome"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")


def make_driver():
    opts = Options()
    for a in ["--headless=new", "--no-sandbox", "--disable-gpu",
              "--disable-dev-shm-usage", "--window-size=1400,2200",
              "--lang=en-US", f"--user-agent={UA}", "--no-first-run"]:
        opts.add_argument(a)
    opts.binary_location = CHROME
    d = webdriver.Chrome(options=opts)
    d.set_page_load_timeout(75)
    return d


def extract_text(html):
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript", "svg", "iframe"]):
        tag.decompose()
    # privilégier article/main si présent
    node = soup.find("article") or soup.find("main") or soup.body or soup
    txt = node.get_text("\n", strip=True)
    txt = re.sub(r"\n{3,}", "\n\n", txt)
    return txt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default=os.path.join(DATA, "render_targets.jsonl"))
    ap.add_argument("--limit", type=int, default=0)
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
        if not os.path.exists(t["_txt"]):
            todo.append(t)
    print(f"[i] {len(targets)} cibles, {len(todo)} à rendre", flush=True)
    if not todo:
        return

    d = make_driver()
    ok = err = 0
    try:
        for i, t in enumerate(todo, 1):
            try:
                try:
                    d.get(t["url"])
                except TimeoutException:
                    pass
                time.sleep(4.5)  # laisse l'hydratation JS se terminer
                html = d.page_source
                if len(html) < 3000:  # page vide/bloquée
                    time.sleep(4)
                    html = d.page_source
                txt = extract_text(html)
                with open(t["_html"], "w", encoding="utf-8") as f:
                    f.write(html)
                with open(t["_txt"], "w", encoding="utf-8") as f:
                    f.write(txt)
                ok += 1
                flag = "" if len(txt) > 1200 else "  (texte court — vérifier)"
                print(f"[{i}/{len(todo)}] ok {t['slug'][:60]} ({len(txt)} chars){flag}", flush=True)
            except Exception as ex:
                err += 1
                print(f"[{i}/{len(todo)}] ERR {t['slug'][:60]} : {ex}", flush=True)
            time.sleep(1.2)
    finally:
        try:
            d.quit()
        except Exception:
            pass
    print(f"[i] terminé : ok={ok} err={err}", flush=True)


if __name__ == "__main__":
    main()
