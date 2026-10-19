#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collecte HackerOne Hacktivity (rapports divulgués) via Selenium headless.

- Parcourt les pages Hacktivity triées par date de disclosure (DESC).
- Écrit une ligne JSON par rapport dans data/h1_cards.jsonl.
- S'arrête quand le rapport le plus récent d'une page date de plus de
  --stop-days jours (défaut 700 ≈ tout ce qui suit 2025-01-01, avec marge).
- Reprise automatique après interruption via data/h1_collect_state.json.

Usage :
  .venv/bin/python h1_collect.py [--max-pages N] [--stop-days 700] [--restart]
"""
import argparse
import json
import os
import random
import re
import time
from datetime import datetime, timezone

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
CARDS_PATH = os.path.join(DATA, "h1_cards.jsonl")
STATE_PATH = os.path.join(DATA, "h1_collect_state.json")
CHROME = "/usr/bin/google-chrome"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")

URL_T = ("https://hackerone.com/hacktivity/overview?"
         "queryString=disclosed%3Atrue&sortField=disclosed_at&"
         "sortDirection=DESC&pageIndex={p}")

JS_EXTRACT = r"""
const out = [];
for (const it of document.querySelectorAll('[data-testid="hacktivity-item"]')) {
  const q = (sel) => { const e = it.querySelector(sel); return e ? e.innerText.trim() : null; };
  const a = it.querySelector('a[href^="/reports/"]');
  out.push({
    url: a ? a.getAttribute('href') : null,
    title: q('[data-testid="report-title"]'),
    severity: q('[data-testid="report-severity"]'),
    disclosed_text: q('[data-testid="report-disclosed-at"]'),
    reward: q('[data-testid="report-reward"]'),
  });
}
return out;
"""

_UNIT_DAYS = {
    "minute": 1 / 1440.0,
    "hour": 1 / 24.0,
    "day": 1.0,
    "week": 7.0,
    "month": 30.44,
    "year": 365.25,
}


def rel_days(text):
    """« Bug reported by X was disclosed about 2 months ago » -> ~60.9 jours."""
    if not text:
        return None
    m = re.search(r"(a|an|\d+)\s*(minute|hour|day|week|month|year)s?", text.lower())
    if not m:
        return None
    raw, unit = m.group(1), m.group(2)
    n = 1 if raw in ("a", "an") else int(raw)
    return n * _UNIT_DAYS[unit]


def make_driver():
    opts = Options()
    for a in ["--headless=new", "--no-sandbox", "--disable-gpu",
              "--disable-dev-shm-usage", "--window-size=1440,2400",
              "--lang=en-US", f"--user-agent={UA}",
              "--disable-background-networking", "--no-first-run"]:
        opts.add_argument(a)
    opts.binary_location = CHROME
    d = webdriver.Chrome(options=opts)
    d.set_page_load_timeout(90)
    return d


def wait_items(d, timeout=50):
    """Attend que les cartes rapports apparaissent dans le DOM."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if d.find_elements("css selector", '[data-testid="hacktivity-item"]'):
                return True
        except WebDriverException:
            pass
        time.sleep(1)
    return False


def load_state():
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {"next_page": 0, "total_cards": 0}


def save_state(page, total):
    with open(STATE_PATH, "w") as f:
        json.dump({"next_page": page, "total_cards": total,
                   "updated_at": datetime.now(timezone.utc).isoformat()}, f, indent=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-pages", type=int, default=0, help="0 = pas de limite")
    ap.add_argument("--stop-days", type=float, default=700.0)
    ap.add_argument("--restart", action="store_true", help="repartir de la page 0")
    args = ap.parse_args()

    os.makedirs(DATA, exist_ok=True)
    state = {"next_page": 0, "total_cards": 0}
    if args.restart:
        for p in (CARDS_PATH, STATE_PATH):
            if os.path.exists(p):
                os.remove(p)
    else:
        state = load_state()

    page = state["next_page"]
    total = state["total_cards"]
    empty_streak = 0
    made = 0

    print(f"[i] reprise page {page} — {total} cartes déjà collectées", flush=True)
    d = make_driver()
    try:
        while True:
            url = URL_T.format(p=page)
            try:
                d.get(url)
            except TimeoutException:
                pass  # la page se charge souvent malgré le timeout annoncé

            if not wait_items(d):
                empty_streak += 1
                print(f"[!] page {page} : pas de cartes ({empty_streak}/2)", flush=True)
                if empty_streak >= 2:
                    print("[i] deux pages vides d'affilée — arrêt.", flush=True)
                    break
                page += 1
                continue

            empty_streak = 0
            cards = d.execute_script(JS_EXTRACT) or []
            now = datetime.now(timezone.utc).isoformat()
            with open(CARDS_PATH, "a", encoding="utf-8") as f:
                for c in cards:
                    if not c.get("url"):
                        continue
                    c["id"] = c["url"].rstrip("/").split("/")[-1]
                    c["page"] = page
                    c["collected_at"] = now
                    f.write(json.dumps(c, ensure_ascii=False) + "\n")

            n = len(cards)
            total += n
            made += 1
            newest = rel_days(cards[0].get("disclosed_text"))
            oldest = rel_days(cards[-1].get("disclosed_text"))
            fmt = lambda v: "?" if v is None else f"{v:.0f}j"
            print(f"[page {page:>4}] {n} cartes | plus récent ~{fmt(newest)} "
                  f"| plus ancien ~{fmt(oldest)} | total {total}", flush=True)

            page += 1
            save_state(page, total)

            if newest is not None and newest > args.stop_days:
                print(f"[i] page entièrement antérieure à ~{args.stop_days:.0f} j "
                      f"(~{newest:.0f} j) — arrêt.", flush=True)
                break
            if args.max_pages and made >= args.max_pages:
                print(f"[i] --max-pages {args.max_pages} atteint — arrêt.", flush=True)
                break

            time.sleep(random.uniform(1.5, 3.0))
    except KeyboardInterrupt:
        print("[i] interrompu — état sauvegardé.", flush=True)
    finally:
        save_state(page, total)
        try:
            d.quit()
        except Exception:
            pass
        print(f"[i] terminé : {total} cartes, prochaine page = {page}", flush=True)


if __name__ == "__main__":
    main()
