#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sélectionne les cas pour les fiches SSS + génère des squelettes.

Lecture  : data/arsenal_classified.jsonl, data/raw/h1/*.json
Sorties  :
  data/fiche_selection.jsonl          — la liste des cas retenus (avec score)
  data/fiches_scaffold/<NN-slug>.md   — squelettes par catégorie, prêts à enrichir

Usage : .venv/bin/python select_fiches.py [--per-cat 3]
"""
import argparse
import json
import os
import re
from collections import defaultdict

from classify import CATEGORIES
from render_arsenal import DISPLAY_ORDER, SOURCE_LABELS

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
RAW_H1 = os.path.join(DATA, "raw", "h1")
SCAFFOLD = os.path.join(DATA, "fiches_scaffold")
SEL_OUT = os.path.join(DATA, "fiche_selection.jsonl")

SEV_W = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

PREFERRED_SOURCES = {"hackerone": 4, "logicalbreach-academy": 3, "yeswehack": 3,
                     "portswigger": 2, "critical-thinking": 1}


def h1_raw_stats(rid):
    """Retourne (log_vuln_info, nb_blocs_techniques) depuis le brut H1."""
    p = os.path.join(RAW_H1, f"{rid}.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return None
    vi = d.get("vulnerability_information") or ""
    tech = vi.count("```") // 2 + len(re.findall(r"(?:GET|POST|PUT|DELETE|PATCH) /", vi))
    return len(vi), tech


def score(e):
    s = 0.0
    s += SEV_W.get((e.get("severity") or "none").lower(), 0) * 2
    if e.get("bounty"):
        s += 2
    s += min(int(e.get("votes") or 0), 60) / 15.0
    if e.get("year") == 2026:
        s += 1.5
    elif e.get("year") == 2025:
        s += 0.5
    s += PREFERRED_SOURCES.get(e.get("source"), 0)
    if e.get("source") == "hackerone" and e.get("kind") == "report":
        rid = (e.get("extra") or {}).get("h1_id")
        st = h1_raw_stats(rid) if rid else None
        if st:
            log_vi, tech = st
            if log_vi > 3500:
                s += 2
            elif log_vi > 1500:
                s += 1
            s += min(tech, 6) * 0.5
        else:
            s -= 5  # pas de texte brut → inutilisable pour une fiche
    if (e.get("summary") or "") and len(e["summary"]) > 200:
        s += 0.5
    return round(s, 2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-cat", type=int, default=3)
    args = ap.parse_args()

    rows = []
    with open(os.path.join(DATA, "arsenal_classified.jsonl"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    rows = [e for e in rows if e.get("year") in (2025, 2026) and e.get("kind") != "history"]

    bycat = defaultdict(list)
    for e in rows:
        e["_score"] = score(e)
        bycat[e["category"]].append(e)

    os.makedirs(SCAFFOLD, exist_ok=True)
    selection = []
    for slug in DISPLAY_ORDER:
        es = sorted(bycat.get(slug, []), key=lambda x: -x["_score"])
        taken = []
        seen_titles = set()
        for e in es:
            if len(taken) >= args.per_cat:
                break
            key = re.sub(r"\W+", "", (e.get("title") or "").lower())[:60]
            if key in seen_titles or e["_score"] <= 0:
                continue
            seen_titles.add(key)
            taken.append(e)
        idx = DISPLAY_ORDER.index(slug) + 1
        lines = [f"# Fiches SSS — {CATEGORIES[slug]}", "",
                 f"*{len(taken)} cas sélectionnés dans le corpus 2025-2026.*", ""]
        for e in taken:
            selection.append({**{k: v for k, v in e.items() if k != "_score"},
                              "score": e["_score"]})
            src = SOURCE_LABELS.get(e["source"], e["source"])
            rid = (e.get("extra") or {}).get("h1_id")
            raw = f"`data/raw/h1/{rid}.json`" if e["source"] == "hackerone" and rid else "— (page web)"
            summ = (e.get("summary") or "")[:900]
            lines += [
                f"## {e['title']}", "",
                f"- Source : [{src}]({e['url']})",
                f"- Date : {e.get('date') or '?'} · Sévérité : {e.get('severity') or '?'} · "
                f"Bounty : {e.get('bounty') or 0} · Votes : {e.get('votes') or 0}",
                f"- Programme : {e.get('program') or '?'} · Weakness : {e.get('weakness') or '?'}",
                f"- Texte brut : {raw}",
                "",
                "**Résumé d'après la source :**", "", f"> {summ}", "",
                "**À produire (fiche SSS, format WRITEUP_KB) :**", "",
                "- Résumé factuel du cas (2-5 lignes)",
                "- Cause racine",
                "- Preuve technique — extraits VERBATIM de la source uniquement (requêtes, payloads, code)",
                "- Rejouer / exploiter : prérequis, étapes, pièges (dérivé de la source seule)",
                "- Reproductibilité : haute|moyenne|basse + justification 1 ligne",
                "- Techniques (vocabulaire normalisé, minuscules)",
                "- Classes qualifiantes + Signal (endpoints/params)",
                "",
                "---", ""]
        with open(os.path.join(SCAFFOLD, f"{idx:02d}-{slug}.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    with open(SEL_OUT, "w", encoding="utf-8") as f:
        for e in selection:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    print(f"[i] {len(selection)} cas sélectionnés pour {len(DISPLAY_ORDER)} catégories")
    cnt = defaultdict(int)
    for e in selection:
        cnt[e["category"]] += 1
    for slug in DISPLAY_ORDER:
        print(f"  {cnt[slug]:2d}  {slug}")


if __name__ == "__main__":
    main()
