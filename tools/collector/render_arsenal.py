#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rend le corpus classé en Markdown rangé dans knowledge/writeups/arsenal_2025_2026/.

Lecture :  data/arsenal_classified.jsonl
Sorties :
  knowledge/writeups/arsenal_2025_2026/INDEX.md
  knowledge/writeups/arsenal_2025_2026/categories/NN-slug.md
  knowledge/writeups/arsenal_2025_2026/HISTORIQUE_2021_2024.md
  knowledge/writeups/arsenal_2025_2026/SOURCES.md

Usage : .venv/bin/python render_arsenal.py
"""
import json
import os
import re
from collections import Counter, defaultdict
from datetime import date
from glob import glob

from classify import CATEGORIES

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTDIR = os.path.join(REPO, "knowledge", "writeups", "arsenal_2025_2026")
CATDIR = os.path.join(OUTDIR, "categories")

DISPLAY_ORDER = [
    "access-control-idor", "api-mobile", "auth-bypass", "business-logic", "cloud",
    "command-injection", "kubernetes", "cookie-injection", "cve-deep-dives", "dos",
    "graphql", "http-smuggling", "info-disclosure", "injection", "memory-corruption",
    "open-redirect", "path-traversal", "race-condition", "resource-accounting",
    "ssrf-cache", "ssti-deserialization", "supply-chain", "xss", "misc",
]

SOURCE_LABELS = {
    "hackerone": "HackerOne",
    "logicalbreach-academy": "LogicalBreach",
    "yeswehack": "YesWeHack",
    "critical-thinking": "Critical Thinking (podcast)",
    "infosecwriteups": "Infosec Writeups",
    "intigriti": "Intigriti",
    "reddit-bugbounty": "r/bugbounty",
    "reddit-netsec": "r/netsec",
    "doyensec": "Doyensec",
    "trailofbits": "Trail of Bits",
    "nccgroup": "NCC Group",
    "includesecurity": "Include Security",
    "sonarsource": "SonarSource",
    "projectdiscovery": "ProjectDiscovery",
    "portswigger": "PortSwigger Research",
    "detectify": "Detectify",
    "pentester.land": "pentester.land",
}

SEV_FR = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
          "none": "None", "informative": "Informative"}

MAIN_SOURCES_NO_DATE = {"logicalbreach-academy", "yeswehack"}


def fmt_bounty(b):
    try:
        b = float(b)
        if b <= 0:
            return None
        return f"${b:,.0f}"
    except Exception:
        return None


def clean(s):
    return re.sub(r"\s+", " ", (s or "")).replace("|", "\\|").strip()


def entry_line(e, max_summary=230):
    src = SOURCE_LABELS.get(e["source"], e["source"])
    date = e.get("date") or "date ?"
    bits = [f"**{clean(e['title'])}**", f"[{src}]({e['url']})", f"`{date}`"]
    if e.get("severity") and e["severity"].lower() not in ("none", "informative"):
        sev = SEV_FR.get(e["severity"].lower(), e["severity"])
        bits.append(f"**{sev}**")
    b = fmt_bounty(e.get("bounty"))
    if b:
        bits.append(b)
    extras = []
    if e.get("program"):
        extras.append(f"*{clean(e['program'])}*")
    if e.get("votes") and e["votes"] >= 5:
        extras.append(f"▲{e['votes']}")
    if e.get("cve_ids"):
        extras.append("/".join(e["cve_ids"][:2]))
    if e.get("also_on"):
        extras.append("vu aussi sur " + ", ".join(SOURCE_LABELS.get(s, s) for s in e["also_on"][:3]))
    line = "- " + " · ".join(bits)
    if extras:
        line += " · " + " · ".join(extras)
    summ = clean(e.get("summary"))
    if summ and not summ.startswith("(titre reconstruit"):
        line += f"\n  > {summ[:max_summary]}"
    return line


def write_category(slug, entries):
    label = CATEGORIES[slug]
    idx = DISPLAY_ORDER.index(slug) + 1
    path = os.path.join(CATDIR, f"{idx:02d}-{slug}.md")
    with_date = [e for e in entries if e.get("date")]
    no_date = [e for e in entries if not e.get("date")]
    with_date.sort(key=lambda x: x["date"], reverse=True)
    lines = [f"# {label}", "",
             f"*{len(entries)} entrées — corpus 2025-2026 de l'arsenal "
             f"(voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*", ""]
    for e in with_date:
        lines.append(entry_line(e))
    if no_date:
        lines += ["", f"## Sans date ({len(no_date)})", ""]
        for e in no_date:
            lines.append(entry_line(e))
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def write_index(rows_2025_26, history_rows):
    bycat = defaultdict(list)
    for e in rows_2025_26:
        bycat[e["category"]].append(e)
    src_counts = Counter(e["source"] for e in rows_2025_26)
    y25 = sum(1 for e in rows_2025_26 if e.get("year") == 2025)
    y26 = sum(1 for e in rows_2025_26 if e.get("year") == 2026)
    nd = sum(1 for e in rows_2025_26 if not e.get("year"))
    total_h = len(history_rows)

    lines = ["# Arsenal 2025-2026 — index général", "",
             f"*Corpus collecté le {date.today().isoformat()} · "
             f"{len(rows_2025_26)} entrées 2025-2026 classées en {len(DISPLAY_ORDER)} catégories "
             f"+ {total_h} entrées historiques (2021-2024).*", "",
             "## Statistiques", "",
             f"- 2025 : **{y25}** · 2026 : **{y26}** · sans date : **{nd}**",
             f"- Sources : {len(src_counts)}", "",
             "## Catégories", "",
             "| Catégorie | 2025 | 2026 | sans date | total |",
             "|---|---|---|---|---|"]
    for slug in DISPLAY_ORDER:
        es = bycat.get(slug, [])
        if not es:
            continue
        a = sum(1 for e in es if e.get("year") == 2025)
        b = sum(1 for e in es if e.get("year") == 2026)
        c = sum(1 for e in es if not e.get("year"))
        idx = DISPLAY_ORDER.index(slug) + 1
        lines.append(f"| [{CATEGORIES[slug]}](categories/{idx:02d}-{slug}.md) | {a} | {b} | {c} | **{len(es)}** |")
    lines += ["", "## Sources", "", "| Source | Entrées |", "|---|---|"]
    for s, n in src_counts.most_common():
        lines.append(f"| {SOURCE_LABELS.get(s, s)} | {n} |")
    fiches_dir = os.path.join(OUTDIR, "fiches_sss")
    fiche_files = glob(os.path.join(fiches_dir, "*.md"))
    n_fiches = 0
    for p in fiche_files:
        if os.path.getsize(p) <= 1200:
            continue
        with open(p, encoding="utf-8") as fh:
            n_fiches += sum(1 for line in fh if line.startswith("### "))
    top_exists = os.path.exists(os.path.join(OUTDIR, "TOP_EXPLOITABLE.md"))
    lines += ["",
              "## Contenu du dossier", "",
              "- `categories/` — le corpus 2025-2026 classé (une page par catégorie, tri date décroissante).",
              f"- `fiches_sss/` — **{n_fiches} fiches détaillées** (cause racine, preuve verbatim, "
              "rejouer/exploiter, reproductibilité) au format de `WRITEUP_KB.md`.",
              ("- `TOP_EXPLOITABLE.md` — les cas les plus directement rejouables, classés par reproductibilité."
               if top_exists else
               "- `TOP_EXPLOITABLE.md` — généré par `top_exploitable.py` une fois les fiches écrites."),
              "- `HISTORIQUE_2021_2024.md` — index historique compact (pentester.land).",
              "- `SOURCES.md` — liste des sources, leur état, et comment rafraîchir le corpus.", "",
              "## Rafraîchir le corpus", "",
              "```bash",
              "cd tools/collector",
              ".venv/bin/python h1_collect.py            # énumère Hacktivity (Selenium)",
              ".venv/bin/python h1_fetch_json.py         # récupère le texte des rapports",
              ".venv/bin/python collect_feeds.py         # flux RSS + sitemaps",
              ".venv/bin/python normalize.py && .venv/bin/python classify.py",
              ".venv/bin/python render_arsenal.py        # régénère ce dossier",
              "```", ""]
    with open(os.path.join(OUTDIR, "INDEX.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_history(history_rows, bonus_rows=None):
    by_year = defaultdict(list)
    for e in history_rows:
        by_year[(e.get("date") or "????")[:4]].append(e)
    lines = ["# Historique 2021-2024 — index compact (pentester.land)", "",
             f"*{len(history_rows)} writeups indexés par l'agrégateur pentester.land "
             "(gelé fin 2024). Index compact : titre, lien, types de bugs.*", ""]
    for year in sorted(by_year, reverse=True):
        es = sorted(by_year[year], key=lambda x: x.get("date") or "", reverse=True)
        lines += [f"## {year} ({len(es)})", ""]
        for e in es:
            bugs = ", ".join((e.get("extra") or {}).get("bugs") or [])
            suffix = f" — *{bugs}*" if bugs else ""
            lines.append(f"- `{e.get('date') or '?'}` — [{clean(e['title'])}]({e['url']}){suffix}")
        lines.append("")
    if bonus_rows:
        by_year2 = defaultdict(list)
        for e in bonus_rows:
            by_year2[(e.get("date") or "????")[:4]].append(e)
        lines += ["---", "",
                  f"# Bonus — HackerOne 2023-2024 ({len(bonus_rows)} rapports divulgués)", "",
                  "*Rapports HackerOne hors périmètre principal (collectés en marge quand on "
                  "remontait Hacktivity pour couvrir 2025). Sévérité et bounty inclus quand publics.*", ""]
        for year in sorted(by_year2, reverse=True):
            es = sorted(by_year2[year], key=lambda x: x.get("date") or "", reverse=True)
            lines += [f"## {year} ({len(es)})", ""]
            for e in es:
                suf = []
                if e.get("severity"):
                    suf.append(SEV_FR.get(e["severity"].lower(), e["severity"]))
                b = fmt_bounty(e.get("bounty"))
                if b:
                    suf.append(b)
                if e.get("program"):
                    suf.append(f"*{clean(e['program'])}*")
                suffix = (" — " + ", ".join(suf)) if suf else ""
                lines.append(f"- `{e.get('date') or '?'}` — [{clean(e['title'])}]({e['url']}){suffix}")
            lines.append("")
    with open(os.path.join(OUTDIR, "HISTORIQUE_2021_2024.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_sources():
    lines = ["# Sources du corpus — état et rafraîchissement", "",
             "| Source | Type | Collecte | État vérifié le 2026-10-18 |",
             "|---|---|---|---|",
             "| HackerOne Hacktivity (divulgués) | rapports + texte intégral | Selenium + `.json` par rapport | ✅ actif |",
             "| LogicalBreach Academy | writeups | sitemap `writeups/` | ✅ actif |",
             "| YesWeHack `/news/` | writeups/news | server-sitemap | ✅ actif |",
             "| Critical Thinking (podcast) | veille hebdo (liens dans les notes) | RSS | ✅ actif |",
             "| Intigriti Blog | recherche + writeups | RSS (20 derniers) | ✅ actif |",
             "| Infosec Writeups | writeups communauté | RSS (10 derniers) | ⚠️ cadence ralentie |",
             "| PortSwigger Research | recherche | RSS | ✅ actif |",
             "| Trail of Bits / Doyensec / SonarSource / ProjectDiscovery / Detectify | labs | RSS | ✅ actifs |",
             "| r/bugbounty · r/netsec | communauté | RSS | ✅ actifs |",
             "| pentester.land | agrégateur (gelé fin 2024) | JSON complet | 🧊 historique seulement |",
             "| Assetnote | lab | feed gelé janv. 2024 | ❌ ignoré |",
             "| securitybreached.org | devenu blog perso (SPA) | — | ❌ ignoré |",
             "", "## Notes de politesse et limites", "",
             "- Requêtes espacées (1,5-3 s par page Hacktivity, ~5 req/s max sur les `.json`).",
             "- Les flux RSS ne remontent que leurs N derniers items (10-30 selon la source) ; "
             "l'historique profond vient de Hacktivity et de pentester.land.",
             "- Les dates Hacktivity sont relatives sur les cartes ; la date exacte vient du `.json` du rapport.",
             ""]
    with open(os.path.join(OUTDIR, "SOURCES.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    rows = []
    with open(os.path.join(DATA, "arsenal_classified.jsonl"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    main_rows = [e for e in rows if e.get("kind") != "history"
                 and (e.get("year") in (2025, 2026)
                      or (not e.get("year") and e["source"] in MAIN_SOURCES_NO_DATE))]
    history_rows = [e for e in rows if e.get("kind") == "history"]
    bonus_rows = [e for e in rows if e.get("kind") == "report"
                  and e.get("year") in (2023, 2024)]

    os.makedirs(CATDIR, exist_ok=True)
    bycat = defaultdict(list)
    for e in main_rows:
        bycat[e["category"]].append(e)
    for slug in DISPLAY_ORDER:
        write_category(slug, bycat.get(slug, []))
    write_index(main_rows, history_rows)
    write_history(history_rows, bonus_rows)
    write_sources()
    print(f"[i] rendu : {len(main_rows)} entrées 2025-2026 dans {OUTDIR}")
    print(f"[i] historique : {len(history_rows)} entrées (pentester.land) "
          f"+ bonus {len(bonus_rows)} rapports H1 2023-2024")


if __name__ == "__main__":
    main()
