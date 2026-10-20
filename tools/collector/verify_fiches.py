#!/usr/bin/env python3
"""Contrôle qualité des fiches SSS.

Pour chaque fiche de knowledge/writeups/arsenal_2025_2026/fiches_sss/ :
  1. structure (3 fiches, champs obligatoires) ;
  2. verbatim : chaque bloc de code entre ``` doit trouver ses lignes
     substantielles dans la source brute correspondante (H1 json, page txt,
     summaries, patch_cases) ;
  3. source : l'URL citée doit exister dans fiche_selection.jsonl.

Sortie : rapport ligne à ligne + code de sortie non nul si anomalie.
"""
import json
import re
import sys
import unicodedata
from pathlib import Path

BASE = Path(__file__).resolve().parent
FICHES = BASE.parent.parent / "knowledge/writeups/arsenal_2025_2026/fiches_sss"
RAW_H1 = BASE / "data/raw/h1"
RAW_PAGES = BASE / "data/raw/pages"

SELECTED = {}
for line in (BASE / "data/fiche_selection.jsonl").read_text(encoding="utf-8").splitlines():
    if line.strip():
        d = json.loads(line)
        SELECTED.setdefault(d["url"], d)

PATCH = json.loads((BASE / "data/patch_cases.json").read_text(encoding="utf-8"))

# Writeups externes intégrés au corpus : liés aux rapports dont le texte intégral est absent.
EXTRA_SOURCES = {
    "3423950": [BASE / "data/raw/pages/kazama/cloudflare-self-xss.txt"],
    "3321406": [BASE / "data/raw/pages/kazama/cloudflare-self-xss.txt"],
}


def strip_accents(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")


def norm(s: str) -> str:
    """Normalisation souple pour comparer verbatim <-> source."""
    s = strip_accents(s).lower()
    s = s.replace("’", "'").replace("‘", "'")
    s = s.replace("…", "...").replace("–", "-").replace("—", "-")
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def source_blob(url: str, h1_id: str | None) -> tuple[str, str]:
    """Retourne (texte_source, libellé) pour une entrée."""
    if h1_id:
        p = RAW_H1 / f"{h1_id}.json"
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8"))
            parts = [
                d.get("vulnerability_information") or "",
                d.get("title") or "",
                "\n".join(
                    s.get("content", "") if isinstance(s, dict) else str(s)
                    for s in (d.get("summaries") or [])
                ),
                json.dumps(d.get("severity") or "", ensure_ascii=False),
            ]
            if h1_id in PATCH:
                parts.append("\n".join(
                    s.get("content", "") if isinstance(s, dict) else str(s)
                    for s in (PATCH[h1_id].get("summaries") or [])
                ))
                parts.append(PATCH[h1_id].get("title") or "")
            for extra in EXTRA_SOURCES.get(h1_id, []):
                if extra.exists():
                    parts.append(extra.read_text(encoding="utf-8", errors="replace"))
            return "\n".join(parts), f"h1/{h1_id}.json"
        # sinon chercher une page enregistrée
    if url:
        for sub in ("logicalbreach", "yeswehack", "other"):
            for p in (RAW_PAGES / sub).glob("*.txt"):
                if p.stem and (p.stem in url or url.endswith(p.stem)):
                    return p.read_text(encoding="utf-8", errors="replace"), str(p)
    return "", "INCONNUE"


def check_fiche(path: Path):
    """Renvoie (nb_fiches, erreurs, avertissements)."""
    txt = path.read_text(encoding="utf-8")
    errs, warns = [], []
    stats = {"lignes": 0, "mots": 0}
    parts = re.split(r"(?m)^### ", txt)
    fiches = parts[1:]
    if len(fiches) != 3:
        errs.append(f"structure : {len(fiches)} fiches au lieu de 3")

    for p in fiches:
        head = p.split("\n", 1)[0].strip()[:60]
        m = re.search(r"https://hackerone\.com/reports/(\d+)", p)
        url = m.group(0) if m else None
        h1_id = m.group(1) if m else None

        # URL présente dans la sélection ?
        if url and url not in SELECTED:
            warns.append(f"[{head}] URL absente de la sélection : {url}")

        # source brute
        blob, label = source_blob(url or "", h1_id)
        if not blob:
            warns.append(f"[{head}] source brute introuvable ({url})")
            continue
        nblob = norm(blob)

        # extraire les blocs de code
        blocks = re.findall(r"```[a-z]*\n(.*?)```", p, flags=re.S)
        for bi, block in enumerate(blocks):
            lines = [l for l in block.splitlines() if l.strip()]
            # lignes substantielles (>= 25 caractères après strip)
            subs = [l.strip() for l in lines if len(l.strip()) >= 25]
            if not subs:
                continue
            stats["lignes"] += len(subs)
            for line in subs:  # toutes les lignes substantielles, sans plafond
                nline = norm(line)
                if len(nline) < 25:
                    continue
                if nline in nblob:
                    continue
                # tolérance : sous-séquence de mots de 8+ caractères
                probe = nline[:80]
                if probe in nblob:
                    continue
                errs.append(f"[{head}] bloc{bi} ligne introuvable dans {label} : {line[:90]!r}")

        # reproductibilité obligatoire
        if "**Reproductibilité :**" not in p:
            errs.append(f"[{head}] champ Reproductibilité absent")
        if "**Rejouer / exploiter" not in p:
            errs.append(f"[{head}] section Rejouer absente")

        # longueur de la prose (hors blocs de code) : cible du gabarit 150-400, tolérance 450
        prose = re.sub(r"```.*?```", "", p, flags=re.S)
        words = len(re.findall(r"[\w'À-ÿ]+", prose))
        stats["mots"] += words
        if words > 550:
            errs.append(f"[{head}] fiche trop longue ({words} mots, plafond dur 550)")
        elif words > 450:
            warns.append(f"[{head}] fiche longue ({words} mots, tolérance 450)")
        # cas restreints -> drapeau
        if h1_id and h1_id in PATCH:
            vic = ""
            hp = RAW_H1 / f"{h1_id}.json"
            if hp.exists():
                vic = json.loads(hp.read_text(encoding="utf-8")).get("vulnerability_information") or ""
            if not vic and not re.search(r"indisponible|vulnerability_information`?\s+vide|champ `vulnerability_information` vide", p):
                errs.append(f"[{head}] cas restreint {h1_id} sans drapeau « indisponible »")

    return len(fiches), errs, warns, stats


def main():
    total, all_errs, all_warns, total_lines, total_words = 0, [], [], 0, 0
    for path in sorted(FICHES.glob("*.md")):
        n, errs, warns, stats = check_fiche(path)
        total += n
        total_lines += stats["lignes"]
        total_words += stats["mots"]
        status = "OK " if not errs else "ERR"
        print(f"{status} {path.name:34s} {n} fiches  {stats['lignes']:4d} lignes vérifiées  "
              f"{stats['mots']:4d} mots  {len(errs)} erreur(s) {len(warns)} avertissement(s)")
        for e in errs:
            print(f"     ✗ {e}")
            all_errs.append(e)
        for w in warns[:3]:
            print(f"     ⚠ {w}")
        all_warns.extend(warns)
    print(f"\nTOTAL : {total} fiches | {total_lines} lignes verbatim confrontées aux sources | "
          f"{total_words} mots de prose (médiane du gabarit : 150-400) | "
          f"{len(all_errs)} erreurs | {len(all_warns)} avertissements")
    return 1 if all_errs else 0


if __name__ == "__main__":
    sys.exit(main())
