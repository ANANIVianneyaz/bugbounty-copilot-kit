#!/usr/bin/env python3
"""Longueur des fiches SSS (prose hors blocs de code) + seuil du gabarit.

Usage : .venv/bin/python count_fiches.py [seuil]
Sort la liste des fiches au-dessus du seuil (400 par défaut) et une synthèse.
"""
import re
import sys
from pathlib import Path

SEUIL = int(sys.argv[1]) if len(sys.argv) > 1 else 400
FICHES = Path(__file__).resolve().parent.parent.parent / \
    "knowledge/writeups/arsenal_2025_2026/fiches_sss"

rows = []
for path in sorted(FICHES.glob("*.md")):
    for fiche in re.split(r"(?m)^### ", path.read_text(encoding="utf-8"))[1:]:
        prose = re.sub(r"```.*?```", "", fiche, flags=re.S)
        words = len(re.findall(r"[\w'À-ÿ]+", prose))
        rows.append((words, path.name, fiche.split("\n")[0]))

over = [r for r in rows if r[0] > SEUIL]
print(f"seuil {SEUIL} : {len(over)}/{len(rows)} fiches au-dessus")
for w, f, t in sorted(over, reverse=True):
    print(f"  {w:4d}  {f:28s} {t[:55]}")
if rows:
    ws = sorted(r[0] for r in rows)
    print(f"médiane {ws[len(ws)//2]} · min {ws[0]} · max {ws[-1]}")
