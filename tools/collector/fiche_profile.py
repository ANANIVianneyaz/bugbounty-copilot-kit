#!/usr/bin/env python3
"""Affiche la répartition des mots par bloc de prose d'une fiche (diagnostic).

Usage : .venv/bin/python fiche_profile.py <nom-fichier.md> [index-fiche]
index-fiche : rang de la fiche (1 par défaut).
"""
import re
import sys
from pathlib import Path

FICHES = Path(__file__).resolve().parent.parent.parent / \
    "knowledge/writeups/arsenal_2025_2026/fiches_sss"

name = sys.argv[1]
idx = int(sys.argv[2]) if len(sys.argv) > 2 else 1
parts = re.split(r"(?m)^### ", (FICHES / name).read_text(encoding="utf-8"))
fiche = parts[idx]
print(f"### {fiche.split(chr(10))[0]}")
prose = re.sub(r"```.*?```", "", fiche, flags=re.S)
total = 0
for block in re.split(r"\n\n+", prose):
    b = block.strip()
    if not b:
        continue
    n = len(re.findall(r"[\w'À-ÿ]+", b))
    total += n
    if n > 8:
        print(f"  {n:4d}  {b[:75].replace(chr(10), ' / ')}")
print(f"TOTAL {total}")
