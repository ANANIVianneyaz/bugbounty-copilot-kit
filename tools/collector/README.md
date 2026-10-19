# Collecteur de l'arsenal 2025-2026

Pipeline de collecte, classement et rendu du corpus de writeups bug bounty
(voir le résultat dans `knowledge/writeups/arsenal_2025_2026/`).

## Installation

```bash
cd tools/collector
python3 -m venv .venv
.venv/bin/pip install feedparser beautifulsoup4 lxml requests selenium
```

## Pipeline (ordre d'exécution)

```bash
.venv/bin/python h1_collect.py            # 1. énumère Hacktivity (Selenium headless)
.venv/bin/python h1_fetch_json.py         # 2. récupère le .json par rapport (texte intégral)
.venv/bin/python collect_feeds.py         # 3. flux RSS/Atom + sitemaps
.venv/bin/python fetch_static.py          # 4. pages SPA : fetch statique + extraction du payload SSR
                                          #    (render_pages.py existe aussi pour les pages qui exigent un vrai navigateur)
.venv/bin/python enrich_pages.py          # 5. titre/date/résumé des pages fetchées
.venv/bin/python normalize.py             # 6. fusion + dédoublonnage -> data/arsenal.jsonl
.venv/bin/python classify.py              # 7. classement dans les 24 catégories du kit
.venv/bin/python render_arsenal.py        # 8. génère le Markdown dans knowledge/writeups/arsenal_2025_2026/
.venv/bin/python select_fiches.py         # 9. sélection + squelettes des fiches SSS
.venv/bin/python top_exploitable.py       # 10. TOP_EXPLOITABLE.md (cas triés par reproductibilité)
.venv/bin/python verify_fiches.py         # 11. contrôle qualité : structure + verbatim des 72 fiches
```

`verify_fiches.py` compare chaque ligne substantielle (≥ 25 car.) des blocs de code
des fiches au texte source correspondant (`.json` H1 + `summaries` + writeups externes
déclarés dans `EXTRA_SOURCES`) ; code de sortie non nul si écart. Il sert aussi de
test de non-régression : une ligne fabriquée dans une fiche fait échouer le contrôle.

## Conventions et garde-fous

- **Reprise** : chaque étape est rerunnable ; les états sont dans `data/` (ex. `h1_collect_state.json`).
- **Politesse** : délais entre requêtes (1,5-3 s Hacktivity, ~5 req/s max côté `.json`).
- **Données brutes** : `data/` n'est pas commité (`.gitignore`) — seuls le Markdown rendu et les scripts le sont.
- **Périmètre** : rapports publics/divulgués uniquement, rien de privé ni de contournement d'authentification.
- **Dates H1** : les cartes Hacktivity affichent des dates relatives ; les dates exactes viennent du `.json`.

## Ajouter une source

- Flux RSS/Atom → ajouter à `FEEDS` ou `FEED_CANDIDATES` dans `collect_feeds.py`.
- Sitemap → ajouter à `SITEMAPS` (avec un prédicat sur les URLs).
- Page JS → ajouter à `data/render_targets.jsonl` puis `render_pages.py`.
