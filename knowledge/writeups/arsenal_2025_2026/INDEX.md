# Arsenal 2025-2026 — index général

*Corpus collecté le 2026-10-20 · 1699 entrées 2025-2026 classées en 24 catégories + 6525 entrées historiques (2021-2024).*

## Statistiques

- 2025 : **693** · 2026 : **1006** · sans date : **0**
- Sources : 13

## Catégories

| Catégorie | 2025 | 2026 | sans date | total |
|---|---|---|---|---|
| [Access Control & IDOR](categories/01-access-control-idor.md) | 77 | 105 | 0 | **182** |
| [API & Mobile Security](categories/02-api-mobile.md) | 3 | 11 | 0 | **14** |
| [Auth Bypass — MFA / 2FA / OAuth / Clickjacking](categories/03-auth-bypass.md) | 36 | 17 | 0 | **53** |
| [Business Logic Flaws](categories/04-business-logic.md) | 18 | 39 | 0 | **57** |
| [Cloud Misconfig — AWS / GCP / Azure](categories/05-cloud.md) | 11 | 21 | 0 | **32** |
| [Command Injection](categories/06-command-injection.md) | 3 | 5 | 0 | **8** |
| [Kubernetes & Conteneurs](categories/07-kubernetes.md) | 2 | 1 | 0 | **3** |
| [Cookie Injection / Supercookies](categories/08-cookie-injection.md) | 0 | 3 | 0 | **3** |
| [CVE Deep Dives](categories/09-cve-deep-dives.md) | 216 | 358 | 0 | **574** |
| [Denial of Service](categories/10-dos.md) | 19 | 20 | 0 | **39** |
| [GraphQL](categories/11-graphql.md) | 5 | 5 | 0 | **10** |
| [HTTP Request Smuggling](categories/12-http-smuggling.md) | 4 | 7 | 0 | **11** |
| [Information Disclosure & Credential Leaks](categories/13-info-disclosure.md) | 64 | 51 | 0 | **115** |
| [Injection (SQLi / XXE / Code / Argument)](categories/14-injection.md) | 15 | 35 | 0 | **50** |
| [Memory Corruption](categories/15-memory-corruption.md) | 4 | 17 | 0 | **21** |
| [Open Redirect Chains](categories/16-open-redirect.md) | 7 | 10 | 0 | **17** |
| [Path Traversal](categories/17-path-traversal.md) | 12 | 15 | 0 | **27** |
| [Race Conditions](categories/18-race-condition.md) | 9 | 4 | 0 | **13** |
| [Resource Accounting / Abus de coûts](categories/19-resource-accounting.md) | 5 | 5 | 0 | **10** |
| [SSRF & Cache Attacks](categories/20-ssrf-cache.md) | 18 | 20 | 0 | **38** |
| [SSTI & Désérialisation](categories/21-ssti-deserialization.md) | 4 | 2 | 0 | **6** |
| [Supply Chain — Dependency Confusion, CI/CD](categories/22-supply-chain.md) | 0 | 10 | 0 | **10** |
| [XSS — Reflected to Zero-Click ATO](categories/23-xss.md) | 52 | 79 | 0 | **131** |
| [Misc](categories/24-misc.md) | 109 | 166 | 0 | **275** |

## Sources

| Source | Entrées |
|---|---|
| HackerOne | 1326 |
| Critical Thinking (podcast) | 93 |
| LogicalBreach | 56 |
| YesWeHack | 47 |
| Doyensec | 27 |
| r/bugbounty | 25 |
| PortSwigger Research | 25 |
| Intigriti | 20 |
| Trail of Bits | 20 |
| SonarSource | 20 |
| ProjectDiscovery | 20 |
| Detectify | 10 |
| Infosec Writeups | 10 |

## Contenu du dossier

- `categories/` — le corpus 2025-2026 classé (une page par catégorie, tri date décroissante).
- `fiches_sss/` — **72 fiches détaillées** (cause racine, preuve verbatim, rejouer/exploiter, reproductibilité) au format de `WRITEUP_KB.md`.
- `TOP_EXPLOITABLE.md` — les cas les plus directement rejouables, classés par reproductibilité.
- `HISTORIQUE_2021_2024.md` — index historique compact (pentester.land).
- `SOURCES.md` — liste des sources, leur état, et comment rafraîchir le corpus.

## Rafraîchir le corpus

```bash
cd tools/collector
.venv/bin/python h1_collect.py            # énumère Hacktivity (Selenium)
.venv/bin/python h1_fetch_json.py         # récupère le texte des rapports
.venv/bin/python collect_feeds.py         # flux RSS + sitemaps
.venv/bin/python normalize.py && .venv/bin/python classify.py
.venv/bin/python render_arsenal.py        # régénère ce dossier
```
