# Index de WRITEUP_KB.md (215 cas réels, 24 catégories, 8 634 lignes)

> **Corpus 2025-2026 : voir `arsenal_2025_2026/INDEX.md`** — index complet des
> writeups récents classés dans les mêmes 24 catégories, + fiches détaillées SSS.

**Lire d'abord** `EXPERT_METHODOLOGY.md` (282 lignes, entier) — ce n'est pas un
catalogue de plus, c'est ce qui enseigne COMMENT regarder une fonctionnalité
inconnue et en tirer des hypothèses. Le corpus ci-dessous sert ensuite de
banque d'exemples déjà résolus.

Pour lire UNE SEULE catégorie de `WRITEUP_KB.md` sans tout charger :

```bash
sed -n 'START,ENDp' knowledge/writeups/WRITEUP_KB.md
```

| Catégorie | Lignes |
|---|---|
| Access Control & IDOR (28 cas) | 9-1344 |
| API & Mobile Security | 1345-1803 |
| Auth Bypass — MFA / 2FA / OAuth / Clickjacking | 1804-2614 |
| Business Logic Flaws | 2615-3190 |
| Cloud Misconfig — AWS / GCP / Azure | 3191-3393 |
| Command Injection | 3394-3449 |
| Kubernetes & Conteneurs — Escape, RBAC, Supply Chain | 3450-3822 |
| Cookie Injection / Supercookies | 3823-3856 |
| CVE Deep Dives (curl, libcurl, misc) | 3857-4855 |
| Denial of Service | 4856-4906 |
| GraphQL — Introspection, Batching, DoS | 4907-5287 |
| HTTP Request Smuggling — Techniques Avancées | 5288-5553 |
| Information Disclosure & Credential Leaks | 5554-5882 |
| Injection (SQLi / XXE / Code / Argument) | 5883-6112 |
| Memory Corruption | 6113-6177 |
| meta | 6178-6217 |
| Open Redirect Chains | 6218-6373 |
| Path Traversal | 6374-6477 |
| Race Conditions — TOCTOU, Single-Packet Attack | 6478-6845 |
| Resource Accounting / DoS | 6846-6887 |
| SSRF & Cache Attacks | 6888-7720 |
| SSTI & Désérialisation Non Sécurisée | 7721-8075 |
| Supply Chain — Dependency Confusion, CI/CD | 8076-8182 |
| XSS — Reflected to Zero-Click ATO | 8183-8634 |
