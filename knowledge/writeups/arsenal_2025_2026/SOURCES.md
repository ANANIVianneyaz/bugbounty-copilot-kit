# Sources du corpus — état et rafraîchissement

| Source | Type | Collecte | État vérifié le 2026-10-18 |
|---|---|---|---|
| HackerOne Hacktivity (divulgués) | rapports + texte intégral | Selenium + `.json` par rapport | ✅ actif |
| LogicalBreach Academy | writeups | sitemap `writeups/` | ✅ actif |
| YesWeHack `/news/` | writeups/news | server-sitemap | ✅ actif |
| Critical Thinking (podcast) | veille hebdo (liens dans les notes) | RSS | ✅ actif |
| Intigriti Blog | recherche + writeups | RSS (20 derniers) | ✅ actif |
| Infosec Writeups | writeups communauté | RSS (10 derniers) | ⚠️ cadence ralentie |
| PortSwigger Research | recherche | RSS | ✅ actif |
| Trail of Bits / Doyensec / SonarSource / ProjectDiscovery / Detectify | labs | RSS | ✅ actifs |
| r/bugbounty · r/netsec | communauté | RSS | ✅ actifs |
| pentester.land | agrégateur (gelé fin 2024) | JSON complet | 🧊 historique seulement |
| Assetnote | lab | feed gelé janv. 2024 | ❌ ignoré |
| securitybreached.org | devenu blog perso (SPA) | — | ❌ ignoré |

## Notes de politesse et limites

- Requêtes espacées (1,5-3 s par page Hacktivity, ~5 req/s max sur les `.json`).
- Les flux RSS ne remontent que leurs N derniers items (10-30 selon la source) ; l'historique profond vient de Hacktivity et de pentester.land.
- Les dates Hacktivity sont relatives sur les cartes ; la date exacte vient du `.json` du rapport.
