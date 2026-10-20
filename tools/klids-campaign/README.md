# Outils de la campagne KLDS (BugSecure Africa) — 2026-10-20

Scripts écrits pour cette campagne, réutilisables sur d'autres programmes.

| Script | Rôle |
|---|---|
| `sweep.mjs` | Balayage « auto-correctif » des opérations GraphQL : à partir des messages d'erreur de l'API (champ inconnu, champ requis manquant, type d'entrée erroné, valeur d'enum invalide), la requête est corrigée et rejouée jusqu'à obtenir une réponse d'autorisation exploitable. 3 profils : `AUTH=0` (public), `AUTH=1` (jeton Bearer). Variables : `BB_TOKEN`, `OUT`, `LIMIT`. Nécessite `schema.graphql` (schéma du dépôt MCP) et `allops.txt` (opérations extraites du bundle). |
| `gqlgen.mjs` | Extrait le texte GraphQL d'une opération depuis le bundle web minifié (le nom de l'opération suffit). |
| `otp-only.mjs` | Patterns MFA 2/3/4 : code manifestement faux, oracle de préfixe (10⁶ → ~60 requêtes), budget de tentatives, rejeu du challenge. Variable : `CHALLENGE`. |
| `reset-analysis.mjs` | Entropie d'un token par email (longueur, alphabet, espace de recherche) — **non destructif**. Variable : `RESET_LINK`. |
| `cimd.mjs` / `cimd2.mjs` / `cimd3.mjs` | Chemin CIMD : publication d'un document de metadata client sur un service tiers, attribution du fetch serveur (UA + IP source), taxonomie d'erreurs (oracle de contenu), validation du document. |
| `ssrf-attr.mjs` / `ssrf-proof.mjs` / `ssrf-portscan.mjs` / `dns-bypass.mjs` | SSRF : attribution du fetch, périmètre réseau (min/médiane de N échantillons), contournements de filtre (NAT64, IPv4-mapped, nom DNS, parser differential, redirections). |
| `mfa-test.mjs` | `challengeToken` comme jeton d'accès (bypass MFA), mutations 2FA, surface admin. |
| `mcp-token.mjs` / `mcp2.mjs` | Serveur MCP hébergé : inventaire des outils selon les scopes, appels réels, `tools/list` non filtré. |
| `waf-map.mjs` / `waf-matrix.sh` | Cartographie des règles WAF et ~30 contournements (encodages, variantes de parseur, vecteurs de transport, DNS/IP). |
| `cert-enum2.mjs` | Énumération de références de certificat (vérifie le contrôle de propriété). |

Méthode : **ne jamais conclure d'un `403`/`Forbidden`** → un contrôle est « validé » quand on a une
**mesure** (oracle, latence, capture OOB, message d'erreur discriminant) qui prouve l'absence d'impact.
