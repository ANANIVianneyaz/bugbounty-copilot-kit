# Archives brutes de la campagne KLDS (2026-10-19 → 2026-10-20)

Sorties consoles des scripts de `tools/klids-campaign/`. Elles constituent la **matrice de preuve**
opposable : chaque ligne de la note de validation (`KLDS-verifie-et-findings.md`) renvoie à un de ces
journaux.

| Fichier | Contenu | Contrôles validés |
|---|---|---|
| `waf-matrix.out`, `waf-map.out` | 30+ variantes de contournement WAF (encodages, parseur, transport, DNS/IP) | WAF contournable **mais sans impact** |
| `sqli.out`, `sqli-blind.out` | différentiels booléens sur 5 surfaces | SQLi : paramétré |
| `cimd.out`, `cimd2.out`, `cimd3.out` | fetch serveur CIMD, oracle de contenu, taxonomie d'erreurs | **le finding** + validation du document |
| `ssrf-attr.out`, `ssrf-proof.out`, `ssrf-portscan.out`, `dns-bypass.out` | attribution du fetch, périmètre réseau (min/médiane), contournements d'IP | filtre d'IP efficace, redirections non suivies |
| `webhook-requests-source-IP.json` | journal brut du service tiers : **IP source `52.214.90.218`** + UA du serveur d'autorisation | preuve principale du finding |
| `mfa-test.out`, `otp-only.out`, `2fa-redteam.out` | challengeToken comme jeton, code faux, oracle de préfixe, budget, rejeu | MFA close (7 patterns) |
| `cert-enum2.out`, `cert2.out`, `cert3.out`, `shared2.out` | énumération de références de certificat, `sharedFinding` | pas d'IDOR, pas d'oracle |
| `upload-chain.out`, `upload-web2.out` | 24 variantes de nom de fichier d'upload | clé UUID serveur, traversal impossible |
| `report-own2.out`, `whoown.out` | accès aux données de triage sur un rapport réel | refus `Unauthorized` |
| `mcp-probe.out`, `mcp2.out`, `mcp-token.out`, `mcp-escalation.out` | serveur MCP : audience, Origin, inventaire, scopes | surface MCP propre (scope filtré par appel) |
| `nextjs-probe.out`, `storage-probe.out`, `open-redirect2.out` | `/_next/image`, bucket S3, CORS, host-header, open redirect | pas de SSRF image, pas de fuite |
| `enum.out`, `reset-live.out`, `reset-analysis.out` | `forgotPassword`, reset de mot de passe, entropie du token | token 256 bits, captcha + rate-limit |
| `discord2.out` | intégration Discord : state JWT, callback | state unique, taxonomie uniforme |
| `sweep-auth.json`, `sweep-public.json`, `sweep-web.json` | **cartes d'autorisation complètes** (198 opérations, 3 profils) | la surface complète de l'API |

Note : les jetons et cookies **ne sont pas** archivés ici (ils sont expirés/révoqués) ; seuls les
résultats et les mesures le sont.

## Ajout 21/10/2026 — surface non authentifiée + analytics (P6 clos)

| Fichier | Contenu |
|---|---|
| `unauth-probe.json` | 67 requêtes : 39 routes `/api/*` de l'app, introspection GraphQL (désactivée), 8 variantes de traversée sur `/ingest`, métadonnées MCP/AS, `POST /mcp` sans jeton |
| `posthog-read.mjs` (dans `tools/klids-campaign/`) | 39 endpoints de l'API de lecture PostHog sous `/ingest` — tous 401/403 |
| `ph2.mjs` (idem) | corps bruts de `/ingest/flags?v=2` et `/ingest/decide?v=3` (publics, `flags:{}`), + 24 routes admin PostHog |
| `hdr.mjs` (idem) | en-têtes HTTP complets : `WWW-Authenticate` du serveur MCP, CSP, `/api/health`, métadonnées de ressource |
| `catcher4.cjs` (idem) | gestionnaire de grant OAuth multi-ressources (le RT est stocké par ressource) |
