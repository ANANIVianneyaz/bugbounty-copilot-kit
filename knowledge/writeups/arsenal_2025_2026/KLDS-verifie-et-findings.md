# KLDS (BugSecure Africa) — Web & API — contrôles vérifiés et findings

*Relevé du 2026-10-20 · programme KLDS (Web & API, MCP hébergé, dépôt `kulinda-sec/bugsecure-mcp`).*

Ce document sert de référence : ce qui a été **prouvé non exploitable** (pour ne pas
re-tester inutilement, et pour répondre au triage) et ce qui constitue un finding.

---

## 1. Finding soumettable

### SSRF non authentifié sur le serveur d'autorisation OAuth (chemin CIMD) — CVSS 5.3 (Medium)

`GET /oauth/authorize?client_id=<URL>` (et `POST /oauth/register` avec `client_uri`) fait
**fetch serveur de l'URL fournie**, sans authentification, sans inscription, depuis l'IP de la
plateforme (`52.214.90.218`, UA `BugSecure-OAuth/1 (+client-id-metadata-document)`), et **analyse la
réponse** (elle construit l'identité du client : `client_id`, `client_name`, `redirect_uris`,
`grant_types`, `scope`) → oracle binaire sur la cible.

Preuve : journal du listener du chercheur (44 requêtes, chemin unique par essai) + capture PNG du
log + 302 verbatim horodatée à la seconde (voir `rapports/`).

Limites **mesurées et documentées** dans le rapport : le filtre d'adresses écarte loopback /
RFC1918 / `169.254.169.254` (y compris via nom DNS `localtest.me`, `127.0.0.1.nip.io`,
IPv4-mapped IPv6, NAT64 local-use `64:ff9b:1::/48`) ; les redirections ne sont pas suivies ; le
certificat TLS est validé (auto-signé refusé).

Escalade possible (non démontrée) : si une ressource de la plateforme ou d'un partenaire autorise
l'IP de sortie `52.214.90.218`, ou si le filtre d'adresses est contournable sur un autre chemin.

---

## 2. Contrôles vérifiés (non exploitables) — ne pas re-tester

### OAuth / AS
| Contrôle | Preuve |
|---|---|
| Consent-injection (rapport déjà accepté) | le correctif lie la demande **à la session** : la page refuse « lancée dans un autre navigateur » |
| CSRF sur le consent | l'API n'authentifie que par `Bearer` (le cookie `bounty-session` ne vaut rien) → pas de CSRF simple |
| Auto-approbation d'agent | `decideAgentApproval` / `decideOAuthAuthorization` → « not available to OAuth clients » |
| Création d'approbation | `createAgentApproval` exige **le scope d'écriture de l'opération** (`profile:write`, `grade:write` refusés) |
| PKCE | `code_challenge_method=S256` obligatoire ; `plain`, absence, malformé → `invalid_request` |
| `redirect_uri` | comparaison **exacte** (slash final, query, fragment, userinfo, sous-domaine, chemin différent, IP littéral → refusés) |
| `scope` / `resource` | non dupliquables (« malformed or repeated ») ; scopes hors périmètre rognés à l'émission (`triage:read` retiré) |
| `response_type` | strictement `code` (`token`, `id_token`, `none`, casse → refusés) |
| `iss` (RFC 9207) | toujours émis par l'AS → pas de mix-up |
| `prompt=none` / `request_uri` | non implémentés (pas de consentement silencieux, pas de fetch RFC 9101) |
| Code d'autorisation | usage unique (« already used ») |
| Refresh token | rotation stricte + **révocation de la famille** en cas de rejeu ; client_id obligatoire ; resource vérifié |
| Token exchange | `unauthorized_client` pour les clients CIMD **et** pour `bugsecure-mcp-cli` |
| `client_credentials` | `unsupported_grant_type` (y compris via un document CIMD) |
| Usurpation de nom de client | refusée **sur les deux** chemins (DCR et CIMD) : `BugSecure`, `BugSecure Africa`, `SSO BugSecure`, `Senintel BugSecure`, `MCP BugSecure officiel`, `bugsecure-mcp` |
| `redirect_uris` non conformes (plateforme, IP littéral, `javascript:`, http non-loopback) | refusés sur les deux chemins |
| CIMD : `scope` hors périmètre | accepté **au niveau client** (filtré seulement à l'émission du token) → écart mineur vs DCR |
| TLS de la ressource distante | certificat auto-signé refusé |
| DCR | `429 rate limit exceeded` après ~10 inscriptions |

### JWT / sessions
| Contrôle | Preuve |
|---|---|
| `jku` / `x5u` / `jwk` embarqué | refusés — l'AS utilise un **JWKS figé** et ne suit pas le `jku` (vérifié via log OOB : aucun fetch) |
| `alg:none`, HS256 (confusion RSA/HMAC) | refusés |
| `epoch` | incrémenté à l'activation du 2FA : le token de session **pré-2FA** est refusé sur les écritures (`updateResearcherProfile`, `requestUploadUrl`, `createAgentApproval`, `requestEmailChange` → « Unauthorized ») |
| Claims contrôlés | `id`, `email`, `username`, `roles`, `epoch`, `iat`, `exp`, `aud`, `iss`, `sub` — `roles` non modifiables (`setUserRoles` refusé, et `ADMIN` n'existe pas dans l'enum `BountyUserRole`) |
| Session fixation | `/api/auth/session/refresh` avec un identifiant arbitraire → 403/401 ; pas de session sans cookie |
| CORS | aucun `Access-Control-Allow-Origin` sur `/graphql`, `/api/auth/session/refresh`, `/oauth/token`, `/oauth/authorize`, `/.well-known/jwks.json` |
| Rate limits | login (captcha Turnstile), `verifyEmail`, `confirmEmailChange`, `removeTotpViaToken`, `exchangeCliSignInCode` → « Rate limit exceeded. Try again in 60 seconds » |

### Autorisation (API GraphQL)
| Contrôle | Preuve |
|---|---|
| Surface admin | `adminUser*`, `adminUsers`, `setUserRoles`, `markEmailVerified` (notre userId **et** celui d'autrui), `resetUserTwoFactor`, `certificate*`, `downloadUrl`, `getOrganizationCertificates` → `Unauthorized` / `OAUTH-BLOCKED` (clients OAuth) / scope requis |
| Certificats (justificatifs de prime) | `certificate(reference:)` répond **`Unauthorized` pour toute référence, y compris inexistante** → pas d'énumération, pas d'IDOR, pas d'oracle |
| `sharedFinding(token:)` | `null` uniforme (12 guesses, authentifié et anonyme) → pas d'oracle |
| Rapports | `report(id:)`, `reportComments`, `reportTransitions`, `reportAdjudication`, `reportAppeals`, `reportDisclosureDraft` → `Unauthorized` pour le chercheur |
| Activité d'autrui | `researcherActivity` → « You can only read your own activity » |
| `researcherStats` | public mais déjà visible sur le profil public ; `totalEarned` = null |
| `myPrograms` / `myInvitedPrograms` / `organizationCertificates` / `programStats` / `checkDuplicates` | « You are not a member of this organization » / scope `triage:read` |
| Upload | clé S3 = `<prefixe>/<uuid>.<ext>` (**le nom de fichier n'entre pas dans le chemin**) ; « fileName must not contain a path separator » → traversal impossible |
| `avatarUrl` | **aucun fetch serveur** (vérifié via log OOB) → pas de SSRF ; rendu client, et la CSP `img-src 'self' data: blob:` bloque de toute façon |
| `website` | validé `http(s)` (`javascript:` / `data:` refusés) |
| `bio` | le HTML brut est stocké **et resservi**, mais rendu en **texte React** (`children:w.bio`) → échappé → pas de XSS ; pas de DOMPurify dans le bundle (sans objet : React échappe) |
| Sprites CSP | `script-src 'self' 'unsafe-inline'`, `frame-ancestors 'none'`, `X-Frame-Options: DENY` → pas de clickjacking |

### Injection
| Contrôle | Preuve |
|---|---|
| SQLi | 5 surfaces (`search` global, `programs.filters.search`, `reports.filters.search`, `leaderboard.*`, `researcherPublicProfile.username`) + **différentiels booléens** (`' AND 1 LIKE 1--` vs `' AND 1 LIKE 2--`, `IS NOT NULL` vs `IS NULL`) → **aucun écart** → paramétré (Prisma) |
| WAF (défense en profondeur, contournable mais **sans impact**) | 3 payloads passent le filtre SQLi (`' OR 1 LIKE 1--`, `'||1=1--`, `1' ORDER BY 1--`) ; 6 encodages de traversée passent (`..%c0%af`, `..%ef%bc%8f`, `..;/`, `..%00/`, `..%c1%9c`, `..%5c`) → **aucun effet** (clé UUID, chemins validés côté app) |
| WAF strict par paramètre | `username`/`slug`/`country`/`timeRange` bloquent la citation ; `search` est lax → c'est une allowlist de Quotes, pas un défaut exploitable |

### Serveur MCP hébergé (`bugsecure-mcp.senintel.sn/mcp`)
| Contrôle | Preuve |
|---|---|
| Sans jeton | 401 + `WWW-Authenticate: Bearer scope=...` (challenge RFC 9728 conforme) |
| Jeton forgé (`aud=MCP`, signature invalide) | « token failed validation » |
| Audience | un jeton `aud=API` est **refusé** → pas de mix-up d'audience |
| Token exchange | le client hosted échange côté serveur ; **l'AS ne broaden pas les scopes** : les outils d'écriture sont refusés (`403 insufficient_scope`, « needs the profile:write permission, which was not granted ») |
| Origin | allowlist stricte : même `https://bugsecure.senintel.sn` → 403 « Origin not allowed » |
| Surface HTTP | seul `POST /mcp` ; `GET`/`PUT`/`DELETE` → 405 ; chemins voisins → 404 |
| `tools/list` | **non filtré par les scopes** (les 33 outils, dont les 10 d'écriture, sont annoncés à un jeton en lecture seule) → divulgation mineure, sans impact (chaque appel est refusé) |
| Repo `kulinda-sec/bugsecure-mcp` | **chaque mutation déclarée dans le `payload` soumis à l'approbation** ; les seuls `graphql.request` hors payload sont des lectures → aucune write n'échappe à l'approbation humaine ; `get_org_report` s'appuie sur l'API (qui refuse hors org) |

### Web app (Next.js) / infrastructure
| Contrôle | Preuve |
|---|---|
| `/_next/image` | **pas un SSRF** : « "url" parameter is not allowed » (allowlist), `file://` invalide, IP internes bloquées par le WAF, **0 fetch** dans le log OOB |
| Serveur Actions | aucun `action` id dans le HTML, aucun `createServerReference` dans les chunks |
| Source maps / specs | `*.map` → 404 ; `/api/docs`, `/swagger`, `/openapi.json` → 404 |
| Host header | `Host: evil.example` → 301 vers le vhost par défaut ; `X-Forwarded-Host` sans effet ; `redirect_uri` inchangé → pas de poisoning |
| Bucket S3 des uploads | `AccessDenied` sur le listage et sur tous les préfixes testés |
| `bugsecure-files` (CloudFront) | URLs signées (`Missing Key-Pair-Id`) |
| PostHog (analytics) | auto-hébergé derrière `/ingest` ; API de lecture `401/403` ; `maskAllInputs: true`, `streamNetworkBody: false`, en-têtes et clés sensibles masqués ; le sanitizer d'URL couvre 7 chemins + `/oauth` + `*/callback` + 14 params (les codes OAuth déjà signalés sont bien masqués) |
| Sous-domaines | `staging/beta/dev/…` résolvent (wildcard ELB) mais **ne répondent pas** → pas d'instance de staging |
| Health endpoint | `/api/health` fuit `uptime`/`memory`/`environment` → **hors périmètre** (pas d'impact) |

---

## 3. Restes à tester (il faut une action du chercheur)

1. **Bypass MFA (seul High potentiel restant)** — la réponse JSON de la mutation `login` (avec captcha)
   alors que le 2FA est actif : vérifier si le `accessToken` **émis avant la validation du code TOTP**
   est utilisable. Le token de *session* pré-2FA est déjà refusé partout (epoch), mais le token
   retourné par `login` avant le challenge est une autre emitter.
2. **Entropie des tokens par email** (reset de mot de passe, suppression du 2FA, invitation) —
   l'API refuse les adresses jetables (`Disposable email addresses are not accepted`) → il faut une
   adresse **non jetable** lisible par le chercheur.
3. **IDOR inter-comptes** — il faut un 2e compte de test (le contrôle des références de certificat
   est propre, mais un 2e compte permettrait de tester `report(id:)` / `reportComments` entre comptes).

## 4. Leçons réutilisables (pour d'autres programmes)

- Le chemin **CIMD** (`client_id` = URL) est un SSRF natif de tout AS OAuth 2.1 qui l'implémente :
  tester `client_id=<URL>` avant tout, et le log OOB (webhook.site) est la preuve la plus solide.
- Un AS bien conçu **ne suit pas** l'en-tête `jku` : le `client_id`-URL, lui, est un fetch à part
  entière → c'est là que le SSRF se cache.
- Différencier les erreurs : un AS qui répond `Unauthorized` uniformément (au lieu de 404/not found)
  supprime l'oracle d'énumération — c'est la bonne pratique, et ça se vérifie en trois requêtes.
- Le `streamNetworkBody: false` + `maskAllInputs: true` du recorder PostHog neutralise le risque
  « mot de passe / code 2FA dans l'analytics » : vérifier ces deux drapeaux avant de rapporter.
