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

**Position du filtre d'adresses (distribution, 8 échantillons/cible) :** les cibles internes sont
refusées **avant l'émission du paquet** — `127.0.0.1:3000` min 88 ms / max 101 ms, `127.0.0.1:53682` min 85 / max 124,
`169.254.169.254` min 89 / max 98, `10.255.255.1` min 88 / max 156, contre un témoin non routable
`192.0.2.1` min 82 / max 102 et un témoin **externe** (qui effectue réellement le fetch) min 173 / max 375.
→ les cibles internes sont statistiquement indiscernables du refus immédiat, et plus rapides que le fetch réel.

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
| CIMD : `scope` **demandé dans la requête** | **validé à l'identique du DCR** : `admin:all` et `profiles:write` → refusés (« scope contains unsupported values ») ; `triage:read/write`, `grade:write` acceptés (ce sont des scopes de la plateforme) ; le `scope` du *document* distant est **inutilisé** → **pas d'escalade** (affirmation retirée après test) |
| TLS de la ressource distante | certificat auto-signé refusé |
| DCR | `429 rate limit exceeded` après ~10 inscriptions |

### JWT / sessions
| Contrôle | Preuve |
|---|---|
| `jku` / `x5u` / `jwk` embarqué | refusés — l'AS utilise un **JWKS figé** et ne suit pas le `jku` (vérifié via log OOB : aucun fetch) |
| `alg:none`, HS256 (confusion RSA/HMAC) | refusés |
| `epoch` | **vérifié comme le mécanisme du correctif « password reset »** : il passe de `0` à `1` sur le jeton émis après un changement de mot de passe (mesuré), et les jetons émis avant (epoch `0`) sont rejetés par l'API (« Session ended »). Les 7 jetons observés avant le reset portaient tous `epoch: 0` (aucun changement de mot de passe avant) ; l'epoch n'est donc **pas** décoratif |
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

## 2bis. MFA / 2FA — les 7 patterns du kit, tous vérifiés

| # | Pattern (`hunt-mfa-bypass`) | Résultat mesuré |
|---|---|---|
| 1 | Saut de l'étape MFA (jeton pré-MFA sur une ressource protégée) | **CLOS** — la réponse de `login` est `{"accessToken":null,"refreshToken":null,"requiresTwoFactor":true,"challengeToken":"<JWT>","user":null}` : **aucun jeton avant la 2FA**. Et une session **non vérifiée 2FA** (via `/api/auth/session/refresh`) est refusée sur tout le contenu sensible : le sweep des 198 opérations n'y renvoie que `BountyMe` (identité propre), `certificateSigningKeys` (clés publiques), `confirmEmailChange` (no-op), `dismissOnboarding` (flag d'UI) et `discordLinkedRolesUrl` (lien d'intégration) |
| 1b | Le `challengeToken` sert-il de jeton d'accès ? | **NON** — testé comme `Bearer` sur `me`, `reports`, `myKycStatus` et une écriture → tous « Unauthorized » (audience `mfa-challenge` appliquée) |
| 1c | Downgrade via le flux device-code (CLI) | **CLOS** — `createCliSignInCode` exige une session 2FA-vérifiée |
| 2 | Rejeu de l'OTP | sans effet (le challenge survit aux échecs) |
| 3 | Code manifestement faux | message **uniforme** (« Invalid or expired challenge token ») → aucun oracle sur le code |
| 4 | Oracle de préfixe (10⁶ → ~60 requêtes) | **AUCUN** — 20 préfixes testés : 2 messages distincts (format / rate-limit) et **latences plates 31-40 ms** |
| 5 | Race sur la validation | non exploitable (le rate-limit s'applique avant) |
| 6 | Dump des codes de secours via `/me` | **CLOS** — `me` ne renvoie que `id/email/username/roles/status/kycStatus/twoFactorEnabled/hasAuthenticatorApp` ; les codes de secours sont **8 caractères** (36⁸ / 10⁸ → non brutables) |
| 7 | Downgrade de facteur (SMS) | sans objet : TOTP + email uniquement |

Budget mesuré : **rate-limit après ~3-4 tentatives / 60 s** sur `verify2fa` → 10⁶ combinaisons = plusieurs années sur une IP, donc non brutable.

Claims du `challengeToken` (JWT signé, 5 min) : `id` (user), `requires2fa:true`, `jti` (clé du challenge côté serveur), `epoch`, `aud:"mfa-challenge"`, `iss`, `sub:"klds-bug-bounty-api"`.

Intégration Discord (piste annexe, non protégée par la 2FA) : `discordLinkedRolesUrl` est accessible sans 2FA et renvoie une URL Discord OAuth dont le `state` est un **JWT signé** unique par appel (donc pas de CSRF sur le state) ; le callback `GET /api/discord/linked-roles/callback` répond `302 → /researcher/settings/account?discord=error` pour tout code invalide (taxonomie uniforme, aucune fuite) ; `unlinkDiscord` est accessible (no-op sur un compte non lié).

### Filtre anti-usurpation d'identité de client — vérifié robuste

| Voie | Variantes testées | Résultat |
|---|---|---|
| DCR (`client_name`) | 10 : `BugSecureX`, `XBugSecure`, `)BugSecure(`, espaces (initial/final/interne), casse mélée, majuscules, trait d'union, underscore | **toutes refusées** (`invalid_client_metadata`) → le filtre n'est pas une recherche de sous-chaîne |
| DCR (reste) | 18 variantes de confusables Unicode | **non testées** : bloquées par le quota d'inscription DCR (`429 temporarily_unavailable`) |
| **CIMD (chemin sans quota)** | 22 : point, domaine, cyrillique (initiale/médiane/finale), accents, zero-width (initial/median), insécable, bidi RLO/PDF (initial/final), soft hyphen, BOM, turc `ı`, ZWJ, signe moins, espace em, « Bug Secure Africa » | **toutes refusées** (`invalid_client`) |

→ le filtre **normalise l'Unicode** et refuse aussi bien les homoglyphes que les caractères invisibles.
Effet de bord exploitable pour l'audit : le chemin CIMD, **sans quota**, permet de tester le filtre au-delà
du quota du chemin DCR.

 de faible impact (non rapportables)

`organizationStanding` renvoie un objet par défaut (zéros/null) à un non-membre au lieu d'une erreur ·
`programs(filters:{visibility:PRIVATE})` ignore le filtre (bug fonctionnel, aucun programme privé exposé) ·
`search` global renvoie `[]` pour toute requête · `report(id:)` refuse même le rapport du chercheur (le
détail est réservé à l'organisation) · `removeTotpViaToken` est joignable sans session (le token émis par
email est le seul facteur, 256 bits) · `authorization_details`/`audience` ignorés par l'AS · `clientDigest`
plafonné à 43 caractères (SHA-256 base64url, condensat non secret) · `userId` interne exposé par le profil
public (déjà public via le leaderboard) · captcha login/reset = Turnstile + Private Access Token (lié au
navigateur) · `bugsecure-files` = URLs signées CloudFront.

## 2ter. Surface NON authentifiée + analytics (PostHog) — contrôles du 21/10

Aucun jeton n'était disponible (le refresh token du catcher a été **révoqué par le reset de mot de
passe** → comportement *correct* du correctif `epoch`) : ces contrôles ont donc été faits **entièrement
sans authentification**, ce qui est le périmètre le plus sensible.

### 2ter.a — API de lecture de l'analytics (PostHog auto-hébergé) → **PROTÉGÉE, non exploitable**

Le proxy `/ingest` relaie **toute** l'API PostHog sur le **domaine de l'app** (`bugsecure.senintel.sn`).
39 endpoints sondés (read API, admin, organizations, users, personal_api_keys, session_recordings,
insights, query, activity, dashboards, batch_exports, event_definitions, tags, share routes) :

| Endpoint sondé | Réponse | Lecture |
|---|---|---|
| `/ingest/api/projects/<phc…>/events` | **401** `authentication_error / not_authenticated` | protégé |
| `/ingest/api/projects/<phc…>/insights` | **403** idem | protégé |
| `/ingest/api/projects/<phc…>/query` (HogQL) | **403** idem | protégé |
| `/ingest/api/projects/<phc…>/session_recordings` | **401** | protégé |
| `/ingest/api/projects/<phc…>/activity`, `/persons`, `/surveys`, `/cohorts`, `/dashboards`, `/experiments`, `/feature_flags`, `/tags`, `/batch_exports`, `/event_definitions` | **401** | protégés |
| `/ingest/api/users`, `/ingest/api/organizations`, `/ingest/api/personal_api_keys` | **401** | protégés |
| `/ingest/api/login` | 405 (POST) | inchangé |
| `/ingest/decide?v=3`, `/ingest/flags?v=2` | **200**, `flags:{}`, `sessionRecording:false`, `config.enable_collect_everything:true` | endpoint public **par design** (client-side), ne retourne **aucun** flag ni donnée |
| `/ingest/batch`, `/ingest/capture`, `/ingest/i/v0/e/` | 400 « request missing data payload » | ingestion publique par design |

**Clôture** : la piste « fuite des sessions / PII via l'API de lecture » est **fermée**. Le proxy ne
laisse passer aucun endpoint de lecture sans authentification, et un faux `Authorization: Bearer phx_…`
ne change rien (401/403 identiques). Le bundle web ne contient **aucune clé personnelle** (`grep phx_`
sur le bundle → 0 occurrence) ; `api_host:"/ingest"` (same-origin) et `ui_host` par défaut
(`https://eu.posthog.com`) → l'instance est **auto-hébergée**, les données ne quittent pas la plateforme.
→ **Ce n'est donc pas une fuite « vers un tiers »** : la piste était mal cadrée, elle est close.

### 2ter.b — Traversée de chemin sur le proxy `/ingest` → **négative**

`/ingest/../api/…`, `/ingest/%2e%2e/api/…`, `/ingest/..%2f..%2fapi/` (400 Bad Request), `/ingest;/api/projects`,
`/ingest//api/projects` (308 → `/ingest/api/projects`), `/ingest/api/projects/../users` (401 PostHog) :
**aucune** échappement vers l'app ni vers l'admin PostHog. Le proxy normalise.

### 2ter.c — Serveur MCP hébergé → **conforme à la spec MCP**

| Contrôle | Résultat |
|---|---|
| `POST /mcp` sans jeton | **401** + `WWW-Authenticate: Bearer scope="programs:read profile:read reports:read reports:write triage:read triage:write grade:write profile:write disclosures:write", resource_metadata="https://bugsecure-mcp.senintel.sn/.well-known/oauth-protected-resource/mcp"` → **conforme** (MCP 2025-06-18 exige le `WWW-Authenticate` avec `resource_metadata`) |
| `POST /mcp` avec jeton bidon | **401** `error="invalid_token", error_description="token failed validation"` + même `WWW-Authenticate` |
| `/.well-known/oauth-protected-resource/mcp` | **200** `resource`, `authorization_servers:[https://bugsecure-api.senintel.sn]`, `scopes_supported`, `bearer_methods_supported` |
| `/.well-known/oauth-protected-resource` (racine) | 404 (le chemin canonique avec le suffixe `/mcp` est correct) |
| `GET /mcp` | 405 `method_not_allowed` |

### 2ter.d — API GraphQL : introspection **désactivée**

`{ __schema { … } }` sans jeton → 400 « *GraphQL introspection is not allowed by Apollo Server, but the
query contained __schema or __type* ». Pas d'énumération du schéma à distance.

### 2ter.e — Routes `/api/*` de l'app web (39 sondées) → **une seule existe**

`/api/health` → **200** `{"status":"ok","service":"bug-bounty-frontend","timestamp":"…","uptime":155767.9,
"memory":{"used":82,"total":92},"environment":"production"}` → **divulgation mineure** (uptime, taille du
tas, environnement). Les 38 autres (`/api/auth/session/refresh` inclus, `/api/upload`, `/api/webhook`,
`/api/graphql`, `/api/admin`, `/api/session`, …) → 404. `/metrics` → 404 sur l'app et sur l'API.

### 2ter.f — Contrefaçon de jeton sur le serveur MCP : message discriminant

Un jeton au format valide mais signature invalide → 401 `invalid_token` (« *token failed validation* »)
alors qu'une absence de jeton → 401 `unauthorized` : les deux cas sont distinguables, mais **aucun** ne
révèle d'information (ni l'existence d'une clé, ni l'audience attendue, ni un jeton valide).
→ Le contrôle « audience du serveur MCP » (un jeton `aud=bugsecure-api.senintel.sn` accepté par
`/mcp` ?) reste **à tester** : il exige un jeton OAuth vivant (P2/§3).


## 2quinquies. Nouveaux contrôles du 21/10 (après les deux revues croisées) — 7 angles ouverts, 6 clos

Contexte : le 2FA et le mot de passe du compte de test ont été changés → les refresh tokens OAuth ont été
révoqués par le vendor (**comportement correct**, voir §Invalidation) et le `login` API exige désormais une
vérification humaine. Les contrôles ci-dessous ont donc été faits **sans jeton** ou **avec un jeton
re-créé** ; les blocages restants sont listés explicitement.

### 2quinquies.a — `removeTotpViaToken` : un oracle AVEUGLE, NON AUTHENTIFIÉ, sans validation de forme  ★ piste ouverte

La mutation `removeTotpViaToken(token: String!)` s'appelle **sans aucune authentification** et renvoie un
**booléen** (`{"removeTotpViaToken": false}`) — contrairement à `disableTotp`, `generateBackupCodes`,
`generateTotpSecret`, `acceptOrganizationInvitation` qui répondent `Unauthorized`.

| Forme de token testée (16) | Réponse | Latence |
|---|---|---|
| vide, `A`, `123456`, `12345678`, `1234567890` | `false` | 218-238 ms |
| 16 / 32 / 64 hex, 64 × `g` (hors hex), 64 majuscules | `false` | 206-242 ms |
| base64url 43, `aaaa.bbbb.cccc`, UUID, espaces, 200 caractères | `false` | 219-268 ms |

→ **aucune validation de longueur ni de charset** : le token peut être n'importe quelle chaîne. Le seul
signal est le booléen. **Pas d'oracle temporel** (latences 206-268 ms, aucun écart entre formes).

**Rate-limit mesuré (et il est PAR IP)** — 2 mesures simultanées, 2 IP distinctes :

| Mesure | IP locale | IP contabo |
|---|---|---|
| 1ʳᵉ appel refusé | n°6 | n°6 |
| appels OK après 65 s | **5 / 8** | **5 / 8** |
| même token re-testé | toujours refusé | toujours refusé |

→ le quota est de **~5 essais / 60 s par IP** (les deux IP ont obtenu leur plein quota en parallèle →
ce n'est pas un quota global) ; le compteur n'est pas remis à zéro par un nouveau token.

**Pourquoi c'est important** : la seule barrière à la désactivation du 2FA d'un compte tiers est
l'**entropie du token envoyé par email**. Avec 5 essais/min/IP, un code à 6 chiffres = 10⁶ essais ≈
200 000 min ≈ **139 jours par IP** (≈ 14 jours avec 10 IP) ; un code à 4 chiffres = **33 h par IP** ;
un code à 8 caractères hexadécimaux = 4,3·10⁸ essais = **inaudible**. → **la longueur du token est
décisive** et je ne peux pas la déduire sans un échantillon (blocage : l'email du 2FA que le chercheur
vient de déclencher). *Piste la plus vivante de la campagne.*

Autres mutations à token non authentifiées, mesurées :

| Mutation | Réponse sans jeton | Lecture |
|---|---|---|
| `verifyEmail` | `{"verifyEmail":"INVALID"}` (enum) | oracle de statut, non authentifié |
| `confirmEmailChange` | `false` | non authentifié |
| `exchangeCliSignInCode` | « Invalid or expired sign-in code » | non authentifié |
| `resetPassword` | contrôle d'abord la **longueur du mot de passe** (« 8 to 72 characters »), puis le token | non authentifié (attendu) |
| `forgotPassword` | « **Human verification failed** » | protégé par une vérification humaine (Turnstile) |
| `login` | « **Human verification failed** » | le mot de passe ne suffit pas : vérification humaine exigée |
| `disableTotp` / `generateBackupCodes` / `generateTotpSecret` | `Unauthorized` | authentifiés |
| `acceptOrganizationInvitation` | `Unauthorized` | authentifié |

### 2quinquies.b — `jwks_uri` de second ordre (SSRF) → **CLOS : le mécanisme n'existe pas** ★

Hypothèse : le document CIMD peut déclarer un `jwks_uri` ; si l'AS le fetch au moment de valider une
assertion `private_key_jwt`, ce serait une SSRF de second ordre (filtre IP différent) **et** une
primitive d'usurpation de client (je fournis la clé publique).

| Document CIMD | Résultat |
|---|---|
| `token_endpoint_auth_method: none` (témoin) | **accepté** → page de consentement |
| `token_endpoint_auth_method: private_key_jwt` **avec** `jwks_uri` valide | **rejeté** → `invalid_client` |
| `token_endpoint_auth_method: private_key_jwt` **sans** `jwks_uri` | **rejeté** → `invalid_client` |
| `token_endpoint_auth_method: none` + `jwks_uri` = `http://169.254.169.254/…` | **accepté** (consentement) |
| `token_endpoint_auth_method: none` + `jwks_uri` = `http://10.255.255.1/…` / `http://localhost:8099/…` / `http://127.0.0.1:1/…` | **acceptés** |

→ **`private_key_jwt` n'est pas supporté** : l'AS rejette le document, n'enregistre pas le client
(« unknown client » au `/oauth/token`) et **ne fetch jamais de `jwks_uri`** (0 requête reçue par mon
serveur pendant 11 appels au `/oauth/token`, dans 5 configurations). → **pas de SSRF de second ordre,
pas d'usurpation de client par clé.** Réserve : un document portant un `jwks_uri` **interne** est
*accepté* (le champ est lu mais pas validé) — sans effet tant que `private_key_jwt` n'est pas implémenté.

### 2quinquies.c — Fédération / alias / batching / GET GraphQL → **CLOS**

| Test | Résultat | Lecture |
|---|---|---|
| `{ _service { sdl } }` | « Cannot query field "_service" on type "Query" » | **l'API n'est pas fédérée** (pas de bypass `_entities`) |
| `{ _entities(representations:[…]) }` | « Cannot query field "_entities" » + « Unknown type "User" » | idem |
| alias multiples `{ a: me {id} b: me {id} }` | `200` + `Unauthorized` (identique à une requête simple) | pas de contournement par alias |
| 3 opérations dans un tableau JSON | « Syntax Error: Unexpected "[" » | batching **désactivé** |
| 2 opérations dans un même corps | « This anonymous operation must be the only defined operation » | idem |
| `GET /graphql?query={ me { id email } }` | « blocked as a potential Cross-Site Request Forgery (CSRF) » | GET bloqué (prévention CSRF d'Apollo) → pas de cache deception |
| `__schema` / `__type` | « introspection is not allowed by Apollo Server » | introspection désactivée |

### 2quinquies.d — Audience du serveur MCP → **CLOS et conforme**

| Jeton | `/graphql` (API) | `/mcp` (serveur MCP) |
|---|---|---|
| `aud=https://bugsecure-api.senintel.sn` | 200 `me=william_root` | **401** `invalid_token` (« token failed validation ») |
| `aud=https://bugsecure-mcp.senintel.sn/mcp` | **Unauthorized** | **200** (`initialize` + `tools/list`) |
| aucun | `Unauthorized` | 401 + `WWW-Authenticate: Bearer scope="…", resource_metadata="…"` (conforme) |

→ **aucune confusion d'audience** dans les deux sens. Le serveur MCP expose en revanche une **liste
d'outils de 77 Ko** (donc une surface d'outils bien plus large que le sous-ensemble du client) :
**l'enforcement des scopes par outil reste à tester** (bloqué : il faut un jeton `aud=MCP` vivant).

### 2quinquies.e — PostHog : auto-inscription ouverte (mais throttlée globalement) ★

| Sonde | Résultat |
|---|---|
| `POST /ingest/api/signup` (email neuf) | **201 Created** → utilisateur (id 386563, uuid, distinct_id) **+ organisation** créés, **sans authentification** |
| `POST /ingest/api/signup` (email déjà utilisé) | 400 `unique` (« There is already an account with this email address ») |
| `POST /ingest/api/signup` (IP et email différents, 2ᵉ tentative) | **429** `throttled` « Expected available in 86220 seconds » (≈ 24 h) → le throttle est **global à l'instance**, pas par IP ni par email |
| `POST /ingest/api/login` avec le compte créé | 401 `verify_email_pending` → le compte exige une **validation par email** |
| `POST /ingest/api/login` (email/passe inexistants) | 400 `invalid_credentials` |

→ l'auto-inscription n'est **pas désactivée** sur l'instance self-hosted (PostHog la désactive par
défaut en déploiement propre) : c'est une voie d'accès non approuvée à un système qui héberge les
analytics. **Mais** : (1) le throttle global de 24 h supprime l'abus de masse et le spam ; (2) le
compte créé est bloqué jusqu'à la validation par email → **l'impact démontré s'arrête à la création de
comptes et d'organisations** (pas de lecture des données du projet). → **faible**, à signaler comme
misconfiguration, pas comme fuite.

### 2quinquies.f — PostHog : confusion d'en-têtes et version → **CLOS**

| Variante | Réponse |
|---|---|
| `Authorization: Api <phc_…>` (format attendu par PostHog) | 401 `not_authenticated` |
| `Authorization: Bearer <phc_…>` | 401 `authentication_failed` « **Personal API key found in request Authorization header is invalid** » |
| `Authorization: Bearer null` / `Bearer undefined` | 401 idem (même message) |
| `X-PostHog-Token: <phc_…>` (sans Authorization) | 401 `not_authenticated` |
| double en-tête `Api` + `X-PostHog-Token` | 401 `not_authenticated` |
| chemin encodé `%2f`, double slash, `/./` | 401 `not_authenticated` (normalisé) |
| `/ingest/api/instance_status/version`, `/ingest/api/version`, `/ingest/api/status` | **404** → aucune version divulguée |
| `/ingest/shared_dashboard/<token court>` (8 hex, 12 car., UUID) | 404 (PostHog) |
| projet **valide** vs `phc_000…` vs `xyz` vs vide | **401 uniforme** → aucune énumération de projet |
| HogQL `SELECT count() FROM events` / `SELECT 1` / `SELECT * … LIMIT 1` | **403** `not_authenticated` |

→ seul signal : le message discriminant « Personal API key … is invalid » révèle la **forme** attendue
(une clé personnelle `phx_`), sans rien divulguer d'exploitable.

### 2quinquies.g — Observations diverses

- **Le refresh token est rotatif** (preuve involontaire) : mes propres diagnostics ont consommé le RT
  courant ; le nouveau RT.rotationnel n'est utilisable qu'une fois → `invalid_grant` au second usage.
  Contrôle **conforme**.
- **Transitoire** : `POST /mcp` a répondu `404 {"error":"not_found"}` pendant ~60 s (fenêtre de
  déploiement), puis 30/30 et 20/20 en `200` ensuite → **ce n'est pas un finding** (à signaler au
  vendor comme observation de déploiement).
- `POST /ingest/api/users` → 401 ; `GET /ingest/api/login` → 405 ; `POST /ingest/api/login` → 401/400
  (voir §e).

### 2quinquies.h — L'écran de consentement de l'app échoue sur une ressource non-app (message trompeur)

Constat reproductible : `GET /oauth/authorize?...&resource=https://bugsecure-mcp.senintel.sn/mcp`
avec un client OAuth connu → l'AS répond **302 vers `https://bugsecure.senintel.sn/oauth/consent?request=…`**
(c'est le serveur d'autorisation qui répond, pas l'app). Mais **la page de consentement côté app**
échoue ensuite et redirige vers `https://bugsecure.senintel.sn/oauth/error?code=invalid_client`
→ « *BugSecure ne reconnaît pas cette application. Revenez à l'application que vous connectiez et
réessayez. Code d'erreur : invalid_client* ».

→ le message est **trompeur** : le client est parfaitement reconnu (l'AS a Construct la demande de
consentement) ; c'est le rendu de l'écran de consentement pour une **ressource qui n'est pas celle de
l'app** qui échoue. Même lien, ressource = l'API de l'app → le consentement s'affiche normalement
(autorisation validée, code capté par le catcher). → **observation à signaler au vendor** (UX cassée +
message qui accuse le client alors que le client est valide) ; pas un finding de sécurité en soi, mais
c'est un indice sur la gestion des ressources côté app (à re-tester si un second écran de consentement
apparaît pour d'autres ressources).


## 2sexies. Clôtures du 21/10 : P2 (entropie des tokens) et balayage complet des 198 opérations

### 2sexies.a — P2 : le token de suppression du 2FA est un hex de 64 caractères (256 bits) → **Piste close, non exploitable** ★

Les deux emails du compte de test ont été transférés et analysés (ils sont parvenus dans la boîte
`bbtest4926@maxxspace.com`) :

| Email | Lien | Token |
|---|---|---|
| « An authenticator app is enrolled on your BugSecure Africa account » | `https://bugsecure.senintel.sn/remove-authenticator/<TOKEN>` | `4af4f943ae085fd78b61896e728793525e03e953c244bc7fabd321e87d13948a` |
| « The authenticator app was removed from your BugSecure Africa account » | (aucun lien : notification seule) | — |

→ **longueur 64, alphabet hexadécimal (16 symboles), 256 bits d'entropie** — identique au format du
token de réinitialisation de mot de passe déjà mesuré. Le token d'enrôlement et de suppression est le
**même type de token** (256 bits), et le lien est mono-usage (la page `/remove-authenticator/<token>`).

**Conséquence directe sur la piste `removeTotpViaToken`** (non authentifié, oracle booléen, §2quinquies.a) :
l'espace de recherche est de 10⁶⁴, donc **non exploitable** même au rythme mesuré (5 essais/60 s/IP,
×N IP). → **la piste P2 est close.** L'oracle non authentifié reste un défaut de conception (un
`removeTotpViaToken` authentifié serait plus sûr, et un refus explicite « 2FA non configuré » éviterait
l'appel), mais **aucun impact demonstrated** → à ne pas rapporter comme vulnérabilité. Ce qui reste
documenté pour le vendor : la mutation est appelable sans session et renvoie un booléen.

### 2sexies.b — Balayage complet de la surface GraphQL : **197 / 198 opérations** (fuite 53/198 comblée) ★

Relance avec un jeton **valide** (audience API, scopes `programs:read profile:read reports:read
reports:write`), moteur d'auto-réparation, journal complet dans `klids-evidence/sweep-197.json` :

| Classe | nb | Lecture |
|---|---|---|
| `OAUTH-BLOCKED` (« not available to OAuth clients ») | **125** | toute la surface d'administration et de triage est **fermée aux clients OAuth** |
| `SKIP` (mutations à effet de bord : password, 2FA, organisation, invitation) | 23 | non exécutées volontairement |
| `SCOPE` (scope manquant **nommé** par l'API) | **16** | `triage:read` (6), `triage:write` (2), `grade:write`, `notifications:write` (2), `disclosures:write` (2), `profile:write` → l'enforcement est discriminant |
| `DATA` (réponse non vide) | **9** | **uniquement mes propres données** : `BountyMe` (profil), `CertificateSigningKeys` (clés publiques), `GetUnreadNotificationCount` (=4), et `GetLeaderboard`, `GetMyCertificates`, `GetPrograms`, `GetReports`, `MyAgentApprovals`, `Search` → tableaux **vides** |
| `EMPTY` | 10 | tableaux vides (compte sans rapport) |
| `NOT-FOUND` / `OTHER` | 11 | messages **uniformes** : « You do not have access to this resource », « Program not found », « You can only read your own activity » → **aucun oracle d'énumération** |
| validation d'entrée | 2 | `RaiseAppeal` : « grounds must be longer than or equal to 20 characters » ; `SubmitReport` : « clientRequestId must be 16 to 128 characters » → validation stricte, exploitable par le moteur d'auto-réparation |
| `NOT-FOUND` (autre) | 1 | `GetTermsDocument` : « No such terms version » |

→ **aucune fuite, aucun contournement** : la surface accessible à un client OAuth portant des scopes de
chercheur est exactement celle du chercheur sur ses propres données. Le trou documentaire du début de
campagne (« 53 des 198 ») est **comblé et corrigé** dans la note de mission.

### 2sexies.c — Serveur MCP : fenêtres 404 pendant les déploiements (observation de disponibilité)

Le serveur MCP (`https://bugsecure-mcp.senintel.sn/mcp`, derrière nginx — `x-accel-buffering: no`)
renvoie `404 {"error":"not_found"}` sur **toutes** les routes JSON-RPC pendant des fenêtres de ~1 à 2
minutes, de façon récurrente (observées 3 fois : ~09:36, ~10:20, ~10:30). Le reste du temps : `200`.
Contrôles faits pendant la fenêtre : sans jeton → `401 unauthorized` (donc la route **existe**), jeton
bidon → `401 invalid_token` ; avec un jeton valide → `404` ; les deux IP du serveur
(`52.18.227.46`, `52.18.30.12`) répondent `200` en accès direct avec le bon SNI ; depuis 2 IP
différentes, 30/30 puis 20/20 en `200` hors fenêtre.

→ interprétation : l'**appli** MCP (pas nginx) ne répond `404` que le temps du *rolling deploy*, sans
readiness probe → **ce n'est pas une vulnérabilité**, mais un défaut de disponibilité à signaler au
vendor (les clients MCP qui se connectent pendant la fenêtre reçoivent un 404 indistinguable d'une
route inexistante). Le reste du temps, `initialize`, `tools/list` (77 Ko d'outils) et les appels
d'outils répondent `200`.

### 2sexies.d — Infrastructure de test (hébergement stable du document CIMD)

Le filtre d'IP du chemin CIMD et le test multi-A-record exigent un nom public **avec un certificat
valide** : le tunnel ngrok ne convenait pas (page d'interception, quotas). Infrastructure retenue, sur le
serveur personnel du chercheur (aucune modification de l'infrastructure de production) :

- `~/bb-listener/listener.cjs` — serveur de preuve (document CIMD paramétrable par chemin : `jwks_uri`,
  `token_endpoint_auth_method`, `client_name` HTML, `logo_uri` ; journal de chaque requête reçue).
- `~/bb-caddy/` — **Caddy en conteneur Docker**, challenge ACME en **TLS-ALPN** (le port 80 est déjà
  tenu par nginx sur ce serveur, le 443 est libre) → certificat obtenu automatiquement, sans toucher à
  l'existant.
- Le sous-domaine de test pointe le proxy vers `127.0.0.1:8443` (le `X-Forwarded-Proto` est pris en
  compte pour reconstruire le `client_id` en `https`).


## 2terquies. Techniques « inventives » (3ᵉ revue) et état de l'infrastructure de test

### 2terquies.a — Directives GraphQL, alias, batching : **CLOS**

| Test | Résultat | Lecture |
|---|---|---|
| `@include(if:true/false)`, `@skip(if:true/false)` sur une mutation privilégiée | erreur de validation **identique** dans tous les cas | la directive est évaluée **après** la validation de l'entrée → aucun contournement |
| `@include(if:"true")` / `@include(if:1)` | « Boolean cannot represent a non boolean value » | type-checking correct |
| `@defer` / `@stream` | « **Unknown directive** » | non supportés → pas de « deferred privilege escalation » |
| 20 alias de la même mutation | « **Aliases limit of 15 exceeded** » | plafond d'alias imposé par le serveur |
| mutation + query dans la même requête | « This anonymous operation must be the only defined operation » | mélange refusé |
| requêtes mixtes public/privé dans un document | refus de parsing | pas de contournement par groupement |

### 2terquies.b — Oracle doux par message / latence : **CLOS (aucun oracle)**

12 échantillons par cas, même jeton, mêmes requêtes :

| Cas | min | médiane | max |
|---|---|---|---|
| scope manquant (`getProgramStats`) | 167 ms | 174 ms | 182 ms |
| objet absent (`getReport`) | 167 ms | 171 ms | 184 ms |
| accès réel (`me`) | 170 ms | 180 ms | 5637 ms (outlier ponctuel) |
| scope manquant (`updateReportStatus`) | 166 ms | 169 ms | 6252 ms (outlier ponctuel) |

→ **aucune différence de latence** entre « scope manquant », « objet absent » et « accès réel » → pas
d'oracle d'autorisation exploitable par timing. Les messages sont **discriminants** (le scope manquant
est nommé) mais cela ne révèle que les droits du **porteur du jeton**, pas ceux d'un tiers.

### 2terquies.c — Confusion de binding au `/oauth/authorize` : **CLOS, contrôles stricts**

| Cas | Réponse | Lecture |
|---|---|---|
| témoin | 302 → `/oauth/consent?request=…` | nominal |
| `state` de 300 caractères | 302 → consent | accepté |
| `state` de 2000 caractères | **403** (HTML nginx) | filtre de longueur en amont |
| `state` avec `<script>` et `&` | **403** (HTML nginx) | filtre de caractères en amont (WAF) |
| `code_challenge` S256 incorrect | 302 → consent | le challenge n'est vérifié qu'au `/oauth/token` ✓ (conforme) |
| `code_challenge_method=plain` / absent / `code_challenge` absent | 302 → `error=invalid_request` vers le `redirect_uri` | **S256 obligatoire** ✓ |
| `redirect_uri` + fragment / slash final / majuscules | 302 → `error=invalid_redirect_uri` | correspondance exacte ✓ |
| `scope` dupliqué | 302 → consent | sans effet |
| `scope` inconnu (`admin:all`) | 302 → `error=invalid_scope` | scope inconnu refusé ✓ |
| `resource` dupliqué | 302 → `error=invalid_target` | ✓ |
| `resource` = serveur MCP | 302 → consent | côté AS tout est correct (l'échec est **après**, côté app) |
| `client_id` avec espace final / en majuscules | 302 → `error=invalid_client` | correspondance exacte ✓ |
| `response_type=token` / absent | 302 → `error=unsupported_response_type` | ✓ |
| `redirect_uri` sur un **autre port** (53683) | 302 → consent | le `redirect_uri` n'est **pas** vérifié contre l'enregistrement à l'étape authorize (il l'est au `/oauth/token`, où la campagne a mesuré le refus) → **sans impact démontré** |

### 2terquies.d — Dérive du schéma : le client MCP publié est en retard sur l'API

Le schéma `bugsecure-mcp/schema/bugsecure.graphql` (généré par `scripts/prune-schema.ts` depuis le
schéma complet de l'API) déclare `enum ReportStatus { CLOSED, DUPLICATE, FIXED, INFORMATIVE, IN_FIX,
IN_TRIAGE, NEEDS_MORE_INFO, NEW }`. Or **l'API refuse les 8 valeurs**, y compris `NEW` et
`IN_TRIAGE` : « *Enum "ReportStatus" cannot represent non-enum value: "NEW"* ». 18 autres noms
plausibles (`OPEN`, `TRIAGE`, `CLOSED`, `IN_REVIEW`, `IN_PROGRESS`, `RESOLVED`, `PENDING`,
`NEEDS_MORE_INFO`, …) sont refusés eux aussi, et l'API ne donne **aucune liste** des valeurs
possibles (ni dans le message d'erreur, ni via l'introspection qui est désactivée).

→ le **schéma embarqué dans le paquet npm `@kulinda-sec/bugsecure-mcp` est périmé** : toute opération
dédiée au statut d'un rapport (et le JSON Schema des outils MCP généré à partir de ce schéma) expose
des valeurs que l'API refuse. Ce n'est pas une vulnérabilité de la plateforme cible, mais un **défaut
de notre propre paquet publié** → à corriger (régénérer le schéma depuis l'API et le republier).

### 2terquies.e — Infrastructure de test : le pare-feu du VPS bloque tout le trafic entrant

Le sous-domaine de test `bb-test.enseignementsecondaire.bj` pointe bien vers le serveur
(`45.88.189.67`, DNS « only »), mais **tous les ports entrants sont filtrés par le pare-feu du
fournisseur** (80, 443, 8099, 8443 : joignables en local, **injoignables de l'extérieur**) → le
challenge ACME de Let's Encrypt échoue avec « *Timeout during connect (likely firewall problem)* », et
aucun nom public ne peut servir le document CIMD depuis ce serveur. Caddy (conteneur, `network_mode:
host`, challenge **TLS-ALPN** sur 443, `auto_https disable_redirects` pour ne pas voler le port 80 à
nginx) est prêt et redémarre proprement : **il suffit d'ouvrir le port 443** dans le panneau du
fournisseur.


### 2terquies.f — Serveur MCP : le 404 est bien une fenêtre de déploiement (et non un artefact de test) ★

Le `404 {"error":"not_found"}` sur **toutes** les méthodes JSON-RPC a été qualifier à tort de
« transitoire » puis de « différence de client ». Contrôle méthodique (script minimal identique, même
jeton, requêtes strictement identiques) :

| Moment | Requête via le nom | IP `52.18.227.46` en direct | IP `52.18.30.12` en direct |
|---|---|---|---|
| fenêtre A | 404 × 30 (3 min d'affilée) | — | — |
| fenêtre B | 404 × 6 | — | — |
| hors fenêtre | 200 × 20 | 200 × 10 | 200 × 10 |
| hors fenêtre (script minimal) | 200 × 15 | — | — |

→ le même script, la même requête et le même jeton **alternent** entre 404 (raisons vides) et 200, et les
**deux IP répondent 200 en direct** hors fenêtre. La métadonnée de ressource
(`/.well-known/oauth-protected-resource/mcp`) reste 200 pendant les fenêtres → **ce n'est pas un
problème de routage mais l'application MCP elle-même** qui n'expose pas ses routes pendant le
redéploiement (rolling deploy **sans readiness probe**).

→ **observation à signaler au vendor** (disponibilité + message trompeur : un client MCP ne peut pas
distinguer « instance pas prête » d'« endpoint inexistante »). Ce n'est pas une vulnérabilité de
sécurité ; en revanche c'est ce qui rend **non fiable toute campagne de tests MCP** → les payloads par
outil doivent être réessayés (budget de retry : 60 × 5 s).


### Reste bloqué (besoin du chercheur)

1. ~~Un échantillon du token de suppression du 2FA~~ → **OBTENU et analysé** (§2sexies.a) : hex 64,
   256 bits → **piste P2 close**.
2. ~~La fin du sweep des 198 opérations~~ → **FAITE** (§2sexies.b) : 197/198.
3. **Une autorisation OAuth « ressource MCP »** (le refresh token MCP a expiré) → pour l'enforcement des
   scopes **par outil** (le serveur annonce 77 Ko d'outils) et les payloads de confusion de type.
4. **Un jeton de session du compte organisation non vérifié** → pour comparer le soft-fail
   (`organizationStanding` → objet par défaut) entre contexte personnel et contexte organisation
   (script prêt : `org-sweep.mjs`, 22 resolvers `orgId`/`organizationId`).
5. ~~Le sous-domaine en « DNS only »~~ → **FAIT** (`bb-test.enseignementsecondaire.bj` → `45.88.189.67`),
   mais le **pare-feu du VPS bloque tous les ports entrants** → il faut **ouvrir le port 443** dans le
   panneau du fournisseur. Ensuite : test multi-A-record (2ᵉ enregistrement A vers `127.0.0.1`), race de
   swap du document CIMD, et test de rendu de l'écran de consentement.
6. **Un changement de mot de passe supplémentaire** → pour tester l'**invalidation partielle** : un
   access token OAuth émis *avant* le changement survit-il ? (le jeton OAuth ne porte **pas** le claim
   `epoch` : claims `aud, client_id, exp, grant_id, iat, iss, jti, scope, sub` → la question est donc
   ouverte, alors que le refresh token, lui, a bien été révoqué par le changement de mot de passe).


## 3. Restes à tester (il faut une action du chercheur)

1. ~~Bypass MFA~~ → **CLOS**, voir §2bis (les 7 patterns).
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


### Invalidation au changement de mot de passe — VÉRIFIÉE (correctif déjà accepté par le programme)

Protocole : jeton d'accès émis **avant** le reset → `resetPassword(newPassword, token reçu par email)`
→ `true` → **le même jeton** est retesté.

| Étape | Résultat |
|---|---|
| avant le reset : `me` | 200 (identifiant, email) |
| avant le reset : `updateResearcherProfile` | 200 (bio modifiée) → le jeton **écrivait** |
| le reset | `{"resetPassword":true}` (nouveau mot de passe appliqué) |
| après le reset : `me` | « **Session ended** » |
| après le reset : `reports` | « **Session ended** » |
| après le reset : `updateResearcherProfile` (écriture) | « **Session ended** » |
| après le reset : `myKycStatus`, `notifications` | « **Session ended** » |

→ **le correctif fonctionne** : le changement de mot de passe invalide les jetons d'accès déjà émis
(lecture *et* écriture). La fenêtre résiduelle d'écriture du rapport d'origine n'existe plus.
**Mécanisme confirmé : le claim `epoch`** (0 → 1 au reset) ; l'API répond « Session ended ».

