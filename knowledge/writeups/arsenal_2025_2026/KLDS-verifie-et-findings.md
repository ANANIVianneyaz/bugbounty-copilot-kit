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

### Reste bloqué (besoin du chercheur)

1. **Un échantillon du token de suppression du 2FA** (l'email que le chercheur vient de déclencher) →
   donne la longueur/alphabet et tranche l'impact de §2quinquies.a.
2. **Un jeton OAuth vivant** (nouvelle autorisation : le RT a été révoqué par le changement de mot de
   passe) → pour l'enforcement des scopes par outil MCP (§d) et la fin du sweep des 198 opérations.
3. **Un domaine contrôlable** → pour le test multi-A-record / DNS rebinding du filtre d'IP du CIMD
   (le tunnel ngrok ne permet qu'un nom public à A unique).


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

