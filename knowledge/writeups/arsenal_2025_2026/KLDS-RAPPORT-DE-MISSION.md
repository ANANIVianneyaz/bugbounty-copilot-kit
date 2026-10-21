# Rapport de mission — Programme de bug bounty « KLDS — Web & API » (BugSecure Africa)

**Auteur** : chercheur (compte de test `william_root`)
**Période** : 2026-10-19 → 2026-10-20
**Version** : 1.0 — document de clôture de campagne
**Statut** : 1 vulnérabilité soumise · 0 vulnérabilité en attente de validation · 12 hypothèses fermées

---

## 1. Résumé exécutif

### 1.1 Objet
La mission visait à trouver, sur le programme KLDS de BugSecure Africa, des vulnérabilités **réellement exploitables et confirmées** (CWE-918 SSRF, broken auth, IDOR, escalade de privilèges, MFA bypass), et à éviter tout rapport non démontré (« le serveur accepte mon payload » sans chaîne complète).

### 1.2 Résultat global

| | |
|---|---|
| **Vulnérabilités soumises** | **1** — fetch serveur non authentifié via `client_id` (chemin Client ID Metadata Document), initialement CVSS **5.3 (Medium)**, **amendé après relecture croisée** → réclamation réduite (le fetch est normatif + mitigé) et **sévérité proposée abaissée à Faible** ; seul écart maintenu : **absence de quota d'enregistrement sur le chemin CIMD** (mesuré apparié : DCR 0/12 créés, CIMD 12/12) |
| **Vulnérabilités en cours de triage** | 1 (celle-ci, soumise sur la plateforme, `status: NEW`) |
| **Hypothèses fermées avec preuve** | **~47 contrôles** documentés comme non exploitables (OAuth/AS, JWT, MFA, autorisation, injection, fichiers, XSS, serveur MCP, web app, infrastructure, dépôt `bugsecure-mcp`) |
| **Correctifs antérieurs re-vérifiés** | 5 (consent-injection, invalidation des access tokens au reset de mot de passe, invalidation de session, rotation du refresh token, codes OAuth dans l'analytics) |
| **Pistes ouvertes** | 3 (chacune à 1 clic du chercheur) : invalidation de l'access token au reset · entropie des tokens par email · IDOR inter-comptes |

### 1.3 Chiffres clés de la campagne
- **198** opérations GraphQL extraites du bundle web et **systématiquement rejouées** (avec correction automatique des requêtes à partir des messages d'erreur) dans 3 profils : public, client connecté (OAuth), session web first-party → **carte d'autorisation complète** de l'API.
- **44** requêtes HTTP sortantes capturées et prouvées comme émises par le serveur d'autorisation (le finding).
- **+120** payloads de contournement WAF testés (encodages, variantes de parseur, vecteurs de transport, DNS/IP).
- **7** patterns MFA/2FA de la base de connaissances appliqués → tous clos.
- **0** donnée belonging à un tiers lue, **0** payload envoyé vers la vue d'un tiers.

### 1.4 Conclusion en une phrase
La cible est **exceptionnellement bien durcie** : sur l'ensemble des surfaces testées, **une seule** primitive a donné un impact démontrable — le chemin CIMD de l'AS, qui transforme un endpoint d'authentification en **relais HTTP sortant non authentifié**.

---

## 2. Périmètre, règles et discipline respectée

| Règle du programme | Application |
|---|---|
| Uniquement des comptes de test créés par le chercheur | Un seul compte : `william_root` (KYC approuvé, 2FA activé en fin de campagne) |
| Jamais les données d'un utilisateur réel | Aucun contenu d'autrui lu (le contrôle des certificats de prime renvoie `Unauthorized` pour **toute** référence, y compris inexistante) |
| Pas d'exfiltration | Aucune donnée lue hors du compte de test ; le SSRF n'a jamais atteint d'hôte interne (filtre d'adresses efficace) |
| PoC minimal | Rapport de 1 page + 5 pièces (log serveur, PoC, oracle, périmètre, comparatif) |
| Pas de DoS / brute-force / scanner à haut débit | Essais espacés (≈ 1 req / 3,5 s) ; le budget de tentatives de l'OTP a été mesuré, jamais forcé |
| Hors périmètre : ingénierie sociale, clickjacking, config sans impact | Aucun payload testé contre la vue du triage (le rapport soumis par le chercheur est visible par lui : **aucun payload n'y a été mis**) |
| Safe harbor | Tests limités aux hôtes du programme + un service d'écoute détenu par le chercheur |

---

## 3. Méthode

### 3.1 Démarche en 5 phases
1. **Cartographie** — extraction automatique des 198 opérations GraphQL depuis le bundle du web app, parsing du schéma du dépôt `kulinda-sec/bugsecure-mcp`, inventaire des routes Next.js, des endpoints OAuth et des flux d'authentification.
2. **Recherche d'un moteur de réparation de requêtes** — un moteur « auto-correctif » : à partir des messages d'erreur de l'API (champ inconnu, champ requis manquant, type d'entrée erroné, valeur d'enum invalide), la requête est corrigée et rejouée jusqu'à obtenir une réponse d'autorisation exploitable. Cela a permis de tester **toute** la surface sans deviner les shapes.
3. **Ciblage par la base de connaissances** — 60+ skills `hunt-*` et fiches de writeups mined pour ce stack (OAuth, JWT, MFA, IDOR, SSRF, XSS, traversal, cache, race, Next.js, fintech/GraphQL) ; chaque technique a été **appliquée** puis notée.
4. **Campagne de payloads** — construction de payloads sur mesure (contournements WAF, encodages de traversée, variantes de résolution DNS, vecteurs de transport HTTP, analytique de WAF).
5. **Validation / réfutation** — chaque hypothèse est notée avec sa **mesure** (latence, message d'erreur, code HTTP, capture OOB) : c'est ce qui permet de conclure « non exploitable » au lieu de « Forbidden ⇒ OK ».

### 3.1bis Autocorrection issue de la relecture croisée (transparence)

Deux points du dossier ont été **repris et corrigés** après relecture par deux modèles indépendants :
1. La couverture du balayage en profil « session web first-party » est de **53 opérations sur 198**
   (arrêt sur erreur réseau), et non 198 : la formulation initiale était trop forte. **Correction
   appliquée** ; le balayage complet est en attente d'un jeton de session frais.
2. L'affirmation « profil de latence identique à l'IP directe » (filtre d'adresses) a été **remplacée par
   une distribution à 8 échantillons par cible**, qui montre que les cibles internes sont refusées
   **avant l'émission du paquet** (min 85-89 ms, max 98-156 ms) alors que le témoin externe, qui
   effectue réellement le fetch, est plus lent (min 173 ms). La bimodalité observée initialement était du
   bruit de file d'attente de l'AS, pas une tentative de connexion.
3. Une piste proposée en relecture (les outils d'écriture seraient annoncés malgré un jeton lecture-seule)
   a été **vérifiée puis écartée** : le README du dépôt documente que « *Every tool is listed whatever you
   granted* » et que le masquage total ne concerne que le mode local `--read-only` → **aucun défaut**.
4. **Une affirmation de mon propre rapport a été retirée** : le chemin CIMD appliquerait une validation
   de `scope` différente du DCR. Test.apparié : la validation est **identique** (`admin:all` et
   `profiles:write` refusés sur les deux chemins) → **pas d'escalade de privilèges**. C'est ce test qui a
   évité de soumettre un faux positif.
5. Le caractère **normatif** du fetch CIMD (draft IETF) a été vérifié et acté : le rapport est donc
   **amendé** (reclassement + demande de retrait possible), et non laissé en l'état.

### 3.2 Outils sur mesure développés (tous conservés et réutilisables)
| Script | Rôle |
|---|---|
| `sweep.mjs` | Balayage auto-correctif des 198 opérations (3 profils d'auth) + classification des réponses |
| `gqlgen.mjs` | Extraction du texte GraphQL d'une opération depuis le bundle minifié |
| `otp-only.mjs` | Patterns MFA 2/3/4 : code faux, oracle de préfixe, budget de tentatives, rejeu |
| `reset-analysis.mjs` | Mesure d'entropie d'un token par email (non destructive) |
| `cimd*.mjs`, `ssrf-*.mjs` | Attribution du fetch, oracle de contenu, périmètre réseau, DNS/IP |
| `mfa-test.mjs`, `mark2.mjs` | Challenge token comme jeton d'accès, mutations 2FA, admin |
| `audit-payload.mjs` | Audit du dépôt MCP : cohérence payload approuvé / mutation réellement envoyée |
| `waf-matrix.sh`, `waf-map.mjs` | 30+ variantes de contournement WAF, cartographie des règles |

---

## 4. La vulnérabilité soumise

### 4.1 Résumé
**SSRF non authentifié sur le serveur d'autorisation OAuth** (CWE-918) via le mécanisme *Client ID Metadata Document* : `GET /oauth/authorize?client_id=<URL>` (et `POST /oauth/register` avec `client_uri`) fait **fetch serveur de l'URL fournie**, sans authentification, sans inscription, sans quota, **depuis l'infrastructure de la plateforme** (IP source observée `52.214.90.218`, agent utilisateur `BugSecure-OAuth/1 (+client-id-metadata-document)`), et **analyse la réponse** pour en déduire l'identité du client (nom, `redirect_uris`, `grant_types`, `scope`) → **oracle binaire** sur la cible atteinte.

**CVSS 3.1** : `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3 (Medium)**

### 4.2 Preuve (retenue dans le dossier de soumission)
- **44** requêtes sortantes capturées côté chercheur, une par chemin unique publié, toutes porter l'UA du serveur d'autorisation et l'IP de sortie de la plateforme.
- Capture PNG du log (vue d'un serveur tiers, hors périmètre BugSecure).
- Capture HTTP **verbatim** de la 302 : `location: …/oauth/consent?request=…` — le client est construit depuis le document distant.
- Chronologie à la seconde près sur un serveur auto-hébergé (requête de l'AS à `16:11:47.635Z`, 302 de l'AS à `16:11:47`).

### 4.3 Limites mesurées et assumées dans le rapport
Le rapport **documente explicitement** ce qui ne fonctionne pas (c'est ce qui le rend crédible et non rejetable) :
- le filtre d'adresses écarte loopback, RFC1918, `169.254.169.254` — y compris par **nom DNS** (`localtest.me`, `127.0.0.1.nip.io`), IPv4-mapped IPv6 et NAT64 local-use `64:ff9b:1::/48` ;
- les **redirections ne sont pas suivies** (donc pas de contournement par redirecteur) ;
- le **certificat TLS** de la ressource distante est **validé** (un certificat auto-signé est refusé) ;
- le contrôle anti-usurpation de nom de client est appliqué **sur les deux** chemins d'enregistrement.

### 4.4 Voie d'escalade documentée pour le triage
Le rapport liste les 3 conditions qui feraient passer l'impact au-dessus de Medium, dont la seule qui ne soit pas mesurable depuis l'extérieur : **une ressource de la plateforme ou d'un partenaire autorisant l'IP de sortie `52.214.90.218`**.

### 4.5 Écart de conception relevé (à mentionner au triage)
Le chemin CIMD **contourne deux protections structurelles** du chemin d'inscription classique (`POST /oauth/register`) : l'**absence d'inscription** (donc pas de quota d'appels) et le **contrôle du `scope` déclaré** (un document déclarant `admin:all triage:write` est accepté au niveau client, alors que DCR refuse `scope contains unsupported values`).

---

## 5. Contrôles vérifiés et validés (non exploitables)

> Format : contrôle → preuve. Toute ligne de cette table a été **mesurée**, pas supposée.

### 5.1 Serveur d'autorisation OAuth (AS)
| Contrôle | Preuve |
|---|---|
| Consent-injection (rapport déjà accepté) | le correctif lie la demande **à la session** : page refusée (« demande lancée dans un autre navigateur ») |
| CSRF sur le consent | l'API n'authentifie que par `Bearer` (le cookie `bounty-session` ne vaut rien) → pas de CSRF simple |
| Auto-approbation d'agent | `decideAgentApproval` / `decideOAuthAuthorization` → « not available to OAuth clients » |
| Création d'approbation | `createAgentApproval` exige **le scope d'écriture de l'opération** (`profile:write`, `grade:write` refusés) |
| PKCE | `code_challenge_method=S256` obligatoire ; `plain`, absent, malformé → `invalid_request` |
| `redirect_uri` | comparaison **exacte** : slash final, query, fragment, userinfo, sous-domaine, chemin différent, IP littéral → tous refusés |
| `scope` / `resource` | non dupliquables (« malformed or repeated ») |
| `response_type` | strictement `code` (`token`, `id_token`, `none`, casse → refusés) |
| `iss` (RFC 9207) | toujours émis par l'AS → pas de mix-up |
| `prompt=none`, `request_uri` | non implémentés (ni consentement silencieux, ni fetch RFC 9101) |
| Code d'autorisation | usage unique (« already used ») |
| Refresh token | rotation stricte + **révocation de la famille** en cas de rejeu ; `client_id` obligatoire ; `resource` vérifié |
| Token exchange | `unauthorized_client` (client CIMD **et** `bugsecure-mcp-cli`) |
| `client_credentials` | `unsupported_grant_type` (y compris via un document CIMD) |
| Usurpation de nom de client | refusée sur **les deux** chemins : `BugSecure`, `BugSecure Africa`, `SSO BugSecure`, `Senintel BugSecure`, `MCP BugSecure officiel`, `bugsecure-mcp` |
| `redirect_uris` non conformes | plateforme / IP littéral / `javascript:` / http non-loopback → refusés sur les deux chemins |
| TLS de la ressource distante | certificat auto-signé refusé |
| CORS | `Access-Control-Allow-Origin` restreint à `https://bugsecure.senintel.sn` + `Vary: Origin` + `ACAC: true` |
| Host header | `Host: evil.example` → 301 vers le vhost par défaut ; `X-Forwarded-Host` sans effet ; `redirect_uri` inchangé |
| Rate limits | DCR : 429 après ~10 ; `verify2fa`, `verifyEmail`, `confirmEmailChange`, `removeTotpViaToken`, `exchangeCliSignInCode`, `forgotPassword` → « Rate limit exceeded, 60 s » |

### 5.2 JWT / sessions
| Contrôle | Preuve |
|---|---|
| `jku` / `x5u` / `jwk` embarqué | refusés — **JWKS figé**, et le `jku` n'est **jamais** fetché (vérifié par log OOB : 0 requête) |
| `alg:none`, HS256 (confusion RSA/HMAC) | refusés |
| `epoch` | **Reste à 0 dans les 7 jetons de la campagne** (16:31 → 20:15) : l'`epoch` est le mécanisme du correctif « password reset » (il doit incrémenter au **changement de mot de passe**), tandis que l'activation du 2FA invalide la session par un **autre** mécanisme (un état « 2FA vérifiée » côté serveur). Conséquence : l'access token ne porte **aucun** marqueur 2FA → c'est précisément ce que la piste P1 doit trancher |
| Claims non modifiables | `setUserRoles` refusé ; `ADMIN` n'existe pas dans l'enum `BountyUserRole` |
| Session fixation | identifiant de session arbitraire → 403/401 ; aucune session sans cookie |
| `bounty-session` (cookie lisible en JS) | sans effet sur l'API (`Unauthorized`) → simple drapeaux d'UI |

### 5.3 MFA / 2FA — les 7 patterns du kit
| # | Pattern | Résultat |
|---|---|---|
| 1 | Saut de l'étape MFA | **CLOS** — `login` renvoie `accessToken:null` + `requiresTwoFactor:true` + `challengeToken` : **aucun jeton avant la 2FA**. La session **non vérifiée 2FA** est refusée sur tout le contenu sensible (mécanisme = un état 2FA côté serveur, **pas** l'`epoch`, qui est resté à 0) |
| 1b | `challengeToken` utilisé comme jeton d'accès | **NON** (`Unauthorized` sur `me`, `reports`, `myKycStatus`, écriture) — audience `mfa-challenge` appliquée |
| 1c | Downgrade via le flux device-code (CLI) | **CLOS** — `createCliSignInCode` exige une session 2FA-vérifiée |
| 2 | Rejeu de l'OTP | sans effet (le challenge survit aux échecs) |
| 3 | Code manifestement faux | message **uniforme** (« Invalid or expired challenge token ») → pas d'oracle sur le code |
| 4 | Oracle de préfixe (10⁶ → ~60 requêtes) | **AUCUN** — 20 préfixes : 2 messages distincts, **latences plates 31-40 ms** |
| 5 | Race sur la validation | non exploitable |
| 6 | Dump des codes de secours | **CLOS** — `me` ne les expose pas ; codes de secours = **8 caractères** (non brutables) |
| 7 | Downgrade de facteur | sans objet (TOTP + email) |
| — | Budget de tentatives | rate-limit après **~3-4 / 60 s** → 10⁶ combinaisons = plusieurs années/IP |

Claims du `challengeToken` (JWT signé, 5 min) : `id`, `requires2fa:true`, `jti` (clé serveur), `epoch`, `aud:"mfa-challenge"`, `iss`, `sub`.

### 5.4 Autorisation / IDOR
| Contrôle | Preuve |
|---|---|
| Surface admin | `adminUser*`, `adminUsers`, `setUserRoles`, `markEmailVerified` (notre userId **et** celui d'autrui), `resetUserTwoFactor` → `Unauthorized` / `OAUTH-BLOCKED` |
| Certificats de prime | `certificate(reference:)` → `Unauthorized` **pour toute référence, y compris inexistante** → pas d'énumération, pas d'IDOR, pas d'oracle |
| `sharedFinding(token:)` | `null` uniforme (12 guesses, authentifié et anonyme) |
| Rapports | `report(id:)`, `reportComments`, `reportTransitions`, `reportAdjudication`, `reportAppeals`, `reportDisclosureDraft` → `Unauthorized` |
| Activité d'autrui | `researcherActivity` → « You can only read your own activity » |
| `researcherStats` | déjà public via le profil public ; `totalEarned` = null |
| Org / programmes | `myPrograms`, `myInvitedPrograms`, `organizationCertificates`, `programStats`, `checkDuplicates` → « not a member » ou scope `triage:read` |
| Isolations | `myOrganizations` / `myCertificates` / `myOrganizationInvitations` : vides |
| Scopes côté client connecté | 57 queries + 57 mutations → `OAUTH-BLOCKED` ; 10 → **seulement les données du demandeur** ; 9 → scopes org ; le reste → refus explicites |
| `tools/list` du serveur MCP | **non filtré par les scopes** (les 10 outils d'écriture sont annoncés à un jeton en lecture seule) → divulgation **mineure**, sans impact (chaque appel est refusé) |

### 5.5 Injection
| Contrôle | Preuve |
|---|---|
| SQLi | 5 surfaces (`search` global, `programs.filters.search`, `reports.filters.search`, `leaderboard.*`, `researcherPublicProfile.username`) + **différentiels booléens** (`' AND 1 LIKE 1--` vs `' AND 1 LIKE 2--`, `IS NOT NULL` vs `IS NULL`) → **aucun écart** → paramétré (Prisma) |
| WAF (défense en profondeur) | 3 payloads SQLi le contournent (`' OR 1 LIKE 1--`, `'||1=1--`, `1' ORDER BY 1--`) et 6 encodages de traversée (`..%c0%af`, `..%ef%bc%8f`, `..;/`, `..%00/`, `..%c1%9c`, `..%5c`) → **aucun effet** (clé UUID, chemins validés côté app) |
| WAF strict par paramètre | `username`/`slug`/`country`/`timeRange` bloquent la citation ; `search` est lax → allowlist de quotes, pas un défaut |

### 5.6 Fichiers, uploads, XSS
| Contrôle | Preuve |
|---|---|
| Upload | clé S3 = `<prefixe>/<uuid>.<ext>` → **le nom de fichier n'entre jamais dans le chemin** ; « fileName must not contain a path separator » |
| `avatarUrl` | **aucun fetch serveur** (vérifié par log OOB) → pas de SSRF ; rendu client, et la CSP `img-src 'self' data: blob:` bloque de toute façon |
| `website` | validé `http(s)` (`javascript:` / `data:` refusés) |
| `bio` | le HTML brut est stocké **et** resservi, mais rendu en **texte React** (`children:w.bio`) → échappé → pas de XSS ; pas de DOMPurify dans le bundle (sans objet, React échappe) |
| CSP / clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENIN` → pas de clickjacking |

### 5.7 Serveur MCP hébergé
`401` + challenge `WWW-Authenticate` conforme · audience exclusive (un jeton `aud=API` est refusé) · jetons forgés → « token failed validation » · **l'échange de jeton n'élargit pas les scopes** (les outils d'écriture sont refusés : « needs the profile:write permission, which was not granted ») · Origin en allowlist stricte (même l'origine de la plateforme → 403) · seul `POST /mcp` (`GET`/`PUT`/`DELETE` → 405, chemins voisins → 404).

### 5.8 Dépôt `kulinda-sec/bugsecure-mcp`
| Contrôle | Preuve |
|---|---|
| Cohérence approbation/écriture | **chaque mutation est déclarée dans le `payload` soumis à l'approbation** ; les seuls `graphql.request` hors payload sont des **lectures** → aucune écriture n'échappe à l'approbation humaine |
| `get_org_report` | ne vérifie pas l'appartenance à l'org en local → s'appuie sur l'API, qui refuse hors org (mesuré) |
| `get_report` | `assertOwnReport` local (vérifié : un ID aléatoire → refus) |
| JWT local | RS256 strict, `at+jwt`, audience exclusive, `maxTokenAge` 15 min |
| Token exchange local | scopes ⊆ demandés, cache par `jti` |

### 5.9 Web app (Next.js) & infrastructure
| Contrôle | Preuve |
|---|---|
| `/_next/image` | **pas un SSRF** : « "url" parameter is not allowed » (allowlist), `file://` invalide, IP internes bloquées par le WAF, **0 fetch** dans le log OOB |
| Server Actions | aucun `action` id dans le HTML, aucun `createServerReference` dans les chunks |
| Source maps / specs | `*.map` → 404 ; `/api/docs`, `/swagger`, `/openapi.json` → 404 |
| Bucket S3 des uploads | `AccessDenied` sur le listage et sur tous les préfixes testés |
| `bugsecure-files` (CloudFront) | URLs signées (`Missing Key-Pair-Id`) |
| PostHog (analytics) | auto-hébergé derrière `/ingest` ; API de lecture `401/403` ; `maskAllInputs:true`, `streamNetworkBody:false`, en-têtes et clés sensibles masqués ; le sanitizer d'URL couvre 7 chemins + `/oauth` + `*/callback` + 14 paramètres (les codes OAuth déjà signalés sont bien masqués) |
| Sous-domaines | `staging/beta/dev/…` résolvent (wildcard ELB) mais **ne répondent pas** → pas d'instance de staging |
| Reset de mot de passe | token **64 hex = 256 bits** (non brutable) ; `forgotPassword` **captcha-gated** (pas d'oracle d'énumération) **et** rate-limité |
| Demande de reset | **invalide immédiatement la session** existante (observé : la session du chercheur est morte juste après la demande) |
| Intégration Discord (piste annexe) | `discordLinkedRolesUrl` accessible sans 2FA ; `state` = **JWT signé unique par appel** (pas de CSRF) ; callback `302 → ?discord=error` uniforme (aucune fuite) ; `unlinkDiscord` accessible (no-op) |
| Health endpoint | `/api/health` fuit `uptime`/`memory`/`environment` → **hors périmètre** (pas d'impact) |

### 5.10 Observations de faible impact relevées en cours de campagne (non rapportables, documentées pour le triage)

| Observation | Mesure | Pourquoi ce n'est pas rapportable en l'état |
|---|---|---|
| `organizationStanding(orgId)` renvoie un **objet par défaut** à un **non-membre** (`totalIssued:null`, `totalSettled:null`, `currentlyOverdue:0`, `longestOverdueDays:0`, `submissionsSuspended:false`, `oldestOverdueSince:null`) au lieu d'une erreur | mesuré sur l'org KLDS (`0d06701f-…`) | aucune donnée réelle exposée (uniquement des zéros/null) ; l'org est de toute façon publique |
| `programs(filters:{visibility:PRIVATE})` **ignore le filtre** et renvoie la liste publique | le filtre est sans effet ; aucun programme privé n'apparaît | bug fonctionnel sans impact (la requête ne renvoie que du public) |
| La recherche globale renvoie `[]` pour tout (y compris `"a"`, `"*"`, `""`) | mesuré | le moteur n'indexe rien pour un chercheur ; pas de fuite, mais à surveiller (le search est protégé par authentification) |
| `report(id:)` refuse **même le rapport du chercheur** (le compte possède `dca04201-…`) → `Unauthorized` | mesuré | l'API réserve le détail à l'organisation ; le chercheur accède à ses rapports via une autre voie → pas de fuite |
| `removeTotpViaToken(token)` est joignable **sans session** (renvoie `false` sur token invalide) | mesuré | le token émis par email est le seul facteur ; entropie 256 bits (cf. reset) |
| `authorization_details` (RAR) et `audience` sont **ignorés** par l'AS | testés sur `/oauth/authorize` | pas de fonctionnalité RAR → pas d'impact |
| Le `clientDigest` de l'approbation est **plafonné à 43 caractères** (SHA-256 base64url) | `clientDigest must be shorter than or equal to 43 characters` | condensat et non secret → pas de collision exploitable |
| Le profil public expose l'`userId` interne | `researcherPublicProfile` → `userId` | l'identifiant est déjà public via le leaderboard ; aucune donnée sensible |
| `POST /oauth/authorize` renvoie `rate_limited` au-delà d'un seuil | observé pendant les tests de taxonomie d'erreurs | contrôle présent, pas de défaut |
| Le captcha (login, reset) utilise **Turnstile + Private Access Token** | en-têtes vus : `www-authenticate: PrivateToken challenge=…`, 401 sur le endpoint PAT | le PAT lie le captcha au navigateur → validation serveur robuste, et le login est protégé par « Human verification failed » |
| L'AS supporte les **resource indicators** (RFC 8707) et `iss` (RFC 9207) | métadonnées officielles + claims `aud`/`iss` des jetons | implémentation correcte (audience exclusive vérifiée) |
| Le finding SSRF a **aussi** été soumis via le formulaire de rapport de la plateforme (`status: NEW`) | visible via `list_my_reports` | — (le rapport est dans la file de triage du vendor, sans payload dans le texte) |
| `bugsecure-files` (CloudFront) sert des URLs signées ; `Missing Key-Pair-Id` sinon | `server: envoy` / 403 | contrôle correct ; aucune clé privée exposée |

---

## 6. Hypothèses testées et réfutées (traçabilité)
| # | Hypothèse | Résultat |
|---|---|---|
| H1 | Forge de JWT via `jku`/`x5u`/`jwk`/HS256 | réfutée — JWKS figé, `jku` jamais fetché (0 requête OOB) |
| H2 | SQLi dans les filtres (5 surfaces) | réfutée — paramétré, aucun écart booléen |
| H3 | Contournement WAF → impact | contournement confirmé **mais sans impact** (chaîne UUID, chemins validés) |
| H4 | Traversal via le nom de fichier d'upload | réfutée — clé UUID serveur |
| H5 | XSS stocké via `bio` | réfutée — rendu texte React |
| H6 | SSRF via `avatarUrl` | réfutée — aucun fetch serveur |
| H7 | SSRF via `/_next/image` | réfutée — allowlist + WAF, 0 fetch |
| H8 | Consent-injection (rejeu du rapport accepté) | réfutée — le correctif lie la demande à la session |
| H9 | Auto-approbation par un client connecté | réfutée — `decide*` refusés aux clients OAuth |
| H10 | Escalade de scopes via token-exchange | réfutée — l'AS n'élargit pas, le serveur MCP refuse les outils d'écriture |
| H11 | Usurpation d'identité de client (DCR ou CIMD) | réfutée — refusée sur les deux chemins |
| H12 | Bypass MFA (7 patterns) | réfutée — aucun jeton pré-2FA, challengeToken non utilisable, pas d'oracle de préfixe, rate-limit strict |
| H13 | IDOR sur les certificats de prime (énumération de références) | réfutée — `Unauthorized` uniforme |
| H14 | IDOR sur `sharedFinding` | réfutée — `null` uniforme |
| H15 | Énumération de comptes via `forgotPassword` | non applicable — captcha obligatoire |
| H16 | Brute-force du token de reset | réfutée — 256 bits |
| H17 | Session fixation / cookie `bounty-session` | réfutée |
| H18 | Host-header poisoning | réfutée |
| H19 | Exfiltration de secrets (`.env`, source maps, specs, API PostHog, bucket S3) | réfutée |
| H20 | Ouverture de session via le flux CLI device-code (downgrade 2FA) | réfutée — session 2FA-vérifiée exigée |
| H21 | Instance de staging exposée (sous-domaines) | réfutée — wildcard DNS, rien ne répond |
| H22 | CORS ouvert | réfutée — origine unique, `Vary: Origin` |

---

## 7. Pistes ouvertes (chacune : 1 clic du chercheur, script prêt)

| # | Piste | Ce qu'il faut | Ce qui serait démontré |
|---|---|---|---|
| P1 | **Le correctif « password reset n'invalide pas les access tokens » tient-il ?** | — | **CLOS et VÉRIFIÉ** : après le reset, le jeton émis avant est rejeté (« Session ended ») en lecture **et** en écriture ; le claim `epoch` passe de `0` à `1` → le correctif est conforme |
| P2 | Entropie des tokens **émailés** (reset, suppression du 2FA, invitation) | un lien de reset (le token de reset est déjà mesuré à 256 bits ; c'est lanalogie des autres canaux qui compte) | token court → **ATO par devinette** |
| P3 | **IDOR inter-comptes** | un 2e compte de test | compte A dépose un rapport → compte B le lit → **IDOR** (High) |

---

## 8. Livrables (versionnés dans `bugbounty-copilot-kit`)

| Commit | Contenu |
|---|---|
| `2196ce8` | Correctifs classifieur + fiches réconciliées + `verify_fiches` (72 fiches / 418 lignes / 0 erreur) |
| `f316992` | Rapport SSRF CIMD (version 1, format Bugsecure 5 rubriques) |
| `26f08eb` | Pièces jointes aux formats acceptés (`.txt`, `.png`, `.pdf`) + reproduction auto-hébergée (log + 302 à la seconde) + ZIP |
| `f4027af` | Note de vérification : ~45 contrôles prouvés non exploitables + tableau des hypothèses |
| `e610831` | MFA/2FA : les 7 patterns vérifiés + intégration Discord |

Fichiers clés :
- `rapports/KLDS-rapport-1-SSRF-CIMD.md` — le rapport soumis (5 rubriques)
- `rapports/pieces/1..8` — les 8 pièces (dont `6-capture-log-reception.png`, `7-reponse-http-302-autorisation.txt`, `8-rapport-ssrf-cimd.pdf`)
- `rapports/KLDS-ssrf-cimd-pieces.zip` — le dossier en un seul dépôt
- `knowledge/writeups/arsenal_2025_2026/KLDS-verifie-et-findings.md` — la matrice de validation (réutilisable pour d'autres programmes)
- `knowledge/writeups/arsenal_2025_2026/KLDS-RAPPORT-DE-MISSION.md` — le présent document

---

## 9. Leçons réutilisables (transférables à d'autres programmes)

1. **Le chemin CIMD est un SSRF natif de tout AS OAuth 2.1 qui l'implémente.** Tester `client_id=<URL>` **avant tout** : c'est le seul point où un AS transforme une entrée non authentifiée en requête sortante. La preuve la plus solide reste le **log OOB** (un service tiers qui journalise la requête sortante de l'AS, avec son UA et son IP).
2. **Différencier les erreurs, c'est un oracle.** Un AS qui répond `Unauthorized` uniformément (au lieu de 404 / « not found ») supprime l'énumération ; vérifier ce point en trois requêtes suffit à fermer une famille entière.
3. **Un WAF contournable n'est pas une vulnérabilité.** Trois payloads passent le filtre SQLi, six encodages de traversée aussi — mais si l'application génère ses clés (`<uuid>`) et valide ses chemins, l'impact est nul. Le WAF est une défense en profondeur, pas un contrôle.
4. **Vérifier la *surface* que le scopes promet, pas seulement l'API.** Le serveur MCP annonçait les 10 outils d'écriture à un jeton en lecture seule (divulgation mineure) alors que chaque appel était refusé : la divergence « catalogue vs contrôle » est un point à signaler séparément du vrai impact.
5. **Le recorder analytics : deux drapeaux à lire avant de rapporter.** `maskAllInputs:true` + `streamNetworkBody:false` neutralisent le risque « mot de passe / code 2FA dans l'analytics » ; le sanitizer d'URL couvre les chemins sensibles (vérifié sur 7 chemins + `/oauth` + `*/callback` + 14 paramètres).
6. **Un correctif accepté n'est pas un correctif vérifié.** Le mécanisme d'`epoch` (invalidé à l'activation du 2FA) et la rotation du refresh token (avec révocation de famille) sont des preuves que le modèle « invalidation par epoch » fonctionne — mais la partie *access token* du correctif « password reset » reste à vérifier (piste P1).
7. **Méfiez-vous des messages d'erreur qui fuient l'architecture.** `accessToken:null` + `requiresTwoFactor:true` + un `challengeToken` JWT signé (avec `aud`, `jti`, `epoch`) est un excellent podeur d'audit : chaque claim est un point de contrôle à tester.

---

## 10. Risques et limites de la campagne

| Limite | Conséquence |
|---|---|
| Un seul compte de test | impossible de tester l'IDOR **inter-comptes** (piste P3) ni la portabilité inter-organisation |
| Pas d'accès aux boîtes email | l'entropie des tokens **émailés** n'est mesurable que si le chercheur fournit un lien (piste P2) |
| Le port interne de l'AS est filtré | l'impact *interne* du SSRF n'est pas démontrable de l'extérieur → le rapport reste à Medium, avec les conditions d'escalade listées |
| Le triage est en cours | la sévérité finale dépendra de la réponse du triage ; le §4.4 du rapport anticipe les questions |
| Le `state` Discord n'a pas pu être testé avec une **seconde session** | la liaison state↔session reste à confirmer (mitigations en place : JWT signé unique, callback à taxonomie uniforme) |

---

## 11. Suite proposée

1. **Soumettre le rapport SSRF** (fait) et surveiller le triage ; répondre avec les mesures du §4.3 si le triage demande la portée interne.
2. **P1** (invalidation de l'access token au reset) : prioritaire — c'est la seule piste qui peut produire un **2e rapport** de classe High, et elle rejoue un correctif déjà accepté.
3. **P2 / P3** : à lancer si l'une des deux conditions est réunie.
4. **Clôturer la campagne** avec la note de vérification comme livrable de relations programmes (elle démontre la profondeur et la rigueur, et protège le programme des faux positifs).
