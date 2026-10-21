# KLDS / BugSecure Africa — rapport de campagne complet (Web & API + serveur MCP hébergé)

**Périmètre** : `bugsecure.senintel.sn` (application web), `bugsecure-api.senintel.sn` (API GraphQL +
serveur d'autorisation OAuth), `bugsecure-mcp.senintel.sn` (serveur MCP hébergé), instance
analytics auto-hébergée exposée sous `/ingest` sur le domaine de l'app.
**Fenêtre** : 20-21 octobre 2026. **Compte de test** : un compte chercheur, puis un compte
organisation (non vérifié) et un compte organisation personnel.
**Volume** : ~65 contrôles (201 lignes de résultats mesurés), 60 scripts, 32 journaux bruts,
balayage complet de **197/198 opérations** de la surface GraphQL, **33 outils** MCP testés
individuellement.

---

## 1. Synthèse

| | |
|---|---|
| **Rapports soumis** | **1** — fetch serveur non authentifié via `client_id` (chemin *Client ID Metadata Document*) — **clos par le triage comme doublon, sans récompense** (comportement = mécanisme CIMD normatif de la spec MCP, déjà signalé et évalué *Informatif*) |
| **Surclaims retirés** | **2** (qualification « SSRF » ; écart de validation de `scope`) — retirés à la suite des deux revues croisées et de la réponse du triage |
| **Vulnérabilités exploitables confirmées** | **0** — aucune n'a été démontrée sur la surface testée |
| **Contrôles vérifiés conformes** | **~65**, dont 2 correctifs déjà acceptés par le programme **re-vérifiés conformes** (invalidation des access tokens au reset de mot de passe ; rotation des refresh tokens avec révocation de famille) |
| **Observations à signaler au vendor** (non exploitables) | **7** : auto-inscription ouverte sur l'instance analytics, exigence d'`User-Agent` côté MCP, saisie d'un `logo_uri` non validée par l'AS, rechargement des tokens de session web sans `epoch`, dérive du schéma du client MCP publié, message d'erreur trompeur sur l'écran de consentement, **soft-fail + oracle d'existence sur `organizationStanding`** |
| **Pistes fermées avec preuve** | **10** (entropie des tokens emailed, `jwks_uri` de second ordre, fédération/alias/batching, confusion d'audience, oracle de timing, échappement de l'API de lecture analytics, confusion d'en-têtes, traversée de chemin, IP-littéraux, **IDOR inter-comptes — testé avec un vrai second compte `COMPANY_ADMIN` → négatif**) |
| **Point ouvert principal** | invalidation **partielle** des access tokens OAuth au changement de mot de passe (les access tokens OAuth ne portent pas le claim `epoch` que portent les jetons de session web) |

> **Position honnête** : la plateforme a résisté à l'ensemble de la campagne. Les seuls points
> réellement nouveaux sont des **observations de configuration**, et le seul point qui mériterait un
> examen plus approfondi est l'invalidation partielle des access tokens OAuth, qui ne peut être
> tranchée sans une action du chercheur (un changement de mot de passe supplémentaire).

---

## 2. Le rapport soumis, et pourquoi il a été clos

**Titre** : *Fetch serveur non authentifié via `client_id` (chemin Client ID Metadata Document)*.

Le triage a répondu (20/10) que le comportement décrit est celui du mécanisme CIMD prévu par la spec
MCP qu'ils implémentent, que leurs mitigations sont conformes (HTTPS:443, nom DNS public, pas d'IP,
refus des adresses non publiques **à la résolution et à la connexion**, pas de redirection, TLS
validé), que le `scope` du document n'est pas lu, et que le « même comportement » avait déjà été
signalé et évalué *Informatif* → **doublon, sans récompense**.

**Ce que j'en ai tiré (et qui est exact)** :
1. le fetch est **normatif** (draft IETF *Client ID Metadata Document*) → la qualification « SSRF »
   était inappropriate → **retirée** ;
2. le `scope` du document n'est pas lu → mon argument d'escalade était faux → **retiré** ;
3. l'« oracle » ne révèle qu'un retour de validation public, pas une fuite d'information.

**Ce qui reste vrai et a été communiqué** : le chemin CIMD n'applique **aucun quota d'inscription**
(mesure appariée, même cadence 1 req/3 s, 12 tentatives de chaque côté) :

| Chemin | Clients créés | `429 temporarily_unavailable` |
|---|---|---|
| `POST /oauth/register` (DCR) | **0** | **12** |
| `client_id` = URL (CIMD) | **12** | **0** |

→ un appelant non authentifié peut créer un nombre non borné d'identités de client, chacune
déclenchant une récupération serveur. Signalé au triage comme observation, sans en faire un rapport.

---

## 3. Contrôles vérifiés (et pourquoi ils ne sont pas exploitables)

### 3.1 OAuth / serveur d'autorisation

| Contrôle | Mesure | Verdict |
|---|---|---|
| PKCE | `S256` obligatoire ; `plain`, absent et malformé → `invalid_request` | conforme |
| `redirect_uri` | correspondance **exacte** (fragment, slash final, majuscules, userinfo, sous-domaine, chemin différent, IP littéral, `javascript:` → refusés) sur les deux chemins d'enregistrement | conforme |
| `client_id` | correspondance exacte (espace final, majuscules → `invalid_client`) | conforme |
| `state` | 300 car. acceptés ; 2000 car. ou caractères spéciaux → **403** (filtre en amont) | conforme |
| `scope` | scopes inconnus (`admin:all`) → `invalid_scope` ; `scope` du document CIMD non lu | conforme |
| `resource` | dupliqué → `invalid_target` ; aud=API refusé par le serveur MCP et aud=MCP refusé par l'API (cloisonnement dans les deux sens) | conforme |
| `response_type` | `token`/absent → `unsupported_response_type` | conforme |
| Code d'autorisation | usage unique | conforme |
| Refresh token | **rotation** + révocation de famille (constaté : l'ancien RT est invalidé à chaque usage) | conforme |
| `token-exchange`, `client_credentials` | refusés (`unsupported_grant_type`) | conforme |
| `private_key_jwt` | **non supporté** : un document CIMD le déclarant est rejeté (`invalid_client`) → aucun `jwks_uri` n'est jamais récupéré | conforme (cf. §5.2) |
| Filtre anti-usurpation | 10 variantes par DCR + **22 confusables Unicode** (cyrillique, accents, zero-width, bidi RLO/PDF, BOM, turc `ı`, ZWJ, insécable…) → **toutes refusées** ; un `client_name` contenant la marque est refusé | robuste |
| `jwks_uri` | **accepté sans validation** (y compris `169.254.169.254`, `10.255.255.1`, `localhost`, `javascript:`, `data:text/html`) → mais **jamais récupéré** faute de `private_key_jwt` | sans effet |
| Quota d'inscription | DCR 0/12 · CIMD 12/12 | **écart** (cf. §2) |
| Introspection GraphQL | désactivée (Apollo) | conforme |
| Batching / alias | batching désactivé ; **plafond de 15 alias** ; mutation+query dans un même document refusés | conforme |
| Federation | `_service` et `_entities` absents → l'API **n'est pas fédérée** | conforme |

### 3.2 Sessions, JWT, MFA

| Contrôle | Mesure | Verdict |
|---|---|---|
| Invalidation au changement de mot de passe | jeton de session émis **avant** → rejeté après le reset (« Session ended ») en lecture **et** en écriture ; le claim `epoch` passe de `0` à `1` | **correctif conforme** (re-vérifié) |
| Access tokens **OAuth** | ne portent **pas** de claim `epoch` (`aud, client_id, exp, grant_id, iat, iss, jti, scope, sub`) ; le refresh token est révoqué par le changement de mot de passe | **point ouvert** (cf. §6.1) |
| Rotation du refresh token | l'ancien RT est invalidé à chaque rotation | conforme |
| MFA — 7 patterns du kit | aucun jeton avant la 2FA ; `challengeToken` inutilisable comme jeton ; pas d'oracle de préfixe ; rate-limit ≈ 3-4/60 s ; codes de secours 8 caractères ; `device-code` exigeant une session 2FA ; révocation après usage | tous closed |
| `removeTotpViaToken` | **appelable sans authentification**, renvoie un booléen, **aucune validation de forme** (16 formes testées), rate-limit **5 essais/60 s par IP** (mesuré sur 2 IP en parallèle) | **oracle aveugle, mais non exploitable** (§5.1) |
| Connexion (login) | **« Human verification failed »** → vérification humaine exigée, le mot de passe seul ne suffit pas | conforme |
| `forgotPassword` | idem (anti-bot) | conforme |

### 3.3 Autorisation et données (API GraphQL, balayage 197/198)

| Classe | nb | Lecture |
|---|---|---|
| `OAUTH-BLOCKED` | **125** | toute la surface d'administration et de triage est fermée aux clients OAuth |
| `SCOPE` (scope **nommé** par l'API) | 16 | `triage:read` (6), `triage:write` (2), `grade:write`, `notifications:write` (2), `disclosures:write` (2), `profile:write` |
| `DATA` | 9 | **uniquement mes données** (profil, clés publiques, 4 notifications) ; les autres tableaux sont vides |
| `EMPTY` | 10 | tableaux vides |
| `NOT-FOUND` / `OTHER` | 11 | messages **uniformes** (« You do not have access to this resource », « You can only read your own activity ») → **aucun oracle d'énumération** |
| validation d'entrée | 2 | `RaiseAppeal` (grounds ≥ 20 car.), `SubmitReport` (`clientRequestId` 16-128 car.) |

**Oracle doux par timing : clos.** 12 échantillons × 4 cas : scope manquant 166-182 ms · objet absent
167-184 ms · accès réel 170-180 ms → **aucun écart** → pas d'oracle d'autorisation par latence.

### 3.4 Serveur MCP hébergé (33 outils testés individuellement)

| Résultat | Détail |
|---|---|
| 12 outils exécutés | niveau chercheur, données personnelles uniquement |
| **12 outils refusés en nommant le scope manquant** | `add_triage_comment` (*profile:read triage:write*), `assign_report` (*profile:read triage:read triage:write*), `check_duplicates`/`get_org_report`/`get_org_report_stats`/`get_program_stats`/`list_my_organizations`/`list_org_programs`/`list_org_reports` (*triage:read*), `list_org_certificates` (*profile:read triage:read*), `update_my_profile` (*profile:write*), `update_report_status` (*profile:read triage:read triage:write*) |
| `mark_notifications_read` | `insufficient_scope` |
| `add_report_comment` | « **Nothing was sent yet. This change needs the user's approval on BugSecure** » → le circuit d'approbation est appliqué côté serveur MCP |
| **Anti prompt-injection** | tout contenu non fiable est encapsulé : `<untrusted-content-… source="user:…:username">…</untrusted-content-…>` |
| `User-Agent` obligatoire | sans en-tête `User-Agent` → **403** (conforme à la spec MCP qui l'impose) |
| Audience | jeton `aud=MCP` accepté par `/mcp`, refusé par l'API GraphQL ; jeton `aud=API` l'inverse → **aucune confusion d'audience** |

### 3.5 Injection, uploads, XSS, SSRF, infrastructure

| Contrôle | Mesure | Verdict |
|---|---|---|
| Injection (5 surfaces + différentiels booléens) | paramétrée | non exploitable |
| Uploads | clé S3 `<prefixe>/<uuid>.<ext>` | non exploitable |
| XSS | bio rendue en texte React | non exploitable |
| SSRF `/_next/image` | allowlist, **0 fetch** | non exploitable |
| `avatarUrl` | aucun fetch serveur | non exploitable |
| CORS / Host header / fixation de session | conformes | non exploitable |
| Source maps, specs, staging, session-replay | `maskAllInputs:true`, `streamNetworkBody:false`, sanitizer sur 7 chemins + `/oauth` + `*/callback` + 14 paramètres | non exploitable |
| API de lecture analytics | **39 endpoints** → 401/403 `not_authenticated` ; HogQL 403 ; `/decide` et `/flags` publics mais **vides** (`flags:{}`) ; aucun endpoint de version ; projets valides/invalides → **401 uniforme** | protégée |
| Traversée de chemin sur `/ingest` | 8 variantes (`../`, `%2e%2e`, `..%2f`, `//`, `/./`, `;`) → aucune échappement | non exploitable |
| Binding approbation ↔ arguments | rejeu avec contenu modifié → « *This clientRequestId was already used for a different request* » ; payload identique → idempotent | conforme |

---

## 4. Observations à signaler au vendor (aucune n'est une vulnérabilité)

1. **Auto-inscription ouverte sur l'instance analytics** — `POST /ingest/api/signup` (sous le domaine de
   l'app) crée un utilisateur **et** une organisation sans authentification (HTTP 201). Atténuations
   mesurées : throttle **global de 24 h** (2 IP, 2 emails → `429`) et **validation par email
   obligatoire** (`verify_email_pending`) → l'impact démontré s'arrête à la création de comptes.
   *Recommandation* : désactiver l'auto-inscription sur l'instance self-hosted (PostHog le permet par
   configuration).
2. **`jwks_uri` et `logo_uri` acceptés sans validation** par le serveur d'autorisation — un document
   CIMD peut déclarer un `logo_uri` en `javascript:` ou `data:text/html`, ou un `jwks_uri` vers une
   adresse privée, sans que l'AS ne les refuse. Sans effet aujourd'hui (ni `private_key_jwt`, ni
   rendu du logo non échappé) — mais c'est un **champ non validé**.
3. **`User-Agent` obligatoire sur le serveur MCP** (403 sinon) — conforme à la spec, mais à documenter
   car un client MCP minimal qui l'omet est rejeté sans explication.
4. **Le claim `epoch` n'existe que sur les jetons de session web**, pas sur les access tokens OAuth →
   l'invalidation au reset de mot de passe repose alors sur la révocation du grant, ce qui n'a pas pu
   être validé pour un access token déjà émis (cf. §6.1).
5. **Écran de consentement : message trompeur** — pour une ressource qui n'est pas celle de l'app, la
   page de consentement échoue et affiche « *BugSecure ne reconnaît pas cette application… Code
   d'erreur : invalid_client* », alors que le client **est** reconnu (l'AS a construct la demande).
6. **Dérive du schéma dans le paquet npm `@kulinda-sec/bugsecure-mcp`** (défaut de notre paquet, pas de
   la plateforme) : le schéma embarqué déclare `ReportStatus { CLOSED, DUPLICATE, FIXED, INFORMATIVE,
   IN_FIX, IN_TRIAGE, NEEDS_MORE_INFO, NEW }` alors que **l'API refuse les 8 valeurs** (« *Enum
   "ReportStatus" cannot represent non-enum value* ») et ne donne aucune liste des valeurs possibles
   → les JSON Schema des outils MCP exposent des valeurs inutilisables. *Action* : régénérer le schéma
   depuis l'API (`pnpm prune-schema` + `codegen`) et republier.

---

## 5. Pistes fermées avec preuve (le cœur de la valeur de cette campagne)

### 5.1 Entropie des tokens envoyés par email → **non exploitable**
Les emails « authenticator app enrolled » et « authenticator app removed » ont été analysés : le token
de suppression du 2FA est un **hexadécimal de 64 caractères (256 bits)**, identique au format du token de
réinitialisation de mot de passe, mono-usage, avec une durée de validité annoncée dans l'email.
→ l'oracle non authentifié de `removeTotpViaToken` existe (booléen, 5/min/IP) mais l'espace de
recherche de 10⁶⁴ le rend **hors de portée** → **piste close, non rapportable**.

### 5.2 `jwks_uri` de second ordre → **le mécanisme n'existe pas**
Un document CIMD déclarant `token_endpoint_auth_method: private_key_jwt` est **rejeté**
(`invalid_client`), avec ou sans `jwks_uri` ; le client n'est jamais enregistré (« unknown client ») et
**mon serveur n'a reçu aucune requête** pendant 11 appels au `/oauth/token` dans 5 configurations
(dont `jwks_uri` vers `127.0.0.1:1`, `169.254.169.254`, `10.255.255.1`, `localhost`, un JWKS valide
que je contrôle) → **ni SSRF de second ordre, ni usurpation de client par clé**.

### 5.3 Fédération, alias, batching, GET GraphQL → closed (voir §3.1)
### 5.4 Confusion d'audience API ↔ MCP → closed (voir §3.4)
### 5.5 Oracle de timing → closed (voir §3.3)
### 5.6 API de lecture de l'analytics → protégée (voir §3.5)
### 5.7 IP-littéraux ambigus (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`, `0`, `[::]`,
`[::ffff:7f00:1]`) → tous refusés par la règle « nom DNS public, pas d'IP », avant toute résolution.
### 5.8 `verifyEmail` / `confirmEmailChange` / `exchangeCliSignInCode` sans authentification → renvoient
`"INVALID"` / `false` / « Invalid or expired sign-in code » : **oracle de statut**, mais les tokens
impliqués sont des tokens 256 bits → sans impact.

### 5.9 IDOR inter-comptes → **clos, négatif (avec un vrai second compte)**
Un second compte `COMPANY_ADMIN` a été obtenu pour lever le blocage. Matrice complète : `report(id)`,
`reportComments`, `reportTransitions` du rapport d'un autre compte → « You do not have access to this
report » ; `researcherActivity` → « You can only read your own activity » ; `reports` et `search`
globaux → vides. → **aucun IDOR**, y compris pour un administrateur d'entreprise. C'est aussi la
première fois qu'un contrôle d'autorisation **inter-comptes** est validé par une mesure (et non par
une extrapolation).

---

## 6. Points ouverts

### 6.1 Invalidation partielle des access tokens OAuth (priorité 1)
Protocole : conserver un access token OAuth valide → déclencher un changement de mot de passe →
réutiliser l'**ancien** access token. Le refresh token est bien révoqué (mesuré) ; l'access token ne
porte pas `epoch` → **il faut trancher s'il survit** (fenêtre résiduelle de 10 min après un reset).
*Nécessite* : un changement de mot de passe supplémentaire par le chercheur.

### 6.2 Logique de médiation/paiements — **partiellement close**
Testé avec un second compte `COMPANY_ADMIN` **non membre d'aucune organisation** (le pire cas) :
`payoutSummary`, `reportTrends`, `organizationCertificates`, `severityDistribution` → « You are not a
member of this organization » (message uniforme, y compris pour une organisation inexistante) ;
`organizationStanding` → objet par défaut pour une organisation existante mais « Organization not
found » pour une inexistante → **un seul résolveur fuit l'existence d'une organisation**, sans aucune
donnée sensible et sans intérêt pratique (scope `triage:read` requis, UUID non devinables).
*Il reste à tester* : le cas « membre d'une organisation non vérifiée » (le compte de test n'est
membre d'aucune organisation : l'organisation du programme est gérée par le vendor).

### 6.3 Test multi-A-record du filtre d'IP du chemin CIMD
Le nom de test public (certificat Let's Encrypt valide) et la **baseline** sont en place : le
document est récupéré avec succès (5/5, 185-877 ms) et la requête de l'AS est visible côté OOB
(IP de sortie `52.214.90.218`). *Nécessite* : un second enregistrement A vers `127.0.0.1` pour le nom
de test → mesure de la politique de filtrage sur l'ensemble des adresses résolues.

### 6.4 Rendu de l'écran de consentement (`logo_uri`, HTML dans `client_name`)
L'AS accepte un `logo_uri` arbitraire et du HTML dans le nom ; ce que l'application **rend** reste à
observer. *Nécessite* : l'ouverture des 4 liens de test et le relevé de ce qui est affiché.

---

## 7. Méthode et reproductibilité

- **Moteur d'auto-réparation GraphQL** : à partir des messages d'erreur de l'API (champ inconnu, champ
  requis manquant, type d'entrée erroné, valeur d'enum invalide, opération d'enum invalide), la
  requête est corrigée et rejouée jusqu'à obtenir une réponse d'autorisation exploitable → permet de
  tester **toute** la surface sans deviner les shapes.
- **Balayage complet** : 198 opérations extraites du bundle, 197 couverte avec un jeton valide,
  journal complet et rejouable (`sweep-197.json`).
- **Mesures plutôt que statuts** : chaque contrôle « fermé » repose sur une **mesure** (oracle
  discriminant, latence, capture OOB, message d'erreur nommant le scope, distribution de latences) —
  jamais sur un simple code HTTP.
- **Paires** : DCR vs CIMD (quota), scope vs objet absent vs accès réel (timing), 2 IP en parallèle
  (rate-limit), avec/sans `User-Agent` (serveur MCP), avec/sans claim `epoch` (jetons).
- **Outils** : 64 scripts de campagne, 32 journaux bruts, un dossier de revue zippé.

---

## 8. Leçons (réutilisables sur d'autres programmes)

1. **Cadrer la spécification avant de qualifier.** J'ai écrit « SSRF » là où la spec imposait le
   comportement ; le triage a répondu en quatre lignes et m'a évité un rapport contestable.
2. **Vérifier la documentation du vendor avant de revendiquer un défaut de contrat** (le README du
   client MCP documentait l'inverse de ce que j'allais rapporter).
3. **Un 403 ne prouve rien** ; un « oracle » ne prouve rien non plus s'il est public par design.
4. **Mesurer en apparié** : une comparaison isolée ne montrait rien, une comparaison appariée a
   montré l'écart 0/12 vs 12/12.
5. **Réviser ses propres affirmations publiquement** vaut mieux que les défendre : deux affirmations
   retirées, une fausse conclusion (« fenêtres 404 » du serveur MCP) retirée et corrigée après
   contrôle méthodique — c'est ce qui rend le reste du dossier crédible.
6. **Un correctif accepté n'est pas un correctif vérifié** : deux correctifs re-vérifiés, avec le
   mécanisme exact documenté (`epoch` 0 → 1, « Session ended »).
7. **Sur un programme mature, l'absence de vulnérabilité est un résultat** : le livrable devient la
   cartographie des contrôles et la liste des points à surveiller.

---

---

## 9. Couverture intégrale des demandes des revues croisées (Kimi × 3, Grok × 2)

Légende : **✔ fait & concluant** · **◐ fait & partiellement concluant** · **✖ non testable en l'état** ·
**⏸ en attente d'une action du chercheur** · **— sans objet (déjà couvert)**

### 9.1 Kimi — revue 1 (SSRF/CIMD, P6, P2, 2 nouvelles pistes)

| # | Demande | Statut | Ce qui a été mesuré |
|---|---|---|---|
| 1 | « Le verdict est close, ne te bats pas pour elle » | ✔ | rapport clos en doublon ; **2 surclaims retirés** ; ma réponse au triage est rédigée (`KLDS-REponse-TRIAGE-SSRF-CIMD.md`) mais **non postée**, conformément à la recommandation de ne pas répondre |
| 2 | « Le gap de quota CIMD : laisse-le en observation » | ✔ | mesuré apparié (DCR 0/12 vs CIMD 12/12) et **communiqué au triage** comme observation, sans rapport séparé |
| 3 | P6 (a) lecture de l'API de l'analytics | ✔ | **39 endpoints** → 401/403 `not_authenticated` ; HogQL `count()`/`SELECT 1`/`SELECT *` → 403 ; `Api phc`/`Bearer phc`/`Bearer null`/`undefined`/double en-tête/`X-PostHog-Token`/chemins encodés → **401 partout** |
| 4 | P6 (b) surfaces publiques « à ne pas confondre avec un défaut » | ✔ | `/decide?v=3` et `/flags?v=2` → 200 mais **`flags:{}`**, `sessionRecording:false` ; `/ingest/api/projects` → 401 ; `/ingest/shared_dashboard/<token>` → 404 |
| 5 | P6 (c) différentiel d'erreurs (projet valide vs invalide) | ✔ | **401 uniforme** → aucune énumération de projet |
| 6 | Version de l'instance (CVE < 1.43) | ✔ | aucun endpoint de version exposé (`/ingest/api/instance_status/version`, `/version`, `/status` → 404) → pas de divulgation de version |
| 7 | `/ingest/api/signup` (auto-inscription) | ✔ | **201 Created** (utilisateur + organisation créés sans authentification) **mais** throttle **global 24 h** (2 IP, 2 emails → 429) et validation par email obligatoire → **observation**, pas finding |
| 8 | P2 (a) oracle de format par erreurs | ✔ | 16 formes de token → **toutes `false`**, donc **aucune validation de longueur/charset** ; latences 206-268 ms → **pas d'oracle temporel** ; rate-limit **5 essais/60 s par IP** (mesuré en parallèle sur 2 IP) |
| 9 | P2 (b) le canal reset est-il partagé avec celui du 2FA ? | ◐ | le token de suppression du 2FA est un **hex 64** (256 bits), structurellement identique au token de reset → ce sont des secrets **indépendants**, donc aucun transfert de force ; le test d'usage croisé « un token de 2FAValide réinitialise-t-il le mot de passe ? » n'est **pas testable** faute d'un token de reset vivant (et `removeTotpViaToken` refuse les clients OAuth : « not available to OAuth clients ») |
| 10 | P2 (c) alias Gmail pour un 2ᵉ compte | — | **remplacé** : un 2ᵉ compte a été obtenu (rôle `COMPANY_ADMIN`) → l'IDOR inter-comptes a pu être testé (§3.3) |
| 11 | 4 (a) multi-A-record / DNS rebinding | ⏸ | **baseline complète** : nom public à certificat Let's Encrypt valide, l'AS **fetch le document** (5/5, 185-877 ms), requête OOB visible depuis `52.214.90.218`. Reste à poser le **2ᵉ enregistrement A** vers `127.0.0.1` |
| 12 | 4 (b) paquet npm ≠ dépôt GitHub | ✔ | **0.3.1 publié (19/10) vs dépôt** : **aucun secret figé**, aucun endpoint de staging, dépendances **identiques et épinglées** (`@modelcontextprotocol/server@2.3.1`, `@napi-rs/keyring@2.1.1`, `jose@6.2.12`, `zod@4.6.6`), un seul fichier divergent (`package.json` : build vs source). **En revanche** le schéma embarqué est **périmé** (§4.6) et les **source maps sont publiés** (`dist/**/*.js.map` → le TypeScript est reconstructible) |

### 9.2 Kimi — revue 2 (techniques « inventives »)

| # | Demande | Statut | Ce qui a été mesuré |
|---|---|---|---|
| 13 | §1 double-token race (mutation en parallèle d'un changement d'état) | ⏸ | **non testé** : nécessite un changement d'état déclenché par le chercheur. Le point ouvert n°1 (§6.1) est précisément ce test, ramené à un seul geste : changer le mot de passe pendant que je rejoue un access token |
| 14 | §1 epoch vs audience (réutiliser un `challengeToken` comme access token) | ✔ | clos dans la campagne (7 patterns MFA) : `challengeToken` inutilisable comme jeton, `aud:"mfa-challenge"`, `jti` à usage unique. **Non re-testable** : le 2FA a été supprimé du compte de test |
| 15 | §1 refresh → access token portant un ancien epoch | ✔ | **la question n'a pas lieu d'être** : les access tokens OAuth **ne portent pas** de claim `epoch` (claims : `aud, client_id, exp, grant_id, iat, iss, jti, scope, sub`) ; l'invalidation passe par la révocation du grant (le RT est bien révoqué par le changement de mot de passe) |
| 16 | §2 alias + batch + « deferred privilege escalation » | ✔ | `@include`/`@skip` → erreur de validation **identique** dans les 8 variantes ; `@defer`/`@stream` → « Unknown directive » ; **plafond de 15 alias** ; mutation+query dans un même document → refusé ; requêtes mixtes public/privé → refusées |
| 17 | §3 confusion de type / smuggling sur `tools/call` | ✔ | **20 payloads** : `arguments` en chaîne / tableau / `null` → `-32602 invalid_type` (schéma strict) ; nom d'outil avec octet nul / confusable Unicode / majuscules → « Tool not found » ; **double `name`** → le dernier l'emporte (parsing JSON standard, aucun gain) ; `__proto__` → « **Tool __proto__ disabled** » (pollution de prototype explicitement bloquée) ; champs non déclarés (`__proto__`, `constructor.prototype`) → **ignorés** ; mutation GraphQL en cascade dans un argument → traitée comme une chaîne ; `tools/call` imbriqué → idem ; `resources/read`, `completion/complete`, `prompts/get`, `logging/setLevel` → « Method not found » ; le **circuit d'approbation** reste appliqué |
| 18 | §4 (a) course de swap du document CIMD | ◐ | **l'AS met en cache le document** : **un seul fetch par `client_id`** (observé : 1 fetch pour `swap.json`, puis 6 `authorize` sans nouveau fetch) → **la course TOCTOU côté AS est impossible** (l'AS valide toujours la version qu'il a récupérée). Reste à vérifier ce que **l'app** affiche (elle peut récupérer le document séparément) → 4 liens de test fournis, à ouvrir |
| 19 | §4 (b) confusion client enregistré (DCR) vs client dynamique (CIMD) | ✔ | `POST /oauth/register` → 201 `dcr_Ty2A6_…` ; `authorize` avec ce `client_id` → consentement ; **le même `client_id` avec le `redirect_uri` d'un autre client** → `invalid_redirect_uri` → aucune confusion |
| 20 | §4 (c) confusion PKCE + state / binding | ✔ | 20 variantes : `state` (300 car. OK, 2000 car. → 403 WAF, caractères spéciaux → 403) ; `code_challenge` S256 erroné → vérifié au `/oauth/token` uniquement (conforme) ; `plain`/absent → `invalid_request` ; `redirect_uri` (fragment, slash, majuscules, port différent) → `invalid_redirect_uri` ; `client_id` (espace, casse) → `invalid_client` ; `scope` inconnu → `invalid_scope` ; `resource` dupliqué → `invalid_target` |
| 21 | §5 rejeu/downgrade du `challengeToken` | ✔ | clos (7 patterns MFA) ; non re-testable (2FA supprimé) |
| 22 | §6 oracle doux (messages + timing) | ✔ | **aucun oracle de timing** (15 combinaisons, 165-186 ms) ; côté messages, un seul résolveur fuit l'existence d'une organisation (`organizationStanding`) → **observation**, portée nulle (§3.3) |

### 9.3 Grok — message 1 (6 familles) et message 2 (tableau des techniques)

| # | Demande | Statut | Ce qui a été mesuré |
|---|---|---|---|
| 23 | Epoch confusion / partial invalidation race | ⏸ | **c'est le point ouvert n°1** (§6.1) — le seul geste manquant : un changement de mot de passe |
| 24 | GraphQL alias + batch + directives | ✔ | idem ligne 16 |
| 25 | MCP tool call type confusion | ✔ | idem ligne 17 (20 payloads) |
| 26 | OAuth / CIMD advanced confusion | ✔ | idem lignes 18-20 |
| 27 | MFA challenge replay & downgrade | ✔ | clos (7 patterns) |
| 28 | Soft authorization oracle | ✔ | idem ligne 22 |
| 29 | GraphQL cache deception (`GET /graphql?query=…`) | ✔ | **bloqué par la prévention CSRF d'Apollo** (« This operation has been blocked as a potential Cross-Site Request Forgery ») |
| 30 | Entropie des codes de récupération (`generateBackupCodes`) | ✖ | **non testable** : le 2FA a été supprimé du compte de test et `generateBackupCodes` exige une session 2FA active. Reste à faire si le 2FA est réactivé (le contrôle des codes de secours — usage unique, ré-émission sans ré-authentification — n'a donc **pas** été validé) |
| 31 | Injection CRLF dans le nom d'organisation (en-tête d'email) | ✖ | **non testable** : le compte de test n'est membre d'aucune organisation (l'organisation du programme est gérée par le vendor) ; le point d'entrée (`updateOrganization`) est hors de portée de mon compte |
| 32 | Injection HogQL | ✔ | l'API de lecture est protégée (403) → aucun dialecte injectable |
| 33 | Paquet npm ≠ dépôt | ✔ | idem ligne 12 |
| 34 | Account linking social (pré-hijacking) | ◐ | **inventorié** : le bundle expose `CompleteGithubLink`, `UnlinkGithub`, `UnlinkDiscord` (et `DiscordLinkedRolesUrl`) → le mécanisme de liaison existe, mais le test de pré-hijacking (Agrawal 2023) exige de créer un compte social avec l'email d'une victime → **non testable dans ce cadre** ; à instruire si un compte social de test est disponible |
| 35 | Race/timing sur les mutations d'identité | ⏸ | idem ligne 13 (le même geste) |
| 36 | `tools/call` avec `name` en octet nul / confusable / double | ✔ | idem ligne 17 |
| 37 | Bascule DCR ↔ CIMD, document dynamique | ✔ | idem lignes 18-19 |

### 9.4 Ce que j'ai trouvé **en dehors** des propositions des deux revues

| Découverte | Nature | Suite |
|---|---|---|
| `removeTotpViaToken` appelable **sans authentification**, booléen, sans validation de forme | oracle aveugle | **fermée** par la mesure d'entropie (token 256 bits) — signalée comme observation de conception |
| **IDOR inter-comptes** : testé pour la première fois avec un vrai 2ᵉ compte `COMPANY_ADMIN` | contrôle | **clos négatif** |
| `organizationStanding` : soft-fail + oracle d'existence | observation | documentée |
| Schéma `ReportStatus` du paquet publié **périmé** (les 8 valeurs refusées par l'API) | défaut de notre paquet | à régénérer et republier |
| Auto-inscription ouverte sur l'instance analytics | observation (24 h de throttle) | documentée |
| `logo_uri` / `jwks_uri` acceptés **sans validation** par l'AS | observation | documentée |
| `epoch` confirmé comme le mécanisme du correctif « password reset » (0 → 1) | re-vérification | documentée |
| Rotation des refresh tokens + révocation de famille | re-vérification | documentée |
| 33 outils MCP : enforcement des scopes **par outil**, circuit d'approbation appliqué, **contenu non fiable encapsulé** | contrôle | documenté (contrôles positifs remarquables) |
| Cloisonnement des audiences API ↔ MCP dans les deux sens | contrôle | documenté |
| Balayage complet 197/198 avec un jeton valide | couverture | documenté |

---

## 10. Ce qui n'a **pas** été fait, et pourquoi (transparence)

| Non fait | Raison | Ce qu'il faudrait |
|---|---|---|
| Réponse au triage postée | le rapport est clos ; Kimi recommande de ne pas répondre (ou un simple « cadrage reçu ») ; le brouillon est prêt si tu veux l'envoyer | ton feu vert |
| **IDOR inter-comptes** | ~~abandonné~~ → **fait** (2ᵉ compte obtenu) | rien |
| **Entropie des tokens emailés** | ~~bloqué~~ → **fait** (les 2 emails analysés) | rien |
| **Entropie des codes de récupération (2FA)** | le 2FA a été **supprimé** du compte de test | ré-activer le 2FA (et ré-mesurer : usage unique ? ré-émission sans ré-auth ?) |
| **Injection CRLF via le nom d'organisation** | le compte de test n'est membre d'aucune organisation | une organisation de test dont on contrôle le nom |
| **Account linking social (pré-hijacking)** | exige un compte GitHub/Discord de test avec l'email d'une victime | un compte social de test |
| **Test multi-A-record** | il manque le 2ᵉ enregistrement A (DNS) | 1 enregistrement DNS |
| **Invalidation partielle des access tokens OAuth** | il faut un changement de mot de passe pendant que je rejoue un access token | 1 changement de mot de passe |
| **Rendu de l'écran de consentement** (`logo_uri`, HTML dans le nom) | l'AS accepte ces valeurs ; c'est **l'app** qu'il faut observer | ouvrir 4 liens et relever ce qui s'affiche |
| **Exfiltration de données via les replays PostHog** | l'API de lecture est protégée (401/403) et l'auto-inscription est throttlée ; la lecture exigerait un compte PostHog vérifié (24 h d'attente) | un compte PostHog vérifié (ou unenight d'attente) |
| **Membership réel d'une organisation** | l'organisation du programme est gérée par le vendor | une organisation de test du chercheur |
| Suppression de l'infra de test (`bb-test.enseignementsecondaire.bj`, Caddy, listener) | encore utile pour les 2 tests en attente | ton feu vert (2 commandes) |

---

## 11. Déroulé de la campagne (pour situer chaque action)

| Phase | Contenu |
|---|---|
| **J1 — cadrage** | lecture de la spec CIMD, mise en place de l'infrastructure de test (listener OOB + tunnel), inventaire des 198 opérations de l'API, 1ᵉʳᵉ lot de contrôles (OAuth/AS, JWT, autorisation, injection, uploads, XSS, SSRF) |
| **J1 soir — découverte** | le chemin CIMD n'applique aucun quota (DCR 0/12 vs CIMD 12/12) ; l'API de lecture de l'analytics est protégée ; premier rapport rédigé |
| **J2 — revues croisées** | 2 revues (Kimi, Grok) → 2 surclaims retirés, ~15 nouvelles pistes ; le rapport est clos en doublon (CIMD normatif) |
| **J2 — correctifs re-vérifiés** | invalidation au reset de mot de passe (conformité, mécanisme `epoch` 0→1), rotation des refresh tokens, binding approbation↔arguments, 7 patterns MFA |
| **J2 — surface non authentifiée** | 39 routes `/api/*`, introspection, traversée de chemin, métadonnées MCP/AS, `removeTotpViaToken` non authentifié + rate-limit mesuré, auto-inscription PostHog |
| **J2 — 3ᵉ revue (Grok)** | techniques « inventives » : directives, alias, batching, timing, binding `authorize`, `jwks_uri` de 2ᵉ ordre → 6 angles clos + 2 trouvailles |
| **J2 — infrastructure** | ouverture du pare-feu `ufw`, Caddy en conteneur, certificat Let's Encrypt, document CIMD servi sur un nom public valide, preuve OOB de l'AS |
| **J3 — surfaces fermées** | balayage 197/198 avec jeton valide ; 33 outils MCP testés individuellement (enforcement des scopes, circuit d'approbation, anti prompt-injection) ; 2ᵉ compte → matrice IDOR négative ; soft-fail `organizationStanding` ; diff npm ; confusion de type MCP ; course de swap (cache de l'AS) ; confusion DCR/CIMD |
| **J3 — restitution** | rapport de campagne complet (§1 à §11), note de vérification, dossier de revue zippé, brief pour les revues |

---

*Ce document est le livrable de campagne : il couvre **tout** ce qui a été demandé par les revues
croisées, **tout** ce qui a été fait, **tout** ce qui a été découvert, et **tout** ce qui n'a pas pu
être fait — avec, pour chaque ligne, la mesure correspondante dans les 32 journaux bruts et les
64 scripts du dossier de revue.*

*Aucun élément de ce document n'a été inventé : chaque affirmation renvoie à une mesure reproductible
figée dans les journaux bruts (32 fichiers) et les scripts (60 fichiers) du dossier de revue.*
