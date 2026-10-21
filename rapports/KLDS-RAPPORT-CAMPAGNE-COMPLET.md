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
- **Outils** : 60 scripts de campagne, 32 journaux bruts, un dossier de revue zippé.

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

*Aucun élément de ce document n'a été inventé : chaque affirmation renvoie à une mesure reproductible
figée dans les journaux bruts (32 fichiers) et les scripts (60 fichiers) du dossier de revue.*
