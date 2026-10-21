
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
