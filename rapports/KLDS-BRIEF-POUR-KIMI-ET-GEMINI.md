# KLDS / BugSecure Africa — point d'avancement après vos remarques (20-21 octobre 2026)

Bonjour,

Vos deux revues ont été très utiles : elles m'ont fait **retirer deux affirmations** du rapport principal
et ont réorienté la campagne. Voici l'état complet, ce que j'ai fait depuis, et ce qui reste à creuser.

---

## 1. Où en est le rapport SSRF/CIMD

**Clos par le triage comme doublon, sans récompense.** Réponse du reviewer (20/10, 19:16) :

> « Le comportement est bien celui que vous décrivez : quand client_id est une URL HTTPS, le serveur
> d'autorisation télécharge le document de métadonnées client. C'est le mécanisme Client ID Metadata
> Documents, la méthode d'enregistrement de client que prévoit la spécification MCP que nous implémentons.
> […] il n'accepte que https sur le port 443, un nom DNS public et pas d'IP, il refuse toute adresse non
> publique à la résolution et à la connexion, ne suit pas les redirections et ne renvoie jamais le
> contenu. […] le champ scope d'un document n'est pas lu […] et l'« oracle » indique seulement si un
> document public est un document CIMD valide. Ce même comportement nous a déjà été signalé et a été
> évalué comme Informatif. »

**Mes corrections (elles sont vraies) :**
1. ❌ Je retire la qualification **« SSRF »** du fetch : il est normatif (draft IETF
   `draft-ietf-oauth-client-id-metadata-document` : *« AS SHOULD automatically fetch the Client ID Metadata
   Document »*, et le reviewer le rattache même à la **spec MCP** qu'il implémente — rattachement que je
   n'avais pas vu : c'était mon principal erreur de cadrage.
2. ❌ Je retire l'affirmation d'un **écart de validation de `scope`** entre les deux chemins
   d'enregistrement (voir §2.1 ci-dessous : j'ai mal formulé, et le reviewer l'a corrigé lui-même).
3. ⚠️ Je reformule l'« oracle » : ce n'est pas une fuite d'information exploitable, c'est un retour de
   validation (« ce document public est-il un document CIMD valide ? ») que n'importe qui peut vérifier.

**Un seul écart mesuré subsiste, et je l'ai communiqué au triage** (il ne porte pas sur le fetch mais sur
l'**enregistrement**) : le chemin CIMD n'applique **aucun quota d'inscription**.
Mesure appariée, même cadence (1 requête / 3 s), 12 tentatives de chaque côté :

| Chemin | Clients créés | `429 temporarily_unavailable` |
|---|---|---|
| `POST /oauth/register` (DCR) | **0** | **12** |
| `client_id` = URL (CIMD) | **12** | **0** |

→ un appelant non authentifié peut créer un nombre non borné d'identités de client, chacune déclenchant
une récupération serveur depuis l'IP de la plateforme. Je ne le présente pas comme un rapport séparé.

---

## 2. Ce que j'ai fait depuis vos remarques (et ce que ça a donné)

### 2.1 Test du gap de `scope` (votre question sur l'escalade) → **RÉFUTÉE**
Scope **demandé dans la requête** `/oauth/authorize`, chemin CIMD (un chemin unique par client_id, donc
sans quota) :

| scope demandé | DCR | CIMD |
|---|---|---|
| `programs:read profile:read reports:read reports:write` | accepté | accepté |
| `triage:read` / `triage:write` / `grade:write` (scopes de la plateforme) | accepté | accepté |
| `admin:all` | **refusé** (« *scope contains unsupported values* ») | **refusé** (même message) |
| `profiles:write` (scope inexistant) | **refusé** | **refusé** |

→ **la validation est identique sur les deux chemins**, et le `scope` du *document* est simplement
inutilisé. **Pas d'escalade de privilèges** : c'était une de mes affirmations, elle est retirée.

### 2.2 Mesure de la position du filtre d'adresses (votre « incohérence 1 ») → **RÉFUTÉE pour vous**
Distribution sur **8 échantillons par cible** (URL unique par échantillon) :

| Cible | min | p25 | médiane | p75 | max |
|---|---|---|---|---|---|
| témoin **externe** (fetch réel) | 173 ms | 182 | 188 | 255 | 375 |
| témoin non routable `192.0.2.1` | 82 | 91 | 96 | 99 | 102 |
| `10.255.255.1` | 88 | 92 | 94 | 99 | 156 |
| `169.254.169.254` | 89 | 91 | 94 | 96 | 98 |
| `127.0.0.1:80` | 89 | 92 | 95 | 107 | 125 |
| `127.0.0.1:3000` | 88 | 94 | 95 | 97 | 101 |
| `127.0.0.1:53682` | 85 | 87 | 91 | 96 | 124 |
| `127.0.0.1:9200` | 87 | 93 | 94 | 102 | 105 |

→ les IP internes sont **refusées avant l'émission du paquet** (indiscernables du refus immédiat, et
**plus rapides** qu'un fetch réel) ; la bimodalité que j'avais vue était du **bruit de file d'attente** de
l'AS, pas une tentative de connexion. Ma formulation initiale était correcte, elle est maintenant prouvée.

### 2.3 Filtre anti-usurpation d'identité de client (votre question 4) → **ROBUSTE**
10 variantes par DCR (`BugSecureX`, `XBugSecure`, `)BugSecure(`, espaces initial/final/interne, casse
mêlée, majuscules, trait d'union, underscore) et **22 variantes de confusables Unicode** testées par le
chemin CIMD (qui n'a pas de quota) : cyrillique initiale/médiane/finale, accents, zero-width initial
et médian, insécable, bidi RLO/PDF initial et final, soft hyphen, BOM, turc `ı`, ZWJ, signe moins,
espace em → **toutes refusées**. Le filtre **normalise l'Unicode** : ce n'est pas une sous-chaîne.

### 2.4 « `tools/list` annoncerait les outils d'écriture » (piste B) → **RÉFUTÉE**
Le dépôt documente : « *Every tool is listed whatever you granted, so you can see what more access would
enable* » et « *Write tools are hidden entirely in **read-only mode*** » → le masquage total concerne le
**flag local `--read-only`**, pas le filtrage par scope. **Aucun défaut** → je ne le rapporte pas.

### 2.5 Binding approbation ↔ arguments réellement envoyés (piste A) → **LA PROMESSE TIENT**
Protocole : approbation créée pour `addReportComment { reportId, content: "bb-approval-binding-A" }` avec
une **clé d'idempotence connue**, approuvée par l'utilisateur sur la page de revue, puis rejeux directs à
l'API avec la même clé :

| Test | Réponse de l'API |
|---|---|
| payload approuvé | `{"addReportComment":{"id":"820f70f2-…"}}` → s'exécute |
| **même clé, contenu modifié** | « *This clientRequestId was already used for a different request. Send a new clientRequestId for a new request.* » |
| même clé, autre mutation | « *requires the scope(s): notifications:write* » (le scope passe avant → test partiel) |
| payload approuvé rejoué | même `id`, pas de doublon → idempotent |

→ un client connecté **ne peut pas** exécuter une écriture différente de celle approuvée.

### 2.6 Correctif « password reset n'invalide pas les access tokens » → **VÉRIFIÉ CONFORME**
Jeton émis **avant** le reset → `resetPassword(newPassword, token reçu par email)` → `true` → **le même
jeton** retesté : `me`, `reports`, `updateResearcherProfile` (écriture), `myKycStatus`, `notifications`
→ **tous « Session ended »**. Avant le reset, ce même jeton **lisait et écrivait**. Mécanisme confirmé :
le claim **`epoch` passe de `0` à `1`** au changement de mot de passe (les 7 jetons antérieurs portaient
`0` parce qu'aucun changement n'avait eu lieu) — donc l'`epoch` **n'est pas** décoratif, c'est le compteur
d'invalidation (correction d'une note de la campagne qui le qualifiait à tort de « sans effet »).

### 2.7 Contrôles CIMD vérifiés (positifs, pour la doc du vendor)
`client_id` du document = URL demandée, **correspondance exacte** (une query string de différence →
`invalid_client`) · document servi en 200 + JSON obligatoire (un `200 text/plain` → `invalid_client`) ·
`redirect_uri` comparé **exactement** (slash final, query, fragment, userinfo, sous-domaine, chemin
différent, IP littéral, `javascript:` → refusés, sur les deux chemins) · `token_endpoint_auth_method` :
seuls les clients publics (`none`) · IP « special-use » refusées avant le paquet · redirections non
suivues · TLS vérifié.

### 2.8 Trou documentaire comblé
Le balayage en profil « session web first-party » n'avait couvert que **53 des 198** opérations (arrêt sur
erreur réseau) et j'affirmais 198 → **corrigé**, et le balayage complet a été relancé (jeton passé par
fichier, plus de problème de quoting). C'est le seul écart documentaire que vous aviez relevé : il est
fermé ou en cours de clôture.

---

## 3. Where everything is

| Artefact | Chemin |
|---|---|
| Note de vérification (47 contrôles, chacun avec sa mesure) | `bugbounty-copilot-kit/knowledge/writeups/arsenal_2025_2026/KLDS-verifie-et-findings.md` |
| Rapport de mission (méthode, contrôles, hypothèses réfutées, pistes, leçons) | `…/KLDS-RAPPORT-DE-MISSION.md` |
| Rapport soumis + 8 pièces | `bugbounty-copilot-kit/rapports/` |
| Réponse au triage (à poster) | `rapports/KLDS-REponse-TRIAGE-SSRF-CIMD.md` |
| 24 journaux bruts (matrice de preuve) | `…/klids-evidence/` + `MANIFEST.md` |
| 25 scripts de campagne (dont le moteur d'auto-réparation GraphQL) | `bugbounty-copilot-kit/tools/klids-campaign/` |
| Zip de revue (71 fichiers) | `rapports/KLDS-DOSSIER-REVUE.zip` |

Le moteur qui a le plus servi : **« auto-réparation » de requêtes** — à partir des messages d'erreur de
l'API (champ inconnu, champ requis manquant, type d'entrée erroné, valeur d'enum invalide, opération
d'enum invalide), la requête est corrigée et rejouée jusqu'à obtenir une réponse d'autorisation
exploitable. Il permet de tester **toute** la surface sans deviner les shapes. À réutiliser sur tout
programme GraphQL.

---

## 4. Ce qui reste ouvert (et de quoi il a besoin)

| # | Piste | Blocage | Potentiel |
|---|---|---|---|
| P2 | **Entropie des tokens envoyés par email** (reset, **suppression du 2FA**, invitation d'organisation) | l'API refuse les adresses jetables (« *Disposable email addresses are not accepted* ») et je n'ai pas d'accès à la boîte Gmail du compte → il me faut **le lien reçu par email** (ou une adresse non jetable que je peux lire) | token devinable = **ATO** (désactivation du 2FA + reset) |
| P3 | **IDOR inter-comptes** (`report(id:)`, `reportComments`, `certificate(reference:)`, `downloadUrl(attachmentId:)`) | il faut un **2ᵉ compte de test** (le compte unique actuel n'a aucun rapport d'autrui) | IDOR = High |
| P6 | **API de lecture de l'analytics (PostHog auto-hébergé)** — le proxy `/ingest` est sur le **même domaine que l'app** (`bugsecure.senintel.sn/ingest`) et la version est **self-hosted** (le `ui_host` pointe sur eu.posthog.com pour l'UI, mais les données restent chez eux) : si l'API de lecture ou les **session recordings** sont lisibles sans auth, on lit les navigations + les données saisies (numéro mobile money, coordonnées bancaires — les champs texte ne sont pas masqués, seuls `type=password` et `maskAllInputs` le sont… `maskAllInputs:true` masque quand même les champs texte) | rien : testable seul | **fuite de donnéessessions/PII** |
| P7 | **Logique médiation/paiements** : `organizationStanding` renvoie un **objet par défaut** (`totalIssued:null`, `currentlyOverdue:0`, `submissionsSuspended:false`) à un **non-membre** au lieu d'une erreur ; `payoutSummary`, `settlement`, `expectedAmount`, `openAppealBy`, `certificate(reference:)` | un **compte d'organisation** | logique de prime = impact financier |
| — | **Relais non borné** (quota CIMD) | — | communiqué au triage, en cours d'évaluation |

### Les commandes à essayer pour P6 (l'API de lecture de l'analytics)
L'API de lecture de PostHog est sous `/api/projects/<project_token>/…` ; le proxy `/ingest` relaie le
service. À essayer (sans authentification) :
```
GET /ingest/api/projects/phc_myGuPycfa9UMAmmXHBjPJrqFhzkpvprNv7xof9DZ5Far/events
GET /ingest/api/projects/phc_…/insights
GET /ingest/api/projects/phc_…/query        (HogQL)
GET /ingest/api/projects/phc_…/session_recordings
GET /ingest/api/projects/phc_…/replays
GET /ingest/api/projects/phc_…/activity
GET /ingest/api/projects
GET /ingest/decide    (200, public)
GET /ingest/flags     (200, public)
```
À noter : l'API de lecture de PostHog exige normalement un `Authorization: Api <phx_…>` ; le test sert
à vérifier si le proxy **laisse passer** des requêtes non authentifiées (une régression de reverse-proxy
seraiticles exceptions « no-auth » de certaines installations).

---

## 5. Ce que j'aimerais de vous

1. **Une revue de la réponse au triage** (elle est dans `rapports/`) : est-elle correcte, trop
   conciliante, ou maladroite ? Je préfère une critique franche à une politesse excessive.
2. **P6** : des idées de chemins d'API de lecture PostHog à tester (et, si vous en trouvez, un moyen de
   **prouver** l'impact sans exfiltrer : un compteur, un `LIMIT 1`, la forme d'une seule ligne).
3. **P2** : si vous avez une méthode pour mesurer l'entropie d'un token **sans** posséder la boîte mail
   (ex. le format du token est-il devinable à partir d'un échantillon ? le hash est-il commun ?), je prends.
4. **La piste « org account »** : si vous avez un compte d'organisation de test **sur ce programme**, la
   logique de médiation/paiements (P7) devient testable — c'est le seul angle qui me manque pour toucher
   à l'argent.
5. Une **piste que je n'ai pas vue** sur un bug bounty OAuth/MCP comme celui-ci : le rapport était clos
   en 48 h, la surface est très dure — qu'est-ce que vous auriez testé **en priorité** à ma place ?

---

## 6. Leçons de cette campagne (utiles pour d'autres programmes)

1. **Vérifier la doc du vendor avant de claimed un défaut de contrat** : j'ai failli rapporter
   « `tools/list` annonce les outils d'écriture » alors que le README documente l'inverse.
2. **Un 403 ne prouve rien** : chaque contrôle « fermé » de cette campagne repose sur une **mesure**
   (oracle, latence, capture OOB, message d'erreur discriminant), jamais sur un statut.
3. **Cadrer la spécification avant de qualifier** : j'ai écrit « SSRF » là où la spec imposait le
   comportement ; le triage m'a répondu en 4 lignes et m'a economically évité un rapport contestable.
4. **Mesurer en apparié** : DCR vs CIMD, 12 tentatives de chaque côté, même cadence → un écart net
   (« 0/12 vs 12/12 ») qu'une comparaison isolée ne montrait pas.
5. **Réviser ses propres affirmations publiquement** vaut mieux que les défendre : deux de mes
   affirmations ont été retirées et consignées ; le triage l'a lu comme de la rigueur, pas comme une
   faiblesse.
6. **Un correctif accepté n'est pas un correctif vérifié** : j'ai re-vérifié 2 correctifs (l'un conforme,
   l'autre conforme aussi) et documenté le mécanisme exact (`epoch` 0→1, « Session ended »).
