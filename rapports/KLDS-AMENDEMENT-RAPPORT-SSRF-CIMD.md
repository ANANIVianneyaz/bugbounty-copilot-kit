# Amendement au rapport « fetch serveur via `client_id` (CIMD) » — à poster en commentaire sur le rapport

*Destiné au triage BugSecure. Après relecture croisée (deux modèles indépendants), je **retire deux
affirmations de mon rapport initial** et je **maintiens une seule** observation, désormais quantifiée.
Le reste (preuves, reproduction, captures) est inchangé.*

---

## 1. Ce que je retire de mon rapport initial

### 1.1 Je retire la qualification « SSRF » du fetch lui-même

La récupération du document distant est **normative** : le draft IETF
`draft-ietf-oauth-client-id-metadata-document` écrit « *Authorization servers **SHOULD** automatically
fetch the Client ID Metadata Document* », et le même draft impose de ne pas récupérer d'URL pointant vers
des IP « special-use » (RFC 6890) et de ne pas suivre les redirections.

**Votre AS met ces mitigations en place**, et j'ai mesuré qu'elles sont efficaces :

| Exigence du draft | Votre AS | Mesure (8 échantillons par cible) |
|---|---|---|
| ne pas récupérer d'URL « special-use IP » | conforme | les cibles internes sont **refusées avant l'émission du paquet** (min 85-89 ms, max 98-156 ms), indiscernables d'un témoin non routable (`192.0.2.1` : min 82 / max 102) et **plus rapides** qu'un témoin externe qui, lui, effectue réellement le fetch (min 173 ms) |
| ne pas suivre les redirections | conforme | un redirecteur public → `302` vers mon serveur : **le second saut n'a jamais atteint la cible** |
| TLS vérifié | conforme | un certificat auto-signé est **refusé** |
| le document doit être servi en `200` + JSON | conforme | un `200 text/plain` est refusé (`invalid_client`) |
| le `client_id` du document doit **correspondre exactement** à l'URL | conforme | une différence d'un seul caractère (query string) → `invalid_client` |
| comparaison **de chaîne simple** des `redirect_uri` | conforme | slash final, query, fragment, userinfo, sous-domaine, chemin différent, IP littéral, `javascript:` → tous refusés, sur les deux chemins |

### 1.2 Je retire l'affirmation « le chemin CIMD contourne la validation des `scope` »

J'affirmais que le chemin CIMD n'appliquait pas le filtrage des scopes. **C'est faux**, et j'airefait le
test proprement (scope **demandé dans la requête d'autorisation**, chemin CIMD) :

| `scope` demandé | DCR | CIMD |
|---|---|---|
| `programs:read profile:read reports:read reports:write` | accepté | accepté |
| `triage:read` (scope d'organisation) | accepté | accepté |
| `triage:write` | accepté | accepté |
| `grade:write` | accepté | accepté |
| `admin:all` | **refusé** (« *scope contains unsupported values* ») | **refusé** (même message) |
| `profiles:write` (scope inexistant) | **refusé** | **refusé** (même message) |

→ la validation est **identique** sur les deux chemins ; le champ `scope` du document distant est
simplement **inutilisé** (c'est le scope de la requête qui fait foi). **Il n'y a donc pas d'escalade de
privilèges** : je retire ce point.

---

## 2. Ce que je maintiens (quantifié)

**Un appelant non authentifié peut créer un nombre non borné d'identités de client, chacune déclenchant
une récupération serveur d'une URL de son choix, depuis l'IP de la plateforme, sans limite de débit.**

Mesure appariée, même cadence (1 requête / 3 s), 12 tentatives de chaque côté :

| Chemin | Clients créés | Réponses de quota (`429 temporarily_unavailable`) |
|---|---|---|
| `POST /oauth/register` (DCR) | **0** | **12** |
| `client_id` = URL (CIMD) | **12** | **0** |

Autrement dit : le chemin d'enregistrement classique est plafonné, le chemin CIMD ne l'est pas — et
chaque client CIMD validé correspond à **une requête HTTP sortante** vers l'URL choisie par l'appelant,
émise depuis `52.214.90.218` avec l'agent `BugSecure-OAuth/1 (+client-id-metadata-document)`
(capture dans le rapport, 44 requêtes observées).

**Impact que je revendique** : la plateforme peut servir de **relais de récupération d'URL non
authentifié et non plafonné**, avec sa propre adresse IP et sa réputation (listes d'autorisation d'IP
tierces contournées, requêtes attribuables à BugSecure, spam de requêtes sortantes) ; et le registre
d'identités de client peut être saturé de clients factices.

**Impact que je ne revendique pas** : aucune lecture de donnée (les IP « special-use » sont refusées avant
connexion), aucune escalade de privilèges (les scopes sont validés à l'identique et filtrés à l'émission),
aucune usurpation d'identité de client (le filtre anti-usurpation est robuste — voir §3), aucun accès
inter-organisation (les contrôles d'appartenance sont appliqués).

**Sévérité** : je propose désormais **Faible** (le fetch est normatif et mitigé ; ce qui subsiste est
l'absence de quota sur un chemin d'enregistrement). Je peux descendre à **Informatif** si vous jugez que
c'est une simple defense en profondeur. **Si vous préférez, retirez le rapport** : la valeur restante
tient dans le §3 (des contrôles confirmés comme corrects), qui peut vous être utile pour votre
documentation.

---

## 3. Contrôles que j'ai vérifiés et qui sont corrects (valeur pour vous)

- **Filtre anti-usurpation d'identité de client** : 10 variantes par DCR (`BugSecureX`, `XBugSecure`,
  `)BugSecure(`, espaces initial/final/interne, casse mélée, majuscules, trait d'union, underscore) et
  **22 variantes de confusables Unicode par le chemin CIMD** (cyrillique initiale/médiane/finale, accents,
  zero-width initial et médian, insécable, bidi RLO/PDF initial et final, soft hyphen, BOM, turc
  `ı` sans point, ZWJ, signe moins, espace em) → **toutes refusées**. Le filtre normalise l'Unicode :
  ce n'est pas une recherche de sous-chaîne.
- **PKCE** : `code_challenge_method=S256` obligatoire ; `plain`, absent ou malformé → refusés.
- **Code d'autorisation** : usage unique. **Refresh token** : rotation stricte, famille révoquée en cas de
  rejeu, `client_id` et `resource` vérifiés.
- **`token-exchange` et `client_credentials`** : refusés (y compris pour un client CIMD).
- **Auto-approbation** : `decideAgentApproval` et `decideOAuthAuthorization` refusés aux clients OAuth ;
  `createAgentApproval` exige le scope d'écriture de l'opération concernée.
- **MFA (les 7 patterns)** : `login` ne renvoie **aucun jeton** avant la 2FA ; le `challengeToken` n'est
  pas utilisable comme jeton d'accès ; pas d'oracle de préfixe sur le code TOTP ; rate-limit d'environ
  3-4 tentatives / 60 s ; les codes de secours font 8 caractères ; le flux device-code exige une session
  2FA vérifiée.
- **Isolation des données** : énumération des références de certificat impossible (réponse `Unauthorized`
  uniforme, y compris pour une référence inexistante) ; `sharedFinding` uniforme ; rapports, commentaires,
  transitions, adjudication, appels et brouillons : `Unauthorized` ; `researcherActivity` d'autrui refusée ;
  surface admin et operations « argent » refusées aux clients OAuth.

---

## 4. Correctifs proposés (par ordre de priorité)

1. **Aligner le chemin CIMD sur le chemin DCR** : même quota d'enregistrement / de débit de
   récupération. C'est le seul écart que je:maintiens.
2. Conserver les mitigations déjà en place (IP « special-use » refusées **avant** la connexion, pas de
   redirection, TLS vérifié, `client_id` à correspondance exacte, filtre de nom) : elles fonctionnent, et
   la distribution de latence du §1.1 le démontre.
3. Éventuellement : plafonner le débit de **récupération** de document par IP indépendamment de la
   création de client, et journaliser les URL récupérées avec l'IP résolue.
