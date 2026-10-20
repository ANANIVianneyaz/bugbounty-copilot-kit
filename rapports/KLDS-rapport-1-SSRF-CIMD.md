# Rapport 1 — SSRF non authentifié sur le serveur d'autorisation OAuth (chemin CIMD)

**Programme** : KLDS — Web & API (BugSecure Africa)
**Cible** : `https://bugsecure-api.senintel.sn` (serveur d'autorisation OAuth 2.1)
**Classe** : CWE-918 — SSRF (Server-Side Request Forgery) / fetch non sollicité d'une URL distante
**CVSS 3.1** : `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3 (Medium)**

---

## 1. Résumé

Le point d'entrée OAuth `GET /oauth/authorize` accepte un `client_id` qui est une **URL HTTP(S)**
(mécanisme *Client ID Metadata Document*). Lorsque `client_id` est une URL, le serveur
d'autorisation **effectue lui-même une requête HTTP GET vers cette URL** pour y lire le document
de métadonnées client.

Cette requête :
- est déclenchée **sans aucune authentification** (ni token, ni cookie, ni en-tête d'auth) ;
- porte sur une **URL entièrement choisie par l'attaquant** (schéma, hôte, port, chemin, query) ;
- part de l'**infrastructure cloud de la plateforme** (IP source observée : `52.214.90.218`, plage AWS) ;
- **n'est pas soumise à un quota** : aucune inscription préalable n'est nécessaire (contrairement à
  `POST /oauth/register`, qui est limité en débit) et un fetch a lieu **à chaque** requête
  d'autorisation (25 fetches observés pour 25 URL distinctes) ;
- **est analysée** : le contenu téléchargé sert à définir l'identité du client
  (`client_id`, `client_name`, `redirect_uris`, `grant_types`, `scope`), et l'issue de cette analyse
  est **observable par l'attaquant** (voir §3, oracle).

Le même comportement existe sur `POST /oauth/register` via le champ `client_uri`.

## 2. Reproduction

### 2.1 Serveur d'écoute (attaquant)

Un service qui journalise les requêtes reçues (ici `webhook.site`, avec un **chemin unique par
essai** pour provinguer qu'il s'agit bien de la requête du serveur d'autorisation et non de la nôtre).

### 2.2 Document de métadonnées client contrôlé

Servi sur `https://webhook.site/<UUID>/<chemin-unique>` :

```json
{
  "client_id": "https://webhook.site/<UUID>/<chemin-unique>",
  "client_name": "bb-cimd-research (document de test)",
  "redirect_uris": ["https://webhook.site/<UUID>/cb"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "programs:read profile:read reports:read reports:write"
}
```

### 2.3 Requête — **aucune authentification**

```bash
curl -sS -D- -o/dev/null \
  "https://bugsecure-api.senintel.sn/oauth/authorize?response_type=code\
&client_id=https%3A%2F%2Fwebhook.site%2F<UUID>%2F<chemin-unique>\
&redirect_uri=https%3A%2F%2Fwebhook.site%2F<UUID>%2Fcb\
&scope=programs%3Aread%20profile%3Aread\
&state=bb-test&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
&code_challenge_method=S256\
&resource=https%3A%2F%2Fbugsecure-api.senintel.sn"
```

### 2.4 Preuve

Journal du serveur d'écoute (25 entrées, une par `authorize`) :

```
GET /imp-1792509314546-kdvj            ← chemin unique choisi par l'attaquant
Host: webhook.site
User-Agent: BugSecure-OAuth/1 (+client-id-metadata-document)
ip: 52.214.90.218                       ← IP de sortie de l'infrastructure BugSecure (AWS)
```

- Le `User-Agent` identifie le composant émetteur.
- Le chemin demandé est celui publié par l'attaquant : la requête est bien émise par le serveur
  d'autorisation.
- **L'IP source n'est pas celle du chercheur** : la requête sort du réseau de la plateforme.

Réponse de l'AS pour un document valide — la demande de consentement est créée **à partir du
document distant** :

```
HTTP/2 302
location: https://bugsecure.senintel.sn/oauth/consent?request=8fca8bd1-7c21-4bab-9bb1-7e06d3f71470
```

## 3. Le contenu distant est interprété (oracle)

Le corps téléchargé n'est pas ignoré : il détermine la **validation** du client, et le résultat est
lisible dans la réponse de l'AS.

| Document servi sur l'URL du `client_id` | Réponse de l'AS |
|---|---|
| document valide (`client_id` cohérent, `redirect_uris` https non-plateforme) | **302 → `/oauth/consent?request=…`** (client accepté, identité construite depuis le document distant) |
| `redirect_uris` vers un hôte de la plateforme (`https://bugsecure.senintel.sn/...`) | 302 → `/oauth/error?code=invalid_client` |
| `redirect_uris` vers un IP littéral (`https://1.2.3.4/cb`) | 302 → `/oauth/error?code=invalid_client` |
| `redirect_uris` = `javascript:alert(1)` | 302 → `/oauth/error?code=invalid_client` |
| `client_name` imitant la plateforme (`"BugSecure Africa"`, `"BugSecure"`, `"SSO BugSecure"`) | 302 → `/oauth/error?code=invalid_client` (contrôle anti-usurpation bien appliqué, cf. §6) |
| corps non JSON / JSON invalide / JSON sans `client_id` | 302 → `/oauth/error?code=invalid_client` |

L'attaquant dispose donc d'un **oracle binaire** : il sait si la ressource distante a été atteinte
et si son contenu correspond au format attendu. Il peut ainsi **sonder l'infrastructure** (présence
d'un service, type de réponse) à raison d'une requête par cible.

## 4. Périmètre réel mesuré (et ce qui n'a pas pu l'être)

Mesures effectuées côté AS, en prenant le **minimum** de 5 échantillons par cible (le minimum retire
le bruit de file d'attente) :

| Cible | latence min | médiane | lecture |
|---|---|---|---|
| témoin externe (webhook du chercheur) | 237 ms | 260 ms | fetch réellement effectué (aller-retour réseau) |
| `http://127.0.0.1:3000` | 137 ms | 1724 ms | refusé/échec rapide, comme les non-routables |
| `http://127.0.0.1:9200` | 169 ms | 430 ms | idem |
| `http://127.0.0.1:11211` | 137 ms | 170 ms | idem |
| `http://127.0.0.1/` | 132 ms | 153 ms | idem |
| `http://192.0.2.1/` (non routable) | 127 ms | 136 ms | témoin |
| `http://10.0.0.1/` (privé) | 127 ms | 129 ms | témoin |
| `http://169.254.169.254/` (IMDS) | 125 ms | 131 ms | témoin |

**Conclusion honnête** : le serveur d'autorisation dispose d'un filtre d'adresses qui **écarte les
plages internes** (loopback, RFC1918, link-local/métadonnées) : aucune portée interne n'a pu être
établie. De même, les **redirections ne sont pas suivies** (test avec un redirecteur public : le
second saut n'a jamais atteint la cible) — le contournement classique par redirection ne fonctionne
pas.

**Ce qui reste démontré et exploitable** : un **relais GET non authentifié, sans quota, depuis
l'IP de la plateforme**, vers **n'importe quelle URL externe**, avec un oracle sur la réponse.

## 5. Impact

1. **Le serveur d'autorisation devient un relais HTTP sortant** : un attaquant non authentifié peut
   faire émettre par l'infrastructure de BugSecure une requête GET vers n'importe quelle URL
   externe, **depuis l'IP de la plateforme** (et non la sienne).
   - contournement des listes d'autorisation d'IP chez des tiers (services de paiement, de
     vérification, de scan, de reporting) ;
   - usage de l'identité réseau et de la réputation de BugSecure pour des requêtes à l'attribut
     potentially abusif ;
   - aucune inscription n'est nécessaire (contrairement à `/oauth/register`, limité en débit) et
     **aucun quota** n'est appliqué : le débit est celui du chercheur.
2. **Fuite d'information d'infrastructure** : l'IP de sortie de l'AS est revealed
   (`52.214.90.218`) et l'existence du mécanisme de fetch est confirmée.
3. **Reconnaissance via oracle** : la réponse de l'AS révèle si la cible a répondu et si son
   contenu correspond au format attendu (présence d'un service, type de réponse) — un scanner
   d'infrastructure à la requête.
4. **Élévation possible à High/Critical** si l'une de ces conditions est satisfaite chez BugSecure :
   - une ressource interne (ou un service tiers) **autorise l'IP de la plateforme** ;
   - le filtre d'IP peut être contourné (résolution DNS côté serveur non re-vérifiée, IPv6/NAT64,
     redirect non suivi mais vérifié au moment du fetch, DNS rebinding) ;
   - le contenu distant peut être exploité au-delà du format « document client ».

## 6. Contrôle déjà en place (signalé au vendor, non contourné)

Le contrôle d'usurpation d'identité est **appliqué de façon cohérente** sur les deux chemins
d'enregistrement : `POST /oauth/register` **et** le chemin CIMD refusent tous un `client_name`
imposant la plateforme (`BugSecure`, `BugSecure Africa`, `SSO BugSecure`, `Senintel BugSecure`,
`MCP BugSecure officiel`, `bugsecure-mcp`). Cette vérification a été confirmée par les deux voies :
la protection n'est pas contournable par le fetch distant.

## 7. Recommandation

1. **Désactiver par défaut** l'usage d'un `client_id` qui est une URL : le mécanisme CIMD n'apporte
   rien à un client public classique et introduit un fetch serveur sur une entrée non authentifiée.
   Si CIMD doit être conservé, l'AS doit résoudre l'URL et **valider l'IP résolue** (refuser
   loopback, link-local `169.254.0.0/16`, RFC1918, ULA, `64:ff9b:1::/48`, IPv4-mapped IPv6),
   **re-vérifier après chaque redirection** et **désactiver la suite des redirections**.
2. **Ne jamais exécuter de fetch sur une URL fournie par un appelant non authentifié.** À défaut :
   liste blanche de schémas stricte (`https` uniquement), délai maximal très court, et **jamais de
   restitution** du résultat (ni en contenu, ni en temps distinguant deux réponses).
3. **Appliquer un quota** par IP et par `client_id` sur `/oauth/authorize`, et aligner le chemin CIMD
   sur le quota de `/oauth/register`.
4. **Journaliser** les URL distantes récupérées (avec l'IP résolue) et alerter sur toute cible interne
   ou sur un volume anormal de fetch.

## 8. Conformité / périmètre

- Aucun accès aux données d'un autre utilisateur ; aucun compte réel utilisé (compte de test du
  chercheur uniquement).
- **Aucune donnée exfiltrée** : la lecture de réponses internes n'a pas été réalisée et n'est pas
  revendiquée.
- Aucun impact sur la disponibilité ; les essais ont été espacés (≈ 1 requête / 3,5 s) et limités à
  une centaines de requêtes au total.
- Safe harbor : les tests ne portent que sur l'hôte de l'AS du programme, avec un service d'écoute
  détenu par le chercheur.
