# Amendement au rapport « SSRF via `client_id` (CIMD) » — à poster en commentaire sur le rapport

*Destiné au triage BugSecure. Précède la sévérité : la fetch elle-même est **normative** (draft IETF
`draft-ietf-oauth-client-id-metadata-document`, « *Authorization servers SHOULD automatically fetch the
Client ID Metadata Document* ») et votre AS implémente les mitigations du draft. Je retire donc le
vocabulaire « SSRF » au profit d'un écart de politique entre vos deux chemins d'enregistrement de client,
que je démontre ci-dessous. Le reste du rapport (preuves, reproduction) est inchangé.*

---

## 1. Ce que je retire de mon rapport initial

Je **retire** la qualification « SSRF » du.fetch lui-même : la récupération du document est le
comportement attendu du draft, et votre AS met en place ses protections :

| Exigence du draft | Votre AS | Mesure |
|---|---|---|
| ne pas récupérer d'URL « special-use IP » (RFC 6890 : loopback, RFC1918, 169.254.0.0/16, IPv6 ULA, NAT64) | conforme | **distribution de latence, 8 échantillons par cible** (ci-dessous) : les cibles internes sont **refusées avant tout paquet** |
| ne pas suivre les redirections HTTP | conforme | un redirecteur public → `302` vers notre webhook : **le second saut n'a jamais atteint la cible** |
| TLS vérifié | conforme | un certificat auto-signé est **refusé** |

## 2. Preuve que le filtre d'adresses agit AVANT la connexion (et non après)

Requête unique par échantillon (`client_id` = URL unique) → latence de la réponse 302 de l'AS :

| Cible | min | p25 | médiane | p75 | max | lecture |
|---|---|---|---|---|---|---|
| témoin **externe** (webhook du chercheur) | 173 ms | 182 | 188 | 255 | 375 | un **vrai fetch** a lieu (aller-retour réseau) |
| témoin **non routable** `192.0.2.1` | 82 ms | 91 | 96 | 99 | 102 | refus **immédiat** |
| `10.255.255.1` (RFC1918) | 88 ms | 92 | 94 | 99 | 156 | refus immédiat |
| `169.254.169.254` (IMDS) | 89 ms | 91 | 94 | 96 | 98 | refus immédiat |
| `127.0.0.1:80` | 89 ms | 92 | 95 | 107 | 125 | refus immédiat |
| `127.0.0.1:3000` | 88 ms | 94 | 95 | 97 | 101 | refus immédiat |
| `127.0.0.1:53682` | 85 ms | 87 | 91 | 96 | 124 | refus immédiat |
| `127.0.0.1:9200` | 87 ms | 93 | 94 | 102 | 105 | refus immédiat |

Les cibles internes sont **statistiquement indiscernables du témoin non routable**, et **plus rapides** que le
témoin externe (qui, lui, effectue réellement la requête) : le refus intervient donc **avant l'émission
du paquet**, pas après une tentative de connexion. (J'avaisIRMES première affirmation de campagne comme
étant mesurée sur le *minimum* de quelques échantillons ; cette distribution à 8 échantillons par cible
est la version correcte.)

## 3. Le défaut que je maintiens : le chemin CIMD contourne deux protections que le chemin DCR applique

### 3.1 Aucune limite d'enregistrement ni de débit sur le chemin CIMD

| | `POST /oauth/register` (DCR) | `client_id` = URL (CIMD) |
|---|---|---|
| Limite de débit | **`429 temporarily_unavailable` après ~10 inscriptions** | **aucune** : 25 clients créés, 44 requêtes sortantes, aucun 429 |

Conséquence : un appelant **non authentifié** peut faire disappointed un nombre **non borné** de clients
fictifs, chacun déclenchant une **récupération serveur** d'une URL de son choix, depuis l'IP de la
plateforme (`52.214.90.218`) et avec son agent utilisateur. C'est un **relais HTTP GET non authentifié et
non plafonné** (usage abusive : listes d'autorisation d'IP contournées, réputation réseau de BugSecure
sollicitée, spam de requêtes sortantes).

### 3.2 La validation de `scope` n'est pas appliquée au chemin CIMD

| | DCR | CIMD |
|---|---|---|
| `scope` hors périmètre (`admin:all`, `triage:write`) | **refusé** : `invalid_client_metadata` — « *scope contains unsupported values* » | **accepté** : le client est construit et une **demande de consentement est ouverte** |

Le filtrage n'intervient qu'au moment de l'émission du jeton. Autrement dit, un client enregistré par le
chemin CIMD peut **déclarer** n'importe quel scope, et le consent screen lui est proposé, alors que la
même déclaration est refusée à l'inscription classique. C'est une **incohérence de politique** entre deux
voies d'enregistrement d'un même client.

## 4. Ce que j'ai vérifié et qui est conforme (contrôles positifs)

Je liste ici ce que j'ai **confirmé comme correct**, pour que le triage n'ait pas à le redemander :

- **Filtre anti-usurpation d'identité de client** : 10 variantes par DCR (`BugSecureX`, `XBugSecure`,
  `)BugSecure(`, espaces, casse, trait d'union, underscore) et **22 variantes de confusables Unicode par
  le chemin CIMD** (cyrillique, accents, zero-width, insécable, bidi RLO/PDF, soft hyphen, BOM, turc
  pointless, ZWJ, signe moins) → **toutes refusées** (`invalid_client_metadata` / `invalid_client`).
  Le filtre normalise l'Unicode : ce n'est pas une recherche de sous-chaîne.
- **`redirect_uri`** : comparaison exacte (slash final, query, fragment, userinfo, sous-domaine, chemin
  différent, IP littéral, `javascript:` → tous refusés), sur les deux chemins.
- **PKCE** : `code_challenge_method=S256` obligatoire, `plain`/absent/malformé → refusés.
- **Code d'autorisation** : usage unique. **Refresh token** : rotation stricte, révocation de la famille en
  cas de rejeu. **`token-exchange` / `client_credentials`** : refusés (y compris pour un client CIMD).
- **Usurpation de nom à l'écran de consentement** : sans effet, le filtre ci-dessus s'applique.

## 5. Impact que je revendique (et ce que je ne revendique pas)

- ✅ **Revendiqué** : un appelant non authentifié dispose d'un **relais de récupération d'URL non borné en
  débit et sans inscription**, exécuté depuis l'IP de la plateforme, et d'un **contournement de la
  validation de `scope`** propre au chemin CIMD.
- ❌ **Non revendiqué** : aucune lecture de donnée interne (les IP « special-use » sont refusées avant
  connexion), aucune escalation de privilège (les scopes sont filtrés à l'émission du jeton), aucune
  impersonation d'identité de client (filtre robuste).
- **Sévérité** : je propose **Moyenne** au titre du relais non borné + l'écart de validation de `scope` ;
  je peux descendre à **Faible** si vous jugez que l'absence de quota sur un chemin de fetch normatif
  relève de la simple defense en profondeur. **Ma préférence** : traiter les deux écarts (§3) comme le
  défaut, et le fetch comme le contexte.

## 6. Correctifs proposés (par ordre de priorité)

1. **Aligner le chemin CIMD sur le chemin DCR** : même quota d'enregistrement / de débit, **et** même
   validation du `scope` déclaré (refuser les scopes hors périmètre à la construction du client, comme
   DCR le fait déjà).
2. Ou, si le mécanisme CIMD doit rester ouvert : **plafonner le débit de récupération** (par IP et par
   `client_id`) et **valider le `scope` du document** au moment de la construction du client.
3. Conserver les mitigations déjà en place (IP « special-use », pas de redirection, TLS vérifié) : elles
   fonctionnent, et la distribution de latence ci-dessus le démontre.
