Bonjour,

Merci pour ce retour, et pour vos deux précisions — j'ai corrigé mon rapport en conséquence :

- le champ `scope` d'un document n'est pas lu : je l'avais bien observé sur le chemin `/oauth/authorize` (le `scope` de la requête compte seul, `admin:all` est refusé) et j'avais formulé ce point trop largement dans le rapport ;
- l'« oracle » n'indique en réalité que la validité d'un document CIMD public, ce que n'importe qui peut vérifier directement : je retire la formulation « oracle binaire sur la cible », qui était le principal argument d'impact du rapport.

Je note aussi que le comportement décrit correspond au mécanisme *Client ID Metadata Documents* que vous implémentez, y compris au titre de la spec MCP que vous citez : je n'avais pas identifié ce rattachement, c'est mon principal erreur de cadrage. Je retire donc la qualification « SSRF » du fetch lui-même, et je comprends la clôture en doublon (comportement déjà signalé et évalué Informatif).

**Mes mesures convergent avec vos mitigations** — je vous les laisse, elles sont utilisables pour votre documentation :

| Cible (8 échantillons, latence de la réponse de l'AS) | min | max |
|---|---|---|
| IP internes refusées (`127.0.0.1:3000`, `127.0.0.1:53682`, `169.254.169.254`, `10.255.255.1`) | 85-89 ms | 98-156 ms |
| témoin non routable (`192.0.2.1`) | 82 ms | 102 ms |
| témoin externe (fetch réellement effectué) | 173 ms | 375 ms |

→ les IP internes sont refusées **avant l'émission du paquet** (indiscernables du refus immédiat, et plus rapides qu'un fetch réel). Également vérifié chez vous : redirections non suivies (le second saut n'atteint jamais la cible) ; certificat TLS auto-signé refusé ; `client_id` à correspondance exacte (une query string de différence → `invalid_client`) ; document non-JSON servi en 200 → `invalid_client`.

**Un seul écart mesuré subsiste, et il ne concerne pas le fetch mais l'enregistrement** : le chemin CIMD n'applique pas la limite de débit du chemin d'inscription classique. Mesure appariée, même cadence (1 requête / 3 s), 12 tentatives de chaque côté :

| Chemin | Clients créés | Réponses `429 temporarily_unavailable` |
|---|---|---|
| `POST /oauth/register` | **0** | **12** |
| `client_id` = URL (CIMD) | **12** | **0** |

Cela permet à un appelant non authentifié de créer un nombre non borné d'identités de client, chacune déclenchant une récupération serveur depuis votre IP. Je n'en fais pas un rapport séparé — c'est une observation. Dites-moi si c'est déjà connu et suivi de votre côté ; je peux vous fournir la mesure reproductible et le script.

**Enfin, pour votre documentation**, j'ai vérifié un ensemble de contrôles sans trouver de défaillance (liste complète disponible sur demande) : filtre anti-usurpation d'identité de client (10 variantes par `/oauth/register` + **22 variantes de confusables Unicode** par le chemin CIMD → toutes refusées) · PKCE `S256` obligatoire, `plain`/absent/malformé refusés · code d'autorisation à usage unique · rotation du refresh token avec révocation de la famille en cas de rejeu · `token-exchange` et `client_credentials` refusés · approbation d'agent inaccessible aux clients OAuth, arguments liés à l'approbation (un rejeu avec des arguments différents est refusé par l'API) · MFA : aucun jeton avant la 2FA, `challengeToken` non utilisable comme jeton d'accès, pas d'oracle de préfixe sur le code TOTP, rate-limit d'environ 3-4 tentatives / 60 s, codes de secours de 8 caractères · énumération de références de certificat impossible (réponse uniforme) · surface admin et surface « argent » hors de portée des clients OAuth.

Merci encore pour la qualité de l'échange, et bonne continuation.
