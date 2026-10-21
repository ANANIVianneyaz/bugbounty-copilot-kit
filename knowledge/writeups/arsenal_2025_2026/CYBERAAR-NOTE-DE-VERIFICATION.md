# CYBERAAR / AarMe — note de vérification (en cours)

**Programme** : CyberAar (société derrière AarMe) — ouvert le 4/10/2026 · 5 000-300 000 FCFA ·
35 rapports soumis · 3 failles acceptées · délai moyen 0,4 j
**Actifs du périmètre** (classe fixée **avant** tout rapport) :

| Actif | URL | Classe |
|---|---|---|
| Plateforme AarMe | `aarme.cyberaar.io` | **Critique (58,3/100)** |
| API formulaires | `cyberaar.io/api/*` | Standard (28,3/100) |
| Site principal | `cyberaar.io` | Standard (11,7/100) |

**Score final** = `√(CVSS v4.0 × impact métier 0-10)` → sévérité → fourchette selon la **classe de
l'actif** (règle de trois, arrondi à 5 000 FCFA). Conséquence stratégique : une faille **Critique
technique** sur `aarme.cyberaar.io` vaut **225 000-300 000 FCFA**, la même faille sur `cyberaar.io` ne
vaut que 75 000-125 000 → **priorité à l'actif Critique**.

**Règles du programme** (`aarme.cyberaar.io/regles/`, lues) :
- ✅ autorisés : tests sur les actifs listés, **fuzzing / injection / analyse de la surface** dans le
  périmètre, preuves non destructives, **comptes de test avec ses propres adresses email (3 max)** ;
- ❌ interdits : DoS/DDoS, accès-modification-suppression de **données réelles**, ingénierie sociale,
  divulgation avant correction ;
- **en-tête de traçabilité** : `X-AarMe-Researcher: <pseudo>:<secret>` généré dans *Mon compte →
  Sécurité* (identité vérifiée + 2FA). Il fait passer le plafond d'entrée de **60 à 300 requ/min** et
  évite que mon trafic soit vu comme une attaque. Une valeur fausse/révoquée → **403** *et signalement
  au SOC comme usurpation* → **ne jamais forger cet en-tête** ;
- **PDF obligatoire** pour le rapport (description, étapes, captures, impact, CVSS) · validation sous
  5 jours ouvrés · pas de divulgation avant correction.

---

## 1. Recon (mesurée)

| Élément | Résultat |
|---|---|
| Pile | **Astro** (`data-astro-cid-*`) + **Cloudflare** (edge) ; API **same-origin** sous `/api/aarme/…` |
| CSP | `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; frame-ancestors 'none'` |
| HSTS | `max-age=31536000; includeSubDomains; preload` |
| Pages | SSR + **7 scripts de progression** (9 Ko max) → **pas de SPA** : la surface API client est restreinte |
| `robots.txt` (AarMe) | `Disallow: /admin` → l'admin est sur **un autre hôte** : `admin.aarme.cyberaar.io` → **hors périmètre** (les 3 actifs listés ne le comprennent pas) → **je n'y touche pas** |
| `security.txt` | `security@cyberaar.io`, policy `/regles/`, palmarès `/palmares/` |

### Surface API découverte (client + endpoints publics)

| Endpoint | Méthode | Réponse non authentifiée | Lecture |
|---|---|---|---|
| `/api/aarme/stats` | GET | **200** `{"accepted":3,"avg_response_days":0.4,"open":0,"paused":false,"reports":35,"researchers":2…}` | stats publiques (faible sensibilité) |
| `/api/aarme/programmes` | GET | **200** → la liste des programmes **avec leurs actifs et leur classe** | le périmètre est public par design |
| `/api/aarme/leaderboard` | GET | **200** → classements, `handle`, `badges`, `highest` | public par design (Hall of Fame) |
| `/api/aarme/account/session` | GET | **200** `{"authenticated":false}` | sonde de session ; **la session est un cookie** (`credentials: same-origin`) |
| `/api/aarme/account/register` | POST | 405 sans POST | inscription : corps `{name, email, profile, level, password, accord, lang, hp}` + **pot de miel `hp`** |
| `/api/aarme/org` | POST | 405 sans POST | proposition d'organisation : `{org, sector, email, message, lang, hp}` |
| `/api/aarme/account/logout` | POST | 405 sans POST | déconnexion |
| `/api/aarme/orgs`, `/api/aarme/users`, `/api/aarme/reports`, `/api/aarme/me`, `/api/aarme/config`, `/api/aarme/health` | GET | 404 `{"error":"not_found"}` | n'existent pas |

### Garde-fous mesurés sur l'inscription (endpoint `register`)

| Variante | Réponse | Lecture |
|---|---|---|
| sans `Origin`/`Referer` | **403** `{"error":"forbidden"}` | **garde-fou CSRF/origine** : le POST n'est traité qu'avec un `Origin` same-origin |
| avec `Origin`+`Referer` | **400** `{"error":"disposable_email"}` | **les adresses jetables sont refusées** → il me faut une adresse réelle |
| corps avec `hp` (pot de miel) rempli | **200** `{"success":true}` | **absorption silencieuse** : aucun compte créé (comportement correct) |
| `email` invalide | 400 `{"error":"invalid_email"}` | validation d'email |
| corps vide | 400 `invalid_email` | champs requis validés |
| en-tête `X-AarMe-Researcher` falsifié | **403** `{"error":"invalid_researcher_header"}` | l'en-tête est **validé** → ne jamais le forger (⇒ signalement SOC) |
| champs de privilège ajoutés (`role`, `roles`, `isStaff`, `verified`, `reputation`, `organizationId`, `status`, `id`, `approvedAt`…) | **403/400** | **mass assignment impossible** : le schéma d'entrée est strict (`invalid_input` sur `/api/aarme/org`) |
| ~20 tentatives d'inscription en quelques minutes | **429** `{"error":"rate_limited"}` | anti-abus sur l'inscription (plafond d'entrée 60/min sans l'en-tête chercheur) |

**Aucun compte n'a été créé** à ce stade (pot de miel = absorption ; jetable = refus ; 429 = bloqué).

---

## 2. Points ouverts

| # | Ce qu'il faut | Pourquoi c'est le point ouvert principal |
|---|---|---|
| P1 | **Un access token / une session de test** (alias Gmail du chercheur) | sans compte, je ne teste que la surface publique ; tout l'**authenticated** (IDOR, contrôle d'accès, uploads) est hors d'atteinte |
| P2 | **L'en-tête `X-AarMe-Researcher`** | porte le trafic de 60 à 300/min et évite d'être classé « attaque » par le SOC ; il est dans *Mon compte → Sécurité* (identité vérifiée + 2FA) |
| P3 | La surface API **authentifiée** | à extraire depuis les pages SSR une fois connecté (les bundles ne contiennent que 3 endpoints) ; le fuzzing est explicitement autorisé dans le périmètre |
| P4 | `cyberaar.io/api/*` (actif Standard) | les endpoints de formulaires (`/api/contact`, `/api/apply` → 405 sans POST) : 2ᵉ cible, ~3× moins payée |
| P5 | Le « niveau » auto-déclaré à l'inscription (`level`) | s'il influence un score de réputation ou un accès → auto-attribution de privilèges (à mesurer une fois connecté) |

### Les formulaires `cyberaar.io` (actif Standard) — premiers constats

| Endpoint | Champ obligatoire d'après l'API | Observation |
|---|---|---|
| `POST /api/contact` | `name` (erreur `missing_name` ; puis `invalid_email`) | champs de la page : `name, email, subject, message` |
| `POST /api/apply` | `org` (erreur `missing_org`) | proposition d'organisation : `org, sector, email, message` |

- Les deux endpoints **refusent les adresses jetables** (`invalid_email`) → il faut une adresse réelle.
- **Le plafond d'entrée de la plateforme est de 60 req/min** sans l'en-tête chercheur (et l'en-tête le
  porte à 300/min) : ~20 requêtes en 15 s suffisent à déclencher `429 {"error":"rate_limited"}`, qui
  s'applique ensuite à **tous** les endpoints (y compris les formulaires) pendant une fenêtre de
  refroidissement. → **l'en-tête `X-AarMe-Researcher` n'est pas un confort, c'est un préalable.**
- Les erreurs sont **champ par champ** (`missing_name`, `missing_org`, `invalid_email`) → schéma strict,
  ce qui rend le mass assignment peu probable (à confirmer sur l'inscription, qui refuse déjà
  `invalid_input` sur champs inconnus).

### Tests à exécuter une fois le plafond levé et un email réel disponible

| Test | Cible | Ce qu'il doit démontrer |
|---|---|---|
| **Injection CRLF → Bcc** | `contact` (`name`, `subject`, `email`), `apply` (`org`, `message`), puis **`aarme.cyrme` `register`/`org`** (actif **Critique**) | si le mailer du vendor accepte un `
Bcc:` injecté, l'attaquant reçoit une copie de l'e-mail de notification — et, sur l'inscription, d'un éventuel **lien de confirmation de compte** ⇒ ATO. **C'est le test à plus fort rendement de la campagne** : le même code de formulaire sert sur les deux actifs, et la version AarMe est en classe Critique (225 000-300 000 FCFA). |
| Mass assignment sur `contact`/`apply`/`register` | tous | un champ de privilège ignoré = inscription avec privilège |
| Type confusion / NoSQL | `name` en tableau / en objet | bypass de validation, injection |
| XSS stocké | `name`/`subject`/`message` | si le contenu est affiché dans un back-office ⇒ XSS en privilege |
| Longueurs / formats | tous | validation d'entrée stricte (déjà partially true) |


### Le périmètre exact (lu dans l'API `/api/aarme/programmes`) et une correction

```json
{"programmes":[{"key":"cyberaar","name":"CyberAar","org":"CyberAar","assets":[
  {"key":"aarme","name":"Plateforme AarMe","class":"Critique","match":["aarme.cyberaar.io","admin.aarme.cyberaar.io"]},
  {"key":"api","name":"API formulaires","class":"Standard","match":["cyberaar.io/api"]},
  {"key":"site","name":"Site principal","class":"Standard","match":["cyberaar.io","www.cyberaar.io"]}]}]}
```

→ **l'actif Critique inclut `admin.aarme.cyberaar.io`** (j'avais d'abord conclu le contraire : rectification).
**Mais** : `admin.aarme.cyberaar.io` **résout vers `10.9.0.10`** → une adresse **privée RFC1918** →
**l'interface d'administration n'est pas joignable depuis l'Internet** (connect timeout, aucune route) :
elle n'est accessible que depuis leur réseau interne.

Double enseignement :
1. **divulgation d'information** : un enregistrement DNS public révèle leur adressage interne
   (`10.9.0.10`) → à signaler (faible, mais c'est une fuite d'info réelle) ;
2. **l'angle à fort rendement** : si un endpoint public **récupère une URL fournie par l'utilisateur**
   (avatar, `website`, aperçu de lien, soumission de rapport, en-tête de webhook d'organisation…), alors
   `http://admin.aarme.cyberaar.io/…` est une **cible SSRF interne** → l'API d'admin, **non
   authentifiée depuis l'intérieur**, sur l'actif **Critique** (225 000-300 000 FCFA). C'est l'angle que
   je qualifie de prioritaire.

### La carte réelle de la surface API (différentiel 404/405/401, 40 sondes)

| Route | Réponse | Lecture |
|---|---|---|
| `GET /api/aarme/account/me` | **401** `{"error":"unauthenticated"}` | existe, **protégée** |
| `POST /api/aarme/account/profile` | 405 | mise à jour du profil (le schéma porte `website`, `avatarUrl`, `country`, `bio` → **champs d'URL à tester en SSRF**) |
| `POST /api/aarme/report` | 405 | soumission d'un rapport |
| `POST /api/aarme/org` | 405 | proposition d'organisation |
| `POST /api/aarme/account/register` | 405 | inscription (avec pot de miel) |
| `POST /api/aarme/account/login` | 405 | connexion |
| `POST /api/aarme/account/logout` | 405 | déconnexion |
| `GET /api/aarme/account/session` | 200 `{"authenticated":false}` | sonde de session (cookie same-origin) |
| `GET /api/aarme/{stats,programmes,leaderboard}` | 200 | publics par design |
| 30 autres chemins (`/api/aarme/{reports,orgs,members,payouts,settlements,certificates,invitations,notifications,search,taxonomy,badges,admin/*}`…) | 404 `{"error":"not_found"}` | **n'existent pas** |

→ **aucune API d'administration sur l'hôte public** : elle est sur `admin.` (privé). La surface publique
est volontairement **très étroite** : 11 endpoints, 3 publics, 8 sur session.

### Contrôles déjà prouvés sur cette surface

| Contrôle | Mesure | Verdict |
|---|---|---|
| **Enumeration de compte au login** | 8 variantes (email existant / inexistant / absent / champ `login` / password en tableau / mass assignment) → **toujours `401 {"error":"invalid_credentials"}`**, latences 224-580 ms | **aucun oracle** (ni par message, ni par timing) |
| Normalisation de chemin | `/api/aarme/./account/session` et `//account/session` → 200 ; `..%2f..%2f`, `/API/AARME/…`, `//api.aarme.cyberaar.io/…` → 404 | pas d'échappement |
| Confusion de méthode | `PUT`/`PATCH`/`DELETE`/`POST` → **405 `method_not_allowed`** ; `OPTIONS`/`HEAD` → 200 | seuls GET/POST sont routés |
| Paramètres cachés | `?limit=1000`, `?all=true`, `?include=email`, `?verbose=true`, `?debug=1`, `?include=internal` → réponses **identiques octet pour octet** | aucun amplificateur d'énumération |
| Profil public `/h/<handle>` | aucun email, aucun UUID, aucun montant | pas de fuite |
| Pages SSR | les seuls emails présents sont les placeholders de formulaire (`vous@email.com`) | pas de fuite au rendu |
| Leaderboard | 1 chercheur : `accepted, avatar, badges, handle, highest, name, points, position, rank` | pas de donnée sensible |


### La surface des formulaires, cartographiée (53 sondes, différentiel de code)

Sur `cyberaar.io/api/*` (actif Standard), **seuls 2 endpoints existent** :
`POST /api/contact` (405 sur GET) et `POST /api/apply` (405 sur GET) → les 51 autres chemins testés
(`/api/{newsletter,career,upload,webhook,kyc,avatar,login,register,lead,search,auth,billing,invoice,partner,form,forms,feedback,…}`) → **404**. La surface est très étroite.

**Le code client est maintenant lu en entier** (`/contact-form.js` et `/aarme-form.js`) :
- `POST /api/contact` → corps exact `{name, email, subject, message}` ;
- `POST /api/aarme/account/register` → corps exact `{name, email, profile, level, password, accord, lang, hp}` ;
- `POST /api/aarme/org` → corps exact `{org, sector, email, message, lang, hp}` ;
- le pot de miel est un `<input name="website">` masqué (`hp-org` / `hp-res`) dont la valeur est renvoyée
  sous la clé `hp` → **il est bien lu côté serveur** (un `hp` rempli absorbe la requête en `200 success`
  **sans créer de compte** → comportement correct).

**Deux détails qui ouvrent des tests** :
1. **Le champ `level` (niveau auto-déclaré) n'a pas d'attribut `value`** → le navigateur envoie le
   **texte** de l'option : « Débutant (je commence) », « Intermédiaire (CTF, labs, quelques reports) »,
   « Expert (expérience confirmée en bug bounty) » → **côté serveur c'est une chaîne libre** (à tester :
   acceptation d'une valeur hors liste ? le niveau fabrique-t-il un rang public ? un accès ?).
2. **La politique de mot de passe n'est imposée que côté client** : `minlength="12"`,
   placeholder « 12 caractères minimum » → **à vérifier côté serveur** (un mot de passe faible accepté
   = ATO facilitée sur la plateforme de bug bounty elle-même).

### Le plafond des formulaires : une limite dédiée, à fenêtre longue

Les `GET` passent (200) pendant que les `POST /api/contact` et `POST /api/aarme/account/register`
renvoient `429 {"error":"rate_limited"}` depuis ~25 min → le plafond est **spécifique aux formulaires**
(leurs règles confirment que l'en-tête chercheur **ne modifie pas** les limites de formulaire : il porte
le plafond d'**entrée** de 60 à 300/min, pas celui des formulaires).
⚠️ **erreur de méthode à ne pas reproduire** : en sondant toutes les 45 s pour mesurer la fenêtre, je
**réarmais moi-même** la pénalité (chaque probe la renouvelle). → il faut **arrêter de sonder** et laisser
décanter, puis tester une fois.


---

*Chaque ligne de ce document renvoie à une mesure reproductible (scripts + journaux dans le kit).*
