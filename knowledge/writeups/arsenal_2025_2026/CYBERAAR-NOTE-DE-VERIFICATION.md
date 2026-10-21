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

---

*Chaque ligne de ce document renvoie à une mesure reproductible (scripts + journaux dans le kit).*
