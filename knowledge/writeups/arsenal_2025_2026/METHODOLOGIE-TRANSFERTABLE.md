# Méthodologie transférable — bug bounty OAuth / GraphQL / MCP

*Document de reprise pour attaquer un autre programme avec la même méthode. Tout ce qui suit a été
validé sur une campagne réelle (KLDS / BugSecure Africa, 20-21/10/2026) : 65 contrôles, 197/198
opérations, 33 outils MCP, 1 rapport (clos en doublon), 0 vulnérabilité exploitable, 7 observations.*

---

## 1. L'ordre qui fonctionne (et celui qui ne fonctionne pas)

| Étape | Ce qu'il faut faire | Pourquoi |
|---|---|---|
| **0. Cadrer la spec AVANT de tester** | lire le draft OAuth concerné (CIMD, JAR, PAR…), le MCP spec, le README du client officiel | j'ai écrit « SSRF » là où la spec imposait le comportement → le triage a clos en doublon en 4 lignes |
| **1. Chercher la doc du vendor** | README, docs, code source du client officiel | j'allais rapporter un défaut de contrat que la doc décrivait exactement à l'opposé |
| **2. Inventorier la surface, pas les vulnérabilités** | extraire **toutes** les opérations de l'API depuis le bundle (les introspection est souvent désactivée) | le balayage complet (198 ops) est la base de tout ; il a révélé que 125 opérations sont hors périmètre OAuth |
| **3. Mesurer, ne jamais supposer** | chaque contrôle « fermé » = une **mesure** : message discriminant, latence, capture OOB, distributIon | un 403 ne prouve rien ; un « oracle » peut être public par design |
| **4. Mesurer en apparié** | DCR vs CIMD · scope manquant vs objet absent vs accès réel · 2 IP en parallèle | une comparaison isolée ne montre rien ; l'apparié montre l'écart (0/12 vs 12/12) |
| **5. Faire relire par 2 IA, et **retirer** ce qui ne tient pas** | 2 revues indépendantes, puis on retire publiquement | 2 surclaims retirés + 1 fausse conclusion retirée → le dossier devient crédible |
| **6. Mesurer l'entropie avant de conclure sur un oracle** | obtenir un **échantillon** du token (email transféré) | j'ai conclu « non exploitable » grâce à 64 caractères hex = 256 bits, pas grâce à une intuition |
| **7. Documenter les contrôles positifs** | ce qui est conforme vaut autant que ce qui est cassé | c'est ce qui fait la différence avec un rapport de 5 lignes |

## 2. L'outillage à réutiliser (tout est dans `tools/klids-campaign/`)

| Outil | Rôle |
|---|---|
| `sweep.mjs` (+ variante fusion) | balayage complet de l'API avec **moteur d'auto-réparation** : à partir des messages d'erreur (champ inconnu, champ requis manquant, type d'entrée erroné, enum invalide, opération d'enum invalide), la requête est corrigée et rejouée. C'est **le** composant à porter sur un autre programme. |
| `sweep2.mjs` | idem + **fusion** du fichier de résultats (ne pas écraser : la reprise écrasait les passes précédentes) |
| `quota-paired.mjs` | mesure appariée de quotas entre deux chemins d'enregistrement |
| `latency-dist.mjs` | distribution de latences par cible (8 échantillons) → prouve *avant/après* le paquet réseau |
| `confusables.mjs` / `namefilter2.mjs` | filtre anti-usurpation : 22 variantes de confusables Unicode (cyrillique, accents, zero-width, bidi RLO/PDF, BOM, turc `ı`, ZWJ, insécable) |
| `token-store.mjs` | **discipline obligatoire** : un refresh token est rotatif → chaque refresh **sauvegarde** le couple (AT, RT). J'ai brûlé 3 refresh tokens en diagnostiquant à la main. |
| `catcher4.cjs` | gestionnaire de grant OAuth multi-ressources (le `state` porte la ressource → un RT par ressource) |
| `jwks-listener.cjs` | serveur de preuve : sert un document CIMD paramétrable (par **chemin**, pas par query string → sinon le `client_id` ne correspond plus et l'AS refuse), journalise chaque requête reçue, reçoit des jetons par navigation (contournement de la CSP `connect-src`) |
| `mcp-scope-final.mjs` | enforcement des scopes **par outil** MCP (33 outils) avec arguments valides par outil |
| `mcp-type-confusion.mjs` | 20 payloads de confusion de type / smuggling sur `tools/call` |
| `softfail.mjs` / `org-context.mjs` | oracle doux (messages + latence) et matrice IDOR inter-comptes |
| `npm-diff.mjs` | diff paquet npm publié ↔ dépôt (secrets figés, endpoints de staging, dérive de schéma) |
| `multi-a-test.mjs` | test multi-A-record : résolution publique, latence de l'AS, preuve OOB |
| `residual-probe.mjs` | **invalidation d'un access token** : boucle de rejeu horodatée, discriminating message, vérification des effets de bord par un 2ᵉ jeton |

## 3. Les 12 gestes qui ont le plus rapporté (à refaire dans cet ordre)

1. **Extraire toutes les opérations** du bundle → la carte de la surface (198 ops en 2 min).
2. **Balayer avec un jeton valide** et le moteur d'auto-réparation → 90 % de la surface en une passe.
3. **Lire les messages d'erreur** : ils nomment le scope manquant (`requires the scope(s): triage:read`) → la carte des droits, gratuitement.
4. **Comparer les classes de réponse** entre 2 comptes/2 contextes → l'IDOR sort tout seul (uniformité =Closed).
5. **Chercher l'incohérence** entre deux résolveurs d'un même groupe (un soft-fail au lieu d'un refus = l'observation qui vaut le rapport).
6. **Énumérer les enums** en automatique (le moteur le fait) → puis **vérifier la schéma du client officiel** contre l'API (j'ai trouvé le schéma périmé du paquet npm).
7. **Tester l'enforcement scope par outil** côté MCP, avec des **arguments valides** (sinon tu confonds « scope manquant » et « argument invalide »).
8. **Mesurer le rate-limit sur 2 IP en parallèle** → s'il est par IP, le débit est multipliable (à dire dans le rapport).
9. **Récupérer un échantillon de token par email** (le chercheur peut transférer l'email) → la seule façon de trancher l'exploitabilité d'un oracle.
10. **Contrôler les champs non validés** (`jwks_uri`, `logo_uri`) → même sans effet aujourd'hui, c'est un champ à signaler.
11. **Vérifier la sémantique de révocation** (grant, session, access token) → 3 mécanismes distincts à tester séparément.
12. **Écrire la note de vérification en continu** (chaque contrôle = une ligne de tableau) → le rapport final s'écrit seul.

## 4. Le gabarit de rapport qui a marché

1. Synthèse (volumétrie, verdicts, points ouverts) — **1 tableau**.
2. Le rapport soumis et **pourquoi** il a été clos (avec les retraits).
3. L'inventaire des contrôles **par famille**, chacun avec sa mesure.
4. Les **observations** à signaler au vendor (≠ vulnérabilités).
5. Les **pistes closes avec preuve** (le cœur de la valeur : 10 pistes fermées, c'est ce qui rend le reste crédible).
6. Les **points ouverts** et ce qu'il faut pour les trancher.
7. Méthode et reproductibilité (scripts, journaux).
8. **Leçons** (7 ici) — réutilisables sur n'importe quel programme.
9. **Couverture intégrale** des demandes des revues (statut par ligne : ✔ fait · ◐ partiel · ✖ non testable · ⏸ en attente).
10. **Ce qui n'a pas été fait et pourquoi** (transparence).
11. Le déroulé chronologique.

## 5. Les 8 pièges que j'ai payés (à ne pas répéter)

| Piège | Coût | Règle |
|---|---|---|
| Écrire un script qui concatène deux fois un segment d'URL (`/mcp` + `/mcp`) | 1 h à croire à un « défaut de disponibilité » du serveur | **un serveur d'écho local** tranche en 2 min : il journalise la requête réelle |
| `pkill -f "un motif qui apparaît dans ma propre commande"` | mon shell se tue | killer par **port** (`ss -ltnp`), pas par motif |
| Diagnostic à la main du `/oauth/token` → le RT est rotatif, l'ancien est révoqué | 3 RT perdus | **un seul point de rafraîchissement**, qui sauvegarde systématiquement (cf. `token-store.mjs`) |
| Recopier un JWT à la main | 4 versions divergentes, dont une « différente mais valide » | le faire **transporter par le serveur** (navigation → query string) |
| Envoyer une mutation sans le scope requis | faux négatif : le refus est dû au scope, pas au token | vérifier d'abord que le scope de la mutation est **accordé** |
| `@include(if:false)` sur une mutation → je croyais tester un contournement | validation d'entrée qui masque tout | mettre des **valeurs d'enum valides** avant de tester la logique d'accès |
| `REMOVE`/quoting/heredoc qui perd un `[` | 20 min de debug | un script sur disque, jamais une commande à la quote fragile |
| Croire que le rapport non envoyé est perdu | — | tout est dans le kit (note + rapports + journaux + scripts) → rien n'est dans ma tête |

## 6. Ce qu'il faut demander au chercheur (et quand)

| Moment | Demande | Pourquoi |
|---|---|---|
| J1 | un **2ᵉ compte** (le plus gros gain : IDOR, contexte organisation, comparaison de réponses) | 1 seule demande, 4 pistes débloquées |
| J1 | le droit de **modifier le mot de passe** du compte de test (ou de le changer lui-même) | l'invalidation d'access token ne se teste que par un changement d'état |
| J2 | un **échantillon de token par email** (transfert vers une boîte que le chercheur peut lire) | l'entropie décide de l'exploitabilité d'un oracle |
| J2 | 15 min de **relecture croisée** par 2 IA | 2 surclaims retirés avant soumission, 1 fausse conclusion retirée |
| J3 | l'ouverture de **4 liens de test** + un relevé de ce qui s'affiche | le rendu d'un écran de consentement ne se mesure qu'en navigateur |
| Fin | le **désarmement de l'infra de test** (2 commandes) | ne pas laisser un hébergeur public ouvert |

## 7. Critères d'arrêt (pour ne pas allonger la campagne)

La campagne s'arrête quand, sur 3 cycles consécutifs :
1. les 5 surfaces sont couvertes (OAuth/AS, sessions, autorisation, injection, surface serveur MCP) ;
2. le balayage complet est passé **avec un jeton valide** (pas un jeton expiré : c'est l'erreur qui a fait croire à 125 faux blocages) ;
3. chaque piste restante est soit close par une mesure, soit bloquée par une **action unique** du chercheur ;
4. le rapport de campagne est écrit (contrôles, observations, pistes closes, non-faits).

*Durée de référence : 3 jours, ~65 contrôles, 0 vulnérabilité exploitable sur une plateforme mature — ce qui est un résultat, pas un échec.*
