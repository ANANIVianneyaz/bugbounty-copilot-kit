# Méthodologie experte — comment penser une cible, pas juste la scanner

Ce document n'est pas un catalogue de vulnérabilités de plus. Le corpus `index.json`/`WRITEUP_KB.md`
répond à la question « qu'est-ce qui a déjà cassé, et comment ». Celui-ci répond à une question
différente et plus importante : **comment un chasseur de bugs expérimenté REGARDE une fonctionnalité
qu'il n'a jamais vue, sur un site qu'il ne connaît pas, et en tire des hypothèses à tester** — sans
attendre qu'un nom de CVE ou un payload tout fait lui dise quoi faire.

C'est particulièrement critique pour la logique métier : il n'existe pas de « payload logique métier »
universel comme `' OR 1=1--` pour le SQLi. Chaque logique métier est unique à l'application. Ce qui
est transférable, ce n'est pas le payload — c'est la **question qu'on se pose**.

Chaque section ci-dessous suit le même format : le principe mental, les questions concrètes à se poser
face à une fonctionnalité, un exemple de raisonnement travaillé (pas juste un résultat), et les signaux
de terrain qui doivent déclencher ce mode de pensée.

---

## 1. Penser en machine à états (state machine thinking)

**Le principe.** Toute fonctionnalité multi-étapes (checkout, onboarding, validation KYC, workflow
d'approbation, réinitialisation de mot de passe, upload avec traitement asynchrone) est une machine à
états implicite : `étape 1 → étape 2 → étape 3 → terminé`. Le développeur code presque toujours le
chemin HEUREUX (l'utilisateur suit les étapes dans l'ordre, une seule fois, jusqu'au bout). Il code
beaucoup plus rarement la défense contre les chemins qu'un utilisateur normal ne prendrait jamais mais
qu'un attaquant, lui, prendra volontiers.

**Les questions à se poser sur CHAQUE flux multi-étapes :**
- Est-ce que je peux appeler l'endpoint de l'étape 3 directement, sans être passé par l'étape 1 et 2 ?
- Est-ce que je peux revenir en arrière après l'étape 3 et la refaire (répétition d'une étape sensée
  être unique — appliquer un coupon deux fois, valider un paiement deux fois) ?
- Est-ce que je peux abandonner le flux au milieu et le reprendre plus tard dans un état incohérent
  (ex : commencer un paiement, ne jamais le finir, mais l'objet réservé reste réservé) ?
- Qu'est-ce qui différencie, côté SERVEUR, « je suis à l'étape 2 » de « je suis à l'étape 3 » ? Si la
  réponse est « un champ que le client envoie » (`step: 3`, `stage: "payment"`), c'est un signal
  d'alarme immédiat — le client se déclare lui-même où il en est.
- Est-ce que deux étapes indépendantes peuvent être exécutées EN PARALLÈLE au lieu de séquentiellement,
  et si oui qu'est-ce que ça casse (voir §3, la course).

**Exemple de raisonnement travaillé.** Sur un site de billetterie, l'expert observe le flux : panier →
paiement → confirmation. Il ne se demande pas « est-ce que le paiement est sécurisé ? » (question
générique, peu actionnable). Il se demande : « qu'est-ce qui EMPÊCHE techniquement que je fasse
`POST /confirm` directement, avec un `order_id` que j'ai vu dans une réponse précédente, sans jamais
avoir payé ? » Il essaie. Si ça marche, il a trouvé un bug de logique métier en 30 secondes sans avoir
lu une ligne de code source. C'est exactement le type de raisonnement documenté dans le cas réel
`exploiting-business-logic-inventory-depletion-via-parameter-tampering` du corpus : la vraie question
posée par le chercheur n'était pas « comment exploiter CWE-840 », c'était « qu'est-ce qui empêche
techniquement le serveur d'accepter une quantité plus grande que le stock, et un mode de paiement que
je ne suis pas autorisé à utiliser ? » — et la réponse était : rien.

**Signaux de terrain.** Un `Content-Type: application/json` avec des champs `step`/`stage`/`status`
contrôlés par le client ; un bouton « Suivant » qui ne fait qu'un `PATCH` sur une ressource déjà créée ;
une confirmation de commande dont l'URL est directement accessible en GET.

---

## 2. Penser en frontière de confiance (trust boundary thinking)

**Le principe.** La question la plus utile qu'un chasseur puisse se poser en permanence, sur CHAQUE
requête qu'il observe, est : « cette donnée, qui a la dernière autorité dessus — le client qui l'envoie,
ou le serveur qui la reçoit ? » Un attaquant contrôle TOUT ce qu'un navigateur envoie : URL, headers,
cookies, body JSON, y compris les champs que l'interface ne montre jamais. La question n'est donc pas
« est-ce que ce champ est modifiable » (il l'est toujours, techniquement), mais « **est-ce que le serveur
revérifie sa valeur indépendamment**, ou lui fait-il une confiance aveugle parce que l'UI ne l'exposait
pas ? »

**Les questions à se poser :**
- Ce champ (rôle, prix, quantité, propriétaire, statut, permission) apparaît-il dans le JSON de réponse
  d'un GET quelque part, même si l'UI ne l'affiche pas ? Si oui, il existe probablement en écriture
  quelque part aussi (cf. mass assignment).
- Si je supprime ce champ de ma requête, qu'est-ce qui se passe — une erreur (le serveur en a
  visiblement besoin et le valide), ou un succès silencieux avec une valeur par défaut permissive ?
- Un ID que je fournis (user_id, org_id, tenant_id) est-il revérifié comme appartenant à MA session, ou
  simplement utilisé tel quel pour la requête base de données ?
- Le prix, la quantité, ou toute donnée financière viennent-ils du panier stocké côté serveur, ou sont-ils
  renvoyés par le client à l'étape de paiement (et donc falsifiables) ?

**Exemple de raisonnement travaillé.** Sur une app SaaS avec plans payants, l'expert voit une requête
`POST /workspaces/{id}/projects` avec un body `{"visibility": "personal"}`. Rien dans l'UI ne permet de
choisir « Workspace » (visibilité premium) en étant sur le plan gratuit. Mais la question n'est pas
« l'UI le permet-elle » — c'est « le SERVEUR sait-il, indépendamment de ce que j'envoie, que je suis sur
le plan gratuit, et l'applique-t-il à CETTE requête précise ? » Il essaie `{"visibility": "workspace"}`.
201 Created. Le serveur a fait confiance à la valeur envoyée par le client au lieu de la dériver de l'état
du compte. C'est exactement le raisonnement du cas réel `business-logic-bypass-read-access-role-without-pro-plan-subscription`.

**Signaux de terrain.** Un formulaire UI avec peu de champs, mais un body JSON de la requête réelle qui
en contient beaucoup plus (visible en interceptant avec un proxy) ; une réponse GET qui « fuite » plus
de champs qu'elle n'en montre à l'écran ; un champ nommé `role`, `plan`, `tier`, `verified`, `is_admin`,
`owner_id` n'importe où dans un payload.

---

## 3. Penser en concurrence (race / timing thinking)

**Le principe.** Presque toute vérification métier suit le pattern « lire l'état → décider → écrire le
nouvel état » en deux requêtes séparées, non protégées par une transaction atomique. Un attaquant qui
envoie N requêtes EN MÊME TEMPS fait lire le MÊME état initial à chacune, avant qu'aucune ne l'ait mis à
jour — chacune « pense » être la première.

**Les questions à se poser :**
- Cette action a-t-elle une limite censée être appliquée une seule fois (un coupon, un crédit gratuit,
  un like, une inscription à un événement à places limitées) ? Que se passe-t-il si je l'exécute 20 fois
  EN PARALLÈLE plutôt que séquentiellement ?
- Cette action modifie-t-elle un solde/compteur (argent, points, stock) ? Le calcul `nouveau_solde =
  ancien_solde - montant` est-il fait dans la MÊME transaction que la lecture, ou en deux temps ?
- Un mécanisme anti-abus (limite de tentatives, OTP à usage unique) compte-t-il les tentatives de façon
  atomique, ou lit-il un compteur puis l'incrémente après coup ?

**Exemple de raisonnement travaillé.** L'expert voit un bouton « Appliquer le coupon » qui déclenche un
`POST /cart/apply-coupon`. Le raisonnement n'est pas « ce coupon est-il valide » — c'est « qu'est-ce qui
empêche techniquement que ce même coupon soit accepté deux fois si j'envoie deux requêtes strictement
simultanées, avant que le serveur ait eu le temps de marquer le premier passage comme consommé ? » Avec
un outil comme Turbo Intruder (technique du « single-packet attack »), il envoie 20 requêtes synchronisées
à la microseconde près. Si plusieurs passent, le bug est confirmé — pas parce qu'il connaissait un CVE,
mais parce qu'il a posé la question « et si c'était simultané plutôt que séquentiel ? »

**Signaux de terrain.** Toute action avec une notion de « une seule fois » énoncée dans l'UI/la doc
(« un coupon par commande », « une tentative OTP toutes les X secondes ») sans qu'on sache COMMENT c'est
techniquement garanti.

---

## 4. Penser en confusion d'identité (identity/context confusion thinking)

**Le principe.** Une application multi-utilisateur ou multi-tenant maintient en permanence la question
« qui suis-je, dans quel contexte ». Un attaquant peut souvent se placer dans un état où cette réponse
est AMBIGUË — deux comptes ouverts en parallèle, un compte qui vient d'être créé mais pas encore
pleinement « adopté » par le système, une session partagée entre deux contextes (personnel/pro,
tenant A/tenant B).

**Les questions à se poser :**
- Si je crée DEUX comptes et que je fais une action avec le token de A mais un ID de ressource de B,
  qu'est-ce qui se passe (cf. §2, IDOR) — mais aussi : que se passe-t-il si je fais l'inverse, l'ID de A
  avec le token de B, dans un endpoint où l'ordre des vérifications pourrait être inversé par erreur ?
- Un flux d'invitation/liaison de compte (« rejoindre une organisation », « lier un compte tiers ») :
  est-ce que l'action finale associe la BONNE identité, ou celle qui était active en dernier dans le
  navigateur au moment du clic (cf. OAuth login CSRF, §« questions transverses ») ?
- Sur un système multi-tenant, un identifiant de ressource (ex: un ID de document) est-il unique
  GLOBALEMENT ou seulement PAR tenant ? S'il est global mais que le contrôle d'accès ne vérifie que
  l'appartenance au tenant courant sans revérifier l'ID complet, deux tenants peuvent se marcher dessus.

**Exemple de raisonnement travaillé.** Sur une plateforme d'onboarding SaaS, l'expert observe qu'après
un signup, l'utilisateur reçoit un email de confirmation avec un lien contenant un token. Il se demande :
« ce token identifie-t-il UNIQUEMENT le compte à confirmer, ou pourrait-il, une fois consommé, être
réutilisé dans un contexte différent (récupération de compte, changement d'email) où l'identité qu'il
représente n'est plus la bonne ? » C'est ce type de question qui a mené au cas
`fizzy-do-import-filename-preview-dom-xss-ato` du corpus : la chaîne complète exploitait précisément une
confusion entre « quelle action ce token/cette requête authentifiée est-elle censée accomplir » et « quelle
action le serveur accepte réellement de lui faire accomplir ».

---

## 5. Penser en composition de fonctionnalités (feature interaction thinking)

**Le principe.** Deux fonctionnalités, individuellement sûres et voulues, peuvent créer une capacité
NON voulue une fois combinées. Aucun développeur n'a pensé « et si on combine A et B », parce que
chaque fonctionnalité a été conçue, revue et testée ISOLÉMENT.

**Les questions à se poser :**
- Existe-t-il une fonctionnalité d'EXPORT (PDF, CSV, capture d'écran) qui traite du contenu généré par
  un AUTRE utilisateur (nom de fichier, commentaire, profil) ? Si oui, ce contenu passe-t-il par le même
  pipeline de sanitisation que l'affichage normal, ou par un pipeline différent (souvent moins strict,
  car « c'est juste un export ») ?
- Existe-t-il une fonctionnalité d'IMPORT qui accepte un format de fichier riche (ZIP, DOCX, SVG) et une
  fonctionnalité de PREVIEW/rendu de ce même contenu ? La combinaison importe souvent plus de structure
  (HTML, métadonnées, macros) que ce que le développeur croyait accepter.
- Existe-t-il une fonctionnalité de RECHERCHE/FILTRE qui accepte un tri ou un critère personnalisé
  (`sort_query`, `orderBy`, `filter`) transmis quasiment tel quel à la couche de données (SQL,
  Elasticsearch, MongoDB) ? La combinaison « champ de tri exposé » + « moteur de recherche puissant »
  ouvre souvent une injection que personne n'a testée parce que « c'est juste un tri ».
- Une fonctionnalité de NOTIFICATION/WEBHOOK envoie-t-elle une requête sortante vers une URL que
  l'utilisateur contrôle en partie (avatar depuis une URL, aperçu de lien, callback de test) ? C'est la
  combinaison la plus fréquemment primée en bug bounty (SSRF, cf. corpus §ssrf-cache).

**Exemple de raisonnement travaillé.** C'est exactement le cas `authenticated-elasticsearch-painless-script-execution`
du corpus : personne n'a audité « le tri de résultats de recherche » comme un vecteur d'injection, parce
qu'individuellement, « chercher » et « trier » semblent inoffensifs. Le chercheur a posé la question :
« ce paramètre de tri, où va-t-il exactement une fois qu'il quitte le resolver GraphQL ? » et a découvert
qu'il finissait tel quel dans le moteur Elasticsearch, qui accepte des scripts.

---

## 6. Penser en hypothèse fausse du développeur (silent assumption thinking)

**Le principe.** Chaque contrôle de sécurité absent révèle une HYPOTHÈSE implicite que le développeur a
faite sur le comportement d'un utilisateur légitime — et qu'un attaquant n'a aucune raison de respecter.
« Personne ne va changer ce champ caché », « personne ne va appeler cet endpoint sans passer par l'UI »,
« personne ne va faire ça deux fois », « ce champ est en lecture seule dans l'UI donc pas la peine de le
revalider côté serveur ». Le travail du chasseur est littéralement de chercher ces hypothèses non-écrites
et de les violer une par une.

**Les questions à se poser, formulées comme un dialogue interne :**
- « Le développeur a probablement supposé que l'utilisateur passe TOUJOURS par le bouton de l'UI. Et si
  j'appelle l'API directement ? »
- « Le développeur a probablement supposé qu'un utilisateur ne changerait JAMAIS ce champ, donc il ne l'a
  pas revalidé. Qu'est-ce qui, dans cette requête, ressemble à une donnée que l'UI affiche mais ne laisse
  pas modifier — et que je pourrais modifier quand même en tapant directement le JSON ? »
- « Le développeur a probablement supposé qu'un événement (paiement, envoi d'email, webhook) allait
  TOUJOURS réussir. Que se passe-t-il si je le fais échouer au bon moment (couper la connexion, renvoyer
  une erreur 500 sur le service tiers simulé) — l'état reste-t-il cohérent ? »
- « Le développeur a probablement supposé qu'un attaquant n'a accès qu'à SA PROPRE instance de la
  fonctionnalité. Et si deux instances (deux comptes, deux sessions, deux onglets) interagissent ? »

**Exemple de raisonnement travaillé.** Le cas `2fa-requirement-bypass-when-inviting-team-members` du
corpus est un exemple pur : le développeur a supposé qu'un utilisateur SANS 2FA activée ne verrait jamais
le flag `2fa_required: false` retourné par le serveur autrement que par la vraie vérification. Le
chercheur n'a fait qu'une chose : intercepter la réponse et se demander « et si je force cette valeur moi-même
avant que le frontend ne la lise ? » Aucune vulnérabilité technique complexe — juste la violation d'une
hypothèse non défendue.

---

## 7. Penser en enchaînement (chaining thinking — bas + bas = haut)

**Le principe.** Un programme bug bounty rejette souvent des findings individuellement « faibles »
(clickjacking, absence de rate-limit, CSRF sur une action mineure, fuite d'information mineure). Un
expert ne les jette JAMAIS — il se demande systématiquement : « avec QUOI d'autre est-ce que je peux
combiner ça pour construire un impact réel ? »

**Les questions à se poser sur chaque finding « mineur » avant de l'abandonner :**
- Ce clickjacking, sur QUELLE page précise ? Si c'est une page qui déclenche une action sensible en un
  clic (pas juste la home), il devient un vecteur de prise de compte, pas juste un finding cosmétique.
- Cette fuite d'information mineure (un ID interne, un email partiel, un nom de champ de config) — sert-elle
  de PRÉREQUIS à une autre attaque que j'ai déjà identifiée mais que je n'ai pas pu terminer faute
  d'un identifiant précis ?
- Ce CSRF sur une action « mineure » (changer une préférence, un avatar) — cette action se répercute-t-elle
  quelque part de façon inattendue (un avatar rendu comme HTML dans un contexte admin, une préférence lue
  par un moteur de template) ?
- Cet open redirect « juste » cosmétique — s'insère-t-il dans un flow OAuth/SSO où il devient un vecteur de
  vol de code d'autorisation ?

**Exemple de raisonnement travaillé.** Le cas `duplicate-open-redirect-flow-abuse-via-oauth-validation-bypass`
du corpus est exactement ça : un open redirect « simple » sur une page de callback, individuellement
souvent jugé non-qualifiant par un triageur pressé, devient critique une fois enchaîné avec le flow OAuth
complet (le code d'autorisation part vers le domaine de l'attaquant). L'expert qui a trouvé ce bug ne
s'est pas arrêté à « je peux rediriger vers un domaine externe » — il a continué avec « et donc, qu'est-ce
qui transite AVEC cette redirection ? »

---

## 8. Penser « d'abord comprendre le métier, ensuite chercher le bug »

**Le principe.** Avant de taper le moindre payload, un expert passe du temps à comprendre CE QUE fait
réellement l'application, pour QUI, et ce qui a de la VALEUR pour un attaquant sur CE site précis. Un
site de comparaison de prix n'a pas la même surface de valeur qu'une fintech ou qu'un réseau social. Ce
n'est pas une perte de temps — c'est ce qui permet de prioriser où creuser plutôt que de tester
mécaniquement les mêmes 40 payloads partout.

**Les questions à se poser en tout début de mission :**
- Qu'est-ce que cette application MANIPULE qui a de la valeur : de l'argent, des données personnelles
  sensibles, des identités, de la propriété intellectuelle, des accès à d'autres systèmes ?
- Qui sont les DIFFÉRENTS rôles/niveaux (utilisateur gratuit vs payant, membre vs admin, tenant vs
  tenant) — et où sont les FRONTIÈRES entre ces rôles dans le produit (c'est exactement là où la logique
  métier est susceptible d'être mal gardée, cf. §2) ?
- Quelle est l'action la PLUS VALORISABLE qu'un attaquant pourrait vouloir faire sur ce site précis (pas
  en général) ? Sur une billetterie : réserver du stock gratuitement. Sur une fintech : bouger de l'argent
  ou obtenir des données de carte. Sur un réseau social : usurper une identité ou accéder à du contenu
  privé. Cette question orient ensuite QUELLES fonctionnalités auditer en priorité.
- Quelles fonctionnalités sont MANIFESTEMENT sous-testées parce qu'elles sont récentes, secondaires ou peu
  visibles (une nouvelle intégration webhook, un module bêta, une fonctionnalité d'export ajoutée
  récemment) ? Le code neuf et peu utilisé est statistiquement moins audité que le cœur historique du
  produit.

**Exemple de raisonnement travaillé.** Avant de toucher à quoi que ce soit, l'expert qui a trouvé
`exploiting-business-logic-inventory-depletion-via-parameter-tampering` a d'abord compris que la
plateforme était un système de billetterie ÉVÉNEMENTIELLE (stock fini, forte demande, paiement différé
possible pour certains partenaires). Cette compréhension métier PRÉCÈDE la découverte technique — c'est
elle qui a fait germer l'hypothèse « et si je pouvais épuiser le stock sans payer » avant même de regarder
un seul endpoint. Un chasseur qui teste mécaniquement des payloads sans cette compréhension trouve des
XSS et des en-têtes manquants ; celui qui comprend le métier trouve les bugs à fort impact.

---

## Comment utiliser ce document en pratique

Ce n'est pas une checklist à cocher mécaniquement une fois. C'est un ensemble de LENTILLES à appliquer
en boucle sur chaque fonctionnalité découverte : une fonctionnalité de checkout mérite d'être regardée à
travers §1 (état), §2 (confiance), §3 (concurrence), §5 (composition), ET §8 (métier) — pas une seule.
Le corpus de cas réels (`WRITEUP_KB.md`/`index.json`) sert de PREUVE que ce mode de pensée produit des
résultats concrets et de RÉSERVOIR d'exemples déjà résolus pour reconnaître un pattern similaire plus
vite la prochaine fois. Les deux documents sont complémentaires : celui-ci enseigne à PENSER, l'autre
donne la mémoire de ce qui a déjà été trouvé.
