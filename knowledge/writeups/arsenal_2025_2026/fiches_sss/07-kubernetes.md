# Fiches SSS — Kubernetes & Conteneurs

*3 cas sélectionnés dans le corpus 2025-2026. Preuves verbatim extraites des fichiers bruts `tools/collector/data/raw/h1/<id>.json` (texte intégral HackerOne, ou résumé d'équipe quand le texte intégral est absent).*

---

### elections.k8s.io uses weak session secret key, may place elections at risk

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/1387366)

`elections.k8s.io` (application d'élection Elekto) signe ses cookies d'authentification avec une `SECRET_KEY` Flask faible, littéralement la chaîne `N/A`. Découverte via l'outil CookieMonster (avec @nagli) : un cookie `session=eyJ…` récupéré sans authentification est décodé puis bruteforcé hors ligne avec `flask-unsign`, qui retrouve la clé. L'impact n'est pas forcément une prise de contrôle complète, Elekto injectant le jeton OAuth GitHub dans la session plutôt qu'un identifiant utilisateur (difficile à obtenir pour un tiers) ; la clé permet de manipuler la session et d'envisager du CSRF sur les flux de vote/authentification.

**Cause racine :** la clé de signature `SECRET_KEY` de l'application n'a jamais été renseignée pour de bon : le code source (Elekto) porte la valeur par défaut `env('APP_KEY', 'test')` avec l'avertissement « please do not deploy before doing this! », et le rapport confirme que l'instance déploie la valeur `N/A` (« this is what you have set to `N/A` »), relevée par `flask-unsign`. Cookies signés donc forgeables.

**Preuve technique (verbatim depuis la source) :**

```
# Encryption Key
#
# This is used by the Flask server and should be set to a random character
# string, please do not deploy before doing this!.
SECRET_KEY = env('APP_KEY', 'test')

% curl https://elections.k8s.io -Is | grep cookie
set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.YX-V3g.NET76NNJbweb_qagyfYl2_7TDJg; Expires=Thu, 02 Dec 2021 07:23:10 GMT; HttpOnly; Path=/

% flask-unsign -u -c "eyJfcGVybWFuZW50Ijp0cnVlfQ.YX-V3g.NET76NNJbweb_qagyfYl2_7TDJg"
…
[+] Found secret key after 8192 attemptspdcQHNyXaB0O
'N/A'
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : accès réseau à l'application ; aucun compte (le `curl` est anonyme) ; `pip3 install flask-unsign[wordlist]` pour la vérification.
- Étapes : 1. `curl https://elections.k8s.io -Is | grep cookie` récupère le cookie `session`. 2. `flask-unsign -u -c "<cookie>"` : décodage `{'_permanent': True}`, bruteforce qui retrouve `'N/A'` après 8192 essais (wordlist par défaut, 8 threads). 3. Forger/altérer la session signée — non documenté dans la source.
- Pièges / limites : le cookie contient le jeton OAuth GitHub, pas un identifiant utilisateur : l'usurpation d'un tiers est difficile sans son jeton ; impact « likely » sans PoC de bout en bout ; `CookieMonster` n'était pas public au moment du rapport.

**Reproductibilité :** haute — aucun compte requis, commandes exactes, secret trivial retrouvé hors ligne.

**Techniques :** weak flask secret key, session cookie forgery, offline cookie brute force, flask-unsign, stateless session cracking

**Correspond aux classes qualifiantes :** session forgery, ato (potentiel), csrf

**Signal (endpoints/fonctions observés) :**
- Cookie `session` signé Flask servi par `elections.k8s.io`
- `SECRET_KEY` (Elekto `config.py`) alimentée par `APP_KEY`

**Paramètres impliqués :** cookie `session`, variable `APP_KEY`

---

### Existence of completed pods allows for bypass of Kubernetes NetworkPolicy

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3328291)

Le contrôleur Amazon VPC CNI, quand il gère les règles NetworkPolicy, applique les règles de firewall des pods Completed comme s'ils tournaient encore : ces règles restent attachées à leur adresse IP et sont héritées par n'importe quel pod qui reçoit ensuite la même IP. Un pod B à qui aucune politique n'accorde d'accès peut donc obtenir l'accès d'un pod A terminé, jusqu'à la suppression du pod A. Testé sur EKS 1.33, en auto mode avec le network policy controller, et sans auto mode avec les add-ons VPC CNI v1.19.5-eksbuild.1 et v1.20.1-eksbuild.3 ; le mode strict n'a aucun effet.

**Cause racine :** le contrôleur ne traite pas la fin d'un pod (completion) comme sa suppression : les règles de firewall ne sont pas retirées quand le pod se termine, et l'IP réutilisée hérite des droits.

**Preuve technique (verbatim depuis la source) :**

```
The Amazon VPC CNI controller, when configured to manage NetworkPolicy rules, will incorrectly apply firewall rules for Completed pods as if the pods are still running, causing these rules to be applied to other unrelated pods that happen to receive the same IP address as a Completed pod.

However if there is an _allowed_ job in Completed state, the _blocked_ pod has a chance of receiving the same IP address as the completed _allowed_ pod, when that happens the _blocked_ pod will, in violation of the NetworkPolicy, be able to access the Deployment.

The correct behavior would be to check for pod completion and treat pod completion the same as pod deletion, removing firewall rules when a pod is finished.

image: "alpine/curl:latest"
command: ["curl", "-v", "whoami.networkpolicy-test.svc.cluster.local:80"]
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : cluster EKS avec auto mode + network policy controller activé, ou contrôleur VPC CNI avec `enableNetworkPolicy` à true ; droits pour créer namespace, Deployment, Service, NetworkPolicy et Jobs ; images `traefik/whoami:latest` et `alpine/curl:latest`.
- Étapes : 1. Appliquer les ressources préparatoires : namespace `networkpolicy-test`, Deployment `whoami`, Service, et NetworkPolicy n'autorisant l'ingress que vers les pods `test: allowed` sur le port 80. 2. Vérifier qu'un Job `allowed` joint le service et qu'un Job `blocked` (label `test: blocked`) bloque puis expire. 3. Créer 20 Jobs `allowed`, attendre qu'ils se terminent (pods Completed). 4. Créer 20 Jobs `blocked` : ceux qui reçoivent l'IP d'un pod `allowed` terminé atteignent le Deployment et sortent en succès, les autres échouent correctement.
- Pièges / limites : succès probabiliste lié à la réutilisation des IP (« Almost certainly some of the _blocked_ pods… » avec 20 Jobs de chaque côté) ; les fichiers YAML « attached » de la source sont masqués (████████) et doivent être reconstruits à partir des ressources documentées ; le mode strict ne change rien ; versions testées précises (EKS 1.33, add-ons cités).

**Reproductibilité :** moyenne — contexte de cluster et versions CNI précis, résultat dépendant de la réutilisation d'IP (probabiliste mais attendu avec 20 Jobs).

**Techniques :** kubernetes network policy bypass, stale firewall rules on completed pods, pod ip reuse, aws vpc cni controller

**Correspond aux classes qualifiantes :** access control bypass, network policy bypass

**Signal (endpoints/fonctions observés) :**
- Règles firewall VPC CNI attachées à l'IP d'un pod Completed et non retirées
- `enableNetworkPolicy` du contrôleur VPC CNI / auto mode EKS
- NetworkPolicy `networkpolicy-test/ingress` (podSelector `test: allowed`, port 80)

**Paramètres impliqués :** `enableNetworkPolicy`, labels `test: allowed` / `test: blocked`, adresse IP des pods

---

### RBAC bypass on App log endpoints via `permissionRequired` typo

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3589551)

⚠️ texte intégral indisponible — le fichier brut `data/raw/h1/3589551.json` ne contient pas de `vulnerability_information` ; seuls le titre, le CVE et le résumé d'équipe sont exploitables.

Une typo dans le mécanisme de permissions fait que les endpoints de logs d'App de Rocket.Chat (`/api/apps/logs` et `/api/apps/:id/logs`) ne sont pas correctement protégés : tout utilisateur authentifié peut récupérer des informations par des requêtes GET, y compris des logs d'Enterprise App en principe réservés aux admins. Le correctif touche les versions <8.4.0, <8.3.2, <8.2.2, <8.1.3, <8.0.4, <7.13.6, <7.12.7, <7.11.7 et <7.10.10 ; CVE-2026-29197.

**Cause racine :** d'après le titre, une typo dans la clé de permission (`permissionRequired`) rend la vérification de droits inopérante sur les endpoints de logs d'App ; le résumé d'équipe parle d'« a typo in the permissions mechanism ». Le détail du code fautif n'est pas documenté dans le fichier brut.

**Preuve technique (verbatim depuis la source — résumé d'équipe du JSON brut) :**

```
A typo in the permissions mechanism for `/api/apps/logs` and `/api/apps/:id/logs` allows any authenticated user to retrieve information via GET requests.

Affects versions <8.4.0, <8.3.2, <8.2.2, <8.1.3, <8.0.4, <7.13.6, <7.12.7, <7.11.7, and <7.10.10.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : un compte Rocket.Chat valide (« any authenticated user ») sur une instance en version affectée.
- Étapes : 1. S'authentifier — non documenté dans la source. 2. Envoyer une requête `GET /api/apps/logs` (ou `GET /api/apps/:id/logs`) — format exact, en-têtes et exemple de réponse non documentés dans la source. 3. Constater le retour d'informations normalement réservées aux administrateurs.
- Pièges / limites : le texte intégral du rapport est indisponible (aucun PoC, payload ou diff fourni) ; la liste des versions corrigées ci-dessus permet de situer les cibles ; le CVE-2026-29197 est référencé dans le JSON brut.

**Reproductibilité :** basse — la source ne donne ni étapes détaillées ni artefact, seulement le résumé d'équipe et les versions affectées.

**Techniques :** broken access control, rbac bypass, typo in permission check, authenticated information disclosure

**Correspond aux classes qualifiantes :** idor, broken access control, information disclosure

**Signal (endpoints/fonctions observés) :**
- `GET /api/apps/logs`
- `GET /api/apps/:id/logs`
- clé de permission `permissionRequired` (titre source)

**Paramètres impliqués :** aucun (aucun paramètre documenté dans la source)
