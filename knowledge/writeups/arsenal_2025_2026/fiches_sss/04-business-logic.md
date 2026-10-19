# Fiches SSS — Business Logic Flaws

*3 fiches SSS rejouables, tirées de cas réels du corpus 2025-2026.*

### Wallet RPC Restricted-Mode Policy Bypass (Monero)

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3620006)

`monero-wallet-rpc --restricted-rpc` est annoncé « view-only », mais de nombreux handlers non lecture seule n'appliquent pas `m_restricted`. Validé localement : `create_wallet`, `close_wallet`, `open_wallet`, `create_address`, `export_key_images` réussissent en mode restreint (et `get_tx_key`/`get_reserve_proof` atteignent leur logique de preuve/clé), alors que `transfer` — correctement gardé — renvoie « Command unavailable in restricted mode. ». Un client restreint peut donc créer/ouvrir/fermer des wallets et muter l'état, y compris avec l'authentification digest active.

**Cause racine :** L'application du mode restreint est dispersée handler par handler au lieu d'une allowlist centralisée : la liste des handlers non gardés inclut `create_wallet`, `close_wallet`, `open_wallet`, `create_address`, `export_key_images`, `get_tx_key`, `get_reserve_proof`, etc.

**Preuve technique (verbatim depuis la source) :**

```
const command_line::arg_descriptor<bool> arg_restricted = {"restricted-rpc", "Restricts to view-only commands", false};
...
if (m_restricted)
{
  er.code = WALLET_RPC_ERROR_CODE_DENIED;
  er.message = "Command unavailable in restricted mode.";
  return false;
}
...
rpc '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"attacker_wallet","password":"testpass","language":"English"}}'
...
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {}
}
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : binaire `monero-wallet-rpc` en mode restreint (série introduite par le commit `a64f57fe…`, releases ≥ v0.13.0.0-RC1) ; credentials digest si l'authentification est activée.
- Étapes : 1. Lancer le daemon avec `--restricted-rpc --offline --disable-rpc-login` et un `--wallet-dir`. 2. Envoyer `create_wallet` sur `/json_rpc` → `"result": {}` (succès). 3. `close_wallet`, puis `get_balance` → « No wallet file » (impact disponibilité) ; `open_wallet` et `create_address` réussissent aussi. 4. Contrôle négatif : `transfer` → « Command unavailable in restricted mode. ».
- Pièges / limites : le RPC écoute en loopback par défaut et l'authentification reste active sauf désactivation — le framing réseau suppose un opérateur exposant un client restreint distant.

**Reproductibilité :** haute — PoC scripté complet fourni (avec et sans auth digest), exécution locale.

**Techniques :** authorization bypass, restricted mode bypass, ad hoc policy enforcement, state mutation, local rpc

**Correspond aux classes qualifiantes :** auth bypass, improper access control, dos

**Signal (endpoints/fonctions observés) :**
- `POST /json_rpc` (monero-wallet-rpc) : `create_wallet`, `close_wallet`, `open_wallet`, `create_address`, `export_key_images`
- Option `--restricted-rpc` (« Restricts to view-only commands »)
- Contrôle négatif : `transfer` → `Command unavailable in restricted mode.`

**Paramètres impliqués :** `filename`, `password`, `language`, `account_index`, `all`

---

### wallet-rpc crash via malformed /gettransactions response (empty txs → vector::front())

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3693636)

`wallet2` fait confiance à la réponse `/gettransactions` de son daemon pour la vérification de paiement. Le garde n'exige qu'UNE des deux représentations (`txs` structuré ou `txs_as_hex` legacy) de longueur 1 : si le daemon (ou un MITM sur HTTP clair) renvoie `status: OK`, `txs: []` et un blob unique dans `txs_as_hex` dont le hash correspond, le code parse la transaction puis lit quand même `res.txs.front()` pour le pool height/confirmations → UB sur vecteur vide (segfault en Release). Même schéma dans `check_tx_proof` et sur le chemin cold de `get_tx_key` (`txs_as_hex.front()`).

**Cause racine :** Garde disjonctif (`txs.size()!=1 && txs_as_hex.size()!=1`) suivi d'un accès inconditionnel à `res.txs.front()` : les deux représentations sont supposées synchronisées sans l'être.

**Preuve technique (verbatim depuis la source) :**

```
THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
  error::wallet_internal_error, "Failed to get transaction from daemon");
...
in_pool = res.txs.front().in_pool;   // ← txs may still be empty
...
{"status":"OK","untrusted":false,"credits":0,"top_hash":"","txs":[],"txs_as_hex":["<hex>"],"missed_tx":[]}
...
curl: (52) Empty reply from server
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : builds `monerod`+`monero-wallet-rpc` en regtest ; position MITM sur la jambe wallet→daemon ; scripts `reports/poc_gettransactions_empty_txs_crash.sh` et `poc_proxy_malicious_gettransactions.py`.
- Étapes : 1. Démarrer monerod regtest, créer un wallet, miner, self-transfer avec `get_tx_key` (triplet txid/tx_key/address). 2. Capturer le hex canonique via un `/gettransactions` honnête. 3. Démarrer le proxy malveillant, relancer le wallet avec `--daemon-address` pointant sur le proxy puis un `set_daemon` de reconnexion. 4. Appeler `check_tx_key` → le wallet meurt (signal 11 / segfault).
- Pièges / limites : le proxy PoC ajoute `Connection: close` (hygiène de labo) ; impact = DoS/UB, aucune RCE revendiquée.

**Reproductibilité :** moyenne — chaîne MITM + builds Monero, mais scripts PoC complets fournis.

**Techniques :** mitm, daemon response spoofing, empty vector front(), undefined behavior crash, payment verification abuse

**Correspond aux classes qualifiantes :** dos, mitm, memory corruption adjacency

**Signal (endpoints/fonctions observés) :**
- `POST /gettransactions` (réponse `txs: []` + un seul `txs_as_hex`)
- `check_tx_key`, `check_tx_proof`, `get_tx_key` (wallet2.cpp)

**Paramètres impliqués :** `txs`, `txs_as_hex`, `txs_hashes`, `status`

---

### Approval app's file-freshness check bypassed by omitting the etag parameter (Nextcloud)

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3610332)

Dans l'app Nextcloud Approval, un approbateur ne devrait pas pouvoir approuver un fichier modifié après sa relecture (protection par etag). Le backend n'applique ce contrôle que si le paramètre `etag` est présent et non vide. En interceptant la requête d'approbation depuis l'UI et en supprimant `etag`, l'approbateur valide une version du fichier différente de celle relue — réponse `HTTP/1.1 200 OK`. Impact : intégrité du workflow d'approbation (artefacts conformité, légaux, financiers, release).

**Cause racine :** Le contrôle de fraîcheur est conditionné à la présence de `etag` : « the backend only enforces this check when the etag parameter is present and non-empty. »

**Preuve technique (verbatim depuis la source) :**

```
PUT /ocs/v2.php/apps/approval/api/v1/approve/14831 HTTP/1.1
Host: 172.16.88.96:8081
...
{"message":"test2"}
...
HTTP/1.1 200 OK
...
{"ocs":{"meta":{"status":"ok","statuscode":200,"message":"OK"},"data":[]}}
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : workflow d'approbation configuré ; test1 (demandeur) et test2 (approbateur avec accès au fichier).
- Étapes : 1. Créer un workflow d'approbation. 2. Connecté en test1, uploader un fichier (ex. poc.md) et demander l'approbation. 3. Connecté en test2, relire le contenu puis cliquer Approve — intercepter `PUT /ocs/v2.php/apps/approval/api/v1/approve/<id>`. 4. Revenu en test1, modifier le fichier après la relecture. 5. test2 supprime le champ `etag` du corps JSON et forward : 200 OK, approbation appliquée.
- Pièges / limites : nécessite le workflow déjà en place et une modification du fichier entre relecture et approbation ; non documenté au-delà.

**Reproductibilité :** moyenne — deux comptes et un workflow d'approbation configuré requis ; étapes complètes.

**Techniques :** business logic, missing parameter validation, etag bypass, integrity bypass, workflow abuse

**Correspond aux classes qualifiantes :** business logic, access control weakness

**Signal (endpoints/fonctions observés) :**
- `PUT /ocs/v2.php/apps/approval/api/v1/approve/<id>` (champ `etag` optionnel)
- Réponse OCS `{"meta":{"status":"ok"}}` malgré un fichier modifié depuis la relecture

**Paramètres impliqués :** `etag`, `message`, `requesttoken`
