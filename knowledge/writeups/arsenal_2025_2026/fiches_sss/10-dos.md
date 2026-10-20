# Fiches SSS — Denial of Service

*3 cas réels 2025-2026 (HackerOne) : cause racine, preuves verbatim et plan de reproduction dérivés de la source uniquement.*

---

### DOS of RSKJ server

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/2105808)

Un attaquant paralyse un nœud RSKJ (Rootstock) avec un paquet UDP malformé. Le serveur est lancé depuis le jar officiel `rskj-core-5.0.0-FINGERROOT-all.jar`, qui ouvre le port `UDPv6` `5050`. Le client exécute ensuite un script Python (`poc.py`) contre ce port : l'`UDPServer` traite alors *un seul* paquet UDP à jamais et cesse de traiter ceux des autres nœuds ; au bout de quelques minutes, l'application plante en `Out of memory`. Le décodage RLP est en cause : `bytesToLength` renvoie `-5`, la longueur devient `0` et la position reste inchangée. La fonction vulnérable `decode2` étant utilisée partout, d'autres points d'entrée du service peuvent être affectés. Rapport publié le 2025-06-13, bounty $5 000, 120 votes.

**Cause racine :** décodage RLP invalide — `bytesToLength` renvoie `-5`, longueur `0`, position inchangée (`RLP.java`) : un paquet UDP malformé bloque définitivement l'`UDPServer`, puis provoque un `Out of memory`.

**Preuve technique (verbatim depuis la source) :**

```text
bytesToLength returns -5 and length becomes 0
https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/util/RLP.java#L432
this is legal
https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/util/RLP.java#L440
and position is unchangeable
```
```text
the `UDPServer` is going to process *only* one UDP packet forever and it prevents to process other packages received from different nodes. In a while (some minutes left) the application crashes.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : jar `rskj-core-5.0.0-FINGERROOT-all.jar` (release publique) ; côté client Python 3 avec `pip install pysha3` ; le script `poc.py` est une pièce jointe (`{F2591198}`, 427 octets) absente du texte.
- Étapes : 1. Télécharger le jar. 2. Côté serveur : `java -classpath rskj-core-5.0.0-FINGERROOT-all.jar -Drpc.providers.web.cors=* -Drpc.providers.web.ws.enabled=true co.rsk.Start` → ouvre le port UDPv6 5050. 3. Côté client : installer `pysha3`, récupérer `poc.py`, modifier `HOST`, lancer le script contre le serveur. 4. Observer l'`UDPServer` bloqué sur un seul paquet, puis le crash `Out of memory`.
- Pièges / limites : `poc.py` est une pièce jointe (`{F2591198}`) non incluse dans le texte ; le rapport consolide la fermeture d'un autre rapport (`#2102315`) ; `decode2` étant utilisée partout, d'autres entrées peuvent être vulnérables (non détaillées).

**Reproductibilité :** moyenne — jar public et étapes complètes, mais le script d'attaque reste une pièce jointe et le blocage dépend d'un paquet RLP malformé précis.

**Techniques :** dos, uncontrolled resource consumption, udp packet stall, rlp decoding flaw, out of memory, java node

**Correspond aux classes qualifiantes :** dos (availability), resource accounting (uncontrolled resource consumption)

**Signal (endpoints/fonctions observés) :**
- port `UDPv6` `5050` (`UDPServer`)
- décodage RLP : `bytesToLength`, `decode2` (`org/ethereum/util/RLP.java` L403/L405/L432/L440)
- point d'entrée : `co.rsk.Start` (jar `rskj-core-5.0.0-FINGERROOT-all.jar`)

**Paramètres impliqués :** `HOST` (dans `poc.py`), charge UDP malformée (RLP), port `5050`
### Denial of Service (DoS) Vulnerability in Drafts Creation Endpoint

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3400140)

Sur `try.discourse.org`, un utilisateur authentifié soumet des brouillons de ~800 000 caractères à `POST /drafts.json`. Le serveur traite et sauvegarde le brouillon malgré un 502 Bad Gateway retourné au client ; en envoyant 9 brouillons uniques (séquentiels ou parallèles), les réponses suivantes atteignent 32,108 secondes, signe d'épuisement de ressources côté backend. Le rapport note que le payload ne peut pas être posté comme message (validation) mais que les brouillons contournent cette limite. Aucune requête HTTP complète n'est publiée : les étapes sont décrites et un payload externe est référencé.

**Cause racine :** l'endpoint de brouillons accepte et persiste des charges énormes sans la validation de taille appliquée aux messages normaux, chaque sauvegarde consommant lourdement le backend (traitement + stockage), jusqu'à la saturation du service.

**Preuve technique (verbatim depuis la source) :**

```
Intercept a request to create a draft (e.g., using Burp Suite or a similar proxy) at POST /drafts.json.
Modify the payload to include a large string in the draft content (e.g., use the large payload from https://github.com/DpaysmX/payload_/blob/main/payload.txt, adapted as a long string in the data or draft field).
Submit the request. Observe that the server returns a 502 Bad Gateway error, but the draft is still saved (check the drafts section or via GET requests).

Monitor response times: The server slows down, with durations up to 32.108 seconds for subsequent requests.

Note: The payload cannot be posted as a message (due to validation), but drafts bypass this, allowing abuse.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte de test authentifié sur l'instance Discourse cible ; le payload volumineux référencé (lien externe) ; Burp Suite ou proxy équivalent (optionnel).
- Étapes : 1. Se connecter avec un compte de test. 2. Intercepter la requête de création de brouillon `POST /drafts.json` et remplacer le contenu par la chaîne géante (~800 000 caractères, champ `data` ou `draft`). 3. Soumettre : 502 mais brouillon sauvegardé (vérifier la section drafts ou via GET). 4. Créer 9 brouillons uniques (variations légères / compteur séquentiel pour éviter l'erreur « already editing »), en séquence ou en parallèle, et mesurer les temps de réponse (jusqu'à 32,108 s observés).
- Pièges / limites : chaque brouillon doit avoir une clé/ID unique pour ne pas entrer en conflit ; le 502 masque le succès de l'opération ; le lien du payload est externe au rapport (peut disparaître) ; aucun verbatim HTTP.

**Reproductibilité :** moyenne — nécessite un compte authentifié et un payload externe, mais les étapes sont complètes et sans secret.

**Techniques :** authenticated dos, uncontrolled resource consumption, large payload, validation bypass via alternate endpoint, request amplification

**Correspond aux classes qualifiantes :** dos, resource accounting (uncontrolled resource consumption)

**Signal (endpoints/fonctions observés) :**
- `POST /drafts.json` (création de brouillon acceptée malgré 502)
- payload ~800 000 caractères : `https://github.com/DpaysmX/payload_/blob/main/payload.txt`
- latence serveur > 30 s après 8-9 brouillons uniques

**Paramètres impliqués :** champ contenu du brouillon (`data` / `draft`), identifiants uniques de brouillon

---

### Critical Deadlock Vulnerability in Monero RPC Leading to Complete Node Paralysis

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3307874)

Un attaquant distant non authentifié paralyse complètement un nœud Monero avec une seule requête HTTP contenant une combinaison de méthodes batch JSON-RPC. Le PoC multithread (50 threads) mélange méthodes RPC valides, requêtes malformées et requêtes lourdes, avec taille de batch adaptative, gzip et randomisation d'en-têtes ; résultat : 29+ threads bloqués, nœud deadlocké, qui ne répond plus en RPC, P2P ni admin et ne réagit plus à SIGTERM/SIGINT — seul `kill -9` le termine. Sont affectés Monero « Fluorine Fermi » (v0.18.4.2-2987b7200), probablement toutes versions précédentes, tous OS et tous modes (mainnet, testnet, offline, restricted-rpc).

**Cause racine :** « Deadlock occurs when Monero RPC threads enter circular wait on shared resources during batch request handling » — l'attente circulaire est déclenchable par n'importe quelle combinaison de méthodes RPC batch, y compris en mode restreint/offline.

**Preuve technique (verbatim depuis la source) :**

```
python3 exploit/PoC.py http://localhost:28081/json_rpc 50 500

- Node becomes completely unresponsive (RPC, P2P, admin)
- Standard termination signals (SIGTERM/SIGINT) do not work
- Only kill -9 can terminate the process

  - Gzip compression for large payloads
  - User-Agent and X-Forwarded-For randomization to bypass basic filtering
  - Effect: 29+ threads blocked, node deadlocked, requires SIGKILL to recov

Deadlock occurs when Monero RPC threads enter circular wait on shared resources during batch request handling.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : accès réseau au port JSON-RPC du nœud (ex. 28081 en testnet), aucune authentification ; nœud Monero vulnérable, tout mode de fonctionnement.
- Étapes : 1. Démarrer le nœud (`./monerod --testnet --data-dir … --rpc-bind-port 28081 --p2p-bind-port 28080 --restricted-rpc --confirm-external-bind --add-exclusive-node 127.0.0.1:28080 --log-level 4`). 2. Lancer le script : `python3 exploit/PoC.py http://localhost:28081/json_rpc 50 500`. 3. Observer le nœud complètement bloqué et le tuer avec `kill -9`.
- Pièges / limites : le script PoC lui-même n'est pas inclus dans le texte du rapport (seulement référencé, avec `gdb_thread_dump.txt`, `process_status.txt`, `deadlock_graph.png`) ; le script est adaptatif face aux réponses 413/429/batch trop gros ; latence de déclenchement non chiffrée dans la source.

**Reproductibilité :** basse — le script d'exploitation n'est pas fourni dans la source et le déclenchement dépend d'un batch/contexte précis sur un nœud Monero à faire tourner.

**Techniques :** dos, deadlock, json-rpc batch abuse, unauthenticated attack, adaptive payloads, header randomization, gzip body

**Correspond aux classes qualifiantes :** dos, resource exhaustion (deadlock)

**Signal (endpoints/fonctions observés) :**
- `POST /json_rpc` (batch de méthodes ; port RPC 28081 en testnet)
- deadlock persistant même avec `--restricted-rpc` ou en mode offline
- artefacts : `gdb_thread_dump.txt`, `process_status.txt`, `deadlock_graph.png`

**Paramètres impliqués :** batch `methods`, `--rpc-bind-port`, corps gzip, `User-Agent`, `X-Forwarded-For`
