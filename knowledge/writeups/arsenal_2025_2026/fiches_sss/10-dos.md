# Fiches SSS — Denial of Service

*3 cas réels 2025-2026 (HackerOne) : cause racine, preuves verbatim et plan de reproduction dérivés de la source uniquement.*

---

### Netlify Authentication Token Exposed in Public Mozilla CI Logs

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/2915647)

Un token d'authentification Netlify du compte « Mozilla IT Web SRE » a été trouvé dans un log CI public de Mozilla (`live.log`, task `d5NRF8FdQamV9XdPO_mTBQ`, mot-clé `auth:`). Le token, valide pour l'API Netlify, portait les rôles Owner, Developer, Billing Admin, Reviewer, Publisher et Content Editor, donnant un contrôle complet sur les sites (dont `https://crash-pings.mozilla.org`), le déploiement, les variables d'environnement, les logs et la facturation. Le rapport liste comme risques le détournement de l'email de facturation, la compromission de sites, l'exposition de données et la perte définitive de contrôle. La valeur du token est masquée (`███`) dans le rapport.

**Cause racine :** un pipeline CI a écrit un token d'authentification vivant dans des logs de build accessibles publiquement, sans masquage — exposition de credential dans un artefact public.

**Preuve technique (verbatim depuis la source) :**

```
curl -X GET https://api.netlify.com/api/v1/accounts -H "Authorization: Bearer ████" -s | jq

    "roles_allowed": [
      "Owner",
      "Developer",
      "Billing Admin",
      "Reviewer",
      "Publisher",
      "Content Editor"
    ],

   - Search for the keyword `auth:` in the log file.
   - Extract the Netlify token (e.g., `███`).
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte — la page de log est publique : `https://firefox-ci-tc.services.mozilla.com/tasks/d5NRF8FdQamV9XdPO_mTBQ/runs/0/logs/public/logs/live.log`. Le token réel est masqué dans le rapport (non rejouable tel quel).
- Étapes : 1. Ouvrir l'URL du log public. 2. Chercher le mot-clé `auth:` et extraire le token Netlify. 3. Vérifier sa validité : `curl -X GET https://api.netlify.com/api/v1/accounts -H "Authorization: Bearer <token>" -s | jq` → réponse contenant les infos du compte (name, role, billing_email, roles_allowed, saml_config…). 4. Confirmer l'accès complet via les autres endpoints de l'API Netlify (déployer, supprimer, modifier des sites ; lire variables d'environnement et logs) — la documentation référence est `https://open-api.netlify.com`.
- Pièges / limites : le token est intégralement masqué (`███`) et a vraisemblablement été révoqué ; le rejeu nécessite un log équivalent non nettoyé. La source recommande révocation, audit des pipelines (masquage) et scopes OAuth/IP allowlisting.

**Reproductibilité :** basse — le credential est masqué et révoqué ; seule la technique (fouille de logs CI publics) est rejouable, pas l'artefact.

**Techniques :** secrets in public ci logs, token leak, public build logs, api token abuse, credential exposure, log mining

**Correspond aux classes qualifiantes :** information disclosure, credential leak, ato (account/site takeover)

**Signal (endpoints/fonctions observés) :**
- log public `…/tasks/d5NRF8FdQamV9XdPO_mTBQ/runs/0/logs/public/logs/live.log` (mot-clé `auth:`)
- `https://api.netlify.com/api/v1/accounts` avec `Authorization: Bearer`
- compte « Mozilla IT Web SRE », site `https://crash-pings.mozilla.org`

**Paramètres impliqués :** `Authorization: Bearer`, `billing_email`, `selected_access_site_ids`, `roles_allowed`

---

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
