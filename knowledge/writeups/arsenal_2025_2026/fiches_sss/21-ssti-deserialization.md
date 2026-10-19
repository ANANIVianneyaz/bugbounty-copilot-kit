# Fiches SSS — SSTI & Désérialisation

*3 fiches exploitables issues du corpus 2025-2026 — chaque extrait « Preuve technique » est copié verbatim de la source brute indiquée.*

### connect.8x8.com: Deserialization via Jint→Newtonsoft coercion (TypeNameHandling)

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3861550)
**⚠️ texte intégral indisponible** (`vulnerability_information` vide dans `data/raw/h1/3861550.json`) — fiche basée sur le résumé d'équipe du même fichier.

Un utilisateur authentifié de l'Automation Builder de 8x8 Connect fait renvoyer une réponse JSON forgée à l'étape « HTTP request » d'un workflow. L'évaluation de template côté serveur expose alors les objets Newtonsoft au moteur JavaScript Jint : la coercition de surcharge (*overload resolution*) construit un `JsonSerializer` avec un `TypeNameHandling` contrôlé par l'attaquant, permettant de désérialiser des types .NET arbitraires comme `System.Diagnostics.Process`. Correctif : projection des réponses HTTP en valeurs JavaScript simples (`System.Dynamic.ExpandoObject`) avant l'évaluation.

**Cause racine :** le moteur de template (Jint) reçoit des objets Newtonsoft bruts issus d'une réponse contrôlée par l'attaquant, lui permettant de choisir une surcharge dangereuse (`JsonSerializer` + `TypeNameHandling` attaquant) et de désérialiser des types .NET arbitraires.

**Preuve technique (verbatim depuis la source) :**

```
@kyotozzx reported a deserialization vulnerability in the 8x8 Connect Automation Builder's HTTP request step. The vulnerability occurred when server-side template evaluation exposed Newtonsoft JSON objects directly to the Jint JavaScript engine. By providing a specially crafted JSON response, an authenticated user could coerce Jint's overload resolution to construct a `JsonSerializer` with attacker-controlled `TypeNameHandling` settings, enabling deserialization of arbitrary .NET types including `System.Diagnostics.Process`.
```
```
The issue was quickly addressed by projecting HTTP responses to plain JavaScript values (`System.Dynamic.ExpandoObject`) before template evaluation, removing all Newtonsoft object exposure from the template scope.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte authentifié sur connect.8x8.com (Automation Builder), avec un workflow comportant une étape « HTTP request ».
- Étapes : 1. faire appeler par l'étape « HTTP request » un endpoint renvoyant le JSON forgé (format non publié) 2. l'évaluation du template expose l'objet Newtonsoft à Jint 3. la coercition de surcharge construit le `JsonSerializer` avec le `TypeNameHandling` attaquant et désérialise le type .NET choisi.
- Pièges / limites : rapport original non publié ; aucun payload ni étape exacte — étapes déduites du résumé.

**Reproductibilité :** basse — prérequis clairs (compte authentifié) mais aucun payload ni étape exacte publiés.

**Techniques :** deserialization of untrusted data, json.net typenamehandling, jint overload coercion, ssti template scope escape, .net rce

**Correspond aux classes qualifiantes :** deserialization, rce, ssti

**Signal (endpoints/fonctions observés) :**
- `Automation Builder — étape « HTTP request »`
- `évaluation de template côté serveur (moteur Jint)`
- `JsonSerializer / TypeNameHandling (Newtonsoft)`

**Paramètres impliqués :** `TypeNameHandling`, réponse JSON de l'étape « HTTP request »

---

### insecure deserilize object leads to RCE On Sitecore (CVE-██████████-27218)

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3090123)
**⚠️ texte intégral indisponible** (`vulnerability_information` vide dans `data/raw/h1/3090123.json`) — fiche basée sur le résumé d'équipe présent dans ce même fichier brut.

Sur une implémentation Sitecore en production (périmètre `*.banfield.com`, programme Mars), une désérialisation non sécurisée a été identifiée et assignée CVE-2025-27218. L'entrée utilisateur non assainie transite par l'en-tête `ThumbnailsAccessToken` jusqu'à `BinaryFormatter` : un attaquant peut fabriquer un objet sérialisé malveillant avec `ysoserial.net` et exécuter des commandes système arbitraires, avec compromission complète de l'hôte (création, lecture, exfiltration de fichiers). La remédiation a consisté à retirer l'accès public au site, désormais protégé par le WAF Cloudflare.

**Cause racine :** donnée utilisateur non assainie dans l'en-tête `ThumbnailsAccessToken` désérialisée par `BinaryFormatter`, qui autorise l'instanciation de types arbitraires contrôlés par l'attaquant.

**Preuve technique (verbatim depuis la source) :**

```
This critical vulnerability involves an insecure deserialization issue in Sitecore implementation on ██████████ , which has been assigned CVE-2025-27218. The vulnerability allows remote code execution (RCE) through unsanitized user input in the ThumbnailsAccessToken header. Using the BinaryFormatter serialization method, an attacker can create malicious serialized objects with tools like ysoserial.net and execute arbitrary operating system commands on the target server.
```
```
The vulnerability has been remediated by removing public access to the affected site, which is now protected behind Cloudflare WAF.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : accès HTTP à un site Sitecore vulnérable (aucune authentification mentionnée dans la source).
- Étapes : 1. générer l'objet malveillant avec `ysoserial.net` (payload exact non documenté dans la source) 2. l'envoyer dans l'en-tête `ThumbnailsAccessToken` (requête exacte non documentée) 3. la désérialisation `BinaryFormatter` côté serveur exécute les commandes OS.
- Pièges / limites : le site est depuis derrière un WAF Cloudflare ; ni le PoC ni la requête HTTP ne sont publiés dans la source.

**Reproductibilité :** basse — seuls l'en-tête vulnérable, la classe de composant (`BinaryFormatter`) et l'outil (`ysoserial.net`) sont documentés ; aucune étape ni payload.

**Techniques :** binaryformatter deserialization, ysoserial.net, http header injection, unauthenticated rce, cve-2025-27218

**Correspond aux classes qualifiantes :** deserialization, rce

**Signal (endpoints/fonctions observés) :**
- en-tête `ThumbnailsAccessToken`
- implémentation Sitecore (CVE-2025-27218)
- `BinaryFormatter` (désérialisation .NET)
- outil `ysoserial.net`

**Paramètres impliqués :** `ThumbnailsAccessToken`

---

### CVE-2025-24813: RCE via write enabled Default Servlet (Tomcat)

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3031518)

Le chercheur signale une RCE dans Apache Tomcat 9.0.98, rapportée au canal sécurité officiel de l'ASF et corrigée sous CVE-2025-24813. Quatre conditions doivent être réunies : écriture activée sur le default servlet, support du partial PUT, persistance de session Tomcat à l'emplacement de stockage par défaut, et bibliothèque exploitable en désérialisation. Impact revendiqué : exécution de commandes système.

**Cause racine :** la combinaison « écriture via le default servlet + partial PUT + fichiers de session à l'emplacement par défaut + bibliothèque désérialisable » ouvre un chemin de désérialisation exploitable en RCE (mécanisme interne non détaillé dans la source).

**Preuve technique (verbatim depuis la source) :**

```
I am sw0rd1ight.I found an Apache Tomcat RCE vulnerability in tomcat 9.0.98. 
If all of the following were true, a malicious user was able to perform remote code execution:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- application was using Tomcat's file based session persistence with the default storage location
- application included a library that may be leveraged in a deserialization attack
```
```
I reported this vulnerability through the official Apache Tomcat security email and received a fix along with a CVE number CVE-2025-24813.
```
```
Execute system commands to obtain system permissions
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : Tomcat 9.0.98 et les quatre conditions ci-dessus (écriture default servlet activée explicitement ; partial PUT activé par défaut ; sessions fichier à l'emplacement par défaut ; bibliothèque désérialisable présente).
- Étapes : non documentées dans la source (rapport court renvoyant aux échanges e-mail avec l'ASF ; les captures `{F4134453}`…`{F4134466}` ne sont pas fournies).
- Pièges / limites : configuration rare en production, aucune requête HTTP publiée.

**Reproductibilité :** basse — conditions précisément listées mais aucune étape, requête ou payload dans la source.

**Techniques :** partial put, default servlet write enabled, file based session persistence, deserialization rce, cve-2025-24813

**Correspond aux classes qualifiantes :** rce, deserialization

**Signal (endpoints/fonctions observés) :**
- `Apache Tomcat 9.0.98`
- `default servlet` avec écriture activée
- support du `partial PUT`
- `file based session persistence` (emplacement par défaut)
- `CVE-2025-24813`

**Paramètres impliqués :** non documenté dans la source
