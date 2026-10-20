# Fiches SSS — Race Conditions

*3 cas sélectionnés dans le corpus 2025-2026 — extraits verbatim des fichiers bruts.*

---

### Race condition on add 1 free domain

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/2616045)

Sur wordpress.com/Gravatar, un compte gratuit permet de réclamer un domaine personnalisé offert. D'après les étapes du rapport, l'utilisateur complète le paiement jusqu'à obtenir l'endpoint `public-api.wordpress.com/rest/v1.1/me/transactions?…`, crée ensuite un groupe de requêtes (duplication 1 à 15 fois), change le paramètre `meta` pour un autre nom, puis envoie toutes les copies en parallèle : plus d'un domaine gratuit est acheté avec le même compte, la limitation « 1 domaine » étant contournée. Impact : création de plusieurs domaines gratuits avec un seul compte.

**Cause racine :** le rapport établit la cause au niveau macro : la limite de domaine gratuit est contournable « by sending multiple requests at the same time » (race condition). Le détail mécanique (lecture du quota, verrou, état « déjà utilisé ») n'est pas documenté dans la source.

**Preuve technique (verbatim depuis la source) :**

```
3. after click claim domain you will redirect to
https://wordpress.com/start/domain-for-gravatar/domain-only?search=yes&new=(gravatar domain)
4. complete the payment until you get this endpoint
public-api.wordpress.com/rest/v1.1/me/transactions?
██████
5. create group request and duplicate until 1-15 times
6. change parameter "meta" to any other name
7. after complete changing meta, send all request with Group (parallel)
8. free domain will buy more than 1
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : compte gratuit Gravatar ; passage par le flux de paiement jusqu'à obtenir l'endpoint de transactions.
- Étapes : 1. Créer un compte gratuit dans Gravatar et sélectionner « claim free custom domain » sous My profile. 2. Compléter le paiement jusqu'à l'endpoint `public-api.wordpress.com/rest/v1.1/me/transactions?`. 3. Dupliquer la requête en groupe (1 à 15 fois), renommer `meta` dans chaque copie, puis envoyer le groupe en parallèle : plus d'un domaine gratuit est acheté.
- Pièges / limites : plusieurs parties du flux sont caviardées (`██████`) dans la source (URL de claim du domaine, suite de paramètres après `me/transactions?`) ; le détail du PoC est annoncé en pièce jointe, non incluse dans le texte brut ; le mécanisme interne de contrôle de quota n'est pas décrit.

**Reproductibilité :** moyenne — compte gratuit et flux de paiement requis ; méthode de course documentée mais étapes partiellement caviardées.

**Techniques :** race condition, parallel request racing, business logic limit bypass, free resource abuse

**Correspond aux classes qualifiantes :** race, business logic

**Signal (endpoints/fonctions observés) :**
- `public-api.wordpress.com/rest/v1.1/me/transactions?`
- `https://wordpress.com/start/domain-for-gravatar/domain-only?search=yes&new=…`

**Paramètres impliqués :** `meta`, `search`, `new`

---

### Race Condition in Folder Creation Allows Bypassing Folder Limit

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3104355)

L'application impose une limite de 10 dossiers par utilisateur dans un espace (`Knowledge -> Space -> Folder`). Après suppression d'un dossier (total 9), l'envoi simultané de nombreuses requêtes de création crée plus de 10 dossiers : la limite est contournée. Impact annoncé : abus de ressources et dégradation de performance pour les autres utilisateurs.

**Cause racine :** le rapport attribue la cause à une race condition observée au moment des créations simultanées : « due to a Race Condition, it is possible to bypass this limit by sending multiple folder creation requests simultaneously after deleting one folder ». La source ne détaille pas le mécanisme interne (comptage lu avant insertion, TOCTOU, verrou) — seule l'enchaînement « supprimer un dossier → bombarder les créations » est documenté.

**Preuve technique (verbatim depuis la source) :**

```
The application enforces a hard limit of **10 folders** per user under a specific space (`Knowledge -> Space -> Folder`). However, due to a **Race Condition**, it is possible to bypass this limit by sending multiple folder creation requests simultaneously after deleting one folder.

4. Delete one folder so the total becomes 9.
5. Immediately after deletion, send a large number of simultaneous folder creation requests (e.g., using Burp Suite Intruder or a custom script).
6. Observe that more than 10 folders are created — the limit is bypassed successfully.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : un compte utilisateur avec accès à la section Knowledge et à un espace.
- Étapes : 1. Naviguer dans Knowledge et entrer dans un espace précis. 2. Créer des dossiers jusqu'à la limite de 10 (une création de plus renvoie une erreur de limite). 3. Supprimer un dossier (total 9), puis envoyer immédiatement un grand nombre de requêtes de création simultanées (Burp Suite Intruder ou script maison) : plus de 10 dossiers sont créés.
- Pièges / limites : le nombre de requêtes et le timing ne sont pas documentés ; la vidéo PoC est caviardée (`███████`) ; aucune requête HTTP fournie.

**Reproductibilité :** moyenne — compte et espace requis, étapes complètes mais réussite dépendante du timing concurrent.

**Techniques :** race condition, toctou on quota check, simultaneous create requests after delete, business logic limit bypass, burp intruder parallel requests

**Correspond aux classes qualifiantes :** race, business logic

**Signal (endpoints/fonctions observés) :**
- création de dossiers dans `Knowledge -> Space -> Folder` (limite de 10)
- séquence suppression d'un dossier puis rafale de créations parallèles

**Paramètres impliqués :** non documenté dans la source

---

### Exceeding the limit of Workspaces via Race Condition

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3226838)

⚠️ texte intégral indisponible : le champ `vulnerability_information` du fichier brut `data/raw/h1/3226838.json` est vide. Seul le résumé public de l'équipe, présent dans ce même fichier (champ `summaries`), documente le cas.

Sur `backend.singlestore.com`, un utilisateur free-tier a pu contourner la limite de 5 workspaces en envoyant de multiples requêtes `CreateWorkspace` simultanées, permettant une création illimitée de workspaces et un abus potentiel de ressources. Le problème a été corrigé par SingleStore en date du 3 octobre 2025.

**Cause racine :** le résumé d'équipe documente une race condition sur le quota : « bypass the 5-workspace limit by sending multiple simultaneous CreateWorkspace requests ». Il ne précise ni atomicité, ni compteur, ni ordre des vérifications — ces détails ne sont pas dans le JSON brut (champ `vulnerability_information` vide).

**Preuve technique (verbatim depuis la source) :**

```
Reporter 4x4 discovered a race condition vulnerability in backend.singlestore.com that allowed free-tier users to bypass the 5-workspace limit by sending multiple simultaneous CreateWorkspace requests, enabling unlimited workspace creation and potential resource abuse. This issue has since been patched by SingleStore as of October 3rd, 2025.
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : non documenté dans la source (le résumé mentionne un utilisateur free-tier sur `backend.singlestore.com`).
- Étapes : non documenté dans la source.
- Pièges / limites : corps du rapport vide dans le fichier brut, aucune requête ni payload disponible ; la cible est patchée depuis le 3 octobre 2025.

**Reproductibilité :** basse — aucune étape ni artefact technique dans la source, et la cible est corrigée.

**Techniques :** race condition, simultaneous createworkspace requests, free-tier limit bypass, resource abuse

**Correspond aux classes qualifiantes :** race, business logic

**Signal (endpoints/fonctions observés) :**
- `backend.singlestore.com` — `CreateWorkspace` (d'après le résumé équipe)

**Paramètres impliqués :** non documenté dans la source
