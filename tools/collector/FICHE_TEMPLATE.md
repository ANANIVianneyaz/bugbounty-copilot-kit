# Gabarit des fiches SSS (format aligné sur `WRITEUP_KB.md`)

Chaque fiche suit ce gabarit EXACT. Le contenu vient UNIQUEMENT de la source
(`data/raw/h1/<id>.json` pour HackerOne, page rendue sinon) — jamais d'invention,
jamais de PoC reconstruit de mémoire.

```markdown
### <Titre — titre source, raccourci si > 90 caractères>

**📄 Cas réel**
sévérité : <critical|high|medium|low> · [source](<url exacte>)

<Résumé factuel 2-6 lignes : contexte, découverte, mécanisme, impact.>

**Cause racine :** <1-3 lignes, le défaut unique à la base du bug.>

**Preuve technique (verbatim depuis la source) :**

```
<2-3 extraits VERBATIM les plus décisifs : requêtes HTTP, payloads,
code vulnérable/patch, commandes. Jamais réécrits, jamais complétés.>
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : <compte/rôle/contexte — uniquement ce que la source indique>
- Étapes : 1. <…> 2. <…> 3. <…>
- Pièges / limites : <WAF, rate limit, ID à haute entropie, info préalable requise… si documenté>

**Reproductibilité :** <haute|moyenne|basse> — <justification en 1 ligne>

**Techniques :** <3-8 items normalisés, minuscules, séparés par des virgules —
ex. `idor sequential ids, waf bypass via headless browser, pin bruteforce`>

**Correspond aux classes qualifiantes :** <classes : idor, xss, ssrf, rce, ato,
csrf, sqli, race, open redirect, subdomain takeover, cache poisoning, ...>

**Signal (endpoints/fonctions observés) :**
- `<endpoint, paramètre, fonction ou comportement clé>`

**Paramètres impliqués :** `param1`, `param2`
```

## Échelle de reproductibilité

- **haute** — prérequis accessibles (aucun compte, ou compte trivial) + étapes
  complètes dans la source + aucun secret/imprévu à deviner.
- **moyenne** — nécessite un compte/utilisateur, un ID secret, une droite
  d'interaction ou un contexte spécifique ; étapes néanmoins complètes.
- **basse** — dépend de conditions rares (timing de course précis, chaîne
  complexe, version spécifique), ou la source ne donne pas assez d'étapes.

## Règles de qualité

1. **Zéro invention.** Si une information n'est pas dans la source brute, elle
   n'existe pas dans la fiche. En cas de doute, omettre.
2. **Preuves courtes.** Maximum ~15 lignes pour tout le bloc preuve. Choisir les
   artefacts qui expliquent le bug (requête de vuln, payload final, diff/patch).
3. **Sévérité.** Utiliser celle de la source (`severity_rating` pour H1).
4. **Pas d'exploitation au-delà de la source.** On documente, on ne complète pas
   le PoC avec des variantes non publiées. Pour « Rejouer / exploiter », si la
   source ne détaille pas une sous-partie : écrire `non documenté dans la source`.
5. **Pas de ToC, pas de méta.** La fiche commence par `### Titre` et finit par
   le bloc « Paramètres impliqués » (sauf absence).
6. **Si la source n'a pas d'artefact technique** (writeup narratif) :
   remplacer le bloc preuve par :
   `**Preuve technique :** aucune publiée dans la source (cas narratif).`
7. **Longueur cible :** 150-400 mots par fiche.
8. **Langue :** labels en français comme ci-dessus ; termes techniques, titres et
   extraits laissés dans leur langue d'origine.
9. **Exploitabilité d'abord.** Le but d'une fiche est qu'un hunter puisse
   reconnaître le signal et rejouer le test. Signal + prérequis + étapes priment
   sur le récit.

## Barème de sélection (« SSS »)

- Sévérité Critical/High, bounty > 0, votes élevés, 2026 prioritaire.
- Texte brut riche (requêtes HTTP, payloads, patches).
- Diversité : ~3 fiches par catégorie, sans doublon de cible/programme.
