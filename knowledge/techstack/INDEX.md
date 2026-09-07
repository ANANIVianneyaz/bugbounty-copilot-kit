# Index des patterns par stack technique (9 fichiers YAML)

Chaque fichier liste, pour une stack technique donnée : `tech_name`, puis une
liste `common_vulns` avec pour chaque vulnérabilité un `vuln_name`, une
`description`, des `indicators` (motifs à repérer dans le code ou les réponses
HTTP) et une `test_idea` (comment tester concrètement).

| Fichier | Stack | Vulnérabilités documentées |
|---|---|---|
| `wordpress.yaml` | WordPress | 8 |
| `laravel.yaml` | Laravel | 8 |
| `django.yaml` | Django | 8 |
| `rails.yaml` | Ruby on Rails | 7 |
| `spring_boot.yaml` | Spring Boot | 8 |
| `express.yaml` | Express.js | 8 |
| `graphql.yaml` | GraphQL | 7 |
| `jwt_patterns.yaml` | JWT (JSON Web Tokens) | 8 |
| `generic_api.yaml` | API générique (fallback si stack inconnue) | 8 |

**Usage** : dès que la stack de la cible est identifiée (headers HTTP, erreurs,
chemins caractéristiques comme `/wp-content/`, `/wp-json/`), lire le fichier
correspondant AVANT de commencer à tester à l'aveugle.
