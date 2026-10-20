# P5 - POST /oauth/register (DCR) vs chemin CIMD

## POST /oauth/register

- exige une inscription : le client_id est renvoye par le serveur (prefixe dcr_)
- **limite en debit** : apres une dizaine d inscriptions, reponse 429
  {"error":"temporarily_unavailable","error_description":"rate limit exceeded"}
- valide le redirect_uri : https obligatoire, pas d hote de la plateforme, pas d IP litteral
  -> "redirect_uris must be https (not a platform host or IP literal), or http on
     127.0.0.1, [::1] or localhost"
- refuse les scopes hors perimetre : "scope contains unsupported values"
- refuse les clients confidentiels : "only public clients (token_endpoint_auth_method
  \"none\") may register"
- refuse l usurpation du nom de la plateforme : client_name "BugSecure", "BugSecure Africa",
  "MCP BugSecure officiel", "Senintel BugSecure", "SSO BugSecure", "bugsecure-mcp"
  -> invalid_client_metadata

## Chemin CIMD (client_id = URL)

- **aucune inscription** : le client est construit a partir du document distant
- **aucun quota** : 25 fetch observes pour 25 authorize distincts, sans limitation
- le document distant est valide par le meme regles de contenu (memes refus de nom, de
  redirect_uri plateforme, d IP litteral, de scope hors perimetre)
- le serveur emet un GET vers l URL fournie, avec l agent utilisateur
  "BugSecure-OAuth/1 (+client-id-metadata-document)"

Conclusion : le chemin CIMD retire les deux protections structurelles du DCR
(inscription + quota) et ajoute une sortie reseau non authentifiee.
