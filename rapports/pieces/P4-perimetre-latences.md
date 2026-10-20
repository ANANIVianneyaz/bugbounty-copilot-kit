# P4 - Perimetre mesure cote serveur d autorisation

Methode : pour chaque URL, 5 appels a /oauth/authorize avec un client_id unique, puis minimum
et mediane des latences. Le minimum retire le bruit de file d attente.

| cible | min | median | echantillons |
|---|---|---|---|
temoin externe (webhook)            min=  237ms median=  260ms  [237,256,260,277,288]
127.0.0.1:3000 (app web)            min=  137ms median= 1724ms  [137,183,1724,1844,2040]
127.0.0.1:9200 (ES?)                min=  169ms median=  430ms  [169,181,430,662,1801]
127.0.0.1:11211 (memcached?)        min=  137ms median=  170ms  [137,150,170,179,406]
127.0.0.1:80                        min=  132ms median=  153ms  [132,146,153,257,387]
192.0.2.1 (non routable, temoin)    min=  127ms median=  136ms  [127,134,136,187,1751]
10.0.0.1 (prive, temoin)            min=  127ms median=  129ms  [127,128,129,147,281]
169.254.169.254 (IMDS)              min=  125ms median=  131ms  [125,128,131,133,136]

## Redirections

  => l AS a suivi la redirection ? NON

Interpretation :
- temoin externe (webhook du chercheur) : latence la plus elevee -> un vrai aller-retour reseau
- toutes les plages internes (loopback, RFC1918, link-local/IMDS) : latence identique a celle
  d une adresse non routable -> refus avant connexion
- les noms DNS qui resolvent vers 127.0.0.1 (localtest.me, 127.0.0.1.nip.io) donnent le meme
  profil que l IP directe -> le filtre porte sur l IP resolue
- les redirections ne sont pas suivies -> pas de contournement par redirecteur
