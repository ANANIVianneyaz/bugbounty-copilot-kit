# Index de METHODOLOGIE_COMPLETE.md (17 394 lignes, ~115 sections)

Ce fichier est volontairement resté **monolithique** (pas coupé en 115 petits
fichiers) : la table ci-dessous donne la plage de lignes exacte de chaque
section, pour extraire UNE SEULE section sans charger tout le fichier en
mémoire/contexte.

**Comment lire une seule section** (remplace `START`/`END` par les valeurs de
la table) :

```bash
sed -n 'START,ENDp' knowledge/methodology/METHODOLOGIE_COMPLETE.md
```

Ou avec ton propre outil de lecture de fichier (offset/limit), si tu en as un.

| Section | Lignes | Titre |
|---|---|---|
| PARTIE 0 | 11-531 | Routeur de cibles + profils + tags + schéma JSON + won't fix |
| PARTIE I | 532-611 | Philosophie : ce que les meilleurs ont compris |
| PARTIE II | 612-671 | Sélection de cible : la décision qui fait 80% du travail |
| PARTIE III | 672-706 | Spécialisation : choisir sa classe et sa stack |
| PARTIE IV | 707-812 | Reconnaissance : l'avantage compétitif réel |
| PARTIE V | 813-877 | Méthodologies signature des top hunters |
| PARTIE VI | 878-1093 | Modes de pensée (l'IA doit switcher entre eux) |
| PARTIE VII | 1094-1316 | Vulnérabilités à haute valeur bounty |
| PARTIE VIII | 1317-1427 | Chaining : construire l'impact maximum |
| PARTIE IX | 1428-1539 | Techniques de bypass de défenses |
| PARTIE X | 1540-1602 | Tests API modernes |
| PARTIE XI | 1603-1638 | Out-of-band testing |
| PARTIE XII | 1639-1709 | Reporting : où se gagne la moitié de l'argent |
| PARTIE XIII | 1710-1771 | Pièges techniques et anti-patterns |
| PARTIE XIV | 1772-1824 | IA et automatisation en 2025-2026 |
| PARTIE XV | 1825-1854 | Mindset opérationnel |
| PARTIE XVI | 1855-1962 | Grille d'auto-évaluation opérationnelle |
| PARTIE XVII | 1963-2061 | HTTP Request Smuggling (CL/TE desync) |
| PARTIE XVIII | 2062-2130 | Web Cache Poisoning & Web Cache Deception |
| PARTIE XIX | 2131-2270 | DOM Clobbering & attaques client-side avancées |
| PARTIE XX | 2271-2324 | Host Header attacks |
| PARTIE XXI | 2325-2372 | CORS misconfigurations (avancées) |
| PARTIE XXII | 2373-2423 | WebSocket vulnerabilities |
| PARTIE XXIII | 2424-2470 | Subdomain Takeover (avancé) |
| PARTIE XXIV | 2471-2525 | Dependency confusion & supply chain |
| PARTIE XXV | 2526-2619 | Source code analysis |
| PARTIE XXVI | 2620-2688 | Differential analysis systématique |
| PARTIE XXVII | 2689-2745 | Advanced parameter analysis |
| PARTIE XXVIII | 2746-2844 | Zero-day research framework |
| PARTIE XXIX | 2845-2886 | Mobile API hunting |
| PARTIE XXX | 2887-2961 | Automatisation avancée |
| PARTIE XXXI | 2962-3056 | Trouver ce que l'automatisation rate (avantage humain) |
| PARTIE XXXII | 3057-3168 | Attaques cryptographiques applicables au web |
| PARTIE XXXIII | 3169-3239 | Side-channel timing attacks (avancé) |
| PARTIE XXXIV | 3240-3308 | DNS rebinding (SSRF ultimate bypass) |
| PARTIE XXXV | 3309-3369 | Dangling markup & CSS injection pour exfiltration |
| PARTIE XXXVI | 3370-3428 | Bypass de CSP |
| PARTIE XXXVII | 3429-3492 | Polyglots et fichiers hybrides |
| PARTIE XXXVIII | 3493-3531 | Protocol-level research |
| PARTIE XXXIX | 3532-3550 | Advanced recon : OSINT niveau recherche |
| PARTIE XL | 3551-3759 | Ce que je ferais personnellement pour trouver des zéro-days |
| PARTIE XLI | 3760-3860 | Ce qu'un Project Zero ferait sur une app web |
| PARTIE XLII | 3861-3938 | Intégration dans SecOps-Nexus : comment penser |
| PARTIE XLIII | 3939-4059 | Instrumentation dynamique : Frida |
| PARTIE XLIV | 4060-4154 | Attaques sur les générateurs PDF et documents |
| PARTIE XLV | 4155-4212 | OAuth 2.0 et OIDC : attaques de niveau recherche |
| PARTIE XLVI | 4213-4266 | Timing attacks par le navigateur (Spectre-class) |
| PARTIE XLVII | 4267-4334 | Injection dans les couches inférieures |
| PARTIE XLVIII | 4335-4386 | Browser security research : edge cases |
| PARTIE XLIX | 4387-4406 | Supply chain avancé : attaque par confiance |
| PARTIE L | 4407-4538 | La carte mentale finale |
| PARTIE LI | 4539-4816 | Modélisation formelle offensive (TLA+, Alloy) |
| PARTIE LII | 4817-5109 | Parser differential fuzzing (niveau Project Zero) |
| PARTIE LIII | 5110-5320 | Temporal vulnerability research |
| PARTIE LIV | 5321-5594 | Covert channel analysis |
| PARTIE LV | 5595-5792 | Compound vulnerability research (failles de composition) |
| PARTIE LVI | 5793-5959 | State space explosion |
| PARTIE LVII | 5960-6149 | Cryptographic oracle research |
| PARTIE LVIII | 6150-6295 | Security assumption reversal |
| PARTIE LIX | 6296-6453 | Distributed consensus exploitation |
| PARTIE LX | 6454-6593 | Instrumentation dynamique avancée (Frida, eBPF, DBI) |
| PARTIE LXI | 6594-6742 | RFCs critiques : lecture offensive ligne par ligne |
| PARTIE LXII | 6743-7056 | Recherche de vulnérabilités dans l'IA / LLM |
| PARTIE LXIII | 7057-7201 | Recherche dans les browser extensions |
| PARTIE LXIV | 7202-7302 | Research sur les SDK mobiles tiers |
| PARTIE LXV | 7303-7476 | Kubernetes / cloud native attack surface |
| PARTIE LXVI | 7477-7680 | Race conditions de niveau recherche |
| PARTIE LXVII | 7681-7815 | Supply chain attacks de niveau recherche |
| PARTIE LXVIII | 7816-7951 | Research sur les protocoles bas-niveau |
| PARTIE LXIX | 7952-8160 | OSINT offensif de niveau agence |
| PARTIE LXX | 8161-8322 | Le framework ultime : "Zero-Day Factory" |
| PARTIE LXXI | 8323-8461 | Le playbook opérationnel de l'agent autonome |
| PARTIE LXXII | 8462-8541 | Anti-duplicate strategy (ne jamais être le 2e) |
| PARTIE LXXIII | 8542-8650 | Psychologie du hunter d'élite |
| PARTIE LXXIV | 8651-8854 | Les scénarios de compromise totale (références) |
| PARTIE LXXV | 8855-9373 | Annexes opérationnelles étendues |
| PARTIE LXXVI | 9374-9456 | Intégration finale : la checklist opérationnelle complète |
| PARTIE LXXVII | 9457-9591 | Apprentissage continu |
| PARTIE LXXVIII | 9592-9676 | Éthique offensive avancée |
| PARTIE LXXIX | 9677-9772 | Roadmap de progression (0 → maîtrise) |
| PARTIE LXXX | 9773-9882 | Mot de la fin : la philosophie du grand chercheur |
| PARTIE LXXXI | 9883-10014 | WebAuthn / Passkeys |
| PARTIE LXXXII | 10015-10105 | Telemetry / session replay leaks |
| PARTIE LXXXIII | 10106-10213 | Risques de sérialisation ML |
| PARTIE LXXXIV | 10214-10374 | Indirect RAG prompt injection |
| PARTIE LXXXV | 10375-10741 | GraphQL avancé |
| PARTIE LXXXVI | 10742-10861 | HTTP Request Smuggling 2024-2025 |
| PARTIE LXXXVII | 10862-11025 | Server-side Prototype Pollution (Node.js) |
| PARTIE LXXXVIII | 11026-11152 | LLM Output → XSS (vecteur émergent) |
| PARTIE LXXXIX | 11153-12789 | OAuth 2.0 / OIDC / DPoP / PKCE — vecteurs 2024-2025 |
| PARTIE XC | 12790-13019 | Cloud Red Team AWS |
| PARTIE XCI | 13020-13184 | Cloud Red Team Azure / Entra ID |
| PARTIE XCII | 13185-13320 | Cloud Red Team GCP |
| PARTIE XCIII | 13321-13507 | Kubernetes Red Team |
| PARTIE XCIV | 13508-13677 | CI/CD Red Team |
| PARTIE XCV | 13678-13864 | Active Directory / Entra ID on-prem-hybrid |
| PARTIE XCVI | 13865-14115 | Cryptanalyse appliquée |
| PARTIE XCVII | 14116-14315 | GraphQL Red Team avancé |
| PARTIE XCVIII | 14316-14461 | SAML / XML Security |
| PARTIE XCIX | 14462-14587 | WebSocket / HTTP/3 / QUIC |
| PARTIE C | 14588-14784 | SSRF avancé |
| PARTIE CI | 14785-14975 | Deserialization multi-langage |
| PARTIE CII | 14976-15128 | Race conditions avancées |
| PARTIE CIII | 15129-15278 | Supply Chain Red Team |
| PARTIE CIV | 15279-15480 | Mobile Red Team avancé |
| PARTIE CV | 15481-15623 | Hardware / Firmware |
| PARTIE CVI | 15624-15810 | OSINT / Recon avancée |
| PARTIE CVII | 15811-15975 | WAF / CDN bypass |
| PARTIE CVIII | 15976-16135 | Browser security avancée |
| PARTIE CIX | 16136-16314 | Post-exploit / OPSEC (conceptuel) |
| PARTIE CXVI | 16315-16474 | eBPF Red Team |
| PARTIE APPENDIX | 16475-16484 | Méthodologies & chaînes (préambule) |
| PARTIE CX | 16485-16626 | Threat Modeling formel |
| PARTIE CXI | 16627-16808 | Reporting standards |
| PARTIE CXII | 16809-16929 | OPSEC Red Team |
| PARTIE CXIII | 16930-17024 | Bug Bounty business |
| PARTIE CXIV | 17025-17122 | Kill-chain par profil |
| PARTIE CXV | 17123-17394 | Chains canoniques (30 chaînes d'exploitation) |

> Note : PARTIE CXVI (eBPF) est physiquement placée avant PARTIE APPENDIX/CX-CXV
> dans le fichier — ordre d'ajout historique, pas une erreur.
