# Index des 83 skills de hunting (par classe de vulnérabilité)

Chaque fichier est une méthodologie autonome (frontmatter `name`/`description`,
souvent construite à partir de N rapports publics réels — `report_count` dans
le frontmatter). Source : dépôt public Claude-BugHunter (MIT), voir
`NOTICE_LICENSE.md`.

## Par où commencer sur une nouvelle cible

1. `bug-bounty.md` ou `bb-methodology.md` — orchestrateur/méthodologie générale
2. `recon-scope-triage.md` — comprendre et prioriser le périmètre
3. Puis piocher dans `hunt-*.md` selon ce que la reconnaissance révèle

## Orchestration / méthodologie générale

- `bug-bounty.md` — workflow complet, orchestrateur central
- `bb-methodology.md` — méthodologie non-linéaire en 5 phases + pensée critique
- `bb-local-toolkit.md` — même workflow, orienté outils/wordlists en local
- `recon-scope-triage.md` — triage du périmètre
- `redteam-mindset.md` — posture red team

## Reporting & validation

- `report-writing.md` — rédaction (CVSS 3.1, gates de validation, ton humain)
- `redteam-report-template.md` — gabarit de rapport red team
- `bugcrowd-reporting.md` — tactiques spécifiques Bugcrowd
- `triage-validation.md` — validation avant soumission
- `evidence-hygiene.md` — hygiène de la preuve

## OSINT & reconnaissance

- `offensive-osint.md`, `osint-methodology.md`, `web2-recon.md`, `hunt-subdomain.md`

## Hunting par classe (`hunt-*.md`)

`hunt-api-misconfig` · `hunt-aspnet` · `hunt-ato` · `hunt-auth-bypass` ·
`hunt-brute-force` · `hunt-business-logic` · `hunt-cache-poison` ·
`hunt-captcha-bypass` · `hunt-cicd` · `hunt-clickjacking` ·
`hunt-cloud-misconfig` · `hunt-cors` · `hunt-csrf` · `hunt-deserialization` ·
`hunt-dispatch` (routage vers les autres hunt-*) · `hunt-dom` ·
`hunt-exceptional-conditions` · `hunt-file-upload` · `hunt-fintech-graphql` ·
`hunt-forgot-password` · `hunt-graphql` · `hunt-grpc` · `hunt-host-header` ·
`hunt-html-injection` · `hunt-http-smuggling` · `hunt-idor` (26 rapports) ·
`hunt-jwt-crypto` · `hunt-k8s` · `hunt-laravel` · `hunt-ldap` · `hunt-lfi` ·
`hunt-llm-ai` · `hunt-mfa-bypass` · `hunt-misc` · `hunt-nextjs` ·
`hunt-nodejs` · `hunt-nosqli` · `hunt-ntlm-info` · `hunt-oauth` ·
`hunt-open-redirect` · `hunt-race-condition` (12 rapports, dont James Kettle
DEF CON 2023 "Smashing the State Machine") · `hunt-rag-vector` · `hunt-rce` ·
`hunt-saml` · `hunt-session` · `hunt-shadow-api` · `hunt-sharepoint` ·
`hunt-source-leak` · `hunt-spa-api` · `hunt-springboot` · `hunt-sqli` ·
`hunt-ssrf` · `hunt-ssti` · `hunt-tls-network` · `hunt-websocket` ·
`hunt-xss` · `hunt-xxe`

## Mobile

- `apk-redteam-pipeline.md` — pipeline Android complet (acquisition APK,
  jadx, grep secrets/JWT, Frida)
- `ios-redteam-pipeline.md` — équivalent iOS

## Cloud / infra / entreprise

- `cloud-iam-deep.md`, `enterprise-vpn-attack.md`, `m365-entra-attack.md`,
  `okta-attack.md`, `vmware-vcenter-attack.md`

## Niche

- `mid-engagement-ir-detection.md` — savoir détecter qu'on a déclenché une
  réponse à incident (et s'arrêter proprement)
- `supply-chain-attack-recon.md`, `meme-coin-audit.md`, `web3-audit.md`,
  `security-arsenal.md`
