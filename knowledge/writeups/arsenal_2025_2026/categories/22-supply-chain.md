# Supply Chain — Dependency Confusion, CI/CD

*10 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **My first Wall Of Fame** · [r/bugbounty](https://reddit.com/r/bugbounty/comments/1x6csb6/my_first_wall_of_fame) · `2026-10-15`
  > After months of grinding and bug bounty politics, i finally got my recognition as a pre degree student. Originally my vuln got downplay by a program manager despite being in scope and agreed by platform triager. Nonetheless, persi
- **Full Admin Takeover of R3 Limited's JFrog Artifactory - 292 Users, Corda Enterprise & CBDC Supply Chain Compromised** · [HackerOne](https://hackerone.com/reports/3994056) · `2026-10-08` · **Critical** · *R3* · ▲81 · CVE-2026-82329
  > Immediate Impact (Proven) 1. Full admin takeover — Unauthenticated access to the admin API of R3 Limited's enterprise Artifactory instance 2. 292 accounts exposed — R3 employees and blockchain partner organizations with corporate 
- **Add labels to arbitrary issues/prs via Memex Bulk Update to compromise github actions label gating** · [HackerOne](https://hackerone.com/reports/3527788) · `2026-08-25` · **Medium** · *GitHub* · ▲44 · CVE-2026-3306
- **Supply Chain Security Analysis of a 9.5M-Install VS Code Extension** · [ProjectDiscovery](https://projectdiscovery.io/blog/a-9-5m-install-vs-code-extension-one-markdown-file-and-a-supply-chain-foothold) · `2026-08-16`
  > Your code editor extensions auto-update and run with your privileges on the machine that holds your source code, your SSH keys, and your publishing credentials, but they rarely show up in a software bill of materials. Using Neo we
- **OS Command Injection in `aws-cdk-lib` NodejsFunction via Unsanitized `OsCommand` Helper (Supply Chain RCE)** · [HackerOne](https://hackerone.com/reports/3637898) · `2026-07-06` · **High** · *AWS VDP* · ▲111
  > The NodejsFunction construct in aws-cdk-lib/aws-lambda-nodejs uses an internal helper class named OsCommand to construct shell commands during Docker-based bundling. The OsCommand.write() and OsCommand.writeJson() methods wrap use
- **Don’t eat the ChocoPoCs! Vulnerability researchers were targeted by trojanised exploits** · [YesWeHack](https://yeswehack.com/news/chocopocs-vulnerability-researchers-trojanised-exploits) · `2026-07-01`
  > A suspicious contribution request led YesWeHack and Sekoia researchers to uncover sophisticated malware targeting the vulnerability research supply chain.
- **RCE + PAT Exfiltration via pull_request_target in privacy-configuration/auto-respond-pr.yml — Direct Supply Chain to All DDG Browsers** · [HackerOne](https://hackerone.com/reports/3619288) · `2026-06-11` · **Critical** · *DuckDuckGo* · ▲66
  > The duckduckgo/privacy-configuration repository's .github/workflows/auto-respond-pr.yml GitHub Actions workflow uses pull request target trigger, checks out the fork's repository as both "base" and "PR" branches (attacker controls
- **RCE + Supply Chain Attack via pull_request_target in content-scope-scripts/semver-label.yml — Affects All DuckDuckGo Browsers** · [HackerOne](https://hackerone.com/reports/3619287) · `2026-06-11` · **Critical** · *DuckDuckGo* · ▲41
  > The duckduckgo/content-scope-scripts repository's .github/workflows/semver-label.yml GitHub Actions workflow uses pull request target trigger without any access controls, checks out and executes untrusted fork PR code via npm inst
- **Add labels to arbitrary issues/prs & compromise github actions label checks** · [HackerOne](https://hackerone.com/reports/3527771) · `2026-03-19` · **Medium** · *GitHub* · ▲71 · CVE-2026-3306
- **Information Disclosure via Logback Configuration Injection in GoCD Agent** · [HackerOne](https://hackerone.com/reports/3509632) · `2026-02-04` · *GoCD* · ▲37
  > An attacker or a malicious insider who can modify the agent configuration can steal sensitive environment variables. In many CI/CD environments, these variables often contain: Cloud provider credentials (AWS ACCESS KEY ID, etc.) D
