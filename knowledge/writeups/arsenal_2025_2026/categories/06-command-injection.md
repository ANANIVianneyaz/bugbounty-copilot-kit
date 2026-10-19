# Command Injection

*8 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **Low-privilege RCE in MariaDB: SYS_REFCURSOR cursor-array use-after-free chained with an ST_Area heap over-read** · [HackerOne](https://hackerone.com/reports/3856148) · `2026-10-07` · **Critical** · *MariaDB* · ▲13
  > A low-privilege authenticated user can execute arbitrary OS commands as the mariadbd process user through a single SQL session over the normal TCP port. The account needs only per-database SELECT,INSERT,UPDATE,DELETE,CREATE,DROP,C
- **Incomplete Input Sanitization in CodeInterpreter install_packages Allows Command Injection via pip Flags** · [HackerOne](https://hackerone.com/reports/3633123) · `2026-09-16` · **High** · *AWS VDP* · ▲23 · CVE-2026-12530
  > Summary: An attacker who can influence the arguments to install packages() , for example through prompt injection against an LLM agent that uses Code Interpreter, can: 1. Read arbitrary files from the sandbox via pip's -r flag. Co
- **Command Injection via Unsanitized Bundling Options in `aws-cdk-lib/aws-lambda-nodejs`** · [HackerOne](https://hackerone.com/reports/3558713) · `2026-06-11` · **High** · *AWS VDP* · ▲48
  > The NodejsFunction construct in aws-cdk-lib/aws-lambda-nodejs constructs a shell command string from several user-controlled bundling properties ( externalModules , define , loader , inject , esbuildArgs ) without sanitizing or es
- **Argument Injection in /manage/ssh/ via host parameter leads to sensitive file disclosure on Weblate** · [HackerOne](https://hackerone.com/reports/3518571) · `2026-04-26` · *Weblate* · ▲34 · CVE-2026-24126
  > Describe the security issue you would like to report Product: Weblate. Verified on self-hosted instances. Affected Versions: Confirmed in version 5.0.2 and the current stable release 5.15.2. Probably all versions are vulnerable. A
- **Command Injection on Amazon Q Developer CLI via malicious .amazonq/mcp.json leads to arbitrary code execution** · [HackerOne](https://hackerone.com/reports/3427370) · `2026-01-16` · *AWS VDP* · ▲19
  > Running Q chat from Amazon Q Developer CLI from an attacker-controlled repository/directory that contains a crafted .amazonq/mcp.json enables arbitrary command injection/execution. Amazon Q Developer CLI automatically loads and ex
- **Remote Code Execution in Amazon MWAA due to outdated Apache Airflow version** · [HackerOne](https://hackerone.com/reports/3217840) · `2025-08-14` · *AWS VDP* · ▲24 · CVE-2024-39877
  > Summary: An attacker can execute arbitrary commands remotely on the affected environment. While I limited my actions to a non-destructive proof-of-concept command, a malicious actor could leverage this vulnerability to access sens
- **Remote Code Execution via unsafe usage of `reply.view({ raw })` in @fastify/view (EJS template engine)** · [HackerOne](https://hackerone.com/reports/3122019) · `2025-05-28` · *Fastify* · ▲66
  > Impact: This vulnerability allows Remote Code Execution (RCE) when using the @fastify/view plugin with the EJS engine and providing a user-controlled raw template input. Any attacker who can influence or inject unescaped EJS paylo
- **Middleware Authentication Bypass on IBM Portal** · [HackerOne](https://hackerone.com/reports/3088290) · `2025-05-02` · **Critical** · *IBM* · ▲80 · CVE-2025-29927
