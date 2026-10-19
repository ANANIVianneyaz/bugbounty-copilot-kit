# Injection (SQLi / XXE / Code / Argument)

*50 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **SQL Injection vulnerability found on IBM.com subdomain** · [HackerOne](https://hackerone.com/reports/3730301) · `2026-10-16` · *IBM* · ▲16
- **SQL Injection found on ibm.com subdomain** · [HackerOne](https://hackerone.com/reports/3662095) · `2026-10-12` · **Critical** · *IBM* · ▲27
- **`SHOW [CREATE\|GRANTS] ...` / `mariadb-dump` Unescaped SQL Generation** · [HackerOne](https://hackerone.com/reports/3848978) · `2026-10-07` · *MariaDB* · ▲5
  > Admin / migration script helpers may unknowingly create SQL output containing attacker injected queries if ran against an attacker controlled db. Importing this SQL then executes those commands as the user running the import.
- **Persistent SMTP header injection via identity `organization` / `name`** · [HackerOne](https://hackerone.com/reports/3913012) · `2026-09-18` · *Nextcloud* · ▲19
  > Every message the account sends silently carries attacker-authored headers until the identity is edited — covert Bcc recipients, forged From: / Sender: , and forged trust signals consumed by downstream MTAs and spam filters, all e
- **From Bug to Schema: Exploring Error-Based SQL Injection on an Authenticating Portal** · [Infosec Writeups](https://infosecwriteups.com/from-bug-to-schema-exploring-error-based-sql-injection-on-an-authenticating-portal-be905548ada2) · `2026-09-17`
  > Case Study Analysis of how I identified an Error-Based SQL Injection vulnerability in a production environment via (VDP). Disclaimer: This paper is only intended for informative and educational use. The vulnerability described her
- **Critical SQL Injection WDM API (████████)** · [HackerOne](https://hackerone.com/reports/3778282) · `2026-08-27` · **Critical** · *Essity* · ▲37
  > Hello Team and Hugo, I found and unauthenticated boolean-based and time-based blind SQL injection in the searchText query parameter of GET /api/WDMProduct , served by the backend that powers ████████ (EcoMed Safety Hub Angular SPA
- **DDP methods getThreadsList / getThreadMessages leaks private thread content to any authenticated low privilege user (unpatched sibling of #1446767)** · [HackerOne](https://hackerone.com/reports/3852135) · `2026-08-20` · **High** · *Rocket.Chat* · ▲16 · CVE-2026-65645
- **HTML Injection in Transaction Confirmation Dialog via Address Book Description Enables UI Spoofing Before Fund Transfer** · [HackerOne](https://hackerone.com/reports/3679471) · `2026-08-20` · **Medium** · *Monero* · ▲30 · CVE-2021-3401
  > The Monero GUI wallet renders address book descriptions as TextEdit.RichText (HTML) in the transaction confirmation dialog ( TxConfirmationDialog.qml:299 ) without HTML entity escaping. An attacker can craft a monero: URI or QR co
- **ZMQ RPC Log Injection and Untrusted Payload Persistence** · [HackerOne](https://hackerone.com/reports/3621606) · `2026-07-24` · **Medium** · *Monero* · ▲30
  > The ZMQ RPC request path logs untrusted request content before semantic validation. A remote party with access to the ZMQ endpoint can inject newline and control-character content into daemon logs, enabling log forging and persist
- **Unauthenticated Oracle Boolean-Based SQL Injection Through a Legacy Search Filter** · [LogicalBreach](https://academy.logicalbreach.com/writeups/unauthenticated-oracle-boolean-based-sql-injection-through-a-legacy-search-filter-4f97867e) · `2026-07-21`
  > An unauthenticated boolean-based SQL injection was identified in a legacy Oracle-backed web application. A non-correlated scalar subquery was used to turn an Oracle error into a reliable boolean oracle, enabling character-by-chara
- **Unauthenticated pl sql injection via a package name parameter oracle error based 42826779** · [LogicalBreach](https://academy.logicalbreach.com/writeups/unauthenticated-pl-sql-injection-via-a-package-name-parameter-oracle-error-based-42826779) · `2026-07-16`
- **Unauthenticated Error-Based SQL Injection via an Identity Header (SiteMinder SM_USER)** · [LogicalBreach](https://academy.logicalbreach.com/writeups/unauthenticated-error-based-sql-injection-via-an-identity-header-siteminder-sm-user-975333f3) · `2026-07-14`
  > A critical SQL injection vulnerability in an authentication endpoint allows attackers to execute arbitrary SQL commands, access sensitive data, and manipulate the database.
- **Error-Based SQL Injection in ████████.com Login/Password Reset (username parameter)** · [HackerOne](https://hackerone.com/reports/3809973) · `2026-07-03` · **Critical** · *Essity* · ▲10
  > An error-based SQL injection vulnerability was identified in the ████████.com authentication workflows. The username parameter is concatenated into a SQL query without adequate parameterization, enabling an attacker to inject MySQ
- **jitsi-meet: Prosody/Jigasi missing header whitelist in mod_filter_iq_rayo allows arbitrary SIP header injection and Caller ID spoofing** · [HackerOne](https://hackerone.com/reports/3789570) · `2026-07-02` · **Low** · $100 · *8x8* · ▲72
- **PHP code injection in delivery-limitation `logical` validation bypass - XML-RPC setChannelTargeting** · [HackerOne](https://hackerone.com/reports/3781492) · `2026-06-25` · **High** · *Revive Adserver* · ▲46 · CVE-2026-50741/CVE-2026-34916
- **PHP code injection in delivery-limitation `logical` validation bypass** · [HackerOne](https://hackerone.com/reports/3780854) · `2026-06-25` · **High** · *Revive Adserver* · ▲35 · CVE-2026-50741
- **Blind SQL injection via clientid parameter in zone‑include.php** · [HackerOne](https://hackerone.com/reports/3653196) · `2026-06-03` · **High** · *Revive Adserver* · ▲48 · CVE-2026-34914
- **PHP code injection via delivery limitation logical** · [HackerOne](https://hackerone.com/reports/3656781) · `2026-06-03` · **High** · *Revive Adserver* · ▲36 · CVE-2026-34916
- **PHP code injection via unexpected delivery limitation parameter** · [HackerOne](https://hackerone.com/reports/3744200) · `2026-06-03` · **High** · *Revive Adserver* · ▲11 · CVE-2026-44959
- **Pre authenticated sql injection on api redacted target com through api v1 auth login via post parameter module leads to sensitive data exposure and remote code execution 3905cf93** · [LogicalBreach](https://academy.logicalbreach.com/writeups/pre-authenticated-sql-injection-on-api-redacted-target-com-through-api-v1-auth-login-via-post-parameter-module-leads-to-sensitive-data-exposure-and-remote-code-execution-3905cf93) · `2026-05-20`
- **Sql injection on api target example through api v1 projects via post parameter tablename leads to remote code execution rce 3fc57486** · [LogicalBreach](https://academy.logicalbreach.com/writeups/sql-injection-on-api-target-example-through-api-v1-projects-via-post-parameter-tablename-leads-to-remote-code-execution-rce-3fc57486) · `2026-05-20`
- **SQL Injection in Column Type Parameter Allows Arbitrary SQL Execution** · [HackerOne](https://hackerone.com/reports/3462991) · `2026-05-15` · **High** · *Nextcloud* · ▲80 · CVE-2026-45545
- **Complete authentication bypass to admin permissions** · [HackerOne](https://hackerone.com/reports/3564655) · `2026-04-22` · **Critical** · *Rocket.Chat* · ▲99 · CVE-2026-29198
- **SQL Injection Detection Bypass in AWS WAF Managed Rules (AWSManagedRulesSQLiRuleSet)** · [HackerOne](https://hackerone.com/reports/3591725) · `2026-04-15` · *AWS VDP* · ▲39
  > AWS WAF fails to detect certain SQL injection payload variants. These payloads bypass the AWS WAF SQL injection detection rules and reach the backend application. When processed by the backend database, the injected SQL expression
- **SQL Injection vulnerability found on ibm.com endpoint** · [HackerOne](https://hackerone.com/reports/3578842) · `2026-03-12` · **Critical** · *IBM* · ▲137
- **Injection in path parameter of Ingress-nginx** · [HackerOne](https://hackerone.com/reports/2701701) · `2026-03-07` · **High** · *Kubernetes* · ▲89 · CVE-2021-25748
  > An attacker in a multi-tenant cluster with permission to create/modify ingresses can inject content into the connection-proxy-header annotation and read arbitrary files from the ingress controller (including the service account).
- **SQLi At `███████` via `theme_name`** · [HackerOne](https://hackerone.com/reports/3293803) · `2026-02-24` · **Critical** · *Mars* · ▲62
- **SQLi at █████ parameter** · [HackerOne](https://hackerone.com/reports/3277276) · `2026-02-24` · **Critical** · *Mars* · ▲42
- **SQL injection in structure plugin** · [HackerOne](https://hackerone.com/reports/3249794) · `2026-01-26` · **Medium** · *ExpressionEngine* · ▲124 · CVE-2025-59473
- **SQL Injection - JSON 'name' parameter** · [HackerOne](https://hackerone.com/reports/3257171) · `2026-01-12` · **High** · *U.S. Dept Of Defense* · ▲6
  > The ability to manipulate SQL queries can lead to: - Unauthorized access to sensitive data. - Potential data leakage. - Data manipulation or corruption. - Full database compromise if administrative permissions are accessible. Syst
- **XML E██████ternal Entity (XXE) Injection in ███** · [HackerOne](https://hackerone.com/reports/2564265) · `2026-01-12` · **High** · *U.S. Dept Of Defense* · ▲8 · CVE-2022-2414
  > E███████ploitation of this vulnerability can lead to████████ 1-Confidentiality Breach██████████ Unauthorized access to sensitive information stored on the server. 2-Integrity Violation██████████ Potential manipulation or corruptio
- **SQL Injection in URI Path Leading to Full Database Disclosure on ████████** · [HackerOne](https://hackerone.com/reports/3234050) · `2026-01-12` · **High** · *U.S. Dept Of Defense* · ▲10
  > - Attacker can extract all database metadata and data. - Sensitive information exposure: user data, credentials, configs. - Possible full compromise of backend data integrity. System Host(s) █████████ Affected Product(s) and Versi
- **SQL Injection - data[account][id] parameter** · [HackerOne](https://hackerone.com/reports/3127152) · `2026-01-12` · **High** · *U.S. Dept Of Defense* · ▲6
  > The ability to manipulate SQL queries can lead to: Unauthorized access to sensitive data. Potential data leakage. Data manipulation or corruption. Full database compromise if administrative permissions are accessible. System Host(
- **SQL Injection via URL** · [HackerOne](https://hackerone.com/reports/3127562) · `2026-01-12` · **High** · *U.S. Dept Of Defense* · ▲7
  > The ability to manipulate SQL queries can lead to: Unauthorized access to sensitive data. Potential data leakage. Data manipulation or corruption. Full database compromise if administrative permissions are accessible. System Host(
- **SQL injection identified on IBM endpoint.** · [HackerOne](https://hackerone.com/reports/2830573) · `2026-01-07` · **Critical** · *IBM* · ▲8
- **Potential SQL Injection when annotating FilteredRelation on PostgreSQL** · [HackerOne](https://hackerone.com/reports/3417967) · `2025-12-02` · **High** · *Django* · ▲52 · CVE-2025-57833/CVE-2025-59681
  > The impact is a SQL injection allowing to exfiltrate data, read system files as the PoC demonstrates, or allow remote command execution. Remediation The remediation consists in adding the $ symbol to the FORBIDDEN ALIAS PATTERN re
- **SQL Injection in Django ORM via Unvalidated `_connector` in Q Objects** · [HackerOne](https://hackerone.com/reports/3335709) · `2025-11-06` · **Critical** · *Django* · ▲77
  > A critical SQL injection vulnerability exists in the Django ORM's handling of Q objects. The internal WhereNode.as sql method uses unsafe string formatting to inject the query connector (e.g., 'AND') into the raw SQL query. An att
- **Error-Based & Time-Based SQL Injection in 'keyword' Parameter of admin-search.php Allowing Full Database Access in Revive Adserver v6.0.0** · [HackerOne](https://hackerone.com/reports/3395221) · `2025-10-24` · **High** · *Revive Adserver* · ▲93 · CVE-2025-52664
  > A critical SQL Injection vulnerability has been identified in Revive Adserver's administrative search functionality, specifically in the admin-search.php file. The vulnerability exists in the handling of the keyword GET parameter,
- **SQL Injection when using FilteredRelation** · [HackerOne](https://hackerone.com/reports/3292573) · `2025-09-15` · **Critical** · *Django* · ▲95
  > The impact is direct SQL Injection for any user with access to select related( as above. I hope you have a great day!!! Eyal :)
- **SQL injection in JSONField KeyTransform** · [HackerOne](https://hackerone.com/reports/2588426) · `2025-09-12` · **High** · *Django* · ▲68 · CVE-2024-42005
  > if user input get into .values( the user will able to create sql injection attack. I hope you have best day :) Eyal
- **Potential XSS vector in curl via unsanitized URL parameter handling** · [HackerOne](https://hackerone.com/reports/3118915) · `2025-06-30` · **High** · *curl* · ▲8
  > Impact If successfully exploited, this flaw could lead to XSS through insecure processing of user-controlled URLs. An attacker could: Steal session cookies or tokens Redirect victims to malicious sites Execute code in the browser 
- **Woocommerce SQL Injection in WC_Report_Coupon_Usage** · [HackerOne](https://hackerone.com/reports/3198980) · `2025-06-24` · **Medium** · *Automattic* · ▲96
  > A SQL injection vulnerability is found with required privililege is view reports. Endpoint: /wp-admin/admin.php?page=wc-reports&tab=orders&report=coupon usage&coupon codes=')+union+select+1,sleep(10)--+- Vuln param: coupon codes P
- **Apache Airflow Sql injection by authenticated user** · [HackerOne](https://hackerone.com/reports/3078856) · `2025-05-27` · **Low** · $505 · *Internet Bug Bounty* · ▲35
  > The DAGS that use the SQLColumnCheckOperator in the system will remote code execution.
- **Episode 118: Hacking Happy Hour: 0days on Tap and SQLi Shots** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-04-10`
  > Episode 118: In this episode of Critical Thinking - Bug Bounty Podcast we cover a host of news, including clientside tidbits, “Credentialless” iframes, prototype pollution, and what constitutes a polyglot in llms.txt. Follow us on
- **HTML Injection in Business Name Parameter in Payapps** · [HackerOne](https://hackerone.com/reports/2978923) · `2025-04-07` · **Medium** · *Autodesk* · ▲75
- **HTTP Response Header Injection in shopify/pitchfork + Rack 3** · [HackerOne](https://hackerone.com/reports/2279572) · `2025-03-27` · **Low** · $800 · *Shopify* · ▲136 · CVE-2025-30221
  > If attacker can manipulate the redirect destination or cookie value, HTTP response header injection and XSS is possible. (Past cases https://hackerone.com/reports/904059 activity-8945588 ) In the case of Rack 2, the value of \n is
- **SQLi \| in URL paths** · [HackerOne](https://hackerone.com/reports/2958619) · `2025-03-06` · **Critical** · *MTN Group* · ▲148
  > A SQL Injection vulnerability was discovered in the customerId parameter of the URL path: ███████ We can observe this by adding a little quote in the customerId: █████████ which will show the following error, indicating that its v
- **Boolen Based Blind Sql Injection Via User Agent in ███.mil** · [HackerOne](https://hackerone.com/reports/2599826) · `2025-01-24` · **Medium** · *U.S. Dept Of Defense* · ▲67
  > - Information Disclosure: Attackers may infer database schema details and potentially sensitive information. Database and Web Server Details - Database Management System: MySQL 8 (MariaDB fork) - Web Server Operating System: Windo
- **Time-based blind SQL injection** · [HackerOne](https://hackerone.com/reports/2759243) · `2025-01-24` · **Medium** · *U.S. Dept Of Defense* · ▲53
  > This vulnerability allows an attacker to: - Confirm the existence of SQL injection by observing server response delays - Potentially extract sensitive information from the database, such as usernames, passwords, or other critical 
- **SQL injection in URL path leads to Database Access** · [HackerOne](https://hackerone.com/reports/2633959) · `2025-01-08` · **Critical** · *MTN Group* · ▲115
  > The application https://corporate.admyntec.co.za/ application has an SQL injection in the URL paths since it takes the ID numbers in there and insert them directly into the backend SQL query without sanitizing them. In the registr
