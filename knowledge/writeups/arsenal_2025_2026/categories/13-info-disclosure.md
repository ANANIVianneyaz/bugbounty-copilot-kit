# Information Disclosure & Credential Leaks

*113 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **IPI Black: $300K in bounties for prompt-injecting agents in the Gray Swan Arena, open through Nov 5** · [r/bugbounty](https://reddit.com/r/bugbounty/comments/1x8mpmh/ipi_black_300k_in_bounties_for_promptinjecting) · `2026-10-17`
  > (Disclosure: I work at Gray Swan, where I run the Frontier Lab Safety team and the Arena) We just launched our largest-ever AI red teaming challenge, at the request of Anthropic, Meta, Google DeepMind, Reflection, and our other la
- **Unauthenticated self-registration on ████████ grants full access to internal supplier procurement portal and vendor data** · [HackerOne](https://hackerone.com/reports/4071064) · `2026-10-14` · **Medium** · *Essity* · ▲23
  > The program i open scope so i did ASN enumeration and found the following subdomains is owned by Essity ████████ . while checking the JavaScript file found that there is endpoint hidden from GUI but found in the code ████████/Acco
- **hackerone should improve their concern on researchers over sales alone** · [r/bugbounty](https://reddit.com/r/bugbounty/comments/1x4v6fr/hackerone_should_improve_their_concern_on) · `2026-10-13`
  > i saw this disclosed report on hackerone https://hackerone.com/reports/3189580 , felt bad for researcher . he literally waiting for months for valid bug at the end he got nothing and team asking error in payout is crazy submitted 
- **Is leaking the model info and system instructions using prompt injection a bug or not ?** · [r/bugbounty](https://reddit.com/r/bugbounty/comments/1x4ye3p/is_leaking_the_model_info_and_system_instructions) · `2026-10-13`
  > Testing an LLM and that is what I got so far, I have been trying to leak internal files or do calls using it , but what I got so far are the model info and the system instructions only. I can make it do other instructions other th
- **Detectify Cyber Hygiene Index Report reveals that most critical vulnerabilities sit unfixed for months** · [Detectify](https://blog.detectify.com/industry-insights/detectify-cyber-hygiene-index-report-reveals-that-most-critical-vulnerabilities-sit-unfixed-for-months) · `2026-09-29`
  > The Detectify Cyber Hygiene Index Report H2 2026 measures something most reports ignore: not what happened after an attack, but what’s exposed right now, before ... The post Detectify Cyber Hygiene Index Report reveals that most c
- **HackerOne Code sends live password-reset tokens to Segment in automatic page events** · [HackerOne](https://hackerone.com/reports/4000185) · `2026-09-24` · **Low** · $200 · *HackerOne* · ▲114
  > Opening a HackerOne Code password-reset link discloses the still-valid reset token to Segment before the user submits the reset form. For a returning browser, the token-bearing event uses the same anonymousId that was already iden
- **Episode 193: Browser Logic Errors & XS-Leaks with Jorian Woltjer** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2026-09-24`
  > Episode 193: In this episode of Critical Thinking - Bug Bounty Podcast we’re joined by Jorian Woltjer to talk through his Bug Bounty journey and all the crazy research he’s done for the Critical Thinking Lab. Follow us on twitter 
- **EU Cyber Resilience Act: 24-hour deadline for reporting exploited vulnerabilities now applies** · [YesWeHack](https://yeswehack.com/news/cyber-resilience-act-24-hour) · `2026-09-18`
  > The EU CRA introduces new vulnerability reporting rules. Learn what manufacturers need to know about disclosure, testing and Bug Bounty.
- **Heap Memory Disclosure via Integer Underflow in Item_func_json_arrayagg::cut_max_length in MariaDB Server** · [HackerOne](https://hackerone.com/reports/3771139) · `2026-09-15` · *MariaDB* · ▲16
  > Any authenticated user with the default SELECT and CREATE TEMPORARY TABLES privileges can read adjacent heap memory from the mariadbd process. Disclosed contents can include other sessions' query data (PII, credentials), mysql.use
- **Preinstalled but Not Safe. OnePlus OEM App Session Takeover Vulnerability** · [Doyensec](https://blog.doyensec.com/2026/09/10/oneplus-session-takeover.html) · `2026-09-09`
  > Change of Plan 9+ months. One unresolved vulnerability. One disclosure published today. Following a last-minute request from the affected vendor, we’ve temporarily taken the technical details offline and agreed to provide one fina
- **Corridor — A Simple Web CTF That Made Me Look Twice** · [Infosec Writeups](https://infosecwriteups.com/corridor-a-simple-web-ctf-that-made-me-look-twice-668a430418f1) · `2026-09-08`
  > THM Corridor room I started the Corridor room with a basic Nmap scan. Here’s how I worked through it and what I tried along the way. Starting With Nmap I began with an Nmap scan against the target: nmap -A <Target IP> The scan sho
- **Email Enumeration via Password-Protected Share Identity Verification** · [HackerOne](https://hackerone.com/reports/3507273) · `2026-09-05` · **Low** · $100 · *Nextcloud* · ▲35
- **Unauthenticated testing endpoint of notify_push expose internal IP** · [HackerOne](https://hackerone.com/reports/3513471) · `2026-09-05` · **Medium** · $150 · *Nextcloud* · ▲38
- **API token sent to URL dictated by an untrusted project .weblate file** · [HackerOne](https://hackerone.com/reports/3825141) · `2026-09-04` · **Medium** · *Weblate* · ▲26 · CVE-2026-22251
  > - Direct primitive : theft of the Weblate API token by anyone who can influence a config file on the victim's discovery path. - Chain potential (per 05-chain-analysis): - Downstream : the token grants the attacker the victim's ful
- **VulnNet Roasted — TryHackMe Active Directory Write-up** · [Infosec Writeups](https://infosecwriteups.com/vulnnet-roasted-tryhackme-active-directory-write-up-9cdfccacc13e) · `2026-09-04`
  > In this write-up, I document the process followed to solve the VulnNet Roasted room on TryHackMe. It is a simple Active Directory challenge that requires us to carry out AS-REP Roasting to obtain the password for a low-privilege u
- **VMs won't contain cyber-capable agents** · [Trail of Bits](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents) · `2026-08-26`
  > As part of Patch the Planet , we received preview access to GPT 5.6-Cyber with a simple task: evaluate its cyber capabilities. Recent events inspired me to give it a challenge to work through: escape the VM I’d normally use for sa
- **Intigriti Bug Bytes #238 - July 2026 🚀** · [Intigriti](https://intigriti.com/researchers/blog/bug-bytes/intigriti-bug-bytes-238-july-2026) · `2026-07-31`
  > Hello hackers, Welcome to the latest edition of Bug Bytes! In this month's issue, we'll be featuring: Intigriti turns 10! RCE in GitHub.com and GitHub Enterprise Server Burp Suite going agentic with Burp AT Hacking Gemini Enterpri
- **Non-Production API Endpoints for the Amazon Cloudwatch Fails to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3775702) · `2026-07-27` · **Medium** · *AWS VDP* · ▲21
  > Summary: An adversary can enumerate permissions of compromised credentials for the cloudwatch service without logging to CloudTrail.
- **AI’s convenience cost. The impact of the lethal trifecta on organizations today** · [Intigriti](https://intigriti.com/blog/business-insights/impact-of-the-lethal-trifecta-on-organizations-today) · `2026-07-23`
  > The lethal trifecta matters more now than ever because AI tools can read your data, absorb instructions, and act on your behalf. That means a poisoned email, webpage, or document could trick your AI into leaking information or tak
- **Wildcard Account Lookup and Unsalted Hash Identifiers Defeat PII Masking** · [LogicalBreach](https://academy.logicalbreach.com/writeups/wildcard-account-lookup-and-unsalted-hash-identifiers-defeat-pii-masking-202f1403) · `2026-07-21`
  > An account-recovery API interpreted the supplied email selector as a wildcard pattern, allowing unauthenticated enumeration of arbitrary users. Although email addresses and phone numbers were visually masked, the API returned unsa
- **Rust-proof your code with our new Testing Handbook chapter** · [Trail of Bits](https://blog.trailofbits.com/2026/07/13/rust-proof-your-code-with-our-new-testing-handbook-chapter) · `2026-07-13`
  > We’ve added a new chapter to our Testing Handbook : a comprehensive guide to security testing Rust programs. This chapter covers the tools and techniques we use at Trail of Bits to validate the security of Rust programs and system
- **29 Premium Plugin Packages with License Keys Publicly Accessible in Uploads Directory** · [HackerOne](https://hackerone.com/reports/3839889) · `2026-07-06` · **Medium** · *Essity* · ▲8
  > Hello team, The WordPress media library on ████████ exposes 29 ZIP archives containing premium (paid) plugin packages. These files are accessible without authentication via direct URL and are indexed by the WordPress REST API ( /w
- **Non-Production API Endpoints for the Amazon S3 Tables Service Fails to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3780277) · `2026-07-02` · **Medium** · *AWS VDP* · ▲69
  > Summary: An adversary can enumerate permissions of compromised credentials for the s3tables service without logging to CloudTrail.
- **Introducing Patch the Planet** · [Trail of Bits](https://blog.trailofbits.com/2026/06/22/introducing-patch-the-planet) · `2026-06-22`
  > What happens when you clear dozens of Trail of Bits engineers’ schedules, pair them with every open-source maintainer they can contact, and unleash the latest frontier models like GPT-5.5-Cyber on critical open-source targets? Tha
- **The Vulnerability Curve Bent With the AI Curve** · [ProjectDiscovery](https://projectdiscovery.io/blog/the-vulnerability-curve-bent-with-the-ai-curve) · `2026-06-18`
  > How CVE volume, known-exploited counts and time-to-exploit all changed shape across the LLM build-out and why defenders are now on the wrong side of the clock. In 2018 the world published about 18,000 CVEs and the average vulnerab
- **The sorry state of skill distribution** · [Trail of Bits](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution) · `2026-06-03`
  > Public skill marketplaces are being flooded with malicious skills that steal credentials, exfiltrate data, and hijack agents. In response, a segment of the security industry released skill scanners, a new family of tools designed 
- **Connection Count Bug in Monero Node Enables Outbound Peer Reset Attack** · [HackerOne](https://hackerone.com/reports/3185083) · `2026-05-06` · *Monero* · ▲39
  > We disclosed a vulnerability that could cause all outbound connections of a Monero node to be dropped. The vulnerability exploits a flaw in how the Monero node incorrectly counts the number of current outbound connections. An atta
- **Episode 172: Source Code Review Meta Analysis** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2026-04-30`
  > Episode 172: In this episode of Critical Thinking - Bug Bounty Podcast trying out a new structure of episode: a Meta Analysis of sorts of many Source Code Review techniques. This episode features tips gathered from Shubs, Rafax, a
- **IBM Aspera HTTP Gateway stores sensitive information in clear text in easily obtainable files which can be read by an unauthenticated user.** · [HackerOne](https://hackerone.com/reports/3340797) · `2026-04-27` · **High** · *IBM* · ▲46
- **Benchmarking Neo's Black-Box DAST Capabilities** · [ProjectDiscovery](https://projectdiscovery.io/blog/neo-black-box-dast-capabilities) · `2026-04-27`
  > Since the launch of Neo, we've been steadily expanding what it can do. Neo has found 33+ real CVEs across open-source projects, performed well on white-box security testing where source code is available, and generally proven itse
- **Information Disclosure — Unauthenticated API Exposes PII of 500+ Employees and Enterprise Clients** · [LogicalBreach](https://academy.logicalbreach.com/writeups/information-disclosure-unauthenticated-api-exposes-pii-of-500-employees-and-enterprise-clients-852b28b3) · `2026-04-01`
  > A hardcoded backend URL found in a JavaScript bundle exposed an unauthenticated API endpoint that returned 500+ records containing employee full names, enterprise client details, and internal database IDs. The writeup walks throug
- **Session Cookie Leakage via Static Header Field in WebViewerFragment** · [HackerOne](https://hackerone.com/reports/3475626) · `2026-03-17` · **High** · *LinkedIn* · ▲130
  > A static field ( CUSTOM HEADERS ) in WebViewerFragment persists cookies across different URL loads, allowing an attacker to chain multiple weaknesses to exfiltrate a victim's LinkedIn session cookies to an attacker-controlled serv
- **Public Exposure of Internal API Models (.smd)** · [LogicalBreach](https://academy.logicalbreach.com/writeups/en-public-exposure-of-internal-api-models-smd-10ce697c-0c4e-4077-bf82-165bee277bbe) · `2026-03-01`
  > This writeup details an Information Disclosure (CWE-200) vulnerability that allowed viewing the source code and complete domain model mapping of a corporate backend.
- **Sensitive Data Exposure via JSON-RPC (Whistleblowing Channel)** · [LogicalBreach](https://academy.logicalbreach.com/writeups/en-sensitive-data-exposure-via-json-rpc-whistleblowing-channel-cdcf8659-4341-4694-9084-6fa2f84b8d1a) · `2026-03-01`
  > An unprotected endpoint allowed the exfiltration, via a simple unauthenticated POST request, of gigabytes of configurations, structural metadata, and private personal/corporate information belonging to the organizations using the 
- **Publicly accessible `█████████` endpoint exposing internal user identifiers and email addresses** · [HackerOne](https://hackerone.com/reports/3360293) · `2026-02-24` · **Medium** · *Mars* · ▲49
- **███████ - Publicly Accessible public_html Directory Exposing WordPress Configuration** · [HackerOne](https://hackerone.com/reports/3066548) · `2026-02-24` · **Medium** · *Mars* · ▲29
- **Sensitive information exposed at [███] via /export_panelists_to_xlsx endpoint** · [HackerOne](https://hackerone.com/reports/3376598) · `2026-02-24` · **Medium** · *Mars* · ▲35
- **ASLR leak in Mario Kart World through LAN mode** · [HackerOne](https://hackerone.com/reports/3463719) · `2026-02-19` · **High** · *Nintendo* · ▲74
- **LLM bug hunters lack intuition, EU Cyber Act revision – offsec roundup** · [YesWeHack](https://yeswehack.com/news/llm-hunters-visibility-cyber-act) · `2026-02-16`
  > This edition features an EU proposal that would strengthen vulnerability disclosure, CISOs’ cyber predictions for 2026 and insights about autonomous AI hacking.
- **User enumeration via timing attack in Django mod_wsgi authentication backend leads to account discovery** · [HackerOne](https://hackerone.com/reports/3424977) · `2026-02-04` · *Django* · ▲62
  > This timing attack allows attackers to enumerate valid usernames in the system, which can be used as a stepping stone for further attacks such as credential stuffing or brute force attempts focused on known valid accounts. Remedia
- **Internal logs/info leaked via endpoint {https://203.137.128.240/server-status}** · [HackerOne](https://hackerone.com/reports/2473173) · `2026-01-20` · **High** · *pixiv* · ▲144
- **Roundcube Webmail Style Sanitizer can be bypassed using CSS Character Escapes** · [HackerOne](https://hackerone.com/reports/3443563) · `2026-01-14` · **Medium** · *Nextcloud* · ▲46
  > The style sanitizer in Roundcube Webmail can be bypassed by creating HTML entities using CSS character escapes. This allows using arbitrary inline CSS, like e.g. url() , and retrieve the IP address and user agent of the person rea
- **Publicly Accessible CDN Endpoint Exposing XML Metadata (including ETag)** · [HackerOne](https://hackerone.com/reports/3346375) · `2026-01-12` · **Low** · *U.S. Dept Of Defense* · ▲14
  > Metadata & ETag exposure: Filenames, timestamps, sizes, and ETags give an attacker reconnaissance data to map internal content and activity patterns. File fingerprinting: ETags often contain a hash (commonly MD5 for single-part S3
- **Debug Info disclose** · [HackerOne](https://hackerone.com/reports/3066992) · `2026-01-12` · **Low** · *U.S. Dept Of Defense* · ▲9
  > Hi team, I hope you are well I found your domain that discloses debug output info. Steps of Reproduction:- ██████████&format=jsonv2&debug=2 ██████████ Impact Information disclosure System Host(s) ███████ Affected Product(s) and Ve
- **exposed FOUO documents, including Passport information** · [HackerOne](https://hackerone.com/reports/3291053) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲6
  > Access to someone's private passport, complete with their address, DOB and personal information. System Host(s) ██████████ Affected Product(s) and Version(s) CVE Numbers Steps to Reproduce 1)enter this into google: intitle:FOUO fi
- **ASBS viewing other soldiers PII/Board/Board Voters/ETC** · [HackerOne](https://hackerone.com/reports/2954320) · `2026-01-12` · **Critical** · *U.S. Dept Of Defense* · ▲6
  > This would allow an attacker to capture data of soldiers by DoDID, to then look up other soldier data to gather board information, SSN, Clearance information, Branch information. If a user was able to grab their own information, t
- **[Critical Data Breach] Exposure of PII Data Leak via API Response** · [HackerOne](https://hackerone.com/reports/3078508) · `2026-01-12` · **Critical** · *U.S. Dept Of Defense* · ▲8
- **Postgres Admin Username and Password in Plain text** · [HackerOne](https://hackerone.com/reports/1561448) · `2026-01-06` · **Low** · *UPchieve* · ▲12
  > Gitlab commit contains password in plain text Steps To Reproduce: Navigate to https://gitlab.com/upchieve/subway/-/commit/e0e039496321c9d62a591504d387589224660a5c Supporting Material/References: Recommendations for Fixing/Mitigati
- **Non-Production API Endpoints for the AI Ops Service Fails to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3418966) · `2026-01-06` · **Medium** · *AWS VDP* · ▲18
  > Summary: An adversary can enumerate permissions of compromised credentials for the aiops service without logging to CloudTrail.
- **Information disclosure via Desktop client when attempting to lock a file inside a end-to-end encrypted directory** · [HackerOne](https://hackerone.com/reports/3159877) · `2026-01-04` · *Nextcloud* · ▲8 · CVE-2025-66549
- **Episode 152: GeminiJack and Agentic Security with Sasi Levi** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-12-11`
  > Episode 152: In this episode of Critical Thinking - Bug Bounty Podcast we’re joined by Sasi Levi from Noma Security to talk about AI and Agentic Security. We also talk about ForcedLeak, a Google Vertex Bug, and debate if Prompt In
- **Episode 150: ASP.NET MVC Patterns, Popping Oracle Identity, and Esoteric Subdomain Enumeration** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-11-27`
  > Episode 150: In this episode of Critical Thinking - Bug Bounty Podcast we're highlighting some cool news and research, but not before expressing our gratitude to the Hacker community. We are so thankful for you all! Follow us on t
- **Username Validation Bypass** · [HackerOne](https://hackerone.com/reports/3434156) · `2025-11-26` · **Medium** · *Revive Adserver* · ▲64 · CVE-2025-55129
  > - MOST DANGEROUS - Visually indistinguishable from "admin" - Perfect phishing vector - Users cannot detect the fake account - Credential harvesting - Admin impersonation attacks
- **Information Disclosure via Verbose Error Messages** · [HackerOne](https://hackerone.com/reports/3403450) · `2025-11-19` · **Medium** · *Revive Adserver* · ▲17 · CVE-2025-52671
  > Revive Adserver v6.0.0 exposes sensitive technical details through verbose error messages, revealing the exact MySQL/MariaDB version, SQL queries, and PHP environment details. Attackers can use this information to identify known v
- **Information Disclosure via “Add user” lookup in Account Management (User Access)** · [HackerOne](https://hackerone.com/reports/3401464) · `2025-11-19` · **Medium** · *Revive Adserver* · ▲16 · CVE-2025-52669
  > When a user under Management 1 navigates to User Access → Add user and enters a username, the system performs a global lookup across all accounts instead of restricting the search to the current account’s scope. If the entered use
- **Microsoft `x-apikey` Exposed in Mozilla CI Public Logs** · [HackerOne](https://hackerone.com/reports/3243860) · `2025-11-03` · **Medium** · $200 · *Mozilla* · ▲84
- **No Confirmation Email For Email Change** · [HackerOne](https://hackerone.com/reports/268221) · `2025-10-31` · **Low** · *Hiro* · ▲28
  > https://forum.blockstack.org/u/username/preferences/email Hello, it looks like there is a security flaw in this part. While changing email address from email1 to email2. A Confirmation email is sent to email2 not to email1 which i
- **Information Disclosure** · [HackerOne](https://hackerone.com/reports/268224) · `2025-10-31` · **Medium** · *Hiro* · ▲21
  > It looks like I can access notification panel of any user. https://forum.blockstack.org/u/username/notifications Just change the username with the desired username and you are redirected to their notification panel.
- **Can view all username leaked in https://core.blockstack.org** · [HackerOne](https://hackerone.com/reports/377565) · `2025-10-31` · *Hiro* · ▲14
  > Information Disclosure
- **Blockstack Browser For Mac leaks "Core API Password" to 3rd parties** · [HackerOne](https://hackerone.com/reports/541760) · `2025-10-31` · **Low** · *Hiro* · ▲8
  > compromise or accidental exposure of any of the sites, loadbalancer logs, or tracking services used on the listed sites would expose BlockStack users' CoreAPIPasswords. This leakage of the CoreAPIPassword contradicts public statem
- **Information Disclosure via Accessible debug.log on ExactHosting** · [HackerOne](https://hackerone.com/reports/3372277) · `2025-10-14` · *Tucows (VDP)* · ▲14
- **Directory Listing of publicly available assets** · [HackerOne](https://hackerone.com/reports/2311179) · `2025-09-29` · **Medium** · *Nextcloud* · ▲70
  > The web server is configured to display the list of files contained in this directory. This is not recommended because the directory may contain files that are not normally exposed through links on the web site. For obvious reason
- **Critical Information Disclosure via /talos/api/v1/files/upload** · [HackerOne](https://hackerone.com/reports/3228011) · `2025-09-17` · **Critical** · *Bykea* · ▲96
- **MongoDB Query Logs & Schema Leak via Unauthenticated Endpoint** · [HackerOne](https://hackerone.com/reports/3249406) · `2025-09-17` · **Low** · *Bykea* · ▲43
- **337k users and 1 employee leaked credentials** · [HackerOne](https://hackerone.com/reports/3250691) · `2025-09-10` · **High** · *Khan Academy* · ▲86
  > Users account are being leaked which can leak Khan Academy's customers sensitive information
- **ksmbd - Fuzzing Improvements and Vulnerability Discovery (2/3)** · [Doyensec](https://blog.doyensec.com/2025/09/02/ksmbd-2.html) · `2025-09-01`
  > Introduction This is a follow-up to the article originally published here . Our initial research uncovered several unauthenticated bugs, but we had only touched the attack surface lightly. Even after patching the code to bypass au
- **Inline Style Exfiltration: leaking data with chained CSS conditionals** · [PortSwigger Research](https://portswigger.net/research/inline-style-exfiltration) · `2025-08-26`
  > I discovered how to use CSS to steal attribute data without selectors and stylesheet imports! This means you can now exploit CSS injection via style attributes! Learn how below: Someone asked if you c
- **PII Exposure via Email Confirmation Link – Email Embedded in Token & Leaked via Wayback Machine** · [HackerOne](https://hackerone.com/reports/3210022) · `2025-08-23` · **Medium** · *Omise* · ▲78
  > - Leaks PII (email address) in URL - Publicly archived link on Wayback Machine exposes user identity - Token is easily Base64-decoded - Potential email confirmation abuse if token is replayable - Risk of user enumeration or phishi
- **█.8x8.vc/index.js: Exposed Google Maps API Key Allowing Potential Abuse of Paid Services** · [HackerOne](https://hackerone.com/reports/3250315) · `2025-08-14` · **Medium** · $500 · *8x8* · ▲87
- **Episode 133: Building Hacker Communities - Bug Bounty Village, getDisclosed, and the LHE Squad** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-07-31`
  > Episode 133: In this episode of Critical Thinking - Bug Bounty Podcast we’re joined by Harley and Ari from H1 to talk some about community management roles within Bug Bounty, as well as discuss the evolution of Bug Bounty Village 
- **Episode 131: SL Cyber Writeups, Bug Bounty Metastrategy, and Orphaned Github Commits** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-07-17`
  > Episode 131: In this episode of Critical Thinking - Bug Bounty Podcast we're covering Christmas in July with several banger articles from Searchlight Cyber, as well as covering things like Raycast for Windows, Third-Person prompti
- **exposure of personal IP address via email.** · [HackerOne](https://hackerone.com/reports/3179850) · `2025-07-16` · *Weblate* · ▲61
  > Attackers can leverage the exposed IP for network reconnaissance, which may lead to: Fingerprinting the user’s device or ISP. Port scanning, service discovery, or OS detection. Tracking or correlating with other data leaks (OSINT 
- **Information disclosure identified on IBM endpoint.** · [HackerOne](https://hackerone.com/reports/2402842) · `2025-07-08` · **Medium** · *IBM* · ▲39
- **WordPress Version Exposure via ███████ on hemi.xyz** · [HackerOne](https://hackerone.com/reports/3198394) · `2025-06-13` · *Hemi VDP* · ▲38
  > The WordPress CMS version is exposed in the XML file at https://hemi.xyz███. This disclosure allows attackers to fingerprint the CMS version, potentially leading to targeted exploitation if known vulnerabilities exist for this spe
- **Public GitHub repositories for multiple HackerOne managed triage team profiles contain private HackerOne reports information** · [HackerOne](https://hackerone.com/reports/2937622) · `2025-05-31` · **Medium** · *HackerOne* · ▲225
  > Hello, team! I hope this report finds you well. I identified a shared GitHub profile for the HackerOne-managed triage team at ███. It contains 44 public repositories, many of which were recently created: ██████████ Since this is a
- **Information Disclosure of metrics fax.wavecell.com/metrics** · [HackerOne](https://hackerone.com/reports/1365076) · `2025-05-30` · **Low** · *8x8* · ▲93
  > This information may help attackers understand more things about the target application which may help in further investigation and exploitation.
- **Non-Production API Endpoints for the bedrock-agent Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/2800091) · `2025-05-28` · **Medium** · *AWS VDP* · ▲38
  > Summary: An adversary can enumerate permissions of compromised credentials for the bedrock-agent service without logging to CloudTrail.
- **Non-Production API Endpoints for the bedrock Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/2951803) · `2025-05-28` · **Medium** · *AWS VDP* · ▲25
  > An adversary can enumerate permissions of compromised credentials for two actions from the bedrock service without logging to CloudTrail. We have found 5 non-production endpoints which exhibit this behavior.
- **Non-Production API Endpoint for the EventBridge Service Fails to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3021618) · `2025-05-28` · **Medium** · *AWS VDP* · ▲26
  > Summary: An adversary can enumerate permissions of compromised credentials for the elasticache service without logging to CloudTrail.
- **Non-Production API Endpoints for the Global Accelerator Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3029552) · `2025-05-28` · **Medium** · *AWS VDP* · ▲23
  > Summary: An adversary can enumerate permissions of compromised credentials for the globalaccelerator service without logging to CloudTrail.
- **Non-Production API Endpoints for the Health Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3042588) · `2025-05-28` · **Medium** · *AWS VDP* · ▲21
  > Summary: An adversary can enumerate permissions of compromised credentials for the health service without logging to CloudTrail.
- **Non-Production API Endpoints for the Neptune Graph Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3068422) · `2025-05-27` · **Medium** · *AWS VDP* · ▲17
  > Summary: An adversary can enumerate permissions of compromised credentials for the lakeformation and m2 service without logging to CloudTrail.
- **Non-Production API Endpoints for the Route 53 Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3092085) · `2025-05-27` · **Medium** · *AWS VDP* · ▲14
  > Summary: An adversary can enumerate permissions of compromised credentials for the redshift-data service without logging to CloudTrail.
- **Users Data Exposure via Insecure Endpoint** · [HackerOne](https://hackerone.com/reports/2828608) · `2025-05-12` · **Medium** · *Mars* · ▲40
- **debug.log leaked [█████████]** · [HackerOne](https://hackerone.com/reports/3063026) · `2025-05-12` · **Low** · *Mars* · ▲40
- **massive PII leakage for ███████** · [HackerOne](https://hackerone.com/reports/2887506) · `2025-05-12` · **Medium** · *Mars* · ▲36
- **Improper Session Invalidation – Auto Sign-In Without Credentials After Logout (Affects Chrome & Firefox)** · [HackerOne](https://hackerone.com/reports/3101207) · `2025-04-29` · **Medium** · *Dust* · ▲56
  > When a user logs out, the session is not invalidated properly. Revisiting the login page allows automatic re-authentication without any user input. This means the session remains active or is being improperly restored. Tested on: 
- **Possible Sensitive Session Information Leak in Active Storage** · [HackerOne](https://hackerone.com/reports/3082917) · `2025-04-27` · **High** · $4,323 · *Internet Bug Bounty* · ▲82
  > Active Storage, when serving files (blobs), incorrectly sends the Set-Cookie header containing the user's session cookie along with a Cache-Control: public header. Some certain caching proxies may cache this response, including th
- **Non-Production API Endpoints for the Glue Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3031512) · `2025-04-25` · **Medium** · *AWS VDP* · ▲18
  > Summary: An adversary can enumerate permissions of compromised credentials for the glue service without logging to CloudTrail.
- **Non-Production API Endpoints for the cloudwatch Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/2972435) · `2025-04-25` · **Medium** · *AWS VDP* · ▲23
  > Summary: An adversary can enumerate permissions of compromised credentials for the bedrock-agent service without logging to CloudTrail.
- **Non-Production API Endpoints for the ssm Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/2926361) · `2025-04-24` · **Medium** · *AWS VDP* · ▲37
  > An adversary can enumerate permissions of compromised credentials for the ssm service without logging to CloudTrail. We have found 18 non-production endpoints which exhibit this behavior.
- **Leaked credentials ( emails and passwords , etc...)** · [HackerOne](https://hackerone.com/reports/3091909) · `2025-04-16` · *WakaTime* · ▲77
  > Hi i'm a CTI analyst And Bug bounty Hunter , I found A lot of credentials for your domain on the Telegram bot: ████████ While the exact sources of the leaked data are unknown, the volume of exposed information is substantial. This
- **(Part 2) Non-Production API Endpoints for the Datazone Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3014785) · `2025-04-08` · **Medium** · *AWS VDP* · ▲56
  > Summary: An adversary can enumerate permissions of compromised credentials for the datazone service without logging to CloudTrail.
- **The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summary is present** · [HackerOne](https://hackerone.com/reports/3000510) · `2025-04-01` · **Critical** · *HackerOne* · ▲625
  > Reporter H1 account private data disclosed
- **Non-Production API Endpoints for the Forecast Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3022516) · `2025-03-24` · **Medium** · *AWS VDP* · ▲75
  > Summary: An adversary can enumerate permissions of compromised credentials for the forcast service without logging to CloudTrail.
- **Great ‘Wallbleed’ of China, overlooked Burp feature – hacker roundup** · [YesWeHack](https://yeswehack.com/news/youtube-wallbleed-burp-hacker-roundup) · `2025-03-21`
  > Our latest hacker roundup features a video about leveraging Burp’s overlooked “best feature” and an exploit that leaks the email of any YouTube user.
- **Django Debug Mode Enabled - Information Disclosure on api.wwm-dev.autodesk.com** · [HackerOne](https://hackerone.com/reports/2965143) · `2025-03-18` · **Medium** · *Autodesk* · ▲82
- **Non-Production API Endpoints for the DocumentDB Elastic Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/3009411) · `2025-03-11` · **Medium** · *AWS VDP* · ▲45
  > Summary: An adversary can enumerate permissions of compromised credentials for the docdb-elastic service without logging to CloudTrail.
- **US House passes bill mandating VDPs for federal contractors** · [YesWeHack](https://yeswehack.com/news/us-house-bill-vulnerability-disclosure) · `2025-03-11`
  > The US House of Representatives has passed a bill that would oblige federal contractors to implement a vulnerability disclosure policy (VDP).
- **Exposing debug.log file leads to server full path disclosure** · [HackerOne](https://hackerone.com/reports/3002345) · `2025-03-06` · **Low** · *Autodesk* · ▲56
- **Non-Production API Endpoints for the Datazone Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** · [HackerOne](https://hackerone.com/reports/2981210) · `2025-02-26` · **Medium** · *AWS VDP* · ▲50
  > Summary: An adversary can enumerate permissions of compromised credentials for the datazone service without logging to CloudTrail.
- **Burp Suite extensions can execute arbitrary code** · [HackerOne](https://hackerone.com/reports/3014158) · `2025-02-26` · **High** · *PortSwigger Web Security* · ▲85
  > The primary issue is that Burp Suite extensions execute code with the same privileges as the user. If an attacker manages to convince a target to install a malicious extension, they can: - Gain persistent access to the system. - E
- **User Email Disclosure via ID-Based Invitation** · [HackerOne](https://hackerone.com/reports/3003716) · `2025-02-22` · **Medium** · *WakaTime* · ▲73
  > The issue occurs when inviting a user by their WakaTime ID. If a user has set their email to private, their email address still appears when they are invited using their ID. This contradicts the privacy settings and could lead to 
- **VSCode launch.json file exposed on hemi.xyz** · [HackerOne](https://hackerone.com/reports/2997774) · `2025-02-21` · *Hemi VDP* · ▲38
- **Possible to enumerate valid files in password protected shares/files drop shares as well as spam folder with files** · [HackerOne](https://hackerone.com/reports/2376909) · `2025-02-21` · **Low** · *Nextcloud* · ▲29
  > It is possible possible to enumerate valid files in password protected shares/files drop shares as well as spam the folder with empty files with an attacker controlled file name. Steps To Reproduce: 1. Create a folder and create t
- **Wordpress users Disclosure** · [HackerOne](https://hackerone.com/reports/2981756) · `2025-02-12` · **Critical** · *Autodesk* · ▲69
  > Malicious people could collect the usernames disclosed (and the admin user) and be focused throughout BF attack (as the usernames are now known), making it less harder to penetrate your systems.
- **API Data Leakage Vulnerability Report - `xvcams.com`** · [HackerOne](https://hackerone.com/reports/2979153) · `2025-02-09` · *XVIDEOS* · ▲33
  > Impact: 🚨 This vulnerability exposes personally identifiable information (PII), leading to: - Identity Theft & Fraud (birthdates + location = easy identity verification attacks) - Targeted Harassment & Doxxing (users' real locatio
- **Weak credentials found in Jenkins endpoint** · [HackerOne](https://hackerone.com/reports/2954547) · `2025-02-05` · **Critical** · *IBM* · ▲40
- **Public google drive link Exposes Military Orders Containing PII (Name, SSN etc..) and Operational Details** · [HackerOne](https://hackerone.com/reports/2926447) · `2025-01-24` · **Critical** · *U.S. Dept Of Defense* · ▲99
  > 1. Privacy Violation: Exposes PII of personnel, violating privacy laws such as the U.S. Privacy Act of 1974. 2. Identity Theft and Fraud: Information like SSNs and home addresses can be used for malicious purposes. System Host(s) 
- **Lack of Rate Limiting on Account Creation Endpoint** · [HackerOne](https://hackerone.com/reports/2915502) · `2025-01-16` · **Low** · $200 · *XVIDEOS* · ▲110
  > Impact : - Account Flooding : Automated creation of fake accounts overwhelms the system. - Abuse & Spamming : Fake accounts can be used for malicious activities. - Degraded Performance : Slower system performance for legitimate us
- **netrc and redirect credential leak** · [HackerOne](https://hackerone.com/reports/2894283) · `2025-01-15` · **Low** · $505 · *Internet Bug Bounty* · ▲49 · CVE-2024-11053
  > Information disclosure (password sent to the wrong host).
- **Information Disclosure: .dockerignore file is publicly accessible** · [HackerOne](https://hackerone.com/reports/2888001) · `2025-01-14` · *Flickr* · ▲45
- **Yet Another OTP code Leaked in the API Response** · [HackerOne](https://hackerone.com/reports/2635315) · `2025-01-08` · **Critical** · *MTN Group* · ▲134
  > This is much similar to my report here(https://hackerone.com/reports/2633888) , except it affects a different domain. The application requests a phone number for authentication, then sends an OTP code to the user. But the OTP is l
