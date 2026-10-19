# Path Traversal

*27 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **RCE in AWS Amplify CLI via Prototype Chain Traversal in amplify-velocity-template** · [HackerOne](https://hackerone.com/reports/3897236) · `2026-10-13` · **High** · *AWS VDP* · ▲21
  > amplify-velocity-template (npm, published by Amazon) is a fork of velocityjs used by @aws-amplify/amplify-appsync-simulator to render VTL resolver templates during amplify mock api . The fork never backported any prototype-chain g
- **Path Traversal in Nextcloud Talk Android Exposes User Credentials and Private Data via FileProvider** · [HackerOne](https://hackerone.com/reports/3696266) · `2026-08-24` · **Medium** · *Nextcloud* · ▲18
- **Unauthenticated Path Traversal (LFI) via /custom-sounds/ when CustomSounds uses FileSystem storage** · [HackerOne](https://hackerone.com/reports/3514640) · `2026-08-03` · **High** · *Rocket.Chat* · ▲47 · CVE-2026-56845
- **SELECT ... INTO OUTFILE does not enforce the FILE WRITE privilege unprivileged arbitrary file write on the server** · [HackerOne](https://hackerone.com/reports/3780695) · `2026-07-13` · **High** · *SingleStore* · ▲50
- **jitsi-call-analytics: Unauthenticated arbitrary file write via path traversal in `/api/v1/uploads/analyze`** · [HackerOne](https://hackerone.com/reports/3485343) · `2026-07-02` · **Low** · $100 · *8x8* · ▲68
- **Path traversal via an unauthenticated export download action using client controlled directory and filename parameters a9c49b9e** · [LogicalBreach](https://academy.logicalbreach.com/writeups/path-traversal-via-an-unauthenticated-export-download-action-using-client-controlled-directory-and-filename-parameters-a9c49b9e) · `2026-06-30`
- **Burp Suite Professional: browser-powered crawl can write attacker-controlled files through file input handling** · [HackerOne](https://hackerone.com/reports/3712279) · `2026-06-14` · **High** · $5,000 · *PortSwigger Web Security* · ▲174
  > When Burp Scanner's browser-powered crawler crawls an attacker's website, the website can force Burp to write an attacker-controlled file to an attacker-controlled local path. For example, the PoC writes calc.exe into the current 
- **ActiveStorage Disk Service Path Traversal via Custom Blob Key Injection** · [HackerOne](https://hackerone.com/reports/3580511) · `2026-05-07` · **Medium** · *Ruby on Rails* · ▲57
  > ActiveStorage's DiskService path for does not validate or sanitize blob keys before constructing file paths. Combined with the Hash attachable interface — which passes user-supplied key: values directly to Blob.build after unfurli
- **SMIL values and by attributes bypass remote image blocking via unvalidated resource-loading animations, enabling email tracking without consent** · [HackerOne](https://hackerone.com/reports/3590576) · `2026-04-20` · **Medium** · *Nextcloud* · ▲26
  > Tracking of opens, read time, and element hover
- **Episode 168: XSSDoctor - Client-side Path Traversal Research** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2026-04-02`
  > Episode 168: In this episode of Critical Thinking - Bug Bounty Podcast we’re getting a visit from the XSS Doctor. Jonathan joins us to go through his Client-side workflow, run labs, and diagnose some bugs live. Follow us on twitte
- **Path Traversal in writeFile via Unsafe Prefix Containment Check Allows Out-of-Directory Writes** · [HackerOne](https://hackerone.com/reports/3634571) · `2026-03-31` · **Medium** · *arkadiyt-projects* · ▲21
  > protodump uses descriptor-controlled paths ( name/go package ) in output filename construction and then enforces containment with a lexical strings.HasPrefix check after EvalSymlinks . That check is bypassable with ../ traversal i
- **Bypass of Open Redirect Fix on lovable.dev via /..// Path Traversal in redirect parameter** · [HackerOne](https://hackerone.com/reports/3599248) · `2026-03-12` · **Medium** · *Lovable VDP* · ▲73
  > A bypass exists for the previously patched open redirect vulnerability (report 3581815) on lovable.dev. The original fix blocked backslash-based payloads (/\ and /%5C), but fails to account for path traversal sequences combined wi
- **CVE-█████-35813 in █████** · [HackerOne](https://hackerone.com/reports/2200329) · `2026-02-24` · **Critical** · *Mars* · ▲71 · CVE-2023-35813
- **Information Disclosure via Publicly Accessible Debug Log** · [HackerOne](https://hackerone.com/reports/3318295) · `2026-01-12` · **Low** · *U.S. Dept Of Defense* · ▲15
  > A publicly accessible WordPress debug.log file via █████████ was discovered on the target system. The file contains PHP warnings and deprecated notices that disclose sensitive server paths and plugin details. This exposure may ass
- **DNN - Unrestricted Arbitrary File Upload #████████** · [HackerOne](https://hackerone.com/reports/3414079) · `2026-01-12` · **Critical** · *U.S. Dept Of Defense* · ▲10 · CVE-2025-64095
  > Unauthenticated attackers can upload and overwrite files, leading to website defacement and cross-site scripting attacks. System Host(s) █████ Affected Product(s) and Version(s) CVE Numbers Steps to Reproduce Vulnerable subdomain 
- **Path traversal via archive.extract - CVE 2021-3281 incomplete patch** · [HackerOne](https://hackerone.com/reports/3328367) · `2025-11-21` · **Low** · *Django* · ▲38 · CVE-2021-3281
  > This leads to a partial-path traversal vulnerability, which allows an attacker to write files outside of the base directory when unzipping archives (tar and zip).
- **Arbitrary File Write** · [HackerOne](https://hackerone.com/reports/3384150) · `2025-10-19` · **High** · *arkadiyt-projects* · ▲56
  > arbitrary file write on user's machine Affected Version : Latest (commit 17ad807, verified October 2025) Repository : https://github.com/arkadiyt/protodump Installation : go install github.com/arkadiyt/protodump/cmd/protodump@late
- **Path Traversal Vulnerability in Nextcloud Tables Enables Arbitrary File Exfiltration of Any Files Supported by PhpSpreadsheet Library** · [HackerOne](https://hackerone.com/reports/3249624) · `2025-10-16` · **Medium** · *Nextcloud* · ▲63 · CVE-2025-58051
- **Exposing debug.log file leads to server full path disclosure** · [HackerOne](https://hackerone.com/reports/2778441) · `2025-09-29` · **Medium** · *Nextcloud* · ▲47
  > The exposed debug.log file on the nextcloud.com website contains sensitive information, including the server’s full directory path. This type of information disclosure can assist attackers in understanding the internal structure o
- **Mozilla VPN Clients: RCE via file write and path traversal** · [HackerOne](https://hackerone.com/reports/2995025) · `2025-07-29` · **High** · $6,000 · *Mozilla* · ▲172
  > Hi! I decided to have another look at the Mozilla VPN Client, after 2920675 was set to resolved. When going over all commands in the inspector, I noticed the "live reload" command can be used with remote files. When using this com
- **Episode 127: Drama, PDF as JS Chaos, Bounty Profile Apps, And More** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-06-19`
  > Episode 127: In this episode of Critical Thinking - Bug Bounty Podcast we address some recent bug bounty controversy before jumping into a slew of news items Follow us on X Shoutout to YTCracker for the awesome intro music! Today'
- **Path Traversal Vulnerability in Lila Project** · [HackerOne](https://hackerone.com/reports/3181066) · `2025-06-09` · **High** · *Lichess* · ▲116
  > A path traversal vulnerability was discovered in the Lila project that allows an attacker to access arbitrary files on the server by manipulating user-supplied input to traverse outside the intended directory structure. This flaw 
- **Path Traversal Vulnerability found on IBM Cloud** · [HackerOne](https://hackerone.com/reports/3060373) · `2025-05-07` · **Critical** · *IBM* · ▲63
- **CSPT Resources** · [Doyensec](https://blog.doyensec.com/2025/03/27/cspt-resources.html) · `2025-03-26`
  > As a follow up to Maxence Schmitt’s research on Client-Side Path Traversal (CSPT) , we wanted to encourage researchers, bug hunters, and security professionals to explore CSPT further, as it remains an underrated yet impactful att
- **cgi scripts wordlist entry for windmail.exe has payload that sends arbitrary file read result to third-party** · [HackerOne](https://hackerone.com/reports/2733994) · `2025-03-13` · **Low** · $200 · *PortSwigger Web Security* · ▲81
  > Burp sends the not-very-confidential file C:\boot.ini of an exploited server to the e-mail address Hacker@hax0r.com
- **Unauthenticated Path Traversal and Command Injection in Trellix Enterprise Security Manager 11.6.10** · [HackerOne](https://hackerone.com/reports/2817658) · `2025-01-12` · **Critical** · *Trellix* · ▲60
  > A critical vulnerability in Trellix Enterprise Security Manager (ESM) version 11.6.10 allows unauthenticated access to the internal Snowservice API and enables remote code execution through command injection, executed as the root 
- **Bypassing File Upload Restrictions To Exploit Client-Side Path Traversal** · [Doyensec](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html) · `2025-01-08`
  > In my previous blog post , I demonstrated how a JSON file could be used as a gadget for Client-Side Path Traversal (CSPT) to perform Cross-Site Request Forgery (CSRF). That example was straightforward because no file upload restri
