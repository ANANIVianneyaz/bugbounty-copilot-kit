# XSS — Reflected to Zero-Click ATO

*131 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **Burp Suite OpenAPI Event Log HTML injection triggers Windows SMB authentication** · [HackerOne](https://hackerone.com/reports/3972558) · `2026-10-15` · **Medium** · $1,000 · *PortSwigger Web Security* · ▲41 · CVE-2021-29416
  > Burp Suite 2026.8 build 53343 inserts attacker-controlled text from an OpenAPI parser exception into the Event log HTML without encoding it. After the user invokes Response → Save OpenAPI requests to site map and selects the resul
- **Stored XSS on the public Pontoon dashboards: the latest-activity tooltip re-parses a contributor's account address as HTML** · [HackerOne](https://hackerone.com/reports/3988961) · `2026-10-14` · **High** · $3,000 · *Mozilla* · ▲39
- **ActionText `to_markdown` still allows `javascript:` links in kramdown via Rails-generated table cells after PR #58754** · [HackerOne](https://hackerone.com/reports/4082665) · `2026-10-10` · **Medium** · *Ruby on Rails* · ▲15
- **HTML Injection in Contact Form Email Enables Phishing via Legitimate ████████ Infrastructure** · [HackerOne](https://hackerone.com/reports/3802451) · `2026-10-05` · **Medium** · *Essity* · ▲37
  > The contact form email endpoint at POST ████████/contacts/email on ████████ accepts a firstName field that is rendered as raw, unescaped HTML in the body of the transactional confirmation email sent via SendGrid. The email greetin
- **One-click cross-account JavaScript execution steals a victim write token through Turbo pagination and unattached Active Storage HTML** · [HackerOne](https://hackerone.com/reports/3943339) · `2026-10-02` · **High** · *Basecamp* · ▲48
  > A low-privileged attacker with their own Fizzy account can compromise an unrelated signed-in victim's Fizzy Identity by convincing the victim to open one attacker-owned public-board URL. No shared account is required. The attacker
- **Action Text to_markdown: <code>/<pre> content escapes its delimiter, letting a stored body inject arbitrary Markdown** · [HackerOne](https://hackerone.com/reports/3994016) · `2026-09-12` · **Medium** · *Ruby on Rails* · ▲23
  > ActionText::Content to markdown escapes text nodes so that a stored rich text body cannot turn into Markdown syntax. Text whose immediate parent is <code or <pre is exempt from that escaping ( MarkdownConversion::SKIP ESCAPING PAR
- **CORS Misconfiguration / Broken Access Control** · [HackerOne](https://hackerone.com/reports/3930102) · `2026-09-10` · *Myndr* · ▲21
  > DescribImpact Any website hosted on a .myndr.net subdomain can read authenticated admin panel responses. This includes: CSRF nonces from login and password change forms. Admin panel functionality and data. Session tokens if stored
- **Author → stored XSS in wp-admin: unescaped sub-size filename from attachment metadata breaks out of the `src` attribute in `get_media_item()`** · [HackerOne](https://hackerone.com/reports/3931771) · `2026-08-28` · **Critical** · *WordPress* · ▲31
  > finalize item() stores the attacker-supplied sub sizes[].file string verbatim into wp attachment metadata['sizes'][<name ]['file'] — no sanitize file name() , no pattern , no sanitize callback . image get intermediate size() strin
- **Pre-authentication Stored XSS in Essity Customer-Service Pipeline via ContactApi (reCAPTCHA bypass + no rate limit)** · [HackerOne](https://hackerone.com/reports/3729501) · `2026-08-27` · **Critical** · *Essity* · ▲46
  > The Essity customer contact API ( ContactApi.SavePersonalContactExtended and SaveProductContactExtended ) accepts unauthenticated ticket submissions with arbitrary HTML/JavaScript in 12+ fields, bypassing reCAPTCHA validation, CSR
- **@jitsi/docker-jitsi-meet: `/colibri-relay-ws/` unsafe nginx regex (OCTO relay configuration)** · [HackerOne](https://hackerone.com/reports/3889473) · `2026-08-25` · **Low** · *8x8* · ▲25
- **URI scheme validation bypass in ActionText `to_markdown` via user-supplied `<action-text-markdown>` marker tag** · [HackerOne](https://hackerone.com/reports/3727743) · `2026-08-24` · **Medium** · *Ruby on Rails* · ▲13
  > Any consumer of ActionText::RichText to markdown / Content to markdown output (preview pane, email digest, federated mirror, secondary markdown renderer) can receive an attacker-controlled javascript:, data:, or other unsafe-schem
- **Stored HTML Injection (CWE-79) via Livechat Visitor Name** · [HackerOne](https://hackerone.com/reports/3872858) · `2026-08-20` · **Low** · *Rocket.Chat* · ▲15 · CVE-2026-65644
- **Stored XSS in nameserver field on account settings page** · [HackerOne](https://hackerone.com/reports/3644182) · `2026-07-31` · **Low** · *Tucows (VDP)* · ▲56
  > The lack of input validation and weak CSP configuration on the account settings page leads to a stored XSS vulnerability Steps To Reproduce: 1. Go to this address: https://www.████████.com/signin/ 2. Sign in to your account 3. Cli
- **Stored XSS via SVG Upload — check_content() Blocklist Bypass & 256-Byte Scan Limit (Self-Propagating Worm)** · [HackerOne](https://hackerone.com/reports/3606773) · `2026-07-30` · **Medium** · *phpBB* · ▲55
  > Tested Version: phpBB 4.0.0-a2-dev (Docker, latest master branch as of March 2026) phpBB implements a content-scanning check ( phpbb\files\filespec storage::check content() ) to prevent upload of malicious files. Two critical, ind
- **Reflected HTML Injection in ████████ Login Page via infotext/signintext Parameters** · [HackerOne](https://hackerone.com/reports/3781785) · `2026-07-22` · **High** · *Essity* · ▲7
  > A reflected HTML injection vulnerability was identified on the ████████████████ login page. The page includes a custom JavaScript theme script that reads the URL parameters infotext and signintext and inserts them into the DOM usi
- **Rickrolling The World Cup, 0-click sXSS in Next.js – ethical hacker roundup** · [YesWeHack](https://yeswehack.com/news/rickrolling-fifa-ai-google-xss) · `2026-07-21`
  > Featuring a calamitous API bug in the Fifa Agent Platform, a one-click vulnerability in github.dev and stored XSS in Next.js, among other recent highlights.
- **Stored XSS in Rocket.Chat HTML File Export — Unauthenticated Entry via LiveChat** · [HackerOne](https://hackerone.com/reports/3779690) · `2026-07-16` · **Medium** · *Rocket.Chat* · ▲96
  > Rocket.Chat's HTML file export feature ( rooms.export API, type=file , format=html ) writes message content and metadata directly into HTML output without any sanitization or entity encoding. An attacker — including an unauthentic
- **Episode 183: PortSwigger Research Impossible XSS SOLVED** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2026-07-16`
  > Episode 183: In this episode of Critical Thinking - Bug Bounty Podcast Justin and Brandyn talk about looking at AI features like tech features, Using AI to leak private repos, and solving PortSwigger’s Unexploitable XSS labs Follo
- **Stored XSS on Trix Editor version latest (2.1.16) - Sanitizer Bypass** · [HackerOne](https://hackerone.com/reports/3581911) · `2026-07-14` · **Low** · $337 · *Basecamp* · ▲88
  > Any application that utilizes Trix to accept untrusted rich text input and renders the serialized output to other users is vulnerable to Stored Cross-Site Scripting (XSS). An attacker can successfully leverage this to steal sessio
- **[Duplicate] Reflected XSS in Import Map Overrides Enables Account Takeover** · [LogicalBreach](https://academy.logicalbreach.com/writeups/reflected-xss-in-import-map-overrides-enables-account-takeover-212e75e5) · `2026-07-08`
  > A reflected XSS vulnerability in the import map overrides feature allows attackers to execute arbitrary JavaScript in authenticated user contexts, risking account takeover and credential theft.
- **[Duplicate] DOM XSS in Charting Service's URL Parameter Enables Phishing** · [LogicalBreach](https://academy.logicalbreach.com/writeups/dom-xss-in-charting-service-s-url-parameter-enables-phishing-bd379e36) · `2026-07-08`
  > A DOM-based XSS vulnerability in the widgetScriptUrl parameter of a charting service allows execution of arbitrary JavaScript, enabling phishing attacks to capture user credentials and potentially take over accounts.
- **[Duplicate] Reflected XSS in Chart Widget via connectorUrl Parameter** · [LogicalBreach](https://academy.logicalbreach.com/writeups/reflected-xss-in-chart-widget-via-connectorurl-parameter-ceb5bf74) · `2026-07-08`
  > A reflected XSS vulnerability in the chart widget's connectorUrl parameter allows attackers to execute arbitrary JavaScript, potentially leading to credential phishing attacks on users.
- **Reflected XSS in legacy CGI script /cgi-bin/████████.pl on ████████ via `████████` parameter** · [HackerOne](https://hackerone.com/reports/3830771) · `2026-06-30` · **High** · *Essity* · ▲5
  > The legacy Perl CGI script at https://████████/cgi-bin/████████.pl reflects user-supplied input from the ████████ parameter directly into the HTML response without output encoding. This allows unauthenticated reflected XSS via bot
- **POST-Based XSS Using Octal Escapes** · [LogicalBreach](https://academy.logicalbreach.com/writeups/post-based-xss-using-octal-escapes-51f1aab9) · `2026-06-26`
  > tonysec Bypassing XSS security using octal encoding Introduction During the security assessment of a large insurance company's partner extranet, I identified a reflected Cross-Site Scripting (XSS) vulnerability affecting the authe
- **Reflected XSS via unsanitised refresh parameter in zone invocation tag** · [HackerOne](https://hackerone.com/reports/3780806) · `2026-06-25` · **Medium** · *Revive Adserver* · ▲29 · CVE-2026-50740
- **Stored XSS in maintenance tools via unescaped entity names** · [HackerOne](https://hackerone.com/reports/3781311) · `2026-06-25` · **Medium** · *Revive Adserver* · ▲25 · CVE-2026-50742
- **Reflected XSS in stats‑video.php via improperly encoded URL parameters** · [HackerOne](https://hackerone.com/reports/3793243) · `2026-06-25` · **Medium** · *Revive Adserver* · ▲12 · CVE-2026-50745
- **Unauthenticated reflected XSS in Essity "Network Toolbox" CGI (████████ ████████** · [HackerOne](https://hackerone.com/reports/3793533) · `2026-06-23` · **High** · *Essity* · ▲7
  > Legacy Perl "Network Toolbox" CGI at ████████ reflects packet size into the HTML response without output encoding. When packet size is non-integer, the script echoes the raw value inside an <h3 error element, allowing arbitrary HT
- **Reflected XSS in AI Chat Bot Greetings at help.shopify.com via Markdown Image Rendering** · [HackerOne](https://hackerone.com/reports/2509022) · `2026-06-18` · **Medium** · $1,600 · *Shopify* · ▲107
  > I was able to leverage a potential CSRF at help.shopify.com which can lead to RXSS via the AI assistant chat greetings by abusing the way markdown images are rendered in the chat. The AI bot at help.shopify.com has the ability to 
- **Reflected Cross-Site Scripting (XSS) found on IBM.com domain** · [HackerOne](https://hackerone.com/reports/3664261) · `2026-06-15` · *IBM* · ▲29
- **Reflected XSS via clientid parameter in zone‑include.php** · [HackerOne](https://hackerone.com/reports/3653316) · `2026-06-03` · **Medium** · *Revive Adserver* · ▲26 · CVE-2026-34915
- **Stored XSS via Full Name field in userlog email entries** · [HackerOne](https://hackerone.com/reports/3669623) · `2026-06-03` · **Medium** · *Revive Adserver* · ▲21 · CVE-2026-44956
- **Stored XSS via malicious usernames in audit log details + Username validation bypass in XML‑RPC addUser** · [HackerOne](https://hackerone.com/reports/3680090) · `2026-06-03` · *Revive Adserver* · ▲9 · CVE-2026-44960/CVE-2026-44961
- **Stored XSS in public-share preview silently exposes the victim's entire drive** · [LogicalBreach](https://academy.logicalbreach.com/writeups/stored-xss-in-public-share-preview-silently-exposes-the-victim-s-entire-drive-e63671bc) · `2026-06-01`
  > Stored XSS on a cloud-drive public-share preview endpoint that serves user-uploaded HTML as text/html on the main application origin with a permissive CSP. A single click on the share link executes attacker JavaScript with same-or
- **DOM-XSS on Central SSO Origin via Unvalidated `retryUrl` (WAF Bypass with `javascript:name`)** · [LogicalBreach](https://academy.logicalbreach.com/writeups/dom-xss-on-central-sso-origin-via-unvalidated-retryurl-waf-bypass-with-javascript-name-ac701cac) · `2026-05-30`
  > Collab with Tonysec https://academy.logicalbreach.com/authors/tonysec
- **Episode 171: Path-Scoped Cookie Hacks with Uppercase & Post-based Raw Protobuf XSS** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2026-04-23`
  > Episode 171: In this episode of Critical Thinking - Bug Bounty Podcast Justin gives us some quick tips from his own hacking, including some clickjacking, using capital letters, and the potential value of leaking ages Follow us on 
- **Escalating a Reflected XSS to High Severity via Filter Bypass and Cache-Assisted Delivery** · [LogicalBreach](https://academy.logicalbreach.com/writeups/escalating-a-reflected-xss-to-high-severity-via-filter-bypass-and-cache-assisted-delivery-f3fc7324) · `2026-04-22`
  > Generic XSS caused by improper handling of user-controlled input in the URL path
- **Escalating Reflected XSS to High Severity via WAF Bypass + Credential Phishing** · [LogicalBreach](https://academy.logicalbreach.com/writeups/escalating-reflected-xss-to-high-severity-via-waf-bypass-credential-phishing-ffd8112d) · `2026-04-22`
  > A Reflected XSS vulnerability was identified in a navigation/routing endpoint of a financial institution's web application. The callback GET parameter is reflected unsanitized into a JavaScript context on the client side, allowing
- **Stored XSS in attachment-display exploitable through SameSite** · [HackerOne](https://hackerone.com/reports/3594137) · `2026-04-19` · **Medium** · *Nextcloud* · ▲39
  > The compose attachments preview endpoint renders user-uploaded HTML files inline without a restrictive Content Security Policy, allowing JavaScript execution. By uploading an HTML file and opening it via display-attachment, the sc
- **DOM XSS to High Severity via Credential Phishing Overlay** · [LogicalBreach](https://academy.logicalbreach.com/writeups/dom-xss-to-high-severity-via-credential-phishing-overlay-df9c3034) · `2026-04-19`
  > A DOM-based XSS vulnerability was discovered affecting multiple endpoints within a financial institution's web application. The target_route parameter was being processed client-side without proper validation or sanitization. This
- **Residual Malicious Payloads on HackerOne after Vulnerability Fixes** · [HackerOne](https://hackerone.com/reports/3168691) · `2026-04-16` · **Medium** · *HackerOne* · ▲71
  > Attackers are able to construct their own payloads, as long these are below 25 characters. These can be used for payload delivery, redirect, xss or abuse of other vulnerabilities/gadgets at the social platfoms.
- **DOM XSS in `fizzy.do` import filename preview enables one-click victim account takeover** · [HackerOne](https://hackerone.com/reports/3608199) · `2026-04-14` · **High** · *Basecamp* · ▲81
  > Summary: While auditing the latest Fizzy code and validating it end to end in a live Docker deployment of current main , I found that the account import page renders the selected local filename with innerHTML instead of textConten
- **[Duplicate] Reflected XSS to Account Takeover (Credential Hijacking)** · [LogicalBreach](https://academy.logicalbreach.com/writeups/duplicate-reflected-xss-to-account-takeover-credential-hijacking-6df42df2) · `2026-04-11`
  > A critical Reflected Cross-Site Scripting (XSS) vulnerability was discovered in a captive WiFi portal, allowing an unauthenticated attacker to steal the credentials of any user connecting via a malicious URL.
- **HTML Injection via Email Address Payloads** · [LogicalBreach](https://academy.logicalbreach.com/writeups/html-injection-via-email-address-payloads-3b0e2d6e) · `2026-03-24`
  > How a simple payload and a shift in mindset exposed a vulnerability hidden in a complex invite and notification system.
- **XSS Bypass to Zero Click Account Takeover in AI Chatbot** · [LogicalBreach](https://academy.logicalbreach.com/writeups/xss-bypass-to-zero-click-account-takeover-in-ai-chatbot-265f0dff) · `2026-03-17`
  > Poor HTML sanitization combined with a file upload feature led to a stored XSS that allowed administrator accounts to be compromised.
- **HTML Injection to DoS (P2)** · [LogicalBreach](https://academy.logicalbreach.com/writeups/html-injection-to-dos-p2-40869d85) · `2026-03-14`
  > HTML Injection is a web security vulnerability that occurs when an application fails to properly sanitize or validate user-supplied input before rendering it in a web page. As a result, an attacker can insert arbitrary HTML code i
- **En cve 2025 24752 reflected xss in popup selector parameter of essential addons for elementor 6 0 14 406dd8ba 7004 4f61 89f2 419b67812259** · [LogicalBreach](https://academy.logicalbreach.com/writeups/en-cve-2025-24752-reflected-xss-in-popup-selector-parameter-of-essential-addons-for-elementor-6-0-14-406dd8ba-7004-4f61-89f2-419b67812259) · `2026-03-06`
- **Stored XSS via SVG Upload Horizontal Tab Character Filter Evasion** · [LogicalBreach](https://academy.logicalbreach.com/writeups/stored-xss-via-svg-upload-horizontal-tab-character-filter-evasion-47555d37-871d-4e40-88bd-a12819f158cc) · `2026-03-02`
  > Stored Cross-Site Scripting via SVG File Upload Filter Bypass
- **AI Playground XSS to steal user-chat messages and access to connected MCP Server** · [HackerOne](https://hackerone.com/reports/3424998) · `2026-02-26` · **Low** · *Cloudflare Public Bug Bounty* · ▲61
- **HTML Injection in DAST Trial Request Form Confirmation Email – PortSwigger** · [HackerOne](https://hackerone.com/reports/3556892) · `2026-02-26` · **Low** · $200 · *PortSwigger Web Security* · ▲93
  > The DAST trial request form at https://portswigger.net/burp/dast/trial is vulnerable to HTML injection through the "First Name" field. User-supplied input is not properly sanitized before being inserted into confirmation emails, a
- **XSS Vulnerability on Pressable/Atomic Hosting Platform via unescaped admin notices leads to code execution** · [HackerOne](https://hackerone.com/reports/3447021) · `2026-02-18` · *Automattic* · ▲76
  > XSS Vulnerability: Unescaped text output in admin notice on atomic-platform.php Platform(s) Affected: Pressable / Atomic Hosting Platform Steps To Reproduce: 1. Update or set the atomic single option limiter notices option on a si
- **Mail stored HTML injection in subject text** · [HackerOne](https://hackerone.com/reports/3357036) · `2026-02-12` · **Medium** · *Nextcloud* · ▲48 · CVE-2025-66514
- **[revive-adserver] Reflected XSS in Banner Delivery Options via cap parameter** · [HackerOne](https://hackerone.com/reports/3473696) · `2026-01-14` · **Medium** · *Revive Adserver* · ▲37 · CVE-2026-21663
- **Reflected XSS in banner-acl.php and channel-acl.php via executionorder** · [HackerOne](https://hackerone.com/reports/3470970) · `2026-01-14` · **Medium** · *Revive Adserver* · ▲39 · CVE-2026-21642
- **Reflected XSS in afr.php** · [HackerOne](https://hackerone.com/reports/3468169) · `2026-01-14` · **Medium** · *Revive Adserver* · ▲36 · CVE-2026-21664
- **Reflected XSS via user Parameter in /ssl-vpn/getconfig.esp** · [HackerOne](https://hackerone.com/reports/3205104) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲8
  > - Allows JavaScript injection in the victim’s browser. - Can be used for phishing, session hijacking, or impersonating the secure VPN login interface. - Exploitable via social engineering (malicious links in emails or messages). -
- **Reflected XSS via user Parameter on getconfig.esp Endpoint** · [HackerOne](https://hackerone.com/reports/3204997) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲9
  > - An attacker can craft a malicious URL and trick victims (e.g., via phishing emails or malicious links) into visiting the site, leading to: - Theft of session tokens (if stored in cookies). - Execution of arbitrary actions in the
- **XSS on ███** · [HackerOne](https://hackerone.com/reports/3053220) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲12
  > A reflected Cross-Site Scripting (XSS) vulnerability exists on the ████ search Steps 1. Visit: █████████ 2. Enter this in the search: [code]or simply visit: ████████ 3. XSS is Executed! Impact An attacker can potentially: - Steal 
- **Cross-Site Scripting via 'currentImage' parameter** · [HackerOne](https://hackerone.com/reports/3136746) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲8
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) ███ Affected Product(s) and Version(s) 
- **Cross-Site Scripting via URL on ████████** · [HackerOne](https://hackerone.com/reports/3437836) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲12
  > I discovered a Cross-Site Scripting (XSS) vulnerability on ████████ , specifically through the GET method. This vulnerability allows an attacker to inject malicious scripts that could be executed, potentially leading to cookie the
- **Cross-Site Scripting via 'wikitext' parameter** · [HackerOne](https://hackerone.com/reports/3137212) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲9
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) █████████ Affected Product(s) and Versi
- **Cross-Site Scripting (XSS) in ASP.NET via ResolveUrl on ███████** · [HackerOne](https://hackerone.com/reports/3166582) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲7
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) ██████ Affected Product(s) and Version(
- **Cross-Site Scripting (XSS) in ASP.NET via ResolveUrl on ███████** · [HackerOne](https://hackerone.com/reports/3166581) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲8
  > Hi, team! A Cross-Site Scripting (XSS) vulnerability was identified in an ASP.NET web application on the ██████████ . The issue arises from improper handling of URLs passed to the ResolveUrl method, which fails to sanitize user-co
- **Cross-Site Scripting (XSS) in ASP.NET via ResolveUrl on ██████████** · [HackerOne](https://hackerone.com/reports/3166587) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲6
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) █████████ Affected Product(s) and Versi
- **Cross-Site Scripting via URL on ███████** · [HackerOne](https://hackerone.com/reports/3354494) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲7
  > I discovered a Cross-Site Scripting (XSS) vulnerability on ███ , specifically through the GET method. This vulnerability allows an attacker to inject malicious scripts that could be executed, potentially leading to cookie theft, s
- **Cross-Site Scripting via URL on ███████** · [HackerOne](https://hackerone.com/reports/3351408) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲8
  > Hi, team! I discovered a Cross-Site Scripting (XSS) vulnerability on ████████, specifically through the GET method via URL. This vulnerability allows an attacker to inject malicious scripts that could be executed, potentially lead
- **Cross-Site Scripting via 'RAISED_FUNDS_DESC' parameter** · [HackerOne](https://hackerone.com/reports/3284389) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲9
  > I discovered a Cross-Site Scripting (XSS) vulnerability on ████ , specifically through the POST method. This vulnerability allows an attacker to inject malicious scripts that could be executed, potentially leading to cookie theft,
- **Cross-Site Scripting via 'autoPlay' parameter** · [HackerOne](https://hackerone.com/reports/3136754) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲10
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) █████ Affected Product(s) and Version(s
- **Reflected XSS in `Telerik.ReportViewer.axd` with F5 BIG-IP ASM Bypass on `████`** · [HackerOne](https://hackerone.com/reports/3135626) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲5
  > Exploitation of this vulnerability could allow an attacker to: - Steal session tokens or cookies - Perform targeted phishing by injecting malicious scripts - Hijack authenticated user workflows - Undermine trust in the staging env
- **Cross-Site Scripting via 'description_extra' parameter** · [HackerOne](https://hackerone.com/reports/3137206) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲9
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) edmaps.usna.edu Affected Product(s) and
- **Cross-Site Scripting (XSS) in ASP.NET via ResolveUrl on ████** · [HackerOne](https://hackerone.com/reports/3166579) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲8
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) ██████████ Affected Product(s) and Vers
- **Cross-Site Scripting (XSS) in ASP.NET via ResolveUrl on ██████** · [HackerOne](https://hackerone.com/reports/3166585) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲9
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) ████ Affected Product(s) and Version(s)
- **Cross-Site Scripting via 'EVENT_DESCRIPTION' parameter** · [HackerOne](https://hackerone.com/reports/3284381) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲6
  > I discovered a Cross-Site Scripting (XSS) vulnerability on █████ , specifically through the POST method. This vulnerability allows an attacker to inject malicious scripts that could be executed, potentially leading to cookie theft
- **Cross-Site Scripting via 'return_link_url' parameter** · [HackerOne](https://hackerone.com/reports/3137200) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲6
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) ████ Affected Product(s) and Version(s)
- **POST XSS - data[type] parameter** · [HackerOne](https://hackerone.com/reports/3127154) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲5
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) ███████ Affected Product(s) and Version
- **POST XSS - data[account][id] parameter** · [HackerOne](https://hackerone.com/reports/3127147) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲6
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) ██████ Affected Product(s) and Version(
- **POST XSS - fields[account][firstname] parameter** · [HackerOne](https://hackerone.com/reports/3127158) · `2026-01-12` · **Medium** · *U.S. Dept Of Defense* · ▲6
  > Exploitation of this vulnerability can lead to severe consequences, including but not limited: Session Hijacking: Attackers can steal cookies and impersonate legitimate users. System Host(s) ████ Affected Product(s) and Version(s)
- **Stored XSS via SVG Upload in chat.line.biz** · [HackerOne](https://hackerone.com/reports/3008878) · `2026-01-05` · **Low** · $100 · *LY Corporation* · ▲40
- **Stored XSS in contacts app via organisation and title field** · [HackerOne](https://hackerone.com/reports/3293290) · `2026-01-04` · **Low** · $100 · *Nextcloud* · ▲15 · CVE-2025-66554
- **RXSS in https://jp.mcafee.com/apps/mdm/jp/3.0_asp/** · [HackerOne](https://hackerone.com/reports/1068477) · `2025-12-19` · **Medium** · *Trellix* · ▲54
  > Hello! I found another subdomain with XSS, let me show you the steps to reproduce it... Website reports - browsers verified In: Chrome 87/ Firefox Steps to reproduce: 1. Write the following URL: https://jp.mcafee.com/apps/mdm/jp/3
- **Second-Order XSS via javascript protocol in MCP Server Portal Apps leads to ATO** · [HackerOne](https://hackerone.com/reports/3316910) · `2025-12-16` · **Low** · *Cloudflare Public Bug Bounty* · ▲50
- **Stored XSS Vulnerability via SVG File** · [HackerOne](https://hackerone.com/reports/3357808) · `2025-12-05` · **Medium** · $150 · *Nextcloud* · ▲79 · CVE-2025-66512
- **runs javascript on powershell when it shouldnt** · [HackerOne](https://hackerone.com/reports/3442024) · `2025-11-26` · *curl* · ▲12
  > Summary: 1. run javascript on powershell curl. 2. It also hangs the process, I wasn't able to control+c to stop the curl process while the alert window was open, so it could potentially be used to hang powershell scripts.
- **Stored-XSS in Banner Name field** · [HackerOne](https://hackerone.com/reports/3404968) · `2025-11-19` · **Low** · *Revive Adserver* · ▲21 · CVE-2025-55123
  > A stored Cross-Site Scripting (XSS) vulnerability exists in the Banner → Name field. An attacker can create or edit a banner with a malicious payload in the Name field; that payload is stored and later executed in the browser of u
- **Reflected XSS in /admin/banner-zone.php (v6.0.0+)** · [HackerOne](https://hackerone.com/reports/3403727) · `2025-11-19` · **Medium** · *Revive Adserver* · ▲18 · CVE-2025-55124
  > A Reflected Cross-Site Scripting (Reflected XSS) vulnerability. User-supplied input from the banner search fields ("Website") is reflected into the page without proper context-aware encoding Step: 1. When I create Banners, I click
- **Stored-XSS in campaign name displayed in Banners modal** · [HackerOne](https://hackerone.com/reports/3411750) · `2025-11-19` · **Medium** · *Revive Adserver* · ▲32 · CVE-2025-55126
  > A low-privilege authenticated user can create or edit advertiser/campaign names containing HTML/JavaScript. Those values are stored in the application and later rendered without proper HTML escaping in the admin Inventory → Banner
- **Stored XSS on inventory-retrieve.php** · [HackerOne](https://hackerone.com/reports/3399809) · `2025-11-19` · **Low** · *Revive Adserver* · ▲17 · CVE-2025-52667
  > Cross-site Scripting (XSS) - Stored on inventory-retrieve.php and campaign-edit.php
- **Stored XSS in Conversion Statistics via Tracker Name** · [HackerOne](https://hackerone.com/reports/3400506) · `2025-11-19` · **High** · *Revive Adserver* · ▲28 · CVE-2025-52668
  > An advertiser (or compromised advertiser account) can inject persistent XSS that executes when admins view conversion statistics. I successfully captured admin session cookies, which enable full account takeover. The attacker can 
- **Reflected XSS in account-preferences-plugin.php** · [HackerOne](https://hackerone.com/reports/3399191) · `2025-11-19` · **Medium** · *Revive Adserver* · ▲21 · CVE-2025-48987
  > An attacker can inject script that executes in the victim’s browser context. This can be used for typical XSS abuse (UI redress, persistence of phishing content, session manipulation). Note: I only tested non-destructive PoCs and 
- **Reflected Cross-Site Scripting (XSS) in Revive Adserver 5.5.2** · [HackerOne](https://hackerone.com/reports/3091390) · `2025-10-22` · **Medium** · *Revive Adserver* · ▲49 · CVE-2025-27208
  > The impact of this vulnerability is significant as it allows an attacker to: Steal sensitive information such as session cookies. Perform actions on behalf of the victim. Redirect the victim to malicious websites. Deface the appli
- **`use-mcp`'s oauth2 process uses a window.open call with untrusted mcp server provided data allowing for code execution under the page using it** · [HackerOne](https://hackerone.com/reports/3211031) · `2025-09-30` · **Medium** · $550 · *Cloudflare Public Bug Bounty* · ▲75
- **Stored XSS via LINK Name.** · [HackerOne](https://hackerone.com/reports/1392262) · `2025-09-23` · **High** · *Insightly* · ▲106
  > Hi Team, The LINK NAME is not properly escaped at the Templates page leading to Stored XSS and the name is reflected in the <script tag , due to lack of sanitization the user can break out of the <script tag and execute the XSS. S
- **Stored XSS in Email Notifcation** · [HackerOne](https://hackerone.com/reports/1597271) · `2025-09-19` · **Medium** · *Insightly* · ▲101
  > Hi team user input most be Decoded this is wired Stored XSS as the XSS been fired in https://crm.na1.insightly.com/list/Email/ when ever user open the ==Notifcation == message been send or even refresh his mail service as the site
- **DOM XSS on www.omnipod.com/freedom/birthdate-confirmation and www.omnipod.com/pif/thanks-freedom** · [HackerOne](https://hackerone.com/reports/1073725) · `2025-09-13` · **Medium** · *Insulet Corporation* · ▲61
  > DOM based XSS was found on multiple pages (and may exist on still more pages) Steps To Reproduce: 1. Navigate to the following URL: https://www.omnipod.com/freedom/birthdate-confirmation?sid=a1t2J000005vUzlQAE& 'onload='alert(docu
- **Stored XSS on TikTok's backend leads to the leakage of highly sensitive administrator data (Cookies, API Keys, Internal Paths, Emails, phone numbers).** · [HackerOne](https://hackerone.com/reports/3037447) · `2025-09-11` · **Medium** · *TikTok* · ▲102
- **RXSS on stores on *█████████/visitorRegistration.pml via destination parameter** · [HackerOne](https://hackerone.com/reports/2189797) · `2025-09-02` · **Medium** · *Mars* · ▲40
- **Stored XSS in AREA tutorials** · [HackerOne](https://hackerone.com/reports/3008066) · `2025-08-25` · **High** · *Autodesk* · ▲73
- **RXSS on ██████ via customerId parameter** · [HackerOne](https://hackerone.com/reports/3126603) · `2025-07-28` · **Medium** · *Mars* · ▲71
- **XSS on Amazon Aquisition: elemental** · [HackerOne](https://hackerone.com/reports/3205667) · `2025-07-22` · **High** · *AWS VDP* · ▲83
- **Reflected XSS in "Cost Tracker" Notes Field** · [HackerOne](https://hackerone.com/reports/3185205) · `2025-07-17` · **Low** · $50 · *MainWP* · ▲92
  > The presence of such a vulnerability indicates that user input is not properly sanitized or encoded before being reflected back into the HTML response. While not directly exploitable by other users, this flaw can have the followin
- **Reflected XSS in "Manage Tags" Notes Field** · [HackerOne](https://hackerone.com/reports/3181803) · `2025-07-17` · **Low** · $50 · *MainWP* · ▲72
  > The presence of such a vulnerability indicates that user input is not properly sanitized or encoded before being reflected back into the HTML response. While not directly exploitable by other users, this flaw can have the followin
- **Reflected XSS in "Create Category" Functionality of Post Creation Module** · [HackerOne](https://hackerone.com/reports/3179138) · `2025-07-17` · **Low** · $50 · *MainWP* · ▲65
  > The presence of such a vulnerability indicates that user input is not properly sanitized or encoded before being reflected back into the HTML response. While not directly exploitable by other users, this flaw can have the followin
- **Stored Cross-Site Scripting (XSS) in "Add Contact" Name Field – MainWP Plugin** · [HackerOne](https://hackerone.com/reports/3176981) · `2025-07-17` · $50 · *MainWP* · ▲56
  > This vulnerability allows an attacker to execute arbitrary JavaScript in the browser of any user who views the affected page, leading to full control of the user’s session and actions. An attacker can exploit this to: - Steal admi
- **Reflected XSS in "Client Notes" Field** · [HackerOne](https://hackerone.com/reports/3181802) · `2025-07-13` · **Low** · $50 · *MainWP* · ▲66
  > The presence of such a vulnerability indicates that user input is not properly sanitized or encoded before being reflected back into the HTML response. While not directly exploitable by other users, this flaw can have the followin
- **Chunked-body parsing flaws, making self-XSS great again – ethical hacker news roundup** · [YesWeHack](https://yeswehack.com/news/chunked-parsing-self-xss-http) · `2025-07-09`
  > Featuring exploitation of “lax” parsing logic due to HTTP/1.1 implementations plus turning stored self-XSS into regular stored XSS using credential-less frames.
- **RXSS AT https://proze.yelp.com/tmsubscribe.net/vidsn.aspx** · [HackerOne](https://hackerone.com/reports/2947762) · `2025-06-30` · **Medium** · *Yelp* · ▲56
- **Mutation Based Stored XSS on Trix Editor version latest (2.1.8)** · [HackerOne](https://hackerone.com/reports/2819573) · `2025-06-27` · **Critical** · *Basecamp* · ▲87
  > An attacker could exploit these vulnerabilities to execute arbitrary JavaScript code within the context of the user's session, potentially leading to unauthorized actions being performed or sensitive information being disclosed.
- **[XSS] Reflected XSS via POST request in (███████)** · [HackerOne](https://hackerone.com/reports/3146996) · `2025-06-12` · **Medium** · *Mars* · ▲54
- **HTML Injection in LinkedIn Premium Support Chat** · [HackerOne](https://hackerone.com/reports/3079966) · `2025-05-07` · **Low** · *LinkedIn* · ▲102
  > 🔸 1. Phishing Attacks Against LinkedIn Employees By injecting a crafted HTML link (e.g., <a href="https://malicious-site.com" CLICK HERE</a ), the attacker can: - Trick LinkedIn support staff into visiting malicious websites - Lea
- **Stored XSS in File Upload Leads to Privilege Escalation and Full Workspace Takeover** · [HackerOne](https://hackerone.com/reports/3115705) · `2025-05-02` · **High** · *Dust* · ▲118
  > A stored cross-site scripting (XSS) vulnerability was discovered in the Dust platform’s file upload functionality. An attacker can upload a malicious HTML file to a conversation. When another user, including an admin, visits the u
- **Reflected XSS Vulnerability in SVG File at area-resources-stg.autodesk.com** · [HackerOne](https://hackerone.com/reports/3045455) · `2025-04-17` · **Medium** · *Autodesk* · ▲93
- **Reflected XSS In Marketing Reports Page On *.myshopify.com/admin** · [HackerOne](https://hackerone.com/reports/1754843) · `2025-04-15` · **Medium** · *Shopify* · ▲128
- **1-Click Cross-Site Scripting via Custom Configuration in SafeListSanitizer** · [HackerOne](https://hackerone.com/reports/3008446) · `2025-04-09` · **Medium** · *Ruby on Rails* · ▲70
- **Stored Cross-Site Scripting found in custom integration app on https://admin.b360.autodesk.com.** · [HackerOne](https://hackerone.com/reports/2971572) · `2025-03-14` · **Medium** · *Autodesk* · ▲127
- **Stored Cross-Site Scripting in mercadopago.com.ar** · [HackerOne](https://hackerone.com/reports/1955485) · `2025-03-13` · **High** · *MercadoLibre* · ▲109
- **CSRF to Reflected XSS at echo.urbandictionary.biz via spoofing content type** · [HackerOne](https://hackerone.com/reports/1237321) · `2025-03-11` · **Medium** · *Urban Dictionary* · ▲86
  > The host is vulnerable to XSS due to the fact that it does reflect any sent POST request body when the request sent to any existed/non-existed filename with .html extension which spoof the response content type to HTML. Proof of C
- **Stored XSS via Post Tittle Enabling Non-Privileged User to Privileged User Exploitation on https://forums.autodesk.com/** · [HackerOne](https://hackerone.com/reports/2974307) · `2025-02-26` · **High** · *Autodesk* · ▲139
- **Episode 111: How to Bypass DOMPurify in Bug Bounty with Kevin Mizu** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-02-20`
  > Episode 111: In this episode of Critical Thinking - Bug Bounty Podcast Justin interviews Kevin Mizu to showcase his knowledge regarding DOMPurify and its misconfigurations. We walk through some of Kevin’s research, highlighting th
- **XSS on using the legacy "Graphie To Png" API** · [HackerOne](https://hackerone.com/reports/2846011) · `2025-02-06` · **Critical** · *Khan Academy* · ▲86
  > XSS on pages that use graphies, potentially leading to account takeovers.
- **ActionView sanitize helper bypass with 'style' and 'svg' tags** · [HackerOne](https://hackerone.com/reports/2931688) · `2025-02-06` · **Medium** · *Internet Bug Bounty* · ▲25
  > Sanitizer bypass that leads to XSS on applications built with it. It also affects applications using Rails Action View's sanitize helper: https://api.rubyonrails.org/v7.2/classes/ActionView/Helpers/SanitizeHelper.html
- **ActionView sanitize helper bypass with noscript** · [HackerOne](https://hackerone.com/reports/2931691) · `2025-02-06` · **Medium** · *Internet Bug Bounty* · ▲22
  > Sanitizer bypass that leads to XSS on applications built with it. It also affects applications using Rails Action View's sanitize helper: https://api.rubyonrails.org/v7.2/classes/ActionView/Helpers/SanitizeHelper.html
- **ActionView sanitize helper bypass with style and math** · [HackerOne](https://hackerone.com/reports/2931636) · `2025-02-06` · **Medium** · *Internet Bug Bounty* · ▲20
  > Sanitizer bypass that leads to XSS on applications built with it. It also affects applications using Rails Action View's sanitize helper: https://api.rubyonrails.org/v7.2/classes/ActionView/Helpers/SanitizeHelper.html
- **ActionView sanitize helper bypass with style** · [HackerOne](https://hackerone.com/reports/2931639) · `2025-02-06` · **Medium** · *Internet Bug Bounty* · ▲19
  > Sanitizer bypass that leads to XSS on applications built with it. It also affects applications using Rails Action View's sanitize helper: https://api.rubyonrails.org/v7.2/classes/ActionView/Helpers/SanitizeHelper.html
- **#2931639 ActionView sanitize helper bypass with math-related tags** · [HackerOne](https://hackerone.com/reports/2931710) · `2025-02-06` · **Medium** · *Internet Bug Bounty* · ▲22
  > Sanitizer bypass that leads to XSS on applications built with it. It also affects applications using Rails Action View's sanitize helper: https://api.rubyonrails.org/v7.2/classes/ActionView/Helpers/SanitizeHelper.html
- **Action Text XSS (Rails 7.1.x)** · [HackerOne](https://hackerone.com/reports/2389565) · `2025-02-04` · **Medium** · *Ruby on Rails* · ▲33
  > If multiple users have access to the same edit page, an XSS-based attack is possible between users. This vulnerability is probably due to https://github.com/rails/rails/pull/45739 PR and was not reproduced in Rails 7.0.
- **XSS vulnerability found in javascript code of https://███.mil** · [HackerOne](https://hackerone.com/reports/2888784) · `2025-01-24` · **Medium** · *U.S. Dept Of Defense* · ▲42
  > Hello DoD Team I found an XSS vulnerability in the javascript code of ██████████.mil. The parameter code isn't sanitized enough to prevent an attack. If you click the following link: https://███.mil/?code=xxx';%0d%0a!!!MALICIOUS%2
- **XSS found in https://www.████████.mil** · [HackerOne](https://hackerone.com/reports/2853410) · `2025-01-24` · **Medium** · *U.S. Dept Of Defense* · ▲39
  > Reflected XSS allows attackers to inject malicious scripts into a web application, which execute in the user's browser when triggered (e.g., via a malicious link). This can lead to theft of sensitive data like cookies, session tok
- **Stored XSS via SMTP Error Message** · [HackerOne](https://hackerone.com/reports/2956266) · `2025-01-24` · **Low** · $250 · *XVIDEOS* · ▲84
- **POST based Cross-Site Scripting on IBM research endpoint** · [HackerOne](https://hackerone.com/reports/2899380) · `2025-01-23` · **Medium** · *IBM* · ▲44
- **Episode 106: Announcing our new cohost...** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-01-16`
  > Episode 106: In this episode of Critical Thinking - Bug Bounty Podcast we are pleased to announce our new co-host of the podcast: Joseph Thacker Aka Rez0! We discuss Joseph's transition to full-time bug bounty hunting, his goals, 
- **WAF bypass and java script incomplete handling of Unicode characters might leads to dom-xss** · [HackerOne](https://hackerone.com/reports/2921905) · `2025-01-13` · *Doppler* · ▲36
  > attackers can inject malicious code that steals sensitive user information like login credentials, personal details, and financial data.
