# SSRF & Cache Attacks

*38 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **SSRF via User-Controlled Push proxyServer in Notifications Push Registration** · [HackerOne](https://hackerone.com/reports/3623149) · `2026-09-30` · **Medium** · *Nextcloud* · ▲45
  > An authenticated low-privilege user can register a push device with an attacker-controlled proxyServer through POST /ocs/v2.php/apps/notifications/api/v2/push Later, when a notification is triggered for that user, the backend perf
- **SSRF with bypass leads to client side hosting / vulnerabilities ( XSS and others )** · [HackerOne](https://hackerone.com/reports/3522157) · `2026-09-17` · **Medium** · $500 · *DuckDuckGo* · ▲74
  > Hi team, your web app is vulnerable to SSRF. Overview of the Vulnerability Server-side request forgery (SSRF) is a vulnerability that exploits the trust relationship between a server and an application, or other backend systems. A
- **Unauthenticated blind SSRF in Circles signature verification bypasses Nextcloud local-address protections** · [HackerOne](https://hackerone.com/reports/3303283) · `2026-09-17` · **Medium** · *Nextcloud* · ▲14 · CVE-2026-77164
  > - The Circles app exposes public, no-auth endpoints (e.g., POST /index.php/apps/circles/event/). During signature verification, the server fetches the attacker-provided keyId URL before trust is established. Circles configures the
- **How I Tricked OpenClaw Into Attacking Its Own Network: A NAT64 SSRF Bypass** · [Infosec Writeups](https://infosecwriteups.com/how-i-tricked-openclaw-into-attacking-its-own-network-a-nat64-ssrf-bypass-9b93a7f11cd9) · `2026-09-17`
  > A story about how a single misread pair of bytes let a public-looking IPv6 address secretly point at 169.254.169.254. An AI assistant with keys to your whole network OpenClaw (previously known as Clawdbot and Moltbot) runs on your
- **SSRF via URL Parser Differential in `normalize_request_url` (wlc)** · [HackerOne](https://hackerone.com/reports/3887969) · `2026-09-02` · **High** · *Weblate* · ▲42
  > wlc validates that outgoing API requests stay on the configured server's origin by parsing URLs with urllib.parse.urlparse and comparing (scheme, hostname, port) against the known-good origin. The actual HTTP request, however, is 
- **50: CMake `HTTP_ONLY` does not disable SSH backends — SCP and SFTP remain usable** · [HackerOne](https://hackerone.com/reports/3973228) · `2026-08-29` · *curl* · ▲13
  > The CMake HTTP ONLY=ON option is documented as "Disable all protocols except HTTP" ( CMakeLists.txt:538 ), but the implementation ( CMakeLists.txt:541-557 ) only sets CURL DISABLE flags for non-SSH protocols. It does not disable C
- **Unauthenticated SSRF in Voxtelesys integration ('checkUrlForSsrf' Bypass via DNS rebinding)** · [HackerOne](https://hackerone.com/reports/3473145) · `2026-07-29` · **High** · *Rocket.Chat* · ▲28 · CVE-2024-39713
  > This enables an attacker to reach internal network resources that would normally be inaccessible and to perform network scanning. Because an attacker can receive responses from internal hosts, the risk of data leakage is very high
- **AWS *.a2z.com \| Unauthenticated Clickhouse UI : Database access + SSRF** · [HackerOne](https://hackerone.com/reports/3809407) · `2026-07-22` · **High** · *AWS VDP* · ▲53
- **SSRF via Improper Redirect Validation in Rocket.Chat oEmbed Function** · [HackerOne](https://hackerone.com/reports/3383079) · `2026-06-11` · **Medium** · *Rocket.Chat* · ▲25
  > In Rocket.Chat version 7.10.1, the oEmbed feature is enabled by default and automatically generates a preview whenever a valid URL is posted in a chat. If the URL redirects to another site, the feature follows the redirect to the 
- **SSRF via improper validation after DNS name resolution in the link-preview feature** · [HackerOne](https://hackerone.com/reports/3393664) · `2026-06-11` · **High** · *Rocket.Chat* · ▲26
  > In Rocket.Chat version 7.11.0, the link-preview is a feature that displays a preview of a linked page when a link is sent in the chat, and it is enabled by default. On the server side, the hostname of the posted URL is initially c
- **curl-ipv4-percent-normalization-SSRF** · [HackerOne](https://hackerone.com/reports/3791168) · `2026-06-10` · **Medium** · *curl* · ▲13
  > [six or fewer sentences describing the issue in your own human voice and optionally a short proof-of-concept script] Affected version [Which curl/libcurl version are you using to reproduce? On which platform? curl -V typically gen
- **Blind POST SSRF via Web Push Notification Endpoint** · [HackerOne](https://hackerone.com/reports/3608558) · `2026-05-30` · **Medium** · *phpBB* · ▲33
  > A registered user can register an arbitrary URL as their Web Push notification endpoint. phpBB stores this URL without validation and later uses the Minishlink WebPush library to send HTTP POST requests to it. This allows the atta
- **A PortSwigger-lab-style cache poisoning → pre-auth ATO with a single request** · [LogicalBreach](https://academy.logicalbreach.com/writeups/a-portswigger-lab-style-cache-poisoning-pre-auth-ato-with-a-single-request-6dce8f5e) · `2026-05-30`
  > PortSwigger-lab-style cache poisoning via Referer + Akamai WAF bypass → zero-interaction ATO
- **Authorization header leak in ssrf_filter via cross-host redirect leads to credential theft and unauthorized access** · [HackerOne](https://hackerone.com/reports/3642600) · `2026-04-15` · *arkadiyt-projects* · ▲42
  > ssrf filter follows redirects by rebuilding each redirected request from the original request options. When a redirect crosses to a different host, it still reapplies caller-supplied sensitive state such as the Authorization heade
- **Unauthenticated SSRF via Public Reference API -Sharing Token Bypass** · [HackerOne](https://hackerone.com/reports/3479692) · `2026-03-31` · *Nextcloud* · ▲41
- **SSRF Filter Bypass via Unblocked NAT64 Local-Use IPv6 Prefix (64:ff9b:1::/48)** · [HackerOne](https://hackerone.com/reports/3634400) · `2026-03-31` · **High** · *arkadiyt-projects* · ▲65
  > ssrf filter v1.3.0 blocks 64:ff9b::/96 , but doesnt block the NAT64 local-use prefix 64:ff9b:1::/48 , allowing those addresses to be treated as public. This enables SSRF requests through /fetch to internal-equivalent targets encod
- **How Neo found an SSRF vulnerability in Faraday, and why it matters for every team that ships code** · [ProjectDiscovery](https://projectdiscovery.io/blog/how-neo-found-an-ssrf-vulnerability-in-faraday-and-why-it-matters-for-every-team-that-ships-code) · `2026-03-03`
  > Executive Summary Neo found a Server-Side Request Forgery (SSRF) vulnerability in Faraday, a widely used HTTP client library in the Ruby ecosystem. This is Neo’s first credited CVE discovery. Neo is ProjectDiscovery’s AI security 
- **Massive Data Leak via Web Cache Deception** · [LogicalBreach](https://academy.logicalbreach.com/writeups/en-massive-data-leak-via-web-cache-deception-85005932-47d6-4d7b-9a44-39662226a148) · `2026-03-01`
  > This writeup details a critical Web Cache Deception (CWE-524) vulnerability discovered across the core API endpoints of an IoT/Smart Home device management platform.
- **Node.js permission model bypass via unchecked Unix Domain Socket connections (UDS)** · [HackerOne](https://hackerone.com/reports/3465156) · `2026-02-12` · **Medium** · *Node.js* · ▲52 · CVE-2026-21636
- **Episode 160: Cloudflare Zero-days & Mail Unsubscribing for XSS** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2026-02-05`
  > Episode 160: In this episode of Critical Thinking - Bug Bounty Podcast Joseph and Brandyn. Chat through some news, Including a Cloudflare Zero-day, Turning List-Unsubscribe into an SSRF/XSS Gadget, & Magic String Denial of Service
- **[nextcloud/mail] Blind SSRF to Internal Network via "List-Unsubscribe" SMTP Header when allow_local_remote_servers is allowed** · [HackerOne](https://hackerone.com/reports/2902856) · `2025-12-23` · **Medium** · *Nextcloud* · ▲25
- **Link unfurling calls out to arbitrary URLs and the private-network guard misses link-local addresses** · [HackerOne](https://hackerone.com/reports/3445890) · `2025-12-22` · **Medium** · *Basecamp* · ▲62
  > - /unfurl link lets any signed-in user supply a URL that the server fetches for OpenGraph data. - The “private network” guard only blocks RFC1918/loopback/0.0.0.0 and ignores link-local ranges, so 169.254.0.0/16 (IMDS) and fe80::/
- **File URL UNC Path Access (Windows SSRF)** · [HackerOne](https://hackerone.com/reports/3470649) · `2025-12-18` · **High** · *curl* · ▲19
  > 1. SSRF (Server-Side Request Forgery) - Access internal file shares not accessible from internet - Bypass firewall restrictions - Read sensitive files on internal servers 2. Credential Theft - Windows automatically sends NTLM cred
- **[my.stripo.email] Blind SSRF Vulnerability in Stripo App Export via Missing Endpoints Export Email Message to Zapier** · [HackerOne](https://hackerone.com/reports/2932960) · `2025-12-01` · **Critical** · *Stripo Inc* · ▲92
  > Data Exfiltration : - Attackers can leverage SSRF to access sensitive internal network data, such as cloud metadata, internal API endpoints, or other restricted services. port-scan - Missing Endpoints Export Email Message to Zapie
- **Bypass of Cloudflare's Cache Keys and WAF via header overflow** · [HackerOne](https://hackerone.com/reports/3027461) · `2025-11-18` · **High** · *Cloudflare Public Bug Bounty* · ▲76
- **DNS Rebinding Attack** · [HackerOne](https://hackerone.com/reports/3383095) · `2025-10-19` · **Critical** · *arkadiyt-projects* · ▲42
  > The library validates DNS resolution but passes the hostname (not the validated IP) to Net::HTTP, which performs a second DNS lookup. Attacker's DNS server returns different IPs for each query
- **DNS Rebinding SSRF in Burp Suite MCP Server Enables Internal Network Access via send_http1_request Tool** · [HackerOne](https://hackerone.com/reports/3176157) · `2025-10-08` · *PortSwigger Web Security* · ▲144
  > This allows malicious websites to: 1. Connect to the victim's local MCP server (127.0.0.1:9876) 2. Use the send http1 request MCP tool to make arbitrary HTTP requests 3. Access internal networks, localhost services, and cloud meta
- **Unsanitized IPFS CID Allows SSRF Against Configured Gateway** · [HackerOne](https://hackerone.com/reports/3366484) · `2025-10-03` · **Medium** · *curl* · ▲34
  > ipfs url rewrite() (in src/tool ipfs.c ) decodes the host component (CID) of ipfs:// / ipns:// URLs using CURLU URLDECODE and then concatenates that decoded value directly into the gateway path ( aprintf("%s%s/%s%s", ...) ) withou
- **Inconsistent URL Parsing in curl Leading to Potential SSRF and Access Control Bypass** · [HackerOne](https://hackerone.com/reports/2814750) · `2025-09-26` · **Low** · *curl* · ▲22
  > - Server-Side Request Forgery (SSRF) : Attackers can manipulate requests to access internal resources. - Access Control Bypass : Security policies based on network interfaces can be circumvented. - Information Leakage : Potential 
- **Episode 137: How We Do AI-Assisted Whitebox Review, New CSPT Gadgets, and Tools from SLCyber** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-08-28`
  > Episode 137: In this episode of Critical Thinking - Bug Bounty Podcast Justin Gardner and Joseph Thacker reunite to talk about AI Hacking Assistants, CSPT and cache deception, and a bunch of tools like ch.at , Slice, Ebka, and mor
- **Prompt Injection via GitHub Patch in Brave AI Chat (Leo)** · [HackerOne](https://hackerone.com/reports/3086301) · `2025-08-22` · **High** · *Brave Software* · ▲77
  > Prompt Injection / Instruction Hijacking: An attacker can control the AI assistant's behavior within a user's chat session after they navigate to a crafted GitHub URL and interact with the chat. The AI can be made to ignore its sa
- **URL Path Manipulation Enables Cache Poisoning of Amazon Affiliate Products in Shopify Linkpop** · [HackerOne](https://hackerone.com/reports/1848940) · `2025-08-14` · **Low** · $500 · *Shopify* · ▲86
  > The fix in report ████████ seems to prevent correctly an attacker from redirecting the request to another domain which was the main issue, however, there is still a way for that attacker to "poison" the cache usin the Amazon domai
- **Episode 128: New Research in Blind SSRF and Self-XSS, and How to Architect Source-code Review AI Bots** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-06-26`
  > Episode 128: In this episode of Critical Thinking - Bug Bounty Podcast we talking Blind SSRF and Self-XSS, as well as Reversing massive minified JS with AI and a wild Google Logo Ligature Bug Follow us on twitter at: https://x.com
- **DoS Vulnerability via Cache Poisoning on cdn.shopify.com and shopify-assets.shopifycdn.com** · [HackerOne](https://hackerone.com/reports/1695604) · `2025-06-04` · **Medium** · $3,800 · *Shopify* · ▲266
  > There's a web cache poisoning vulnerability on cdn.shopify.com that allows the attacker to block access to any file hosted on the website. This vulnerability exists as the cache server deals with the backslash as a frontslash. How
- **Server-Side Request Forgery (SSRF) via Game Export API** · [HackerOne](https://hackerone.com/reports/3165242) · `2025-06-03` · **Critical** · *Lichess* · ▲115
  > Hello Lichess Team, I found a Server-Side Request Forgery vulnerability in the game export functionality. An attacker can make the Lichess server send HTTP requests to arbitrary URLs by manipulating the players parameter. This wor
- **SSRF in Autodesk Rendering leading to account takeover** · [HackerOne](https://hackerone.com/reports/3024673) · `2025-03-18` · **Critical** · *Autodesk* · ▲161
- **Blind SSRF Vulnerability in Appstore Release Upload Form** · [HackerOne](https://hackerone.com/reports/2925666) · `2025-01-14` · **Low** · *Nextcloud* · ▲43
- **Denial of Access to Static Resources via Cache Poisoning on addons.allizom.org** · [HackerOne](https://hackerone.com/reports/2860983) · `2025-01-08` · **Low** · *Mozilla* · ▲24
  > An attacker can poison the cache and block access to static files (e.g., image, JS) that are delivered with the homepage. Steps To Reproduce: To reproduce cache poisoning for an image file: 1. curl -H "X-HTTP-Method-Override: HEAD
