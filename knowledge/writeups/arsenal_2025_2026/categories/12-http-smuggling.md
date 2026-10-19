# HTTP Request Smuggling

*11 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **James Kettle’s ‘autonomous research cascade’, RCE on humanoid robots – hacker news roundup** · [YesWeHack](https://yeswehack.com/news/kettle-ai-innovation-crlf-robots) · `2026-09-15`
  > Can AI invent new attack techniques? James Kettle found out. Also covered: CRLF-powered desync attacks, the CSS bomb in your inbox and getting root on the G1.
- **HTTP Request Smuggling via Unsanitized Hop-by-Hop Headers** · [HackerOne](https://hackerone.com/reports/3622877) · `2026-09-14` · **High** · $1,500 · *Cloudflare Public Bug Bounty* · ▲52
- **CRLF-Powered Desync Attacks: Beheading HTTP Streams** · [PortSwigger Research](https://portswigger.net/research/crlf-powered-desync-attacks) · `2026-08-05`
  > Abstract In this paper we’ll show that HTTP Header Injection is severely underestimated. Forget open redirects or Cross-Site Scripting and instead, embrace the catastrophic potential of the CRLF-Power
- **Unauthenticated SQL Injection via REST Batch Route Confusion ████████** · [HackerOne](https://hackerone.com/reports/3873072) · `2026-07-21` · **Critical** · *Essity* · ▲13
  > The WordPress REST API batch endpoint ( /wp-json/batch/v1 ) on ████████ is vulnerable to an unauthenticated blind SQL injection . By nesting a crafted batch payload, an attacker triggers a route-dispatch desynchronisation that cau
- **HTTP Request Smuggling** · [HackerOne](https://hackerone.com/reports/3589269) · `2026-05-20` · **Critical** · *Essity* · ▲13
  > HTTP Request Smuggling is a vulnerability stemming from HTTP/1.1's core weakness, the boundaries between requests on keep-alive connections. In this case, it was possible to achieve a 0.CL desync. This means that it is possible to
- **Gopher Protocol Command Injection (SSRF Smuggling)** · [HackerOne](https://hackerone.com/reports/3508785) · `2026-01-14` · **High** · *curl* · ▲8
  > The curl Gopher protocol handler is vulnerable to command injection through URL-encoded CRLF sequences in the path. This allows an attacker to "smuggle" additional Gopher selectors or arbitrary commands into a single Gopher reques
- **HTTP Request Smuggling and SSRF via CRLF Injection in Curl_add_custom_headers** · [HackerOne](https://hackerone.com/reports/3484431) · `2026-01-02` · **High** · *curl* · ▲9
  > A lack of CRLF validation in Curl add custom headers at lib/http.c:1761 allows users to inject arbitrary HTTP headers. This violation of RFC 7230 §3.2.4 leads to HTTP Request Smuggling and potential SSRF bypass. AI Disclosure: I u
- **SMTP CRLF Injection & Protocol Desynchronization in libcurl** · [HackerOne](https://hackerone.com/reports/3481595) · `2025-12-29` · **Medium** · *curl* · ▲16
  > - Email Fraud/Spoofing : Forge sender addresses and inject arbitrary headers. - Unauthorized Distribution : Send emails to undisclosed recipients by smuggling RCPT TO commands. - Protocol Smuggling : Use curl-master/lib/urlapi.c 1
- **Nonce CSP bypass using disk cache, Amazon Q self-destruct saga – hacker news roundup** · [YesWeHack](https://yeswehack.com/news/csp-bypass-smuggling-amazon-q) · `2025-08-22`
  > Featuring a Gemini CLI hijack, nonce-based CSP bypasses using the disk cache, and HTTP smuggling exploits based on trust (as opposed to complexity).
- **Beware the false false-positive: how to distinguish HTTP pipelining from request smuggling** · [PortSwigger Research](https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling) · `2025-08-19`
  > Sometimes people think they've found HTTP request smuggling, when they're actually just observing HTTP keep-alive or pipelining. This is usually a false positive, but sometimes there's actually a real
- **HTTP/1.1 must die: the desync endgame** · [PortSwigger Research](https://portswigger.net/research/http1-must-die) · `2025-08-06`
  > Abstract Upstream HTTP/1.1 is inherently insecure and regularly exposes millions of websites to hostile takeover. Six years of attempted mitigations have hidden the issue, but failed to fix it. This p
