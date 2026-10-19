# Open Redirect Chains

*17 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **Open redirect on app.hey.com bypasses HEY desktop's internal-origin allowlist and loads attacker content inside a HEY BrowserWindow** · [HackerOne](https://hackerone.com/reports/3972760) · `2026-10-15` · **Medium** · *Basecamp* · ▲21
  > app.hey.com/proxy image compares the URL scheme case-sensitively. https:// gets signed and proxied correctly. HTTPS:// isn't recognised, so instead of proxying it, the endpoint 302s the visitor to the raw URL. No authentication ne
- **OAuth redirect uri validation bypass for :proxima_first_party_sync apps** · [HackerOne](https://hackerone.com/reports/3588801) · `2026-07-21` · **High** · *GitHub* · ▲78 · CVE-2026-4296
- **1-Click Account Takeover via Open Redirect through Regex Bypass in Domain Validation** · [HackerOne](https://hackerone.com/reports/3723458) · `2026-06-20` · **Critical** · *Khan Academy* · ▲124
  > Hello there, During my security research, I identified a critical vulnerability chain that allows an attacker to achieve full account takeover of any Khan Academy user. The attack exploits an unescaped dot flaw in the KA DOMAIN RE
- **page.line.me Open Redirect Leading to OAuth Authorization Code Exposure and Access Token Compromise** · [HackerOne](https://hackerone.com/reports/3423013) · `2026-06-02` · **High** · $1,000 · *LY Corporation* · ▲43
- **another liberapay member team twitter account broken Link Hijacking via Expired Twitter Account Link** · [HackerOne](https://hackerone.com/reports/3723002) · `2026-05-09` · *Liberapay* · ▲77
  > Describe impact here.An attacker who claims the expired Twitter account could leverage the perceived legitimacy from the Liberapay profile link to conduct social engineering attacks, scam users, impersonate the profile owner, or s
- **Liberapay member team twitter account broken Link Hijacking via Expired Twitter Account Link** · [HackerOne](https://hackerone.com/reports/3721519) · `2026-05-09` · *Liberapay* · ▲65
  > An attacker who claims the expired Twitter account could leverage the perceived legitimacy from the Liberapay profile link to conduct social engineering attacks, scam users, impersonate the profile owner, or spread misinformation.
- **[Duplicate] Open Redirect Flow Abuse via OAuth Validation Bypass** · [LogicalBreach](https://academy.logicalbreach.com/writeups/duplicate-open-redirect-flow-abuse-via-oauth-validation-bypass-32d63048) · `2026-04-11`
  > A Open Redirect vulnerability was identified within an OAuth authorization flow endpoint. The vulnerability occurs because the callback_url (or equivalent redirect parameter) is validated using an insecure string prefix match inst
- **Open Redirect in Rocket.Chat** · [HackerOne](https://hackerone.com/reports/3418031) · `2026-04-10` · **Medium** · *Rocket.Chat* · ▲32 · CVE-2026-22560
- **Open Redirect — Base64-Encoded Parameter Bypasses Client-Side Validation on Login Page** · [LogicalBreach](https://academy.logicalbreach.com/writeups/open-redirect-base64-encoded-parameter-bypasses-client-side-validation-on-login-page-d33fb2e0) · `2026-04-01`
  > A base64-encoded query parameter on a login/terms acceptance page was decoded and used directly in window.location.href with only protocol validation — no domain check. The writeup covers tracing the vulnerable code in the Angular
- **Open Redirect on lovable.dev via redirect parameter leads to phishing attacks** · [HackerOne](https://hackerone.com/reports/3581815) · `2026-03-05` · *Lovable VDP* · ▲44
  > An open redirect exists on lovable.dev. After logging in, a request is sent to 'https://lovable.dev/auth/post-login?redirect=%2F%3Fshould-refresh-credentials%3D1& rsc=1b5jt'. Changing the redirect URL to /\google.com (https://lova
- **tabnabbing in roundcube webmail** · [HackerOne](https://hackerone.com/reports/3367676) · `2025-12-24` · *Nextcloud* · ▲37
  > Impact Due to the redirection being done in the background and most people aren't aware of this type of attack unlike the open redirection, Most people will fall into it and will enter their credentials leading to account takeover
- **Authentication Token Theft via Open Redirect in Callback URL Parameter** · [HackerOne](https://hackerone.com/reports/3419636) · `2025-11-14` · **Critical** · *lemlist* · ▲60
- **REDIRECTION VULNERABILITY/HOST HEADER INJECTION VULNERABILITY** · [HackerOne](https://hackerone.com/reports/300164) · `2025-10-31` · **Medium** · *Hiro* · ▲20
  > Attack vectors are somewhat limited but depends on how the host header is used by the back-end application code. If code references the hostname used in the URL such as password reset pages, an attacker could spoof the host header
- **Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing Attack** · [HackerOne](https://hackerone.com/reports/3099816) · `2025-05-15` · **Low** · *Lichess* · ▲70
  > An open redirect vulnerability exists in the OAuth flow on lichess4545.com. By manipulating the redirect uri parameter during the OAuth authorization process with Lichess, an attacker can redirect users to an arbitrary external do
- **Open Redirect on ███████** · [HackerOne](https://hackerone.com/reports/2265413) · `2025-05-02` · **Low** · *Fastly VDP* · ▲74
  > Open redirect vulnerabilities can have various impacts on both users and organizations. Here are some potential consequences: Phishing Attacks: Attackers can exploit open redirect vulnerabilities to craft convincing phishing attac
- **Open redirect** · [HackerOne](https://hackerone.com/reports/2957962) · `2025-02-06` · *XVIDEOS* · ▲143
  > An open redirect vulnerability was discovered on the website https://www.xnxx.com/todays-selection/1. This issue allows attackers to modify URLs to redirect users to arbitrary external websites, including malicious or phishing sit
- **Open Redirection effects autodiscover.rockstargames.com** · [HackerOne](https://hackerone.com/reports/1269332) · `2025-02-03` · **Low** · *Rockstar Games* · ▲49
