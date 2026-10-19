# Auth Bypass — MFA / 2FA / OAuth / Clickjacking

*53 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **HackerOne Code: a live password reset token reaches Datadog RUM, and the same session records the account it unlocks** · [HackerOne](https://hackerone.com/reports/4071670) · `2026-10-08` · **Low** · $200 · *HackerOne* · ▲39
  > Opening a password reset link on app.pullrequest.com sends the complete, unused, 64 character reset token to Datadog, before the reset form is submitted. The link carries the token as a bare query string key, and the Datadog RUM b
- **Client-Side Denial of Service (DoS) via Memory Exhaustion on Password Reset Endpoint** · [HackerOne](https://hackerone.com/reports/3987499) · `2026-10-05` · **High** · *Khan Academy* · ▲30
  > 1.Denial of Service for any logged‑in user who visits the link 2.Browser memory exhaustion leading to crash or system suspend 3.No user interaction required beyond visiting the link 4.Can be used in phishing campaigns to disrupt u
- **SAML: A fractal of bad design** · [Trail of Bits](https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design) · `2026-09-21`
  > Born out of academia and raised in corporate IT departments, the Security Assertion Markup Language (SAML) authentication protocol continues to be a staple in these organizations. However, it’s time for it to retire. With the rise
- **Improper OTP Implementation to Full Account Takeover** · [Infosec Writeups](https://infosecwriteups.com/improper-otp-implementation-to-full-account-takeover-df21e126f10f) · `2026-09-08`
  > By Sid — Cybersecurity Engineer & Pentester Photo by Maxim Ilyahov on Unsplash Disclosure note: This was found during an authorized, client-commissioned penetration test. The target platform’s domain, endpoints, employee identitie
- **Adding phone number to profile By OTP brute forcing** · [HackerOne](https://hackerone.com/reports/3265780) · `2026-08-08` · **Medium** · $100 · *CoinMate.io* · ▲113
  > Using this we can add any user phone number to our account , Then that added phone number will received the OTP's and used to login. Note : As i received a mail from you to report this bug again i am reporting this bug again so pl
- **Authentication Bypass via XML Signature Wrapping in SAML SSO** · [HackerOne](https://hackerone.com/reports/3827674) · `2026-07-27` · **Critical** · *Rocket.Chat* · ▲38 · CVE-2026-58066
- **Taskcluster web-server OAuth2 authorization codes are reusable and the exchange handler checks the wrong expiry column** · [HackerOne](https://hackerone.com/reports/3734676) · `2026-06-23` · **Medium** · $2,000 · *Mozilla* · ▲42
  > With a captured authorization code (referer in narrow conditions, redirect-page logs, TLS-inspecting proxy, browser-history access on the redirect page), the attacker can: 1. Replay POST /login/oauth/token to mint a fresh OAuth br
- **Authentication Bypass in ID4me handling via Missing JWT Signature Verification in User OIDC** · [HackerOne](https://hackerone.com/reports/3489490) · `2026-06-07` · **High** · $2,500 · *Nextcloud* · ▲55 · CVE-2026-45156
- **Session ID reuse allowing XML‑RPC API authentication bypass** · [HackerOne](https://hackerone.com/reports/3672641) · `2026-06-03` · **Medium** · *Revive Adserver* · ▲8 · CVE-2026-34917
- **Unauthenticated Account Registration + Email Verification Bypass + PII Data Leak (2,480 Records) on ████████** · [HackerOne](https://hackerone.com/reports/3737516) · `2026-05-27` · **Medium** · *Essity* · ▲14
  > The ████████ portal at ████████ (intended only for authorized Essity employees and partners) has a multi-step vulnerability chain that allows any unauthenticated attacker to: 1. Register an account via the public ████████ API 2. B
- **MFA Bypass via Account Attribute Manipulation** · [LogicalBreach](https://academy.logicalbreach.com/writeups/mfa-bypass-via-account-attribute-manipulation-77cec1bd) · `2026-04-24`
  > A vulnerability was identified where an authenticated user could disable Multi-Factor Authentication (MFA) on their own account by modifying hidden account attributes through a backend API endpoint. This allowed subsequent logins 
- **Episode 169: Attacking OAuth 2.1** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2026-04-09`
  > Episode 169: In this episode of Critical Thinking - Bug Bounty Podcast gr3pme goes over some of the changes from OAuth 2.0 vs 2.1 and how Hackers can capitalize. Follow us on twitter at: https://x.com/ctbbpodcast Got any ideas and
- **2FA Bypass Despite Fix via Manual Injection of isVerifyAuth Cookie in Local Storage** · [LogicalBreach](https://academy.logicalbreach.com/writeups/2fa-bypass-despite-fix-via-manual-injection-of-isverifyauth-cookie-in-local-storage-cad7154e) · `2026-03-17`
  > After an initial 2FA bypass vulnerability was “fixed” by removing the isVerifyAuth cookie from local storage, the application still trusted this value if it existed.
- **Unauthenticated OAuth Token Leading to Access to Protected APIs** · [LogicalBreach](https://academy.logicalbreach.com/writeups/unauthenticated-oauth-token-leading-to-access-to-protected-apis-73c58419-6878-4a66-ba35-74abdf94b67c) · `2026-03-06`
  > What started as a simple JavaScript analysis ended in a broken OAuth flow that allowed unauthenticated access to protected APIs — and a €1500 bug bounty reward.
- **2FA requirement bypass when inviting team members** · [HackerOne](https://hackerone.com/reports/3356149) · `2026-02-28` · **Medium** · *Omise* · ▲105
  > The application requires users to enable 2FA before sending team invitations. However, this restriction can be bypassed by modifying client-side responses (match and replace from false to true). This allows invitations to be sent 
- **No Rate Limiting on Password Attempts After Insecure Registration Flow cause ATO** · [HackerOne](https://hackerone.com/reports/3174778) · `2026-02-24` · **Medium** · *Mars* · ▲28
- **clickjacing can lead to account takeover** · [HackerOne](https://hackerone.com/reports/2119892) · `2026-01-18` · **Low** · $200 · *pixiv* · ▲70
  > Users are tricked into performing all sorts of unintended actions are such as typing in the password, clicking on ‘Delete my account’ button, liking a post, deleting a post, commenting on a blog. In other words all the actions tha
- **The Fragile Lock:&nbsp;Novel Bypasses For SAML Authentication** · [PortSwigger Research](https://portswigger.net/research/the-fragile-lock) · `2025-12-10`
  > TLDR This post shows how to achieve a full authentication bypass in the Ruby and PHP SAML ecosystem by exploiting several parser-level inconsistencies: including attribute pollution, namespace confusi
- **Unauthorized Password Reset Allows Account Takeover Across Tenant Boundaries** · [HackerOne](https://hackerone.com/reports/3378635) · `2025-11-07` · **High** · *lemlist* · ▲65
- **2FA bypass possible on https://authsvc.singlestore.com** · [HackerOne](https://hackerone.com/reports/3329361) · `2025-10-22` · **Medium** · *SingleStore* · ▲94
  > To exploit this vulnerability and break into the victim's account, the attacker only needs to know the email address and password of the victim's account. The 2FA authentication mechanism can be bypassed completely. Steps To Repro
- **Email not verified when changing afterwards on apps.nextcloud.com** · [HackerOne](https://hackerone.com/reports/2305880) · `2025-09-29` · **Low** · *Nextcloud* · ▲42
  > Email Verification Bypass is a dangerous vulnerability, which is found in Web-Applications. An Attackers can bypass the control mechanisms which are used by the underlying web application like Email verification, OTP, Captcha, 2FA
- **Session Persistence Designed to Keep Users Logged In Across Multiple Devices (Intended Behaviour)** · [HackerOne](https://hackerone.com/reports/3161827) · `2025-09-04` · *Shopify* · ▲63
  > Hi, After logging out of the application, the session associated with the user is not invalidated server-side. An attacker with access to the session cookie prior to logout can reuse the same cookie to re-authenticate, effectively
- **Account Takeover in Password Reset Function** · [HackerOne](https://hackerone.com/reports/3228888) · `2025-09-02` · **Critical** · *Mars* · ▲104
- **Invalid** · [HackerOne](https://hackerone.com/reports/3304704) · `2025-08-19` · **Low** · *WakaTime* · ▲26
  > Full Account Takeover (ATO): The attacker gains complete access to the victim’s account. Confidentiality: The attacker can view all sensitive information of the victim. Integrity: The attacker can modify or delete the victim’s dat
- **Email verification bypass via request to endpoint "accounts.insightly.com/signup/provisionuser"** · [HackerOne](https://hackerone.com/reports/2718253) · `2025-08-18` · **Critical** · *Insightly* · ▲147
  > The vulnerability occurs in the "EmailAddress" parameter in the member creation area and affects all users. Steps To Reproduce: Before proceeding with the steps of the vulnerability, have a previously created account or open it no
- **Trivial C# Random Exploitation** · [Doyensec](https://blog.doyensec.com/2025/08/19/trivial-exploit-on-C-random.html) · `2025-08-18`
  > Exploiting random number generators requires math, right? Thanks to C#’s Random , that is not necessarily the case! I ran into an HTTP 2.0 web service issuing password reset tokens from a custom encoding of (new Random()).Next(min
- **Double Clickjacking Attack on WakaTime OAuth Authorization Flow at https://wakatime.com/oauth/authorize** · [HackerOne](https://hackerone.com/reports/3287060) · `2025-08-05` · **Medium** · *WakaTime* · ▲57
  > An attacker can trick users into unknowingly clicking the "Connect my WakaTime account" button in the WakaTime App consent dialog using a double-clickjacking attack. This allows an attacker to register a WakaTime OAuth App, host a
- **total Failure of password protection while extracting seed phrase! increases attack surface area for scammers** · [HackerOne](https://hackerone.com/reports/2280279) · `2025-07-31` · **Medium** · *MetaMask* · ▲131
- **Mint Oauth2 access token for targeted user** · [HackerOne](https://hackerone.com/reports/1148364) · `2025-07-23` · **High** · $5,580 · *GitLab* · ▲139
  > It is possible to mint access token for targeted user. There is a flaw for group level application setup. It allows a group owner to create an application with user's trust by default. This bypassed the CSRF control for authorizat
- **[CRITICAL] 0-Click Account Takeover via Password Reset [AUTH-3243] /orchestrator/v1/password_reset/start** · [HackerOne](https://hackerone.com/reports/2831902) · `2025-07-21` · **Critical** · *Remitly* · ▲287
  > A 0-click Account Takeover vulnerability was identified in the password reset functionality of the target website. This flaw allows an attacker to reset the victim's password without any interaction or consent from the victim, lea
- **Account takeover of existing HackerOne accounts through SCIM provisioning** · [HackerOne](https://hackerone.com/reports/3178999) · `2025-07-17` · **High** · *HackerOne* · ▲232
  > Why I think this is so critical is that apart from taking over user accounts, take note of EVERY new organisation, sandbox alike, there are two users present by default: Demo Triager demo-triager@hackerone.com Demo Member demo-mem
- **Leaked reused password for a few Khan Academy users** · [HackerOne](https://hackerone.com/reports/3099978) · `2025-07-12` · **High** · *Khan Academy* · ▲92
  > Impact Exposure of user emails and passwords, leading to credential compromise. Increased risk of account takeover (ATO) if users reuse passwords across platforms. Potential for phishing and social engineering attacks targeting af
- **Novel exploits for double-clickjacking, request tunnelling – hacker roundup** · [YesWeHack](https://yeswehack.com/news/double-clickjacking-request-tunnelling-encryption) · `2025-06-20`
  > Fresh twists on double-clickjacking and HTTP request tunnelling along with a guide to Google dorking feature in our latest roundup aimed at bug hunters.
- **1 Click Account Takeover via Auth Token Theft on marketing.hostinger.com** · [HackerOne](https://hackerone.com/reports/3081691) · `2025-06-06` · **High** · *hostinger* · ▲219
  > Hey Paul, hope you're doing good ! I discovered a One Click Account Takeover vulnerability in Hostinger through the [code] subdomain. Since this subdomain is part of hostinger.com and is whitelisted for redirects, an attacker can 
- **Apache Airflow Fab Provider: Application does not invalidate session after password change via Airflow cli** · [HackerOne](https://hackerone.com/reports/3073507) · `2025-05-29` · **Low** · *Internet Bug Bounty* · ▲57 · CVE-2024-45033
  > Account takeover possibility due to insufficient session expiration vulnerability in Apache Airflow Fab Provider.
- **Shopify Partners Invitation Process Allows Privilege Escalation Without Email Verification** · [HackerOne](https://hackerone.com/reports/2885269) · `2025-05-15` · **Medium** · *Shopify* · ▲244
  > Impact Analysis Internal Escalation by Low-Privilege Member: - A low-privilege member can escalate their role by exploiting this vulnerability to accept an invitation sent to a victim's email, gaining unauthorized access to Owner 
- **Enable 2FA without verifying the email** · [HackerOne](https://hackerone.com/reports/3016540) · `2025-05-09` · **Low** · *XVIDEOS* · ▲69
  > The victim can't register an account with their email. If the victim reset the password, the password will change, but the victim can't login because of 2FA which was enabled by attacker leading to denial-of-service against the le
- **Episode 121: Slonser’s Image Injection 0-day -> ATO & New Caido Collab Plugin** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-05-08`
  > Episode 121: In this episode of Critical Thinking - Bug Bounty Podcast we cover so much news and research that we ran out of room in the description... Follow us on X Shoutout to YTCracker for the awesome intro music! ====== Links
- **Unauthorized Account Access via Leaked Credentials in URL Format (Account Takeover )** · [HackerOne](https://hackerone.com/reports/3080597) · `2025-05-07` · **Critical** · *Khan Academy* · ▲107
  > Full account takeover: Unauthorized access to user accounts with no user awareness. Exposure of personal data: Private information such as learning progress, messages, and linked accounts may be compromised. Potential financial or
- **SCIM Hunting - Beyond SSO** · [Doyensec](https://blog.doyensec.com/2025/05/08/scim-hunting.html) · `2025-05-07`
  > Introduction Single Sign-On (SSO) related bugs have gotten an incredible amount of hype and a lot of amazing public disclosures in recent years. Just to cite a few examples: Common OAuth Vulnerabilities Sign in as anyone: Bypassin
- **Session Replay Attack Allows Authentication Bypass via Captured Login Responses Allowing Bypass of 429 Too many attempts for Multiple Failed Logins** · [HackerOne](https://hackerone.com/reports/3120790) · `2025-05-01` · **High** · *WakaTime* · ▲54
  > An attacker can bypass authentication by capturing a valid login response (including session cookies/tokens) and replaying it during a failed login attempt with incorrect credentials. The server fails to invalidate or validate ses
- **Broken Access Control Exposes Email Verification Status and Privacy Settings via API Endpoint** · [HackerOne](https://hackerone.com/reports/3114132) · `2025-04-29` · **Low** · *WakaTime* · ▲57
  > Account Enumeration: Attackers can confirm valid/verified accounts (is email confirmed: true), enabling targeted credential stuffing or phishing. Privacy Violations: Knowing a user’s email privacy preference (is email public: fals
- **Episode 116: Auth Bypasses and Google VRP Writeups** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-03-27`
  > Episode 116: In this episode of Critical Thinking - Bug Bounty Podcast Justin gives a quick rundown of Portswigger’s SAML Roulette writeup, as well as some Google VRP reports, and a Next.js middleware exploit. Follow us on twitter
- **SAML roulette: the hacker always wins** · [PortSwigger Research](https://portswigger.net/research/saml-roulette-the-hacker-always-wins) · `2025-03-18`
  > Introduction In this post, we’ll show precisely how to chain round-trip attacks and namespace confusion to achieve unauthenticated admin access on GitLab Enterprise by exploiting the ruby-saml library
- **Account Takeover Vulnerability in Shopify Collabs Platform Due to Missing Email Verification** · [HackerOne](https://hackerone.com/reports/1679734) · `2025-03-11` · **Low** · $800 · *Shopify* · ▲112
  > Shopify collabs (collabs.shopify.com) is a new platform for content creators / influencers to discover and advertise the millions of brands of Shopify. The content creators can apply for different brands on this platform and get p
- **Ability to Add and Verify Uncontrolled Mobile Numbers Leading to Account Takeover (ATO)** · [HackerOne](https://hackerone.com/reports/2762462) · `2025-03-04` · **Critical** · *MTN Group* · ▲97
  > A critical vulnerability was identified in the OTP verification process on the shop.mtn.ng platform, which allows attackers to add and verify mobile numbers that they do not control. By tampering with the OTP verification request,
- **Account Takeover via Password Reset without user interactions** · [HackerOne](https://hackerone.com/reports/2293343) · `2025-02-26` · **Critical** · $35,000 · *GitLab* · ▲985
- **Unauthorized access to PII leads to Administrator account Takeover** · [HackerOne](https://hackerone.com/reports/2450685) · `2025-02-22` · **Critical** · *MTN Group* · ▲82
  > This vulnerability is present in the wp-json/wp/v2/users/15 file located in the wordpress directory endpoints. This flaw arises from insufficient restrictions placed on the list of post authors, which can be exploited by remote at
- **Episode 110: Oauth Gadget Correlation and Common Attacks** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-02-13`
  > Episode 110: In this episode of Critical Thinking - Bug Bounty Podcast we hit some quick news items including a DOMPurify 3.2.3 Bypass, O3 mini updates, and a cool postLogger Chrome Extension. Then, we hone in on OAuth vulnerabili
- **Clickjacking in main domain https://topechelon.com/** · [HackerOne](https://hackerone.com/reports/2964441) · `2025-02-10` · **High** · *Top Echelon Software* · ▲80
  > - User Account Takeover: If a logged-in user interacts with the iframe, attackers could force unintended actions. - Phishing Attacks: Users may unknowingly enter sensitive credentials. - Malicious Actions: Attackers can exploit us
- **Episode 109: Creative Recon - Alternative Techniques** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-02-06`
  > Episode 109: In this episode of Critical Thinking - Bug Bounty Podcast we start off with a quick recap of some of the DeepSeek Drama that’s been going down, and discuss AI in CAPTCHA and 2FA as well. Then we switch to cover some o
- **Common OAuth Vulnerabilities** · [Doyensec](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html) · `2025-01-29`
  > OAuth2’s popularity makes it a prime target for attackers. While it simplifies user login, its complexity can lead to misconfigurations that create security holes. Some of the more intricate vulnerabilities keep reappearing becaus
- **Bypass Email Verification on Add Email Monitoring** · [HackerOne](https://hackerone.com/reports/2387297) · `2025-01-07` · **Medium** · *Mozilla* · ▲93
  > Attacker can add the victim's email address without verification. And if attacker choose Send all breach alerts to primary email address , attacker will get a notification when victim's email address is leaked {F3074332}
