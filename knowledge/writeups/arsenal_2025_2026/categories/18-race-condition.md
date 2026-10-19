# Race Conditions

*13 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **node:sqlite SQLTagStore Iterator Replay Lets Attacker Re-Execute Victim-Bound Writes Indefinitely** · [HackerOne](https://hackerone.com/reports/3795900) · `2026-08-28` · **Medium** · *Node.js* · ▲11 · CVE-2026-58041
- **Exceeding the maximum number of spaces allowed by exploiting a Race Condition in the Workspace creation process** · [HackerOne](https://hackerone.com/reports/3295500) · `2026-07-01` · **Low** · *SingleStore* · ▲35
- **Server-side ReDoS via user-controlled regex in OIDC Access Policy** · [HackerOne](https://hackerone.com/reports/3542546) · `2026-03-26` · *RubyGems* · ▲41
  > A single crafted request can block a Puma worker thread for an extended period of time due to catastrophic regex backtracking. Since RubyGems.org runs with a very small thread pool, a small number of concurrent requests can exhaus
- **Notepad++ hijack, pwning Claude Code – ethical hacker news roundup** · [YesWeHack](https://yeswehack.com/news/notepad-hijack-pwn-claude-code) · `2026-02-23`
  > Our first roundup of 2026 features 2025’s top web hacking techniques, HTTP trailer parsing discrepancies and a race condition in blockchain infrastructure.
- **ksmbd - Exploiting CVE-2025-37947 (3/3)** · [Doyensec](https://blog.doyensec.com/2025/10/08/ksmbd-3.html) · `2025-10-07`
  > Introduction This is the last of our posts about ksmbd. For the previous posts, see part1 and part2 . Considering all discovered bugs and proof-of-concept exploits we reported, we had to select some suitable candidates for exploit
- **Exceeding the limit of Workspaces via Race Condition** · [HackerOne](https://hackerone.com/reports/3226838) · `2025-10-06` · **Medium** · *SingleStore* · ▲62
- **Yet Another Random Story: VBScript's Randomize Internals** · [Doyensec](https://blog.doyensec.com/2025/09/25/yet-another-random-story.html) · `2025-09-24`
  > In one of our recent posts , Dennis shared an interesting case study of C# exploitation that rode on Random -based password-reset tokens. He demonstrated how to use the single-packet attack, or a bit of old-school math, to beat th
- **Email Verification Bypass via Race Condition** · [HackerOne](https://hackerone.com/reports/3020733) · `2025-08-15` · *Malwarebytes* · ▲69
  > - This vulnerability allows an attacker to take control of an account associated with a victim's email by changing the registered email address. - It presents a risk of data theft, unauthorized transactions, and further exploitati
- **Exceed the maximum number of subscribers using Race Condition** · [HackerOne](https://hackerone.com/reports/3221185) · `2025-08-12` · **Low** · *SingleStore* · ▲70
- **Not a Vuln: Race Condition Allows Creation of Multiple Organizations with the Same Name** · [HackerOne](https://hackerone.com/reports/3248712) · `2025-07-14` · *WakaTime* · ▲40
  > A race condition vulnerability exists in the organization creation logic that allows an attacker to create multiple organizations with the same name, violating the expected uniqueness constraint enforced by the UI. This could lead
- **MozillaVPN: Elevation of Privilege via a Race Condition Vulnerability** · [HackerOne](https://hackerone.com/reports/2261577) · `2025-07-03` · **Medium** · *Mozilla* · ▲41
- **Race condition on add 1 free domain** · [HackerOne](https://hackerone.com/reports/2616045) · `2025-05-09` · **Medium** · *Automattic* · ▲93
  > When a website/provider provide free account they will give the user some feature that limited from access, but if we using race condition vulnerability an user can create/bypass limitation from the provider Platform(s) Affected: 
- **Race Condition in Folder Creation Allows Bypassing Folder Limit** · [HackerOne](https://hackerone.com/reports/3104355) · `2025-04-29` · **Medium** · *Dust* · ▲65
  > The application enforces a hard limit of 10 folders per user under a specific space ( Knowledge - Space - Folder ). However, due to a Race Condition , it is possible to bypass this limit by sending multiple folder creation request
