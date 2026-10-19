# SSTI & Désérialisation

*6 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **connect.8x8.com: Deserialization Vulnerability in Automation Builder via Jint→Newtonsoft serializer coercion (TypeNameHandling)** · [HackerOne](https://hackerone.com/reports/3861550) · `2026-09-01` · **Critical** · $3,000 · *8x8* · ▲48
- **`relay_tx` wallet-rpc skips `--restricted-rpc` guard and lets any caller corrupt wallet state via attacker-controlled `pending_tx`** · [HackerOne](https://hackerone.com/reports/3687543) · `2026-08-05` · **Low** · *Monero* · ▲20
  > monero-wallet-rpc exposes a relay tx JSON-RPC method. The handler on relay tx (lines 1926–1970) deserializes a caller-supplied hex blob into a wallet2::pending tx structure and hands it directly to wallet2::commit tx without any o
- **Two click Account Takeover** · [HackerOne](https://hackerone.com/reports/3079738) · `2025-11-11` · **High** · *Basecamp* · ▲77
- **Episode 130: Minecraft Hacks to Google Hacking Star - Valentino** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-07-10`
  > Episode 130: In this episode of Critical Thinking - Bug Bounty Podcast Justin is joined by Valentino, who shares his journey from hacking Minecraft to becoming a Google hunter. He talks us through several bugs, including an HTML S
- **insecure deserilize object leads to RCE On Sitecore (CVE-██████████-27218)** · [HackerOne](https://hackerone.com/reports/3090123) · `2025-05-12` · **Critical** · *Mars* · ▲59 · CVE-2025-27218
- **CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet** · [HackerOne](https://hackerone.com/reports/3031518) · `2025-04-27` · **High** · $4,323 · *Internet Bug Bounty* · ▲56 · CVE-2025-24813
  > Execute system commands to obtain system permissions
