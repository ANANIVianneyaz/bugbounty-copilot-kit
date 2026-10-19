# Cookie Injection / Supercookies

*3 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **Unauthenticated go-httpbin servers : Leads to Cookie Tossing on *.aws.dev and Open Redirect** · [HackerOne](https://hackerone.com/reports/3966599) · `2026-10-16` · **Medium** · *AWS VDP* · ▲13
  > Summary: Cross-subdomain cookie injection/tossing: Plant attacker-controlled cookies scoped to .aws.dev , causing them to be sent to unrelated sibling applications. Denial of service: Crafted cookie values can trigger CloudFront/W
- **[Variation of #3321406] YetAnother 1-Click Chaining of Self-XSS, Cookie Tossing and AntiCSRF Token Prediction leads to auto approval in AccessTempAuth** · [HackerOne](https://hackerone.com/reports/3423950) · `2026-04-14` · **High** · *Cloudflare Public Bug Bounty* · ▲63
- **[Variation of #1554049] 1-Click Chaining of Self-XSS, Cookie Tossing and AntiCSRF Token Prediction leads to auto approval in Access Temp Auth** · [HackerOne](https://hackerone.com/reports/3321406) · `2026-04-14` · **High** · *Cloudflare Public Bug Bounty* · ▲39
