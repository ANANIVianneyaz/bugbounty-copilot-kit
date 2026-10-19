# Kubernetes & Conteneurs

*3 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **RBAC bypass on App log endpoints via `permissionRequired` typo — any authenticated user reads admin-only Enterprise App logs** · [HackerOne](https://hackerone.com/reports/3589551) · `2026-04-23` · **Medium** · *Rocket.Chat* · ▲40 · CVE-2026-29197
- **Existence of completed pods allows for bypass of Kubernetes NetworkPolicy** · [HackerOne](https://hackerone.com/reports/3328291) · `2025-11-19` · **Medium** · *AWS VDP* · ▲28
  > The Amazon VPC CNI controller, when configured to manage NetworkPolicy rules, will incorrectly apply firewall rules for Completed pods as if the pods are still running, causing these rules to be applied to other unrelated pods tha
- **elections.k8s.io uses weak session secret key, may place elections at risk** · [HackerOne](https://hackerone.com/reports/1387366) · `2025-09-19` · **High** · $250 · *Kubernetes* · ▲85
  > Hi there, I have been working on a new tool to detect misconfigured session signing across bug bounty programs, called CookieMonster. Many applications use stateless cookies to preserve session information (i.e. who has logged in)
