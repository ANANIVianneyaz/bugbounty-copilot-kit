# GraphQL

*10 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)** · [HackerOne](https://hackerone.com/reports/3782701) · `2026-08-05` · **Critical** · $12,000 · *Mozilla* · ▲357
  > The public GraphQL endpoint at /graphql allows an unauthenticated caller to execute arbitrary JavaScript inside the web-server's Node.js process. The query argument filter is a free-form JSON object that the server passes directly
- **Episode 182: Partial Auth, Hackbot GraphQL, and AI's #1 Mission** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2026-07-09`
  > Episode 182: In this episode of Critical Thinking - Bug Bounty Podcast we talk about some recent bugs involving WPM, MCP, and a possible emerging bug class using Wayback. We also talk about some GraphQL Hackbot finds, and what AI’
- **[CVE-2026-40762] Unauthenticated SQL Injection in WPGraphQL < 2.11.1** · [LogicalBreach](https://academy.logicalbreach.com/writeups/cve-2026-40762-unauthenticated-sql-injection-in-wpgraphql-2-11-1-f85ad3b3) · `2026-07-08`
  > An unauthenticated time-based blind SQL injection was confirmed in a public WPGraphQL `node(id:)` resolver affected by CVE-2026-40762. The issue was triggered by passing a crafted base64 Relay global ID that decoded to a malicious
- **Authenticated Elasticsearch Painless script execution via Query.search.sort_query on hackerone.com/graphql** · [HackerOne](https://hackerone.com/reports/3694007) · `2026-06-17` · **High** · $7,000 · *HackerOne* · ▲170
  > Describe impact here. Painless execution inside the ES JVM process grants code execution on the infrastructure that indexes HackerOne's platform data. The types reachable through Query.search (via the DocumentUnion schema union) i
- **DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** · [HackerOne](https://hackerone.com/reports/3287208) · `2026-04-16` · *HackerOne* · ▲184
  > An attacker can exploit this vulnerability to cause a Denial of Service (DoS) by sending a single GraphQL request with multiple aliases of the expensive mutation. This forces the server to perform repeated, resource-intensive oper
- **Unauthenticated GraphQL access by prepending __schema to private operations** · [HackerOne](https://hackerone.com/reports/3452015) · `2025-12-05` · **Medium** · $500 · *Enjin* · ▲75
- **InQL v6.1.0 Just Landed with New Features and Contribution Swag! 🚀** · [Doyensec](https://blog.doyensec.com/2025/12/02/inql-v610.html) · `2025-12-01`
  > Introduction We are excited to announce a new release of our Burp Suite Extension - InQL v6.1.0 ! The complete re-write from Jython to Kotlin in our previous update ( v6.0.0 ) laid the groundwork for us to start implementing power
- **GraphQL Introspection Enabled on Shopify API Endpoint (Intended Behavior)** · [HackerOne](https://hackerone.com/reports/2886723) · `2025-09-17` · *Shopify* · ▲28
  > if attacker will get available query operation types , fields , mutations so an attacker will be able to modify and list the data and will be able to perform unauthorised api calls
- **Insecure Direct Object Reference (IDOR) in GraphQL deleteProfileImages Mutation** · [HackerOne](https://hackerone.com/reports/2968039) · `2025-02-21` · **High** · *Autodesk* · ▲80
- **Disclosing PolicyPageAssetGroup in Private Programs via /graphql `gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/{id}`** · [HackerOne](https://hackerone.com/reports/1618347) · `2025-01-21` · **Critical** · $25,000 · *HackerOne* · ▲294
  > Disclosing Sсope(Assets) in Private Programs
