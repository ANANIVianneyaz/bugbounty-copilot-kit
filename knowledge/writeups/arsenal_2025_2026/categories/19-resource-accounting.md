# Resource Accounting / Abus de coûts

*10 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **Tor onion service INTRODUCE2 invalid-MAC cells permanently grow service replay cache** · [HackerOne](https://hackerone.com/reports/3709703) · `2026-09-10` · **Low** · *Tor* · ▲28
  > A remote client can send well-formed v3 INTRODUCE1 cells whose encrypted section has an invalid MAC but a unique byte pattern. The introduction point parses and forwards these cells to the onion service as INTRODUCE2 . On the serv
- **Unauthenticated ?q= search query causes exponential pyparsing backtracking under a process-global lock in Weblate** · [HackerOne](https://hackerone.com/reports/3898281) · `2026-09-04` · **High** · *Weblate* · ▲32
  > Weblate's search-query grammar ( weblate/utils/search.py:174-227 ) is built with pyparsing.infix notation over a term rule that is ambiguous at every position, and packrat memoization is never enabled. Parsing a query with nested 
- **Malicious Conflux Endpoint Can Leave Stale Global OOO Queue Accounting After Teardown** · [HackerOne](https://hackerone.com/reports/3701692) · `2026-06-16` · **Low** · $100 · *Tor* · ▲35
  > Tor's Conflux OOO queue accounting can remain inflated after a Conflux set is torn down. A malicious Conflux-capable endpoint relay can send a real CONFLUX SWITCH gap followed by RELAY DATA cells, causing the client to queue out-o
- **Action Text ReDoS (Ruby 3.1 or lower)** · [HackerOne](https://hackerone.com/reports/2389431) · `2026-06-09` · **Low** · *Ruby on Rails* · ▲28
  > When using ActionText under Ruby 3.1, it is ReDoS if crafted text is sent and to plain text is called. The same regular expressions are used in Rails 6.1 and 7.0. - https://github.com/rails/rails/blob/v6.1.7.7/actiontext/lib/actio
- **Out of scope: Improper Input Validation Order on /api-internal/login via password field leads to unnecessary resource consumption** · [HackerOne](https://hackerone.com/reports/3625600) · `2026-05-05` · **Low** · $200 · *PortSwigger Web Security* · ▲91
  > The /api-internal/login authentication endpoint in Burp Suite DAST (Enterprise) internal login interface (test instance) processes user-supplied input before enforcing field-level validation, allowing extremely large payloads in t
- **High resource consumption by insufficient sanitization of forum threads pagination** · [HackerOne](https://hackerone.com/reports/1916400) · `2025-11-24` · **Medium** · $479 · *Flickr* · ▲75
- **Crafted smart contract can take 8 minutes to execute due to bug in modexp precompile.** · [HackerOne](https://hackerone.com/reports/2412583) · `2025-06-13` · **High** · *Rootstock Labs* · ▲85
  > A bug in the modexp precompile can cause long stalls. Steps To Reproduce: Tested on Linux x64. sh !/bin/bash wget -q https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2 linux-x64 bin.tar.gz tar zxf openjdk-11.0.2 linux-x6
- **Crafted smart contract can take 1.5 minutes to execute due to inefficient CODESIZE implementation** · [HackerOne](https://hackerone.com/reports/2489843) · `2025-06-12` · **Medium** · *Rootstock Labs* · ▲30
  > TLDR: VM.doCODESIZE() is inefficient which can lead to slow executions. VM.doCODESIZE() retrieves the code size by calling Program.getCode() , and then invoking the length property on the return value: java protected void doCODESI
- **Crafted smart contract can take ~23 seconds to execute due to immense error string construction** · [HackerOne](https://hackerone.com/reports/2559404) · `2025-06-12` · **Medium** · *Rootstock Labs* · ▲23
  > Stall the network.
- **Dynamic fee algorithm doesn't check for zero fee** · [HackerOne](https://hackerone.com/reports/1981441) · `2025-05-23` · **Low** · *Monero* · ▲46
  > Dynamic fee algorithm Blockchain::get dynamic base fee calculates the minimal fee per byte from current median block weight and block reward. The comment in the code says // min fee per byte = round up( 0.95 block reward ref weigh
