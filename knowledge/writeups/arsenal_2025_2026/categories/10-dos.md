# Denial of Service

*39 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **Memory exhaustion (DoS) via unbounded file read in `EncodingDiscovery.detect_encoding()`** · [HackerOne](https://hackerone.com/reports/4028616) · `2026-10-16` · **Medium** · *Weblate* · ▲18
  > EncodingDiscovery.detect encoding() in translation finder/discovery/base.py passes the raw file handle to charset normalizer.from fp() , which internally does from bytes(fp.read()) — the entire file is loaded into memory , with no
- **Uncaught RecursionError crash in translation-finder (deep directory tree DoS)** · [HackerOne](https://hackerone.com/reports/4022462) · `2026-10-14` · **Low** · *Weblate* · ▲15
  > - Availability: uncaught exception kills Weblate's discovery task - Repeated failures: every retry crashes again - Component stuck: import/update/hook activity stops for affected component - Aggregate CPU DoS: possible with many n
- **MariaDB HandlerSocket Improper Request Field-Count Validation Causes Server Crash** · [HackerOne](https://hackerone.com/reports/3867363) · `2026-10-07` · **Medium** · *MariaDB* · ▲23
  > HandlerSocket is an optional MariaDB plugin that exposes a separate port for direct table index access similar to key-value queries, bypassing normal SQL parsing to improve performance for simple read/write operations. When Handle
- **Possible DoS in NumberHelpers** · [HackerOne](https://hackerone.com/reports/2814774) · `2026-10-06` · **Medium** · *Ruby on Rails* · ▲17
- **ZMQ get_output_distribution duplicate amount DoS** · [HackerOne](https://hackerone.com/reports/3681690) · `2026-09-17` · **Medium** · *Monero* · ▲22
- **Web fuzzing for hackers** · [Intigriti](https://intigriti.com/researchers/blog/hacking-tools/web-fuzzing-for-hackers) · `2026-08-20`
  > Fuzzing has been around for as long as web applications have. In fact, the term itself was coined back in 1988, when Barton Miller, a professor at the University of Wisconsin, was working over a dial-up connection during a thunder
- **Debug Deep Link Abuse Allows Repeated Forced Logout and Application Disruption** · [HackerOne](https://hackerone.com/reports/3829030) · `2026-08-13` · **Low** · *Yelp* · ▲53
  > 1. Summary The Android application com.yelp.android.biz contains an exposed deep link: [code] Triggering this deep link externally causes the application to crash. After the application is restarted, the current user session is in
- **Denial of Service (DoS) Vulnerability in Drafts Creation Endpoint** · [HackerOne](https://hackerone.com/reports/3400140) · `2026-06-30` · **High** · $1,024 · *Discourse* · ▲97
  > This vulnerability enables an authenticated attacker to: Send large payloads that are processed and saved despite 502 errors, consuming backend resources. Create multiple drafts in quick succession, causing server-wide delays (e.g
- **Remote node DOS** · [HackerOne](https://hackerone.com/reports/876530) · `2026-06-29` · **Medium** · *Monero* · ▲24
  > In monerod, there is an outgoing send queue for each p2p connection to other peers. When this send queue is full, the thread sleeps for approximately 6 seconds and then terminates the connection. It is possible for an attacker to 
- **V1Plugin.Decrypt panics on empty ciphertext (Remote DoS)** · [HackerOne](https://hackerone.com/reports/3620748) · `2026-05-28` · **Medium** · *AWS VDP* · ▲41
  > V1Plugin.Decrypt() accesses request.Cipher[0] without checking that the slice is non-empty. Sending a DecryptRequest with empty or nil Cipher field causes an unrecoverable index out of range panic that crashes the entire gRPC serv
- **V2Plugin.Decrypt panics on empty ciphertext (Remote DoS)** · [HackerOne](https://hackerone.com/reports/3620753) · `2026-05-28` · **Medium** · *AWS VDP* · ▲25
  > V2Plugin.Decrypt() accesses request.Ciphertext[0] without checking that the slice is non-empty. Same root cause as BUG-001 but in the V2 (KMS v2) API path. Crashes the entire gRPC server process. --- Vulnerable Code go // pkg/plug
- **HMAC signature verification omits endpoint and payload allowing request forgery on CoinMate API** · [HackerOne](https://hackerone.com/reports/3670955) · `2026-05-20` · **Low** · *CoinMate.io* · ▲66
  > Complete compromise of API-connected accounts. An attacker can drain funds, execute Flash Crashes via market manipulation, and bypass all intended API Key endpoint restrictions, resulting in catastrophic loss of user assets. Becau
- **Critical Deadlock Vulnerability in Monero RPC Leading to Complete Node Paralysis** · [HackerOne](https://hackerone.com/reports/3307874) · `2026-05-06` · **Critical** · *Monero* · ▲96
  > A deadlock vulnerability in Monero's JSON-RPC interface allows a remote, unauthenticated attacker to completely paralyze any Monero node with a single HTTP request containing specific batch methods, leading to permanent denial of 
- **Improper input validation On Exported deep-link handler crashes `FileDisplayActivity` on crafted external URL — Denial-of-Service** · [HackerOne](https://hackerone.com/reports/3399016) · `2026-05-01` · *Nextcloud* · ▲65
  > Product / Package com.nextcloud.client Component com.owncloud.android.ui.activity.FileDisplayActivity (exported, multiple VIEW intent-filters with wildcard host) Severity Medium — Denial of Service (app crash). Potential for highe
- **Reported Denial of Service** · [HackerOne](https://hackerone.com/reports/3241102) · `2026-04-06` · *Monero* · ▲23
  > Potential denial of service; potential monerod crash
- **Potential DoS due to PasswordPoliciesNotMet in errors.go** · [HackerOne](https://hackerone.com/reports/2441029) · `2026-03-27` · **Low** · *passhash* · ▲19
  > Possible DoS depending on amount of PasswordPolicyError instances that can be created in a short time [code] Bug: The possible vulnerability is in the PasswordPoliciesNotMet struct. This struct collects all
- **DoS via Unbounded Memory Allocation in sendWebStream on Fastify v5.7.0+ leads to OOM crash when backpressure is ignored** · [HackerOne](https://hackerone.com/reports/3524779) · `2026-03-05` · *Fastify* · ▲35 · CVE-2026-25224
  > I have discovered a High-Severity Denial of Service (DoS) vulnerability in Fastify v5.7.0 and later . The issue lies in the sendWebStream function within lib/reply.js , which was recently introduced to support native Web Streams. 
- **Cache Pollution via Unkeyed GET Parameters on www.omise.co** · [HackerOne](https://hackerone.com/reports/3183046) · `2026-02-11` · **Medium** · *Omise* · ▲43
  > - An attacker can generate a large number of unique query variants to: - Pollute the CDN cache. - Evict useful cache entries (denial of service on popular pages). - Potentially inject harmful content if parameters are ever reflect
- **ASGIRequest header concatenation quadratic CPU DoS on Django via repeated headers leads to worker exhaustion** · [HackerOne](https://hackerone.com/reports/3426417) · `2026-02-09` · *Django* · ▲24
  > django.core.handlers.asgi.ASGIRequest builds the META dictionary by iterating over the ASGI scope["headers"] array. Whenever the same header name appears multiple times (which is legal in HTTP/2 and HTTP/3), the code concatenates 
- **Memory Exhaustion in CometBFT v1.0.1 via malicious ProposalMessage leads to network-wide denial of service** · [HackerOne](https://hackerone.com/reports/3510161) · `2026-01-20` · *Cosmos* · ▲47
  > CometBFT v1.0.1 contains a critical memory exhaustion vulnerability that allows any peer to crash nodes with a single ~50-byte P2P message. An attacker can send a malicious ProposalMessage with PartSetHeader.Total set to 2^32-1 , 
- **Economic DoS (Griefing) on IBC Relayers via `memo` Callback Gas Exploitation** · [HackerOne](https://hackerone.com/reports/3425308) · `2025-12-18` · **High** · *Cosmos* · ▲16
  > - Immediate Relayer Bankruptcy: Any permissionless relayer servicing this chain's callback-enabled channels will be rapidly drained of funds and forced to shut down. - Total Channel DoS: When relayers stop servicing the channel, a
- **Unrestricted setPerPage allows huge result sets / resource exhaustion / mass log retrieval** · [HackerOne](https://hackerone.com/reports/3413890) · `2025-11-19` · **Medium** · *Revive Adserver* · ▲22 · CVE-2025-55128
  > The setPerPage query parameter controls pagination for the log viewer but is not validated or capped on the server. An attacker can supply an extremely large numeric value (for example setPerPage=100000000000000000) and the applic
- **Episode 148: MCP Hacking Guide** · [Critical Thinking (podcast)](https://criticalthinkingpodcast.io) · `2025-11-13`
  > Episode 148: In this episode of Critical Thinking - Bug Bounty Podcast Justin gives us a crash course on Model Context Protocol. Follow us on twitter at: https://x.com/ctbbpodcast Got any ideas and suggestions? Feel free to send u
- **Application Level DoS - Large Markdown Payload in Reply Section Leading to Resource Exhaustion** · [HackerOne](https://hackerone.com/reports/3058919) · `2025-10-18` · **High** · *Discourse* · ▲84
  > An application level Denial of Service (DoS) vulnerability was identified in the reply section on https://try.discourse.org By submitting an excessively large markup payload (~800,000 characters), the server takes 30 seconds to re
- **Vulnerability: XML-RPC Interface Enabled and Accessible** · [HackerOne](https://hackerone.com/reports/3255910) · `2025-10-10` · *Tucows (VDP)* · ▲15
  > The enabled XMLRPC interface allows unauthenticated attackers to abuse these methods potentially leading to distributed denial of service attacks on the website or third parties and amplification of brute force login attempts This
- **Sample report: Denial of service** · [HackerOne](https://hackerone.com/reports/3290630) · `2025-08-07` · *GitHub* · ▲33
- **明確な認証不備および潜在的な中間者攻撃の可能性（Clear Authentication Deficiencies & Potential for Man-in-the-Middle Attacks）** · [HackerOne](https://hackerone.com/reports/2642615) · `2025-07-08` · **High** · *Sony* · ▲71
  > - DoS - Link Key Hijack - MitM Attacks
- **DOS of RSKJ server** · [HackerOne](https://hackerone.com/reports/2105808) · `2025-06-13` · **High** · $5,000 · *Rootstock Labs* · ▲120
  > DOS of RSKJ server Steps To Reproduce: 1. download https://github.com/rsksmart/rskj/releases/download/FINGERROOT-5.0.0/rskj-core-5.0.0-FINGERROOT-all.jar 2. at server side run [code] it opens UDPv6 port 5050 3. at client side inst
- **RPC service DOS** · [HackerOne](https://hackerone.com/reports/2338094) · `2025-05-23` · **Medium** · *Monero* · ▲47
  > The RPC service running port 18081 (or 28081, 38081) is vulnerable to a DOS rendering the service unusable. This is due to the possibility of a for loop going up until uint64 t's max range (1<<64 - 1). On the get fee estimate JSON
- **Weak Rate Limiting Controls in the (LOGIN) page Expose System to Brute Force and DoS Attacks** · [HackerOne](https://hackerone.com/reports/3085889) · `2025-05-15` · **Critical** · *Lichess* · ▲73
  > The login page lacks proper rate limiting, allowing an attacker to easily perform a brute-force attack. This vulnerability enables the attacker to systematically try different username and password combinations until they successf
- **[Xenoblade Chronicles X: Definitive Edition] Unrestricted RPCs allow DoS and writing arbitrary flags remotely** · [HackerOne](https://hackerone.com/reports/3062122) · `2025-05-15` · **Critical** · *Nintendo* · ▲65
- **Denial of Service by memory exhaustion in net/imap** · [HackerOne](https://hackerone.com/reports/3108869) · `2025-04-27` · **Medium** · *Internet Bug Bounty* · ▲23
  > There is a possibility for denial of service by memory exhaustion when net-imap reads server responses. At any time while the client is connected, a malicious server can send can send a "literal" byte count, which is automatically
- **Possible DoS by memory exhaustion in net/imap** · [HackerOne](https://hackerone.com/reports/2987782) · `2025-04-27` · **Medium** · *Internet Bug Bounty* · ▲18
  > This vulnerability causes Denial of Service by memory exhaustion for the projects using net-imap for connecting to an imap server.
- **Remote memory exhaustion in Epee RPC stack under zero Receive Window** · [HackerOne](https://hackerone.com/reports/2912194) · `2025-04-23` · **High** · *Monero* · ▲24
  > Memory exhaustion can be triggered in http protocol handler.inl and abstract tcp server2.inl under delayed ACK or zero Receive Window advertisement. This can lead with specific RPC methods to remote crash of nodes through restrict
- **Spamming highly nested JSON RPC requests cause node to disconnect from p2p network** · [HackerOne](https://hackerone.com/reports/2677306) · `2025-04-23` · *Monero* · ▲22
  > By forging a highly nested JSON payload, and spamming it through a restricted RPC interface, an adversary can remotely lock monerod from syncing with the rest of the p2p network. This vulnerability apply to syncing node as well sy
- **low-level p2p ping + tcp flooding leads to a remote crash in monerod** · [HackerOne](https://hackerone.com/reports/2858802) · `2025-04-14` · **Critical** · *Monero* · ▲97
- **Possible ReDoS vulnerability in query parameter filtering in Action Dispatch** · [HackerOne](https://hackerone.com/reports/2872502) · `2025-03-07` · **Medium** · *Internet Bug Bounty* · ▲44 · CVE-2024-41128
  > Carefully crafted query parameters can cause query parameter filtering to take an unexpected amount of time, possibly resulting in a DoS vulnerability. All users running an affected release should either upgrade or apply the relev
- **Deadlock in x86 HVM standard VGA handling** · [HackerOne](https://hackerone.com/reports/2921724) · `2025-03-07` · **Medium** · $2,162 · *Internet Bug Bounty* · ▲87 · CVE-2024-45818
  > An attacker executing code in ring0 inside of an unprivileged x86-HVM-DomU can trigger a deadlock in the host hypervisor, resulting in a Denial of Service of all other Domains running under the Hypervisor, including the hypervisor
- **Unsufficent input verification leads to DoS and resource consumption** · [HackerOne](https://hackerone.com/reports/2818147) · `2025-02-26` · **Low** · $300 · *Sorare* · ▲108
  > This vulnerability affects the endpoint at api.sorare.com/api/v1/users/ where weakness in verifying the length of the email parameter can lead to partial DoS of the backend component. Steps To Reproduce: This endpoint accepts an e
