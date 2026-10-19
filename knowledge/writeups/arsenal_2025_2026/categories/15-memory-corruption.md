# Memory Corruption

*21 entrées — corpus 2025-2026 de l'arsenal (voir `../INDEX.md` pour les stats et `../fiches_sss/` pour les fiches détaillées).*

- **[Switch] Remote stack buffer overflow in the LDN/LP2P DHCP server leads to control-flow hijack** · [HackerOne](https://hackerone.com/reports/3770768) · `2026-10-15` · **High** · *Nintendo* · ▲26 · CVE-2026-82079
- **Connector/ODBC: malicious server's long version string wraps size_t PrefixLen via negative _snprintf return, causing heap out-of-bounds write** · [HackerOne](https://hackerone.com/reports/3871977) · `2026-10-12` · **Medium** · *MariaDB* · ▲7
  > A malicious or MITM MariaDB/MySQL server corrupts client-process memory (out-of-bounds write) in any application using MariaDB Connector/ODBC, the moment it opens a connection and allocates a statement. The demonstrated effect is 
- **Pre-authentication `size_t` integer underflow → out-of-bounds read / server crash in MariaDB `caching_sha2_password` (auth_mysql_sha2) via an RSA-OAEP** · [HackerOne](https://hackerone.com/reports/3781201) · `2026-10-07` · **Medium** · *MariaDB* · ▲14
  > The caching sha2 password server plugin, on a plaintext TCP connection, RSA-decrypts the client's password reply and sets pkt len = (int)plain text len without checking for an empty plaintext. It then calls sha256 crypt r(pkt, pkt
- **libmariadb ( mariadb-connector-c ): stack overflow via server-controlled field->length in prepared-statement codec** · [HackerOne](https://hackerone.com/reports/3766217) · `2026-10-04` · **Medium** · *MariaDB* · ▲23
  > A malicious MariaDB/MySQL server, or a network attacker performing MITM on a non-TLS database connection, can crash any application linked against libmariadb that uses prepared statements ( mysql stmt API). The crash occurs when t
- **The skb that wasn't freed - the Fragnesia primitive via Open vSwitch** · [Doyensec](https://blog.doyensec.com/2026/09/17/ovs.html) · `2026-09-16`
  > TLDR: Exploit . This is a deterministic local privilege escalation affecting the default install of the latest Arch, Fedora, Debian, Amazon Linux and RHEL distributions, having unprivileged user namespaces enabled, openvswitch aut
- **Stack Buffer-Overflow in MariaDB Charset_collation_map_st::insert_or_replace()** · [HackerOne](https://hackerone.com/reports/3782405) · `2026-09-15` · *MariaDB* · ▲23
  > Any authenticated user (USAGE-only privilege is sufficient) can crash the entire mariadbd process with a single SQL statement, disconnecting all clients and rolling back in-flight transactions. On builds without stack protectors (
- **Stack Buffer Overflow via Crafted keyseg->start/ keyseg->length in .MYI File (MariaDB MyISAM)** · [HackerOne](https://hackerone.com/reports/3771147) · `2026-09-15` · *MariaDB* · ▲11
  > The overflow content is fully attacker-controlled row data. At minimum, any DML touching the corrupted table's key reliably crashes the server (DoS). On targets without stack canaries or ASLR, this yields direct code execution as 
- **Conflux-queued zero-length RELAY_END triggers heap out-of-bounds read** · [HackerOne](https://hackerone.com/reports/3709605) · `2026-09-10` · **Medium** · *Tor* · ▲33
  > A zero-length RELAY END cell can trigger a heap out-of-bounds read when the cell is copied through Conflux out-of-order delivery and then processed on a non-open AP stream. Tor explicitly allows zero-length RELAY END cells by trea
- **Stack Buffer Overflow in mariadb-dump quote_name() Allows Malicious Server to Execute Arbitrary Code on Client** · [HackerOne](https://hackerone.com/reports/3788482) · `2026-09-08` · **Critical** · *MariaDB* · ▲51 · CVE-2025-13699
  > A malicious MySQL/MariaDB server achieves remote code execution against any mariadb-dump client that connects to it. The quote name() function in client/mysqldump.cc performs unbounded 2x character expansion into a fixed 387-byte 
- **Improper Input Validation and Integer Overflow in timeamount parameter of files_retention app** · [HackerOne](https://hackerone.com/reports/3521639) · `2026-09-05` · **Low** · *Nextcloud* · ▲23
- **Stack Overflow DoS in ST_GeomFromGeoJSON Allows Any Authenticated User to Crash the Entire Server** · [HackerOne](https://hackerone.com/reports/3769676) · `2026-09-03` · **Medium** · *MariaDB* · ▲18
  > A single authenticated user with the most basic privilege level (SELECT) can crash the entire MariaDB server with one query. This is not a per-connection crash. MariaDB uses a single-process, multi-threaded architecture, so a stac
- **[Wii U/3DS/Switch] Improper bounds check in StationURL in all NEX clients leading to remote crash/RCE** · [HackerOne](https://hackerone.com/reports/2551512) · `2026-08-07` · **Low** · *Nintendo* · ▲41
- **When Filenames Become Attack Surfaces: Weaponizing NASA's CFITSIO Extended Filename Syntax** · [Doyensec](https://blog.doyensec.com/2026/05/19/cfitsio-weaponized-filenames.html) · `2026-05-18`
  > This research was recently presented at BSides Luxembourg 2026 . This blogpost documents our findings presented during the talk. The BSides slides are posted here . Today, we’re also releasing the Docker-based playground utilized 
- **Double fdrop on a socket through sys_netcontrol** · [HackerOne](https://hackerone.com/reports/3320669) · `2026-05-01` · **High** · $10,000 · *PlayStation* · ▲227
- **mruby-engine: UAF in MRubyEngine#initialize enables local RCE** · [HackerOne](https://hackerone.com/reports/3679660) · `2026-04-24` · *Shopify* · ▲35
  > Double-init of MRubyEngine frees engine + unmaps mspace, but leaves Ruby DATA PTR dangling. Kernel reuses freed VA via mmap(MAP FIXED) . Attacker forges me mruby engine struct + mrb state in reclaimed region, points mrb state- all
- **CFITSIO Fuzzing: Memory Corruptions and a Codex-Assisted Pipeline** · [Doyensec](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html) · `2026-04-19`
  > Have you ever wondered how those amazing space photos are taken? Are they exclusive to the big telescopes floating in space or can you take one from your backyard? What does it take to extract hydrogen colors out of a seemingly bl
- **Reported RPC Overflow** · [HackerOne](https://hackerone.com/reports/3240792) · `2026-04-06` · *Monero* · ▲25
  > Potential denial of service
- **[MK8DX] Improper ranking/replay file parsing** · [HackerOne](https://hackerone.com/reports/1813453) · `2025-07-06` · **Critical** · *Nintendo* · ▲36
- **NEX: Stack overflow in UnicodeToUtf8** · [HackerOne](https://hackerone.com/reports/469997) · `2025-06-27` · *Nintendo* · ▲23
- **[Xenoblade Chronicles X: Definitive Edition] Buffer overflow in string escape function, multiplayer DoS** · [HackerOne](https://hackerone.com/reports/3048061) · `2025-05-15` · **High** · *Nintendo*
- **sys_fsc2h_ctrl kernel stack free** · [HackerOne](https://hackerone.com/reports/2900606) · `2025-04-18` · **High** · $10,000 · *PlayStation* · ▲236
