# Fiches SSS — Memory Corruption

*3 cas sélectionnés dans le corpus 2025-2026 (HackerOne).*

### Stack Buffer Overflow in mariadb-dump quote_name() (malicious server → RCE)

**📄 Cas réel**
sévérité : critical · [source](https://hackerone.com/reports/3788482)

`quote_name()` (`client/mysqldump.cc`, l. 2227) double chaque backtick d'un identifiant dans un buffer de pile de 387 octets (`NAME_LEN*2+3`) sans aucun contrôle de longueur. Le protocole MySQL n'impose pas `NAME_LEN` aux valeurs renvoyées : un serveur malveillant retourne un nom de table de 400 backticks lors du `SHOW FULL TABLES`, l'expansion écrit 802 octets (backticks encadrants compris) et déborde de 415 octets. Le core dump de `mariadb-dump 10.11.17` montre RIP, RBP et quatre registres callee-saved à `0x6060606060606060` (des backticks), et le PoC `exploit_rce.py` obtient un shell `/bin/sh` en utilisant le backtick fermant (0x60) écrit par la fonction elle-même comme 4e octet de l'adresse de retour. Même motif non borné dans `quote_for_like()` (expansion x4) et `strmov()` sur `hash_key`.

**Cause racine :** confiance dans le fait que les identifiants renvoyés par le serveur tiennent dans `NAME_LEN` ; expansion non bornée vers des buffers de pile de taille fixe.

**Preuve technique (verbatim depuis la source) :**

```c
static char *quote_name(const char *name, char *buff, my_bool force)
...
  while (*name)
  {
    if (*name == qtype)
      *to++= qtype;       // doubles every backtick: 1 byte in -> 2 bytes out
```
```bash
mariadb-dump -h 127.0.0.1 -P 3307 -u root --password=x --skip-lock-tables testdb
```
```text
#1  0x6060606060606060 in ?? ()   <-- return address = attacker-controlled
rbp  0x6060606060606060   <-- frame pointer
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : une machine avec `mariadb-dump` (testé en 10.11.17) et Python 3 pour le faux serveur ; les scripts `fake_mysql_server.py` et `exploit_rce.py` sont attachés au rapport (références caviardées ████ dans le texte).
- Étapes : 1. lancer le faux serveur MySQL (`python3 fake_mysql_server.py`, port 3307, nom de table = 400 backticks). 2. Exécuter `mariadb-dump -h 127.0.0.1 -P 3307 -u root --password=x --skip-lock-tables testdb`. 3. Constater le SIGSEGV (exit 139). 4. GDB sur le core : return address, RBP, RBX, R12-R15 = `0x6060606060606060`. 5. Lancer `exploit_rce.py --evidence` pour la preuve d'exécution (shellcode `execve("/bin/sh")`).
- Pièges / limites : le harnais compile avec `-fno-stack-protector -z execstack` (mitigations retirées) ; sur le binaire de production (PIE+NX+RELRO+canary) il faut brute-forcer 12 bits d'ASLR (~2048 tentatives) et construire un ROP chain ; la boucle `while (*name)` s'arrête aux octets nuls, d'où la technique du backtick fermant comme octet d'adresse.

**Reproductibilité :** moyenne — crash et math du débordement entièrement documentés, mais scripts attachés caviardés et code-execution exigeant de contourner PIE/NX/canary.

**Techniques :** stack buffer overflow, malicious sql server, 2x expansion overflow, return address overwrite, null-byte constraint bypass, pie brute force, gdb core analysis

**Correspond aux classes qualifiantes :** memory corruption (cwe-121), rce

**Signal (endpoints/fonctions observés) :**
- `quote_name()` / `quote_for_like()` (`client/mysqldump.cc:2227`, `:2269`)
- `getTableName()` (l. 4820) et résultat de `SHOW FULL TABLES`
- `char hash_key[2*NAME_LEN+2];` puis `strmov(afterdot, table)` (l. 5835-5862)

**Paramètres impliqués :** nom de table renvoyé par le serveur (`SHOW FULL TABLES`), options `mariadb-dump -h`/`-P`/`-u`

### Double fdrop on a socket through sys_netcontrol

**📄 Cas réel**
sévérité : high · [source](https://hackerone.com/reports/3320669)

Sur PlayStation, le syscall `netcontrol` ajoute un socket à une structure `netevent` (commande `0x20000003`, référence prise par `getsock_cap()`) et le retire via `0x20000007`. `bnet_netevent_clear_queue()` retrouve le netevent par comparaison de **fd** (`ne->socket_fd != socket_fd`), pas du pointeur de fichier. En fermant `s1` puis en recréant un socket `s2` avec le même fd, le clear appelle deux `fdrop()` sur le fichier de `s2` (qui n'a jamais emprunté cette référence) et laisse fuir celle de `s1` : le fichier de `s2` est libéré alors que la fdtable le référence encore (use-after-free). Sur PS4, `fcntl(F_SETFL)` en boucle libère à nouveau le fichier (crash/panic) ; sur PS5, `fget()` se bloque. (Source : résumé d'équipe du rapport, champ `vulnerability_information` vide.)

**Cause racine :** identification du socket par fd (mutable, réutilisable) au lieu du `struct file` dans la file de netevents → `fdrop()` en double et référence fuitée.

**Preuve technique (verbatim depuis la source) :**

```c
    res = bnet_netevent_clear_queue(td, ifp, fp->f_data, user_buf);
    if (res == 0)
        fdrop(fp, td); // Drop ref that was held by netevent
    fdrop(fp, td); // Drop ref from getsock_cap() call above
```
```c
        if ((ne->flags & 1) != 0 || ne->socket_fd != socket_fd)
```
```c++
    close(s1); // s1 refcnt = 1
    int64_t s2 = socket(AF_INET, SOCK_STREAM, 0); // s2 refcnt = 1

    // Remove s2 from netevent (will cause double fdrop on file of s2)
    netcontrol(0, NETCONTROL_NETEVENT_CLEAR_QUEUE, &s2, sizeof(s2)); // s2 refcnt = 0, s1 refcnt = 1
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : plateforme exposant le syscall `netcontrol` (PoC PS4/PS5) ; capacité de créer/fermer des sockets avec des fd prédictibles.
- Étapes : 1. `s1 = socket(AF_INET, SOCK_STREAM, 0)` (refcnt 1). 2. `netcontrol(0, 0x20000003, &s1, sizeof(s1))` → refcnt 2. 3. `close(s1)` (refcnt 1) puis rouvrir `s2` : même fd. 4. `netcontrol(0, 0x20000007, &s2, sizeof(s2))` → double `fdrop` sur le file de `s2` (refcnt 0), `s1` reste à 1. 5. Déclencher `fcntl(s2, F_SETFL, 0)` en boucle (100 itérations dans la source) : PS4 → libération répétée du file → crash/panic ; PS5 → blocage dans `fget()`.
- Pièges / limites : le fd doit être réutilisé de façon déterministe ; sur PS5 le bug ne produit qu'un hang par `fget()` ; la source ne documente pas de primitive aboutie (exécution de code noyau non démontrée).

**Reproductibilité :** moyenne — code C complet fourni, mais nécessite une plateforme exposant `netcontrol` et la réutilisation déterministe du fd.

**Techniques :** double fdrop, reference count leak, fd reuse, use-after-free, kernel memory corruption, syscall abuse

**Correspond aux classes qualifiantes :** memory corruption (double free/uaf), privilege escalation (kernel rce potentiel)

**Signal (endpoints/fonctions observés) :**
- `netcontrol(if_index, cmd, buf, buflen)` — cmd `0x20000003` / `0x20000007`
- `kern_netevent_set_queue()`, `kern_netevent_clear_queue()`, `bnet_netevent_clear_queue()`
- `so->so_netevent`, `getsock_cap()`, `fdrop()`, `fcntl(F_SETFL)`

**Paramètres impliqués :** `if_index`, `cmd`, `buf` (fd du socket), `buflen`

### Conflux-queued zero-length RELAY_END triggers heap out-of-bounds read

**📄 Cas réel**
sévérité : medium · [source](https://hackerone.com/reports/3709605)

Tor autorise les cellules `RELAY_END` de longueur nulle (traitées comme `END_STREAM_REASON_MISC`), mais `connection_ap_process_end_not_open()` lit `msg->body[0]` avant de vérifier `msg->length`. En temps normal la lecture est masquée par le stockage « backing » des cellules relay ; avec la file hors-ordre de Conflux, `relay_msg_copy()` alloue exactement `sizeof(relay_msg_t) + msg->length`, donc pour `msg->length == 0` le `msg->body` copié pointe juste après l'allocation : la lecture devient un vrai OOB heap. Le PoC est un test de régression local ASan (`relaycell/end_cell_conflux_copy_oob`) qui fait passer la cellule par `conflux_process_relay_msg()`. Impact : crash fiable en build ASan/hardened ; en build normal, lecture mémoire hors bornes (CVSS 3.0 : AV:N/AC:H/UI:N/A:H).

**Cause racine :** `get_uint8(msg->body)` sans contrôle de `msg->length` avant accès, combiné aux copies heap de taille exacte de la voie Conflux qui suppriment l'espace protecteur habituel.

**Preuve technique (verbatim depuis la source) :**

```c
int reason = get_uint8(msg->body);
```
```c
if (msg->length == 0) {
  reason = END_STREAM_REASON_MISC;
}
```
```c
void *alloc = tor_malloc_zero(sizeof(relay_msg_t) + msg->length);
```
```text
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1
    #0 get_uint8 src/lib/arch/bytes.h:25
    #1 connection_ap_process_end_not_open src/core/or/relay.c:846
```

**Rejouer / exploiter (dérivé de la source) :**
- Prérequis : checkout Tor propre + le patch PoC attaché (référence `{F5843197}`, test `test_relaycell_end_cell_conflux_copy_oob()` et helper `copy_msg_through_conflux_ooo()`) ; clang et OpenSSL (la source indique des chemins Homebrew si nécessaire).
- Étapes : 1. appliquer le patch de test (`src/test/test_relaycell.c`). 2. `./autogen.sh`. 3. `CC=clang CFLAGS='-O0 -g -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address' ./configure --disable-asciidoc --disable-manpage --disable-html-manual`. 4. `make micro-revision.i` puis `make -j"$(nproc)" src/test/test`. 5. `ASAN_OPTIONS='abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=1' ./src/test/test relaycell/end_cell_conflux_copy_oob` → heap-buffer-overflow (`0 bytes after 16-byte region`).
- Pièges / limites : l'exploitation réseau exige une paire Conflux liée, un trou de séquence hors-ordre et un stream AP non ouvert (ex. `AP_CONN_STATE_CONNECT_WAIT`) ; le test local ne dépend pas du réseau ; en build non-ASan, seule une lecture mémoire est démontrée (aucune divulgation prouvée).

**Reproductibilité :** moyenne — commandes ASan exactes, mais code de test référencé en pièce jointe et conditions réseau AC:H.

**Techniques :** heap out-of-bounds read, zero-length relay cell, conflux out-of-order queue, exact-size heap copy, asan regression test

**Correspond aux classes qualifiantes :** memory corruption (oob read), dos (crash de process)

**Signal (endpoints/fonctions observés) :**
- `connection_ap_process_end_not_open()` (`src/core/or/relay.c:846`), `get_uint8(msg->body)`
- `relay_msg_copy()` (`relay_msg.c:71`), `conflux_process_relay_msg()` (`conflux.c:923`)
- cellule `RELAY_END` de longueur 0, `END_STREAM_REASON_MISC`, stream AP non ouvert

**Paramètres impliqués :** `msg->length`, `msg->body` (champs de cellule relay)
