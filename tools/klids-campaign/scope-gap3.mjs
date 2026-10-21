const AS = "https://bugsecure-api.senintel.sn";
const TUN = process.env.TUN;
const WBH = "https://webhook.site/3ef992c0-b173-407f-ab55-e3ea613a534a";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const F = async (u, o = {}) => { for (let a = 0; a < 3; a++) { try { return await fetch(u, { ...o, signal: AbortSignal.timeout(25000) }); } catch (e) { await sleep(2500); } } return null; };

async function probe(label, clientId, requestedScope) {
  const u = AS + "/oauth/authorize?response_type=code&client_id=" + encodeURIComponent(clientId) + "&redirect_uri=" + encodeURIComponent(TUN + "/cb") + "&scope=" + encodeURIComponent(requestedScope) + "&state=bb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=" + encodeURIComponent(AS);
  const r = await F(u, { redirect: "manual" });
  const loc = r?.headers.get("location") || "";
  const consent = loc.includes("/oauth/consent");
  const err = (loc.match(/code=([^&]+)/) || [])[1] || "";
  const desc = decodeURIComponent((loc.match(/error_description=([^&]+)/) || [])[1] || "");
  console.log("  " + label.padEnd(56) + "-> " + (consent ? "ACCEPTE (consentement ouvert)" : "refuse (" + (err + " " + desc).slice(0, 50) + ")"));
  await sleep(1800);
  return consent;
}

console.log("=== A) chemin SANS query string (client_id = /doc/plain) ===");
await probe("CIMD sans query, scope normal", TUN + "/doc/plain", "programs:read profile:read reports:read reports:write");
console.log("\n=== B) scope demande hors perimetre, chemin sans query ===");
await probe("CIMD sans query, scope=admin:all", TUN + "/doc/plain2", "programs:read admin:all");
await probe("CIMD sans query, scope=triage:write", TUN + "/doc/plain3", "programs:read profile:read reports:read triage:write");
await probe("CIMD sans query, scope=grade:write", TUN + "/doc/plain4", "programs:read profile:read reports:read grade:write");
await probe("CIMD sans query, scope=profiles:write", TUN + "/doc/plain5", "programs:read profile:read reports:read profiles:write");
console.log("\n=== C) temoin webhook.site (l AS accepte-t-il encore le CIMD ?) ===");
await probe("CIMD webhook.site (temoin)", WBH + "/alive-check-1", "programs:read profile:read");
await probe("CIMD webhook.site (temoin 2)", WBH + "/alive-check-2", "programs:read profile:read");
console.log("\n=== D) un client CLI enregistre (controle hors CIMD) ===");
await probe("client_id=bugsecure-mcp-cli (enregistre)", "bugsecure-mcp-cli", "programs:read profile:read");
