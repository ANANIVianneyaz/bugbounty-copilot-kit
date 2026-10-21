// RECON #2 CyberAar : regles du programme, sitemap (surface publique), endpoints API REELS de AarMe.
// Lecture seule (GET/HEAD) sur l actif Critique aarme.cyberaar.io. Aucune ecriture, aucun scan.
import fs from "fs";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const OUT = "/tmp/opencode/cyberaar";
const log = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function get(url, o = {}) {
  const t0 = Date.now();
  try {
    const r = await fetch(url, { method: o.m || "GET", headers: { "User-Agent": UA, Accept: o.accept || "*/*", ...(o.h || {}) }, redirect: "manual", signal: AbortSignal.timeout(25000) });
    const txt = await r.text();
    const rec = { url, m: o.m || "GET", s: r.status, ms: Date.now() - t0, ct: r.headers.get("content-type") || "", loc: r.headers.get("location") || "", len: txt.length, body: txt.slice(0, 600) };
    log.push(rec);
    return { ...rec, txt };
  } catch (e) {
    const rec = { url, s: 0, ms: Date.now() - t0, ct: "", loc: "", len: 0, body: "ERR " + (e.cause?.code || e.message) };
    log.push(rec);
    return { ...rec, txt: "" };
  }
}
const show = (l, r) => console.log("  " + l.padEnd(50) + String(r.s).padEnd(4) + (r.ms + "ms").padEnd(8) + (r.ct.split(";")[0] || "-").padEnd(24) + (r.loc ? "-> " + r.loc.slice(0, 50) : r.body.replace(/\s+/g, " ").slice(0, 90)));

console.log("=== A) regles du programme (aarme.cyberaar.io/regles/) ===");
const rules = await get("https://aarme.cyberaar.io/regles/");
show("/regles/", rules);
const text = rules.txt.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/\s+/g, " ");
console.log("\n  --- regles (texte) ---");
console.log("  " + text.slice(0, 3500).replace(/(.{110})/g, "$1\n  "));

console.log("\n=== B) sitemap AarMe : la surface publique ===");
const sm = await get("https://aarme.cyberaar.io/sitemap.xml");
show("/sitemap.xml", sm);
const urls = [...sm.txt.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
console.log("  " + urls.length + " URL(s) :");
const groups = {};
for (const u of urls) { const p = new URL(u).pathname; const k = p.split("/").filter(Boolean)[0] || "/"; (groups[k] = groups[k] || []).push(p); }
for (const [k, v] of Object.entries(groups)) console.log("    /" + k.padEnd(22) + v.length + "  " + v.slice(0, 6).join(" "));

console.log("\n=== C) endpoints API REELS de AarMe (lecture seule, sans jeton) ===");
const apiPaths = [
  "/api/aarme/org", "/api/aarme/orgs", "/api/aarme/stats", "/api/aarme/account/session",
  "/api/aarme/account/logout", "/api/aarme/account/register", "/api/aarme/account",
  "/api/aarme/programs", "/api/aarme/programmes", "/api/aarme/reports", "/api/aarme/users",
  "/api/aarme/me", "/api/aarme/session", "/api/aarme/config", "/api/aarme/version",
  "/api/aarme/leaderboard", "/api/aarme/palmares", "/api/aarme/health",
];
for (const p of apiPaths) {
  const r = await get("https://aarme.cyberaar.io" + p, { accept: "application/json" });
  show(p, r);
  await sleep(250);
}

console.log("\n=== D) l interface d administration (2 requetes, lecture) ===");
for (const p of ["/admin", "/admin/", "/api/aarme/admin", "/api/aarme/admin/users"]) {
  const r = await get("https://aarme.cyberaar.io" + p, { accept: "application/json" });
  show(p, r);
  await sleep(250);
}

console.log("\n=== E) API formulaires de cyberaar.io (actif Standard) ===");
for (const p of ["/api/contact", "/api/inscription", "/api/signup", "/api/v1/contact", "/api/form", "/api/forms", "/api/newsletter", "/api/apply"]) {
  const r = await get("https://cyberaar.io" + p, { accept: "application/json" });
  show(p, r);
  await sleep(250);
}

fs.writeFileSync(OUT + "/recon2-log.json", JSON.stringify(log, null, 1));
console.log("\n-> " + OUT + "/recon2-log.json (" + log.length + " requetes)");
