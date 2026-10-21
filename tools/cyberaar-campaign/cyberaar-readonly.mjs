// CYBERAAR : travail LECTURE SEULE (pendant la decantage du plafond des formulaires)
//  1) la page de signalement de vulnerabilite du site principal (actif Standard) : formulaire ? upload ?
//  2) la page de soumission d AarMe (actif Critique) : champs, pieces jointes, upload ?
//  3) les en-tetes de securite de l API (le JSON renvoie-t-il de l HTML ?)
//  4) la carte des pages de cyberaar.io (sitemap) -> quels formulaires existent
import fs from "fs";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function get(u, o = {}) {
  try {
    const r = await fetch(u, { headers: { "User-Agent": UA, Accept: o.accept || "text/html,*/*" }, redirect: "manual", signal: AbortSignal.timeout(25000) });
    return { s: r.status, txt: await r.text(), h: Object.fromEntries(r.headers), loc: r.headers.get("location") || "" };
  } catch (e) { return { s: 0, txt: "ERR " + e.message, h: {}, loc: "" }; }
}
const clean = (s) => s.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/\s+/g, " ");

console.log("=== 1) cyberaar.io/signaler-vulnerabilite (actif Standard) ===");
const sv = await get("https://cyberaar.io/signaler-vulnerabilite");
console.log("  HTTP " + sv.s + " | " + sv.txt.length + " car.");
if (sv.s === 200) {
  fs.writeFileSync("/tmp/opencode/cyberaar/signaler.html", sv.txt);
  const forms = [...sv.txt.matchAll(/<form[\s\S]*?<\/form>/gi)].map((m) => m[0]);
  console.log("  formulaires : " + forms.length);
  for (const f of forms) {
    console.log("    attrs : " + (f.match(/<form[^>]*>/i)?.[0] || "").replace(/\s+/g, " ").slice(0, 140));
    console.log("    champs : " + [...new Set([...f.matchAll(/name="([^"]+)"/g)].map((m) => m[1]))].join(", "));
    console.log("    types : " + [...new Set([...f.matchAll(/type="([^"]+)"/g)].map((m) => m[1]))].join(", "));
  }
  const files = [...new Set([...sv.txt.matchAll(/accept="([^"]+)"|type="file"/g)].map((m) => m[0]))];
  console.log("  upload ? " + (files.join(" | ") || "aucun"));
  const t = clean(sv.txt);
  console.log("  texte : " + t.slice(0, 700));
}
await sleep(1500);

console.log("\n=== 2) aarme.cyberaar.io/soumettre/ (actif Critique) : le formulaire de soumission ===");
const so = await get("https://aarme.cyberaar.io/soumettre/");
console.log("  HTTP " + so.s + " | " + so.txt.length + " car.");
if (so.s === 200) {
  fs.writeFileSync("/tmp/opencode/cyberaar/soumettre.html", so.txt);
  const zones = [...new Set([...so.txt.matchAll(/id="(rep-[a-z-]+|res-[a-z-]+|hp-[a-z-]+)"/g)].map((m) => m[1]))];
  console.log("  zones de formulaire : " + (zones.join(", ") || "(aucune)"));
  const inputs = [...new Set([...so.txt.matchAll(/<input[^>]*name="([^"]+)"[^>]*>/g)].map((m) => m[1]))];
  console.log("  champs <input name> : " + (inputs.join(", ") || "(aucun)"));
  const fileInputs = [...new Set([...so.txt.matchAll(/<input[^>]*type="file"[^>]*>/g)].map((m) => m[0].replace(/\s+/g, " ").slice(0, 120)))];
  console.log("  champs fichier : " + (fileInputs.join(" | ") || "(aucun)"));
  const apiRefs = [...new Set([...so.txt.matchAll(/['"`](\/api\/[A-Za-z0-9\/_\-\.]*)['"`]/g)].map((m) => m[1]))];
  console.log("  appels /api en clair : " + (apiRefs.join(", ") || "(aucun)"));
}
await sleep(1500);

console.log("\n=== 3) en-tetes de securite de l API (et des pages) ===");
for (const u of ["https://aarme.cyberaar.io/api/aarme/account/session", "https://cyberaar.io/api/contact"]) {
  const r = await get(u, { accept: "application/json" });
  const h = r.h;
  console.log("  " + u.replace("https://", ""));
  console.log("      csp: " + (h["content-security-policy"] || "-").slice(0, 150));
  console.log("      xfo: " + (h["x-frame-options"] || "-") + " | nosniff: " + (h["x-content-type-options"] || "-") + " | referrer: " + (h["referrer-policy"] || "-"));
  await sleep(1200);
}

console.log("\n=== 4) sitemap cyberaar.io : les pages (et donc les formulaires) ===");
const sm = await get("https://cyberaar.io/sitemap.xml", { accept: "application/xml" });
if (sm.s === 200) {
  const urls = [...sm.txt.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  console.log("  " + urls.length + " URL(s) :");
  for (const u of urls) console.log("    " + u.replace("https://cyberaar.io", "") + (/\/api\//.test(u) ? "   <-- API" : ""));
}
