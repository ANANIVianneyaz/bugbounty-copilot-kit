// CYBERAAR : test authentifie (session de test) — surface une fois connecte
// Priorites : (1) ce que je vois, (2) ce que je ne dois pas voir (IDOR), (3) les effets de bord
import fs from "fs";
const APP = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE = fs.readFileSync("/tmp/opencode/cyberaar/session-cookie.txt", "utf8").trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const H = { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/compte/", Cookie: COOKIE };
async function gql(q, v = {}) {
  const t0 = Date.now();
  const r = await fetch(APP + "/graphql-not", { method: "POST" }).catch(() => null); // noop
  const r2 = await fetch(APP + "/api/aarme/graphql", { method: "POST", headers: H, body: JSON.stringify({ query: q, variables: v }), redirect: "manual", signal: AbortSignal.timeout(20000) });
  const t = await r2.text();
  let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r2.status, ms: Date.now() - t0, txt: t, j };
}
async function get(path) {
  const r = await fetch(APP + path, { headers: { Accept: "application/json", "User-Agent": UA, Cookie: COOKIE, Origin: APP }, redirect: "manual", signal: AbortSignal.timeout(20000) });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, txt: t, j };
}
const show = (l, r) => console.log("  " + l.padEnd(46) + "HTTP " + r.s + " " + String(r.ms || 0).padStart(5) + "ms  " + (r.txt || "").replace(/\s+/g, " ").slice(0, 170));

console.log("=== A) qui suis-je (session) ? ===");
show("GET /api/aarme/account/me", await get("/api/aarme/account/me"));
show("GET /api/aarme/account/session", await get("/api/aarme/account/session"));

console.log("\n=== B) surface des routes AVEC session (le 404 disparait-il ?) ===");
for (const p of ["/api/aarme/account/profile", "/api/aarme/report", "/api/aarme/org", "/api/aarme/reports", "/api/aarme/notifications", "/api/aarme/payouts", "/api/aarme/orgs", "/api/aarme/admin", "/api/aarme/account/me", "/api/aarme/account/logout"]) {
  const r = await get(p);
  console.log("  " + p.padEnd(46) + "HTTP " + r.s + "  " + r.txt.replace(/\s+/g, " ").slice(0, 100));
  await sleep(1200);
}
