// CYBERAAR : cartographie de la surface ADMIN (dans le perimetre : admin.aarme.cyberaar.io, classe Critique)
// Technique : le DIFFERENTIEL DE CODE dessine la carte des routes sans session et sans toucher aux donnees
//   404 = route inexistante | 401/403 = route existante protegee | 200 = route accessible
import fs from "fs";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = [];
async function probe(base, path, method = "GET") {
  for (let i = 0; i < 2; i++) {
    try {
      const t0 = Date.now();
      const r = await fetch(base + path, { method, headers: { "User-Agent": UA, Accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(20000) });
      const txt = await r.text();
      const rec = { base, path, method, s: r.status, ms: Date.now() - t0, ct: r.headers.get("content-type") || "", body: txt.replace(/\s+/g, " ").slice(0, 200) };
      log.push(rec);
      return rec;
    } catch (e) { await sleep(2000); }
  }
  return { s: 0, body: "ERR" };
}
const cls = (r) => (r.s === 404 ? "404" : r.s === 401 ? "401" : r.s === 403 ? "403" : r.s === 405 ? "405" : r.s === 200 ? "200" : r.s === 429 ? "429" : String(r.s));
const show = (l, r) => console.log("  " + l.padEnd(46) + cls(r) + "  " + String(r.ms).padStart(5) + "ms  " + r.body.slice(0, 100));

const HOSTS = ["https://admin.aarme.cyberaar.io", "https://aarme.cyberaar.io"];
const PATHS = [
  "/", "/api", "/api/", "/api/aarme", "/api/admin", "/api/admin/users", "/api/admin/reports", "/api/admin/orgs",
  "/api/aarme/admin", "/api/aarme/admin/users", "/api/aarme/admin/reports", "/api/aarme/admin/programs",
  "/api/aarme/admin/payouts", "/api/aarme/admin/settings", "/api/aarme/admin/stats", "/api/aarme/admin/audit",
  "/api/aarme/reports", "/api/aarme/reports/list", "/api/aarme/report", "/api/aarme/orgs", "/api/aarme/org",
  "/api/aarme/members", "/api/aarme/member", "/api/aarme/payouts", "/api/aarme/payout", "/api/aarme/payments",
  "/api/aarme/settlements", "/api/aarme/certificates", "/api/aarme/invitations", "/api/aarme/notifications",
  "/api/aarme/account/me", "/api/aarme/account/profile", "/api/aarme/account/identity", "/api/aarme/account/security",
  "/api/aarme/account/researcher-header", "/api/aarme/programmes/cyberaar", "/api/aarme/search",
  "/api/aarme/taxonomy", "/api/aarme/badges", "/api/aarme/leaderboard",
];
console.log("=== A) admin.aarme.cyberaar.io : la surface existe-t-elle ? ===");
for (const p of ["/", "/api", "/api/aarme", "/api/aarme/account/session", "/api/aarme/stats", "/admin", "/admin/"]) {
  show(p, await probe(HOSTS[0], p));
  await sleep(1500);
}

console.log("\n=== B) carte des routes sur aarme.cyberaar.io (differentiel 404/401/200) ===");
const found = [];
for (const p of PATHS) {
  const r = await probe(HOSTS[1], p);
  const c = cls(r);
  const mark = c === "404" ? " " : "*";
  if (c !== "404") found.push({ p, c, body: r.body.slice(0, 120) });
  console.log("  " + mark + " " + p.padEnd(44) + c + "  " + r.body.slice(0, 90));
  await sleep(1400);
}

console.log("\n=== C) routes existantes (hors 404) ===");
for (const f of found) console.log("  " + f.p.padEnd(44) + f.c + "  " + f.body);

console.log("\n=== D) POST /api/aarme/account/login : formes et messages (sans session) ===");
for (const [l, b] of [
  ["corps vide", {}],
  ["email existant + faux mdp", { email: "trixx", password: "mauvais-mot-de-passe" }],
  ["email inexistant", { email: "inconnu-zzz-4242@maxxspace.com", password: "mauvais-mot-de-passe" }],
  ["sans email", { password: "x" }],
  ["champ login au lieu de email", { login: "trixx", password: "x" }],
  ["password en tableau", { email: "trixx", password: ["a", "b"] }],
  ["mass assignment", { email: "trixx", password: "x", role: "admin", isAdmin: true, level: "expert" }],
  ["username en plus", { email: "trixx", username: "trixx", password: "x" }],
]) {
  let out = { s: 0, body: "", ms: 0, cookies: [] };
  try {
    const t0 = Date.now();
    const r = await fetch(HOSTS[1] + "/api/aarme/account/login", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, Origin: HOSTS[1], Referer: HOSTS[1] + "/compte/" }, body: JSON.stringify(b), redirect: "manual", signal: AbortSignal.timeout(20000) });
    out = { s: r.status, body: (await r.text()).replace(/\s+/g, " ").slice(0, 160), ms: Date.now() - t0, cookies: r.headers.getSetCookie?.() || [] };
  } catch (e) { out.body = "ERR " + e.message; }
  console.log("  " + l.padEnd(38) + "HTTP " + out.s + " " + String(out.ms).padStart(5) + "ms  " + out.body);
  if (out.cookies.length) console.log("      cookies: " + out.cookies.map((c) => c.split(";")[0]).join(" | "));
  await sleep(1600);
}
fs.writeFileSync("/tmp/opencode/cyberaar/admin-surface.json", JSON.stringify(log, null, 1));
console.log("\n-> /tmp/opencode/cyberaar/admin-surface.json (" + log.length + " requetes)");
