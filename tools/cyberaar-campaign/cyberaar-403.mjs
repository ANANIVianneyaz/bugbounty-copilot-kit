// CYBERAAR : pourquoi 403 sur /api/aarme/account/register ? On isole le garde-fou.
import fs from "fs";
const BASE = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const body = { name: "bb-probe", email: "bbtest4926@maxxspace.com", profile: "test", level: "debutant", password: "Bb-test-2026-ok!", accord: true, lang: "fr", hp: "" };

async function get(url, h = {}) {
  const r = await fetch(url, { headers: { "User-Agent": UA, Accept: "text/html,*/*", ...h }, redirect: "manual", signal: AbortSignal.timeout(25000) });
  const t = await r.text();
  return { s: r.status, txt: t, cookies: r.headers.getSetCookie?.() || [] };
}
async function post(path, b, h = {}) {
  const r = await fetch(BASE + path, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, ...h }, body: JSON.stringify(b), redirect: "manual", signal: AbortSignal.timeout(25000) });
  const t = await r.text();
  return { s: r.status, txt: t, cookies: r.headers.getSetCookie?.() || [] };
}
const show = (l, r) => console.log("  " + l.padEnd(54) + "HTTP " + r.s + "  " + r.txt.replace(/\s+/g, " ").slice(0, 150));

console.log("=== 0) cookies anonymes poses par le site ===");
const home = await get(BASE + "/");
console.log("  cookies sur / :", home.cookies.map((c) => c.split(";")[0]).join(" | ") || "(aucun)");
const compte = await get(BASE + "/compte/");
console.log("  cookies sur /compte/ :", compte.cookies.map((c) => c.split(";")[0]).join(" | ") || "(aucun)");
const CK = [...new Set([...home.cookies, ...compte.cookies].map((c) => c.split(";")[0]))].join("; ");
console.log("  cookie composite :", CK || "(vide)");

console.log("\n=== 1) variantes de requete POST ===");
const V = [
  ["nu (baseline)", {}],
  ["+ Origin + Referer", { Origin: BASE, Referer: BASE + "/compte/" }],
  ["+ cookie anonyme", { Cookie: CK }],
  ["+ Origin + cookie", { Origin: BASE, Referer: BASE + "/compte/", Cookie: CK }],
  ["+ X-Requested-With", { "X-Requested-With": "XMLHttpRequest" }],
  ["+ Origin + XRW + cookie", { Origin: BASE, Referer: BASE + "/compte/", "X-Requested-With": "XMLHttpRequest", Cookie: CK }],
  ["+ Content-Type: text/plain", { "Content-Type": "text/plain" }],
  ["+ Accept: text/html", { Accept: "text/html" }],
  ["+ Sec-Fetch-Site: same-origin", { "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty" }],
  ["+ X-AarMe-Researcher bidon", { "X-AarMe-Researcher": "bb-probe:0000000000000000000000000000000000000000000000000000000000000000" }],
];
for (const [lbl, h] of V) {
  const b = { ...body };
  if (lbl.includes("text/plain")) { /* on garde le body JSON mais le CT change */ }
  const r = await post("/api/aarme/account/register", b, h);
  show(lbl, r);
  await sleep(1200);
}

console.log("\n=== 2) le pot de miel (hp) : l endpoint valide-t-il les champs avant le 403 ? ===");
for (const [lbl, b] of [
  ["hp rempli (anti-spam)", { ...body, hp: "x" }],
  ["accord=false", { ...body, accord: false }],
  ["password trop court", { ...body, password: "a" }],
  ["email invalide", { ...body, email: "pas-un-email" }],
  ["level inconnu", { ...body, level: "dieu" }],
  ["nom vide", { ...body, name: "" }],
  ["champs manquants (corps vide)", {}],
]) {
  const r = await post("/api/aarme/account/register", b, { Origin: BASE, Referer: BASE + "/compte/", Cookie: CK });
  show(lbl, r);
  await sleep(1200);
}

console.log("\n=== 3) l autre endpoint POST (proposition d organisation) ===");
for (const [lbl, b] of [
  ["nominal", { org: "BB Probe Org", sector: "tech", email: "bbtest4926@maxxspace.com", message: "test de la surface", lang: "fr", hp: "" }],
  ["avec mass assignment", { org: "BB Probe Org", sector: "tech", email: "bbtest4926@maxxspace.com", message: "test", lang: "fr", hp: "", status: "APPROVED", assets: [{ url: "aarme.cyberaar.io", class: "Critique" }] }],
]) {
  const r = await post("/api/aarme/org", b, { Origin: BASE, Referer: BASE + "/organisations/", Cookie: CK });
  show(lbl, r);
  await sleep(1200);
}
