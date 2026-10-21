// RECON #3 : perimetre exact (page du programme) + surface API complete extraite des bundles Astro
import fs from "fs";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const OUT = "/tmp/opencode/cyberaar";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function get(url, o = {}) {
  const t0 = Date.now();
  try {
    const r = await fetch(url, { method: o.m || "GET", headers: { "User-Agent": UA, Accept: o.accept || "*/*", ...(o.h || {}) }, redirect: "manual", signal: AbortSignal.timeout(25000) });
    const txt = await r.text();
    return { url, s: r.status, ms: Date.now() - t0, ct: r.headers.get("content-type") || "", loc: r.headers.get("location") || "", txt, body: txt.slice(0, 500) };
  } catch (e) { return { url, s: 0, ms: Date.now() - t0, ct: "", loc: "", txt: "", body: "ERR " + (e.cause?.code || e.message) }; }
}
const text = (html) => html.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, " ");

console.log("=== A) page du programme : perimetre exact des actifs + classes ===");
for (const u of ["https://aarme.cyberaar.io/programmes/cyberaar/", "https://aarme.cyberaar.io/programmes/"]) {
  const r = await get(u);
  console.log("\n  " + u + "  HTTP " + r.s + " " + r.ms + "ms");
  const t = text(r.txt);
  const i = t.search(/Périmètre|Actif|Classe|actif/i);
  console.log("  " + (i >= 0 ? t.slice(Math.max(0, i - 200), i + 1800) : t.slice(0, 1200)).replace(/(.{118})/g, "$1\n  "));
  await sleep(300);
}

console.log("\n=== B) surface publique : pages utiles (programmes, organisations, palmares, compte) ===");
for (const u of ["https://aarme.cyberaar.io/organisations/", "https://aarme.cyberaar.io/palmares/", "https://aarme.cyberaar.io/compte/", "https://aarme.cyberaar.io/statut/"]) {
  const r = await get(u);
  console.log("  " + u.replace("https://aarme.cyberaar.io", "").padEnd(24) + "HTTP " + r.s + " " + r.ms + "ms  " + (r.loc ? "-> " + r.loc : r.body.replace(/\s+/g, " ").slice(0, 80)));
  await sleep(250);
}

console.log("\n=== C) bundles Astro : TOUTE la surface API + le schema d'auth ===");
const home = await get("https://aarme.cyberaar.io/");
const srcs = [...new Set([...home.txt.matchAll(/<script[^>]+src="([^"]+)"/gi)].map((m) => m[1]))];
// les chunks _astro sont charges dynamiquement : on les tire du HTML de la page et du manifeste
const astro = [...new Set([...home.txt.matchAll(/\/_astro\/[A-Za-z0-9._-]+\.js/g)].map((m) => m[0]))];
console.log("  scripts directs : " + srcs.length + " | chunks /_astro cites : " + astro.length);
const all = [...new Set([...srcs.filter((s) => s.includes("/_astro/")), ...astro])];
const apiPaths = new Map();
const authBits = new Map();
const interesting = new Map();
const PATHS = /["'`](\/api\/[A-Za-z0-9\/_\-\.{}$%]{2,120})["'`]/g;
const AUTH = /(localStorage|sessionStorage|document\.cookie|Authorization|Bearer|X-AarMe-Researcher|csrf|xsrf)/gi;
const INTEREST = /(s3|amazonaws|upload|avatar|logo|webhook|payout|kyc|invoice|bank|password|reset|2fa|totp|otp|magic|invite|token|refresh|admin|internal|debug|graphiql|playground)/gi;
let n = 0;
for (const s of all.slice(0, 40)) {
  const u = s.startsWith("http") ? s : "https://aarme.cyberaar.io" + s;
  const r = await get(u);
  if (r.s !== 200) continue;
  n++;
  fs.writeFileSync(OUT + "/astro-" + (s.split("/").pop().split("?")[0].replace(/[^\w.-]/g, "_")), r.txt);
  for (const m of r.txt.matchAll(PATHS)) if (!apiPaths.has(m[1])) apiPaths.set(m[1], s.split("/").pop());
  for (const m of r.txt.matchAll(AUTH)) if (!authBits.has(m[1])) authBits.set(m[1], s.split("/").pop());
  for (const m of r.txt.matchAll(INTEREST)) {
    const ctx = r.txt.slice(Math.max(0, m.index - 60), m.index + 60).replace(/\s+/g, " ");
    if (!interesting.has(ctx)) interesting.set(ctx, s.split("/").pop());
  }
  await sleep(150);
}
console.log("  " + n + " bundle(s) telecharge(s)");
console.log("\n  --- chemins /api/ distincts (" + apiPaths.size + ") ---");
for (const [p, f] of apiPaths) console.log("    " + p.padEnd(56) + "[" + f + "]");
console.log("\n  --- mecanismes d'auth (" + authBits.size + ") ---");
for (const [a, f] of authBits) console.log("    " + a.padEnd(24) + "[" + f + "]");
console.log("\n  --- extraits sensibles (" + interesting.size + ", echantillon) ---");
let k = 0;
for (const [c, f] of interesting) { if (k++ > 24) break; console.log("    " + c.slice(0, 120) + "  [" + f + "]"); }
