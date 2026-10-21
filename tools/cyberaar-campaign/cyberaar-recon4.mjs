// RECON #4 : bundles Astro depuis les pages interactives -> surface API complete + schema d'auth
import fs from "fs";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const OUT = "/tmp/opencode/cyberaar";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function get(url) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": UA, Accept: "*/*" }, redirect: "manual", signal: AbortSignal.timeout(25000) });
    return { s: r.status, txt: await r.text(), ct: r.headers.get("content-type") || "" };
  } catch (e) { return { s: 0, txt: "", ct: "" }; }
}
const PAGES = [
  "https://aarme.cyberaar.io/compte/",
  "https://aarme.cyberaar.io/soumettre/",
  "https://aarme.cyberaar.io/suivi-rapport/",
  "https://aarme.cyberaar.io/programmes/cyberaar/",
  "https://aarme.cyberaar.io/organisations/",
  "https://aarme.cyberaar.io/palmares/",
  "https://aarme.cyberaar.io/en/account/",
  "https://aarme.cyberaar.io/en/h/",
  "https://aarme.cyberaar.io/en/hall-of-fame/",
  "https://aarme.cyberaar.io/en/organisations/",
  "https://aarme.cyberaar.io/en/programmes/",
  "https://cyberaar.io/",
];
const chunkSet = new Set();
const pageInfo = [];
for (const p of PAGES) {
  const r = await get(p);
  const chunks = [...new Set([...r.txt.matchAll(/\/_astro\/[A-Za-z0-9._-]+\.(?:js|mjs)/g)].map((m) => m[0]))];
  const scripts = [...new Set([...r.txt.matchAll(/<script[^>]+src="([^"]+)"/gi)].map((m) => m[1]))];
  for (const c of chunks) chunkSet.add(c);
  pageInfo.push({ p, s: r.s, len: r.txt.length, chunks: chunks.length, scripts: scripts.length, title: (r.txt.match(/<title[^>]*>([^<]*)<\/title>/i) || [])[1] });
  console.log("  " + p.replace("https://", "").padEnd(42) + "HTTP " + r.s + " " + String(r.txt.length).padStart(7) + " car. | chunks " + chunks.length + " | scripts " + scripts.length + " | " + ((r.txt.match(/<title[^>]*>([^<]*)<\/title>/i) || [])[1] || ""));
  await sleep(250);
}
console.log("\n  total chunks distincts : " + chunkSet.size);

console.log("\n=== analyse des chunks ===");
const apiPaths = new Map(), authBits = new Map(), hosts = new Set(), interest = new Map();
const PATHS = /["'`](\/api\/[A-Za-z0-9\/_\-\.{}$%]{2,140})["'`]/g;
const REL = /["'`](\/(?:compte|soumettre|suivi-rapport|programmes|organisations|palmares|admin|api)[A-Za-z0-9\/_\-\.{}$%]{0,80})["'`]/g;
const AUTH = /(localStorage|sessionStorage|document\.cookie|Authorization|Bearer|X-AarMe-Researcher|csrf|xsrf|credentials:\s*["']include|sameSite|httpOnly|secure)/gi;
const INTEREST = /(s3|amazonaws|cloudfront|upload|avatar|logo|webhook|payout|kyc|invoice|rib|bank|password|reset|2fa|totp|otp|magic|invite|refresh|admin|internal|debug|graphiql|playground|role|permission|scope)/gi;
let n = 0, bytes = 0;
for (const c of chunkSet) {
  const r = await get("https://aarme.cyberaar.io" + c);
  if (r.s !== 200) { console.log("  " + c.slice(0, 70).padEnd(72) + "HTTP " + r.s); continue; }
  n++; bytes += r.txt.length;
  fs.writeFileSync(OUT + "/chunk-" + c.split("/").pop(), r.txt);
  for (const m of r.txt.matchAll(PATHS)) if (!apiPaths.has(m[1])) apiPaths.set(m[1], c.split("/").pop());
  for (const m of r.txt.matchAll(REL)) if (!apiPaths.has(m[1])) apiPaths.set(m[1], c.split("/").pop() + " (route)");
  for (const m of r.txt.matchAll(AUTH)) if (!authBits.has(m[1])) authBits.set(m[1], c.split("/").pop());
  for (const m of r.txt.matchAll(/https?:\/\/[A-Za-z0-9._:-]+/g)) hosts.add(m[0]);
  for (const m of r.txt.matchAll(INTEREST)) {
    const ctx = r.txt.slice(Math.max(0, m.index - 70), m.index + 70).replace(/\s+/g, " ");
    if (!interest.has(ctx)) interest.set(ctx, c.split("/").pop());
  }
  await sleep(120);
}
console.log("  " + n + " chunk(s) telecharge(s), " + (bytes / 1024).toFixed(0) + " Ko");
console.log("\n  --- chemins /api/ et routes (" + apiPaths.size + ") ---");
for (const [p, f] of apiPaths) console.log("    " + p.padEnd(58) + "[" + f + "]");
console.log("\n  --- mecanismes d'auth (" + authBits.size + ") ---");
for (const [a, f] of authBits) console.log("    " + a.padEnd(26) + "[" + f + "]");
console.log("\n  --- hotes ---");
for (const h of hosts) console.log("    " + h);
console.log("\n  --- extraits sensibles (echantillon) ---");
let k = 0;
for (const [c, f] of interest) { if (k++ > 30) break; console.log("    " + c.slice(0, 130) + "  [" + f + "]"); }
fs.writeFileSync(OUT + "/surface.json", JSON.stringify({ pageInfo, apiPaths: [...apiPaths], auth: [...authBits], hosts: [...hosts] }, null, 1));
