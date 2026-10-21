// CYBERAAR : carte de l API formulaires cyberaar.io/api/* (actif Standard) par differentiel de code
// 404 = inexistant | 405 = existe (POST attendu) | 200 = accessible | 429 = plafond
import fs from "fs";
const SITE = "https://cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = [];
async function probe(path, method = "GET") {
  for (let i = 0; i < 2; i++) {
    try {
      const t0 = Date.now();
      const r = await fetch(SITE + path, { method, headers: { "User-Agent": UA, Accept: "application/json", Origin: SITE, Referer: SITE + "/" }, redirect: "manual", signal: AbortSignal.timeout(20000) });
      const txt = await r.text();
      const rec = { path, method, s: r.status, ms: Date.now() - t0, body: txt.replace(/\s+/g, " ").slice(0, 160) };
      log.push(rec);
      return rec;
    } catch (e) { await sleep(2000); }
  }
  return { s: 0, body: "ERR" };
}
const cls = (r) => (r.s === 404 ? "404" : r.s === 405 ? "405" : r.s === 200 ? "200" : r.s === 429 ? "429" : r.s === 403 ? "403" : String(r.s));

const PATHS = [
  "/api/contact", "/api/apply", "/api/newsletter", "/api/subscribe", "/api/career", "/api/careers",
  "/api/jobs", "/api/spontaneous", "/api/spontanee", "/api/candidature", "/api/application",
  "/api/callback", "/api/webhook", "/api/webhooks", "/api/upload", "/api/files", "/api/file",
  "/api/kyc", "/api/documents", "/api/avatar", "/api/logo", "/api/image", "/api/images",
  "/api/subscribe/newsletter", "/api/v1/contact", "/api/v2/contact", "/api/partner", "/api/partner/apply",
  "/api/demo", "/api/quote", "/api/estimate", "/api/billing", "/api/invoice", "/api/payment",
  "/api/search", "/api/news", "/api/blog", "/api/rss", "/api/auth", "/api/login", "/api/register",
  "/api/lead", "/api/leads", "/api/trial", "/api/signup", "/api/inscription", "/api/account",
  "/api/contact-form", "/api/form", "/api/forms", "/api/feedback", "/api/review", "/api/testimonial",
];
console.log("=== carte de cyberaar.io/api/* (GET, sans corps) ===");
const found = [];
for (const p of PATHS) {
  const r = await probe(p);
  const c = cls(r);
  if (c !== "404") found.push({ p, c, body: r.body });
  console.log("  " + (c === "404" ? " " : "*") + " " + p.padEnd(32) + c + "  " + r.body.slice(0, 90));
  await sleep(1200);
}
console.log("\n=== routes existantes (hors 404) ===");
for (const f of found) console.log("  " + f.p.padEnd(32) + f.c + "  " + f.body);
fs.writeFileSync("/tmp/opencode/cyberaar/api-forms-map.json", JSON.stringify(log, null, 1));
console.log("\n-> " + log.length + " requetes");
