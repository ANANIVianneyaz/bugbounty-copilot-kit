// RECON CIBLEE CyberAar / AarMe - requetes GET/HEAD uniquement, ciblees, pas de scan.
// 3 actifs du perimetre : aarme.cyberaar.io (Critique), cyberaar.io/api/* (Standard), cyberaar.io (Standard)
import fs from "fs";
import crypto from "crypto";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const OUT = "/tmp/opencode/cyberaar";
fs.mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = [];

async function get(url, opts = {}) {
  const t0 = Date.now();
  try {
    const r = await fetch(url, { method: opts.m || "GET", headers: { "User-Agent": UA, Accept: opts.accept || "*/*", ...(opts.h || {}) }, redirect: opts.redirect || "manual", signal: AbortSignal.timeout(25000) });
    const txt = await r.text();
    const rec = { url, s: r.status, ms: Date.now() - t0, ct: r.headers.get("content-type") || "", loc: r.headers.get("location") || "", headers: Object.fromEntries(r.headers), len: txt.length, body: txt.slice(0, 400) };
    log.push(rec);
    return { ...rec, txt };
  } catch (e) {
    const rec = { url, s: 0, ms: Date.now() - t0, ct: "", loc: "", headers: {}, len: 0, body: "ERR " + (e.cause?.code || e.message) };
    log.push(rec);
    return { ...rec, txt: "" };
  }
}
const show = (l, r) => console.log("  " + l.padEnd(46) + String(r.s).padEnd(4) + (r.ms + "ms").padEnd(8) + (r.ct.split(";")[0] || "-").padEnd(26) + (r.loc ? "-> " + r.loc.slice(0, 60) : r.body.replace(/\s+/g, " ").slice(0, 70)));

console.log("=== A) racine des 3 actifs ===");
const roots = ["https://aarme.cyberaar.io/", "https://cyberaar.io/", "https://cyberaar.io/api/"];
const pages = {};
for (const u of roots) {
  const r = await get(u);
  show(u, r);
  pages[u] = r;
  const h = r.headers;
  const tech = [h["x-powered-by"], h["server"], h["x-nextjs-cache"], h["via"], h["cf-ray"] ? "cloudflare" : null, h["x-vercel-id"] ? "vercel" : null, h["x-amz-cf-id"] ? "cloudfront" : null].filter(Boolean);
  if (tech.length) console.log("      techno: " + tech.join(" | "));
  const ck = h["set-cookie"] ? String(h["set-cookie"]).split(/, (?=[A-Za-z0-9_-]+=)/).map((c) => c.split("=")[0].trim()).join(", ") : "";
  if (ck) console.log("      cookies: " + ck);
  const ttl = h["strict-transport-security"] ? h["strict-transport-security"].slice(0, 80) : "";
  if (ttl) console.log("      hsts: " + ttl);
  const csp = h["content-security-policy"] ? h["content-security-policy"].slice(0, 200) : "";
  if (csp) console.log("      csp: " + csp);
  await sleep(400);
}

console.log("\n=== B) metadonnees & politique ===");
for (const u of [
  "https://cyberaar.io/.well-known/security.txt",
  "https://aarme.cyberaar.io/.well-known/security.txt",
  "https://cyberaar.io/robots.txt",
  "https://cyberaar.io/sitemap.xml",
  "https://aarme.cyberaar.io/robots.txt",
  "https://aarme.cyberaar.io/.well-known/openid-configuration",
  "https://aarme.cyberaar.io/.well-known/oauth-protected-resource",
  "https://cyberaar.io/.well-known/oauth-authorization-server",
]) {
  const r = await get(u);
  show(u.replace("https://", ""), r);
  if (r.s === 200 && r.len < 3000) console.log("      " + r.txt.replace(/\s+/g, " ").slice(0, 500));
  await sleep(300);
}

console.log("\n=== C) scripts et bundles de aarme.cyberaar.io ===");
const html = pages["https://aarme.cyberaar.io/"].txt || "";
const title = (html.match(/<title[^>]*>([^<]*)<\/title>/i) || [])[1];
console.log("  title:", title);
const metas = [...html.matchAll(/<meta[^>]+(?:name|property)="([^"]+)"[^>]+content="([^"]*)"/gi)].map((m) => m[1] + "=" + m[2].slice(0, 60));
console.log("  metas :", metas.slice(0, 12).join(" | "));
const scripts = [...new Set([...html.matchAll(/<script[^>]+src="([^"]+)"/gi)].map((m) => m[1]))];
const links = [...new Set([...html.matchAll(/<link[^>]+href="([^"]+)"/gi)].map((m) => m[1]))];
console.log("  " + scripts.length + " script(s) :", scripts.slice(0, 10).join("\n                      "));
console.log("  " + links.length + " link(s) :", links.filter((l) => !/\.(css|woff2?|ttf|eot)$/i.test(l)).slice(0, 8).join(" | "));
// endpoints cites en clair dans le HTML
const inline = [...html.matchAll(/https?:\/\/[A-Za-z0-9._:\/-]+/g)].map((m) => m[0]);
const apiPaths = [...new Set([...html.matchAll(/["'`]\/(api|graphql|v1|v2|auth|oauth|_next\/api)[A-Za-z0-9\/_\-\.{}$]*/g)].map((m) => m[0]))];
console.log("  URLs en clair :", [...new Set(inline)].slice(0, 10).join(" | "));
console.log("  chemins API en clair :", apiPaths.slice(0, 15).join(" | "));

console.log("\n=== D) contenu des bundles : surface API, auth, stockage ===");
const INTEREST = /(https?:\/\/[A-Za-z0-9._:-]+)|(\/(api|graphql|oauth|auth|uploads?|files?|s3|admin|triage|payout|invoices?|kyc|webhook)\/[A-Za-z0-9\/_\-\.${}]*)|(Bearer [A-Za-z0-9._-]{8,})|((?:api[_-]?key|secret|password|token)["'\s:=]{1,4}[A-Za-z0-9._-]{12,})/gi;
const found = new Map();
for (const s of scripts.slice(0, 12)) {
  const u = s.startsWith("http") ? s : "https://aarme.cyberaar.io" + s;
  const r = await get(u);
  if (r.s !== 200) { console.log("  " + s.slice(0, 70).padEnd(72) + "HTTP " + r.s); continue; }
  const name = s.split("/").pop().slice(0, 40);
  console.log("  " + s.slice(0, 70).padEnd(72) + "HTTP " + r.s + " " + (r.len / 1024).toFixed(0) + " Ko");
  fs.writeFileSync(OUT + "/bundle-" + name.replace(/[^\w.-]/g, "_"), r.txt);
  for (const m of r.txt.matchAll(INTEREST)) {
    const v = m[0].slice(0, 120);
    if (!found.has(v)) found.set(v, name);
  }
  await sleep(300);
}
console.log("\n  --- extraits d interet (" + found.size + ") ---");
const groups = { "hotes": [], "chemins api": [], "auth/secret": [] };
for (const [v, f] of found) {
  if (/^https?:\/\//.test(v)) groups.hotes.push(v + "   [" + f + "]");
  else if (/\/(api|graphql|oauth|auth|uploads?|files?|s3|admin|triage|payout|invoices?|kyc|webhook)\//i.test(v)) groups["chemins api"].push(v + "   [" + f + "]");
  else groups["auth/secret"].push(v + "   [" + f + "]");
}
for (const [k, v] of Object.entries(groups)) {
  console.log("  [" + k + "]");
  for (const x of v.slice(0, 30)) console.log("    " + x);
}

fs.writeFileSync(OUT + "/recon-log.json", JSON.stringify(log, null, 1));
console.log("\n-> " + OUT + "/recon-log.json (" + log.length + " requetes)");
