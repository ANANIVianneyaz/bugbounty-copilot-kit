// RECON #5 : les 7 scripts clients (lecture integrale) + pages SSR (donnees inline) + profil public
import fs from "fs";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const OUT = "/tmp/opencode/cyberaar";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function get(url) {
  for (let i = 0; i < 4; i++) {
    try {
      const r = await fetch(url, { headers: { "User-Agent": UA, Accept: "*/*" }, redirect: "manual", signal: AbortSignal.timeout(30000) });
      return { s: r.status, txt: await r.text(), h: Object.fromEntries(r.headers) };
    } catch (e) { await sleep(2500); }
  }
  return { s: 0, txt: "", h: {} };
}

console.log("=== A) les 7 scripts clients : lecture integrale des appels API ===");
const SCRIPTS = ["/aarme-form.js?v=909bcc2f", "/aarme-bg.js?v=18a66ae9", "/aarme-theme.js?v=5df34cc7", "/aarme-nav.js?v=8feecce4", "/aarme-ambient.js?v=cb228fa2", "/aarme-reveal.js?v=f1428a28", "/aarme-form.js"];
for (const s of SCRIPTS) {
  const r = await get("https://aarme.cyberaar.io" + s);
  if (r.s !== 200) { console.log("\n  " + s + " -> HTTP " + r.s); continue; }
  const name = s.split("/").pop().split("?")[0];
  fs.writeFileSync(OUT + "/script-" + name, r.txt);
  console.log("\n  === " + s + " (" + r.txt.length + " car.) ===");
  // appels fetch/XHR
  const calls = [...r.txt.matchAll(/fetch\(\s*[`'"]([^`'"]+)[`'"]\s*(,\s*\{[^}]{0,300}\})?/g)];
  for (const c of calls) console.log("    fetch(" + c[1] + ")" + (c[2] ? " " + c[2].replace(/\s+/g, " ").slice(0, 160) : ""));
  // methodes HTTP
  const meth = [...r.txt.matchAll(/method:\s*["'`]([A-Z]+)["'`]/g)].map((m) => m[1]);
  if (meth.length) console.log("    methodes: " + [...new Set(meth)].join(", "));
  // corps de requete
  const bodies = [...r.txt.matchAll(/body:\s*JSON\.stringify\(([^)]{0,220})\)/g)].map((m) => m[1].replace(/\s+/g, " "));
  if (bodies.length) { console.log("    corps:"); for (const b of [...new Set(bodies)].slice(0, 8)) console.log("      " + b.slice(0, 200)); }
  // en-tetes d'auth
  const auth = [...r.txt.matchAll(/["'`]((?:Authorization|X-[A-Za-z-]+|credentials|credentials|sameSite|secure|httpOnly|localStorage|sessionStorage)[^'"`]{0,60})["'`]/g)].map((m) => m[1]);
  if (auth.length) console.log("    auth/cookies: " + [...new Set(auth)].slice(0, 10).join(" | "));
  // champs de formulaire
  const fields = [...r.txt.matchAll(/name=["']([a-zA-Z_][a-zA-Z0-9_]*)["']/g)].map((m) => m[1]);
  if (fields.length) console.log("    champs de formulaire: " + [...new Set(fields)].join(", "));
  await sleep(400);
}

console.log("\n\n=== B) pages SSR : donnees inline (data-astro-props) ===");
for (const p of ["/compte/", "/soumettre/", "/suivi-rapport/", "/en/h/", "/en/hall-of-fame/", "/en/organisations/", "/en/programmes/", "/organisations/"]) {
  const r = await get("https://aarme.cyberaar.io" + p);
  if (r.s !== 200) { console.log("  " + p.padEnd(24) + "HTTP " + r.s); await sleep(1500); continue; }
  const props = [...r.txt.matchAll(/data-astro-props="([^"]+)"/g)].map((m) => m[1]);
  const islands = [...r.txt.matchAll(/<astro-island[^>]*props="([^"]+)"/g)].map((m) => m[1]);
  let decoded = [];
  for (const s of [...props, ...islands]) {
    try { decoded.push(JSON.parse(s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&"))); } catch {}
  }
  console.log("\n  " + p + "  HTTP " + r.s + " | " + r.txt.length + " car. | " + decoded.length + " bloc(s) de donnees");
  for (const d of decoded.slice(0, 4)) {
    const s = JSON.stringify(d);
    console.log("    " + s.replace(/\s+/g, " ").slice(0, 700));
  }
  fs.writeFileSync(OUT + "/page" + p.replace(/[^\w.-]/g, "_") + ".html", r.txt);
  await sleep(1200);
}
