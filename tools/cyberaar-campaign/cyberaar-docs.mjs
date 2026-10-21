// CYBERAAR : lecture de la documentation (dans le perimetre : cyberaar.io/docs/...) + endpoint de soumission
import fs from "fs";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function get(u, o = {}) {
  try {
    const r = await fetch(u, { headers: { "User-Agent": UA, Accept: o.accept || "text/html,*/*" }, redirect: o.redirect || "manual", signal: AbortSignal.timeout(25000) });
    return { s: r.status, txt: await r.text(), loc: r.headers.get("location") || "", h: Object.fromEntries(r.headers) };
  } catch (e) { return { s: 0, txt: "ERR " + e.message, loc: "", h: {} }; }
}
const clean = (s) => s.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/\s+/g, " ");

console.log("=== 1) /signaler-vulnerabilite : ou ca redirige ? ===");
const sv = await get("https://cyberaar.io/signaler-vulnerabilite");
console.log("  HTTP " + sv.s + " -> " + (sv.loc || "(pas de redirection)"));
if (sv.loc) {
  const t = await get(new URL(sv.loc, "https://cyberaar.io").href);
  console.log("  cible : HTTP " + t.s + " | " + t.txt.length + " car.");
  const forms = [...t.txt.matchAll(/<form[\s\S]*?<\/form>/gi)].map((m) => m[0]);
  for (const f of forms) {
    console.log("    champs : " + [...new Set([...f.matchAll(/name="([^"]+)"/g)].map((m) => m[1]))].join(", "));
    console.log("    fichier : " + ([...f.matchAll(/type="file"[^>]*>/g)].map((m) => m[0].replace(/\s+/g, " ").slice(0, 110)).join(" | ") || "aucun"));
  }
  console.log("  texte : " + clean(t.txt).slice(0, 500));
}
await sleep(1500);

console.log("\n=== 2) la doc de l API AarView (dans le perimetre) ===");
for (const p of ["/docs/aarview/api/", "/docs/aarview/securite/", "/docs/aarview/federation-identite/"]) {
  const r = await get("https://cyberaar.io" + p);
  console.log("\n  --- " + p + "  HTTP " + r.s + " (" + r.txt.length + " car.)");
  if (r.s === 200) {
    fs.writeFileSync("/tmp/opencode/cyberaar/doc-" + p.replace(/[^\w.-]/g, "_") + ".html", r.txt);
    const t = clean(r.txt);
    console.log("  " + t.slice(0, 1500).replace(/(.{116})/g, "$1\n  "));
  }
  await sleep(1500);
}

console.log("\n=== 3) l endpoint de soumission de rapport (AarMe) : le chunk de lilot ===");
const so = await get("https://aarme.cyberaar.io/soumettre/");
if (so.s === 200) {
  fs.writeFileSync("/tmp/opencode/cyberaar/soumettre.html", so.txt);
  const scripts = [...new Set([...so.txt.matchAll(/<script[^>]+src="([^"]+)"/gi)].map((m) => m[1]))];
  const inline = [...so.txt.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]{0,20000}?)<\/script>/gi)].map((m) => m[1]).join("\n");
  const apiRefs = [...new Set([...inline.matchAll(/['"`](\/api\/[A-Za-z0-9\/_\-\.]*)['"`]/g)].map((m) => m[1]))];
  const fetches = [...inline.matchAll(/fetch\(\s*[`'"]([^`'"]+)[`'"](\s*,\s*\{[\s\S]{0,400}?\})?/g)].map((m) => m[0]);
  console.log("  scripts externes : " + scripts.join(" "));
  console.log("  /api en clair (inline) : " + (apiRefs.join(", ") || "(aucun)"));
  for (const f of fetches.slice(0, 6)) console.log("  fetch : " + f.replace(/\s+/g, " ").slice(0, 300));
  const fd = [...inline.matchAll(/new FormData\(\)/g)].length;
  console.log("  FormData dans le script inline : " + fd + " occurrence(s)");
  const fieldNames = [...new Set([...inline.matchAll(/append\(\s*['"`]([a-zA-Z_-]+)['"`]/g)].map((m) => m[1]))];
  console.log("  champs ajoutes au FormData : " + (fieldNames.join(", ") || "(aucun)"));
}
