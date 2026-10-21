const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function get(u){try{const r=await fetch(u,{headers:{"User-Agent":UA,Accept:"text/html,*/*"},redirect:"manual",signal:AbortSignal.timeout(25000)});return{s:r.status,txt:await r.text()};}catch(e){return{s:0,txt:"ERR "+e.message};}}
console.log("=== A) le mecanisme reel du formulaire de contact (HTML brut) ===");
const r=await get("https://cyberaar.io/contact/");
if(r.s===200){
  const fs=await import("node:fs");
  fs.writeFileSync("/tmp/opencode/cyberaar/contact.html", r.txt);
  const forms=[...r.txt.matchAll(/<form[\s\S]{0,1200}?<\/form>/gi)].map(m=>m[0]);
  console.log("  "+forms.length+" formulaire(s) :");
  for(const f of forms){
    const attrs=f.match(/<form[^>]*>/i)?.[0]||"";
    const names=[...new Set([...f.matchAll(/name="([^"]+)"/g)].map(m=>m[1]))];
    const method=(attrs.match(/method="([^"]+)"/i)||[])[1];
    const action=(attrs.match(/action="([^"]+)"/i)||[])[1];
    const inline=[...f.matchAll(/<script[^>]*>([\s\S]{0,4000}?)<\/script>/gi)].map(m=>m[1]).join(" ").replace(/\s+/g," ");
    const fetches=[...inline.matchAll(/fetch\([^)]*\)/g)].map(m=>m[0]);
    console.log("   attrs : "+attrs.replace(/\s+/g," ").slice(0,160));
    console.log("   method="+(method||"(defaut GET)")+" action="+(action||"(aucun)"));
    console.log("   champs : "+names.join(", "));
    if(fetches.length) console.log("   fetch inline : "+fetches.slice(0,4).join(" | ").slice(0,300));
  }
  // scripts inline de la page (hors formulaire)
  const inlineAll=[...r.txt.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]{0,6000}?)<\/script>/gi)].map(m=>m[1]).join("\n");
  const apiRefs=[...new Set([...inlineAll.matchAll(/['"`](\/[A-Za-z0-9\/_\-\.]*api[A-Za-z0-9\/_\-\.]*)['"`]/g)].map(m=>m[1]))];
  console.log("  references /api dans les scripts inline : "+(apiRefs.join(", ")||"(aucune)"));
  const fetchAll=[...inlineAll.matchAll(/fetch\(\s*[`'"]([^`'"]+)[`'"]/g)].map(m=>m[1]);
  console.log("  fetch() en dur : "+(fetchAll.join(", ")||"(aucun)"));
}
await sleep(1500);
console.log("\n=== B) www.cyberaar.io (actif Standard) : identique a cyberaar.io ? ===");
const w=await get("https://www.cyberaar.io/contact/");
console.log("  /contact/ -> HTTP "+w.s+" | "+(w.s===200?w.txt.length+" car.":""));
await sleep(1500);
console.log("\n=== C) la page de contact de cyberaar.io : autres indices (mailto, action externe) ===");
const c2=await get("https://cyberaar.io/contact/");
const mailtos=[...new Set((c2.txt.match(/mailto:[^"'\s]+/g)||[]))];
const thirds=[...new Set((c2.txt.match(/https?:\/\/(?!cyberaar\.io|www\.cyberaar\.io|schema\.org|fonts\.|cdn\.)[A-Za-z0-9._-]+\.[A-Za-z]{2,}[^\s"']*/g)||[]))];
console.log("  mailto : "+(mailtos.join(", ")||"(aucun)"));
console.log("  domaines tiers : "+(thirds.slice(0,10).join(", ")||"(aucun)"));
