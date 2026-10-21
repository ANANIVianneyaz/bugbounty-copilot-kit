const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function get(u){try{const r=await fetch(u,{headers:{"User-Agent":UA,Accept:"*/*"},redirect:"manual",signal:AbortSignal.timeout(25000)});return{s:r.status,txt:await r.text()};}catch(e){return{s:0,txt:"ERR "+e.message};}}
async function post(u,b,h={}){const r=await fetch(u,{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json","User-Agent":UA,...h},body:JSON.stringify(b),redirect:"manual",signal:AbortSignal.timeout(25000)});return{s:r.status,txt:await r.text()};}
const show=(l,r)=>console.log("  "+l.padEnd(46)+"HTTP "+r.s+"  "+r.txt.replace(/\s+/g," ").slice(0,150));
console.log("=== A) les scripts de cyberaar.io : appels de formulaire ===");
const home=await get("https://cyberaar.io/");
const srcs=[...new Set([...home.txt.matchAll(/<script[^>]+src="([^"]+)"/gi)].map(m=>m[1]))];
console.log("  scripts:",srcs.join(" "));
for(const s of srcs){
  const r=await get(s.startsWith("http")?s:"https://cyberaar.io"+s);
  if(r.s!==200) continue;
  const calls=[...r.txt.matchAll(/fetch\(\s*[`'"]([^`'"]+)[`'"](\s*,\s*\{[^}]{0,260}\})?/g)];
  const bodies=[...r.txt.matchAll(/body:\s*JSON\.stringify\(([^)]{0,300})\)/g)].map(m=>m[1].replace(/\s+/g," "));
  const fields=[...new Set([...r.txt.matchAll(/name=["']([a-zA-Z_][a-zA-Z0-9_]*)["']/g)].map(m=>m[1]))];
  const forms=[...new Set([...r.txt.matchAll(/action=["']([^"']+)["']/g)].map(m=>m[1]))];
  console.log("\n  --- "+s.split("/").pop()+" ("+r.txt.length+" car.) ---");
  for(const c of calls) console.log("      fetch("+c[1]+")"+(c[2]?" "+c[2].replace(/\s+/g," ").slice(0,150):""));
  for(const b of bodies) console.log("      body: "+b.slice(0,220));
  if(fields.length) console.log("      champs: "+fields.join(", "));
  if(forms.length) console.log("      actions: "+forms.join(", "));
  await sleep(300);
}
console.log("\n=== B) les endpoints de formulaire : POST (avec Origin same-origin) ===");
for(const u of ["https://cyberaar.io/api/contact","https://cyberaar.io/api/apply"]){
  show(u+" (corps vide)",await post(u,{},{Origin:"https://cyberaar.io",Referer:"https://cyberaar.io/"}));
  await sleep(1500);
}
console.log("\n=== C) la page de contact : quels champs ? ===");
for(const p of ["/contact","/contact/","/devenir-partenaire","/rejoindre"]){
  const r=await get("https://cyberaar.io"+p);
  if(r.s===200){
    const fields=[...new Set([...r.txt.matchAll(/name=["']([a-zA-Z_][a-zA-Z0-9_]*)["']/g)].map(m=>m[1]))];
    const acts=[...new Set([...r.txt.matchAll(/action=["']([^"']+)["']/g)].map(m=>m[1]))];
    const ins=[...new Set([...r.txt.matchAll(/\/api\/[A-Za-z0-9\/_\-]+/g)].map(m=>m[0]))];
    console.log("  "+p+"  HTTP 200 | champs: "+(fields.join(", ")||"-")+" | actions: "+(acts.join(", ")||"-")+" | api: "+(ins.join(" ")||"-"));
  } else console.log("  "+p+"  HTTP "+r.s);
  await sleep(300);
}
