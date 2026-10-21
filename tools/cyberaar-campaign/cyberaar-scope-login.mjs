const APP="https://aarme.cyberaar.io";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function req(u,o={}){const t0=Date.now();try{const r=await fetch(u,{method:o.m||"GET",headers:{"User-Agent":UA,Accept:o.accept||"*/*",...(o.h||{})},redirect:"manual",signal:AbortSignal.timeout(25000)});const t=await r.text();return{s:r.status,txt:t,ms:Date.now()-t0,h:Object.fromEntries(r.headers),cookies:r.headers.getSetCookie?.()||[]};}catch(e){return{s:0,txt:"ERR "+e.message,ms:Date.now()-t0,h:{},cookies:[]};}}
const show=(l,r)=>console.log("  "+l.padEnd(46)+"HTTP "+r.s+" "+String(r.ms).padStart(5)+"ms  "+r.txt.replace(/\s+/g," ").slice(0,150));
console.log("=== A) le perimetre EXACT des actifs (JSON complet) ===");
const pr=await req(APP+"/api/aarme/programmes",{accept:"application/json"});
console.log(JSON.stringify(JSON.parse(pr.txt),null,1));
await sleep(1500);
console.log("\n=== B) le leaderboard complet (tous les champs) ===");
const lb=await req(APP+"/api/aarme/leaderboard",{accept:"application/json"});
console.log(JSON.stringify(JSON.parse(lb.txt),null,1));
await sleep(1500);
console.log("\n=== C) l endpoint de connexion : POST /api/aarme/account/login ===");
for(const [l,b] of [
  ["corps vide",{}],
  ["email existant (handle trixx) + faux mdp",{email:"trixx",password:"mauvais-mot-de-passe"}],
  ["email inexistant",{email:"inconnu-zzz-4242@maxxspace.com",password:"mauvais-mot-de-passe"}],
  ["sans email",{password:"x"}],
  ["champ login au lieu de email",{login:"trixx",password:"x"}],
  ["password en tableau",{email:"trixx",password:["a","b"]}],
  ["mass assignment au login",{email:"trixx",password:"x",role:"admin",isAdmin:true,level:"expert"}],
]){
  const r=await req(APP+"/api/aarme/account/login",{m:"POST",accept:"application/json",h:{"Content-Type":"application/json",Origin:APP,Referer:APP+"/compte/"}});
  // corps envoye
  const rr=await fetch(APP+"/api/aarme/account/login",{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json","User-Agent":UA,Origin:APP,Referer:APP+"/compte/"},body:JSON.stringify(b),redirect:"manual",signal:AbortSignal.timeout(25000)});
  const t=await rr.text();
  console.log("  "+l.padEnd(46)+"HTTP "+rr.status+"  "+t.replace(/\s+/g," ").slice(0,140));
  if(rr.status===200||rr.status===401){ if(rr.headers.getSetCookie) { const ck=rr.headers.getSetCookie(); if(ck.length) console.log("      cookies: "+ck.map(c=>c.split(";")[0]).join(" | ")); } }
  await sleep(1800);
}
