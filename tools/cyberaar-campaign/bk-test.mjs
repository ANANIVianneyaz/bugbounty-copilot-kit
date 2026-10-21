import fs from "fs";
const APP="https://aarme.cyberaar.io";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE=fs.readFileSync("/tmp/opencode/cyberaar/session-cookie.txt","utf8").trim();
const PASS=process.env.PASS;
async function post(path,body){const t0=Date.now();const r=await fetch(APP+path,{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json","User-Agent":UA,Origin:APP,Referer:APP+"/compte/",Cookie:COOKIE},body:JSON.stringify(body),redirect:"manual",signal:AbortSignal.timeout(25000)});const t=await r.text();return{s:r.status,ms:Date.now()-t0,txt:t};}
const show=(l,r)=>console.log("  "+l.padEnd(52)+"HTTP "+r.s+" "+String(r.ms).padStart(5)+"ms  "+r.txt.replace(/\s+/g," ").slice(0,260));
show("backup-codes {current: VRAI mdp, totp: 000000}",await post("/api/aarme/account/totp/backup-codes",{current:PASS,totp:"000000"}));
await new Promise(r=>setTimeout(r,2500));
show("backup-codes {current: VRAI mdp} (sans totp)",await post("/api/aarme/account/totp/backup-codes",{current:PASS}));
await new Promise(r=>setTimeout(r,2500));
show("backup-codes {current: VRAI mdp, totp: type invalide}",await post("/api/aarme/account/totp/backup-codes",{current:PASS,totp:["0"]}));
