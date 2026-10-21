const APP="https://aarme.cyberaar.io";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const {writeFileSync}=await import("node:fs");
const email=process.env.EMAIL, password=process.env.PASS, code=process.argv[2];
let cookie="";
const H=(extra={})=>({"Content-Type":"application/json",Accept:"application/json","User-Agent":UA,Origin:APP,Referer:APP+"/compte/",...(cookie?{Cookie:cookie}:{}),...extra});
async function post(path,body){const t0=Date.now();const r=await fetch(APP+path,{method:"POST",headers:H(),body:JSON.stringify(body),redirect:"manual",signal:AbortSignal.timeout(25000)});const t=await r.text();const ck=r.headers.getSetCookie?.()||[];if(ck.length)cookie=ck.map(c=>c.split(";")[0]).join("; ");return{s:r.status,ms:Date.now()-t0,txt:t};}
console.log("=== etape 1 : POST /login {email,password} ===");
const a=await post("/api/aarme/account/login",{email,password});
console.log("  HTTP "+a.s+"  "+a.txt.replace(/\s+/g," ").slice(0,200));
console.log("  cookie de session : "+(cookie||"(aucun)"));
if(!cookie){process.exit(1);}
const isBackup = /backup/i.test(code) || /^\S{6,11}$/.test(code) && !/^\d{6}$/.test(code);
console.log("\n=== etape 2 : POST /login {"+(isBackup?"backup_code":"totp")+"} ("+code+") ===");
const b=await post("/api/aarme/account/login", isBackup?{backup_code:code}:{totp:code});
console.log("  HTTP "+b.s+"  "+b.txt.replace(/\s+/g," ").slice(0,300));
if(b.s===200 && !/mfa_required/.test(b.txt)){
  writeFileSync("/tmp/opencode/cyberaar/session-cookie.txt",cookie+"\n");
  console.log("  -> SESSION ETABLIE, cookie enregistre");
  for(const u of ["/api/aarme/account/session","/api/aarme/account/me"]){
    const s=await fetch(APP+u,{headers:{Accept:"application/json","User-Agent":UA,Origin:APP,Cookie:cookie}});
    console.log("  "+u+" : "+(await s.text()).replace(/\s+/g," ").slice(0,700));
  }
}else{
  console.log("  (session non etablie : le code a echoue ou a expire)");
}
