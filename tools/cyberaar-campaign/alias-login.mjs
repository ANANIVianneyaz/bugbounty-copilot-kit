const APP="https://aarme.cyberaar.io";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const {writeFileSync}=await import("node:fs");
const email="vianney24lechancelier+bb1@gmail.com", password="Bb-test-2026-ok!";
const r=await fetch(APP+"/api/aarme/account/login",{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json","User-Agent":UA,Origin:APP,Referer:APP+"/compte/"},body:JSON.stringify({email,password}),redirect:"manual",signal:AbortSignal.timeout(25000)});
const t=await r.text();
const ck=r.headers.getSetCookie?.()||[];
console.log("  login alias : HTTP "+r.status+"  "+t.replace(/\s+/g," ").slice(0,220));
console.log("  cookies : "+(ck.map(c=>c.split(";")[0]).join(" | ")||"(aucun)"));
if(ck.length && r.status===200 && !/mfa_required/.test(t)){
  const cookie=ck.map(c=>c.split(";")[0]).join("; ");
  writeFileSync("/tmp/opencode/cyberaar/session-cookie.txt", cookie+"\n");
  console.log("  -> SESSION SANS 2FA OBTENUE (compte alias)");
  const me=await fetch(APP+"/api/aarme/account/me",{headers:{Accept:"application/json","User-Agent":UA,Origin:APP,Cookie:cookie}});
  console.log("  me : "+(await me.text()).replace(/\s+/g," ").slice(0,300));
} else if(/mfa_required/.test(t)){
  console.log("  -> le compte existe mais exige la 2FA (j aurais le code TOTP a fournir)");
}
