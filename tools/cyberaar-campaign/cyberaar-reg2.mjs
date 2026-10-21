const BASE="https://aarme.cyberaar.io";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function post(path,b,h={}){
  const r=await fetch(BASE+path,{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json","User-Agent":UA,Origin:BASE,Referer:BASE+"/compte/",...h},body:JSON.stringify(b),redirect:"manual",signal:AbortSignal.timeout(25000)});
  const t=await r.text();
  return {s:r.status,txt:t,cookies:r.headers.getSetCookie?.()||[]};
}
const body={name:"bb-probe",email:process.env.EM,profile:"Chercheur securite - test de la surface AarMe",level:"debutant",password:"Bb-test-2026-ok!",accord:true,lang:"fr",hp:""};
console.log("=== inscription avec l alias : "+body.email+" ===");
const r=await post("/api/aarme/account/register",body);
console.log("  HTTP "+r.s+"  "+r.txt.replace(/\s+/g," ").slice(0,500));
console.log("  cookies :", r.cookies.map(c=>c.split(";")[0]).join(" | ")||"(aucun)");
for(const c of r.cookies) console.log("     "+c);
if(r.s===200||r.s===201){
  const ck=r.cookies.map(c=>c.split(";")[0]).join("; ");
  if(ck){
    const s=await fetch(BASE+"/api/aarme/account/session",{headers:{Accept:"application/json","User-Agent":UA,Cookie:ck,Origin:BASE}});
    console.log("  session :",(await s.text()).replace(/\s+/g," ").slice(0,500));
    console.log("  COOKIE="+ck);
  }
}
