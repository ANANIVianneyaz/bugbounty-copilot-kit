// Observe la levee du plafond d entree : 1 requete / 45 s, corps invalide (aucune donnee creee)
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const {appendFileSync}=await import("node:fs");
const LOG="/tmp/opencode/cyberaar/ratelimit-watch.log";
const note=s=>{console.log(s);try{appendFileSync(LOG,s+"\n")}catch{}};
for(let i=1;i<=40;i++){
  const t0=Date.now();
  let s=0,txt="";
  try{
    const r=await fetch("https://cyberaar.io/api/contact",{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json","User-Agent":UA,Origin:"https://cyberaar.io",Referer:"https://cyberaar.io/contact/"},body:JSON.stringify({name:"probe",email:"invalide",subject:"x",message:"x"}),redirect:"manual",signal:AbortSignal.timeout(25000)});
    s=r.status; txt=await r.text();
  }catch(e){txt="ERR "+e.message}
  const limited=s===429;
  note(`[${new Date().toISOString()}] probe ${i} : HTTP ${s} ${Date.now()-t0}ms ${txt.replace(/\s+/g," ").slice(0,90)}`);
  if(!limited && s===400) { note("=> plafond leve (reponse de validation, pas de rate limit)"); break; }
  await new Promise(r=>setTimeout(r,45000));
}
