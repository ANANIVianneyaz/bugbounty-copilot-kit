import fs from "fs";
const EP="https://bugsecure-api.senintel.sn/graphql";
const T=process.env.BB_TOKEN;
const MAIL="bbtest4926@maxxspace.com";
const MJWT=fs.readFileSync("/tmp/opencode/mail_token.txt","utf8").trim();
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
const call=async(q,v)=>{const r=await fetch(EP,{method:"POST",headers:{"Content-Type":"application/json",...(T?{Authorization:"Bearer "+T}:{})},body:JSON.stringify({query:q,variables:v||{}})});const t=await r.text();let j=null;try{j=JSON.parse(t)}catch{};return{s:r.status,t,j}};
const show=(l,r,m=300)=>console.log("  "+l.padEnd(46)+"HTTP "+r.s+"  "+(r.j?.errors?"ERR: "+r.j.errors.map(x=>x.message).join(" | "):JSON.stringify(r.j?.data)).slice(0,m));
console.log("=== 1) requestEmailChange vers notre boite ("+MAIL+") ===");
show("requestEmailChange", await call(`mutation($i:RequestEmailChangeInput!){ requestEmailChange(input:$i) }`,{i:{currentPassword:"bb-test-2026!",newEmail:MAIL}}),400);
await sleep(3000);
console.log("\n=== 2) inbox : le token de confirmation est arrive ? ===");
let tokFound=null;
for(let i=0;i<6;i++){
  const r=await fetch("https://api.mail.tm/messages",{headers:{Authorization:"Bearer "+MJWT}});
  const j=await r.json();
  const list=j["hydra:member"]||[];
  if(list.length){
    for(const m of list){
      const full=await (await fetch("https://api.mail.tm/messages/"+m.id,{headers:{Authorization:"Bearer "+MJWT}})).json();
      console.log("  sujet : "+(full.subject||"").slice(0,90));
      console.log("  texte : "+String(full.text||"").replace(/\s+/g," ").slice(0,400));
      const mm=String(full.text||"").match(/[A-Fa-f0-9]{32,}/) || String(full.html||"").match(/[A-Fa-f0-9]{32,}/);
      if(mm) tokFound=mm[0];
    }
    break;
  }
  console.log("  (en attente... "+(i+1)+")");
  await sleep(5000);
}
if(tokFound){
  console.log("\n  token de confirmation : "+tokFound);
  console.log("=== 3) confirmEmailChange ===");
  show("confirmEmailChange", await call(`mutation($t:String!){ confirmEmailChange(token:$t) }`,{t:tokFound}),400);
} else console.log("\n  (aucun token recu -> je repete la demande)");
