import { ensureToken } from "/tmp/opencode/token-store.mjs";
const AS="https://bugsecure-api.senintel.sn", EP=AS+"/graphql";
const { token } = await ensureToken(AS);
const H={"Content-Type":"application/json",Authorization:"Bearer "+token};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const cands=["NEW","IN_TRIAGE","TRIAGE","OPEN","CLOSED","FIXED","DUPLICATE","NEEDS_MORE_INFO","INFORMATIVE","IN_FIX","PENDING","RESOLVED","REJECTED","IN_PROGRESS","UNDER_REVIEW","WAITING","ACCEPTED","DISPUTED"];
console.log("=== valeurs acceptees de l enum ReportStatus (coté API) ===");
const valid=[];
for(const s of cands){
  const r=await fetch(EP,{method:"POST",headers:H,body:JSON.stringify({query:`mutation { updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"${s}"}) { id } }`})});
  const t=await r.text();
  let j=null;try{j=JSON.parse(t)}catch{}
  const m=(j?.errors||[]).map(e=>e.message).join(" | ");
  const isEnum=m.includes("cannot represent non-enum value");
  console.log("  "+s.padEnd(18)+(isEnum?"INVALIDE":"autre")+"  "+(isEnum?"":m.slice(0,110)));
  if(!isEnum) valid.push(s);
  await sleep(250);
}
console.log("\nvalides selon l API :",valid.join(", ")||"(aucune)");
