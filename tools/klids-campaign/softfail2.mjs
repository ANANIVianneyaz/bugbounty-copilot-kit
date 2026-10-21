import fs from "fs";
const EP="https://bugsecure-api.senintel.sn/graphql";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const T_ORG=fs.readFileSync("/tmp/opencode/orgtoken.txt","utf8").trim();
const R="0d06701f-d109-4280-b10e-8a923fa69346", F="11111111-2222-3333-4444-555555555555";
async function gql(tok,query,variables){const r=await fetch(EP,{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+tok},body:JSON.stringify({query,variables})});const t=await r.text();let j=null;try{j=JSON.parse(t)}catch{};return j;}
const fmt=j=>(j?.errors?"ERR: "+j.errors.map(x=>x.message).join(" | "):JSON.stringify(j?.data)).replace(/\s+/g," ").slice(0,150);
const CASES=[
  ["payoutSummary  (org reelle)",`query($orgId:ID!){ payoutSummary(orgId:$orgId, months:6){ month count avgBounty totalPaid } }`,R],
  ["payoutSummary  (inexistante)",`query($orgId:ID!){ payoutSummary(orgId:$orgId, months:6){ month count avgBounty totalPaid } }`,F],
  ["reportTrends   (org reelle)",`query($orgId:ID!){ reportTrends(orgId:$orgId, months:6){ date count status } }`,R],
  ["reportTrends   (inexistante)",`query($orgId:ID!){ reportTrends(orgId:$orgId, months:6){ date count status } }`,F],
  ["organizationStanding (org reelle)",`query($orgId:ID!){ organizationStanding(orgId:$orgId){ totalIssued currentlyOverdue submissionsSuspended } }`,R],
  ["organizationStanding (inexistante)",`query($orgId:ID!){ organizationStanding(orgId:$orgId){ totalIssued currentlyOverdue submissionsSuspended } }`,F],
];
for (const [l,query,org] of CASES){
  const j=await gql(T_ORG,query,{orgId:org});
  console.log("  "+l.padEnd(40)+fmt(j));
  await sleep(400);
}
