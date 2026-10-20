import fs from "fs";
const M="https://bugsecure-mcp.senintel.sn/mcp";
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
const T=fs.readFileSync("/tmp/opencode/oauth-access-token.txt","utf8").trim();
const rpc=async(body,headers={})=>{const r=await fetch(M,{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json, text/event-stream",...headers},body:JSON.stringify(body)});const t=await r.text();return{s:r.status,t}};
const H={Authorization:"Bearer "+T};
console.log("=== 1) initialize / tools/list sans Origin ===");
let r=await rpc({jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2025-06-18",capabilities:{},clientInfo:{name:"bb",version:"1"}}},H);
console.log("  initialize -> HTTP "+r.s+"  "+r.t.replace(/\s+/g," ").slice(0,220));
await sleep(1000);
r=await rpc({jsonrpc:"2.0",id:2,method:"tools/list"},H);
console.log("  tools/list -> HTTP "+r.s+"  "+r.t.replace(/\s+/g," ").slice(0,1500));
await sleep(1000);
console.log("\n=== 2) liste d Origines candidates ===");
for(const o of ["https://mcp.bugsecure.senintel.sn","https://app.bugsecure.senitel.sn","https://app.bugsecure.senintel.sn","https://bugsecure-mcp.senintel.sn","https://app.example","https://localhost","https://127.0.0.1"]){
  const rr=await rpc({jsonrpc:"2.0",id:3,method:"initialize",params:{protocolVersion:"2025-06-18",capabilities:{},clientInfo:{name:"bb",version:"1"}}},{...H,Origin:o});
  console.log("  Origin="+o.padEnd(36)+"-> "+rr.s+" "+(rr.s===403?"(refuse)":rr.t.replace(/\s+/g," ").slice(0,60)));
  await sleep(700);
}
console.log("\n=== 3) outils d ecriture dans l inventaire ? (jeton en lecture seule) ===");
const tl=await rpc({jsonrpc:"2.0",id:4,method:"tools/list"},H);
let names=[];
try{const j=JSON.parse(tl.t.replace(/^event: message\ndata: /,"").trim());names=(j?.result?.tools||[]).map(x=>x.name);}catch(e){const m=tl.t.match(/"name":"([a-z_]+)"/g);names=m?m.map(x=>x.replace(/"/g,"")):[];}
console.log("  outils ("+names.length+"): "+(names.join(", ")||"(aucun)"));
const WRITE=["submit_report","add_report_comment","add_triage_comment","update_report_status","assign_report","grade_report","raise_appeal","save_disclosure_draft","update_my_profile","mark_notifications_read","request_upload_url","remove_totp"];
const pres=WRITE.filter(w=>names.includes(w));
console.log("\n  outils d ECRITURE presentes : "+(pres.length?pres.join(", "):"AUCUN"));
if(pres.length) console.log("  >>> ESCALADE DE SCOPES : le jeton porte " + JSON.stringify(JSON.parse(Buffer.from(T.split(".")[1],"base64url").toString()).scope) + " mais le serveur propose des outils d ecriture");
console.log("\n=== 4) appels d outils reels ===");
for(const [tool,args] of [["search_programs",{query:"klds"}],["get_leaderboard",{}],["get_my_profile",{}],["list_my_reports",{}]]){
  const rr=await rpc({jsonrpc:"2.0",id:5,method:"tools/call",params:{name:tool,arguments:args}},H);
  console.log("  "+tool.padEnd(20)+"HTTP "+rr.s+"  "+rr.t.replace(/\s+/g," ").slice(0,230));
  await sleep(1500);
}
