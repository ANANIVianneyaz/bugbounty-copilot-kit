import fs from "fs";
import { ensureToken } from "/tmp/opencode/token-store.mjs";
const MCP="https://bugsecure-mcp.senintel.sn/mcp";
const fileTok=fs.readFileSync("/tmp/opencode/catcher-at-https_bugsecure_mcp_senintel_sn_mcp.txt","utf8").trim();
async function call(label,tok,extra={}){
  try{
    const r=await fetch(MCP+"/mcp",{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json, text/event-stream",Authorization:"Bearer "+tok,...extra},body:JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/list",params:{}}),signal:AbortSignal.timeout(30000)});
    const t=await r.text();
    console.log("  "+label.padEnd(50)+"HTTP "+r.status+" len="+t.length);
    return r.status;
  }catch(e){console.log("  "+label.padEnd(50)+"ERR "+e.message.slice(0,50));return 0;}
}
console.log("=== A) jeton lu depuis le FICHIER ===");
await call("A1 fichier",fileTok);
await call("A2 fichier (2e)",fileTok);
console.log("\n=== B) apres un ensureToken() ===");
const t2=await ensureToken("https://bugsecure-mcp.senintel.sn/mcp");
console.log("  ensureToken -> source="+t2.source+" exp="+t2.exp);
await call("B1 token ensureToken",t2.token);
await call("B2 token fichier",fileTok);
console.log("\n=== C) avec un fetch de l AS juste avant (comme le script) ===");
const ar=await fetch("https://bugsecure-api.senintel.sn/.well-known/oauth-authorization-server");
await ar.text();
await call("C1 apres fetch AS",fileTok);
console.log("\n=== D) headers identiques mais sans le signal ===");
try{
  const r=await fetch(MCP+"/mcp",{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json, text/event-stream",Authorization:"Bearer "+fileTok},body:JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/list",params:{}})});
  const t=await r.text();
  console.log("  D1 sans signal".padEnd(52)+"HTTP "+r.status+" len="+t.length);
}catch(e){console.log("  D1 ERR",e.message);}
