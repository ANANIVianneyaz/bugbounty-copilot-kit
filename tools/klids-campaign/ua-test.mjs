import fs from "fs";
const tok=fs.readFileSync("/tmp/opencode/catcher-at-https_bugsecure_mcp_senintel_sn_mcp.txt","utf8").trim();
const body=JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/list",params:{}});
console.log("=== sans User-Agent ===");
for(let i=0;i<3;i++){const r=await fetch("https://bugsecure-mcp.senintel.sn/mcp",{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json, text/event-stream",Authorization:"Bearer "+tok},body});const t=await r.text();console.log("  HTTP "+r.status+" len="+t.length+" | "+t.replace(/\s+/g," ").slice(0,70));await new Promise(x=>setTimeout(x,600));}
console.log("=== avec User-Agent ===");
for(let i=0;i<3;i++){const r=await fetch("https://bugsecure-mcp.senintel.sn/mcp",{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json, text/event-stream","User-Agent":"bb-bounty-mcp-probe/1",Authorization:"Bearer "+tok},body});const t=await r.text();console.log("  HTTP "+r.status+" len="+t.length+" | "+t.replace(/\s+/g," ").slice(0,70));await new Promise(x=>setTimeout(x,600));}
