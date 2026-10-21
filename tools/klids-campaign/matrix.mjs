import fs from "fs";
const tok=fs.readFileSync("/tmp/opencode/catcher-at-https_bugsecure_mcp_senintel_sn_mcp.txt","utf8").trim();
const H=(extra={})=>({"Content-Type":"application/json",Accept:"application/json, text/event-stream",Authorization:"Bearer "+tok,...extra});
async function call(label,body,extra={}){
  try{
    const r=await fetch("https://bugsecure-mcp.senintel.sn/mcp",{method:"POST",headers:H(extra),body:body,signal:AbortSignal.timeout(30000)});
    const t=await r.text();
    console.log("  "+label.padEnd(42)+"HTTP "+r.status+" len="+t.length+(r.status!==200?" | "+t.slice(0,40):""));
  }catch(e){console.log("  "+label.padEnd(42)+"ERR "+e.message.slice(0,60));}
}
const b2=JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/list",params:{}});
const b1=JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list",params:{}});
const bInit=JSON.stringify({jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2025-06-24",capabilities:{},clientInfo:{name:"p",version:"0"}}});
for(let i=0;i<3;i++){
  console.log("--- tour "+(i+1));
  await call("tools/list id=2",b2);
  await call("tools/list id=1",b1);
  await call("tools/list id=1 (2e appel identique)",b1);
  await call("initialize id=1",bInit);
  await call("tools/list id=2 + Accept simple",b2,{Accept:"application/json, text/event-stream"});
  await new Promise(r=>setTimeout(r,1500));
}
