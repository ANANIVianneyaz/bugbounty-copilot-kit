import fs from "fs";
const MCP="https://bugsecure-mcp.senintel.sn/mcp";
const AT="/tmp/opencode/catcher-at-https_bugsecure_mcp_senintel_sn_mcp.txt";
const RT="/tmp/opencode/catcher-rt-https_bugsecure_mcp_senintel_sn_mcp.txt";
const form=(o)=>Object.entries(o).map(([k,v])=>encodeURIComponent(k)+"="+encodeURIComponent(v)).join("&");
async function F(u,o={}){let e=null;for(let i=0;i<5;i++){try{return await fetch(u,{...o,signal:AbortSignal.timeout(30000)});}catch(x){e=x;await new Promise(r=>setTimeout(r,1500));}}return null;}
async function token(){
  let at="";try{at=fs.readFileSync(AT,"utf8").trim();}catch{}
  const c=(()=>{try{return JSON.parse(Buffer.from(at.split(".")[1],"base64url").toString());}catch{return{};}})();
  if(at&&c.exp&&c.exp-Math.floor(Date.now()/1000)>60) return at;
  const rt=fs.readFileSync(RT,"utf8").trim();
  const r=await F("https://bugsecure-api.senintel.sn/oauth/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:form({grant_type:"refresh_token",refresh_token:rt,client_id:"bugsecure-mcp-cli",resource:"https://bugsecure-mcp.senintel.sn/mcp"})});
  const j=await r.json();
  if(!j.access_token) throw new Error("refresh KO "+JSON.stringify(j).slice(0,150));
  fs.writeFileSync(AT,j.access_token); if(j.refresh_token) fs.writeFileSync(RT,j.refresh_token);
  return j.access_token;
}
const tok=await token();
for(let attempt=0;attempt<6;attempt++){
  const r=await F(MCP+"/mcp",{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json, text/event-stream",Authorization:"Bearer "+tok},body:JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/list",params:{}})});
  const t=r?await r.text():"";
  console.log("essai",attempt+1,"HTTP",r?.status,"len",t.length);
  if(t.length>2000){
    fs.writeFileSync("/tmp/opencode/mcp-tools-raw.txt",t);
    const line=t.split("\n").find(l=>l.startsWith("data:"));
    const j=JSON.parse(line.slice(5).trim());
    const tools=j.result.tools;
    console.log("OUTILS PARSES:",tools.length);
    console.log("noms :",tools.map(x=>x.name).join(", "));
    break;
  }
  await new Promise(r2=>setTimeout(r2,3000));
}
