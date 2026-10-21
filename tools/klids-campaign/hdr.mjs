const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36";
async function dump(label,url,o={}){
  const t0=Date.now();
  try{
    const r=await fetch(url,{method:o.m||"GET",headers:{"User-Agent":UA,"Content-Type":"application/json",...(o.h||{})},body:o.b?JSON.stringify(o.b):undefined,redirect:"manual"});
    const t=await r.text();
    console.log("\n### "+label+"  ->  HTTP "+r.status+"  ("+(Date.now()-t0)+"ms)");
    console.log("   url: "+url);
    for(const [k,v] of r.headers) if(!/^date|^server|^content-length|^content-encoding|^x-powered-by|^strict-transport|^alt-svc|^vary|^cache-control|^etag|^last-modified|^expires|^pragma|^transfer|^cf-|^x-cache|^accept-ranges|^age|^via/i.test(k)) console.log("   "+k+": "+v);
    console.log("   body: "+t.replace(/\s+/g," ").slice(0,300));
    return r;
  }catch(e){console.log("\n### "+label+" -> ERR "+e.message);return null}
}
const MCP="https://bugsecure-mcp.senintel.sn";
const APP="https://bugsecure.senintel.sn";
const API="https://bugsecure-api.senintel.sn";
await dump("MCP POST /mcp sans jeton (JSON-RPC initialize)",MCP+"/mcp",{m:"POST",h:{Accept:"application/json, text/event-stream"},b:{jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2025-06-24",capabilities:{},clientInfo:{name:"probe",version:"0"}}}});
await dump("MCP POST /mcp avec jeton bidon",MCP+"/mcp",{m:"POST",h:{Accept:"application/json, text/event-stream",Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.invalide"},b:{jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2025-06-24",capabilities:{},clientInfo:{name:"probe",version:"0"}}}});
await dump("MCP POST /mcp tools/list sans jeton",MCP+"/mcp",{m:"POST",h:{Accept:"application/json, text/event-stream"},b:{jsonrpc:"2.0",id:2,method:"tools/list",params:{}}});
await dump("MCP metadata ressource",MCP+"/.well-known/oauth-protected-resource/mcp");
await dump("MCP metadata ressource (racine)",MCP+"/.well-known/oauth-protected-resource");
await dump("APP /api/health",APP+"/api/health");
await dump("APP /metrics",APP+"/metrics");
await dump("API /metrics",API+"/metrics");
await dump("API /health",API+"/health");
await dump("AS metadata serveur",API+"/.well-known/oauth-authorization-server");
await dump("AS metadata ressource (API)",API+"/.well-known/oauth-protected-resource");
