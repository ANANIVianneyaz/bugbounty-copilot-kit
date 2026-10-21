// Matrice d'audience croisee : quel jeton est accepte par quelle surface ?
//  A) jeton OAuth aud=API        -> GraphQL API ?   -> serveur MCP ?
//  B) jeton OAuth aud=MCP        -> GraphQL API ?   -> serveur MCP ?
//  C) jeton de session web aud=bounty-api-auth -> (perime, mais on note les claims)
import fs from "fs";
import crypto from "crypto";
async function f(url,o={}){let e=null;for(let i=0;i<4;i++){try{return await fetch(url,o);}catch(x){e=x;await new Promise(r=>setTimeout(r,1500));}}throw e;}
const API = "https://bugsecure-api.senintel.sn";
const MCP = "https://bugsecure-mcp.senintel.sn";
const EP = API + "/graphql";

const claims = (t) => { try { return JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()); } catch { return {}; } };
const at = (res) => { try { return fs.readFileSync("/tmp/opencode/catcher-at-" + res.replace(/[^a-z0-9]+/gi, "_").toLowerCase() + ".txt", "utf8").trim(); } catch { return ""; } };
const T_API = at("https://bugsecure-api.senintel.sn");
const T_MCP = at("https://bugsecure-mcp.senintel.sn/mcp");

console.log("=== 1) claims complets des deux jetons OAuth ===");
for (const [n, t] of [["API ", T_API], ["MCP ", T_MCP]]) {
  const c = claims(t);
  console.log(n, "->", JSON.stringify(c));
  console.log("     header:", Buffer.from(t.split(".")[0], "base64url").toString());
}

async function gql(tok, label) {
  const r = await f(EP, { method: "POST", headers: { "Content-Type": "application/json", ...(tok ? { Authorization: "Bearer " + tok } : {}) }, body: JSON.stringify({ query: "{ me { id username email } }" }) });
  const txt = await r.text();
  let j = null; try { j = JSON.parse(txt); } catch {}
  console.log("  " + label.padEnd(46) + "HTTP " + r.status + "  " + (j?.data?.me ? "me=" + j.data.me.username : (j?.errors?.[0]?.message || txt).slice(0, 110)));
  return { r, j };
}
async function mcp(tok, label, method = "tools/list", params = {}) {
  const body = method === "initialize"
    ? { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-24", capabilities: {}, clientInfo: { name: "probe", version: "0" } } }
    : { jsonrpc: "2.0", id: 2, method, params };
  const r = await f(MCP + "/mcp", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...(tok ? { Authorization: "Bearer " + tok } : {}) }, body: JSON.stringify(body) });
  const txt = await r.text();
  console.log("  " + label.padEnd(46) + "HTTP " + r.status + "  " + txt.replace(/\s+/g, " ").slice(0, 150));
  const wa = r.headers.get("www-authenticate") || "";
  if (wa) console.log("     www-authenticate: " + wa.slice(0, 150));
  return { r, txt };
}

console.log("\n=== 2) matrice d'audience ===");
console.log(" [GraphQL API]");
await gql("", "sans jeton");
await gql(T_API, "jeton OAuth aud=bugsecure-api.senintel.sn");
await gql(T_MCP, "jeton OAuth aud=bugsecure-mcp.senintel.sn/mcp");
console.log(" [serveur MCP]");
await mcp("", "sans jeton", "initialize");
await mcp(T_API, "jeton OAuth aud=bugsecure-api.senintel.sn", "initialize");
await mcp(T_MCP, "jeton OAuth aud=bugsecure-mcp.senintel.sn/mcp", "initialize");

console.log("\n=== 3) le jeton MCP : quelles surfaces lui sont ouvertes ? ===");
await mcp(T_MCP, "MCP tools/list (aud=MCP)", "tools/list");
await mcp(T_MCP, "MCP resources/list (aud=MCP)", "resources/list");
await mcp(T_MCP, "MCP prompts/list (aud=MCP)", "prompts/list");

console.log("\n=== 4) le 2FA a ete supprime : le jeton porte-t-il un marqueur 2FA ? ===");
const c = claims(T_API);
console.log("  claims du jeton OAuth :", JSON.stringify(Object.keys(c)));
console.log("  roles:", JSON.stringify(c.roles), "| scopes:", JSON.stringify(c.scopes), "| epoch:", c.epoch);

console.log("\n=== 5) revocation : que renvoie l'API sur un jeton hors audience mais signature valide ? ===");
const r5 = await f(EP, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + T_MCP }, body: JSON.stringify({ query: "{ me { id } }" }) });
console.log("  GraphQL + aud=MCP ->", r5.status, (await r5.text()).replace(/\s+/g, " ").slice(0, 200));
