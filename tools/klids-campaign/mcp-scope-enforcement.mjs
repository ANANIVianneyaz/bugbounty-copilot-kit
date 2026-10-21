// Enforcement des scopes PAR OUTIL sur le serveur MCP (jeton aud=MCP, scopes minimaux :
// programs:read profile:read reports:read reports:write)
// Le serveur a des fenetres ou POST /mcp renvoie 404 -> retry automatique.
import fs from "fs";
const MCP = "https://bugsecure-mcp.senintel.sn/mcp";
const AT = "/tmp/opencode/catcher-at-https_bugsecure_mcp_senintel_sn_mcp.txt";
const RT = "/tmp/opencode/catcher-rt-https_bugsecure_mcp_senintel_sn_mcp.txt";
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function F(u, o = {}) { let e = null; for (let i = 0; i < 5; i++) { try { return await fetch(u, { ...o, signal: AbortSignal.timeout(30000) }); } catch (x) { e = x; await sleep(1500); } } return null; }
import { ensureToken } from "/tmp/opencode/token-store.mjs";
async function token() { const t = await ensureToken("https://bugsecure-mcp.senintel.sn/mcp"); return t.token; }
let id = 0;
async function rpc(tok, method, params) {
  id++;
  for (let attempt = 0; attempt < 8; attempt++) {
    const r = await F(MCP + "/mcp", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: "Bearer " + tok }, body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
    const txt = r ? await r.text() : "";
    if (r && r.status === 404) { await sleep(4000); continue; } // fenetre transitoire du serveur
    const line = txt.split("\n").find((l) => l.startsWith("data:"));
    let j = null;
    if (line) { try { j = JSON.parse(line.slice(5).trim()); } catch {} }
    if (!j) { try { j = JSON.parse(txt); } catch {} }
    return { s: r?.status ?? 0, j, txt };
  }
  return { s: 404, j: null, txt: "" };
}
const tok = await token();
const c = JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString());
console.log("jeton MCP : aud=" + c.aud + " | scope=" + c.scope + "\n");

const tl = await rpc(tok, "tools/list", {});
fs.writeFileSync("/tmp/opencode/mcp-tools-full.json", JSON.stringify(tl.j, null, 1));
const tools = tl.j?.result?.tools || [];
console.log("=== inventaire : " + tools.length + " outils ===");
for (const t of tools) {
  const p = Object.keys(t.inputSchema?.properties || {});
  console.log(" - " + t.name.padEnd(32) + " | " + (t.title || "").slice(0, 46).padEnd(46) + " | " + (p.join(",") || "-"));
}
console.log("\n=== appel de chaque outil avec le jeton a scopes minimaux ===");
const S = {
  reportId: "dca04201-559b-4088-bdc3-e1666ea42461", report_id: "dca04201-559b-4088-bdc3-e1666ea42461",
  id: "dca04201-559b-4088-bdc3-e1666ea42461", content: "bb-mcp-scope-probe", body: "bb-mcp-scope-probe",
  text: "bb-mcp-scope-probe", comment: "bb-mcp-scope-probe", message: "bb-mcp-scope-probe",
  question: "bb-mcp-scope-probe", query: "bb-mcp-scope-probe", reference: "bb-mcp-scope-probe",
  title: "bb-mcp-scope-probe", programId: "7cf52a09-38ca-48ec-a9a5-44c5d517718a",
  program_id: "7cf52a09-38ca-48ec-a9a5-44c5d517718a", url: "https://example.org/",
  filename: "bb-mcp-scope-probe.txt", reason: "bb-mcp-scope-probe", notes: "bb-mcp-scope-probe",
  justification: "bb-mcp-scope-probe", answer: "bb-mcp-scope-probe", name: "bb-mcp-scope-probe",
  label: "bb-mcp-scope-probe", value: "bb-mcp-scope-probe", severity: "LOW", status: "OPEN",
  disclosureId: "dca04201-559b-4088-bdc3-e1666ea42461", commentId: "bb-mcp-scope-probe",
  type: "text", scope: "programs:read", clientRequestId: "bb-mcp-scope-probe",
};
const results = [];
for (const t of tools) {
  const props = t.inputSchema?.properties || {};
  const args = {};
  for (const [p, sch] of Object.entries(props)) {
    const ty = (sch.type || "string");
    if (ty === "integer" || ty === "number") args[p] = 1;
    else if (ty === "boolean") args[p] = false;
    else if (ty === "array") args[p] = [];
    else if (ty === "object") args[p] = {};
    else args[p] = S[p] !== undefined ? S[p] : "bb-mcp-scope-probe";
  }
  const r = await rpc(tok, "tools/call", { name: t.name, arguments: args });
  const res = r.j?.result, err = r.j?.error;
  const flat = JSON.stringify(res ?? err);
  const isErr = res?.isError === true;
  const reqScope = (flat.match(/requires the scope\(s\):\s*([^"\\]*)/i) || [])[1] || "";
  const msg = (flat.match(/"message":"([^"]{0,140})/) || [])[1] || "";
  const verdict = reqScope ? "SCOPE(" + reqScope.replace(/[^a-z:]/g, "") + ")" : isErr ? "isError" : "OK";
  console.log(" " + t.name.padEnd(32) + verdict.padEnd(26) + msg.slice(0, 96));
  if (verdict === "OK") console.log("      -> " + flat.slice(0, 240));
  results.push({ tool: t.name, verdict, msg, isErr, raw: flat.slice(0, 700), args });
  await sleep(350);
}
fs.writeFileSync("/tmp/opencode/mcp-scope-enforcement.json", JSON.stringify(results, null, 1));
console.log("\n=== resume ===");
const by = {};
for (const r of results) by[r.verdict] = (by[r.verdict] || 0) + 1;
console.log(by);
console.log("outils AYANT REUSSI avec les scopes minimaux :", results.filter((r) => r.verdict === "OK").map((r) => r.tool).join(", ") || "(aucun)");
