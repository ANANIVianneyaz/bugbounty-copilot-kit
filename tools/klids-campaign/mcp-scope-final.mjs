// ENFORCEMENT DES SCOPES PAR OUTIL — version definitive, avec des arguments VALIDES par outil.
// But : pour chaque outil, le serveur doit soit repondre, soit refuser en nommant le scope manquant.
// Un outil qui repond malgre un scope manquant = escalade de privilege.
import fs from "fs";
import { ensureToken } from "/tmp/opencode/token-store.mjs";
const API = "https://bugsecure-api.senintel.sn";
const MCP = "https://bugsecure-mcp.senintel.sn/mcp";
const REPORT = "dca04201-559b-4088-bdc3-e1666ea42461";
const PROGRAM = "7cf52a09-38ca-48ec-a9a5-44c5d517718a";
const ORG = "0d06701f-d109-4280-b10e-8a923fa69346";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const { token } = await ensureToken("https://bugsecure-mcp.senintel.sn/mcp");
const H = { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "User-Agent": "bb-bounty-mcp-probe/1", Authorization: "Bearer " + token };

async function rpc(method, params) {
  const r = await fetch(MCP, { method: "POST", headers: H, body: JSON.stringify({ jsonrpc: "2.0", id: Date.now() % 100000, method, params }) });
  const txt = await r.text();
  const line = txt.split("\n").find((l) => l.startsWith("data:"));
  let j = null; try { j = JSON.parse(line ? line.slice(5).trim() : txt); } catch {}
  return { s: r.status, j, txt };
}

// arguments valides par outil
const A = {
  add_report_comment: { reportId: REPORT, content: "bb-mcp-scope-probe" },
  add_triage_comment: { reportId: REPORT, content: "bb-mcp-scope-probe", visibleToResearcher: false },
  assign_report: { reportId: REPORT },
  check_duplicates: { programId: PROGRAM, title: "bb-mcp-scope-probe", description: "bb-mcp-scope-probe" },
  get_leaderboard: { period: "ALL", country: "BJ", limit: 1 },
  get_my_kyc_status: {},
  get_my_profile: { stats: false },
  get_org_report: { reportId: REPORT, historyOffset: 0, fullText: true },
  get_org_report_stats: { organizationId: ORG, months: 6 },
  get_program: { id: PROGRAM, activity: true },
  get_program_stats: { programId: PROGRAM },
  get_program_terms: { programId: PROGRAM, kind: "TERMS_OF_SERVICE", fullText: true },
  get_report: { reportId: REPORT, historyOffset: 0, fullText: true },
  get_researcher_profile: { username: "william_root" },
  get_taxonomy: { query: "ssrf", limit: 1, offset: 1 },
  grade_report: { reportId: REPORT, severity: "HIGH", cvssScore: 7.5, reasoning: "bb-mcp-scope-probe raison assez longue", amount: 100, amountReason: "bb-mcp-scope-probe" },
  list_badges: { state: "EARNED", limit: 1, offset: 1 },
  list_my_certificates: { limit: 1, offset: 1 },
  list_my_organizations: {},
  list_my_reports: { limit: 1, offset: 1 },
  list_notifications: { limit: 1, offset: 1 },
  list_org_certificates: { organizationId: ORG, limit: 1, offset: 1 },
  list_org_programs: { limit: 1, offset: 1 },
  list_org_reports: { limit: 1, offset: 1 },
  mark_notifications_read: { all: false, ids: [] },
  raise_appeal: { reportId: REPORT, adjudicationId: "00000000-0000-0000-0000-000000000000", grounds: "bb-mcp-scope-probe groundes suffisamment longues" },
  save_disclosure_draft: { reportId: REPORT, revision: 1, title: "bb", summary: "bb", writeup: "bb", creditResearcher: true },
  search: { query: "ssrf", limit: 1, offset: 1 },
  search_programs: { query: "kl", limit: 1, offset: 1 },
  submit_report: { programId: PROGRAM, title: "bb-mcp-scope-probe", severity: "LOW", description: "bb", stepsToReproduce: "bb", impact: "bb", remediation: "bb" },
  update_my_profile: { bio: "bb-mcp-scope-probe" },
  update_report_status: { reportId: REPORT, status: "IN_TRIAGE", reason: "bb-mcp-scope-probe" },
  verify_certificate: { publicToken: "bb-mcp-scope-probe" },
};
const tools = JSON.parse(fs.readFileSync("/tmp/opencode/mcp-tools-full.json", "utf8")).result.tools;
console.log("jeton scope =", JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).scope, "| outils =", tools.length, "\n");
const out = [];
for (const t of tools) {
  const args = A[t.name] || {};
  const r = await rpc("tools/call", { name: t.name, arguments: args });
  const res = r.j?.result, err = r.j?.error;
  const flat = JSON.stringify(res ?? err);
  const isErr = res?.isError === true;
  const txt = (flat.match(/"text":"([^"]{0,160})/) || [])[1] || "";
  const scopeMsg = (flat.match(/insufficient_scope[^"]*"([^"]{0,120})/) || [])[1] || "";
  const scopeList = (flat.match(/"(triage:[a-z]+|grade:[a-z]+|disclosures:[a-z]+|profile:[a-z]+|notifications:[a-z]+|reports:[a-z]+|programs:[a-z]+)"/) || [])[1] || "";
  let verdict = "OK";
  if (/insufficient_scope/i.test(flat)) verdict = "SCOPE(" + (scopeList || scopeMsg || "?") + ")";
  else if (isErr) verdict = "isError";
  console.log("  " + t.name.padEnd(28) + verdict.padEnd(34) + txt.replace(/\\n/g, " ").slice(0, 90));
  if (verdict === "OK") console.log("      -> " + flat.slice(0, 200));
  out.push({ tool: t.name, verdict, raw: flat.slice(0, 600), args });
  await sleep(350);
}
fs.writeFileSync("/tmp/opencode/mcp-scope-final.json", JSON.stringify(out, null, 1));
const by = {};
for (const r of out) by[r.verdict] = (by[r.verdict] || 0) + 1;
console.log("\n=== resume ===", by);
console.log("OK :", out.filter((r) => r.verdict === "OK").map((r) => r.tool).join(", "));
console.log("SCOPE :", out.filter((r) => r.verdict.startsWith("SCOPE")).map((r) => r.tool + "[" + r.verdict + "]").join(", "));
console.log("isError :", out.filter((r) => r.verdict === "isError").map((r) => r.tool).join(", "));
