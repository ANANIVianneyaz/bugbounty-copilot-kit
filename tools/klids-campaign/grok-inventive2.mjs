// A et E corriges : enums valides + redirect_uri enregistre (/callback)
import fs from "fs";
import { ensureToken } from "/tmp/opencode/token-store.mjs";
const AS = "https://bugsecure-api.senintel.sn";
const EP = AS + "/graphql";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
const { token } = await ensureToken(AS);
const H = { "Content-Type": "application/json", Authorization: "Bearer " + token };
async function gql(query, variables) {
  const t0 = Date.now();
  const r = await fetch(EP, { method: "POST", headers: H, body: JSON.stringify({ query, variables }) });
  const txt = await r.text();
  let j = null; try { j = JSON.parse(txt); } catch {}
  return { ms: Date.now() - t0, s: r.status, j, txt };
}
const brief = (r) => (r.j?.errors ? "ERR: " + r.j.errors.map((e) => e.message).join(" | ") : JSON.stringify(r.j?.data)).replace(/\s+/g, " ").slice(0, 140);
const show = (l, r) => console.log("  " + l.padEnd(48) + String(r.ms).padStart(5) + "ms  " + brief(r));

const MUT = `mutation { updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) { id } }`;
console.log("=== A corrige : @include / @skip sur une mutation qui exige triage:write ===");
show("mutation directe", await gql(MUT, {}));
show("@include(if:true)", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @include(if: true) { id } }`, {}));
show("@include(if:false)", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @include(if: false) { id } }`, {}));
show("@skip(if:false)", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @skip(if: false) { id } }`, {}));
show("@skip(if:true)", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @skip(if: true) { id } }`, {}));
show("@include(if:$v) variable false", await gql(`mutation($v:Boolean!){ u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @include(if:$v) { id } }`, { v: false }));
show("@include(if:$v) variable true", await gql(`mutation($v:Boolean!){ u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @include(if:$v) { id } }`, { v: true }));
show("@include(if:\"true\") type invalide", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @include(if: "true") { id } }`, {}));
show("@include(if:1) type invalide", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @include(if: 1) { id } }`, {}));
show("deux alias, un avec @include(false)", await gql(`mutation { a: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @include(if:false) { id } b: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"IN_TRIAGE"}) @include(if:true) { id } }`, {}));

console.log("\n=== E corrige : confusion de binding au /oauth/authorize (redirect_uri enregistre) ===");
const RU = "http://127.0.0.1:53682/callback";
const base = { response_type: "code", client_id: "bugsecure-mcp-cli", redirect_uri: RU, scope: "programs:read profile:read reports:read reports:write", state: "bb-" + Date.now(), code_challenge: "FCwpR1pJLeFhZQu7BkPOcqIZ8QXf5YyXgWFDn_N7Sw8", code_challenge_method: "S256", resource: AS };
const cases = [
  ["temoin (tout conforme)", {}],
  ["state de 2000 caracteres", { state: "A".repeat(2000) }],
  ["state avec <script> et &", { state: "<script>alert(1)</script>&x=1" }],
  ["state de 300 caracteres", { state: "B".repeat(300) }],
  ["code_challenge S256 incorrect", { code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" }],
  ["code_challenge_method=plain", { code_challenge_method: "plain" }],
  ["code_challenge_method absent", { code_challenge_method: undefined }],
  ["code_challenge absent", { code_challenge: undefined }],
  ["redirect_uri avec fragment", { redirect_uri: RU + "#f" }],
  ["redirect_uri avec slash final", { redirect_uri: RU + "/" }],
  ["redirect_uri en majuscules", { redirect_uri: RU.replace("127.0.0.1", "127.0.0.1").toUpperCase() }],
  ["scope duplique", { scope: "programs:read programs:read" }],
  ["scope inconnu ajoute", { scope: "programs:read profile:read reports:read reports:write admin:all" }],
  ["resource duplique", { resource: AS + " " + AS }],
  ["resource different (MCP)", { resource: "https://bugsecure-mcp.senintel.sn/mcp" }],
  ["client_id avec espace final", { client_id: "bugsecure-mcp-cli " }],
  ["client_id en majuscules", { client_id: "BUGSECURE-MCP-CLI" }],
  ["response_type=token", { response_type: "token" }],
  ["response_type absent", { response_type: undefined }],
  ["port different sur redirect_uri", { redirect_uri: "http://127.0.0.1:53683/callback" }],
];
for (const [lbl, over] of cases) {
  const q = { ...base, ...over };
  const p = Object.fromEntries(Object.entries(q).filter(([, v]) => v !== undefined));
  const r = await fetch(AS + "/oauth/authorize?" + form(p), { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  const body = loc ? "" : (await r.text()).replace(/\s+/g, " ").slice(0, 60);
  console.log("  " + lbl.padEnd(36) + "HTTP " + r.status + " -> " + (loc ? loc.replace("https://bugsecure.senintel.sn", "").slice(0, 70) : body));
  await sleep(450);
}
