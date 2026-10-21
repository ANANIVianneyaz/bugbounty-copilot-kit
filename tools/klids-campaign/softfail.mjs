// SOFT-FAIL / ORACLE D'AUTORISATION (Grok §6) : la reponse depend-elle de l existence de l org ?
// 3 cibles : l org reelle (KLDS), un UUID inexistant, un identifiant malforme
// 2 comptes : le compte ORG (COMPANY_ADMIN) et le compte PERSONNEL (chercheur, token OAuth)
// + distribution de latence (5 echantillons par cas) pour detecter un oracle temporel
import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T_ORG = fs.readFileSync("/tmp/opencode/orgtoken.txt", "utf8").trim();
const { ensureToken } = await import("/tmp/opencode/token-store.mjs");
const { token: T_PERSON } = await ensureToken("https://bugsecure-api.senintel.sn");

const ORG_REAL = "0d06701f-d109-4280-b10e-8a923fa69346";
const ORG_FAKE = "11111111-2222-3333-4444-555555555555";
const ORG_MALFORMED = "not-an-uuid";
const TARGETS = [["org reelle (KLDS)", ORG_REAL], ["UUID inexistant", ORG_FAKE], ["malforme", ORG_MALFORMED]];

const RESOLVERS = [
  ["organizationStanding", (o) => [`query($orgId:ID!){ organizationStanding(orgId:$orgId){ totalIssued currentlyOverdue submissionsSuspended } }`, { orgId: o }]],
  ["payoutSummary", (o) => [`query($orgId:ID!){ payoutSummary(orgId:$orgId, months:6){ month amount currency } }`, { orgId: o }]],
  ["organizationCertificates", (o) => [`query($orgId:ID!){ organizationCertificates(orgId:$orgId, take:5){ id reference status } }`, { orgId: o }]],
  ["reportTrends", (o) => [`query($orgId:ID!){ reportTrends(orgId:$orgId, months:6){ month count } }`, { orgId: o }]],
  ["severityDistribution", (o) => [`query($orgId:ID!){ severityDistribution(orgId:$orgId){ severity count } }`, { orgId: o }]],
];
async function q(tok, query, variables) {
  const t0 = Date.now();
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + tok }, body: JSON.stringify({ query, variables }) });
  const txt = await r.text();
  let j = null; try { j = JSON.parse(txt); } catch {}
  return { ms: Date.now() - t0, j };
}
const fmt = (j) => (j?.errors ? "ERR: " + j.errors.map((x) => x.message).join(" | ") : JSON.stringify(j?.data)).replace(/\s+/g, " ").slice(0, 110);

console.log("=== A) reponses par (resolver, cible, compte) ===");
for (const [rname, build] of RESOLVERS) {
  console.log("\n  -- " + rname);
  for (const [clabel, org] of TARGETS) {
    for (const [alabel, tok] of [["ORG ", T_ORG], ["PERS", T_PERSON]]) {
      const [bq, bv] = build(org); const r = await q(tok, bq, bv);
      console.log("    " + alabel + " | " + clabel.padEnd(20) + fmt(r.j));
      await sleep(300);
    }
  }
}

console.log("\n=== B) distribution de latence (5 echantillons) : oracle temporel ? ===");
for (const [rname, build] of RESOLVERS) {
  const line = [];
  for (const [clabel, org] of TARGETS) {
    const lats = [];
    const [bq2, bv2] = build(org); for (let i = 0; i < 5; i++) { const r = await q(T_PERSON, bq2, bv2); lats.push(r.ms); await sleep(220); }
    lats.sort((a, b) => a - b);
    line.push(`${clabel}: min=${lats[0]} med=${lats[2]} max=${lats[4]}`);
  }
  console.log("  " + rname.padEnd(26) + line.join("  |  "));
}
