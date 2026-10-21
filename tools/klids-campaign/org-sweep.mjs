// Sweep cible "organisation" (demande de Grok) : compare le CONTEXTE 1 (compte personnel)
// et le CONTEXTE 2 (compte organisation non verifie) sur les 34 resolvers qui prennent
// un organizationId / orgId. L outil produit une table ; le diff des deux tables dit si le
// soft-fail (organizationStanding -> objet par defaut) change quand on est membre non verifie.
//
// Usage:
//   BB_TOKEN=<jeton> ORG_ID=<uuid-organisation> node org-sweep.mjs <etiquette>
// (l etiquette est ecrite dans le JSON de sortie pour le diff)
import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const TOKEN = process.env.BB_TOKEN;
const ORG = process.env.ORG_ID;
const LABEL = process.argv[2] || "contexte";
if (!TOKEN) { console.error("BB_TOKEN manquant"); process.exit(1); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const H = { "Content-Type": "application/json", Authorization: "Bearer " + TOKEN };

// les 34 operations du corpus qui prennent un organizationId / orgId, avec les arguments plausibles
const OPS = [
  ["getOrganizationStanding", `query($orgId:ID!){ organizationStanding(orgId:$orgId){ totalIssued currentlyOverdue submissionsSuspended } }`, { orgId: ORG }],
  ["getPayoutSummary", `query($orgId:ID!){ payoutSummary(orgId:$orgId, months:6){ month amount currency } }`, { orgId: ORG }],
  ["getOrganizationCertificates", `query($orgId:ID!){ organizationCertificates(orgId:$orgId, take:5){ id reference status } }`, { orgId: ORG }],
  ["getReportTrends", `query($orgId:ID!){ reportTrends(orgId:$orgId, months:6){ month count } }`, { orgId: ORG }],
  ["getSeverityDistribution", `query($orgId:ID!){ severityDistribution(orgId:$orgId){ severity count } }`, { orgId: ORG }],
  ["getOrganizationInvitations", `query($organizationId:ID!){ getOrganizationInvitations(organizationId:$organizationId){ id email status token } }`, { organizationId: ORG }],
  ["getMyOrganizationInvitations", `query{ getMyOrganizationInvitations{ id email status token } }`, {}],
  ["getMyInvitedPrograms", `query{ getMyInvitedPrograms{ id name } }`, {}],
  ["getMyOrganizations", `query{ getMyOrganizations{ id name status } }`, {}],
  ["getMyPrograms", `query{ getMyPrograms{ id name } }`, {}],
  ["hasOrganizationAcceptedTerms", `query($organizationId:ID!){ hasOrganizationAcceptedTerms(organizationId:$organizationId) }`, { organizationId: ORG }],
  ["getOrganizationInterventionUsage", `query($organizationId:ID!){ getOrganizationInterventionUsage(organizationId:$organizationId, month:"2026-10"){ count } }`, { organizationId: ORG }],
  ["getOverdueCertificates", `query($organizationId:ID!){ getOverdueCertificates(organizationId:$organizationId){ id } }`, { organizationId: ORG }],
  ["getCriticalReviewQueue", `query($organizationId:ID!){ getCriticalReviewQueue(organizationId:$organizationId){ id } }`, { organizationId: ORG }],
  ["adminUserOrganisations", `query($userId:ID!){ adminUserOrganisations(userId:$userId){ id name } }`, { userId: "e3aa51e2-2c87-4b64-a3cb-6d5eb857f40c" }],
  ["inviteOrganizationMember", `mutation($organizationId:ID!){ inviteOrganizationMember(organizationId:$organizationId, input:{email:"bb-probe@example.org", role:"RESEARCHER"}){ id token email } }`, { organizationId: ORG }],
  ["updateOrganization", `mutation($organizationId:ID!){ updateOrganization(organizationId:$organizationId, input:{name:"BB Probe Org"}){ id name } }`, { organizationId: ORG }],
  ["setOrganizationAiGrading", `mutation($organizationId:ID!){ setOrganizationAiGrading(organizationId:$organizationId, enabled:false){ id } }`, { organizationId: ORG }],
  ["setOrganizationAiTriageAccess", `mutation($organizationId:ID!){ setOrganizationAiTriageAccess(organizationId:$organizationId, enabled:false){ id } }`, { organizationId: ORG }],
  ["removeOrganizationMember", `mutation($organizationId:ID!){ removeOrganizationMember(organizationId:$organizationId, memberId:"00000000-0000-0000-0000-000000000000"){ id } }`, { organizationId: ORG }],
  ["revokeOrganizationInvitation", `mutation($organizationId:ID!){ revokeOrganizationInvitation(organizationId:$organizationId, invitationId:"00000000-0000-0000-0000-000000000000"){ id } }`, { organizationId: ORG }],
  ["adjudicateReport", `mutation($organizationId:ID!){ adjudicateReport(input:{reportId:"dca04201-559b-4088-bdc3-e1666ea42461", side:"REPORTER", outcome:"VALID", reason:"bb-probe-sweep-raison-de-test-assez-longue"}){ id } }`, { organizationId: ORG }],
];

async function gql(q, v) {
  const t0 = Date.now();
  const r = await fetch(EP, { method: "POST", headers: H, body: JSON.stringify({ query: q, variables: v }) });
  const txt = await r.text();
  let j = null; try { j = JSON.parse(txt); } catch {}
  const errs = j?.errors || [];
  const msg = errs.map((e) => e.message).join(" | ");
  let cls = "DATA";
  if (/requires the scope/i.test(msg)) cls = "SCOPE";
  else if (/not available to OAuth clients/i.test(msg)) cls = "OAUTH-BLOCKED";
  else if (/Unauthorized|not authenticated/i.test(msg)) cls = "UNAUTH";
  else if (/Forbidden|not allowed|must be a member|not a member|only read your own/i.test(msg)) cls = "FORBIDDEN";
  else if (/not found|does not exist/i.test(msg)) cls = "NOT-FOUND";
  else if (errs.length) cls = "OTHER";
  const shape = cls === "DATA" ? JSON.stringify(j.data).slice(0, 220) : msg.slice(0, 160);
  return { cls, shape, ms: Date.now() - t0, raw: JSON.stringify(j).slice(0, 400) };
}
const out = [];
console.log("=== sweep organisation | contexte: " + LABEL + " | org: " + (ORG || "(non fourni)") + " ===\n");
for (const [name, q, v] of OPS) {
  const r = await gql(q, v);
  console.log("  " + name.padEnd(30) + r.cls.padEnd(16) + String(r.ms).padStart(5) + "ms  " + r.shape.slice(0, 120));
  out.push({ name, ...r });
  await sleep(400);
}
fs.writeFileSync("/tmp/opencode/org-sweep-" + LABEL + ".json", JSON.stringify({ label: LABEL, org: ORG, results: out }, null, 1));
console.log("\n-> /tmp/opencode/org-sweep-" + LABEL + ".json");
if (fs.existsSync("/tmp/opencode/org-sweep-contexte1.json")) {
  const a = JSON.parse(fs.readFileSync("/tmp/opencode/org-sweep-contexte1.json")).results;
  const b = out;
  console.log("\n=== DIFF contexte1 (personnel) vs " + LABEL + " ===");
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i], y = b[i];
    if (!x || !y) { console.log("  (operation absente d un contexte)"); continue; }
    const same = x.cls === y.cls && x.shape === y.shape;
    console.log("  " + (same ? "=" : "!") + " " + x.name.padEnd(30) + "ctx1=" + x.cls.padEnd(15) + "ctx2=" + y.cls.padEnd(15) + (same ? "" : "  <-- DIFFERENT : " + y.shape.slice(0, 90)));
  }
}
