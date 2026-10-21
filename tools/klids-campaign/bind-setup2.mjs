import fs from "fs";
import crypto from "crypto";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tok = await (await fetch("http://127.0.0.1:53682/token")).json();
if (!tok.access_token) { console.log("catcher:", JSON.stringify(tok).slice(0, 200)); process.exit(1); }
const T = tok.access_token;
const p = JSON.parse(Buffer.from(T.split(".")[1], "base64url").toString());
console.log("jeton : aud=" + p.aud + " | client_id=" + p.client_id + " | scope=" + p.scope);
const call = async (q, v) => {
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + T }, body: JSON.stringify({ query: q, variables: v || {} }) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, t, j };
};
const show = (l, r, m = 600) => console.log("  " + l.padEnd(48) + "HTTP " + r.s + "  " + (r.j?.errors ? "ERR: " + r.j.errors.map((x) => x.message).join(" | ") : JSON.stringify(r.j?.data)).slice(0, m));

// Notre rapport (celui soumis via la plateforme) + notre notification
const REPORT = "dca04201-559b-4088-bdc3-e1666ea42461";
const NOTIF = "8841f424-c998-4a93-8bb2-d835893eea6f";
const A = "bb-approval-binding-A";
const KEY = "bb-bind-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex");
const digest = crypto.randomBytes(32).toString("base64url").slice(0, 43);

console.log("\n=== 1) creation de l approbation (payload benin, cle connue) ===");
console.log("  cle d idempotence : " + KEY);
console.log("  payload approuve   : addReportComment { reportId: " + REPORT + ", content: \"" + A + "\" }");
const c = await call(
  `mutation($i:CreateAgentApprovalInput!,$c:String!){ createAgentApproval(input:$i,clientRequestId:$c){ id status reviewUrl expiresAt clientRequestId } }`,
  { i: { clientDigest: digest, parts: [{ operation: "addReportComment", arguments: { input: { reportId: REPORT, content: A } } }] }, c: KEY });
show("createAgentApproval", c, 700);
const ap = c.j?.data?.createAgentApproval;
if (!ap) { console.log("\n  (approbation non creee)"); process.exit(0); }
fs.writeFileSync("/tmp/opencode/bind-approval.json", JSON.stringify({ ...ap, key: KEY, contentA: A, report: REPORT, notif: NOTIF, digest }, null, 1));
console.log("\n=== 2) A VALIDER PAR TOI (1 clic) ===");
console.log("  " + ap.reviewUrl);
console.log("\n  Dis-moi \"approuve\" et j enchaine :");
console.log("   - controle  : rejouer le payload APPROUVE  -> doit s executer (commentaire \"" + A + "\")");
console.log("   - rejeu 1   : meme cle, contenu \"" + A + "-B\"  -> doit etre REFUSE (IDEMPOTENCY_KEY_REUSED)");
console.log("   - rejeu 2   : meme cle, AUTRE mutation (markNotificationAsRead) -> doit etre REFUSE");
console.log("   - rejeu 3   : meme payload approuve, 2e fois -> doit etre idempotent (pas de doublon)");
