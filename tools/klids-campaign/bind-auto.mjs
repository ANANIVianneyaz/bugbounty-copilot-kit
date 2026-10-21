import fs from "fs";
import crypto from "crypto";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const REPORT = "dca04201-559b-4088-bdc3-e1666ea42461";
const NOTIF = "8841f424-c998-4a93-8bb2-d835893eea6f";

const token = async () => {
  const j = await (await fetch("http://127.0.0.1:53682/token")).json();
  if (!j.access_token) throw new Error("catcher: " + JSON.stringify(j).slice(0, 120));
  return j.access_token;
};
const call = async (T, q, v) => {
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + T }, body: JSON.stringify({ query: q, variables: v || {} }) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, t, j };
};
const log = (s) => { console.log(s); try { fs.appendFileSync("/tmp/opencode/bind-auto.log", s + "\n"); } catch {} };

async function createApproval(T) {
  const digest = crypto.randomBytes(32).toString("base64url").slice(0, 43);
  const KEY = "bb-bind-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex");
  const A = "bb-approval-binding-A";
  const c = await call(T, `mutation($i:CreateAgentApprovalInput!,$c:String!){ createAgentApproval(input:$i,clientRequestId:$c){ id status reviewUrl expiresAt clientRequestId } }`,
    { i: { clientDigest: digest, parts: [{ operation: "addReportComment", arguments: { input: { reportId: REPORT, content: A } } }] }, c: KEY });
  const ap = c.j?.data?.createAgentApproval;
  if (!ap) { log("  creation refusee : " + JSON.stringify(c.j?.errors || c.j).slice(0, 160)); return null; }
  return { ...ap, key: KEY, contentA: A, report: REPORT, notif: NOTIF };
}

async function runTests(T, A) {
  log("\n=== TESTS DE LIAISON (approbation " + A.id + ", cle " + A.key + ") ===");
  const out = {};
  const t0 = await call(T, `mutation($i:AddCommentInput!,$k:String){ addReportComment(clientRequestId:$k,input:$i){ id content isInternal } }`, { i: { reportId: A.report, content: A.contentA }, k: A.key });
  log("  1) payload APPROUVE        : HTTP " + t0.s + " " + (t0.j?.errors ? "ERR " + t0.j.errors.map((x) => x.message).join("|").slice(0, 120) : JSON.stringify(t0.j?.data)));
  out.t0 = t0;
  await sleep(1500);
  const t1 = await call(T, `mutation($i:AddCommentInput!,$k:String){ addReportComment(clientRequestId:$k,input:$i){ id content isInternal } }`, { i: { reportId: A.report, content: A.contentA + "-B" }, k: A.key });
  log("  2) rejeu contenu MODIFIE   : HTTP " + t1.s + " " + (t1.j?.errors ? "ERR " + t1.j.errors.map((x) => x.message).join("|").slice(0, 120) : JSON.stringify(t1.j?.data)));
  out.t1 = t1;
  await sleep(1500);
  const t2 = await call(T, `mutation($k:String,$id:ID!){ markNotificationAsRead(clientRequestId:$k,id:$id) }`, { id: A.notif, k: A.key });
  log("  3) rejeu AUTRE MUTATION     : HTTP " + t2.s + " " + (t2.j?.errors ? "ERR " + t2.j.errors.map((x) => x.message).join("|").slice(0, 120) : JSON.stringify(t2.j?.data)));
  out.t2 = t2;
  await sleep(1500);
  const t3 = await call(T, `mutation($i:AddCommentInput!,$k:String){ addReportComment(clientRequestId:$k,input:$i){ id content isInternal } }`, { i: { reportId: A.report, content: A.contentA }, k: A.key });
  log("  4) rejeu payload identique  : HTTP " + t3.s + " " + (t3.j?.errors ? "ERR " + t3.j.errors.map((x) => x.message).join("|").slice(0, 120) : JSON.stringify(t3.j?.data)));
  out.t3 = t3;
  const id0 = t0.j?.data?.addReportComment?.id, id1 = t1.j?.data?.addReportComment?.id, id3 = t3.j?.data?.addReportComment?.id;
  log("\n  VERDICT :");
  log("   payload approuve execute   : " + (id0 ? "OUI (" + id0 + ")" : "NON"));
  log("   rejeu MODIFIE accepte     : " + (id1 ? "*** OUI -> BINDING ROMPU ***" : "non (refuse)"));
  log("   rejeu AUTRE MUTATION       : " + (t2.j?.data?.markNotificationAsRead ? "*** OUI -> BINDING ROMPU ***" : "non (refuse)"));
  log("   idempotence                : " + (id3 && id0 ? (id3 === id0 ? "OK (meme resultat)" : "resultat different") : "refuse/NA"));
  fs.writeFileSync("/tmp/opencode/bind-result.json", JSON.stringify(out, null, 1));
  return out;
}

(async () => {
  let T = await token();
  let A = await createApproval(T);
  if (!A) { log("impossible de creer l approbation"); process.exit(1); }
  fs.writeFileSync("/tmp/opencode/bind-approval.json", JSON.stringify(A, null, 1));
  log("APPROBATION " + A.id + " cle=" + A.key);
  log("URL DE REVUE : " + A.reviewUrl);
  log("expire le   : " + A.expiresAt);
  log("(poll toutes les 5 s ; les tests se lancent automatiquement a l approbation)");
  const deadline = Date.now() + 14 * 60 * 1000;
  while (Date.now() < deadline) {
    await sleep(5000);
    T = await token();
    const st = await call(T, `query($id:ID!){ agentApproval(id:$id){ id status } }`, { id: A.id });
    const s = st.j?.data?.agentApproval?.status;
    if (s === "APPROVED") { log("\n>>> APPROBATION ACCEPTEE -> tests"); await runTests(T, A); return; }
    if (s && s !== "PENDING") { log("\n>>> statut = " + s + " -> nouvelle approbation"); A = await createApproval(T); if (!A) return; fs.writeFileSync("/tmp/opencode/bind-approval.json", JSON.stringify(A, null, 1)); log(">>> NOUVELLE URL : " + A.reviewUrl + " (expire " + A.expiresAt + ")"); }
  }
  log("delai depasse");
})();
