import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const A = JSON.parse(fs.readFileSync("/tmp/opencode/bind-approval.json", "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tok = await (await fetch("http://127.0.0.1:53682/token")).json();
if (!tok.access_token) { console.log("catcher:", JSON.stringify(tok).slice(0, 200)); process.exit(1); }
const T = tok.access_token;
const call = async (q, v) => {
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + T }, body: JSON.stringify({ query: q, variables: v || {} }) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, t, j };
};
const show = (l, r, m = 420) => console.log("  " + l.padEnd(52) + "HTTP " + r.s + "  " + (r.j?.errors ? "ERR: " + r.j.errors.map((x) => x.message).join(" | ") : JSON.stringify(r.j?.data)).slice(0, m));

console.log("=== 0) etat de l approbation ===");
console.log("  cle=" + A.key + " | payload=" + A.contentA + " | report=" + A.report);
show("agentApproval(id)", await call(`query($id:ID!){ agentApproval(id:$id){ id status clientRequestId expiresAt } }`, { id: A.id }), 300);
await sleep(1200);

console.log("\n=== 1) CONTROLE : le payload APPROUVE doit s executer ===");
const c0 = await call(
  `mutation($i:AddCommentInput!,$k:String){ addReportComment(clientRequestId:$k,input:$i){ id content isInternal } }`,
  { i: { reportId: A.report, content: A.contentA }, k: A.key });
show("addReportComment(contenu approuve)", c0, 400);
const id0 = c0.j?.data?.addReportComment?.id;
await sleep(1500);

console.log("\n=== 2) REJEU 1 : meme cle, CONTENU DIFFERENT (doit etre refuse) ===");
const c1 = await call(
  `mutation($i:AddCommentInput!,$k:String){ addReportComment(clientRequestId:$k,input:$i){ id content isInternal } }`,
  { i: { reportId: A.report, content: A.contentA + "-B" }, k: A.key });
show("addReportComment(contenu MODIFIE)", c1, 420);
const id1 = c1.j?.data?.addReportComment?.id;
await sleep(1500);

console.log("\n=== 3) REJEU 2 : meme cle, AUTRE MUTATION (doit etre refuse) ===");
const c2 = await call(
  `mutation($k:String,$id:ID!){ markNotificationAsRead(clientRequestId:$k,id:$id) }`,
  { id: A.notif, k: A.key });
show("markNotificationAsRead(meme cle)", c2, 420);
await sleep(1500);

console.log("\n=== 4) REJEU 3 : le payload approuve, 2e fois (idempotence) ===");
const c3 = await call(
  `mutation($i:AddCommentInput!,$k:String){ addReportComment(clientRequestId:$k,input:$i){ id content isInternal } }`,
  { i: { reportId: A.report, content: A.contentA }, k: A.key });
show("addReportComment(payload approuve, 2e fois)", c3, 420);
const id3 = c3.j?.data?.addReportComment?.id;
await sleep(1500);

console.log("\n=== VERDICT ===");
const ok0 = !!id0, ok1 = !!id1, ok2 = !!c2.j?.data?.markNotificationAsRead, idem = id3 && id0 && id3 === id0;
console.log("  1) payload approuve execute            : " + (ok0 ? "OUI (commentaire " + id0 + ")" : "NON"));
console.log("  2) rejeu contenu MODIFIE accepte      : " + (ok1 ? "*** OUI -> BINDING ROMPU ***" : "non (refuse)"));
console.log("  3) rejeu AUTRE MUTATION accepte       : " + (ok2 ? "*** OUI -> BINDING ROMPU ***" : "non (refuse)"));
console.log("  4) idempotence (meme payload 2e fois) : " + (idem ? "OK (meme resultat, pas de doublon)" : (id3 ? "commentaire different -> pas d idempotence" : "refuse")));
console.log("\n  (identifiants de commentaires : approuve=" + id0 + " modifie=" + (id1 || "-") + " rejeu=" + (id3 || "-") + ")");
