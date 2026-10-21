import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const T = process.env.BB_TOKEN;             // jeton emis AVANT le reset
const RESET_TOKEN = process.env.RESET_TOKEN; // token recu par email
const NEW_PASSWORD = process.env.NEW_PASSWORD || "bb-test-2026!";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const call = async (q, v) => {
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + T }, body: JSON.stringify({ query: q, variables: v || {} }) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, t, j };
};
const show = (l, r, m = 300) => console.log("  " + l.padEnd(50) + "HTTP " + r.s + "  " + (r.j?.errors ? "ERR: " + r.j.errors.map((x) => x.message).join(" | ") : JSON.stringify(r.j?.data)).slice(0, m));
const claims = () => { try { return JSON.parse(Buffer.from(T.split(".")[1], "base64url").toString()); } catch { return {}; } };

console.log("=== JETON EMIS AVANT LE RESET ===");
const c0 = claims();
console.log("  iat=" + c0.iat + " (" + new Date(c0.iat * 1000).toISOString() + ")  exp=" + c0.exp + "  epoch=" + c0.epoch + "  roles=" + JSON.stringify(c0.roles));
console.log("\n=== A) AVANT le reset : le jeton vit-il ? ===");
show("me", await call("{ me { id username email } }", {}), 260);
await sleep(1200);
show("updateResearcherProfile (ecriture)", await call(`mutation($i:UpdateResearcherProfileInput!){ updateResearcherProfile(input:$i){ id bio } }`, { i: { bio: "bb-epoch-test" } }), 300);
await sleep(1200);

console.log("\n=== B) RESET : changement de mot de passe avec le token recu par email ===");
const r = await call(`mutation($p:String!,$t:String!){ resetPassword(newPassword:$p, token:$t) }`, { p: NEW_PASSWORD, t: RESET_TOKEN });
show("resetPassword(newPassword, token)", r, 300);
await sleep(2000);

console.log("\n=== C) APRES le reset : le jeton emis AVANT survit-il ? ===");
show("me (lecture)", await call("{ me { id username email } }", {}), 260);
await sleep(1200);
show("reports (lecture donnees)", await call("{ reports(take:3){ id title } }", {}), 260);
await sleep(1200);
show("updateResearcherProfile (ECRITURE)", await call(`mutation($i:UpdateResearcherProfileInput!){ updateResearcherProfile(input:$i){ id bio } }`, { i: { bio: "bb-epoch-test-after" } }), 320);
await sleep(1200);
show("myKycStatus (lecture)", await call("{ myKycStatus { status } }", {}), 220);
await sleep(1200);
show("notifications (lecture)", await call("{ notifications(take:2){ id type } }", {}), 220);

console.log("\n=== D) etat final du jeton ===");
const c1 = claims();
console.log("  meme jeton, claims inchangés : epoch=" + c1.epoch + " iat=" + c1.iat);
console.log("  => si 'me' et l'écriture passent encore ci-dessus, le jeton d acces SURVIT au changement de mot de passe");
console.log("\n  (le nouveau mot de passe du compte de test est : " + NEW_PASSWORD + ")");
