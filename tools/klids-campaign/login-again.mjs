// Reconnexion autonome : le 2FA a ete supprime -> BountyLogin doit rendre un jeton complet.
// On essaie les shapes plausibles et on lit les messages d erreur de l API pour converger.
import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const EMAIL = "williamnex24lechallenge@gmail.com";
const PASS = "bb-test-2026!";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function call(q, v) {
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query: q, variables: v || {} }) });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, j, t };
}
const show = (l, r) => {
  const e = r.j?.errors ? "ERR: " + r.j.errors.map((x) => x.message).join(" | ") : JSON.stringify(r.j?.data);
  console.log("  " + l.padEnd(62) + "HTTP " + r.s + "  " + e.slice(0, 190));
  return r;
};

console.log("=== A) formes de mutation possibles ===");
const candidates = [
  ["BountyLoginInput + input", `mutation($input: BountyLoginInput!){ bountyLogin(input:$input){ accessToken refreshToken requiresTwoFactor } }`, { input: { email: EMAIL, password: PASS } }],
  ["LoginInput + input", `mutation($input: LoginInput!){ bountyLogin(input:$input){ accessToken refreshToken requiresTwoFactor } }`, { input: { email: EMAIL, password: PASS } }],
  ["SignInInput + input", `mutation($input: SignInInput!){ bountyLogin(input:$input){ accessToken refreshToken requiresTwoFactor } }`, { input: { email: EMAIL, password: PASS } }],
  ["args directs", `mutation($email:String!,$password:String!){ bountyLogin(email:$email,password:$password){ accessToken refreshToken requiresTwoFactor } }`, { email: EMAIL, password: PASS }],
  ["username au lieu de email", `mutation($input: LoginInput!){ bountyLogin(input:$input){ accessToken refreshToken requiresTwoFactor } }`, { input: { username: "william_root", password: PASS } }],
];
for (const [l, q, v] of candidates) { show(l, await call(q, v)); await sleep(700); }

console.log("\n=== B) le mutation a repondu ? on rejoue la forme qui a marche ===");
let ok = null;
for (const [l, q, v] of candidates) {
  const r = await call(q, v);
  if (!r.j?.errors) { ok = { l, q, v, r }; console.log("  FORME RETENUE: " + l); break; }
  await sleep(700);
}
if (!ok) { console.log("  aucune forme n'a abouti -> envoyer le message d erreur le plus parlant"); process.exit(1); }
const data = ok.r.j.data.bountyLogin;
console.log("  requiresTwoFactor:", data.requiresTwoFactor);
console.log("  accessToken:", data.accessToken ? data.accessToken.slice(0, 40) + "..." : null);
console.log("  refreshToken:", data.refreshToken ? data.refreshToken.slice(0, 24) + "..." : null);
if (data.accessToken) {
  const c = JSON.parse(Buffer.from(data.accessToken.split(".")[1], "base64url").toString());
  console.log("  claims:", JSON.stringify(c));
  fs.writeFileSync("/tmp/opencode/session-at.txt", data.accessToken);
  if (data.refreshToken) fs.writeFileSync("/tmp/opencode/session-rt.txt", data.refreshToken);
  console.log("  -> ecrit /tmp/opencode/session-at.txt (+ session-rt.txt)");
}
