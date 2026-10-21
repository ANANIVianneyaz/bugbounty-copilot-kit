// Mesure du rate-limit de removeTotpViaToken (endpoint NON authentifie)
//  - taille du burst
//  - vitesse de recharge
//  - le compteur est-il par IP, par token, ou global ?
import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const Q = `mutation RemoveTotpViaToken($token: String!) { removeTotpViaToken(token: $token) }`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const TAG = process.env.TAG || "local";
async function hit(tok) {
  const t0 = Date.now();
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query: Q, variables: { token: tok } }) });
  const txt = await r.text();
  let j = null; try { j = JSON.parse(txt); } catch {}
  const msg = j?.errors?.[0]?.message || (j?.data ? "false" : txt);
  const limited = /rate limit/i.test(msg);
  return { ms: Date.now() - t0, limited, msg: msg.slice(0, 60) };
}
const tok = () => "bb-" + Math.random().toString(36).slice(2, 12);

console.log(`=== [${TAG}] burst : jusqu'a 40 appels consecutifs ===`);
let n = 0, firstLimit = null;
const t0 = Date.now();
for (let i = 0; i < 40; i++) {
  const r = await hit(tok());
  n++;
  if (r.limited && firstLimit === null) { firstLimit = { at: n, ms: Date.now() - t0 }; console.log(`  [${TAG}] premiere limite a l'appel n=${n} (${Date.now() - t0}ms)`); }
  await sleep(120);
}
console.log(`  [${TAG}] appels effectues: ${n} | limite atteinte: ${firstLimit ? "oui (n=" + firstLimit.at + ")" : "NON"}`);

console.log(`\n=== [${TAG}] recharge : attente 65s puis 8 tentatives ===`);
await sleep(65000);
let ok = 0;
for (let i = 0; i < 8; i++) {
  const r = await hit(tok());
  if (!r.limited) { ok++; console.log(`  [${TAG}] t+65s appel ${i + 1}: OK (${r.ms}ms) ${r.msg}`); }
  else console.log(`  [${TAG}] t+65s appel ${i + 1}: LIMITE (${r.ms}ms)`);
  await sleep(200);
}
console.log(`  [${TAG}] appels reussis apres 65s: ${ok}/8`);

console.log(`\n=== [${TAG}] le meme token rechange-t-il le compteur ? ===`);
const same = tok();
for (let i = 0; i < 3; i++) { const r = await hit(same); console.log(`  [${TAG}] meme token #${i + 1}: ${r.limited ? "LIMITE" : "OK"} (${r.ms}ms)`); await sleep(150); }
fs.writeFileSync(`/tmp/opencode/ratelimit-${TAG}.json`, JSON.stringify({ tag: TAG, firstLimit, okAfter65s: ok }, null, 1));
