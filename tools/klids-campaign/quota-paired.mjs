const AS = "https://bugsecure-api.senintel.sn";
const TUN = process.env.TUN;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const F = async (u, o = {}) => { for (let a = 0; a < 3; a++) { try { return await fetch(u, { ...o, signal: AbortSignal.timeout(25000) }); } catch (e) { await sleep(2500); } } return null; };

// Mesure PAIREE du quota : 12 DCR vs 12 CIMD, meme cadence, meme longueur de nom.
const N = 12;
let dcr = { ok: 0, quota: 0, other: 0 }, cimd = { ok: 0, quota: 0, other: 0 };
const dcrDetails = [], cimdDetails = [];
for (let i = 0; i < N; i++) {
  // --- DCR ---
  const r1 = await F(AS + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "bb-quota-test-" + i + "-" + Date.now(), redirect_uris: [TUN + "/cb"] }) });
  const t1 = r1 ? await r1.text() : "ERR";
  let cls = "other", msg = t1.slice(0, 60);
  try {
    const j = JSON.parse(t1);
    if (j.client_id) { cls = "ok"; msg = j.client_id.slice(0, 14); }
    else if (j.error === "temporarily_unavailable") { cls = "quota"; msg = j.error_description || j.error; }
    else { cls = "other"; msg = j.error || t1.slice(0, 60); }
  } catch {}
  dcr[cls]++; dcrDetails.push(i + ":" + cls);
  await sleep(3000);
  // --- CIMD ---
  const path = "/doc/q-" + Date.now() + "-" + i;
  const u = AS + "/oauth/authorize?response_type=code&client_id=" + encodeURIComponent(TUN + path) + "&redirect_uri=" + encodeURIComponent(TUN + "/cb") + "&scope=programs%3Aread%20profile%3Aread%20reports%3Aread&state=bb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=" + encodeURIComponent(AS);
  const r2 = await F(u, { redirect: "manual" });
  const loc = r2?.headers.get("location") || "";
  let cls2 = "other", msg2 = (loc.match(/code=([^&]+)/) || [])[1] || "";
  if (loc.includes("/oauth/consent")) { cls2 = "ok"; msg2 = "consentement ouvert"; }
  else if (msg2 === "temporarily_unavailable") { cls2 = "quota"; }
  cimd[cls2]++; cimdDetails.push(i + ":" + cls2);
  await sleep(3000);
}
console.log("=== QUOTA : inscription DCR vs client CIMD (12 tentatives chacun, meme cadence) ===\n");
console.log("  DCR  (POST /oauth/register) : " + JSON.stringify(dcr) + "   " + dcrDetails.join(" "));
console.log("  CIMD (client_id = URL)       : " + JSON.stringify(cimd) + "   " + cimdDetails.join(" "));
console.log("\n  => nombre de clients creats sans limitation : DCR " + dcr.ok + " / CIMD " + cimd.ok);
console.log("  => nombre de reponses de quota :               DCR " + dcr.quota + " / CIMD " + cimd.quota);
