// =============================================================================
// VECTEUR UNIQUE : l'access token OAuth survit-il au changement de mot de passe ?
//
// Protocole (le reset est fait par le chercheur dans le navigateur, à son rythme) :
//   1. snapshot du jeton OAuth (AT1) AVANT le reset -> il ne sera jamais rafraîchi
//   2. boucle de rejeu continue (cycle de 3 s) pendant N minutes :
//        - lecture  : { me { id email } }                     <- le test d'authentification
//        - écritures (uniquement SI la lecture passe) :
//             * addReportComment          (reports:write)   -> effet visible (commentaire)
//             * updateResearcherProfile   (profile:write)   -> effet visible (bio)
//             * markAllNotificationsAsRead(notifications:write) -> effet silencieux
//        - le vieux refresh token reutilise (revocation du grant)
//        - le meme jeton envoye au serveur MCP (revocation interservices)
//        - variantes de parsing d'en-tetes (double Authorization, token dans le corps,
//          token dans clientRequestId)
//   3. chaque cycle est horodate (ns) et journalise en JSONL
//   4. verification finale des effets de bord avec un SECOND jeton frais
// =============================================================================
import fs from "fs";
import crypto from "crypto";
const API = "https://bugsecure-api.senintel.sn";
const EP = API + "/graphql";
const MCP = "https://bugsecure-mcp.senintel.sn/mcp";
const AT_FILE = "/tmp/opencode/catcher-at-https_bugsecure_api_senintel_sn.txt";
const RT_FILE = "/tmp/opencode/catcher-rt-https_bugsecure_api_senintel_sn.txt";
const OUT = "/tmp/opencode/residual-probe.jsonl";
const REPORT = "dca04201-559b-4088-bdc3-e1666ea42461";
const MINUTES = Number(process.env.MINUTES || 5);
const CYCLE_MS = Number(process.env.CYCLE_MS || 3000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");

const AT1 = fs.readFileSync(AT_FILE, "utf8").trim();
const RT1 = fs.readFileSync(RT_FILE, "utf8").trim();
const claims = (t) => { try { return JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()); } catch { return {}; } };
const c1 = claims(AT1);
console.log("=== JETON SOUS TEST (snapshot, jamais rafraichi) ===");
console.log("  jti      :", c1.jti);
console.log("  grant_id :", c1.grant_id);
console.log("  scope    :", c1.scope);
console.log("  aud      :", c1.aud);
console.log("  iat/exp  :", c1.iat, "->", c1.exp, "(duree de vie residuelle max apres le reset :", Math.max(0, c1.exp - Math.floor(Date.now() / 1000)), "s)");
console.log("  epoch present ?", "epoch" in c1, "| claims :", Object.keys(c1).join(","));
fs.writeFileSync("/tmp/opencode/AT1-snapshot.txt", AT1 + "\n");
fs.writeFileSync("/tmp/opencode/RT1-snapshot.txt", RT1 + "\n");

const H = { "Content-Type": "application/json", Authorization: "Bearer " + AT1, "User-Agent": "bb-bounty-residual-probe/1" };
async function gql(text, variables, headers = H) {
  const t0 = Date.now();
  try {
    const r = await fetch(EP, { method: "POST", headers, body: JSON.stringify({ query: text, variables }) });
    const txt = await r.text();
    let j = null; try { j = JSON.parse(txt); } catch {}
    return { ms: Date.now() - t0, s: r.status, j, txt };
  } catch (e) { return { ms: Date.now() - t0, s: 0, j: null, txt: "ERR " + e.message }; }
}
const msg = (r) => (r.j?.errors ? r.j.errors.map((e) => e.message).join(" | ") : (r.j?.data ? "DATA " + JSON.stringify(r.j.data).slice(0, 120) : r.txt.slice(0, 120)));
const write = (rec) => fs.appendFileSync(OUT, JSON.stringify(rec) + "\n");
fs.writeFileSync(OUT, "");

console.log("\n=== BOUCLE DE REJEU (" + MINUTES + " min, cycle " + CYCLE_MS + " ms) ===");
console.log("  -> le chercheur change le mot de passe quand il veut ; le journal date chaque cycle\n");
const t0all = Date.now();
let cycle = 0, firstDead = null, lastAlive = null;
while (Date.now() - t0all < MINUTES * 60000) {
  cycle++;
  const ts = new Date().toISOString();
  const rec = { cycle, ts, t_rel_ms: Date.now() - t0all };

  // (1) lecture : le test d'authentification
  const read = await gql(`query { me { id email } }`, {});
  rec.read = { s: read.s, ms: read.ms, msg: msg(read) };
  const alive = !/Unauthorized|Session ended|UNAUTHENTICATED|invalid|expired|revoked/i.test(read.txt) && read.s === 200;
  rec.alive = alive;

  if (alive) {
    lastAlive = rec;
    // (2) ecritures avec effets de bord observables
    const marker = "residual-" + Date.now();
    const w1 = await gql(`mutation($i:AddCommentInput!){ addReportComment(input:$i){ id content createdAt } }`, { i: { reportId: REPORT, content: marker + " comment" } });
    rec.write_comment = { s: w1.s, ms: w1.ms, msg: msg(w1) };
    const w2 = await gql(`mutation($i:UpdateResearcherProfileInput!){ updateResearcherProfile(input:$i){ id bio } }`, { i: { bio: marker + " bio" } });
    rec.write_profile = { s: w2.s, ms: w2.ms, msg: msg(w2) };
    const w3 = await gql(`mutation{ markAllNotificationsAsRead }`, {});
    rec.write_notifications = { s: w3.s, ms: w3.ms, msg: msg(w3) };
    // (3) variantes de parsing / smuggling
    const dbl = await gql(`query { me { id } }`, {}, { ...H, Authorization: "Bearer " + AT1 + ", Bearer null" });
    rec.double_auth = { s: dbl.s, msg: msg(dbl) };
    const bodyTok = await gql(`query { me { id } }`, { tok: "Bearer " + AT1 }, { "Content-Type": "application/json", Authorization: "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.dead" });
    rec.token_in_body = { s: bodyTok.s, msg: msg(bodyTok) };
  } else if (!firstDead) {
    firstDead = rec;
  }

  // (4) le vieux refresh token, reutilise
  try {
    const r = await fetch(API + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form({ grant_type: "refresh_token", refresh_token: RT1, client_id: "bugsecure-mcp-cli", resource: API }) });
    const txt = await r.text();
    rec.old_rt = { s: r.status, msg: txt.replace(/\s+/g, " ").slice(0, 160) };
    if (r.status === 200) { try { const c = claims(JSON.parse(txt).access_token); rec.old_rt.new_claims = { jti: c.jti, grant_id: c.grant_id, epoch: c.epoch, scope: c.scope }; } catch {} }
  } catch (e) { rec.old_rt = { s: 0, msg: e.message }; }

  // (5) le meme jeton contre le serveur MCP (revocation interservices)
  try {
    const r = await fetch(MCP, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: "Bearer " + AT1, "User-Agent": "bb-bounty-residual-probe/1" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_my_profile", arguments: {} } }) });
    const txt = await r.text();
    rec.mcp = { s: r.status, msg: txt.replace(/\s+/g, " ").slice(0, 140) };
  } catch (e) { rec.mcp = { s: 0, msg: e.message }; }

  write(rec);
  const st = alive ? "VIVANT" : "MORT ";
  console.log(`  [${ts}] cycle ${String(cycle).padStart(3)} ${st} lecture: ${rec.read.msg.slice(0, 70)}` + (alive ? ` | write: ${rec.write_comment.msg.slice(0, 40)}` : ""));
  await sleep(CYCLE_MS);
}

console.log("\n=== BILAN ===");
console.log("  cycles           :", cycle);
console.log("  dernier vivant   :", lastAlive ? `cycle ${lastAlive.cycle} à ${lastAlive.ts}` : "aucun");
console.log("  premier mort     :", firstDead ? `cycle ${firstDead.cycle} à ${firstDead.ts} (${firstDead.read.msg.slice(0, 80)})` : "aucun (le jeton a survécu à toute la fenêtre)");
if (lastAlive && firstDead) console.log("  instant de la mort:", ((new Date(firstDead.ts) - new Date(lastAlive.ts)) / 1000).toFixed(1), "s après le dernier cycle vivant");
console.log("  journal          :", OUT);

console.log("\n=== VERIFICATION DES EFFETS DE BORD avec un jeton FRAIS (2e jeton) ===");
const { ensureToken } = await import("/tmp/opencode/token-store.mjs");
const { token: AT2 } = await ensureToken(API);
const H2 = { "Content-Type": "application/json", Authorization: "Bearer " + AT2, "User-Agent": "bb-bounty-residual-probe/1" };
const H3 = H2;
const v1 = await gql(`query($r:ID!){ reportComments(reportId:$r){ id content createdAt } }`, { r: REPORT }, H2);
console.log("  commentaires du rapport :", msg(v1).slice(0, 700));
const v2 = await gql(`query { me { id profile { bio } } }`, {}, H2);
console.log("  mon profil (bio)       :", msg(v2).slice(0, 300));
const v3 = await gql(`query{ notifications(skip:0, take:50, unreadOnly:true){ id title readAt } }`, {}, H3);
console.log("  notifications non lues:", msg(v3).slice(0, 300));
