// CyberAar : creation du compte de test (en arriere-plan, car l endpoint d inscription est rate-limite)
// Email fourni par le chercheur : un ALIAS de son adresse (le +bb1) -> la verification tombe dans sa boite.
const BASE = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const EM = process.env.EM;
const LOG = "/tmp/opencode/cyberaar/registration.log";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
if (!EM) { console.error("EM manquant"); process.exit(1); }
const body = { name: "bb-probe", email: EM, profile: "Chercheur securite - evaluation de la surface AarMe", level: "debutant", password: "Bb-test-2026-ok!", accord: true, lang: "fr", hp: "" };
const log = (s) => { console.log(s); try { require("fs").appendFileSync(LOG, s + "\n"); } catch {} };
const { appendFileSync } = await import("node:fs");
const note = (s) => { console.log(s); try { appendFileSync(LOG, s + "\n"); } catch {} };

let attempt = 0;
while (attempt < 40) {
  attempt++;
  const t0 = Date.now();
  let r = null, txt = "";
  try {
    r = await fetch(BASE + "/api/aarme/account/register", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, Origin: BASE, Referer: BASE + "/compte/" },
      body: JSON.stringify(body), redirect: "manual", signal: AbortSignal.timeout(25000),
    });
    txt = await r.text();
  } catch (e) { txt = "ERR " + (e.cause?.code || e.message); }
  const s = r ? r.status : 0;
  note(`[${new Date().toISOString()}] essai ${attempt} : HTTP ${s} ${Date.now() - t0}ms  ${txt.replace(/\s+/g, " ").slice(0, 200)}`);
  if (s === 200 || s === 201) {
    const ck = (r.headers.getSetCookie?.() || []).map((c) => c.split(";")[0]).join("; ");
    note("  => COMPTE CREE. cookie=" + (ck || "(aucun cookie)"));
    if (ck) {
      const { writeFileSync } = await import("node:fs");
      writeFileSync("/tmp/opencode/cyberaar/session-cookie.txt", ck + "\n");
      const s1 = await fetch(BASE + "/api/aarme/account/session", { headers: { Accept: "application/json", "User-Agent": UA, Cookie: ck, Origin: BASE } });
      note("  session : " + (await s1.text()).replace(/\s+/g, " ").slice(0, 400));
    }
    break;
  }
  if (s === 429) { await sleep(120000); continue; }
  if (s === 400) { note("  => refus metier (" + txt.slice(0, 120) + ") -> arret"); break; }
  await sleep(60000);
}
note("=== fin du poll d inscription ===");
