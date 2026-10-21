// P6 bis : auto-inscription PostHog non authentifiee -> mesurer l impact reel
//  1) signup avec une adresse que je peux lire (boite mail.tm)
//  2) recuperation du lien de verification -> validation
//  3) login -> la reponse contient-elle une cle / un cookie de session ?
//  4) tentative de lecture des donnees du projet (events, session_recordings, persons, insights)
import fs from "fs";
const APP = "https://bugsecure.senintel.sn";
const P = "phc_myGuPycfa9UMAmmXHBjPJrqFhzkpvprNv7xof9DZ5Far";
const MAIL = fs.readFileSync("/tmp/opencode/mail_addr.txt", "utf8").trim();
const MAIL_TOKEN = fs.readFileSync("/tmp/opencode/mail_token.txt", "utf8").trim();
const PASS = "Bb-probe-2026-ok";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const J = { "Content-Type": "application/json" };
async function F(u, o = {}) { let e = null; for (let a = 0; a < 3; a++) { try { return await fetch(u, { ...o, signal: AbortSignal.timeout(25000) }); } catch (x) { e = x; await sleep(1500); } } return null; }

console.log("=== 1) inscription PostHog avec mon adresse lisible (" + MAIL + ") ===");
const email = MAIL;
const r = await F(APP + "/ingest/api/signup", { method: "POST", headers: J, body: JSON.stringify({ email, password: PASS, first_name: "BB", organization_name: "BB Probe Org" }) });
const txt = r ? await r.text() : "ERR";
console.log("  HTTP " + (r?.status ?? 0));
console.log("  corps complet : " + txt.slice(0, 900));
let j = null; try { j = JSON.parse(txt); } catch {}
fs.writeFileSync("/tmp/opencode/posthog-signup.json", JSON.stringify(j, null, 1));

console.log("\n=== 2) boite mail : un email de verification PostHog ? ===");
let msgs = [];
for (let i = 0; i < 8; i++) {
  const mr = await F("https://api.mail.tm/messages", { headers: { Authorization: "Bearer " + MAIL_TOKEN } });
  const mj = await mr.json().catch(() => ({}));
  msgs = Array.isArray(mj) ? mj : (mj["hydra:member"] || []);
  console.log("  poll " + (i + 1) + " : " + (msgs || []).length + " message(s) : " + (msgs || []).map((m) => (m.subject || "").slice(0, 50)).join(" | "));
  const post = (msgs || []).find((m) => /posthog|verif|confirm/i.test((m.subject || "") + " " + (m.intro || "")));
  if (post) {
    const dr = await F("https://api.mail.tm/messages/" + post.id, { headers: { Authorization: "Bearer " + MAIL_TOKEN } });
    const dj = await dr.json().catch(() => ({}));
    const body = (dj.html || []).map((h) => h.join(" ")).join(" ") + " " + (dj.text || "");
    console.log("  EMAIL TROUVE : " + post.subject);
    console.log("  extrait : " + body.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").slice(0, 400));
    const links = [...body.matchAll(/https?:\/\/[^\s"'<>\\)]+/g)].map((m) => m[0]);
    const cand = links.filter((l) => /posthog|verify|confirm|activate|signup/i.test(l));
    console.log("  liens candidats : " + cand.slice(0, 5).join("\n                    "));
    fs.writeFileSync("/tmp/opencode/posthog-verify-links.txt", cand.join("\n"));
    break;
  }
  await sleep(6000);
}
