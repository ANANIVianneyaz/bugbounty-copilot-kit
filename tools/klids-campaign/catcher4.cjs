// catcher4 : gestionnaire de grant OAuth multi-ressources.
//  - la "resource" est portee par le state (base64 JSON) -> le RT est stocke par ressource
//    (le refresh token d'une ressource n'est pas reutilisable sur une autre : "resource does not match")
//  - /token?resource=<url> : refresh depuis le RT de cette ressource (ou essai des autres)
//  - /callback : capture le code, l'echange, range RT/AT par ressource
const fs = require("fs");
const http = require("http");
const crypto = require("crypto");

const AS = "https://bugsecure-api.senintel.sn";
const EP = AS + "/graphql";
const DIR = "/tmp/opencode";
const LOG = DIR + "/oauth-catch.log";
const PKCE_FILE = DIR + "/pkce.json";
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
const key = (r) => r.replace(/[^a-z0-9]+/gi, "_").toLowerCase();
const rtFile = (r) => DIR + "/catcher-rt-" + key(r) + ".txt";
const atFile = (r) => DIR + "/catcher-at-" + key(r) + ".txt";

let PKCE = {};
const loadPkce = () => { try { PKCE = JSON.parse(fs.readFileSync(PKCE_FILE, "utf8")); } catch {} };
const log = (s) => { console.log(s); try { fs.appendFileSync(LOG, s + "\n"); } catch {} };
const claims = (t) => { try { return JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()); } catch { return {}; } };

function decodeState(state) {
  try {
    const j = JSON.parse(Buffer.from(state, "base64url").toString());
    return j.resource || null;
  } catch { return null; }
}
function makeState(resource) {
  return Buffer.from(JSON.stringify({ resource, n: crypto.randomBytes(8).toString("hex") })).toString("base64url");
}
async function verify(at) {
  try {
    const p = claims(at);
    if (!p.exp || p.exp - Math.floor(Date.now() / 1000) < 45) return false;
    const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + at }, body: JSON.stringify({ query: "{ me { id username } }" }) });
    const j = await r.json();
    return !!j?.data?.me;
  } catch { return false; }
}
async function refreshWith(resource) {
  let rt = "";
  try { rt = fs.readFileSync(rtFile(resource), "utf8").trim(); } catch {}
  if (!rt) return { error: "no rt for " + resource };
  const r = await fetch(AS + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form({ grant_type: "refresh_token", refresh_token: rt, client_id: "bugsecure-mcp-cli", resource }) });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch {}
  if (!j?.access_token) return { error: "refresh KO " + r.status + " " + t.slice(0, 140) };
  fs.writeFileSync(atFile(resource), j.access_token);
  if (j.refresh_token) fs.writeFileSync(rtFile(resource), j.refresh_token);
  const p = claims(j.access_token);
  log("[catch] refresh ok resource=" + resource + " exp dans " + (p.exp - Math.floor(Date.now() / 1000)) + "s");
  return { access_token: j.access_token, resource, expires_in: p.exp - Math.floor(Date.now() / 1000) };
}
async function freshToken(resource) {
  const r = resource || "https://bugsecure-api.senintel.sn";
  let at = "";
  try { at = fs.readFileSync(atFile(r), "utf8").trim(); } catch {}
  if (at && (await verify(at))) return { access_token: at, resource: r, cached: true };
  const res = await refreshWith(r);
  if (res.access_token) return res;
  // sinon : essayer les autres ressources connues
  for (const other of ["https://bugsecure-api.senintel.sn", "https://bugsecure-mcp.senintel.sn/mcp"]) {
    if (other === r) continue;
    const r2 = await refreshWith(other);
    if (r2.access_token) return { ...r2, requested: r, note: "token d'une autre ressource" };
  }
  return res;
}
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://127.0.0.1:53682");
  loadPkce();
  if (u.pathname === "/token") {
    const t = await freshToken(u.searchParams.get("resource"));
    res.writeHead(t.error ? 503 : 200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(t)); return;
  }
  if (u.pathname === "/ping") { res.writeHead(200); res.end("ok"); return; }
  if (u.pathname === "/state") { // genere un state encode(porteur de ressource) + une URL d'autorisation
    const resource = u.searchParams.get("resource") || "https://bugsecure-api.senintel.sn";
    const scope = u.searchParams.get("scope") || "programs:read profile:read reports:read reports:write";
    const st = makeState(resource);
    const url = AS + "/oauth/authorize?" + form({ response_type: "code", client_id: "bugsecure-mcp-cli", redirect_uri: PKCE.redirect_uri, scope, state: st, code_challenge: PKCE.challenge || "", code_challenge_method: "S256", resource });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ state: st, url })); return;
  }
  const code = u.searchParams.get("code"), state = u.searchParams.get("state"), err = u.searchParams.get("error");
  log("[catch] " + new Date().toISOString() + " " + req.method + " " + u.pathname + " err=" + (err || "-") + " state=" + String(state).slice(0, 24));
  if (err) { res.writeHead(400, { "Content-Type": "text/html" }); res.end("<h1>Erreur OAuth: " + err + "</h1>"); return; }
  if (!code) { res.writeHead(200, { "Content-Type": "text/html" }); res.end("<h1>catcher</h1>"); return; }
  if (state !== PKCE.state && !decodeState(state)) { res.writeHead(400); res.end("state invalide"); return; }
  const resource = decodeState(state) || "https://bugsecure-api.senintel.sn";
  const body = form({ grant_type: "authorization_code", code, redirect_uri: PKCE.redirect_uri, client_id: "bugsecure-mcp-cli", code_verifier: PKCE.verifier, resource });
  const r = await fetch(AS + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const txt = await r.text();
  log("[catch] token HTTP " + r.status + " resource=" + resource + " " + txt.slice(0, 140));
  try {
    const j = JSON.parse(txt);
    if (j.access_token) { fs.writeFileSync(atFile(resource), j.access_token); log("[catch] AT ecrit " + atFile(resource)); }
    if (j.refresh_token) { fs.writeFileSync(rtFile(resource), j.refresh_token); log("[catch] RT ecrit " + rtFile(resource)); }
  } catch {}
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end("<h1>OK</h1><p>Code echange pour " + resource + ". Tu peux fermer cet onglet.</p>");
});
server.listen(53682, "127.0.0.1", () => log("[catch] gestionnaire v4 (multi-ressources) en ecoute"));
