// TEST MULTI-A-RECORD : le nom public est-il refuse quand un de ses A records est prive ?
// Protocole (Kimi §3) :
//   1. mesurer la resolution publique (plusieurs resolvers)
//   2. demander a l AS de fetcher le document CIMD -> la reponse (302/consent = fetch reussi,
//      erreur = refuse) et la LATENCE (le filtre agit-il avant ou apres la connexion ?)
//   3. verifier dans le journal d acces si la requete de l AS est arrivee (preuve OOB)
import { execSync } from "node:child_process";
const AS = "https://bugsecure-api.senintel.sn";
const HOST = process.env.TEST_HOST || "bb-test.enseignementsecondaire.bj";
const DOC = "https://" + HOST + "/doc/nojwks.json";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

console.log("=== 1) resolution publique du nom de test ===");
try {
  console.log("  getaddrinfo local :", execSync(`python3 -c "import socket;print(sorted({a[4][0] for a in socket.getaddrinfo('${HOST}',443,type=socket.SOCK_STREAM)}))"`).toString().trim());
} catch (e) { console.log("  (local indisponible)"); }
for (const resolver of ["1.1.1.1", "8.8.8.8", "9.9.9.9"]) {
  try {
    const out = execSync(`dig +short ${HOST} A @${resolver} 2>/dev/null || true`).toString().trim();
    console.log(`  dig @${resolver.padEnd(7)} : ${out.replace(/\n/g, " ").trim() || "(rien)"}`);
  } catch {}
}
try {
  console.log("  dig +trace (serveur de noms) :", execSync(`dig +short ${HOST} A | tr '\\n' ' '`).toString().trim());
} catch {}

console.log("\n=== 2) l AS fetch-t-il le document ? (5 mesures) ===");
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
for (let i = 0; i < 5; i++) {
  const u = AS + "/oauth/authorize?" + form({
    response_type: "code", client_id: DOC, redirect_uri: "https://" + HOST + "/cb",
    scope: "programs:read profile:read reports:read", state: "bb-" + Date.now() + "-" + i,
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", resource: AS,
  });
  const t0 = Date.now();
  const r = await fetch(u, { redirect: "manual" });
  const ms = Date.now() - t0;
  const loc = r.headers.get("location") || "";
  const verdict = loc.includes("/oauth/consent") ? "FETCH REUSSI (consentement)" : (loc.replace("https://bugsecure.senintel.sn", "") || (await r.text()).slice(0, 50));
  console.log(`  mesure ${i + 1} : HTTP ${r.status} ${String(ms).padStart(5)}ms  ${verdict.slice(0, 80)}`);
  await sleep(1500);
}

console.log("\n=== 3) la requete de l AS est-elle arrivee sur mon serveur ? (preuve OOB) ===");
try {
  const log = execSync(`ssh -o BatchMode=yes contabo 'docker exec bb-caddy-caddy-1 sh -c "tail -12 /data/access.log 2>/dev/null || cat /data/access.log 2>/dev/null"' 2>/dev/null || ssh -o BatchMode=yes contabo 'tail -12 /tmp/opencode/jwks-listener.log 2>/dev/null'`).toString();
  const lines = log.trim().split("\n").filter(Boolean).slice(-8);
  let n = 0;
  for (const l of lines) {
    if (l.includes("doc/") || l.includes("GET")) { console.log("  " + l.replace(/\{"ts.*?"request":\{"method":"(\w+)","uri":"([^"]*)"[^}]*"remote_ip":"([^"]*)"[^}]*"user-agent":"([^"]*)".*/, "  $1 $2  ip=$3  ua=$4").slice(0, 170)); n++; }
  }
  if (!n) console.log("  (aucune ligne pertinente)");
} catch (e) { console.log("  (log inaccessible: " + e.message.slice(0, 80) + ")"); }
