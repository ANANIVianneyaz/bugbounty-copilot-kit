// P6 : API de lecture de l'analytics (PostHog) auto-heberge derriere /ingest sur le meme domaine que l'app.
// Regle de preuve : on ne dump aucun contenu PII - on note statut + forme + compte quand c'est lisible.
const APP = "https://bugsecure.senintel.sn";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function head(url) {
  try {
    const r = await fetch(url, { method: "GET", headers: { "User-Agent": UA, "Accept": "*/*" }, redirect: "manual" });
    const t = await r.text();
    return { s: r.status, t, loc: r.headers.get("location") || "", ct: r.headers.get("content-type") || "" };
  } catch (e) {
    return { s: 0, t: "ERR " + (e.cause?.code || e.message), loc: "", ct: "" };
  }
}
function shape(t) {
  if (!t) return "(vide)";
  try {
    const j = JSON.parse(t);
    if (Array.isArray(j)) return "JSON[] len=" + j.length + " cles=" + (j[0] ? Object.keys(j[0]).slice(0, 12).join(",") : "-");
    if (j && typeof j === "object") {
      const ks = Object.keys(j);
      const det = ks.slice(0, 12).join(",");
      const c = j.count ?? j.total ?? j.results?.length ?? j.data?.length;
      return "JSON{} cles=[" + det + "]" + (c !== undefined ? " count=" + c : "");
    }
    return "JSON scalaire " + JSON.stringify(j).slice(0, 60);
  } catch {
    return t.slice(0, 90).replace(/\s+/g, " ");
  }
}

console.log("=== 0) config PostHog dans le HTML de l'app ===");
const app = await head(APP + "/");
const ph = [...app.t.matchAll(/(api_host|apiHost|api_url|apiUrl|host)["'\s:=]+([a-zA-Z0-9:/._-]*posthog[a-zA-Z0-9:/._-]*)/gi)].map((m) => m[0]);
console.log("app status", app.s, "| occurrences posthog:", ph.length);
for (const p of new Set(ph)) console.log("   ", p);
const proj = [...app.t.matchAll(/phc_[A-Za-z0-9]{20,}/g)].map((m) => m[0]);
const projU = [...new Set(proj)];
console.log("   project tokens vus dans le HTML:", projU.join(", ") || "(aucun)");
const cfg = [...app.t.matchAll(/["']?api_host["']?\s*[:=]\s*["']([^"']+)["']/gi)].map((m) => m[1]);
console.log("   api_host:", cfg.join(" | ") || "(non trouve)");

// decouverte du chemin d'analytics dans le bundle
const hosts = new Set([...cfg, ...projU.map(() => "")]);
const P = projU[0] || "phc_myGuPycfa9UMAmmXHBjPJrqFhzkpvprNv7xof9DZ5Far";
const B = "/ingest";

console.log("\n=== 1) sondes de l'API de lecture sous " + B + " (sans authentification) ===");
const paths = [
  "",
  "/",
  "/api",
  "/api/projects",
  "/api/projects/" + P,
  "/api/projects/" + P + "/events",
  "/api/projects/" + P + "/events?limit=1",
  "/api/projects/" + P + "/insights",
  "/api/projects/" + P + "/insights?limit=1",
  "/api/projects/" + P + "/query",
  "/api/projects/" + P + "/session_recordings",
  "/api/projects/" + P + "/session_recordings?limit=1",
  "/api/projects/" + P + "/replays",
  "/api/projects/" + P + "/activity",
  "/api/projects/" + P + "/persons",
  "/api/projects/" + P + "/persons?limit=1",
  "/api/projects/" + P + "/surveys",
  "/api/projects/" + P + "/annotations",
  "/api/projects/" + P + "/cohorts",
  "/api/projects/" + P + "/dashboards",
  "/api/projects/" + P + "/experiments",
  "/api/projects/" + P + "/feature_flags",
  "/decide",
  "/decide?v=3",
  "/flags",
  "/flags?v=2",
  "/batch",
  "/batch/",
  "/array",
  "/capture",
  "/i/v0/e/",
  "/api/config",
  "/api/login",
  "/static/",
  "/_health",
  "/health",
  "/status",
  "/api/projects/" + P + "/hogql",
  "/api/projects/" + P + "/query?query=" + encodeURIComponent("SELECT count(*) FROM events"),
];
const res = [];
for (const p of paths) {
  const u = APP + B + p;
  const r = await head(u);
  const line = { p: p || "/", s: r.s, ct: r.ct.split(";")[0], body: shape(r.t) };
  res.push(line);
  console.log(
    String(line.s).padEnd(4) + (line.ct || "-").padEnd(24) + line.p.padEnd(62) + " " + line.body.slice(0, 110)
  );
  await sleep(120);
}

console.log("\n=== 2) memes sondes, mais hors du prefixe /ingest (le PostHog UI est-il expose ailleurs ?) ===");
for (const p of ["/", "/api/projects", "/api/projects/" + P + "/events", "/decide", "/static/"]) {
  const r = await head(APP + p);
  console.log(String(r.s).padEnd(4) + (r.ct || "-").padEnd(24) + p.padEnd(62) + " " + shape(r.t).slice(0, 110));
  await sleep(120);
}

console.log("\n=== 3) API de lecture avec un faux Bearer (le proxy laisse-t-il passer vers PostHog ?) ===");
for (const p of ["/api/projects/" + P + "/events", "/api/projects/" + P + "/query"]) {
  try {
    const r = await fetch(APP + B + p, {
      method: "GET",
      headers: { "User-Agent": UA, "Authorization": "Bearer phx_definitely_not_a_valid_key", "Accept": "application/json" },
    });
    const t = await r.text();
    console.log(String(r.status).padEnd(4) + p.padEnd(62) + " " + shape(t).slice(0, 160));
  } catch (e) {
    console.log("ERR", p, e.message);
  }
  await sleep(120);
}

console.log("\n=== 4) POST /ingest/api/projects/<P>/query (HogQL en lecture) ===");
try {
  const r = await fetch(APP + B + "/api/projects/" + P + "/query", {
    method: "POST",
    headers: { "User-Agent": UA, "Content-Type": "application/json" },
    body: JSON.stringify({ query: { kind: "HogQLQuery", query: "SELECT count(*) FROM events" } }),
  });
  const t = await r.text();
  console.log(r.status, shape(t).slice(0, 300));
} catch (e) {
  console.log("ERR", e.message);
}

console.log("\n=== 5)辨别 : reponse « PostHog » vs « app » (les 2 suffixes) ===");
for (const p of ["/", "/decide", "/api/projects/" + P + "/events"]) {
  const r = await head(APP + B + p);
  const mark = /posthog/i.test(r.t) ? "posthog" : /bugsecure|senintel/i.test(r.t) ? "app" : "?";
  console.log(String(r.s).padEnd(4) + mark.padEnd(9) + p);
  await sleep(100);
}
