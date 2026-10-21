// Helper unique : RAFRAICHIR un token ET sauvegarder le couple (AT, RT) — discipline obligatoire,
// le refresh token est rotatif (l'ancien est invalide apres chaque usage).
import fs from "fs";
const AS = "https://bugsecure-api.senintel.sn";
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
const key = (r) => r.replace(/[^a-z0-9]+/gi, "_").toLowerCase();
const AT = (r) => "/tmp/opencode/catcher-at-" + key(r) + ".txt";
const RT = (r) => "/tmp/opencode/catcher-rt-" + key(r) + ".txt";
const claims = (t) => { try { return JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()); } catch { return {}; } };

export async function ensureToken(resource) {
  let at = "";
  try { at = fs.readFileSync(AT(resource), "utf8").trim(); } catch {}
  const c = claims(at);
  if (at && c.exp && c.exp - Math.floor(Date.now() / 1000) > 120) return { token: at, source: "cache", exp: c.exp };
  const rt = fs.readFileSync(RT(resource), "utf8").trim();
  const r = await fetch(AS + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form({ grant_type: "refresh_token", refresh_token: rt, client_id: "bugsecure-mcp-cli", resource }) });
  const j = await r.json();
  if (!j.access_token) {
    console.error("[refresh] ECHEC " + resource + " : " + JSON.stringify(j).slice(0, 160));
    return { token: at, source: "cache-expire", exp: c.exp, error: j };
  }
  // SAUVEGARDE IMMEDIATE (le RT est rotatif : l'ancien est invalide des ce refresh)
  fs.writeFileSync(AT(resource), j.access_token);
  if (j.refresh_token) fs.writeFileSync(RT(resource), j.refresh_token);
  const c2 = claims(j.access_token);
  console.error("[refresh] OK " + resource + " jti=" + c2.jti + " exp dans " + (c2.exp - Math.floor(Date.now() / 1000)) + "s (RT sauvegarde)");
  return { token: j.access_token, source: "refresh", exp: c2.exp };
}

if (import.meta.url.endsWith(process.argv[1].split("/").pop())) {
  for (const r of [process.argv[2] || "https://bugsecure-api.senintel.sn", process.argv[3] || "https://bugsecure-mcp.senintel.sn/mcp"]) {
    const t = await ensureToken(r);
    console.log(r, "->", t.source, "| exp", t.exp, t.error ? JSON.stringify(t.error) : "");
  }
}
