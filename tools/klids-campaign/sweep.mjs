import fs from "fs";
import crypto from "crypto";

const EP = "https://bugsecure-api.senintel.sn/graphql";
const AS = "https://bugsecure-api.senintel.sn";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const form = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
const uuid = () => crypto.randomUUID();

// ---------- jeton : le catcher local est le SEUL porteur du refresh token ----------
let T = "";
const AUTH = process.env.AUTH !== "0";

async function getToken() { // CATCHER : gestionnaire unique du grant
  const r = await fetch("http://127.0.0.1:53682/token");
  const j = await r.json();
  if (!j.access_token) throw new Error("token: " + JSON.stringify(j).slice(0, 120));
  return j.access_token;
}
if (AUTH) T = process.env.BB_TOKEN || (await getToken());

// ---------- registre de types (schema du repo) ----------
const schema = fs.readFileSync("/tmp/opencode/schema.graphql", "utf8");
const TYPES = {}, ENUMS = {}, INPUTS = {};
for (const m of schema.matchAll(/^type\s+(\w+)\s*\{([\s\S]*?)^\}/gm)) {
  const f = {};
  for (const l of m[2].split("\n")) {
    const mm = l.match(/^\s*(\w+)\s*(\([^)]*\))?\s*:\s*([\[\]!\w ]+)/);
    if (mm) f[mm[1]] = mm[3].trim();
  }
  TYPES[m[1]] = f;
}
for (const m of schema.matchAll(/^enum\s+(\w+)\s*\{([\s\S]*?)^\}/gm)) {
  ENUMS[m[1]] = m[2].split("\n").map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
}
for (const m of schema.matchAll(/^input\s+(\w+)\s*\{([\s\S]*?)^\}/gm)) {
  const f = {};
  for (const l of m[2].split("\n")) {
    const mm = l.match(/^\s*(\w+)\s*:\s*([\[\]!\w ]+)/);
    if (mm) f[mm[1]] = mm[2].trim();
  }
  INPUTS[m[1]] = f;
}
const ENUM_FALLBACK = ["PENDING", "ACTIVE", "APPROVED", "VALIDATED", "LOW", "MEDIUM", "CRITICAL", "HIGH", "OPEN", "CLOSED"];

function valueForType(t, name = "") {
  t = t.trim();
  const bare = t.replace(/[\[\]!]/g, "").trim();
  if (ENUMS[bare]) return ENUMS[bare][0];
  if (bare.endsWith("Input") || INPUTS[bare]) return {};
  if (bare === "String") return "bb-test";
  if (bare === "ID") return uuid();
  if (bare === "Int") return 1;
  if (bare === "Float") return 1;
  if (bare === "Boolean") return false;
  if (t.startsWith("[")) return [];
  if (/^[A-Z]/.test(bare)) return ENUM_FALLBACK.includes(name) ? name : "PENDING";
  return "bb-test";
}

// ---------- suppression d un champ de selection ----------
function removeField(text, field) {
  const re = new RegExp("(^|[\\s{,])" + field + "\\b", "g");
  let m;
  while ((m = re.exec(text))) {
    const start = m.index + m[1].length;
    let i = start + field.length, p = 0, b = 0, inStr = false;
    while (i < text.length) {
      const c = text[i];
      if (inStr) { if (c === "\\") i++; else if (c === '"') inStr = false; i++; continue; }
      if (c === '"') inStr = true;
      else if (c === "(") p++;
      else if (c === ")") p--;
      else if (c === "{") b++;
      else if (c === "}") b--;
      else if (p === 0 && b === 0 && (c === " " || c === "\n" || c === "," || c === "}" || c === ")")) break;
      i++;
    }
    let j = i, p2 = 0, b2 = 0, inS = false;
    while (j < text.length) {
      const c = text[j];
      if (inS) { if (c === "\\") j++; else if (c === '"') inS = false; j++; continue; }
      if (c === '"') inS = true;
      else if (c === "(") p2++;
      else if (c === ")") p2--;
      else if (c === "{") b2++;
      else if (c === "}") { b2--; if (b2 === 0 && p2 === 0) { j++; break; } }
      j++;
    }
    let end = j;
    while (end < text.length && /\s/.test(text[end])) end++;
    if (text[end] === ",") end++;
    else { let s2 = start; while (s2 > 0 && /\s/.test(text[s2 - 1])) s2--; if (text[s2 - 1] === ",") end = s2; }
    return text.slice(0, start) + text.slice(end);
  }
  return null;
}
function setPath(obj, path, value) {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof cur[parts[i]] !== "object" || cur[parts[i]] === null) cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
}

// ---------- operations ----------
const raw = fs.readFileSync("/tmp/opencode/allops.txt", "utf8");
const blocks = raw.split(/^######## /m).slice(1);
const OPS = [];
for (const b of blocks) {
  const nl = b.indexOf("\n");
  const name = b.slice(0, nl).trim();
  const text = b.slice(nl + 1).trim();
  const kind = /^\s*mutation/.test(text) ? "mutation" : "query";
  const vars = [...text.matchAll(/\$(\w+)\s*:\s*([\[\]!\w ]+)/g)].map((m) => ({ name: m[1], type: m[2].trim() }));
  OPS.push({ name, kind, text, vars });
}
const SKIP = /Enable2fa|Disable2fa|GenerateBackupCodes|Verify2fa|ChangePassword|ResetPassword|ForgotPassword|RevokeSession|RevokeAllSessions|DeleteAccount|CreateOrganization|CreateProgramme|CreateApiToken|AcceptOrganizationInvitation|Invite|Logout|RevokeOAuthGrant|Withdrawal|Withdraw|Payout|Settle/i;

async function gql(text, variables, auth) {
  const r = await fetch(EP, { method: "POST", headers: { "Content-Type": "application/json", ...(auth ? { Authorization: "Bearer " + T } : {}) }, body: JSON.stringify({ query: text, variables }) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, j };
}

function classify(r) {
  const errs = r.j?.errors || [];
  if (!errs.length) {
    const d = r.j?.data;
    const flat = JSON.stringify(d);
    if (flat && flat !== "{}" && !/"me":null/.test(flat) && !/"[a-zA-Z]+":null/.test(flat)) return ["DATA", flat.slice(0, 200)];
    return ["EMPTY", flat ? flat.slice(0, 120) : ""];
  }
  const m = errs.map((e) => e.message).join(" | ");
  if (/requires the scope/i.test(m)) return ["SCOPE", m.replace(/.*requires the scope\(s\):/, "").slice(0, 80)];
  if (/not available to OAuth clients/i.test(m)) return ["OAUTH-BLOCKED", ""];
  if (/Unauthorized|not authenticated|Authentication required/i.test(m)) return ["UNAUTH", ""];
  if (/Forbidden|forbidden|not allowed|must be a member|not a member/i.test(m)) return ["FORBIDDEN", m.slice(0, 110)];
  if (/not found|Not found|does not exist/i.test(m)) return ["NOT-FOUND", m.slice(0, 110)];
  if (/revoked|expired/i.test(m)) return ["TOKEN-DEAD", m.slice(0, 60)];
  return ["OTHER", m.slice(0, 170)];
}

async function runOp(op, auth) {
  let text = op.text;
  let variables = {};
  for (const v of op.vars) variables[v.name] = valueForType(v.type);
  const trail = [];
  for (let iter = 0; iter < 7; iter++) {
    const r = await gql(text, variables, auth);
    const errs = r.j?.errors || [];
    if (!errs.length) { trail.push("ok"); return { text, variables, res: r, trail, iter }; }
    const e0 = errs[0].message;
    // 0) token revoque/expire -> on reprend un jeton frais et on rejoue
    if (AUTH && /revoked|expired|token signature/i.test(e0)) {
      const fresh = await getToken();
      if (fresh !== T) { T = fresh; trail.push("token->frais"); await sleep(500); continue; }
    }
    // 1) champ requis manquant (dans une variable)
    let m = e0.match(/Variable "\$(\w+)" got invalid value[\s\S]*?Field "([\w.]+)" of required type "([^"]+)" was not provided/);
    if (m) {
      const [, vn, path, typ] = m;
      const cur = variables[vn];
      if (cur && typeof cur === "object") {
        const leaf = path.split(".").pop();
        setPath(cur, path, valueForType(typ, leaf));
        trail.push("fill " + path + ":" + typ);
        await sleep(350); continue;
      }
    }
    // 2) type inconnu -> plus proche voisin dans le registre
    m = e0.match(/Unknown type "(\w+)"/);
    if (m) {
      const bad = m[1];
      const cands = [...Object.keys(TYPES), ...Object.keys(INPUTS), ...Object.keys(ENUMS)];
      let best = null, bd = 99;
      for (const c of cands) {
        const d = Math.abs(c.length - bad.length) + (c.toLowerCase() === bad.toLowerCase() ? 0 : 2);
        if (d < bd) { bd = d; best = c; }
      }
      if (best && best !== bad) { text = text.replace(new RegExp("\\b" + bad + "\\b", "g"), best); trail.push("type " + bad + "->" + best); await sleep(350); continue; }
    }
    // 3) champ inexistant -> suppression
    m = e0.match(/Cannot query field "(\w+)" on type "(\w+)"/);
    if (m) {
      const nt = removeField(text, m[1]);
      if (nt && nt !== text) { text = nt; trail.push("del " + m[1]); await sleep(350); continue; }
    }
    // 4) argument invalide -> on retire l argument
    m = e0.match(/Field "(\w+)" argument "(\w+)" has invalid value/);
    if (m) {
      const re = new RegExp("\\(" + m[2] + "\\s*:\\s*[^)]*\\)");
      if (re.test(text)) { text = text.replace(re, ""); trail.push("delArg " + m[2]); await sleep(350); continue; }
    }
    // 5) valeur d enum invalide -> valeur suivante du registre
    m = e0.match(/Value "([^"]*)" does not exist in "(\w+)" enum/);
    if (m) {
      const [, , en] = m;
      const vals = ENUMS[en] || [];
      const cur = JSON.stringify(variables);
      const next = vals.find((v) => !cur.includes('"' + v + '"'));
      if (next) { const nv = variables; for (const k of Object.keys(nv)) if (nv[k] === m[1]) nv[k] = next; trail.push("enum " + en + "->" + next); await sleep(350); continue; }
    }
    // 6) selection invalide sur un scalaire -> on retire la selection
    m = e0.match(/Field "(\w+)" of type "[\w\[\]!]+" must not have a selection since type "[\w\[\]!]+" has no subfields/);
    if (m) {
      const re = new RegExp("\\b" + m[1] + "\\s*\\{[^{}]*\\}");
      if (re.test(text)) { text = text.replace(re, m[1]); trail.push("unsel " + m[1]); await sleep(350); continue; }
    }
    trail.push("stop:" + e0.slice(0, 60));
    return { text, variables, res: r, trail, iter, unresolved: e0 };
  }
  return { text, variables, res: null, trail, iter: 7, unresolved: "boucle" };
}

const LIMIT = Number(process.env.LIMIT || 0);

const OUT = process.env.OUT || "/tmp/opencode/sweep-auth.json";
const list = LIMIT ? OPS.slice(0, LIMIT) : OPS;
const results = [];
console.log("operations: " + list.length + " | auth: " + AUTH + "\n");
let done = new Set();
try { for (const r of JSON.parse(fs.readFileSync(OUT, "utf8"))) done.add(r.name); } catch {}
for (const op of list) {
  if (done.has(op.name)) { console.log("  (deja) " + op.name); continue; }
  if (SKIP.test(op.name)) { console.log("  SKIP  " + op.name); results.push({ name: op.name, kind: op.kind, cls: "SKIP" }); continue; }
  const out = await runOp(op, AUTH);
  const [cls, detail] = out.res ? classify(out.res) : ["UNRESOLVED", out.unresolved || ""];
  results.push({ name: op.name, kind: op.kind, cls, detail, trail: out.trail, iters: out.iter, text: out.text, variables: out.variables });
  console.log("  " + op.name.padEnd(34) + op.kind.padEnd(9) + cls.padEnd(15) + "i" + out.iter + " " + String(detail).replace(/\s+/g, " ").slice(0, 120));
  fs.writeFileSync(OUT, JSON.stringify(results, null, 1));
  await sleep(650);
}
console.log("\n=== RECAP ===");
const by = {};
for (const r of results) { const k = (r.kind === "mutation" ? "M" : "Q") + ":" + r.cls; by[k] = (by[k] || 0) + 1; }
console.log(Object.entries(by).sort().map(([k, v]) => k + " = " + v).join("   "));
console.log("\n=== TOUTES LES OPERATIONS QUI RETOURNENT DES DONNEES (priorite) ===");
for (const r of results) if (r.cls === "DATA") console.log("  *** " + r.kind + " " + r.name + " -> " + r.detail.slice(0, 220));
