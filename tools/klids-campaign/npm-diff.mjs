// DIFF npm vs dépôt (Kimi 4b / Grok 11) : le paquet publié contient-il des secrets figés,
// des endpoints de staging, des defaults permissifs, des dépendances à risque ?
import { execSync } from "node:child_process";
import fs from "fs";
import os from "os";
import path from "path";
const PKG = "@kulinda-sec/bugsecure-mcp";
const REPO = "/tmp/opencode/bugsecure-mcp";
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "npmdiff-"));
console.log("=== 1) métadonnées npm ===");
try {
  const meta = JSON.parse(execSync(`npm view ${PKG} --json 2>/dev/null`).toString());
  console.log("  version publiée :", meta.version);
  console.log("  repository      :", JSON.stringify(meta.repository));
  console.log("  dist.tarball    :", meta.dist?.tarball);
  console.log("  scripts         :", JSON.stringify(meta.scripts));
  console.log("  bin             :", JSON.stringify(meta.bin));
  console.log("  deps            :", Object.keys(meta.dependencies || {}).length, "paquets");
  console.log("  fichiers        :", (meta.files || []).length, "entrées dans files[]");
  console.log("  main/types      :", meta.main, "/", meta.types);
} catch (e) { console.log("  (npm view KO: " + e.message.slice(0, 80) + ")"); }

console.log("\n=== 2) téléchargement et extraction du paquet ===");
execSync(`cd ${TMP} && npm pack ${PKG} --silent`, { stdio: "ignore" });
const tgz = fs.readdirSync(TMP).find((f) => f.endsWith(".tgz"));
if (!tgz) { console.log("  (paquet introuvable)"); process.exit(0); }
execSync(`cd ${TMP} && tar xzf ${tgz}`);
console.log("  extrait :", tgz, `(${(fs.statSync(path.join(TMP, "package")).isDirectory() ? "" : "")}package/)`);
const walk = (d, base = d, out = []) => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) walk(f, base, out);
    else out.push(path.relative(base, f));
  }
  return out;
};
const pkgFiles = walk(path.join(TMP, "package")).filter((f) => !f.startsWith("node_modules"));
console.log("  " + pkgFiles.length + " fichiers dans le paquet :");
for (const f of pkgFiles.slice(0, 40)) console.log("    " + f);

console.log("\n=== 3) secrets / URLs figés dans le paquet ===");
const SECRET_RE = /(api[_-]?key|secret|password|token|bearer|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY|sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|phx_[A-Za-z0-9]{10,})/i;
const URL_RE = /https?:\/\/[A-Za-z0-9._:\/-]+/g;
const findings = [];
for (const f of pkgFiles) {
  const p = path.join(TMP, "package", f);
  if (!fs.statSync(p).isFile()) continue;
  if (fs.statSync(p).size > 2_000_000) continue;
  const txt = fs.readFileSync(p, "utf8");
  const lines = txt.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 400) continue;
    if (SECRET_RE.test(l) && !/^\s*(\/\/|\*|\/\*)/.test(l) && !/process\.env|placeholder|example|YOUR_|xxx|TODO/i.test(l)) {
      findings.push({ f, i: i + 1, l: l.trim().slice(0, 160) });
    }
  }
}
console.log("  " + findings.length + " ligne(s) suspecte(s) :");
for (const x of findings.slice(0, 25)) console.log("    " + x.f + ":" + x.i + "  " + x.l);

console.log("\n=== 4) URLs presentes dans le paquet (endpoints ?) ===");
const urls = new Set();
for (const f of pkgFiles) {
  const p = path.join(TMP, "package", f);
  if (!fs.statSync(p).isFile() || fs.statSync(p).size > 2_000_000) continue;
  for (const m of fs.readFileSync(p, "utf8").matchAll(URL_RE)) urls.add(m[0]);
}
for (const u of [...urls].sort()) console.log("    " + u);

console.log("\n=== 5) diff du code publie vs le depot (fichiers communs) ===");
let same = 0, diff = 0, onlyPkg = [], onlyRepo = [];
const repoFiles = walk(REPO).filter((f) => !f.startsWith(".git") && !f.startsWith("node_modules"));
const pkgSet = new Set(pkgFiles), repoSet = new Set(repoFiles);
for (const f of pkgFiles) if (!repoSet.has(f)) onlyPkg.push(f);
for (const f of repoFiles) if (!pkgSet.has(f)) onlyRepo.push(f);
for (const f of pkgFiles) {
  if (!repoSet.has(f)) continue;
  const a = fs.readFileSync(path.join(TMP, "package", f), "utf8");
  const b = fs.readFileSync(path.join(REPO, f), "utf8");
  if (a === b) same++; else { diff++; console.log("    DIFF " + f + " (" + a.length + " vs " + b.length + " car.)"); }
}
console.log("  identiques : " + same + " | differents : " + diff);
console.log("  uniquement dans le paquet : " + (onlyPkg.length ? onlyPkg.join(", ") : "(aucun)"));
console.log("  uniquement dans le depot  : " + onlyRepo.length + " fichiers");
console.log("\n=== 6) dependances du paquet vs du depot ===");
try {
  const pj = JSON.parse(fs.readFileSync(path.join(TMP, "package", "package.json"), "utf8"));
  const rj = JSON.parse(fs.readFileSync(path.join(REPO, "package.json"), "utf8"));
  const pd = pj.dependencies || {}, rd = rj.dependencies || {};
  console.log("  paquet  :", JSON.stringify(pd));
  console.log("  depot   :", JSON.stringify(rd));
  for (const k of Object.keys(pd)) if (rd[k] !== pd[k]) console.log("    ECART " + k + " : paquet=" + pd[k] + " depot=" + rd[k]);
  console.log("  version du paquet : " + pj.version + " | version du depot : " + rj.version);
} catch (e) { console.log("  (KO: " + e.message.slice(0, 80) + ")"); }
fs.writeFileSync("/tmp/opencode/npm-diff-report.json", JSON.stringify({ findings, urls: [...urls], onlyPkg, onlyRepo }, null, 1));
console.log("\n-> /tmp/opencode/npm-diff-report.json");
