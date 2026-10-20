import fs from "fs";

const targets = process.argv.slice(2);
const files = ["js/c1.js","js/c2.js","js/c3.js","js/c4.js","js/c5.js","js/c6.js","js/c7.js","js/c8.js","js/c9.js","js/c10.js","js/c11.js","js/c12.js","js/c13.js","js/c14.js","js/c15.js","js/c16.js","js/c17.js","js/c18.js"];

function extractDoc(s, name) {
  const m = s.indexOf('value:"' + name + '"');
  if (m < 0) return null;
  let start = s.lastIndexOf('{kind:"Document"', m);
  if (start < 0) start = s.lastIndexOf('{kind:"OperationDefinition"', m);
  if (start < 0) return null;
  let depth = 0, i = start, inStr = false, esc = false, quote = "";
  for (; i < s.length; i++) {
    const c = s[i];
    if (inStr) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === quote) inStr = false; continue; }
    if (c === '"' || c === "'") { inStr = true; quote = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) { i++; break; } }
  }
  return s.slice(start, i);
}

function toJson(js) {
  return js.replace(/([{,])([A-Za-z_$][A-Za-z0-9_$]*):/g, '$1"$2":');
}

function typeStr(t) {
  if (!t) return "?";
  if (t.kind === "NonNullType") return typeStr(t.type) + "!";
  if (t.kind === "ListType") return "[" + typeStr(t.type) + "]";
  return t.name?.value || "?";
}
function valueStr(v) {
  if (!v) return "?";
  switch (v.kind) {
    case "Variable": return "$" + v.name.value;
    case "StringValue": return JSON.stringify(v.value);
    case "IntValue": case "FloatValue": return v.value;
    case "BooleanValue": return String(v.value);
    case "EnumValue": return v.value;
    case "NullValue": return "null";
    case "ListValue": return "[" + v.values.map(valueStr).join(", ") + "]";
    case "ObjectValue": return "{" + v.fields.map((f) => f.name.value + ": " + valueStr(f.value)).join(", ") + "}";
    default: return "<?>";
  }
}
function fieldStr(f) {
  let out = (f.alias ? f.alias.value + ": " : "") + f.name.value;
  if (f.arguments?.length) out += "(" + f.arguments.map((a) => a.name.value + ": " + valueStr(a.value)).join(", ") + ")";
  if (f.selectionSet) out += " { " + f.selectionSet.selections.map(selStr).join(" ") + " }";
  return out;
}
function selStr(s) {
  if (s.kind === "Field") return fieldStr(s);
  if (s.kind === "FragmentSpread") return "..." + s.name.value;
  if (s.kind === "InlineFragment") return "... on " + (s.typeCondition?.name.value || "?") + " { " + s.selectionSet.selections.map(selStr).join(" ") + " }";
  return "";
}
function opStr(d) {
  let out = d.operation;
  if (d.name) out += " " + d.name.value;
  if (d.variableDefinitions?.length) out += "(" + d.variableDefinitions.map((v) => "$" + v.variable.name.value + ": " + typeStr(v.type) + (v.defaultValue ? " = " + valueStr(v.defaultValue) : "")).join(", ") + ")";
  out += " { " + d.selectionSet.selections.map(selStr).join(" ") + " }";
  return out;
}

const found = new Map();
for (const f of files) {
  let s; try { s = fs.readFileSync(f, "utf8"); } catch { continue; }
  for (const t of targets) {
    if (found.has(t)) continue;
    const js = extractDoc(s, t);
    if (!js) continue;
    try {
      const obj = JSON.parse(toJson(js));
      const defs = obj.definitions || [];
      const op = defs.find((d) => d.kind === "OperationDefinition");
      if (!op) continue;
      const frags = defs.filter((d) => d.kind === "FragmentDefinition");
      let q = opStr(op);
      for (const fr of frags) q += "\n" + "fragment " + fr.name.value + " on " + fr.typeCondition.name.value + " { " + fr.selectionSet.selections.map(selStr).join(" ") + " }";
      found.set(t, q);
    } catch (e) {
      found.set(t, "PARSE_ERROR: " + e.message);
    }
  }
}
for (const t of targets) {
  console.log("######## " + t);
  console.log(found.get(t) || "(non trouve)");
  console.log();
}
