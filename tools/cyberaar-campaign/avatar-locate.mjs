import fs from "fs";
const APP="https://aarme.cyberaar.io";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE=fs.readFileSync("/tmp/opencode/cyberaar/session-alias.txt","utf8").trim();
const me=await fetch(APP+"/api/aarme/account/me",{headers:{Accept:"application/json","User-Agent":UA,Origin:APP,Cookie:COOKIE}});
const j=JSON.parse(await me.text());
console.log("=== les cles de /account/me ===");
console.log("  "+Object.keys(j).join(", "));
console.log("\n=== tout ce qui ressemble a une URL ou un chemin ===");
for(const [k,v] of Object.entries(j)){
  const s=JSON.stringify(v);
  if(/avatar|photo|image|\/uploads|https?:|media|file/i.test(k+" "+s)) console.log("  "+k+" = "+s.slice(0,220));
}
console.log("\n=== la page publique : indices de l avatar (data:, /media, /uploads, blob) ===");
const p=await fetch("https://aarme.cyberaar.io/h/bb-probe-ssrf",{headers:{"User-Agent":UA}});
const t=await p.text();
for(const pat of [/data:image\/[a-z]+;base64,[A-Za-z0-9+/=]{0,80}/g, /\/[a-z0-9_\-]*(?:upload|media|avatar|photo|file)[a-z0-9_\-\/]*/gi, /"avatar[^,}]{0,120}/g]){
  const m=[...new Set([...t.matchAll(pat)].map(x=>x[0]))];
  console.log("  "+pat.source.slice(0,28)+" -> "+(m.slice(0,6).join(" | ")||"(rien)"));
}
