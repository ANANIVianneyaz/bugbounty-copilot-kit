import fs from "fs";
const APP="https://aarme.cyberaar.io";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const COOKIE=fs.readFileSync("/tmp/opencode/cyberaar/session-alias.txt","utf8").trim();
const me=await fetch(APP+"/api/aarme/account/me",{headers:{Accept:"application/json","User-Agent":UA,Origin:APP,Cookie:COOKIE}});
const mt=await me.text();
console.log("  /me avatar = "+(mt.match(/"avatar":[^,}]*/)||["(absent)"])[0]);
const handle=(mt.match(/"handle":"([^"]+)"/)||[, ""])[1];
console.log("  handle = "+(handle||"(vide)"));
// la page publique
for (const u of ["https://aarme.cyberaar.io/h/"+(handle||"bb-probe-ssrf"), "https://aarme.cyberaar.io/api/aarme/leaderboard"]) {
  const h=await fetch(u,{headers:{"User-Agent":UA}});
  const t=await h.text();
  const imgs=[...new Set([...t.matchAll(/https?:\/\/[^"'\s<>]+\.(?:png|jpg|jpeg|webp|svg|gif)[^"'\s<>]*/gi)].map(m=>m[0]))];
  const rel=[...new Set([...t.matchAll(/["'(](\/[^"'()\s]*\.(?:png|jpg|jpeg|webp|svg|gif)[^"'()\s]*)/gi)].map(m=>m[1]))];
  console.log("  "+u.replace("https://","")+" -> "+[...imgs,...rel].slice(0,6).join(" | ")||"  (aucune image)");
  if(imgs.length||rel.length){
    for(const a of [...imgs,...rel].slice(0,3)){
      const full=a.startsWith("http")?a:APP+a;
      const hh=await fetch(full,{headers:{"User-Agent":UA},redirect:"manual"});
      const hd=hh.headers;
      const body=await hh.text();
      console.log("      "+full.replace("https://","").slice(0,66));
      console.log("        HTTP "+hh.status+" ct="+(hd.get("content-type")||"-")+" disp="+(hd.get("content-disposition")||"-")+" nosniff="+(hd.get("x-content-type-options")||"-"));
      console.log("        csp="+(hd.get("content-security-policy")||"(aucune)").slice(0,150));
      console.log("        corps="+body.length+" car. | payload xss-proof present : "+(body.includes("xss-proof")?"OUI":"non"));
    }
  }
}
