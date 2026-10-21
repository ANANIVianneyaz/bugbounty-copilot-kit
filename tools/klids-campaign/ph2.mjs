const APP="https://bugsecure.senintel.sn";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function g(p,o={}){try{const r=await fetch(APP+p,{method:o.m||"GET",headers:{"User-Agent":UA,"Content-Type":"application/json",...(o.h||{})},body:o.b?JSON.stringify(o.b):undefined,redirect:"manual"});const t=await r.text();return{s:r.status,t,ct:r.headers.get("content-type")||""};}catch(e){return{s:0,t:"ERR "+e.message,ct:""}}}
const P="phc_myGuPycfa9UMAmmXHBjPJrqFhzkpvprNv7xof9DZ5Far";
console.log("=== A) corps brut de /ingest/flags?v=2 (public) ===");
let r=await g("/ingest/flags?v=2");
console.log(r.s); console.log(r.t.slice(0,3000));
console.log("\n=== B) corps brut de /ingest/decide?v=3 (public) ===");
r=await g("/ingest/decide?v=3");
console.log(r.s); console.log(r.t.slice(0,3000));
console.log("\n=== C) corps 401/403 complet (forme de l erreur) ===");
for(const p of ["/ingest/api/projects/"+P+"/events","/ingest/api/projects/"+P+"/insights","/ingest/api/projects/"+P+"/query"]){
  const x=await g(p); console.log(x.s,p,"\n   ",x.t.slice(0,600),"\n");
  await sleep(150);
}
console.log("=== D) routes PostHog UI / admin sous /ingest ===");
for(const p of ["/ingest/login","/ingest/signup","/ingest/ui/","/ingest/api/users","/ingest/api/organizations","/ingest/api/teams","/ingest/api/personal_api_keys","/ingest/api/projects/"+P+"/activity/","/ingest/api/projects/"+P+"/event","/ingest/api/projects/"+P+"/export","/ingest/api/projects/"+P+"/data_management","/ingest/api/projects/"+P+"/logs","/ingest/api/projects/"+P+"/logs/","/ingest/api/projects/"+P+"/recordings","/ingest/api/projects/"+P+"/session_recordings/","/ingest/api/projects/"+P+"/insight","/ingest/api/projects/"+P+"/dashboards/","/ingest/activity/","/ingest/_internal/","/ingest/api/","/ingest/api/projects/"+P+"/tags","/ingest/api/projects/"+P+"/webhooks","/ingest/api/projects/"+P+"/batch_exports","/ingest/api/projects/"+P+"/event_definitions"]){
  const x=await g(p); const first=x.t.slice(0,110).replace(/\s+/g," "); console.log(String(x.s).padEnd(4)+p.padEnd(58)+first);
  await sleep(110);
}
