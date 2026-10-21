const AS="https://bugsecure-api.senintel.sn", H="bb-test.enseignementsecondaire.bj";
const form=o=>Object.entries(o).map(([k,v])=>encodeURIComponent(k)+"="+encodeURIComponent(v)).join("&");
for (const n of ["nojwks","logo1","logo2","logo3","html1","html2","phish1"]) {
  const u=AS+"/oauth/authorize?"+form({response_type:"code",client_id:`https://${H}/doc/${n}.json`,redirect_uri:`https://${H}/cb`,scope:"programs:read profile:read reports:read",state:"bb-"+Date.now(),code_challenge:"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",code_challenge_method:"S256",resource:AS});
  const r=await fetch(u,{redirect:"manual"});
  const loc=r.headers.get("location")||"";
  const ok=loc.includes("/oauth/consent");
  console.log("  "+n.padEnd(8)+(ok?"ACCEPTE  (page de consentement)":"REFUSE   "+loc.replace("https://bugsecure.senintel.sn","")));
  await new Promise(x=>setTimeout(x,900));
}
