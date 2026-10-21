const http=require("http"),fs=require("fs");
http.createServer((req,res)=>{let b="";req.on("data",c=>b+=c);req.on("end",()=>{
  const rec={at:new Date().toISOString(),method:req.method,url:req.url,httpVersion:req.httpVersion,headers:req.rawHeaders,body:b};
  fs.appendFileSync("/tmp/opencode/echo.log",JSON.stringify(rec)+"\n");
  res.writeHead(200,{"Content-Type":"application/json"});res.end('{"ok":true}');
});}).listen(8099,"127.0.0.1",()=>console.log("echo on 8099"));
