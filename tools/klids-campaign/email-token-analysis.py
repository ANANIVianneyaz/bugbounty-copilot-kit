#!/usr/bin/env python3
"""Analyse des tokens emails (P2) : format exact, alphabet, longueur, entropie."""
import json, urllib.request, math, re, collections

TOK = open('/tmp/opencode/mail_token.txt').read().strip()


def get(url):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + TOK})
    return json.load(urllib.request.urlopen(req, timeout=25))


msgs = get('https://api.mail.tm/messages')
if isinstance(msgs, dict):
    msgs = msgs.get('hydra:member', [])

out = []
for m in msgs:
    d = get('https://api.mail.tm/messages/' + m['id'])
    body = ' '.join(d.get('html') or []) + ' ' + (d.get('text') or '')
    text = re.sub(r'<[^>]+>', ' ', body)
    text = re.sub(r'\s+', ' ', text)
    print('=' * 100)
    print('SUJET :', d.get('subject'))
    print('DE    :', d.get('from', {}).get('address'))
    print('TEXTE :', text[:600])
    print('-' * 100)
    urls = re.findall(r'https?://[^\s"\'<>\\)]+', body)
    for u in urls:
        print('  LIEN :', u[:230])
    cands = set()
    for u in urls:
        for seg in re.split(r'[/?#&=:]', u):
            seg = seg.strip()
            if len(seg) >= 8 and re.fullmatch(r'[A-Za-z0-9_\-\.]+', seg):
                cands.add(seg)
    # aussi les tokens en clair dans le texte (hors URL)
    for seg in re.findall(r'\b[A-Za-z0-9_\-]{12,}\b', text):
        if seg.lower() not in ('authentication', 'notification', 'unsubscribe', 'securite'):
            cands.add(seg)
    print('-' * 100)
    print('  CANDIDATS (>= 8 car.) :')
    for c in sorted(cands, key=len, reverse=True)[:14]:
        alpha = ''.join(sorted({ch for ch in c}))
        cnt = collections.Counter(c)
        ent = -sum((v / len(c)) * math.log2(v / len(c)) for v in cnt.values())
        print(f"    len={len(c):3d}  entropie={ent:5.2f} bits  alphabet({len(alpha)})={alpha[:70]}")
        print(f"        {c[:130]}")
    out.append({'subject': d.get('subject'), 'from': d.get('from', {}).get('address'),
                'text': text[:1500], 'urls': urls, 'cands': sorted(cands)})

json.dump(out, open('/tmp/opencode/email-tokens.json', 'w'), indent=1)
print('\n-> /tmp/opencode/email-tokens.json')
