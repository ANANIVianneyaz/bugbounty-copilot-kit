#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Classe chaque entrée d'arsenal.jsonl dans les catégories du kit
(mêmes 24 classes que knowledge/writeups/WRITEUP_KB.md).

Lecture :  data/arsenal.jsonl
Écriture : data/arsenal_classified.jsonl  (champ « category » ajouté)

Usage : .venv/bin/python classify.py
"""
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
SRC = os.path.join(DATA, "arsenal.jsonl")
DST = os.path.join(DATA, "arsenal_classified.jsonl")

# Libellés affichés (repris de l'INDEX du kit)
CATEGORIES = {
    "access-control-idor": "Access Control & IDOR",
    "api-mobile": "API & Mobile Security",
    "auth-bypass": "Auth Bypass — MFA / 2FA / OAuth / Clickjacking",
    "business-logic": "Business Logic Flaws",
    "cloud": "Cloud Misconfig — AWS / GCP / Azure",
    "command-injection": "Command Injection",
    "cookie-injection": "Cookie Injection / Supercookies",
    "cve-deep-dives": "CVE Deep Dives",
    "dos": "Denial of Service",
    "graphql": "GraphQL",
    "http-smuggling": "HTTP Request Smuggling",
    "info-disclosure": "Information Disclosure & Credential Leaks",
    "injection": "Injection (SQLi / XXE / Code / Argument)",
    "kubernetes": "Kubernetes & Conteneurs",
    "memory-corruption": "Memory Corruption",
    "misc": "Misc",
    "open-redirect": "Open Redirect Chains",
    "path-traversal": "Path Traversal",
    "race-condition": "Race Conditions",
    "resource-accounting": "Resource Accounting / Abus de coûts",
    "ssrf-cache": "SSRF & Cache Attacks",
    "ssti-deserialization": "SSTI & Désérialisation",
    "supply-chain": "Supply Chain — Dependency Confusion, CI/CD",
    "xss": "XSS — Reflected to Zero-Click ATO",
}

# Règles ordonnées : la première qui matche gagne.
# Spécifique d'abord, générique ensuite.
RULES = [
    ("ssti-deserialization", r"\bssti\b|server[- ]side template|template injection|deseriali[sz]|unserialize|pickle|ysoserial|object injection|fastjson|jackson|viewstate|blazor.*deserial"),
    ("http-smuggling", r"smuggl|request split|desync|cl\.te|te\.cl|content[- ]length.*transfer[- ]encoding"),
    ("race-condition", r"race condition|toctou|single[ -]packet|time[ -]of[ -]check|concurren"),
    ("graphql", r"graphql|introspection|apollo|batched quer"),
    ("kubernetes", r"kubernetes|\bk8s\b|container escape|kubelet|kube-|helm chart|pod security|rbac"),
    ("supply-chain", r"dependency confusion|supply chain|typosquat|npm package|pypi|ci/?cd|github actions|build pipeline|artifact (repo|registry)|package registry"),
    ("cve-deep-dives", r"\bcve-\d{4}-\d+\b"),
    ("path-traversal", r"path traversal|directory traversal|\blfi\b|arbitrary file (read|write|delete|download|upload)|file inclusion|zip ?slip|traversal"),
    ("command-injection", r"command injection|os command|shell injection|argument injection|arbitrary command|code execution on the server"),
    ("ssrf-cache", r"\bssrf\b|server[- ]side request forgery|web cache|cache poison|cache deception|cache key|cache purge"),
    ("cookie-injection", r"cookie (injection|toss|bomb|jar|shadow)|supercookie|domain[- ]wide cookie|cookie fixat"),
    ("open-redirect", r"open redirect|unvalidated redirect|redirect (chain|bypass)|redirect_uri (manipulat|attacker|arbitrar|craft|controll)|url redirection"),
    ("memory-corruption", r"memory corruption|buffer overflow|use[ -]after[ -]free|double free|heap overflow|stack overflow|out[ -]of[ -]bounds|integer overflow|type confusion|uaf\b"),
    ("injection", r"\bsqli\b|sql injection|\bxxe\b|xml external entit|\bldap\b|nosql injection|code injection|eval injection|expression language injection|crlf injection|header injection|\bssi\b|template syntax|\bcsti\b"),
    ("xss", r"\bxss\b|cross[ -]site scripting|html injection|dom clobbering|client[ -]side (template|injection)|javascript injection"),
    ("cloud", r"\baws\b|\bgcp\b|google cloud|azure|s3 bucket|bucket (misconfig|expos)|cloud misconfig|\biam\b|cognito|firebase|\bec2\b|lambda function|cloudfront|\bgcs\b|blob storage|metadata endpoint|serverless"),
    ("business-logic", r"business logic|logic flaw|logic bug|payment|refund|coupon|discount|gift ?card|checkout|order (manip|tamper)|wallet|currency|trial abuse|subscription|limit bypass|negative (amount|quantity)|price manip|invoice|tax"),
    ("auth-bypass", r"\bmfa\b|\b2fa\b|two[ -]factor|otp (bypass|reuse|brute)|oauth|saml|\bsso\b|clickjack|authentication bypass|auth bypass|login bypass|password reset|forgot password|session fixation|account takeover|\bato\b|email verification|verification bypass|passkey|password policy|signup"),
    ("access-control-idor", r"\bidor\b|bola\b|bopla|object level|access control|authorization|unauthori[sz]ed|privilege escalation|privesc|missing (authorization|permission)|permission bypass|tenant|cross[ -](account|user|tenant|organi)|other users|admin (page|panel|access|area)|role (manip|escalat)|export (data|users)|broken access"),
    ("dos", r"denial of service|\bdos\b|crash|recursion|resource exhaustion|billion laughs|decompression bomb|zip bomb|infinite loop"),
    ("info-disclosure", r"information disclosure|info (leak|disclosure)|credential|leak|exposed|disclos|\bpii\b|api key|token (leak|expos)|source code|\.env|backup file|debug (endpoint|info|page)|sensitive (data|info|file)|enumerat"),
    ("resource-accounting", r"resource (abuse|accounting|consumption|exhaust)|cost (abuse|incur)|billing|quota|rate limit bypass|sms (flood|bomb|abuse)|email (flood|bomb)|push notification (flood|abuse)"),
    ("api-mobile", r"\bapi\b|android|\bios\b|\bapk\b|mobile app|\bjwt\b|json web token|rest api|swagger|openapi|websocket|grpc"),
]

# Programmes « bibliothèques / logiciels » → CVE Deep Dives
LIB_PROGRAMS = {"curl", "mariadb", "openjdk", "php", "python", "ruby", "linux kernel",
                "git", "openssl", "nginx", "apache http server", "postgresql", "mysql",
                "chromium", "firefox", "node.js", "wordpress"}


# URLs et emails : les URLs de domaine contiennent des mots-clés trompeurs
# (ex : https://crash-pings.mozilla.org → "crash" → dos).
RE_URL = re.compile(r"https?://\S+|www\.\S+|[\w.+-]+@[\w.-]+\.\w+", re.I)
# Négation XSS : "no HTML injection" / "without XSS" = surface fermée, pas un bug.
RE_NEG_XSS = re.compile(r"\b(?:no|not|without|never)\s+(?:[\w-]+\s+){0,3}"
                        r"(?:xss|html injection|cross[- ]site scripting)\b", re.I)


def clean_text(text):
    """Neutralise les faux positifs connus du classifieur avant le matching."""
    text = RE_URL.sub(" ", text)
    text = RE_NEG_XSS.sub(" ", text)
    return text


def classify(e):
    text = " ".join(str(x) for x in (
        e.get("title"), e.get("weakness"), e.get("summary"),
        (e.get("extra") or {}).get("bugs") if isinstance((e.get("extra") or {}).get("bugs"), list) else " ".join((e.get("extra") or {}).get("bugs") or []),
    ) if x)
    text = clean_text(text.lower())
    prog = (e.get("program") or "").lower()

    if prog in LIB_PROGRAMS and not any(k in text for k in ("xss", "sql", "ssrf")):
        return "cve-deep-dives"
    for slug, pat in RULES:
        if re.search(pat, text, re.I):
            return slug
    return "misc"


def main():
    rows = []
    with open(SRC, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    counts = Counter()
    with open(DST, "w", encoding="utf-8") as f:
        for e in rows:
            e["category"] = classify(e)
            counts[e["category"]] += 1
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"[i] classé : {len(rows)} entrées")
    for slug, n in counts.most_common():
        print(f"  {n:5d}  {slug:24s} {CATEGORIES.get(slug, '?')}")


if __name__ == "__main__":
    sys.exit(main())
