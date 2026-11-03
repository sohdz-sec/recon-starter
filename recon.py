#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon.py — l'awal tool dyalek. Python ghir, bla ta dépendance.

Ach kaydir:
  1. DNS (IPs + reverse)
  2. HTTP/HTTPS (status, server, redirects)
  3. TLS (certificat: cn, issuer, expiry)
  4. Security headers audit (HSTS, CSP, X-Frame-Options, ...)
  5. Fichiers/paths li khass ykounou mkhebbiyin (robots, .git, .env, ...)
  6. Kaykteb rapport .md — hada howa l'portfolio dyalek

L'ISTI3MAL (7alali ghir):
  python3 recon.py --scope scope.txt --target example.com
  python3 recon.py --lab http://127.0.0.1:8099      # test local bla internet

L'script kayrefed l'scope: ila l'target machi f scope.txt -> ma kaykhdemch.
Hadi machi 7aja 3ajba — hada l'far9 bin professional w mkhasser.
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

VERSION = "1.0"
UA = f"recon-starter/{VERSION} (+authorized-security-testing)"
DELAY = 0.4          # seconde bin kol talab — 7tiram l'server
TIMEOUT = 8

PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.git/HEAD",
    "/.env",
    "/admin",
    "/api",
    "/graphql",
    "/login",
    "/backup.zip",
    "/server-status",
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "mohim", "Kaymne3 downgrade l HTTP"),
    ("Content-Security-Policy", "mohim", "Kaymne3 XSS"),
    ("X-Frame-Options", "mohim", "Kaymne3 clickjacking"),
    ("X-Content-Type-Options", "mohim", "Kaymne3 MIME sniffing"),
    ("Referrer-Policy", "moyen", "Kaymne3 tasrib dyal URL"),
    ("Permissions-Policy", "moyen", "Kay7ded l'browser features"),
    ("Cross-Origin-Opener-Policy", "faible", "3azl dyal l'windows"),
]

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


# ---------------------------------------------------------------------------
def load_scope(path):
    if not os.path.exists(path):
        return set()
    out = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#")[0].strip().lower()
            if line:
                out.add(line)
    return out


def host_of(target):
    if "://" in target:
        return (urllib.parse.urlsplit(target).hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()


def allowed(target, scope, lab):
    host = host_of(target)
    if not host:
        return False, "ma 9dertch n9ra l'host"
    if host in LOCAL_HOSTS:
        return (True, "localhost") if lab else (False, "localhost bla --lab")
    if lab:
        return False, "--lab ghir l'localhost"
    if host in scope:
        return True, "f scope.txt"
    for s in scope:
        if host.endswith("." + s):
            return True, f"subdomain dyal {s}"
    return False, f"'{host}' machi f scope.txt"


def resolve(host):
    try:
        name, aliases, ips = socket.gethostbyname_ex(host)
        return {"ok": True, "ips": sorted(set(ips)), "aliases": aliases}
    except Exception as e:
        return {"ok": False, "error": str(e), "ips": [], "aliases": []}


def fetch(url, method="GET"):
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(4096)
            return {"ok": True, "status": r.status, "url": r.geturl(),
                    "headers": dict(r.headers), "body": body, "error": None}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "url": url,
                "headers": dict(e.headers or {}), "body": b"", "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"ok": False, "status": None, "url": url, "headers": {},
                "body": b"", "error": str(e)}


def tls_info(host, port=443):
    if host in LOCAL_HOSTS:
        return {"ok": False, "error": "localhost"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto = ss.version()
        subj = dict(x[0] for x in cert.get("subject", []))
        iss = dict(x[0] for x in cert.get("issuer", []))
        exp = cert.get("notAfter", "")
        days = None
        if exp:
            dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (dt - datetime.now(timezone.utc)).days
        return {"ok": True, "cn": subj.get("commonName", "?"),
                "issuer": iss.get("organizationName", iss.get("commonName", "?")),
                "expires": exp, "days_left": days, "tls": proto}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
def scan(target, lab):
    host = host_of(target)
    base = target if "://" in target else f"https://{target}"
    base = base.rstrip("/")
    report = {"target": target, "host": host, "started": datetime.now(timezone.utc).isoformat(),
              "steps": []}

    def step(name):
        report["steps"].append(name)
        print(f"  [{len(report['steps'])}/6] {name} ...", flush=True)

    # 1. DNS
    step("DNS")
    dns = resolve(host)
    print(f"       {', '.join(dns['ips']) if dns['ips'] else dns.get('error')}")

    # 2. TLS
    tls = {"ok": False, "error": "skipped"}
    if not lab and host not in LOCAL_HOSTS:
        step("TLS")
        tls = tls_info(host)
        print(f"       {tls.get('cn')} | {tls.get('issuer')} | {tls.get('days_left')} jours")

    # 3. HTTP
    step("HTTP")
    main = fetch(base + "/")
    time.sleep(DELAY)
    # 4. HTTP sans TLS (ila https khdam)
    plain = None
    if base.startswith("https://"):
        plain = fetch("http://" + host + "/")
        time.sleep(DELAY)
    print(f"       {main.get('status')} {main.get('error') or ''}")

    # 5. Headers
    step("Security headers")
    hdrs = {k.lower(): v for k, v in (main.get("headers") or {}).items()}
    audit = []
    for name, prio, aim in SECURITY_HEADERS:
        val = hdrs.get(name.lower())
        audit.append({"header": name, "present": bool(val), "value": val,
                      "priority": prio, "why": aim})
    missing = [a["header"] for a in audit if not a["present"]]

    # 6. Paths
    step("Paths")
    found = []
    for p in PATHS:
        r = fetch(base + p)
        time.sleep(DELAY)
        if r.get("status") and r["status"] not in (404, 410):
            snippet = r["body"][:200].decode("utf-8", "replace").strip()
            found.append({"path": p, "status": r["status"], "size": len(r["body"]),
                          "snippet": re.sub(r"\s+", " ", snippet)[:160]})
    report.update({"dns": dns, "tls": tls, "http": {
        "status": main.get("status"), "url": main.get("url"),
        "server": hdrs.get("server"), "powered_by": hdrs.get("x-powered-by"),
        "error": main.get("error")},
        "plain_http": None if plain is None else {"status": plain.get("status"),
                                                  "error": plain.get("error")},
        "headers_audit": audit, "missing_headers": missing, "paths": found})
    return report


def to_markdown(r):
    L = []
    t = r["target"]
    L.append(f"# Recon report — `{t}`\n")
    L.append(f"**Date** : {r['started'][:19]} UTC  ")
    L.append(f"**Host** : `{r['host']}`\n")
    L.append("---\n")

    L.append("## 1. DNS\n")
    d = r["dns"]
    if d.get("ok"):
        L.append(f"- IPs : {', '.join(f'`{i}`' for i in d['ips'])}")
        if d.get("aliases"):
            L.append(f"- Aliases : {', '.join(d['aliases'])}")
    else:
        L.append(f"- **Erreur** : {d.get('error')}")
    L.append("")

    L.append("## 2. TLS\n")
    tl = r["tls"]
    if tl.get("ok"):
        L.append(f"- CN : `{tl['cn']}`")
        L.append(f"- Issuer : `{tl['issuer']}`")
        L.append(f"- Expire : {tl['expires']}  ({tl['days_left']} jours)")
        L.append(f"- Protocole : {tl['tls']}")
        if tl["days_left"] is not None and tl["days_left"] < 30:
            L.append("\n> **Attention** : l'certificat kaykml 9rib. Bug valid (medium).")
    else:
        L.append(f"- Sans TLS / erreur : {tl.get('error')}")
    L.append("")

    L.append("## 3. HTTP\n")
    h = r["http"]
    L.append(f"- Status : `{h['status']}`  " + (f"({h['error']})" if h["error"] else ""))
    L.append(f"- Server : `{h['server']}`")
    if h.get("powered_by"):
        L.append(f"- X-Powered-By : `{h['powered_by']}` — **tasrib dyal l'technologie**")
    if r.get("plain_http") is not None:
        ph = r["plain_http"]
        ok = ph.get("status") in (200, 301, 302)
        L.append(f"- HTTP bla TLS : status `{ph.get('status')}` "
                 + ("— **khass redirect l HTTPS**" if ok else ""))
    L.append("")

    L.append("## 4. Security headers\n")
    L.append("| Header | Kayn? | Priorité | 3lach |")
    L.append("|---|---|---|---|")
    for a in r["headers_audit"]:
        L.append(f"| `{a['header']}` | {'✔' if a['present'] else '✘'} | "
                 f"{a['priority']} | {a['why']} |")
    L.append("")
    if r["missing_headers"]:
        L.append(f"**Nqssin ({len(r['missing_headers'])})** : "
                 + ", ".join(f"`{x}`" for x in r["missing_headers"]))
        L.append("\n> Hadi **finding valid** f ay audit: hardening dyal l'headers "
                 "(severity low/medium, CVSS 3-5). Katktebha f report b "
                 "remediation: 'zid had l'headers f l'server config'.")
    else:
        L.append("**Kolhom mawjodin.** L'config mzyana.")
    L.append("")

    L.append("## 5. Paths\n")
    if r["paths"]:
        L.append("| Path | Status | Ach ban |")
        L.append("|---|---|---|")
        for p in r["paths"]:
            L.append(f"| `{p['path']}` | {p['status']} | {p['snippet'][:80] or '—'} |")
        risky = [p for p in r["paths"] if p["path"] in ("/.git/HEAD", "/.env", "/backup.zip")]
        if risky:
            L.append("\n> **!!** Hadi khatra: `.git`, `.env`, `backup.zip` ila kaybano "
                     "→ source code / secrets / database leak. Severity **high/critical**.")
    else:
        L.append("Ma l9it ta path sensitif. (Hadchi mzyan — walakin ma kay3nich belli "
                 "l'site nqi: ba9i khass deep testing.)")
    L.append("")

    L.append("---\n")
    L.append("## Ach daba\n")
    L.append("1. Ila l'site dyalek : sla7 l'headers l'nqssin + 7yed l'paths l'khatra.")
    L.append("2. Ila l'site dyal client : hada report jahz — 3tih m3a l'prix dyal l'audit.")
    L.append("3. Ila target dyal bug bounty : 9ra l'policy 9bel, w ila l'finding valid 3tih.")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Recon starter (authorized targets only)")
    ap.add_argument("--scope", default="scope.txt", help="fichier dyal domains li 3ndek idn 3lihom")
    ap.add_argument("--target", help="domain wla URL")
    ap.add_argument("--lab", help="localhost URL l'test (127.0.0.1:8099)")
    ap.add_argument("-o", "--out", default="reports", help="dossier dyal reports")
    a = ap.parse_args()

    if not a.target and not a.lab:
        ap.error("3tini --target (b scope.txt) wla --lab <url>")

    lab = bool(a.lab)
    target = a.lab or a.target
    scope = load_scope(a.scope)
    ok, why = allowed(target, scope, lab)
    if not ok:
        print(f"\n  ⛔ MAMNOU3 — {why}")
        print("  L'script ma kaykhdemch 3la chi 7aja ma 3ndekch l'idn 3liha.")
        print()
        print("  Ila l'site dyalek: zid l'domaine f scope.txt w 3awd jarrb.")
        print("  Ila bghiti tjarreb bla internet: --lab http://127.0.0.1:8099")
        return 2

    print("=" * 66)
    print(f" RECON  {target}")
    print(f" Sabab  : {why}")
    print(f" Talabat: ~{len(PATHS) + 2}  b delay {DELAY}s")
    print("=" * 66)

    r = scan(target, lab)
    os.makedirs(a.out, exist_ok=True)
    safe = re.sub(r"[^a-z0-9.-]", "_", r["host"])
    path = os.path.join(a.out, f"recon_{safe}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(r))
    with open(os.path.join(a.out, f"recon_{safe}.json"), "w", encoding="utf-8") as fh:
        json.dump(r, fh, indent=2, ensure_ascii=False)

    print("-" * 66)
    print(f" Report : {path}")
    print(f" Headers nqssin : {len(r['missing_headers'])}")
    print(f" Paths maktasfin: {len(r['paths'])}")
    for p in r["paths"]:
        print(f"   {p['status']}  {p['path']}")
    print("-" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
