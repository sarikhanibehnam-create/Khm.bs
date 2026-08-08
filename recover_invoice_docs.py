#!/usr/bin/env python3
"""
بازیابی صورت‌وضعیت‌های تحویل مدارک به مالی (invoice_docs) از بایگانی PRELOADED.

منبع: نسخه قدیمی index.html در commit df0a31e که PRELOADED_INV_DOCS دارد.
مقصد: جدول docs collection='invoice_docs' در mehr.db فعلی.

قوانین اجرا (طبق تصمیم کاربر):
1. فقط رکوردهایی که در DB فعلی نیستند اضافه می‌شوند (keep_current).
2. ID های عجیب PRELOADED (200001+) دور ریخته می‌شوند و شماره طبیعی توسط
   next_doc_id گرفته می‌شود.
3. کل عملیات در یک تراکنش SQL انجام می‌شود؛ در صورت خطا هیچ تغییری اعمال نمی‌شود.
4. برای هر رکورد بازگردانده‌شده یک audit_log با action='restore' ثبت می‌شود.
5. یک پشتیبان کامل قبل از اجرا گرفته شد.
"""
import re, json, sqlite3, sys, os, datetime, shutil

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE, 'mehr.db')
OLD_HTML = '/tmp/old_index.html'

# 1) استخراج PRELOADED_INV_DOCS از بایگانی
print("=" * 70)
print("گام ۱: استخراج داده از بایگانی")
print("=" * 70)
with open(OLD_HTML, 'r', encoding='utf-8') as f:
    txt = f.read()
m = re.search(r'const PRELOADED_INV_DOCS\s*=\s*(\[.*?\]);', txt, re.DOTALL)
if not m:
    print("❌ PRELOADED_INV_DOCS پیدا نشد")
    sys.exit(1)
preloaded = json.loads(m.group(1))
print(f"✅ {len(preloaded)} سند از بایگانی خوانده شد")

# 2) اتصال به DB و پیدا کردن رکوردهای موجود
conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row
conn.execute('PRAGMA foreign_keys = ON')

current_rows = list(conn.execute("SELECT id, data FROM docs WHERE collection='invoice_docs'"))
current_keys = set()
for r in current_rows:
    d = json.loads(r['data'])
    inv_no = str(d.get('invoice_no') or '').strip().lower()
    sup = str(d.get('supplier') or '').strip()
    if inv_no:
        current_keys.add((inv_no, sup))

print(f"✅ در DB فعلی: {len(current_rows)} سند")

# 3) فیلتر: فقط رکوردهایی که در DB نیستند
to_add = []
skipped = []
for d in preloaded:
    inv_no = str(d.get('invoice_no') or '').strip().lower()
    sup = str(d.get('supplier') or '').strip()
    if (inv_no, sup) in current_keys:
        skipped.append(d)
    else:
        to_add.append(d)

print(f"✅ برای اضافه شدن: {len(to_add)}  |  تکراری (رد): {len(skipped)}")

if not to_add:
    print("هیچ رکورد جدیدی برای اضافه شدن نیست. خروج.")
    conn.close()
    sys.exit(0)

# 4) پیدا کردن ID شروع (next_doc_id)
row = conn.execute("SELECT MAX(id) m FROM docs WHERE collection='invoice_docs'").fetchone()
next_id = (row['m'] or 0) + 1
print(f"✅ ID جدید از {next_id} شروع می‌شود")

# 5) اجرای درج در تراکنش
print()
print("=" * 70)
print("گام ۲: درج در دیتابیس (تراکنش امن)")
print("=" * 70)

now_iso = datetime.datetime.now().isoformat()
try:
    conn.execute('BEGIN')
    inserted = 0
    for d in to_add:
        d_clean = dict(d)
        # ID جدید (شماره طبیعی) + پاک‌سازی فیلدهای مربوط به PRELOADED
        d_clean.pop('_preloaded', None)
        d_clean.pop('_source_file', None)
        d_clean['id'] = next_id
        # created_at اگر نبود اضافه کن
        d_clean.setdefault('created_at', now_iso)
        # درج در docs
        conn.execute(
            'INSERT INTO docs (collection, id, data, created_at) VALUES (?,?,?,?)',
            ('invoice_docs', next_id, json.dumps(d_clean, ensure_ascii=False), now_iso)
        )
        # audit_log با action='restore'
        conn.execute(
            'INSERT INTO audit_log (ts, actor, action, entity, entity_id, before_json, after_json, note) '
            'VALUES (?,?,?,?,?,?,?,?)',
            (now_iso, 'system_recovery', 'restore', 'invoice_docs', str(next_id),
             None, json.dumps(d_clean, ensure_ascii=False),
             f'بازیابی از بایگانی PRELOADED_INV_DOCS (نسخه df0a31e). صورت‌وضعیت شماره {d.get("statement_no")}')
        )
        next_id += 1
        inserted += 1

    conn.commit()
    print(f"✅ {inserted} رکورد با موفقیت وارد شد")
except Exception as e:
    conn.rollback()
    print(f"❌ خطا: {e}")
    print("همه تغییرات rollback شد. دیتابیس دست‌نخورده است.")
    conn.close()
    sys.exit(1)

# 6) گزارش نهایی
print()
print("=" * 70)
print("گام ۳: تأیید نتیجه")
print("=" * 70)
total_now = conn.execute("SELECT COUNT(*) FROM docs WHERE collection='invoice_docs'").fetchone()[0]
print(f"تعداد کل invoice_docs بعد از بازیابی: {total_now}")

# توزیع statement_no
print("\nتوزیع صورت‌وضعیت‌ها:")
stmts = {}
for r in conn.execute("SELECT data FROM docs WHERE collection='invoice_docs'"):
    d = json.loads(r['data'])
    s = str(d.get('statement_no', '')).strip() or '(بدون شماره)'
    stmts[s] = stmts.get(s, 0) + 1
for s, n in sorted(stmts.items(), key=lambda x: (x[0] == '(بدون شماره)', int(x[0]) if x[0].isdigit() else 999)):
    print(f"  صورت‌وضعیت شماره {s}: {n} فقره فاکتور")

conn.close()
print("\n✅ عملیات بازیابی با موفقیت انجام شد.")
