#!/usr/bin/env python3
"""
بازیابی صورت‌های تنخواه (petty_cash) از بایگانی PRELOADED_PETTY_DATA.

قوانین (طبق تصمیم کاربر):
1. keep_current: تکراری‌ها رد می‌شوند (کلید تطبیق: number)
2. ID جدید طبیعی (شماره PRELOADED مثل 200001 دور ریخته می‌شود)
3. تراکنش امن؛ در صورت خطا، rollback کامل
4. audit_log با action='restore' برای هر رکورد
"""
import re, json, sqlite3, sys, os, datetime

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE, 'mehr.db')
OLD_HTML = '/tmp/old_index.html'

print("=" * 70)
print("گام ۱: استخراج داده از بایگانی")
print("=" * 70)

with open(OLD_HTML, 'r', encoding='utf-8') as f:
    txt = f.read()

# PRELOADED_PETTY_DATA یک dict است با کلید petty_cash
m = re.search(r'const PRELOADED_PETTY_DATA\s*=\s*(\{.*?\});', txt, re.DOTALL)
if not m:
    print("❌ PRELOADED_PETTY_DATA پیدا نشد"); sys.exit(1)
petty_data = json.loads(m.group(1))
preloaded = petty_data.get('petty_cash', [])
print(f"✅ {len(preloaded)} صورت تنخواه از بایگانی خوانده شد")

# اتصال
conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row
conn.execute('PRAGMA foreign_keys = ON')

# رکوردهای فعلی
current_nums = set()
current_rows = list(conn.execute("SELECT id, data FROM docs WHERE collection='petty_cash'"))
for r in current_rows:
    d = json.loads(r['data'])
    n = str(d.get('number', '')).strip()
    if n:
        current_nums.add(n)
print(f"✅ در DB فعلی: {len(current_rows)} سند (شماره‌های: {sorted(current_nums, key=lambda x: int(x) if x.isdigit() else 9999)})")

# فیلتر
to_add, skipped = [], []
for d in preloaded:
    n = str(d.get('number', '')).strip()
    if n and n in current_nums:
        skipped.append(d)
    else:
        to_add.append(d)

nums_add = sorted([str(d.get('number', '')).strip() for d in to_add], 
                  key=lambda x: int(x) if x.isdigit() else 9999)
print(f"✅ اضافه: {len(to_add)} | تکراری (رد): {len(skipped)}")
print(f"   شماره‌های اضافه‌شونده: {nums_add}")

if not to_add:
    print("چیزی برای اضافه شدن نیست."); conn.close(); sys.exit(0)

# next id
row = conn.execute("SELECT MAX(id) m FROM docs WHERE collection='petty_cash'").fetchone()
next_id = (row['m'] or 0) + 1
print(f"✅ ID جدید از {next_id} شروع می‌شود")

print()
print("=" * 70)
print("گام ۲: درج امن در تراکنش")
print("=" * 70)

now = datetime.datetime.now().isoformat()
try:
    conn.execute('BEGIN')
    for d in to_add:
        rec = dict(d)
        rec.pop('_preloaded', None)
        rec.pop('_source_file', None)
        rec['id'] = next_id
        rec.setdefault('created_at', now)
        conn.execute(
            'INSERT INTO docs (collection, id, data, created_at) VALUES (?,?,?,?)',
            ('petty_cash', next_id, json.dumps(rec, ensure_ascii=False), now)
        )
        conn.execute(
            'INSERT INTO audit_log (ts, actor, action, entity, entity_id, before_json, after_json, note) '
            'VALUES (?,?,?,?,?,?,?,?)',
            (now, 'system_recovery', 'restore', 'petty_cash', str(next_id),
             None, json.dumps(rec, ensure_ascii=False),
             f'بازیابی از بایگانی PRELOADED_PETTY_DATA (نسخه df0a31e). صورت تنخواه شماره {d.get("number")}')
        )
        next_id += 1
    conn.commit()
    print(f"✅ {len(to_add)} صورت تنخواه با موفقیت وارد شد")
except Exception as e:
    conn.rollback()
    print(f"❌ خطا: {e}\nهمه چیز rollback شد.")
    conn.close(); sys.exit(1)

# گزارش
print()
print("=" * 70)
print("گام ۳: تأیید")
print("=" * 70)
total = conn.execute("SELECT COUNT(*) FROM docs WHERE collection='petty_cash'").fetchone()[0]
print(f"تعداد کل petty_cash: {total}")

# توزیع بر اساس holder
holders = {}
for r in conn.execute("SELECT data FROM docs WHERE collection='petty_cash'"):
    d = json.loads(r['data'])
    h = str(d.get('holder', '?'))
    holders[h] = holders.get(h, 0) + 1
print("\nتوزیع بر اساس تنخواه‌دار:")
for h, n in sorted(holders.items(), key=lambda x: -x[1]):
    print(f"  {h}: {n} صورت")

# جمع مبالغ کل
total_amt = 0
for r in conn.execute("SELECT data FROM docs WHERE collection='petty_cash'"):
    d = json.loads(r['data'])
    try:
        total_amt += float(d.get('ceiling', 0) or 0)
    except: pass
print(f"\nجمع کل ceiling همه صورت‌های تنخواه: {int(total_amt):,} ریال")

conn.close()
print("\n✅ عملیات با موفقیت انجام شد.")
