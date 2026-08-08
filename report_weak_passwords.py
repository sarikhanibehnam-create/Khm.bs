#!/usr/bin/env python3
"""
گزارش کاربرانی که رمزشان هنوز با فرمت ناامن قدیمی SHA256 ذخیره شده است.

پیش‌زمینه: در v124 رمز عبور به PBKDF2-SHA256 با 200,000 تکرار ارتقا یافت.
مهاجرت نرم است: هر کاربر با اولین ورود موفق، رمزش خودکار به فرمت جدید تبدیل می‌شود.
ولی اگر کاربری هرگز login نکند، رمزش با فرمت قدیمی می‌ماند — رمز ۴ رقمی
در ثانیه شکسته می‌شود.

این اسکریپت فقط گزارش می‌دهد. هیچ چیزی تغییر نمی‌دهد.
"""
import sqlite3, os

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE, 'mehr.db')

conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row

print("=" * 70)
print("گزارش وضعیت رمز عبور کاربران")
print("=" * 70)

rows = conn.execute("SELECT id, name, role, title, password FROM users ORDER BY id").fetchall()

secure = []
insecure = []
empty = []

for r in rows:
    pw = str(r['password'] or '')
    if not pw:
        empty.append(r)
    elif pw.startswith('pbkdf2$'):
        secure.append(r)
    else:
        insecure.append(r)

print(f"\nکل کاربران: {len(rows)}")
print(f"  ✅ رمز امن (PBKDF2): {len(secure)}")
print(f"  ⚠️ رمز ناامن قدیمی (SHA256): {len(insecure)}")
print(f"  ❌ بدون رمز:                    {len(empty)}")

if insecure:
    print("\n" + "─" * 70)
    print("⚠️ کاربرانی که رمزشان با فرمت قدیمی و ناامن ذخیره شده:")
    print("─" * 70)
    for r in insecure:
        print(f"  • {r['name']:<20} (نقش: {r['role']}, سمت: {r['title'] or '—'})")
    print()
    print("👉 اقدام لازم:")
    print("   ۱) از این کاربران بخواهید یک بار login کنند — رمزشان خودکار امن می‌شود.")
    print("   ۲) اگر رمزشان را فراموش کرده‌اند، ادمین می‌تواند از صفحه کاربران رمز جدید ست کند.")
    print("   ۳) توصیه می‌شود رمز جدید حداقل ۸ کاراکتر، شامل حرف و عدد باشد.")
else:
    print("\n✅ همه کاربران رمز امن دارند.")

if empty:
    print("\n❌ کاربرانی که رمز ندارند (نمی‌توانند login کنند):")
    for r in empty:
        print(f"  • {r['name']} (id={r['id']})")

conn.close()
