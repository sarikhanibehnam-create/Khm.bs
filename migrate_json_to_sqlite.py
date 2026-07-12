#!/usr/bin/env python3
"""
انتقال یک‌بارهٔ دیتای JSON قدیمی به دیتابیس SQLite جدید (mehr.db).
استفاده:
    python3 migrate_json_to_sqlite.py path/to/data.json
اگر مسیر داده نشود، به‌صورت پیش‌فرض data.json در همین پوشه خوانده می‌شود.
این اسکریپت idempotent نیست؛ روی دیتابیس خام اجرا شود (یا قبلش mehr.db پاک شود).
"""
import json, os, sys, datetime
import db

def now():
    return datetime.datetime.now().isoformat()

KNOWN_REQUEST = {'id','req_number','expert','req_date','status','created_by','created_at','imported'}
KNOWN_PURCHASE = {'id','req_number','expert','supplier','supplier_id','date','is_contract','no_request',
                  'line_items','created_at','imported','paid_amount','remaining_amount','due_date',
                  'payment_method','financial_status','closed','close_reason','closed_by','closed_at','_actor'}
KNOWN_LINEITEM = {'line_id','item_code','item_name','qty','unit','unit_price','shipped_qty','ship_status',
                  'nf_qty','nf_reason','no_fulfill','price_pending'}
KNOWN_SHIPPING = {'id','number','date','transport','driver','destination','created_by','warehouse_no',
                   'year','created_at','imported','items'}
KNOWN_SHIPITEM = {'item_name','item_code','qty','unit','req_number','supplier','purchase_id','line_id',
                   'notes','no_request_item'}

def extras(d, known):
    return {k: v for k, v in d.items() if k not in known}

def main(json_path):
    with open(json_path, encoding='utf-8') as f:
        data = json.load(f)

    db.init_db()
    conn = db.get_conn()
    cur = conn.cursor()

    report = []

    # ---------- 1) تامین‌کنندگان: یکتاسازی از سه منبع ----------
    supplier_names = set()
    for s in data.get('suppliers', []):
        if isinstance(s, str) and s.strip():
            supplier_names.add(s.strip())
    for p in data.get('purchases', []):
        if p.get('supplier'):
            supplier_names.add(str(p['supplier']).strip())
    for sh in data.get('shippings', []):
        for it in sh.get('items', []):
            if it.get('supplier'):
                supplier_names.add(str(it['supplier']).strip())

    name_to_id = {}
    for name in sorted(supplier_names):
        cur.execute(
            'INSERT OR IGNORE INTO suppliers (name, is_active, created_at, updated_at) VALUES (?,1,?,?)',
            (name, now(), now())
        )
    conn.commit()
    for row in cur.execute('SELECT id, name FROM suppliers'):
        name_to_id[row['name']] = row['id']
    report.append(f"تامین‌کنندگان منتقل‌شده: {len(name_to_id)}")

    # ---------- 2) کاربران ----------
    # توجه: بر اساس «نام» چک تعارض می‌کنیم نه id خام — چون id کاربر پیش‌فرض (مدیر) که
    # در اولین اجرای سیستم ساخته می‌شود ممکن است با id کاربری در فایل قدیمی یکی باشد و
    # باعث شود آن کاربر (با وجود نام متفاوت) به‌اشتباه نادیده گرفته شود.
    n_users, skipped_users = 0, []
    for u in data.get('users', []):
        name = u.get('name')
        if not name:
            continue
        existing = cur.execute('SELECT 1 FROM users WHERE name=?', (name,)).fetchone()
        if existing:
            skipped_users.append(name)
            continue
        cur.execute(
            '''INSERT INTO users (name, role, title, password, is_expert_listed, unit, fiscal_year, perms_json, perm_log_json)
               VALUES (?,?,?,?,?,?,?,?,?)''',
            (name, u.get('role'), u.get('title', ''), u.get('password'),
             1 if u.get('is_expert_listed', True) else 0, u.get('unit', 'بازرگانی و پشتیبانی'),
             u.get('fiscal_year', ''), json.dumps(u.get('perms', {}), ensure_ascii=False),
             json.dumps(u.get('perm_log', []), ensure_ascii=False))
        )
        n_users += 1
    conn.commit()
    report.append(f"کاربران منتقل‌شده: {n_users}" + (f" (از قبل موجود بودند و رد شدند: {', '.join(skipped_users)})" if skipped_users else ""))

    # ---------- 3) درخواست‌ها ----------
    n_req = 0
    for r in data.get('requests', []):
        cur.execute(
            '''INSERT OR IGNORE INTO requests (id, req_number, expert, req_date, status, created_by, created_at, imported, extra_json)
               VALUES (?,?,?,?,?,?,?,?,?)''',
            (r.get('id'), r.get('req_number'), r.get('expert'), r.get('req_date'),
             r.get('status', 'باز'), r.get('created_by'), r.get('created_at', now()),
             1 if r.get('imported') else 0, json.dumps(extras(r, KNOWN_REQUEST), ensure_ascii=False))
        )
        n_req += 1
    conn.commit()
    report.append(f"درخواست‌های منتقل‌شده: {n_req}")

    # ---------- 4) خریدها + ردیف‌های کالا ----------
    n_pur, n_items = 0, 0
    line_id_map = {}  # (old_purchase_id, old_line_id) -> new global purchase_items.id
    for p in data.get('purchases', []):
        sup_name = (p.get('supplier') or '').strip()
        sup_id = name_to_id.get(sup_name)
        cur.execute(
            '''INSERT OR IGNORE INTO purchases
               (id, req_number, expert, supplier_id, supplier, date, is_contract, no_request,
                created_at, imported, paid_amount, remaining_amount, due_date, payment_method,
                financial_status, closed, close_reason, closed_by, closed_at, extra_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (p.get('id'), p.get('req_number'), p.get('expert'), sup_id, sup_name,
             p.get('date'), 1 if p.get('is_contract') else 0, 1 if p.get('no_request') else 0,
             p.get('created_at', now()), 1 if p.get('imported') else 0,
             float(p.get('paid_amount', 0) or 0), 0.0, p.get('due_date', ''),
             p.get('payment_method', ''), p.get('financial_status'),
             1 if p.get('closed') else 0, p.get('close_reason'), p.get('closed_by'), p.get('closed_at'),
             json.dumps(extras(p, KNOWN_PURCHASE), ensure_ascii=False))
        )
        n_pur += 1
        for li in p.get('line_items', []):
            try:
                qty = float(li.get('qty') or 0)
                price = float(li.get('unit_price') or 0)
            except (TypeError, ValueError):
                qty, price = 0, 0
            cur.execute(
                '''INSERT INTO purchase_items
                   (purchase_id, item_code, item_name, qty, unit, unit_price,
                    shipped_qty, ship_status, nf_qty, nf_reason, no_fulfill, price_pending, legacy_line_no, extra_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (p.get('id'), li.get('item_code', ''), li.get('item_name'),
                 li.get('qty'), li.get('unit'), li.get('unit_price'),
                 float(li.get('shipped_qty', 0) or 0), li.get('ship_status', 'pending'),
                 float(li.get('nf_qty', 0) or 0), li.get('nf_reason', ''),
                 1 if li.get('no_fulfill') else 0,
                 1 if (li.get('price_pending') or price == 0) else 0,
                 li.get('line_id'), json.dumps(extras(li, KNOWN_LINEITEM), ensure_ascii=False))
            )
            new_id = cur.lastrowid
            line_id_map[(p.get('id'), li.get('line_id'))] = new_id
            n_items += 1
    conn.commit()
    report.append(f"خریدهای منتقل‌شده: {n_pur} | ردیف‌های کالا: {n_items}")

    # محاسبه remaining_amount اولیه = جمع ریالی ردیف‌ها - paid_amount (تخمینی، قابل اصلاح دستی)
    for row in cur.execute('SELECT id, paid_amount FROM purchases').fetchall():
        total = cur.execute(
            'SELECT COALESCE(SUM(CAST(qty AS REAL)*CAST(unit_price AS REAL)),0) t FROM purchase_items WHERE purchase_id=?',
            (row['id'],)).fetchone()['t']
        remaining = max(0.0, (total or 0) - (row['paid_amount'] or 0))
        cur.execute('UPDATE purchases SET remaining_amount=? WHERE id=?', (remaining, row['id']))
    conn.commit()

    # ---------- 5) ارسالی‌ها + ردیف‌ها ----------
    n_ship, n_sitems = 0, 0
    for s in data.get('shippings', []):
        cur.execute(
            '''INSERT OR IGNORE INTO shippings (id, number, date, transport, driver, destination,
               created_by, warehouse_no, year, created_at, imported, extra_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (s.get('id'), s.get('number'), s.get('date'), s.get('transport'), s.get('driver'),
             s.get('destination'), s.get('created_by'), s.get('warehouse_no'), s.get('year'),
             s.get('created_at', now()), 1 if s.get('imported') else 0,
             json.dumps(extras(s, KNOWN_SHIPPING), ensure_ascii=False))
        )
        n_ship += 1
        for it in s.get('items', []):
            new_line_id = line_id_map.get((it.get('purchase_id'), it.get('line_id')), it.get('line_id'))
            cur.execute(
                '''INSERT INTO shipping_items (shipping_id, item_name, item_code, qty, unit,
                   req_number, supplier, purchase_id, line_id, notes, no_request_item, extra_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                (s.get('id'), it.get('item_name'), it.get('item_code', ''), it.get('qty'), it.get('unit'),
                 it.get('req_number', ''), it.get('supplier', ''), it.get('purchase_id'), new_line_id,
                 it.get('notes', ''), 1 if it.get('no_request_item') else 0,
                 json.dumps(extras(it, KNOWN_SHIPITEM), ensure_ascii=False))
            )
            n_sitems += 1
    conn.commit()
    report.append(f"ارسالی‌های منتقل‌شده: {n_ship} | ردیف‌های ارسالی: {n_sitems}")

    # ---------- 6) پرداخت‌های تامین‌کننده (اگر داده‌ای موجود باشد) ----------
    n_pay = 0
    for pay in data.get('supplier_payments', []):
        sup_name = (pay.get('supplier') or '').strip()
        cur.execute(
            '''INSERT OR IGNORE INTO supplier_payments (id, supplier_id, supplier, purchase_id,
               amount, date, method, note, created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (pay.get('id'), name_to_id.get(sup_name), sup_name, pay.get('purchase_id'),
             float(pay.get('amount', 0) or 0), pay.get('date'), pay.get('method', ''),
             pay.get('note', ''), pay.get('created_by'), pay.get('created_at', now()))
        )
        n_pay += 1
    conn.commit()
    report.append(f"پرداخت‌های تامین‌کننده منتقل‌شده: {n_pay}")

    # ---------- 7) مقصدها (ممکن است رشته خام یا dict باشد) ----------
    for i, d in enumerate(data.get('destinations', [])):
        if isinstance(d, dict):
            cur.execute('INSERT OR IGNORE INTO destinations (id, name) VALUES (?,?)', (d.get('id'), d.get('name')))
        else:
            cur.execute('INSERT OR IGNORE INTO destinations (id, name) VALUES (?,?)', (i + 1, d))
    conn.commit()

    # ---------- 8) لیست‌های ساده ----------
    simple_map = {
        'units': 'units', 'non_fulfillment_reasons': 'non_fulfillment_reasons',
        'transport_types': 'transport_types', 'ship_statuses': 'ship_statuses',
        'supply_statuses': 'supply_statuses', 'requester_units': 'requester_units',
        'locations': 'locations', 'contract_types': 'contract_types',
        'return_reasons': 'return_reasons', 'petty_holders': 'petty_holders'
    }
    for list_name, json_key in simple_map.items():
        for i, val in enumerate(data.get(json_key, [])):
            cur.execute('INSERT OR IGNORE INTO simple_lists (list_name, value, sort_order) VALUES (?,?,?)',
                        (list_name, val, i))
    conn.commit()

    for i, val in enumerate(['PS12', 'X5', 'SR3', 'Eagle', 'J4']):
        cur.execute('INSERT OR IGNORE INTO simple_lists (list_name, value, sort_order) VALUES (?,?,?)',
                    ('car_models', val, i))
    conn.commit()

    # ---------- 9) تنظیمات ----------
    for k, v in data.get('settings', {}).items():
        cur.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)',
                    (k, json.dumps(v, ensure_ascii=False)))
    if data.get('petty_fund'):
        cur.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)',
                    ('petty_fund', json.dumps(data['petty_fund'], ensure_ascii=False)))
    conn.commit()

    # ---------- 10) مجموعه‌های سندی (doc collections) ----------
    n_docs = 0
    for coll in db.DOC_COLLECTIONS:
        for rec in data.get(coll, []):
            cur.execute('INSERT OR IGNORE INTO docs (collection, id, data, created_at) VALUES (?,?,?,?)',
                        (coll, rec.get('id'), json.dumps(rec, ensure_ascii=False), rec.get('created_at', now())))
            n_docs += 1
    conn.commit()
    report.append(f"اسناد مجموعه‌های فرعی منتقل‌شده: {n_docs}")

    # ---------- 11) ثبت یک رکورد لاگ برای خود migration ----------
    db.log_audit(conn, actor='system', action='migrate', entity='database', entity_id=0,
                 note=f'Migration از JSON به SQLite انجام شد. منبع: {os.path.basename(json_path)}')
    conn.commit()
    conn.close()

    report.append("--- Migration کامل شد ---")
    return report


if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(db.BASE, 'data.json')
    for line in main(src):
        print(line)
