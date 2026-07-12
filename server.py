#!/usr/bin/env python3
import json, os, hashlib, datetime, shutil, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote

import db

BASE = os.path.dirname(os.path.abspath(__file__))
HTML_FILE = os.path.join(BASE, 'index.html')
BACKUP_DIR = os.path.join(BASE, 'backups')

def h(p): return hashlib.sha256(p.encode()).hexdigest()

# لیست کامل مجوزهای دسترسی سطح‌کاربر (بدون تغییر نسبت به نسخه قبلی + یک مجوز جدید)
PERM_KEYS = [
    'create_request','assign_request','edit_request','delete_request',
    'create_purchase','edit_any_purchase','delete_purchase',
    'create_shipping','edit_shipping','delete_shipping','ship_consolidate','register_return',
    'register_payment','register_nonfulfill',
    'manage_lists','manage_users','manage_backup',
    'view_financial','view_reports','export_excel',
    'manage_contracts','view_all_purchases','view_all',
    'manage_supply_plan','manage_petty_cash','petty_view_all',
    'petty_deposit_view','petty_deposit_finance','petty_deposit_delivery','petty_deposit_review',
    'page_dashboard','page_cartable','page_purchase_new','page_purchases',
    'page_shipping_new','page_shippings','page_non_fulfill','page_price_compare',
    'page_expert_perf','page_supplier_perf','page_iatf','page_supply_plan','page_tracking','page_manual_receipts',
    'manage_suppliers',
    # تفکیک ثبت/ویرایش/حذف (علاوه‌بر مجوز «مشاهده» بالا که همان manage_X قدیمی است)
    'create_supplier','edit_supplier','delete_supplier',
    'create_contract','edit_contract','delete_contract',
    'create_supply_plan','edit_supply_plan','delete_supply_plan',
    'create_petty_charge','edit_petty_charge','delete_petty_charge',
    # ماژول فروش
    'page_sales','create_sale','edit_sale','delete_sale','register_sale_return',
    'readonly'
]

def default_perms(role):
    if role == 'admin':
        d = {k: True for k in PERM_KEYS if k != 'readonly'}
        d['readonly'] = False
        return d
    if role == 'manager':
        d = {k: True for k in PERM_KEYS if k != 'readonly'}
        d['manage_users'] = False
        d['readonly'] = False
        return d
    base = {k: False for k in PERM_KEYS}
    base.update({'create_request':True,'create_purchase':True,'edit_shipping':True,'create_shipping':True,
                 'register_payment':True,'register_nonfulfill':True,'register_return':True,
                 'page_dashboard':True,'page_cartable':True,'page_purchase_new':True,'page_purchases':True,
                 'page_shipping_new':True,'page_shippings':True,'page_non_fulfill':True,'page_price_compare':True,
                 'page_expert_perf':True,'page_supplier_perf':True,'page_iatf':True,'page_manual_receipts':True,
                 'manage_suppliers':True,'create_supplier':True})
    return base

# نگاشت لیست‌های ساده‌ی رشته‌ای (توجه: suppliers دیگر اینجا نیست — موجودیت کامل شده)
SIMPLE_LISTS = {
    'units':'units', 'reasons':'non_fulfillment_reasons',
    'transport_types':'transport_types', 'ship_statuses':'ship_statuses',
    'supply_statuses':'supply_statuses', 'requester_units':'requester_units',
    'locations':'locations', 'contract_types':'contract_types', 'return_reasons':'return_reasons',
    'petty_holders':'petty_holders', 'car_models':'car_models', 'petty_card_persons':'petty_card_persons'
}

# مجموعه‌های سندی (JSON-doc) که هنوز ساختار جدول رابطه‌ای اختصاصی ندارند
DOC_PATHS = {
    'contracts':'contracts', 'contract_payments':'contract_payments', 'returns':'returns',
    'supply_plans':'supply_plans', 'need_declarations':'need_declarations',
    'petty_cash':'petty_cash', 'petty_deposits':'petty_deposits', 'petty_charges':'petty_charges',
    'manual_receipts':'manual_receipts', 'ship_queue':'ship_queue', 'invoice_docs':'invoice_docs',
    'items':'items'
}

KNOWN_REQUEST = {'id','req_number','expert','req_date','status','created_by','created_at','imported','_actor'}
KNOWN_PURCHASE = {'id','req_number','expert','supplier','supplier_id','date','is_contract','no_request',
                  'line_items','created_at','imported','paid_amount','remaining_amount','due_date',
                  'payment_method','financial_status','closed','close_reason','closed_by','closed_at','_actor'}
KNOWN_LINEITEM = {'line_id','item_code','item_name','qty','unit','unit_price','shipped_qty','ship_status',
                  'nf_qty','nf_reason','no_fulfill','price_pending'}
KNOWN_SHIPPING = {'id','number','date','transport','driver','destination','created_by','warehouse_no',
                   'year','created_at','imported','items','_actor'}
KNOWN_SHIPITEM = {'item_name','item_code','qty','unit','req_number','supplier','purchase_id','line_id',
                   'notes','no_request_item'}
KNOWN_SALE = {'id','number','date','customer','offset_supplier','line_items','created_at','created_by',
              'paid_amount','remaining_amount','payment_method','financial_status','closed','_actor'}
KNOWN_SALEITEM = {'line_id','item_code','item_name','qty','unit','unit_price','returned_qty'}
KNOWN_SALERETURN = {'id','sale_id','number','date','note','items','created_by','created_at','_actor'}
KNOWN_SALERETURNITEM = {'item_code','item_name','qty','unit','unit_price','reason','sale_item_id'}
KNOWN_SUPPLIER = {'id','name','contact_person','phone','address','category','payment_terms',
                   'bank_account','rating','is_active','note','created_at','updated_at','_actor'}

def now_iso():
    return datetime.datetime.now().isoformat()

def extras(d, known):
    return {k: v for k, v in d.items() if k not in known and k != '_actor'}

# ---------------------------------------------------------------------------
# بازسازی دیکشنری‌های سازگار با فرانت‌اند قدیمی از روی ردیف‌های SQL
# ---------------------------------------------------------------------------

def request_row_to_dict(row):
    d = dict(row)
    extra = json.loads(d.pop('extra_json') or '{}')
    out = {**extra, **{k: v for k, v in d.items()}}
    out['imported'] = bool(out.get('imported'))
    return out

def lineitem_row_to_dict(row):
    d = dict(row)
    extra = json.loads(d.pop('extra_json') or '{}')
    li = {**extra}
    li['line_id'] = d['id']
    li['item_code'] = d.get('item_code') or ''
    li['item_name'] = d.get('item_name')
    li['qty'] = d.get('qty')
    li['unit'] = d.get('unit')
    li['unit_price'] = d.get('unit_price')
    li['shipped_qty'] = d.get('shipped_qty') or 0
    li['ship_status'] = d.get('ship_status') or 'pending'
    li['nf_qty'] = d.get('nf_qty') or 0
    li['nf_reason'] = d.get('nf_reason') or ''
    li['no_fulfill'] = bool(d.get('no_fulfill'))
    li['price_pending'] = bool(d.get('price_pending'))
    return li

def purchase_row_to_dict(conn, row):
    d = dict(row)
    extra = json.loads(d.pop('extra_json') or '{}')
    out = {**extra}
    out.update({k: v for k, v in d.items()})
    out['is_contract'] = bool(d.get('is_contract'))
    out['no_request'] = bool(d.get('no_request'))
    out['imported'] = bool(d.get('imported'))
    out['closed'] = bool(d.get('closed'))
    items = conn.execute('SELECT * FROM purchase_items WHERE purchase_id=? ORDER BY id', (d['id'],)).fetchall()
    out['line_items'] = [lineitem_row_to_dict(r) for r in items]
    return out

def saleitem_row_to_dict(row):
    d = dict(row)
    extra = json.loads(d.pop('extra_json') or '{}')
    si = {**extra}
    si['line_id'] = d['id']
    si['item_code'] = d.get('item_code') or ''
    si['item_name'] = d.get('item_name')
    si['qty'] = d.get('qty')
    si['unit'] = d.get('unit')
    si['unit_price'] = d.get('unit_price')
    si['returned_qty'] = d.get('returned_qty') or 0
    return si

def sale_row_to_dict(conn, row):
    d = dict(row)
    extra = json.loads(d.pop('extra_json') or '{}')
    out = {**extra}
    out.update({k: v for k, v in d.items()})
    out['closed'] = bool(d.get('closed'))
    items = conn.execute('SELECT * FROM sale_items WHERE sale_id=? ORDER BY id', (d['id'],)).fetchall()
    out['line_items'] = [saleitem_row_to_dict(r) for r in items]
    return out

def salesreturn_row_to_dict(conn, row):
    d = dict(row)
    extra = json.loads(d.pop('extra_json') or '{}')
    out = {**extra}
    out.update({k: v for k, v in d.items()})
    items = conn.execute('SELECT * FROM sales_return_items WHERE return_id=? ORDER BY id', (d['id'],)).fetchall()
    def _ri(r):
        ri = {**json.loads(r['extra_json'] or '{}')}
        ri.update({'item_code': r['item_code'] or '', 'item_name': r['item_name'], 'qty': r['qty'],
                    'unit': r['unit'], 'unit_price': r['unit_price'], 'reason': r['reason'] or '',
                    'sale_item_id': r['sale_item_id']})
        return ri
    out['items'] = [_ri(r) for r in items]
    return out

def shipitem_row_to_dict(row):
    d = dict(row)
    extra = json.loads(d.pop('extra_json') or '{}')
    si = {**extra}
    si['item_name'] = d.get('item_name')
    si['item_code'] = d.get('item_code') or ''
    si['qty'] = d.get('qty')
    si['unit'] = d.get('unit')
    si['req_number'] = d.get('req_number') or ''
    si['supplier'] = d.get('supplier') or ''
    si['purchase_id'] = d.get('purchase_id')
    si['line_id'] = d.get('line_id')
    si['notes'] = d.get('notes') or ''
    si['no_request_item'] = bool(d.get('no_request_item'))
    return si

def shipping_row_to_dict(conn, row):
    d = dict(row)
    extra = json.loads(d.pop('extra_json') or '{}')
    out = {**extra}
    out.update({k: v for k, v in d.items()})
    out['imported'] = bool(d.get('imported'))
    items = conn.execute('SELECT * FROM shipping_items WHERE shipping_id=? ORDER BY id', (d['id'],)).fetchall()
    out['items'] = [shipitem_row_to_dict(r) for r in items]
    return out

def supplier_row_to_dict(row):
    d = dict(row)
    d['is_active'] = bool(d.get('is_active', 1))
    return d

def user_public_dict(row):
    d = dict(row)
    return {
        'id': d['id'], 'name': d['name'], 'role': d['role'], 'title': d.get('title', ''),
        'perms': json.loads(d.get('perms_json') or '{}'),
        'perm_log': json.loads(d.get('perm_log_json') or '[]'),
        'is_expert_listed': bool(d.get('is_expert_listed', 1)),
        'fiscal_year': d.get('fiscal_year', ''),
        'unit': d.get('unit', 'بازرگانی و پشتیبانی')
    }

# ---------------------------------------------------------------------------
# مجموعه‌های سندی (contracts, returns, supply_plans, ...) — ذخیره JSON در جدول docs
# ---------------------------------------------------------------------------

def get_docs(conn, collection):
    rows = conn.execute('SELECT data FROM docs WHERE collection=? ORDER BY id', (collection,)).fetchall()
    return [json.loads(r['data']) for r in rows]

def next_doc_id(conn, collection):
    r = conn.execute('SELECT MAX(id) m FROM docs WHERE collection=?', (collection,)).fetchone()
    return (r['m'] or 0) + 1

def create_doc(conn, collection, body, actor=None):
    body = dict(body)
    body.pop('_actor', None)
    body['id'] = next_doc_id(conn, collection)
    body['created_at'] = now_iso()
    conn.execute('INSERT INTO docs (collection, id, data, created_at) VALUES (?,?,?,?)',
                 (collection, body['id'], json.dumps(body, ensure_ascii=False), body['created_at']))
    db.log_audit(conn, actor, 'create', collection, body['id'], after=body)
    conn.commit()
    return body

def update_doc(conn, collection, rid, body, actor=None):
    row = conn.execute('SELECT data FROM docs WHERE collection=? AND id=?', (collection, rid)).fetchone()
    if not row:
        return None
    old = json.loads(row['data'])
    new = {**old, **body}
    new.pop('_actor', None)
    conn.execute('UPDATE docs SET data=? WHERE collection=? AND id=?',
                 (json.dumps(new, ensure_ascii=False), collection, rid))
    db.log_audit(conn, actor, 'update', collection, rid, before=old, after=new)
    conn.commit()
    return new

def delete_doc(conn, collection, rid, actor=None):
    row = conn.execute('SELECT data FROM docs WHERE collection=? AND id=?', (collection, rid)).fetchone()
    if row:
        old = json.loads(row['data'])
        conn.execute('DELETE FROM docs WHERE collection=? AND id=?', (collection, rid))
        db.log_audit(conn, actor, 'delete', collection, rid, before=old)
        conn.commit()
        return True
    return False

# ---------------------------------------------------------------------------
# لیست‌های ساده و تنظیمات
# ---------------------------------------------------------------------------

def get_simple_list(conn, list_name):
    rows = conn.execute('SELECT value FROM simple_lists WHERE list_name=? ORDER BY sort_order, value',
                         (list_name,)).fetchall()
    return [r['value'] for r in rows]

def add_simple_list_value(conn, list_name, value):
    cur = conn.execute('SELECT MAX(sort_order) m FROM simple_lists WHERE list_name=?', (list_name,))
    nxt = (cur.fetchone()['m'] or 0) + 1
    conn.execute('INSERT OR IGNORE INTO simple_lists (list_name, value, sort_order) VALUES (?,?,?)',
                 (list_name, value, nxt))
    conn.commit()

def del_simple_list_value(conn, list_name, value):
    conn.execute('DELETE FROM simple_lists WHERE list_name=? AND value=?', (list_name, value))
    conn.commit()

def get_setting(conn, key, default=None):
    row = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row['value'])
    except (TypeError, json.JSONDecodeError):
        return row['value']

def set_setting(conn, key, value):
    conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)',
                 (key, json.dumps(value, ensure_ascii=False)))
    conn.commit()

def get_all_settings(conn):
    rows = conn.execute('SELECT key, value FROM settings').fetchall()
    out = {}
    for r in rows:
        try:
            out[r['key']] = json.loads(r['value'])
        except (TypeError, json.JSONDecodeError):
            out[r['key']] = r['value']
    return out

# ---------------------------------------------------------------------------
# تامین‌کننده: resolve-or-create بر اساس نام (برای سازگاری با ورودی‌های متنی قدیمی)
# ---------------------------------------------------------------------------

def resolve_or_create_supplier(conn, name, actor=None):
    name = (name or '').strip()
    if not name:
        return None
    row = conn.execute('SELECT id FROM suppliers WHERE name=?', (name,)).fetchone()
    if row:
        return row['id']
    cur = conn.execute('INSERT INTO suppliers (name, is_active, created_at, updated_at) VALUES (?,1,?,?)',
                        (name, now_iso(), now_iso()))
    db.log_audit(conn, actor, 'create', 'suppliers', cur.lastrowid, after={'name': name})
    conn.commit()
    return cur.lastrowid

# ---------------------------------------------------------------------------
# منطق کسب‌وکار: اثر ارسال روی ردیف‌های خرید و بازمحاسبه وضعیت درخواست
# ---------------------------------------------------------------------------

def apply_shipping_to_lines(conn, items, sign=1):
    for sit in items:
        pid, lid = sit.get('purchase_id'), sit.get('line_id')
        try:
            qty = float(sit.get('qty') or 0)
        except (TypeError, ValueError):
            qty = 0
        if pid and lid:
            row = conn.execute('SELECT * FROM purchase_items WHERE id=? AND purchase_id=?', (lid, pid)).fetchone()
            if row:
                new_shipped = max(0.0, (row['shipped_qty'] or 0) + sign * qty)
                try:
                    total_qty = float(row['qty'] or 0)
                except (TypeError, ValueError):
                    total_qty = 0
                nf = float(row['nf_qty'] or 0)
                eff = total_qty - nf
                if eff > 0 and new_shipped >= eff:
                    status = 'shipped'
                elif new_shipped > 0:
                    status = 'partial'
                else:
                    status = 'pending'
                conn.execute('UPDATE purchase_items SET shipped_qty=?, ship_status=? WHERE id=?',
                             (new_shipped, status, lid))

def recompute_request_status(conn, rn):
    if not rn:
        return
    req = conn.execute('SELECT id FROM requests WHERE req_number=?', (str(rn),)).fetchone()
    if not req:
        return
    purs = conn.execute('SELECT id FROM purchases WHERE req_number=?', (str(rn),)).fetchall()
    if not purs:
        conn.execute('UPDATE requests SET status=? WHERE req_number=?', ('باز', str(rn)))
        return
    all_done = True
    for p in purs:
        items = conn.execute('SELECT qty, shipped_qty, nf_qty FROM purchase_items WHERE purchase_id=?',
                              (p['id'],)).fetchall()
        for it in items:
            try:
                tq = float(it['qty'] or 0)
            except (TypeError, ValueError):
                tq = 0
            sq = float(it['shipped_qty'] or 0)
            nf = float(it['nf_qty'] or 0)
            if sq + nf < tq:
                all_done = False
    conn.execute('UPDATE requests SET status=? WHERE req_number=?', ('بسته' if all_done else 'باز', str(rn)))

# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def get_body(self):
        length = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def get_token(self):
        auth = self.headers.get('Authorization', '') or ''
        if auth.startswith('Bearer '):
            return auth[7:].strip()
        return None

    def get_session_user(self, conn):
        """کاربر واقعی صاحب این درخواست، بر اساس توکن نشست معتبر — نه یک نام خوداظهاری
        در بدنه‌ی درخواست. اگر توکن نباشد/منقضی شده باشد، None برمی‌گرداند."""
        return db.resolve_session(conn, self.get_token())

    def require(self, session_user, ok, status=403, msg='عدم دسترسی'):
        """اگر شرط (ok) برقرار نباشد، پاسخ خطا می‌فرستد و False برمی‌گرداند تا handler
        با return از ادامه‌ی پردازش صرف‌نظر کند. اگر اصلاً نشست معتبری وجود نداشته باشد
        (لاگین نکرده/منقضی)، با کد ۴۰۱ پاسخ می‌دهد."""
        if session_user is None:
            self.send_json({'ok': False, 'error': 'لطفاً دوباره وارد شوید (نشست منقضی شده)'}, status=401)
            return False
        if not ok:
            self.send_json({'ok': False, 'error': msg}, status=status)
            return False
        return True

    def session_can(self, session_user, perm):
        """نسخه‌ی مبتنی‌بر نشست actor_can قدیمی — هویت از روی توکن، نه بدنه‌ی پیام."""
        if session_user is None:
            return False
        if session_user['role'] == 'admin':
            return True
        perms = json.loads(session_user['perms_json'] or '{}')
        if session_user['role'] == 'manager':
            if perm == 'manage_users':
                return bool(perms.get('manage_users', False))
            return True
        if perms.get('readonly') and perm not in ('view_financial', 'view_reports', 'export_excel', 'view_all_purchases'):
            return False
        return bool(perms.get(perm, False))

    def is_manager(self, session_user):
        return session_user is not None and session_user['role'] in ('admin', 'manager')

    def do_GET(self):
        p = urlparse(self.path)
        path = p.path
        qs = dict(x.split('=') for x in p.query.split('&') if '=' in x) if p.query else {}

        if path == '/' or path == '/index.html':
            try:
                with open(HTML_FILE, 'rb') as f:
                    body = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', len(body))
                self.end_headers()
                self.wfile.write(body)
            except FileNotFoundError:
                self.send_response(404); self.end_headers()
            return

        conn = db.get_conn()
        try:
            if path == '/api/me':
                su = self.get_session_user(conn)
                if su is None:
                    self.send_json({'ok': False}, status=401)
                else:
                    self.send_json({'ok': True, 'user': user_public_dict(su)})
            elif path == '/api/items':
                self.send_json(get_docs(conn, 'items'))
            elif path == '/api/requests':
                rows = conn.execute('SELECT * FROM requests ORDER BY id').fetchall()
                self.send_json([request_row_to_dict(r) for r in rows])
            elif path == '/api/purchases':
                rows = conn.execute('SELECT * FROM purchases ORDER BY id').fetchall()
                self.send_json([purchase_row_to_dict(conn, r) for r in rows])
            elif path == '/api/shippings':
                rows = conn.execute('SELECT * FROM shippings ORDER BY id').fetchall()
                self.send_json([shipping_row_to_dict(conn, r) for r in rows])
            elif path == '/api/sales':
                rows = conn.execute('SELECT * FROM sales ORDER BY id').fetchall()
                self.send_json([sale_row_to_dict(conn, r) for r in rows])
            elif path == '/api/sales_returns':
                rows = conn.execute('SELECT * FROM sales_returns ORDER BY id').fetchall()
                self.send_json([salesreturn_row_to_dict(conn, r) for r in rows])
            elif path == '/api/units':
                self.send_json(get_simple_list(conn, 'units'))
            elif path == '/api/destinations':
                rows = conn.execute('SELECT * FROM destinations ORDER BY id').fetchall()
                self.send_json([dict(r) for r in rows])
            elif path == '/api/suppliers':
                # سازگاری کامل با فرانت‌اند فعلی: فقط آرایه نام (رشته) — همان قرارداد نسخه قبل.
                # برای پروفایل کامل از /api/supplier_profiles استفاده می‌شود.
                rows = conn.execute('SELECT name FROM suppliers ORDER BY name').fetchall()
                self.send_json([r['name'] for r in rows])
            elif path == '/api/supplier_profiles':
                rows = conn.execute('SELECT * FROM suppliers ORDER BY name').fetchall()
                self.send_json([supplier_row_to_dict(r) for r in rows])
            elif path == '/api/supplier_payments':
                rows = conn.execute('SELECT * FROM supplier_payments ORDER BY id').fetchall()
                self.send_json([dict(r) for r in rows])
            elif path == '/api/reasons':
                self.send_json(get_simple_list(conn, 'non_fulfillment_reasons'))
            elif path == '/api/transport_types':
                self.send_json(get_simple_list(conn, 'transport_types'))
            elif path == '/api/ship_statuses':
                self.send_json(get_simple_list(conn, 'ship_statuses'))
            elif path == '/api/supply_statuses':
                self.send_json(get_simple_list(conn, 'supply_statuses'))
            elif path == '/api/requester_units':
                self.send_json(get_simple_list(conn, 'requester_units'))
            elif path == '/api/locations':
                self.send_json(get_simple_list(conn, 'locations'))
            elif path == '/api/contract_types':
                self.send_json(get_simple_list(conn, 'contract_types'))
            elif path == '/api/contracts':
                self.send_json(get_docs(conn, 'contracts'))
            elif path == '/api/contract_payments':
                self.send_json(get_docs(conn, 'contract_payments'))
            elif path == '/api/returns':
                self.send_json(get_docs(conn, 'returns'))
            elif path == '/api/return_reasons':
                self.send_json(get_simple_list(conn, 'return_reasons'))
            elif path == '/api/supply_plans':
                self.send_json(get_docs(conn, 'supply_plans'))
            elif path == '/api/need_declarations':
                self.send_json(get_docs(conn, 'need_declarations'))
            elif path == '/api/petty_cash':
                self.send_json(get_docs(conn, 'petty_cash'))
            elif path == '/api/petty_holders':
                self.send_json(get_simple_list(conn, 'petty_holders'))
            elif path == '/api/car_models':
                self.send_json(get_simple_list(conn, 'car_models'))
            elif path == '/api/petty_card_persons':
                self.send_json(get_simple_list(conn, 'petty_card_persons'))
            elif path == '/api/petty_deposits':
                self.send_json(get_docs(conn, 'petty_deposits'))
            elif path == '/api/ship_queue':
                self.send_json(get_docs(conn, 'ship_queue'))
            elif path == '/api/petty_charges':
                self.send_json(get_docs(conn, 'petty_charges'))
            elif path == '/api/manual_receipts':
                self.send_json(get_docs(conn, 'manual_receipts'))
            elif path == '/api/invoice_docs':
                self.send_json(get_docs(conn, 'invoice_docs'))
            elif path == '/api/settings':
                self.send_json(get_all_settings(conn))
            elif path == '/api/users':
                rows = conn.execute('SELECT * FROM users ORDER BY id').fetchall()
                self.send_json([user_public_dict(r) for r in rows])
            elif path == '/api/audit_log':
                q = 'SELECT * FROM audit_log'
                args = []
                conds = []
                if qs.get('entity'):
                    conds.append('entity=?'); args.append(unquote(qs['entity']))
                if qs.get('entity_id'):
                    conds.append('entity_id=?'); args.append(unquote(qs['entity_id']))
                if conds:
                    q += ' WHERE ' + ' AND '.join(conds)
                q += ' ORDER BY id DESC LIMIT ?'
                args.append(int(qs.get('limit', 200)))
                rows = conn.execute(q, args).fetchall()
                self.send_json([dict(r) for r in rows])
            elif path == '/api/payment_status':
                self.send_json(self.compute_payment_status(conn))
            elif path == '/api/all':
                self.send_all(conn)
            elif path == '/api/stats':
                self.send_json(self.compute_stats(conn))
            else:
                self.send_json({'error': 'not found'}, 404)
        finally:
            conn.close()

    def send_all(self, conn):
        requests_ = [request_row_to_dict(r) for r in conn.execute('SELECT * FROM requests ORDER BY id')]
        purchases_ = [purchase_row_to_dict(conn, r) for r in conn.execute('SELECT * FROM purchases ORDER BY id')]
        shippings_ = [shipping_row_to_dict(conn, r) for r in conn.execute('SELECT * FROM shippings ORDER BY id')]
        sales_ = [sale_row_to_dict(conn, r) for r in conn.execute('SELECT * FROM sales ORDER BY id')]
        sales_returns_ = [salesreturn_row_to_dict(conn, r) for r in conn.execute('SELECT * FROM sales_returns ORDER BY id')]
        suppliers_names = [r['name'] for r in conn.execute('SELECT name FROM suppliers ORDER BY name')]
        suppliers_full = [supplier_row_to_dict(r) for r in conn.execute('SELECT * FROM suppliers ORDER BY name')]
        users_ = [user_public_dict(r) for r in conn.execute('SELECT * FROM users ORDER BY id')]
        destinations_ = [dict(r) for r in conn.execute('SELECT * FROM destinations ORDER BY id')]
        self.send_json({
            'items': get_docs(conn, 'items'), 'requests': requests_, 'purchases': purchases_,
            'shippings': shippings_, 'sales': sales_, 'sales_returns': sales_returns_,
            'units': get_simple_list(conn, 'units'), 'destinations': destinations_,
            'suppliers': suppliers_names, 'supplier_profiles': suppliers_full,
            'supplier_payments': [dict(r) for r in conn.execute('SELECT * FROM supplier_payments ORDER BY id')],
            'reasons': get_simple_list(conn, 'non_fulfillment_reasons'),
            'transport_types': get_simple_list(conn, 'transport_types'),
            'ship_statuses': get_simple_list(conn, 'ship_statuses'),
            'supply_statuses': get_simple_list(conn, 'supply_statuses'),
            'requester_units': get_simple_list(conn, 'requester_units'),
            'locations': get_simple_list(conn, 'locations'),
            'contract_types': get_simple_list(conn, 'contract_types'),
            'contracts': get_docs(conn, 'contracts'), 'contract_payments': get_docs(conn, 'contract_payments'),
            'settings': get_all_settings(conn),
            'returns': get_docs(conn, 'returns'), 'return_reasons': get_simple_list(conn, 'return_reasons'),
            'supply_plans': get_docs(conn, 'supply_plans'),
            'need_declarations': get_docs(conn, 'need_declarations'),
            'petty_cash': get_docs(conn, 'petty_cash'), 'petty_holders': get_simple_list(conn, 'petty_holders'),
            'car_models': get_simple_list(conn, 'car_models'),
            'petty_card_persons': get_simple_list(conn, 'petty_card_persons'),
            'petty_deposits': get_docs(conn, 'petty_deposits'),
            'petty_charges': get_docs(conn, 'petty_charges'),
            'petty_fund': get_setting(conn, 'petty_fund', {'manager': 'زارع', 'total': 0, 'year': '', 'note': ''}),
            'manual_receipts': get_docs(conn, 'manual_receipts'),
            'invoice_docs': get_docs(conn, 'invoice_docs'),
            'ship_queue': get_docs(conn, 'ship_queue'),
            'users': users_
        })

    def compute_stats(self, conn):
        rows = conn.execute('SELECT * FROM purchases ORDER BY id').fetchall()
        purchases = [purchase_row_to_dict(conn, r) for r in rows]
        today = datetime.date.today().strftime('%Y/%m/%d')
        total = len(purchases)
        shipped = sum(1 for p in purchases if p.get('ship_status') == 'shipped')
        pending = sum(1 for p in purchases if p.get('ship_status') == 'pending')
        non_fulfilled = sum(1 for p in purchases if (p.get('status') or '').find('عدم') >= 0)
        total_amount = sum(float(p.get('invoice_amount', 0) or 0) for p in purchases)
        overdue = [p for p in purchases if p.get('delivery_date', '') and p.get('delivery_date', '') < today
                   and p.get('ship_status') == 'pending']
        req_count = conn.execute('SELECT COUNT(*) c FROM requests').fetchone()['c']
        return {'total': total, 'shipped': shipped, 'pending': pending, 'non_fulfilled': non_fulfilled,
                'total_amount': total_amount, 'overdue_count': len(overdue), 'overdue': overdue[:10],
                'request_count': req_count}

    def compute_payment_status(self, conn):
        """گزارش پیگیری پرداخت: خریدهایی با مانده پرداخت غیر صفر، همراه سررسید و
        پرچم تاخیر (در صورت ثبت سررسید)."""
        today = datetime.date.today().strftime('%Y/%m/%d')
        rows = conn.execute(
            "SELECT * FROM purchases WHERE ABS(remaining_amount) >= 1 ORDER BY due_date").fetchall()
        out = []
        for r in rows:
            due = r['due_date'] or ''
            overdue = bool(due) and due < today and (r['remaining_amount'] or 0) > 0
            out.append({
                'id': r['id'], 'req_number': r['req_number'], 'supplier': r['supplier'],
                'remaining': r['remaining_amount'], 'due_date': due,
                'payment_method': r['payment_method'] or '', 'financial_status': r['financial_status'] or '',
                'overdue': overdue,
            })
        out.sort(key=lambda x: (not x['overdue'], x['due_date'] or '9999'))
        return out

    # توجه: actor_can قدیمی (مبتنی بر هویت خوداظهاری در بدنه‌ی پیام) از اینجا حذف شد —
    # هر بررسی دسترسی باید از session_can/is_manager (مبتنی بر توکن نشست واقعی) استفاده کند.

    # -----------------------------------------------------------------
    def do_POST(self):
        p = urlparse(self.path)
        path = p.path
        body = self.get_body()
        conn = db.get_conn()
        try:
            session_user = self.get_session_user(conn)
            actor = session_user['name'] if session_user is not None else \
                (body.get('_actor') or body.get('created_by') or body.get('expert'))
            self.handle_post(conn, path, body, actor, session_user)
        finally:
            conn.close()

    def handle_post(self, conn, path, body, actor, session_user):
        parts = path.lstrip('/').split('/')

        if path == '/api/login':
            pw = h(body.get('password', ''))
            u = conn.execute('SELECT * FROM users WHERE name=? AND password=?', (body.get('username'), pw)).fetchone()
            if u:
                token = db.create_session(conn, u['id'])
                self.send_json({'ok': True, 'user': user_public_dict(u), 'token': token})
            else:
                self.send_json({'ok': False, 'error': 'نام کاربری یا رمز عبور اشتباه است'})
            return

        if path == '/api/logout':
            tok = self.get_token()
            if tok:
                db.destroy_session(conn, tok)
            self.send_json({'ok': True})
            return

        if path == '/api/items':
            if not self.require(session_user, self.is_manager(session_user)): return
            item = dict(body); item.pop('_actor', None)
            item['id'] = next_doc_id(conn, 'items')
            conn.execute('INSERT INTO docs (collection, id, data, created_at) VALUES (?,?,?,?)',
                         ('items', item['id'], json.dumps(item, ensure_ascii=False), now_iso()))
            db.log_audit(conn, actor, 'create', 'items', item['id'], after=item); conn.commit()
            self.send_json(item); return

        if path == '/api/items/bulk':
            if not self.require(session_user, self.is_manager(session_user)): return
            items = body.get('items', [])
            existing = get_docs(conn, 'items')
            code_index = {i.get('code'): i for i in existing if i.get('code')}
            added, updated = 0, 0
            for item in items:
                code, name = item.get('code'), item.get('name')
                if code and name:
                    if code in code_index:
                        ex = code_index[code]
                        ex.update(item)
                        conn.execute('UPDATE docs SET data=? WHERE collection=? AND id=?',
                                     (json.dumps(ex, ensure_ascii=False), 'items', ex['id']))
                        updated += 1
                    else:
                        item = dict(item)
                        item['id'] = next_doc_id(conn, 'items')
                        conn.execute('INSERT INTO docs (collection, id, data, created_at) VALUES (?,?,?,?)',
                                     ('items', item['id'], json.dumps(item, ensure_ascii=False), now_iso()))
                        code_index[code] = item
                        added += 1
            conn.commit()
            total = conn.execute('SELECT COUNT(*) c FROM docs WHERE collection=?', ('items',)).fetchone()['c']
            self.send_json({'ok': True, 'added': added, 'updated': updated, 'total': total}); return

        # ---- تامین‌کننده: سازگاری قدیمی (فقط نام، مثل لیست‌های ساده‌ی قبلی) ----
        if path == '/api/suppliers':
            if not self.require(session_user, True): return  # فقط نیاز به ورود؛ بخشی از فرم ثبت خرید است
            name = (body.get('value') or body.get('name') or body.get('supplier') or '').strip()
            if name:
                resolve_or_create_supplier(conn, name, actor)
                conn.commit()
            rows = conn.execute('SELECT name FROM suppliers ORDER BY name').fetchall()
            self.send_json([r['name'] for r in rows]); return

        # ---- تامین‌کننده: پروفایل کامل (صفحه مدیریت جدید) ----
        if path == '/api/supplier_profiles':
            if not self.require(session_user, self.session_can(session_user, 'create_supplier')): return
            name = (body.get('name') or '').strip()
            if not name:
                self.send_json({'ok': False, 'error': 'نام تامین‌کننده الزامی است'}); return
            existing = conn.execute('SELECT id FROM suppliers WHERE name=?', (name,)).fetchone()
            if existing:
                self.send_json({'ok': False, 'error': 'تامین‌کننده‌ای با این نام موجود است'}); return
            cur = conn.execute(
                '''INSERT INTO suppliers (name, contact_person, phone, address, category,
                   payment_terms, bank_account, rating, is_active, note, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                (name, body.get('contact_person', ''), body.get('phone', ''), body.get('address', ''),
                 body.get('category', ''), body.get('payment_terms', ''), body.get('bank_account', ''),
                 body.get('rating'), 1 if body.get('is_active', True) else 0, body.get('note', ''),
                 now_iso(), now_iso())
            )
            db.log_audit(conn, actor, 'create', 'suppliers', cur.lastrowid, after=body)
            conn.commit()
            row = conn.execute('SELECT * FROM suppliers WHERE id=?', (cur.lastrowid,)).fetchone()
            self.send_json(supplier_row_to_dict(row)); return

        if path == '/api/supplier_payments':
            if not self.require(session_user, self.session_can(session_user, 'register_payment')): return
            sname = (body.get('supplier') or '').strip()
            sid = resolve_or_create_supplier(conn, sname, actor) if sname else body.get('supplier_id')
            cur = conn.execute(
                '''INSERT INTO supplier_payments (supplier_id, supplier, purchase_id, amount, date, method, note, created_by, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (sid, sname, body.get('purchase_id'), float(body.get('amount', 0) or 0), body.get('date'),
                 body.get('method', ''), body.get('note', ''), actor, now_iso())
            )
            pay = dict(body); pay['id'] = cur.lastrowid; pay['created_at'] = now_iso(); pay['supplier_id'] = sid
            db.log_audit(conn, actor, 'create', 'supplier_payments', cur.lastrowid, after=pay)
            conn.commit()
            self.send_json(pay); return

        # ---- لیست‌های ساده‌ی رشته‌ای ----
        if parts[0] == 'api' and len(parts) == 2 and parts[1] in SIMPLE_LISTS:
            if not self.require(session_user, True): return
            key = SIMPLE_LISTS[parts[1]]
            val = (body.get('value') or body.get('name') or body.get('unit') or
                   body.get('reason') or '').strip()
            if val and val not in get_simple_list(conn, key):
                add_simple_list_value(conn, key, val)
            self.send_json(get_simple_list(conn, key)); return

        if path == '/api/destinations':
            if not self.require(session_user, True): return
            name = (body.get('name') or '').strip()
            if name:
                cur = conn.execute('INSERT INTO destinations (name) VALUES (?)', (name,))
                conn.commit()
            rows = conn.execute('SELECT * FROM destinations ORDER BY id').fetchall()
            self.send_json([dict(r) for r in rows]); return

        if path in ('/api/contracts', '/api/contract_payments', '/api/supply_plans',
                    '/api/need_declarations', '/api/invoice_docs', '/api/manual_receipts',
                    '/api/petty_charges', '/api/petty_cash', '/api/petty_deposits', '/api/ship_queue'):
            collection = DOC_PATHS[parts[1]]
            DOC_CREATE_PERM = {
                'contracts': 'create_contract', 'contract_payments': 'create_contract',
                'supply_plans': 'create_supply_plan',
                'petty_charges': 'create_petty_charge', 'petty_cash': 'create_petty_charge',
                'petty_deposits': 'petty_deposit_view',
            }
            need_perm = DOC_CREATE_PERM.get(collection)
            if need_perm:
                allowed = self.is_manager(session_user) or self.session_can(session_user, need_perm)
            else:
                allowed = session_user is not None
            if not self.require(session_user, allowed): return
            doc = create_doc(conn, collection, body, actor)
            self.send_json(doc); return

        if path.startswith('/api/settings/'):
            if not self.require(session_user, self.is_manager(session_user)): return
            self.handle_settings_post(conn, path, body); return

        if path == '/api/close_purchase':
            pid = body.get('id'); close = body.get('close', True); reason = body.get('reason', '')
            row = conn.execute('SELECT * FROM purchases WHERE id=?', (pid,)).fetchone()
            allowed = self.is_manager(session_user) or \
                (session_user is not None and row is not None and row['expert'] == session_user['name'])
            if not self.require(session_user, allowed): return
            if row:
                before = purchase_row_to_dict(conn, row)
                if close:
                    conn.execute('UPDATE purchases SET closed=1, close_reason=?, closed_by=?, closed_at=? WHERE id=?',
                                 (reason, actor, now_iso(), pid))
                else:
                    conn.execute('UPDATE purchases SET closed=0, close_reason=NULL, closed_by=NULL, closed_at=NULL WHERE id=?',
                                 (pid,))
                db.log_audit(conn, actor, 'close' if close else 'reopen', 'purchases', pid, before=before)
                conn.commit()
            self.send_json({'ok': True}); return

        if path == '/api/petty_fund':
            if not self.require(session_user, self.is_manager(session_user)): return
            cur_fund = get_setting(conn, 'petty_fund', {'manager': 'زارع', 'total': 0, 'year': '', 'note': ''})
            cur_fund['manager'] = body.get('manager', cur_fund.get('manager', 'زارع'))
            cur_fund['total'] = body.get('total', cur_fund.get('total', 0))
            cur_fund['year'] = body.get('year', cur_fund.get('year', ''))
            cur_fund['note'] = body.get('note', cur_fund.get('note', ''))
            set_setting(conn, 'petty_fund', cur_fund)
            self.send_json({'ok': True, 'petty_fund': cur_fund}); return

        if path == '/api/requests':
            if not self.require(session_user, self.session_can(session_user, 'create_request')): return
            req = dict(body); req.pop('_actor', None)
            status = req.pop('status', 'باز')
            dup = conn.execute('SELECT COUNT(*) c FROM requests WHERE req_number=?',
                                (str(req.get('req_number')),)).fetchone()['c'] > 0
            extra = extras(req, KNOWN_REQUEST)
            cur = conn.execute(
                '''INSERT INTO requests (req_number, expert, req_date, status, created_by, created_at, imported, extra_json)
                   VALUES (?,?,?,?,?,?,?,?)''',
                (req.get('req_number'), req.get('expert'), req.get('req_date'), status,
                 req.get('created_by'), now_iso(), 1 if req.get('imported') else 0,
                 json.dumps(extra, ensure_ascii=False))
            )
            rid = cur.lastrowid
            out = request_row_to_dict(conn.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone())
            db.log_audit(conn, actor, 'create', 'requests', rid, after=out)
            conn.commit()
            self.send_json({**out, 'duplicate_warning': dup}); return

        if path == '/api/purchases':
            if not self.require(session_user, self.session_can(session_user, 'create_purchase')): return
            purchase = dict(body); purchase.pop('_actor', None)
            line_items = purchase.pop('line_items', [])
            sup_name = (purchase.get('supplier') or '').strip()
            sup_id = resolve_or_create_supplier(conn, sup_name, actor) if sup_name else None
            # فرانت‌اند فعلی فیلدهای «inv_date» و «paid» را می‌فرستد (نه date/paid_amount)؛
            # برای اینکه ستون‌های ایندکس‌شده (برای گزارش پیگیری پرداخت) واقعاً پر شوند،
            # هر دو نام را می‌خوانیم. invoice_amount و paid از extras استخراج می‌شوند.
            date_val = purchase.get('date') or purchase.get('inv_date') or ''
            try:
                paid_amt = float(purchase.get('paid_amount', purchase.get('paid', 0)) or 0)
            except (TypeError, ValueError):
                paid_amt = 0.0
            try:
                inv_amt = float(purchase.get('invoice_amount', 0) or 0)
            except (TypeError, ValueError):
                inv_amt = 0.0
            remaining_amt = inv_amt - paid_amt
            fin_status = purchase.get('financial_status') or ('تسویه' if remaining_amt <= 0 and inv_amt > 0 else
                                                                 'کسری واریزی' if inv_amt > 0 else None)
            extra = extras(purchase, KNOWN_PURCHASE)
            cur = conn.execute(
                '''INSERT INTO purchases (req_number, expert, supplier_id, supplier, date, is_contract, no_request,
                   created_at, imported, paid_amount, remaining_amount, due_date, payment_method,
                   financial_status, extra_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (purchase.get('req_number'), purchase.get('expert'), sup_id, sup_name, date_val,
                 1 if purchase.get('is_contract') else 0, 1 if purchase.get('no_request') else 0,
                 now_iso(), 1 if purchase.get('imported') else 0, paid_amt,
                 remaining_amt, purchase.get('due_date', ''),
                 purchase.get('payment_method', ''), fin_status,
                 json.dumps(extra, ensure_ascii=False))
            )
            pid = cur.lastrowid
            for it in line_items:
                it = dict(it)
                li_extra = extras(it, KNOWN_LINEITEM)
                conn.execute(
                    '''INSERT INTO purchase_items (purchase_id, item_code, item_name, qty, unit, unit_price,
                       shipped_qty, ship_status, nf_qty, nf_reason, no_fulfill, price_pending, extra_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (pid, it.get('item_code', ''), it.get('item_name'), it.get('qty'), it.get('unit'),
                     it.get('unit_price'), 0, 'pending', 0, '', 0, 0, json.dumps(li_extra, ensure_ascii=False))
                )
            recompute_request_status(conn, purchase.get('req_number'))
            out = purchase_row_to_dict(conn, conn.execute('SELECT * FROM purchases WHERE id=?', (pid,)).fetchone())
            db.log_audit(conn, actor, 'create', 'purchases', pid, after=out)
            conn.commit()
            self.send_json(out); return

        if path == '/api/sales':
            if not self.require(session_user, self.session_can(session_user, 'create_sale')): return
            sale = dict(body); sale.pop('_actor', None)
            line_items = sale.pop('line_items', [])
            total = sum((float(it.get('qty') or 0) * float(it.get('unit_price') or 0)) for it in line_items)
            try:
                paid_amt = float(sale.get('paid_amount', 0) or 0)
            except (TypeError, ValueError):
                paid_amt = 0.0
            offset_supplier = (sale.get('offset_supplier') or '').strip()
            extra = extras(sale, KNOWN_SALE)
            offset_payment_id = None
            if offset_supplier and total > 0:
                sup_id = resolve_or_create_supplier(conn, offset_supplier, actor)
                pcur = conn.execute(
                    'INSERT INTO supplier_payments (supplier_id, supplier, amount, date, method, note, created_by, created_at) '
                    'VALUES (?,?,?,?,?,?,?,?)',
                    (sup_id, offset_supplier, total, sale.get('date', ''), 'تهاتر (فروش)',
                     f"تهاتر بابت فروش شماره {sale.get('number','')}", actor, now_iso())
                )
                offset_payment_id = pcur.lastrowid
                paid_amt = total  # وقتی تهاتر می‌شود، کل مبلغ همان لحظه «تسویه» تلقی می‌شود
                extra['offset_payment_id'] = offset_payment_id
            remaining_amt = max(0.0, total - paid_amt)
            fin_status = sale.get('financial_status') or ('تسویه' if remaining_amt <= 0 and total > 0 else
                                                            'کسری دریافتی' if total > 0 else None)
            extra['invoice_amount'] = total
            cur = conn.execute(
                '''INSERT INTO sales (number, date, customer, offset_supplier, created_by, created_at,
                   paid_amount, remaining_amount, payment_method, financial_status, closed, extra_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,0,?)''',
                (sale.get('number'), sale.get('date'), sale.get('customer'), offset_supplier, actor, now_iso(),
                 paid_amt, remaining_amt, sale.get('payment_method', ''), fin_status,
                 json.dumps(extra, ensure_ascii=False))
            )
            sid = cur.lastrowid
            for it in line_items:
                it = dict(it)
                li_extra = extras(it, KNOWN_SALEITEM)
                conn.execute(
                    '''INSERT INTO sale_items (sale_id, item_code, item_name, qty, unit, unit_price, returned_qty, extra_json)
                       VALUES (?,?,?,?,?,?,0,?)''',
                    (sid, it.get('item_code', ''), it.get('item_name'), it.get('qty'), it.get('unit'),
                     it.get('unit_price'), json.dumps(li_extra, ensure_ascii=False))
                )
            out = sale_row_to_dict(conn, conn.execute('SELECT * FROM sales WHERE id=?', (sid,)).fetchone())
            db.log_audit(conn, actor, 'create', 'sales', sid, after=out)
            conn.commit()
            self.send_json(out); return

        if path == '/api/sales_returns':
            if not self.require(session_user, self.session_can(session_user, 'register_sale_return')): return
            ret = dict(body); ret.pop('_actor', None)
            items = ret.pop('items', [])
            sale_id = ret.get('sale_id')
            sale_row = conn.execute('SELECT * FROM sales WHERE id=?', (sale_id,)).fetchone()
            if not sale_row:
                self.send_json({'ok': False, 'error': 'فروش مرتبط یافت نشد'}); return
            extra = extras(ret, KNOWN_SALERETURN)
            cur = conn.execute(
                'INSERT INTO sales_returns (sale_id, number, date, note, created_by, created_at, extra_json) VALUES (?,?,?,?,?,?,?)',
                (sale_id, ret.get('number', ''), ret.get('date', ''), ret.get('note', ''), actor, now_iso(),
                 json.dumps(extra, ensure_ascii=False))
            )
            rid = cur.lastrowid
            return_total = 0.0
            for it in items:
                it = dict(it)
                qty = float(it.get('qty') or 0)
                price = float(it.get('unit_price') or 0)
                return_total += qty * price
                ri_extra = extras(it, KNOWN_SALERETURNITEM)
                conn.execute(
                    '''INSERT INTO sales_return_items (return_id, sale_item_id, item_code, item_name, qty, unit,
                       unit_price, reason, extra_json) VALUES (?,?,?,?,?,?,?,?,?)''',
                    (rid, it.get('sale_item_id'), it.get('item_code', ''), it.get('item_name'), it.get('qty'),
                     it.get('unit'), it.get('unit_price'), it.get('reason', ''),
                     json.dumps(ri_extra, ensure_ascii=False))
                )
                if it.get('sale_item_id'):
                    conn.execute('UPDATE sale_items SET returned_qty = COALESCE(returned_qty,0) + ? WHERE id=?',
                                 (qty, it.get('sale_item_id')))
            # اگر فروش اصلی تهاتر با تامین‌کننده داشت، به همان میزان برگشتی، بدهی به آن تامین‌کننده دوباره برمی‌گردد
            sale_extra = json.loads(sale_row['extra_json'] or '{}')
            offset_supplier = sale_row['offset_supplier']
            reversal_payment_id = None
            if offset_supplier and return_total > 0:
                sup_id = resolve_or_create_supplier(conn, offset_supplier, actor)
                rcur = conn.execute(
                    'INSERT INTO supplier_payments (supplier_id, supplier, amount, date, method, note, created_by, created_at) '
                    'VALUES (?,?,?,?,?,?,?,?)',
                    (sup_id, offset_supplier, -return_total, ret.get('date', ''), 'برگشت تهاتر',
                     f"برگشت از فروش شماره {sale_row['number']} - کسر از تهاتر قبلی", actor, now_iso())
                )
                reversal_payment_id = rcur.lastrowid
                extra['reversal_payment_id'] = reversal_payment_id
                conn.execute('UPDATE sales_returns SET extra_json=? WHERE id=?',
                             (json.dumps(extra, ensure_ascii=False), rid))
            out = salesreturn_row_to_dict(conn, conn.execute('SELECT * FROM sales_returns WHERE id=?', (rid,)).fetchone())
            db.log_audit(conn, actor, 'create', 'sales_returns', rid, after=out)
            conn.commit()
            self.send_json(out); return

        if path == '/api/shippings':
            if not self.require(session_user, self.session_can(session_user, 'create_shipping')): return
            shipping = dict(body); shipping.pop('_actor', None)
            items = shipping.pop('items', [])
            extra = extras(shipping, KNOWN_SHIPPING)
            cur = conn.execute(
                '''INSERT INTO shippings (number, date, transport, driver, destination, created_by,
                   warehouse_no, year, created_at, imported, extra_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (shipping.get('number'), shipping.get('date'), shipping.get('transport'), shipping.get('driver'),
                 shipping.get('destination'), shipping.get('created_by'), shipping.get('warehouse_no'),
                 shipping.get('year'), now_iso(), 1 if shipping.get('imported') else 0,
                 json.dumps(extra, ensure_ascii=False))
            )
            sid = cur.lastrowid
            for it in items:
                it = dict(it)
                si_extra = extras(it, KNOWN_SHIPITEM)
                conn.execute(
                    '''INSERT INTO shipping_items (shipping_id, item_name, item_code, qty, unit, req_number,
                       supplier, purchase_id, line_id, notes, no_request_item, extra_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (sid, it.get('item_name'), it.get('item_code', ''), it.get('qty'), it.get('unit'),
                     it.get('req_number', ''), it.get('supplier', ''), it.get('purchase_id'), it.get('line_id'),
                     it.get('notes', ''), 1 if it.get('no_request_item') else 0,
                     json.dumps(si_extra, ensure_ascii=False))
                )
            apply_shipping_to_lines(conn, items, sign=1)
            affected = set()
            for it in items:
                rn = it.get('req_number')
                if not rn and it.get('purchase_id'):
                    pur = conn.execute('SELECT req_number FROM purchases WHERE id=?', (it.get('purchase_id'),)).fetchone()
                    if pur: rn = pur['req_number']
                if rn: affected.add(rn)
            for rn in affected:
                recompute_request_status(conn, rn)
            out = shipping_row_to_dict(conn, conn.execute('SELECT * FROM shippings WHERE id=?', (sid,)).fetchone())
            db.log_audit(conn, actor, 'create', 'shippings', sid, after=out)
            conn.commit()
            self.send_json(out); return

        if path == '/api/users':
            allowed = self.is_manager(session_user) and \
                (session_user['role'] == 'admin' or self.session_can(session_user, 'manage_users'))
            if not self.require(session_user, allowed): return
            if conn.execute('SELECT 1 FROM users WHERE name=?', (body.get('name'),)).fetchone():
                self.send_json({'ok': False, 'error': 'این نام کاربری قبلاً وجود دارد'}); return
            role = body.get('role', 'expert')
            # فقط ادمین می‌تواند نقش admin بسازد؛ مدیر (غیرادمین) نمی‌تواند خودش/دیگری را ادمین کند
            if role == 'admin' and session_user['role'] != 'admin':
                self.send_json({'ok': False, 'error': 'فقط ادمین می‌تواند کاربر با نقش ادمین بسازد'}, 403); return
            perms = body.get('perms') if body.get('perms') is not None else default_perms(role)
            cur = conn.execute(
                '''INSERT INTO users (name, role, title, password, is_expert_listed, unit, fiscal_year, perms_json, perm_log_json)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (body['name'], role, body.get('title', ''), h(body.get('password', '')),
                 1 if body.get('is_expert_listed', True) else 0, body.get('unit', 'بازرگانی و پشتیبانی'),
                 body.get('fiscal_year', ''), json.dumps(perms, ensure_ascii=False), '[]')
            )
            db.log_audit(conn, actor, 'create', 'users', cur.lastrowid, after={'name': body['name'], 'role': role})
            conn.commit()
            self.send_json({'ok': True}); return

        if path == '/api/returns':
            if not self.require(session_user, self.session_can(session_user, 'register_return')): return
            apply_shipping_to_lines(conn, body.get('items', []), sign=-1)
            ret = create_doc(conn, 'returns', body, actor)
            affected = set()
            for it in body.get('items', []):
                rn = it.get('req_number')
                if not rn and it.get('purchase_id'):
                    pur = conn.execute('SELECT req_number FROM purchases WHERE id=?', (it.get('purchase_id'),)).fetchone()
                    if pur: rn = pur['req_number']
                if rn: affected.add(rn)
            for rn in affected:
                recompute_request_status(conn, rn)
            conn.commit()
            self.send_json(ret); return

        if path == '/api/backup':
            if not self.require(session_user, self.session_can(session_user, 'manage_backup')): return
            os.makedirs(BACKUP_DIR, exist_ok=True)
            ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            dest = os.path.join(BACKUP_DIR, f'mehr_{ts}.db')
            import sqlite3 as _sqlite3
            with _sqlite3.connect(dest) as bconn:
                conn.backup(bconn)
            backs = sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith('mehr_'))
            if len(backs) > 60:
                for old in backs[:-60]:
                    try: os.remove(os.path.join(BACKUP_DIR, old))
                    except OSError: pass
            self.send_json({'ok': True, 'size': os.path.getsize(dest)}); return

        self.send_json({'error': 'not found'}, 404)

    def handle_settings_post(self, conn, path, body):
        key = path.split('/')[-1]
        if key == 'signature':
            set_setting(conn, 'signature_b64', body.get('signature_b64', ''))
        elif key == 'approver_signature':
            set_setting(conn, 'approver_signature_b64', body.get('signature_b64', ''))
        elif key == 'vat':
            set_setting(conn, 'vat_rate', body.get('vat_rate', 10))
        elif key == 'petty_tracking':
            set_setting(conn, 'petty_tracking', body.get('rows', []))
        elif key == 'dash_labels':
            set_setting(conn, 'dash_labels', body if isinstance(body, dict) else {})
        elif key == 'nf_descriptions':
            nfd = get_setting(conn, 'nf_descriptions', {})
            k = str(body.get('nf_number', ''))
            if k:
                nfd[k] = {'desc': body.get('desc', ''), 'actions': body.get('actions', '')}
                set_setting(conn, 'nf_descriptions', nfd)
        elif key == 'mrp_plan':
            set_setting(conn, 'mrp_plan', body.get('plan', {}) if isinstance(body.get('plan'), dict) else {})
        self.send_json({'ok': True})

    # -----------------------------------------------------------------
    def do_PUT(self):
        p = urlparse(self.path)
        body = self.get_body()
        parts = [unquote(x) for x in p.path.strip('/').split('/')]
        conn = db.get_conn()
        try:
            session_user = self.get_session_user(conn)
            actor = session_user['name'] if session_user is not None else \
                (body.get('_actor') or body.get('created_by') or body.get('expert'))
            self.handle_put(conn, parts, body, actor, session_user)
        finally:
            conn.close()

    def handle_put(self, conn, parts, body, actor, session_user):
        if not (parts[0] == 'api' and len(parts) == 3):
            self.send_json({'error': 'not found'}, 404); return
        collection, rid = parts[1], parts[2]

        if collection == 'users':
            u = conn.execute('SELECT * FROM users WHERE id=?', (rid,)).fetchone()
            if not u:
                self.send_json({'error': 'not found'}, 404); return
            is_self = session_user is not None and str(session_user['id']) == str(rid)
            only_own_password = is_self and set(body.keys()) <= {'password', '_actor'}
            allowed = only_own_password or self.is_manager(session_user) or \
                self.session_can(session_user, 'manage_users')
            if not self.require(session_user, allowed): return
            # فقط ادمین می‌تواند نقش کسی را به admin تغییر دهد یا نقش یک ادمین را تغییر دهد
            if 'role' in body and (body['role'] == 'admin' or u['role'] == 'admin') and \
                    (session_user is None or session_user['role'] != 'admin'):
                self.send_json({'ok': False, 'error': 'فقط ادمین به این کار مجاز است'}, 403); return
            now = datetime.datetime.now().strftime('%Y/%m/%d %H:%M')
            changes = []
            updates = {}
            if body.get('password'):
                updates['password'] = h(body['password']); changes.append('تغییر رمز عبور')
            if 'perms' in body:
                old = json.loads(u['perms_json'] or '{}')
                new = body['perms'] or {}
                for k in set(list(old.keys()) + list(new.keys())):
                    ov, nv = bool(old.get(k, False)), bool(new.get(k, False))
                    if ov != nv:
                        changes.append(('فعال شد: ' if nv else 'غیرفعال شد: ') + k)
                updates['perms_json'] = json.dumps(new, ensure_ascii=False)
            if 'role' in body and body['role'] != u['role']:
                changes.append('نقش: ' + str(u['role']) + ' → ' + str(body['role']))
                updates['role'] = body['role']
            for f in ('name', 'title', 'is_expert_listed', 'unit', 'fiscal_year'):
                if f in body:
                    updates[f] = body[f]
            if changes:
                log = json.loads(u['perm_log_json'] or '[]')
                log.append({'at': now, 'by': actor, 'changes': changes})
                updates['perm_log_json'] = json.dumps(log[-50:], ensure_ascii=False)
            if updates:
                set_clause = ', '.join(f'{k}=?' for k in updates)
                conn.execute(f'UPDATE users SET {set_clause} WHERE id=?', (*updates.values(), rid))
                db.log_audit(conn, actor, 'update', 'users', rid, note='; '.join(changes))
                conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'suppliers':
            row = conn.execute('SELECT * FROM suppliers WHERE id=?', (rid,)).fetchone()
            if not row:
                self.send_json({'error': 'not found'}, 404); return
            if not self.require(session_user, self.is_manager(session_user) or
                                 self.session_can(session_user, 'edit_supplier')): return
            before = supplier_row_to_dict(row)
            fields = ['name', 'contact_person', 'phone', 'address', 'category', 'payment_terms',
                      'bank_account', 'rating', 'is_active', 'note']
            updates = {f: body[f] for f in fields if f in body}
            if updates:
                updates['updated_at'] = now_iso()
                set_clause = ', '.join(f'{k}=?' for k in updates)
                conn.execute(f'UPDATE suppliers SET {set_clause} WHERE id=?', (*updates.values(), rid))
                db.log_audit(conn, actor, 'update', 'suppliers', rid, before=before, after=updates)
                conn.commit()
            out = supplier_row_to_dict(conn.execute('SELECT * FROM suppliers WHERE id=?', (rid,)).fetchone())
            self.send_json(out); return

        if collection == 'purchases':
            row = conn.execute('SELECT * FROM purchases WHERE id=?', (rid,)).fetchone()
            if not row:
                self.send_json({'error': 'not found'}, 404); return
            allowed = self.is_manager(session_user) or \
                (session_user is not None and row['expert'] == session_user['name']) or \
                self.session_can(session_user, 'edit_any_purchase')
            if not self.require(session_user, allowed): return
            before = purchase_row_to_dict(conn, row)
            body = dict(body)
            line_items = body.pop('line_items', None)
            if body.get('supplier'):
                sid = resolve_or_create_supplier(conn, body['supplier'], actor)
                body['supplier_id'] = sid
            # ادغام مقادیر جدید روی موجودی فعلی (مثل رفتار قبلی col[idx].update(body))
            known_updates = {k: v for k, v in body.items() if k in KNOWN_PURCHASE and k not in ('id', '_actor')}
            extra_existing = json.loads(row['extra_json'] or '{}')
            extra_existing.update(extras(body, KNOWN_PURCHASE))
            # فرانت‌اند فعلی «inv_date» و «paid» می‌فرستد (نه date/paid_amount)؛ این مقادیر را
            # از extras (تازه‌ادغام‌شده) می‌خوانیم تا ستون‌های ایندکس‌شده گزارش پرداخت درست بمانند.
            try:
                paid_amt = float(extra_existing.get('paid_amount', extra_existing.get('paid', 0)) or 0)
            except (TypeError, ValueError):
                paid_amt = 0.0
            try:
                inv_amt = float(extra_existing.get('invoice_amount', 0) or 0)
            except (TypeError, ValueError):
                inv_amt = 0.0
            known_updates['paid_amount'] = paid_amt
            known_updates['remaining_amount'] = inv_amt - paid_amt
            known_updates['date'] = (body.get('date') or body.get('inv_date') or
                                      extra_existing.get('inv_date') or row['date'])
            if 'financial_status' not in known_updates:
                known_updates['financial_status'] = (
                    'تسویه' if (inv_amt - paid_amt) <= 0 and inv_amt > 0 else
                    'کسری واریزی' if inv_amt > 0 else row['financial_status'])
            if known_updates or extra_existing:
                set_parts = []
                vals = []
                for k, v in known_updates.items():
                    if k in ('is_contract', 'no_request', 'closed'):
                        v = 1 if v else 0
                    set_parts.append(f'{k}=?'); vals.append(v)
                set_parts.append('extra_json=?'); vals.append(json.dumps(extra_existing, ensure_ascii=False))
                vals.append(rid)
                conn.execute(f'UPDATE purchases SET {", ".join(set_parts)} WHERE id=?', vals)
            if line_items is not None:
                # حفظ ردیف‌های موجود (با line_id)، درج ردیف‌های جدید (بدون line_id)
                existing_ids = {r['id'] for r in conn.execute('SELECT id FROM purchase_items WHERE purchase_id=?', (rid,))}
                kept_ids = set()
                for it in line_items:
                    it = dict(it)
                    lid = it.get('line_id')
                    li_extra = extras(it, KNOWN_LINEITEM)
                    if lid and lid in existing_ids:
                        try:
                            up = float(it.get('unit_price') or 0)
                        except (TypeError, ValueError):
                            up = 0.0
                        price_pending = 0 if up > 0 else 1
                        conn.execute(
                            '''UPDATE purchase_items SET item_code=?, item_name=?, qty=?, unit=?, unit_price=?,
                               price_pending=?, extra_json=? WHERE id=?''',
                            (it.get('item_code', ''), it.get('item_name'), it.get('qty'), it.get('unit'),
                             it.get('unit_price'), price_pending, json.dumps(li_extra, ensure_ascii=False), lid)
                        )
                        kept_ids.add(lid)
                    else:
                        conn.execute(
                            '''INSERT INTO purchase_items (purchase_id, item_code, item_name, qty, unit, unit_price,
                               shipped_qty, ship_status, nf_qty, nf_reason, no_fulfill, price_pending, extra_json)
                               VALUES (?,?,?,?,?,?,0,'pending',0,'',0,0,?)''',
                            (rid, it.get('item_code', ''), it.get('item_name'), it.get('qty'), it.get('unit'),
                             it.get('unit_price'), json.dumps(li_extra, ensure_ascii=False))
                        )
                # ردیف‌هایی که در ارسال جدید نبودند حذف شوند (مطابق رفتار قبلی replace کامل آرایه)
                for old_id in existing_ids - kept_ids:
                    conn.execute('DELETE FROM purchase_items WHERE id=?', (old_id,))
            rn = body.get('req_number', row['req_number'])
            recompute_request_status(conn, rn)
            out = purchase_row_to_dict(conn, conn.execute('SELECT * FROM purchases WHERE id=?', (rid,)).fetchone())
            db.log_audit(conn, actor, 'update', 'purchases', rid, before=before, after=out)
            conn.commit()
            self.send_json(out); return

        if collection == 'sales':
            row = conn.execute('SELECT * FROM sales WHERE id=?', (rid,)).fetchone()
            if not row:
                self.send_json({'error': 'not found'}, 404); return
            allowed = self.is_manager(session_user) or \
                (session_user is not None and row['created_by'] == session_user['name']) or \
                self.session_can(session_user, 'edit_sale')
            if not self.require(session_user, allowed): return
            before = sale_row_to_dict(conn, row)
            body2 = dict(body)
            line_items = body2.pop('line_items', None)
            extra_existing = json.loads(row['extra_json'] or '{}')
            extra_existing.update(extras(body2, KNOWN_SALE))
            known_updates = {k: v for k, v in body2.items() if k in KNOWN_SALE and k not in ('id', '_actor')}
            if line_items is not None:
                existing_ids = {r['id'] for r in conn.execute('SELECT id FROM sale_items WHERE sale_id=?', (rid,))}
                kept_ids = set()
                for it in line_items:
                    it = dict(it)
                    lid = it.get('line_id')
                    li_extra = extras(it, KNOWN_SALEITEM)
                    if lid and lid in existing_ids:
                        conn.execute('UPDATE sale_items SET item_code=?, item_name=?, qty=?, unit=?, unit_price=?, extra_json=? WHERE id=?',
                                     (it.get('item_code', ''), it.get('item_name'), it.get('qty'), it.get('unit'),
                                      it.get('unit_price'), json.dumps(li_extra, ensure_ascii=False), lid))
                        kept_ids.add(lid)
                    else:
                        conn.execute('INSERT INTO sale_items (sale_id, item_code, item_name, qty, unit, unit_price, returned_qty, extra_json) VALUES (?,?,?,?,?,?,0,?)',
                                     (rid, it.get('item_code', ''), it.get('item_name'), it.get('qty'), it.get('unit'),
                                      it.get('unit_price'), json.dumps(li_extra, ensure_ascii=False)))
                for old_id in existing_ids - kept_ids:
                    conn.execute('DELETE FROM sale_items WHERE id=?', (old_id,))
            total = conn.execute(
                "SELECT COALESCE(SUM(CAST(qty AS REAL)*CAST(unit_price AS REAL)),0) t FROM sale_items WHERE sale_id=?",
                (rid,)).fetchone()['t']
            new_offset_supplier = (known_updates.get('offset_supplier', row['offset_supplier']) or '').strip()
            old_offset_payment_id = extra_existing.get('offset_payment_id')
            # اگر تامین‌کننده تهاتر تغییر کرده یا حذف شده، پرداخت تهاتر قبلی را پاک کن و در صورت نیاز دوباره بساز
            if old_offset_payment_id and (new_offset_supplier != (row['offset_supplier'] or '')):
                conn.execute('DELETE FROM supplier_payments WHERE id=?', (old_offset_payment_id,))
                extra_existing.pop('offset_payment_id', None)
                old_offset_payment_id = None
            if new_offset_supplier and total > 0:
                if old_offset_payment_id:
                    conn.execute('UPDATE supplier_payments SET amount=? WHERE id=?', (total, old_offset_payment_id))
                else:
                    sup_id = resolve_or_create_supplier(conn, new_offset_supplier, actor)
                    pcur = conn.execute(
                        'INSERT INTO supplier_payments (supplier_id, supplier, amount, date, method, note, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)',
                        (sup_id, new_offset_supplier, total, known_updates.get('date', row['date']), 'تهاتر (فروش)',
                         f"تهاتر بابت فروش شماره {known_updates.get('number', row['number'])}", actor, now_iso()))
                    extra_existing['offset_payment_id'] = pcur.lastrowid
                known_updates['paid_amount'] = total
            paid_amt = float(known_updates.get('paid_amount', row['paid_amount']) or 0)
            remaining_amt = max(0.0, total - paid_amt)
            known_updates['remaining_amount'] = remaining_amt
            if 'financial_status' not in known_updates:
                known_updates['financial_status'] = 'تسویه' if remaining_amt <= 0 and total > 0 else ('کسری دریافتی' if total > 0 else row['financial_status'])
            extra_existing['invoice_amount'] = total
            set_parts, vals = [], []
            for k, v in known_updates.items():
                if k == 'closed':
                    v = 1 if v else 0
                set_parts.append(f'{k}=?'); vals.append(v)
            set_parts.append('extra_json=?'); vals.append(json.dumps(extra_existing, ensure_ascii=False))
            vals.append(rid)
            if set_parts:
                conn.execute(f'UPDATE sales SET {", ".join(set_parts)} WHERE id=?', vals)
            out = sale_row_to_dict(conn, conn.execute('SELECT * FROM sales WHERE id=?', (rid,)).fetchone())
            db.log_audit(conn, actor, 'update', 'sales', rid, before=before, after=out)
            conn.commit()
            self.send_json(out); return

        if collection == 'shippings':
            row = conn.execute('SELECT * FROM shippings WHERE id=?', (rid,)).fetchone()
            if not row:
                self.send_json({'error': 'not found'}, 404); return
            if not self.require(session_user, self.is_manager(session_user) or
                                 self.session_can(session_user, 'edit_shipping')): return
            before = shipping_row_to_dict(conn, row)
            apply_shipping_to_lines(conn, before.get('items', []), sign=-1)
            new_items = body.get('items', before.get('items', []))
            body2 = dict(body); body2.pop('items', None)
            known_fields = ['number', 'date', 'transport', 'driver', 'destination', 'created_by',
                             'warehouse_no', 'year', 'imported']
            updates = {k: v for k, v in body2.items() if k in known_fields}
            extra_existing = json.loads(row['extra_json'] or '{}')
            extra_existing.update(extras(body2, KNOWN_SHIPPING))
            set_parts = [f'{k}=?' for k in updates]
            vals = list(updates.values())
            set_parts.append('extra_json=?'); vals.append(json.dumps(extra_existing, ensure_ascii=False))
            vals.append(rid)
            conn.execute(f'UPDATE shippings SET {", ".join(set_parts)} WHERE id=?', vals)
            if 'items' in body:
                conn.execute('DELETE FROM shipping_items WHERE shipping_id=?', (rid,))
                for it in new_items:
                    it = dict(it)
                    si_extra = extras(it, KNOWN_SHIPITEM)
                    conn.execute(
                        '''INSERT INTO shipping_items (shipping_id, item_name, item_code, qty, unit, req_number,
                           supplier, purchase_id, line_id, notes, no_request_item, extra_json)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (rid, it.get('item_name'), it.get('item_code', ''), it.get('qty'), it.get('unit'),
                         it.get('req_number', ''), it.get('supplier', ''), it.get('purchase_id'), it.get('line_id'),
                         it.get('notes', ''), 1 if it.get('no_request_item') else 0,
                         json.dumps(si_extra, ensure_ascii=False))
                    )
            apply_shipping_to_lines(conn, new_items, sign=1)
            affected = set()
            for it in new_items:
                rn = it.get('req_number')
                if not rn and it.get('purchase_id'):
                    pur = conn.execute('SELECT req_number FROM purchases WHERE id=?', (it.get('purchase_id'),)).fetchone()
                    if pur: rn = pur['req_number']
                if rn: affected.add(rn)
            for rn in affected:
                recompute_request_status(conn, rn)
            out = shipping_row_to_dict(conn, conn.execute('SELECT * FROM shippings WHERE id=?', (rid,)).fetchone())
            db.log_audit(conn, actor, 'update', 'shippings', rid, before=before, after=out)
            conn.commit()
            self.send_json(out); return

        if collection == 'requests':
            row = conn.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone()
            if not row:
                self.send_json({'error': 'not found'}, 404); return
            allowed = self.is_manager(session_user) or \
                (session_user is not None and row['expert'] == session_user['name']) or \
                self.session_can(session_user, 'edit_request') or \
                self.session_can(session_user, 'assign_request')
            if not self.require(session_user, allowed): return
            before = request_row_to_dict(row)
            known_fields = ['req_number', 'expert', 'req_date', 'status', 'created_by', 'imported']
            updates = {k: v for k, v in body.items() if k in known_fields}
            extra_existing = json.loads(row['extra_json'] or '{}')
            extra_existing.update(extras(body, KNOWN_REQUEST))
            set_parts = [f'{k}=?' for k in updates]; vals = list(updates.values())
            set_parts.append('extra_json=?'); vals.append(json.dumps(extra_existing, ensure_ascii=False))
            vals.append(rid)
            conn.execute(f'UPDATE requests SET {", ".join(set_parts)} WHERE id=?', vals)
            out = request_row_to_dict(conn.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone())
            db.log_audit(conn, actor, 'update', 'requests', rid, before=before, after=out)
            conn.commit()
            self.send_json(out); return

        if collection == 'destinations':
            if not self.require(session_user, True): return
            conn.execute('UPDATE destinations SET name=? WHERE id=?', (body.get('name'), rid))
            conn.commit()
            row = conn.execute('SELECT * FROM destinations WHERE id=?', (rid,)).fetchone()
            self.send_json(dict(row) if row else {'error': 'not found'}); return

        if collection == 'items':
            if not self.require(session_user, self.is_manager(session_user)): return
            out = update_doc(conn, 'items', int(rid), body, actor)
            self.send_json(out if out else {'error': 'not found'}, 200 if out else 404); return

        if collection in DOC_PATHS:
            target = DOC_PATHS[collection]
            DOC_EDIT_PERM = {'contracts': 'edit_contract', 'contract_payments': 'edit_contract',
                              'supply_plans': 'edit_supply_plan',
                              'petty_charges': 'edit_petty_charge', 'petty_cash': 'edit_petty_charge'}
            need_perm = DOC_EDIT_PERM.get(target)
            if need_perm:
                allowed = self.is_manager(session_user) or self.session_can(session_user, need_perm)
            else:
                allowed = session_user is not None
            if not self.require(session_user, allowed): return
            out = update_doc(conn, target, int(rid), body, actor)
            self.send_json(out if out else {'error': 'not found'}, 200 if out else 404); return

        self.send_json({'error': 'not found'}, 404)

    # -----------------------------------------------------------------
    def do_DELETE(self):
        p = urlparse(self.path)
        parts = [unquote(x) for x in p.path.strip('/').split('/')]
        conn = db.get_conn()
        try:
            session_user = self.get_session_user(conn)
            actor = session_user['name'] if session_user is not None else None
            self.handle_delete(conn, parts, actor, session_user)
        finally:
            conn.close()

    def handle_delete(self, conn, parts, actor, session_user):
        if not (parts[0] == 'api' and len(parts) == 3):
            self.send_json({'error': 'not found'}, 404); return
        collection, rid = parts[1], parts[2]

        if collection in SIMPLE_LISTS:
            if not self.require(session_user, self.is_manager(session_user) or
                                 self.session_can(session_user, 'manage_lists')): return
            del_simple_list_value(conn, SIMPLE_LISTS[collection], rid)
            self.send_json({'ok': True}); return

        if collection == 'suppliers':
            if not self.require(session_user, self.is_manager(session_user) or
                                 self.session_can(session_user, 'delete_supplier')): return
            row = None
            if rid.isdigit():
                row = conn.execute('SELECT * FROM suppliers WHERE id=?', (rid,)).fetchone()
            if not row:
                row = conn.execute('SELECT * FROM suppliers WHERE name=?', (rid,)).fetchone()
            if row:
                conn.execute('UPDATE suppliers SET is_active=0 WHERE id=?', (row['id'],))
                db.log_audit(conn, actor, 'deactivate', 'suppliers', row['id'], before=supplier_row_to_dict(row))
                conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'shippings':
            row = conn.execute('SELECT * FROM shippings WHERE id=?', (rid,)).fetchone()
            if not self.require(session_user, self.is_manager(session_user) or
                                 self.session_can(session_user, 'delete_shipping')): return
            if row:
                sh = shipping_row_to_dict(conn, row)
                apply_shipping_to_lines(conn, sh.get('items', []), sign=-1)
                conn.execute('DELETE FROM shipping_items WHERE shipping_id=?', (rid,))
                conn.execute('DELETE FROM shippings WHERE id=?', (rid,))
                affected = set()
                for it in sh.get('items', []):
                    rn = it.get('req_number')
                    if not rn and it.get('purchase_id'):
                        pur = conn.execute('SELECT req_number FROM purchases WHERE id=?', (it.get('purchase_id'),)).fetchone()
                        if pur: rn = pur['req_number']
                    if rn: affected.add(rn)
                for rn in affected:
                    recompute_request_status(conn, rn)
                db.log_audit(conn, actor, 'delete', 'shippings', rid, before=sh)
                conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'purchases':
            row = conn.execute('SELECT * FROM purchases WHERE id=?', (rid,)).fetchone()
            allowed = self.is_manager(session_user) or self.session_can(session_user, 'delete_purchase') or \
                (session_user is not None and row is not None and row['expert'] == session_user['name'])
            if not self.require(session_user, allowed): return
            if row:
                pur = purchase_row_to_dict(conn, row)
                conn.execute('DELETE FROM purchase_items WHERE purchase_id=?', (rid,))
                conn.execute('DELETE FROM purchases WHERE id=?', (rid,))
                recompute_request_status(conn, pur.get('req_number'))
                db.log_audit(conn, actor, 'delete', 'purchases', rid, before=pur)
                conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'sales':
            row = conn.execute('SELECT * FROM sales WHERE id=?', (rid,)).fetchone()
            allowed = self.is_manager(session_user) or self.session_can(session_user, 'delete_sale') or \
                (session_user is not None and row is not None and row['created_by'] == session_user['name'])
            if not self.require(session_user, allowed): return
            if row:
                sale = sale_row_to_dict(conn, row)
                extra = json.loads(row['extra_json'] or '{}')
                # اگر تهاتر شده بود، پرداخت تهاتری مرتبط هم حذف شود تا بدهی تامین‌کننده درست برگردد
                if extra.get('offset_payment_id'):
                    conn.execute('DELETE FROM supplier_payments WHERE id=?', (extra['offset_payment_id'],))
                # برگشت‌های مرتبط هم حذف شوند (و پرداخت‌های برگشتی‌شان)
                for ret in conn.execute('SELECT * FROM sales_returns WHERE sale_id=?', (rid,)).fetchall():
                    ret_extra = json.loads(ret['extra_json'] or '{}')
                    if ret_extra.get('reversal_payment_id'):
                        conn.execute('DELETE FROM supplier_payments WHERE id=?', (ret_extra['reversal_payment_id'],))
                    conn.execute('DELETE FROM sales_return_items WHERE return_id=?', (ret['id'],))
                conn.execute('DELETE FROM sales_returns WHERE sale_id=?', (rid,))
                conn.execute('DELETE FROM sale_items WHERE sale_id=?', (rid,))
                conn.execute('DELETE FROM sales WHERE id=?', (rid,))
                db.log_audit(conn, actor, 'delete', 'sales', rid, before=sale)
                conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'sales_returns':
            if not self.require(session_user, self.is_manager(session_user) or
                                 self.session_can(session_user, 'register_sale_return')): return
            row = conn.execute('SELECT * FROM sales_returns WHERE id=?', (rid,)).fetchone()
            if row:
                ret = salesreturn_row_to_dict(conn, row)
                extra = json.loads(row['extra_json'] or '{}')
                if extra.get('reversal_payment_id'):
                    conn.execute('DELETE FROM supplier_payments WHERE id=?', (extra['reversal_payment_id'],))
                for it in conn.execute('SELECT * FROM sales_return_items WHERE return_id=?', (rid,)).fetchall():
                    if it['sale_item_id']:
                        conn.execute('UPDATE sale_items SET returned_qty = MAX(0, COALESCE(returned_qty,0) - ?) WHERE id=?',
                                     (float(it['qty'] or 0), it['sale_item_id']))
                conn.execute('DELETE FROM sales_return_items WHERE return_id=?', (rid,))
                conn.execute('DELETE FROM sales_returns WHERE id=?', (rid,))
                db.log_audit(conn, actor, 'delete', 'sales_returns', rid, before=ret)
                conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'returns':
            if not self.require(session_user, self.is_manager(session_user) or
                                 self.session_can(session_user, 'register_return')): return
            row = conn.execute('SELECT data FROM docs WHERE collection=? AND id=?', ('returns', rid)).fetchone()
            if row:
                ret = json.loads(row['data'])
                apply_shipping_to_lines(conn, ret.get('items', []), sign=1)
                delete_doc(conn, 'returns', int(rid))
                affected = set()
                for it in ret.get('items', []):
                    rn = it.get('req_number')
                    if not rn and it.get('purchase_id'):
                        pur = conn.execute('SELECT req_number FROM purchases WHERE id=?', (it.get('purchase_id'),)).fetchone()
                        if pur: rn = pur['req_number']
                    if rn: affected.add(rn)
                for rn in affected:
                    recompute_request_status(conn, rn)
                conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'requests':
            row = conn.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone()
            allowed = self.is_manager(session_user) or self.session_can(session_user, 'delete_request') or \
                (session_user is not None and row is not None and row['expert'] == session_user['name'])
            if not self.require(session_user, allowed): return
            if row:
                db.log_audit(conn, actor, 'delete', 'requests', rid, before=request_row_to_dict(row))
            conn.execute('DELETE FROM requests WHERE id=?', (rid,))
            conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'users':
            allowed = session_user is not None and (session_user['role'] == 'admin' or
                       self.session_can(session_user, 'manage_users'))
            if not self.require(session_user, allowed): return
            if session_user is not None and str(session_user['id']) == str(rid):
                self.send_json({'ok': False, 'error': 'نمی‌توانید حساب خودتان را حذف کنید'}, 400); return
            target = conn.execute('SELECT * FROM users WHERE id=?', (rid,)).fetchone()
            if target and target['role'] == 'admin':
                n_admins = conn.execute("SELECT COUNT(*) c FROM users WHERE role='admin'").fetchone()['c']
                if n_admins <= 1:
                    self.send_json({'ok': False, 'error': 'نمی‌توان آخرین کاربر ادمین را حذف کرد'}, 400); return
            conn.execute('DELETE FROM users WHERE id=?', (rid,))
            db.destroy_all_sessions_for_user(conn, rid)
            db.log_audit(conn, actor, 'delete', 'users', rid)
            conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'destinations':
            if not self.require(session_user, self.is_manager(session_user)): return
            conn.execute('DELETE FROM destinations WHERE id=?', (rid,))
            conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'supplier_payments':
            if not self.require(session_user, self.is_manager(session_user) or
                                 self.session_can(session_user, 'register_payment')): return
            conn.execute('DELETE FROM supplier_payments WHERE id=?', (rid,))
            db.log_audit(conn, actor, 'delete', 'supplier_payments', rid)
            conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'items':
            if not self.require(session_user, self.is_manager(session_user)): return
            delete_doc(conn, 'items', int(rid))
            self.send_json({'ok': True}); return

        if collection in DOC_PATHS:
            target = DOC_PATHS[collection]
            DOC_DELETE_PERM = {'contracts': 'delete_contract', 'contract_payments': 'delete_contract',
                                'supply_plans': 'delete_supply_plan',
                                'petty_charges': 'delete_petty_charge', 'petty_cash': 'delete_petty_charge'}
            need_perm = DOC_DELETE_PERM.get(target)
            if need_perm:
                allowed = self.is_manager(session_user) or self.session_can(session_user, need_perm)
            else:
                allowed = session_user is not None
            if not self.require(session_user, allowed): return
            delete_doc(conn, target, int(rid))
            self.send_json({'ok': True}); return

        self.send_json({'error': 'not found'}, 404)


def safe_print(msg):
    """در برخی پیکربندی‌های ویندوز، چاپ متن روی کنسول گاهی با خطای عجیب کنسول
    (WinError 31) مواجه می‌شود. این خطا نباید کل سرور را از کار بیندازد —
    بدترین حالت این است که آن خط پیام دیده نشود، نه اینکه سرور بالا نیاید."""
    try:
        print(msg)
    except OSError:
        pass


def migrate_manual_receipts_to_shippings():
    """رسیدهای دستی قدیمی (که قبلاً فقط سند JSON مستقل بودند و تاثیری روی
    shipped_qty/وضعیت درخواست نداشتند) را به جدول shippings منتقل می‌کند تا
    از این پس دقیقاً مثل یک برگه ارسال واقعی رفتار کنند. این تابع idempotent
    است و فقط یک‌بار اجرا می‌شود (با پرچم در جدول settings)."""
    conn = db.get_conn()
    try:
        if get_setting(conn, 'migrated_manual_receipts_v1', False):
            return
        docs = conn.execute("SELECT id, data FROM docs WHERE collection='manual_receipts'").fetchall()
        migrated = 0
        for d in docs:
            rec = json.loads(d['data'])
            items = rec.get('items', [])
            cur = conn.execute(
                '''INSERT INTO shippings (number, date, transport, driver, destination, created_by,
                   warehouse_no, year, created_at, imported, extra_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (rec.get('number', ''), rec.get('date', ''), '', '', '', rec.get('created_by', ''),
                 rec.get('warehouse_no', ''), '', rec.get('created_at') or now_iso(), 1,
                 json.dumps({'is_manual_receipt': True, 'receipt_type': rec.get('type', ''),
                             'receiver': rec.get('receiver', ''), 'note': rec.get('note', ''),
                             'req_number': rec.get('req_number', '')}, ensure_ascii=False))
            )
            new_sid = cur.lastrowid
            for it in items:
                conn.execute(
                    '''INSERT INTO shipping_items (shipping_id, item_name, item_code, qty, unit,
                       req_number, supplier, purchase_id, line_id, notes, no_request_item, extra_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,0,'{}')''',
                    (new_sid, it.get('item_name'), it.get('item_code', ''), it.get('qty'), it.get('unit'),
                     it.get('req_number', ''), it.get('supplier', ''), it.get('purchase_id'), it.get('line_id'),
                     it.get('notes', ''))
                )
            apply_shipping_to_lines(conn, items, sign=1)
            affected = set()
            for it in items:
                rn = it.get('req_number')
                if not rn and it.get('purchase_id'):
                    pur = conn.execute('SELECT req_number FROM purchases WHERE id=?', (it.get('purchase_id'),)).fetchone()
                    if pur:
                        rn = pur['req_number']
                if rn:
                    affected.add(rn)
            for rn in affected:
                recompute_request_status(conn, rn)
            migrated += 1
        set_setting(conn, 'migrated_manual_receipts_v1', True)
        conn.commit()
        if migrated:
            safe_print(f'{migrated} رسید دستی قدیمی به برگه ارسال منتقل و اعمال شد')
    finally:
        conn.close()


if __name__ == '__main__':
    db.init_db()
    db.seed_if_empty()
    migrate_manual_receipts_to_shippings()
    port = 8765
    server = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    safe_print(f'Server running on port {port} (SQLite: {db.DB_FILE})')
    server.serve_forever()


