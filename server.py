#!/usr/bin/env python3
import json, os, hashlib, datetime, shutil, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote

import db

BASE = os.path.dirname(os.path.abspath(__file__))
HTML_FILE = os.path.join(BASE, 'index.html')
BACKUP_DIR = os.path.join(BASE, 'backups')

import secrets, threading, time

# ═══════════════════════════════════════════════════════════════════
# [v124] امن‌سازی رمز عبور
# مشکل قبلی: sha256 بدون نمک. رمزهای ۴ رقمی در کمتر از یک ثانیه شکسته
# می‌شدند (۱۰ رمز از ۱۳ کاربر با آزمودن ۱۱ هزار حالت پیدا شد).
# راه‌حل: PBKDF2-HMAC-SHA256 با نمک تصادفی و ۲۰۰٬۰۰۰ تکرار.
# مهاجرت نرم: هش قدیمی همچنان پذیرفته می‌شود و در اولین ورود موفق
# خودکار به فرمت جدید ارتقا می‌یابد؛ هیچ کاربری بیرون نمی‌ماند.
# ═══════════════════════════════════════════════════════════════════
PBKDF2_ROUNDS = 200_000

def h(p):
    """هش قدیمی — فقط برای تشخیص و مهاجرت رمزهای پیشین نگه داشته شده."""
    return hashlib.sha256(p.encode()).hexdigest()

def hash_password(p):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', p.encode(), salt.encode(), PBKDF2_ROUNDS)
    return f'pbkdf2${PBKDF2_ROUNDS}${salt}${dk.hex()}'

def verify_password(p, stored):
    """هر دو فرمت را می‌پذیرد. برمی‌گرداند: (درست بود؟, نیاز به ارتقا دارد؟)"""
    if not stored:
        return False, False
    if stored.startswith('pbkdf2$'):
        try:
            _, rounds, salt, want = stored.split('$', 3)
            dk = hashlib.pbkdf2_hmac('sha256', p.encode(), salt.encode(), int(rounds))
            return secrets.compare_digest(dk.hex(), want), False
        except (ValueError, TypeError):
            return False, False
    # فرمت قدیمی sha256 — اگر درست بود، باید ارتقا یابد
    return secrets.compare_digest(h(p), stored), secrets.compare_digest(h(p), stored)

# ── قانون رمز قوی ──────────────────────────────────────────────────
PASSWORD_MIN_LEN = 8
COMMON_PASSWORDS = {
    '12345678','123456789','1234567890','password','password1','qwerty','qwertyui',
    'abc12345','11111111','00000000','iloveyou','admin123','root1234','welcome1',
    'passw0rd','sunshine','princess','football','baseball','superman','trustno1',
    'mehr1234','12341234','asdfasdf','zxcvbnm1','qazwsxedc','1q2w3e4r','1qaz2wsx',
}

def password_problems(pw, username=''):
    """فهرست ایرادهای رمز را برمی‌گرداند. لیست خالی یعنی رمز قابل قبول است."""
    pw = (pw or '')
    bad = []
    if len(pw) < PASSWORD_MIN_LEN:
        bad.append(f'رمز باید حداقل {PASSWORD_MIN_LEN} کاراکتر باشد (الان {len(pw)} کاراکتر است)')
    if pw.isdigit():
        bad.append('رمز نباید فقط عدد باشد — حداقل یک حرف انگلیسی اضافه کنید')
    if pw.isalpha():
        bad.append('رمز نباید فقط حرف باشد — حداقل یک عدد اضافه کنید')
    if not re.search(r'[A-Za-z\u0600-\u06FF]', pw):
        bad.append('رمز باید حداقل یک حرف داشته باشد')
    if not re.search(r'\d', pw):
        bad.append('رمز باید حداقل یک عدد داشته باشد')
    if pw.lower() in COMMON_PASSWORDS:
        bad.append('این رمز بسیار رایج است و به‌راحتی حدس زده می‌شود')
    if len(set(pw)) <= 2 and pw:
        bad.append('رمز نباید از تکرار یک یا دو کاراکتر ساخته شود')
    if re.search(r'(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)', pw.lower()):
        bad.append('رمز نباید شامل دنباله‌های پشت‌سرهم مثل ۱۲۳۴ یا abcd باشد')
    if username and len(username) >= 3 and username.lower() in pw.lower():
        bad.append('رمز نباید شامل نام کاربری باشد')
    return bad

def password_is_weak_legacy(stored):
    """آیا رمز ذخیره‌شده هنوز با فرمت ناامن قدیمی است؟ (برای نشان دادن هشدار)"""
    return bool(stored) and not str(stored).startswith('pbkdf2$')

# ── محدودیت تلاش ورود ──────────────────────────────────────────────
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 300
_login_attempts = {}
_login_lock = threading.Lock()

def login_locked_for(username):
    """اگر حساب قفل است، ثانیه‌های باقی‌مانده را برمی‌گرداند، وگرنه صفر."""
    with _login_lock:
        rec = _login_attempts.get(username)
        if not rec:
            return 0
        count, until = rec
        if until and until > time.time():
            return int(until - time.time())
        if until and until <= time.time():
            _login_attempts.pop(username, None)
        return 0

def login_note_failure(username):
    with _login_lock:
        count, _ = _login_attempts.get(username, (0, 0))
        count += 1
        until = time.time() + LOGIN_LOCK_SECONDS if count >= LOGIN_MAX_ATTEMPTS else 0
        _login_attempts[username] = (count, until)
        return LOGIN_MAX_ATTEMPTS - count

def login_note_success(username):
    with _login_lock:
        _login_attempts.pop(username, None)

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
    # [v131] تجمیع مدارک مالی: دارندهٔ این مجوز همهٔ اسناد «تحویل مدارک به
    # مالی» را می‌بیند تا بتواند آن‌ها را یک‌جا به واحد مالی تحویل دهد،
    # بدون اینکه به بقیهٔ داده‌های مالی دیگران دسترسی پیدا کند.
    'invoice_docs_view_all',
    # [v140] ثبت/ویرایش/حذف اسناد تحویل مدارک. پیش از این هیچ مجوزی نداشت و
    # هر کاربر واردشده‌ای می‌توانست سند مالی بسازد، تغییر دهد و حذف کند.
    'invoice_docs_edit',
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
    # [v115] تفکیک «صورت تنخواه» از «شارژ تنخواه»:
    # صورت تنخواه = فهرست هزینه‌هایی که کارشناس ثبت می‌کند
    # شارژ تنخواه = واریز پول به حساب تنخواه‌دار (عملیات مالی، فقط مدیر صندوق)
    # پیش از این هر دو با یک مجوز کنترل می‌شدند و قابل تفکیک نبودند.
    'create_petty_statement','edit_petty_statement','delete_petty_statement',
    # ماژول فروش
    'page_sales','create_sale','edit_sale','delete_sale','register_sale_return',
    # [v136] چهار مجوز «شبح»: در رابط کاربری استفاده می‌شدند ولی در این فهرست
    # نبودند، پس هرگز قابل اعطا نبودند و صفحهٔ دسترسی نمی‌توانست آن‌ها را
    # ذخیره کند. حالا واقعی شدند.
    'page_audit_log','page_data_health','manage_items','issue_statement_cover',
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
    'items':'items',
    # [v125] بایگانی تاریخی عدم تحقق.
    # این رکوردها پیش‌تر در PRELOADED_NF_DATA داخل index.html سخت‌کد بودند و
    # چون در دیتابیس نبودند، حذفشان بی‌اثر بود و هر بار دوباره تزریق می‌شدند.
    # روی purchase_items نمی‌نشینند: ۴۳ مورد از ۵۴ درخواست متناظر ندارند و
    # nf_qty متن آزاد است («۴۰۰کیلو»، «کل درخواست»)، نه عدد.
    'nf_records':'nf_records'
}

# ───────────────────────────────────────────────────────────────────────────
# مجوزهای هم‌ارز
#
# در صفحه‌ی کاربران فقط ۱۹ مجوز از ۶۷ مجوز برچسب فارسی دارند و قابل تیک‌زدن‌اند.
# مثلاً «مدیریت تنخواه» نمایش داده می‌شود ولی «ثبت صورت تنخواه» نه — در نتیجه
# کاربری که مجوز مدیریت دارد، نمی‌توانست رکورد جدید ثبت کند و راهی هم برای
# فعال‌کردن آن وجود نداشت.
#
# این نگاشت می‌گوید: اگر کاربر مجوز سمت راست را دارد، مجوز سمت چپ هم برایش
# مجاز است. این یک راه‌حل موقت تا زمانی است که صفحه‌ی کاربران همه‌ی مجوزها را
# نمایش دهد.
PERM_EQUIVALENT = {
    # شارژ تنخواه (واریز پول) — عملیات مالی حساس.
    # هیچ مجوز هم‌ارزی ندارد: باید صریحاً تیک بخورد.
    'create_petty_charge': (),
    'edit_petty_charge':   (),
    'delete_petty_charge': (),
    # صورت تنخواه (ثبت هزینه‌ها) — کارشناسان. مجوزهای قدیمی همچنان معتبرند
    # تا هیچ کاربری پس از به‌روزرسانی دسترسی از دست ندهد.
    'create_petty_statement': ('manage_petty_cash', 'edit_petty_statement',
                               'create_petty_charge', 'edit_petty_charge'),
    'edit_petty_statement':   ('manage_petty_cash', 'edit_petty_charge'),
    'delete_petty_statement': ('manage_petty_cash', 'delete_petty_charge'),
    'create_contract':     ('manage_contracts', 'edit_contract'),
    'edit_contract':       ('manage_contracts',),
    'delete_contract':     ('manage_contracts',),
    'create_supply_plan':  ('manage_supply_plan', 'edit_supply_plan'),
    'edit_supply_plan':    ('manage_supply_plan',),
    'delete_supply_plan':  ('manage_supply_plan',),
    'create_supplier':     ('manage_suppliers', 'edit_supplier'),
    'edit_supplier':       ('manage_suppliers',),
    'delete_supplier':     ('manage_suppliers',),
}

# کلیدهای عمومی تنظیمات که فرانت‌اند از طریق POST /api/settings/<key> می‌فرستد.
# پیش از این، این کلیدها در handle_settings_post به هیچ شاخه‌ای نمی‌خوردند و بی‌صدا
# دور ریخته می‌شدند (در حالی که سرور ok:True برمی‌گرداند). همین باعث شد فرانت‌اند
# مجبور شود آن‌ها را در localStorage یا در فیلد address یک تامین‌کننده‌ی ساختگی نگه دارد.
GENERIC_SETTING_KEYS = {
    'purchase_overrides', 'opening_balances', 'hidden_experts',
    'sticky_notes', 'supplier_categories', 'deleted_suppliers',
    'dismissed_nfs', 'supplier_rename_map', 'saved_views',
    'inquiry_three_page',   # [v125]
}

# همه‌ی کلیدهایی که نوشتن‌شان در جدول settings مجاز است (برای ذخیره‌ی یکجا)
ALLOWED_SETTING_KEYS = GENERIC_SETTING_KEYS | {
    'signature_b64', 'approver_signature_b64', 'vat_rate',
    'petty_tracking', 'dash_labels', 'nf_descriptions', 'mrp_plan', 'petty_fund',
    # [v125] «استعلام سه برگی» پیش‌تر هیچ مسیر ذخیره واقعی نداشت و تنها راه
    # ماندگاری‌اش هک tunnelSave بود (ذخیره داخل فیلد آدرس یک تامین‌کننده ساختگی).
    'inquiry_three_page',
}

# ───────────────────────────────────────────────────────────────────────────
# تنخواه: فیلدهای هر نقش در «واریز تنخواه» (مطابق trackCanEdit در فرانت‌اند)
# پیش از این، این سه مجوز فقط در مرورگر بررسی می‌شدند و سرور هیچ کنترلی نداشت؛
# یعنی کاربر بدون مجوز می‌توانست از راه API همان فیلدها را تغییر دهد.
PETTY_DEPOSIT_FIELD_PERM = {
    # نقش مالی: مبلغ و تاریخ واریز و مبلغ مدارک
    'petty_deposit_finance':  ['amount', 'date', 'to_fund_amount', 'allocations',
                               'doc_amount', 'deposit_date', 'fund_manager'],
    # نقش تحویل: تاریخ تحویل مدارک
    'petty_deposit_delivery': ['delivery_date', 'docs_delivered_date', 'delivered_at'],
    # نقش بررسی: علت مغایرت و نتیجه بررسی
    'petty_deposit_review':   ['review_note', 'review_result', 'discrepancy_reason',
                               'reviewed_by', 'reviewed_at'],
}

# مالکیت رکوردهای تنخواه برای دامنه‌ی دید «فقط خودش»
PETTY_OWNER_FIELDS = ('holder', 'expert', 'created_by')

KNOWN_REQUEST = {'id','req_number','expert','req_date','status','created_by','created_at','imported','_actor'}
KNOWN_PURCHASE = {'id','req_number','expert','supplier','supplier_id','date','is_contract','no_request',
                  'line_items','created_at','imported','paid_amount','remaining_amount','due_date',
                  'payment_method','financial_status','closed','close_reason','closed_by','closed_at','_actor'}
KNOWN_LINEITEM = {'line_id','item_code','item_name','qty','unit','unit_price','shipped_qty','ship_status',
                  'nf_qty','nf_reason','no_fulfill','price_pending','no_delivery_needed'}
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
    # [v142.6] فیلد جدید: قلم بدون نیاز به تحویل انبار (خدمات، هزینه‌ها، ...)
    li['no_delivery_needed'] = bool(d.get('no_delivery_needed'))
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

# ───────────────────────────────────────────────────────────────────────────
# [v118] هیچ تأمین‌کننده‌ای محافظت‌شده نیست — همه مثل هم قابل حذف‌اند.
# فقط رکوردهای داخلی خودِ سیستم (که تأمین‌کننده نیستند) استثنا می‌مانند.
PROTECTED_SUPPLIER_PREFIXES = (
    'سیستم بازرگانی',  # رکوردهای داخلی سیستم، نه تأمین‌کننده واقعی
)


def is_protected_supplier(name):
    """فقط رکوردهای داخلی سیستم. سرفصل‌های هزینه مثل بقیه قابل حذف‌اند."""
    n = _norm_sup_name(name)
    return any(n.startswith(p) for p in PROTECTED_SUPPLIER_PREFIXES)


def supplier_usage_count(conn, sup_id, sup_name):
    """چند رکورد به این تأمین‌کننده وصل است؟ (خرید، پرداخت، ارسال، اسناد)"""
    n = 0
    n += conn.execute('SELECT COUNT(*) FROM purchases WHERE supplier_id=? OR supplier=?',
                      (sup_id, sup_name)).fetchone()[0]
    n += conn.execute('SELECT COUNT(*) FROM supplier_payments WHERE supplier_id=? OR supplier=?',
                      (sup_id, sup_name)).fetchone()[0]
    n += conn.execute('SELECT COUNT(*) FROM shipping_items WHERE supplier=?',
                      (sup_name,)).fetchone()[0]
    for coll in ('contracts', 'invoice_docs', 'contract_payments', 'manual_receipts'):
        for r in conn.execute('SELECT data FROM docs WHERE collection=?', (coll,)):
            try:
                d = json.loads(r[0])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(d, dict):
                continue
            for f in ('supplier', 'party', 'seller', 'vendor'):
                if _norm_sup_name(d.get(f)) == _norm_sup_name(sup_name):
                    n += 1
                    break
    return n


FINANCIAL_FIELDS = ('unit_price', 'total', 'invoice_amount', 'paid', 'paid_amount',
                    'remaining_amount', 'vat', 'discount', 'amount', 'payments',
                    'financial_status', 'due_date', 'payment_method', 'paid_date')


def strip_financial_fields(rec):
    """[v120] حذف اعداد مالی از یک رکورد، برای کاربری که مجوز مالی ندارد.
    خودِ رکورد (شماره درخواست، کالا، تعداد) می‌ماند تا کار عملیاتی مختل نشود."""
    if not isinstance(rec, dict):
        return rec
    out = dict(rec)
    for f in FINANCIAL_FIELDS:
        if f in out:
            out[f] = None
    for li in (out.get('line_items') or []):
        if isinstance(li, dict):
            for f in FINANCIAL_FIELDS:
                if f in li:
                    li[f] = None
    return out


def supplier_row_to_dict(row):
    d = dict(row)
    d['is_active'] = bool(d.get('is_active', 1))
    return d

# ═══════════════════════════════════════════════════════════════════
# [v124] پشتیبان‌گیری خودکار
# مشکل قبلی: روت /api/backup فقط با فشردن دکمه اجرا می‌شد و هیچ
# زمان‌بندی‌ای نداشت. پوشه backups هرگز ساخته نشده بود، یعنی در تمام
# عمر سیستم حتی یک پشتیبان هم گرفته نشده بود.
# ═══════════════════════════════════════════════════════════════════
BACKUP_EVERY_HOURS = 6
BACKUP_KEEP_RECENT = 12    # ۱۲ نسخه آخر همیشه دست‌نخورده (شامل چند نسخه در یک روز)
BACKUP_KEEP_DAILY = 7      # سپس یک نسخه برای هر روز، ۷ روز اخیر
BACKUP_KEEP_WEEKLY = 4     # سپس یک نسخه برای هر هفته، ۴ هفته
_backup_lock = threading.Lock()

def _backup_prune():
    """نگه‌داری هوشمند بدون از دست دادن نسخه‌های تازه.
    ابتدا ۱۲ نسخه آخر بی‌قیدوشرط نگه داشته می‌شوند (تا چند پشتیبان در یک
    روز — مثلاً قبل از عملیات خطرناک — حفظ شود)، سپس یک نسخه برای هر روز
    و یک نسخه برای هر هفته قدیمی‌تر."""
    try:
        files = sorted(f for f in os.listdir(BACKUP_DIR)
                       if f.startswith('mehr_') and f.endswith('.db'))
    except OSError:
        return
    keep = set(files[-BACKUP_KEEP_RECENT:])            # تازه‌ترین‌ها همیشه می‌مانند
    by_day, by_week = {}, {}
    for f in files:
        try:
            dt = datetime.datetime.strptime(f[5:20], '%Y%m%d_%H%M%S')
        except ValueError:
            keep.add(f); continue
        by_day[dt.strftime('%Y%m%d')] = f              # آخرین نسخه هر روز
        by_week[dt.strftime('%Y-W%W')] = f             # آخرین نسخه هر هفته
    keep |= set(sorted(by_day.values())[-BACKUP_KEEP_DAILY:])
    keep |= set(sorted(by_week.values())[-BACKUP_KEEP_WEEKLY:])
    for f in files:
        if f not in keep:
            try: os.remove(os.path.join(BACKUP_DIR, f))
            except OSError: pass

def make_backup(reason='خودکار', actor=None):
    """یک نسخه پشتیبان می‌سازد و سلامت آن را بررسی می‌کند."""
    import sqlite3 as _sqlite3
    with _backup_lock:
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            dest = os.path.join(BACKUP_DIR, f'mehr_{ts}.db')
            src = db.get_conn()
            try:
                with _sqlite3.connect(dest) as bconn:
                    src.backup(bconn)
            finally:
                src.close()
            # بررسی سلامت: پشتیبان خرابْ بدتر از نداشتن پشتیبان است
            chk = _sqlite3.connect(dest)
            try:
                integrity = chk.execute('PRAGMA integrity_check').fetchone()[0]
                nrec = chk.execute('SELECT COUNT(*) FROM purchases').fetchone()[0]
            finally:
                chk.close()
            if integrity != 'ok':
                os.remove(dest)
                return {'ok': False, 'error': f'پشتیبان سالم نبود: {integrity}'}
            _backup_prune()
            size = os.path.getsize(dest)
            safe_print(f'پشتیبان گرفته شد: {os.path.basename(dest)} '
                       f'({size/1048576:.1f} مگابایت، {nrec} خرید) — {reason}')
            return {'ok': True, 'file': os.path.basename(dest), 'size': size,
                    'purchases': nrec, 'reason': reason,
                    'created_at': datetime.datetime.now().isoformat()}
        except Exception as e:
            safe_print(f'خطا در پشتیبان‌گیری: {e}')
            return {'ok': False, 'error': str(e)}

def backup_list():
    """فهرست نسخه‌های موجود، تازه‌ترین اول."""
    out = []
    try:
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if not (f.startswith('mehr_') and f.endswith('.db')):
                continue
            full = os.path.join(BACKUP_DIR, f)
            try:
                dt = datetime.datetime.strptime(f[5:20], '%Y%m%d_%H%M%S').isoformat()
            except ValueError:
                dt = ''
            out.append({'file': f, 'size': os.path.getsize(full), 'created_at': dt})
    except OSError:
        pass
    return out

def _backup_scheduler():
    """هر BACKUP_EVERY_HOURS ساعت یک پشتیبان خودکار می‌گیرد."""
    def tick():
        while True:
            time.sleep(BACKUP_EVERY_HOURS * 3600)
            try:
                make_backup(reason='خودکار زمان‌بندی‌شده')
            except Exception as e:
                safe_print(f'خطای زمان‌بند پشتیبان: {e}')
    t = threading.Thread(target=tick, daemon=True)
    t.start()


# ═══════════════════════════════════════════════════════════════════
# [v124] سطل بازیافت
# یافته مهم: log_audit از قبل عکس کامل رکورد را در before_json ذخیره
# می‌کرده. ۱۹۶۳ حذف از ۱۹۶۴ نسخه کامل دارند و هیچ شناسه‌ای دوباره
# اشغال نشده. پس نیازی به تغییر ساختار جدول‌ها نیست — فقط باید
# راه بازگرداندن ساخته شود.
# ═══════════════════════════════════════════════════════════════════
TRASH_DAYS = 30
RESTORABLE = {
    'purchases':  ('purchases',  'خرید'),
    'requests':   ('requests',   'درخواست'),
    'petty_cash': (None,         'تنخواه'),
    'petty_charges': (None,      'شارژ تنخواه'),
    'supply_plans': (None,       'برنامه تامین'),
}
# ارسال‌ها عمداً اینجا نیستند: بازگرداندن یک ارسال باید تعداد ارسال‌شده
# اقلام را هم برگرداند، وگرنه آمار خراب می‌شود. نیازمند بررسی دستی.
NOT_RESTORABLE_NOTE = {
    'shippings': 'بازگرداندن ارسال روی موجودی و آمار اقلام اثر می‌گذارد و باید دستی بررسی شود',
    'users': 'بازگرداندن کاربر به‌دلیل مسائل امنیتی دستی انجام می‌شود',
}

def trash_list(conn, days=TRASH_DAYS):
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()
    rows = conn.execute(
        "SELECT id, ts, actor, entity, entity_id, before_json, note FROM audit_log "
        "WHERE action='delete' AND ts > ? AND before_json IS NOT NULL AND before_json <> '' "
        "ORDER BY id DESC LIMIT 500", (cutoff,)).fetchall()
    out = []
    for r in rows:
        try:
            data = json.loads(r['before_json'])
        except (ValueError, TypeError):
            continue
        ent = r['entity']
        # آیا شناسه دوباره اشغال شده؟
        occupied = False
        tbl = RESTORABLE.get(ent, (None, None))[0]
        if tbl:
            occupied = conn.execute(f'SELECT 1 FROM {tbl} WHERE id=?', (r['entity_id'],)).fetchone() is not None
        elif ent in ('petty_cash', 'petty_charges', 'supply_plans'):
            occupied = conn.execute('SELECT 1 FROM docs WHERE collection=? AND id=?',
                                    (ent, r['entity_id'])).fetchone() is not None
        label = data.get('req_number') or data.get('number') or data.get('name') or data.get('title') or ''
        desc = ''
        if ent == 'purchases':
            items = data.get('line_items') or []
            desc = (items[0].get('item_name', '') if items else data.get('item_name', '')) or ''
            if len(items) > 1:
                desc += f' و {len(items)-1} قلم دیگر'
        elif ent == 'requests':
            desc = data.get('expert', '')
        out.append({
            'audit_id': r['id'], 'ts': r['ts'], 'actor': r['actor'],
            'entity': ent, 'entity_fa': RESTORABLE.get(ent, (None, ent))[1],
            'entity_id': r['entity_id'], 'label': str(label), 'desc': str(desc)[:60],
            'supplier': data.get('supplier', ''), 'note': r['note'] or '',
            'restorable': ent in RESTORABLE and not occupied,
            'blocked_reason': (NOT_RESTORABLE_NOTE.get(ent) if ent not in RESTORABLE
                               else ('این شناسه دوباره استفاده شده است' if occupied else '')),
        })
    return out

def _row_from_snapshot(conn, table, data):
    """فقط کلیدهایی که ستون واقعی جدول‌اند؛ بقیه به extra_json می‌روند."""
    cols = [c[1] for c in conn.execute(f'PRAGMA table_info({table})')]
    row, extra = {}, {}
    for k, v in data.items():
        if k == 'extra_json':
            continue
        if k in cols:
            row[k] = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
        elif k not in ('line_items', 'items'):
            extra[k] = v
    if 'extra_json' in cols:
        row['extra_json'] = json.dumps(extra, ensure_ascii=False)
    return row

def trash_restore(conn, audit_id, actor):
    rec = conn.execute("SELECT * FROM audit_log WHERE id=? AND action='delete'", (audit_id,)).fetchone()
    if not rec:
        return {'ok': False, 'error': 'این رکورد در سطل بازیافت پیدا نشد'}
    ent, rid = rec['entity'], rec['entity_id']
    if ent not in RESTORABLE:
        return {'ok': False, 'error': NOT_RESTORABLE_NOTE.get(ent, 'این نوع رکورد قابل بازگرداندن خودکار نیست')}
    try:
        data = json.loads(rec['before_json'] or '{}')
    except (ValueError, TypeError):
        return {'ok': False, 'error': 'نسخه پشتیبان این رکورد سالم نیست'}
    if not data:
        return {'ok': False, 'error': 'نسخه پشتیبان این رکورد خالی است'}

    tbl = RESTORABLE[ent][0]
    # نگهبان: هرگز روی رکورد موجود بازنویسی نکن
    if tbl:
        if conn.execute(f'SELECT 1 FROM {tbl} WHERE id=?', (rid,)).fetchone():
            return {'ok': False, 'error': f'شناسه {rid} دوباره استفاده شده — بازگرداندن انجام نشد'}
    else:
        if conn.execute('SELECT 1 FROM docs WHERE collection=? AND id=?', (ent, rid)).fetchone():
            return {'ok': False, 'error': f'شناسه {rid} دوباره استفاده شده — بازگرداندن انجام نشد'}

    make_backup(reason=f'قبل از بازگرداندن {ent}/{rid}', actor=actor)
    try:
        conn.execute('BEGIN')
        if tbl is None:
            conn.execute('INSERT INTO docs (collection, id, data, created_at) VALUES (?,?,?,?)',
                         (ent, rid, json.dumps(data, ensure_ascii=False), now_iso()))
        else:
            row = _row_from_snapshot(conn, tbl, data)
            cols = ','.join(row.keys())
            conn.execute(f"INSERT INTO {tbl} ({cols}) VALUES ({','.join('?' * len(row))})",
                         list(row.values()))
            if tbl == 'purchases':
                for li in (data.get('line_items') or []):
                    li = dict(li); li['purchase_id'] = rid; li.pop('id', None)
                    lrow = _row_from_snapshot(conn, 'purchase_items', li)
                    lcols = ','.join(lrow.keys())
                    conn.execute(f"INSERT INTO purchase_items ({lcols}) VALUES ({','.join('?' * len(lrow))})",
                                 list(lrow.values()))
        db.log_audit(conn, actor, 'restore', ent, rid, after=data,
                     note=f'بازگردانی از سطل بازیافت (حذف‌شده در {rec["ts"][:16]} توسط {rec["actor"]})')
        conn.commit()
    except Exception as e:
        conn.rollback()
        return {'ok': False, 'error': f'بازگرداندن ناموفق بود: {e}'}
    if ent == 'purchases' and data.get('req_number'):
        try:
            recompute_request_status(conn, data['req_number']); conn.commit()
        except Exception:
            pass
    return {'ok': True, 'entity': ent, 'id': rid,
            'items': len(data.get('line_items') or []) if ent == 'purchases' else 0}


# ═══════════════════════════════════════════════════════════════════
# [v126] تشخیص ثبت تکراری خرید
#
# چرا لازم است: سیستم هیچ کنترلی روی ثبت دوباره نداشت. اگر کاربر روی
# دکمه ذخیره دوبار می‌زد، یا صفحه را رفرش و دوباره ثبت می‌کرد، یا
# اینترنت کند بود و فکر می‌کرد ثبت نشده، رکورد دوم ساخته می‌شد.
# نتیجه: ۱۵ گروه تکراری با ۱۸ رکورد اضافه و حدود ۲۱ میلیارد ریال
# اضافه‌شمارش در گزارش‌های پارتو و مالی.
#
# قانون: همان شماره درخواست + همان کد کالا + همان نام کالا = تکراری.
# تامین‌کننده عمداً در کلید نیست؛ یک قلم از یک درخواست نباید دو بار
# ثبت شود حتی اگر نام تامین‌کننده کمی متفاوت تایپ شده باشد.
# ═══════════════════════════════════════════════════════════════════
def _norm_item_text(s):
    s = (s or '').replace('ي', 'ی').replace('ك', 'ک').replace('\u200c', '')
    return ' '.join(str(s).split()).strip().lower()

def find_duplicate_purchase(conn, purchase, line_items):
    """اگر این خرید تکراری باشد، توضیح فارسی برمی‌گرداند؛ وگرنه None."""
    req = str(purchase.get('req_number') or '').strip()
    if not req:
        return None      # خرید بدون شماره درخواست (هزینه متفرقه) کنترل نمی‌شود
    incoming = []
    for it in (line_items or []):
        code = str(it.get('item_code') or '').strip()
        name = _norm_item_text(it.get('item_name'))
        if code or name:
            incoming.append((code, name, it))
    if not incoming:
        return None
    rows = conn.execute(
        '''SELECT p.id, p.supplier, p.created_at, pi.item_code, pi.item_name,
                  pi.qty, pi.unit_price
           FROM purchases p JOIN purchase_items pi ON pi.purchase_id = p.id
           WHERE p.req_number = ?''', (req,)).fetchall()
    if not rows:
        return None
    index = {}
    for r in rows:
        index.setdefault((str(r['item_code'] or '').strip(),
                          _norm_item_text(r['item_name'])), r)
    for code, name, it in incoming:
        hit = index.get((code, name))
        if hit is None:
            continue
        try:
            same_qty = float(str(it.get('qty') or 0).replace(',', '') or 0) == \
                       float(str(hit['qty'] or 0).replace(',', '') or 0)
        except (TypeError, ValueError):
            same_qty = False
        when = str(hit['created_at'] or '')[:16].replace('T', ' ')
        # [v142.7] پیام هشدار غنی‌تر شد: نام تامین‌کننده قبلی و جدید و مقایسه قیمت
        prev_sup = str(hit['supplier'] or '—')
        new_sup = str(it.get('supplier') or purchase.get('supplier') or '—')
        different_sup = _norm_sup_name(prev_sup) != _norm_sup_name(new_sup)
        detail = (f"کالای «{hit['item_name']}» برای درخواست {req} پیش‌تر در "
                  f"خرید شماره {hit['id']} از تامین‌کننده «{prev_sup}» ثبت شده است"
                  + (f" (تاریخ ثبت: {when})" if when else '') + '.')
        if different_sup:
            detail += f'\n⚠️ تامین‌کننده جدید متفاوت است: «{new_sup}» — احتمال دوباره‌کاری.'
        if same_qty:
            detail += ' تعداد هر دو یکسان است.'
        else:
            detail += f" تعداد قبلی: {hit['qty']} — تعداد جدید: {it.get('qty')}."
        # مقایسه قیمت (اگر هر دو داشته باشند)
        try:
            prev_price = float(str(hit['unit_price'] or 0).replace(',','') or 0)
            new_price = float(str(it.get('unit_price') or 0).replace(',','') or 0)
            if prev_price > 0 and new_price > 0 and prev_price != new_price:
                diff_pct = round((new_price - prev_price) / prev_price * 100, 1)
                arrow = '⬆️' if diff_pct > 0 else '⬇️'
                detail += f" فی قبلی: {int(prev_price):,} — فی جدید: {int(new_price):,} ({arrow} {abs(diff_pct)}%)."
        except (TypeError, ValueError):
            pass
        return {'id': hit['id'],
                'message': 'این قلم قبلاً برای همین درخواست ثبت شده است' + (' — با تامین‌کننده متفاوت' if different_sup else ''),
                'detail': detail}
    return None


def user_public_dict(row):
    d = dict(row)
    return {
        'id': d['id'], 'name': d['name'], 'role': d['role'], 'title': d.get('title', ''),
        'perms': json.loads(d.get('perms_json') or '{}'),
        'perm_log': json.loads(d.get('perm_log_json') or '[]'),
        'is_expert_listed': bool(d.get('is_expert_listed', 1)),
        'fiscal_year': d.get('fiscal_year', ''),
        'unit': d.get('unit', 'بازرگانی و پشتیبانی'),
        # [v124] هشدار رمز ناامن قدیمی — برای نشان دادن نشان قرمز در صفحه کاربران
        'password_legacy': password_is_weak_legacy(d.get('password'))
    }


# [v136] نسخهٔ سبک برای کاربران عادی: فقط چیزی که رابط کاربری واقعاً لازم دارد
def user_listing_dict(row):
    d = dict(row)
    return {
        'id': d['id'], 'name': d['name'], 'role': d['role'], 'title': d.get('title', ''),
        'is_expert_listed': bool(d.get('is_expert_listed', 1)),
        'unit': d.get('unit', 'بازرگانی و پشتیبانی'),
        'fiscal_year': d.get('fiscal_year', ''),
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

def resolve_or_create_supplier(conn, name, actor=None, revive=False):
    """شناسه تأمین‌کننده را برمی‌گرداند؛ اگر نبود می‌سازد.

    [v118] اگر رکورد وجود دارد ولی غیرفعال شده (یعنی کاربر آن را حذف کرده)،
    به‌طور پیش‌فرض دوباره فعال نمی‌شود. پیش از این هر ذخیره‌ی خرید، نام
    حذف‌شده را دوباره زنده می‌کرد و کاربر می‌دید نامی که پاک کرده برگشته.
    revive=True فقط جایی استفاده می‌شود که کاربر صریحاً نام را وارد کرده باشد.
    """
    name = (name or '').strip()
    if not name:
        return None
    row = conn.execute('SELECT id, is_active FROM suppliers WHERE name=?', (name,)).fetchone()
    if row:
        if revive and not row['is_active']:
            conn.execute('UPDATE suppliers SET is_active=1, updated_at=? WHERE id=?',
                         (now_iso(), row['id']))
            db.log_audit(conn, actor, 'reactivate', 'suppliers', row['id'],
                         note='دوباره فعال شد چون کاربر آن را در فرم وارد کرد')
            conn.commit()
        return row['id']
    cur = conn.execute('INSERT INTO suppliers (name, is_active, created_at, updated_at) VALUES (?,1,?,?)',
                        (name, now_iso(), now_iso()))
    db.log_audit(conn, actor, 'create', 'suppliers', cur.lastrowid, after={'name': name})
    conn.commit()
    return cur.lastrowid

# ---------------------------------------------------------------------------
# ادغام واقعی تامین‌کنندگان (یک تراکنش واحد)
#
# پیش از این، ادغام در فرانت‌اند با ۱۰ درخواست جداگانه انجام می‌شد که برخی‌شان
# روت نداشتند (۴۰۴) و خطایشان بی‌صدا بلعیده می‌شد؛ نتیجه این بود که ادغام فقط
# در حافظه‌ی مرورگر می‌ماند و با اولین loadAll() نام‌های قدیمی برمی‌گشتند.
# اینجا ادغام در خودِ داده ثبت می‌شود، پس دیگر برنمی‌گردد.
# ---------------------------------------------------------------------------

def _norm_sup_name(s):
    """نرمال‌سازی نام برای مقایسه: یکسان‌سازی ی/ک، حذف نیم‌فاصله و فاصله‌های اضافه."""
    s = (s or '').strip()
    s = s.replace('ي', 'ی').replace('ك', 'ک').replace('ۀ', 'ه').replace('ة', 'ه')
    s = s.replace('\u200c', ' ').replace('\u200f', ' ').replace('\u200e', ' ')
    return re.sub(r'\s+', ' ', s).strip()


def merge_suppliers_tx(conn, target, aliases, actor=None, dry_run=False):
    """همه‌ی ارجاع‌های aliases را به target تغییر می‌دهد.
    dry_run=True فقط شمارش می‌کند و چیزی را تغییر نمی‌دهد (برای پیش‌نمایش).
    خروجی: دیکشنری شمارش تغییرات به تفکیک بخش.
    """
    target = _norm_sup_name(target)
    alias_set = {_norm_sup_name(a) for a in (aliases or [])}
    alias_set.discard(target)
    alias_set.discard('')
    alias_set.discard('—')
    if not target or target == '—' or not alias_set:
        return {'error': 'نام مقصد یا فهرست ادغام نامعتبر است'}

    stats = {'purchases': 0, 'purchase_items': 0, 'shipping_items': 0,
             'supplier_payments': 0, 'docs': 0, 'suppliers_removed': 0,
             'target': target, 'aliases': sorted(alias_set)}

    def matches(v):
        return _norm_sup_name(v) in alias_set

    # اطمینان از وجود رکورد مقصد
    trow = conn.execute('SELECT id FROM suppliers WHERE name=?', (target,)).fetchone()
    if not trow and not dry_run:
        cur = conn.execute(
            'INSERT INTO suppliers (name, is_active, created_at, updated_at) VALUES (?,1,?,?)',
            (target, now_iso(), now_iso()))
        target_id = cur.lastrowid
    else:
        target_id = trow['id'] if trow else None

    # ۱) purchases: هم ستون متنی، هم کلید عددی
    for r in conn.execute('SELECT id, supplier FROM purchases').fetchall():
        if matches(r['supplier']):
            stats['purchases'] += 1
            if not dry_run:
                conn.execute('UPDATE purchases SET supplier=?, supplier_id=? WHERE id=?',
                             (target, target_id, r['id']))

    # ۲) purchase_items: نام تامین‌کننده داخل extra_json ردیف‌ها
    for r in conn.execute('SELECT id, extra_json FROM purchase_items').fetchall():
        try:
            e = json.loads(r['extra_json'] or '{}')
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(e, dict) and matches(e.get('supplier')):
            stats['purchase_items'] += 1
            if not dry_run:
                e['supplier'] = target
                conn.execute('UPDATE purchase_items SET extra_json=? WHERE id=?',
                             (json.dumps(e, ensure_ascii=False), r['id']))

    # ۳) shipping_items — این بخش را فرانت‌اند اصلاً به‌روز نمی‌کرد
    for r in conn.execute('SELECT id, supplier FROM shipping_items').fetchall():
        if matches(r['supplier']):
            stats['shipping_items'] += 1
            if not dry_run:
                conn.execute('UPDATE shipping_items SET supplier=? WHERE id=?', (target, r['id']))

    # ۴) supplier_payments
    for r in conn.execute('SELECT id, supplier FROM supplier_payments').fetchall():
        if matches(r['supplier']):
            stats['supplier_payments'] += 1
            if not dry_run:
                conn.execute('UPDATE supplier_payments SET supplier=?, supplier_id=? WHERE id=?',
                             (target, target_id, r['id']))

    # ۵) اسناد JSON: قراردادها، فاکتورها، و هر مجموعه‌ای که نام تامین‌کننده دارد
    for coll in ('contracts', 'invoice_docs', 'contract_payments', 'returns',
                 'manual_receipts', 'need_declarations'):
        for r in conn.execute('SELECT id, data FROM docs WHERE collection=?', (coll,)).fetchall():
            try:
                d = json.loads(r['data'])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(d, dict):
                continue
            changed = False
            for fld in ('supplier', 'party', 'seller', 'vendor'):
                if matches(d.get(fld)):
                    d[fld] = target
                    changed = True
            for it in (d.get('items') or []):
                if isinstance(it, dict) and matches(it.get('supplier')):
                    it['supplier'] = target
                    changed = True
            if changed:
                stats['docs'] += 1
                if not dry_run:
                    conn.execute('UPDATE docs SET data=? WHERE collection=? AND id=?',
                                 (json.dumps(d, ensure_ascii=False), coll, r['id']))

    # ۶) حذف واقعی رکوردهای تکراری (نه صرفاً غیرفعال‌سازی)
    #    سرفصل‌های هزینه هرگز حذف نمی‌شوند، حتی اگر در فهرست ادغام آمده باشند.
    for r in conn.execute('SELECT id, name FROM suppliers').fetchall():
        if is_protected_supplier(r['name']):
            continue
        if matches(r['name']) and r['id'] != target_id:
            stats['suppliers_removed'] += 1
            if not dry_run:
                conn.execute('UPDATE purchases SET supplier_id=? WHERE supplier_id=?',
                             (target_id, r['id']))
                conn.execute('UPDATE supplier_payments SET supplier_id=? WHERE supplier_id=?',
                             (target_id, r['id']))
                conn.execute('DELETE FROM suppliers WHERE id=?', (r['id'],))

    if not dry_run:
        db.log_audit(conn, actor, 'merge', 'suppliers', target_id,
                     before={'aliases': sorted(alias_set)},
                     after={'target': target, 'stats': {k: v for k, v in stats.items()
                                                        if isinstance(v, int)}},
                     note='ادغام تامین‌کننده: ' + '، '.join(sorted(alias_set)) + ' ← ' + target)
        conn.commit()
    return stats


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
        # [v142.6] no_delivery_needed هم مثل تحویل‌شده حساب می‌شود؛ اقلامی که
        # ذاتاً تحویل انبار ندارند (خدمات، هزینه‌ها) نباید مانع بسته‌شدن درخواست شوند.
        items = conn.execute(
            'SELECT qty, shipped_qty, nf_qty, no_delivery_needed FROM purchase_items WHERE purchase_id=?',
            (p['id'],)).fetchall()
        for it in items:
            if it['no_delivery_needed']:
                continue  # این قلم به‌طور خودکار تحویل‌شده حساب می‌شود
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

# [v135] تنها مسیرهای GET که بدون ورود به سیستم مجازند (صفحهٔ ورود به آن‌ها نیاز دارد)
GET_PUBLIC_PATHS = {'/api/me', '/api/ping'}

# [v142] تنها مسیرهای POST که بدون نشست مجازند: ورود، خروج، بررسی قدرت رمز.
# بقیه‌ی POST/PUT/DELETE بدون نشست معتبر ۴۰۱ می‌گیرند (لایه دوم دفاع؛
# پیش از این هر handler خودش با self.require چک می‌کرد، ولی اضافه شدن یک
# handler آینده می‌توانست بی‌سروصدا رخنه ایجاد کند).
POST_PUBLIC_PATHS = {'/api/login', '/api/logout', '/api/password/check'}

# [v135] اگر True باشد فقط رایانه‌های شبکهٔ داخلی می‌توانند وصل شوند
ALLOW_ONLY_PRIVATE = os.environ.get('ALLOW_ONLY_PRIVATE', '1') != '0'

# [v134] فقط مبدأهای محلی/شبکهٔ داخلی مجازند؛ هر سایت اینترنتی بلاک می‌شود
def is_allowed_origin(origin):
    try:
        u = urlparse(origin)
    except Exception:
        return False
    if u.scheme not in ('http', 'https'):
        return False
    h = (u.hostname or '').lower()
    if h in ('localhost', '127.0.0.1', '::1'):
        return True
    parts = h.split('.')
    if len(parts) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in parts):
        a, b = int(parts[0]), int(parts[1])
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    return False

# [v135] آیا این نشانی IP متعلق به همین رایانه یا شبکهٔ داخلی است؟
def is_private_ip(ip):
    ip = (ip or '').strip().lower()
    if ip.startswith('::ffff:'):
        ip = ip[7:]
    if ip in ('127.0.0.1', '::1', 'localhost'):
        return True
    parts = ip.split('.')
    if len(parts) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in parts):
        a, b = int(parts[0]), int(parts[1])
        if a == 127 or a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 169 and b == 254:
            return True
        return False
    return ip.startswith('fe80:') or ip.startswith('fc') or ip.startswith('fd')


# ---------------------------------------------------------------------------
# [v143] یکتایی شماره فرم عدم تحقق (سمت سرور — منبع حقیقت)
#
# قانون تاییدشده:
#   - «سطح فرم»: چند قلم داخلِ یک فرم/خرید می‌توانند یک شماره مشترک داشته باشند.
#   - دو فرم/خریدِ جدا هرگز نباید شماره‌ی یکسانی داشته باشند.
#   - سیاست «مسکوت»: شماره‌ی فرمی که هنگام ویرایش پاک/حل می‌شود، برای همیشه
#     رزرو می‌ماند (در بایگانی nf_records ثبت می‌شود) تا دوباره استفاده نشود.
# ---------------------------------------------------------------------------
def _nf_nums_of_purchase(conn, purchase_id):
    """همه‌ی شماره‌های فرم عدم تحقق یک خرید (سربرگ + قلم‌ها)."""
    nums = set()
    p = conn.execute('SELECT extra_json FROM purchases WHERE id=?', (purchase_id,)).fetchone()
    if p:
        try:
            e = json.loads(p['extra_json'] or '{}')
            for k in ('nf_number', 'form_no'):
                v = str(e.get(k, '') or '').strip()
                if v:
                    nums.add(v)
        except Exception:
            pass
    for it in conn.execute('SELECT extra_json FROM purchase_items WHERE purchase_id=?', (purchase_id,)):
        try:
            e = json.loads(it['extra_json'] or '{}')
            for k in ('nf_number', 'line_nf_number', 'form_no'):
                v = str(e.get(k, '') or '').strip()
                if v:
                    nums.add(v)
        except Exception:
            pass
    return nums


def reserved_nf_numbers(conn, exclude_purchase_id=None):
    """همه‌ی شماره‌های رزروشده: فرم‌های فعالِ سایر خریدها + بایگانی مسکوت (nf_records).

    exclude_purchase_id: هنگام ویرایش، شماره‌های همین خرید لحاظ نمی‌شوند تا چند
    قلمِ همان فرم بتوانند یک شماره داشته باشند."""
    nums = set()
    for r in conn.execute('SELECT pi.purchase_id, pi.extra_json FROM purchase_items pi'):
        if exclude_purchase_id is not None and r['purchase_id'] == exclude_purchase_id:
            continue
        try:
            e = json.loads(r['extra_json'] or '{}')
            for k in ('nf_number', 'line_nf_number', 'form_no'):
                v = str(e.get(k, '') or '').strip()
                if v:
                    nums.add(v)
        except Exception:
            pass
    for r in conn.execute('SELECT id, extra_json FROM purchases'):
        if exclude_purchase_id is not None and r['id'] == exclude_purchase_id:
            continue
        try:
            e = json.loads(r['extra_json'] or '{}')
            for k in ('nf_number', 'form_no'):
                v = str(e.get(k, '') or '').strip()
                if v:
                    nums.add(v)
        except Exception:
            pass
    for r in conn.execute("SELECT data FROM docs WHERE collection='nf_records'"):
        try:
            e = json.loads(r['data'])
            if isinstance(e, dict):
                for k in ('nf_number', 'line_nf_number', 'form_no'):
                    v = str(e.get(k, '') or '').strip()
                    if v:
                        nums.add(v)
        except Exception:
            pass
    return nums


def submitted_nf_numbers(body, line_items):
    """شماره‌های فرم عدم تحققِ درخواست در حال ثبت/ویرایش (سربرگ + قلم‌ها)."""
    nums = set()
    for k in ('nf_number', 'form_no'):
        v = str((body or {}).get(k, '') or '').strip()
        if v:
            nums.add(v)
    for it in (line_items or []):
        it = it or {}
        for k in ('nf_number', 'line_nf_number', 'form_no'):
            v = str(it.get(k, '') or '').strip()
            if v:
                nums.add(v)
    return nums


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    # [v135] درخواست از بیرون شبکهٔ داخلی اصلاً پردازش نمی‌شود
    def handle_one_request(self):
        ip = self.client_address[0] if self.client_address else ''
        if ALLOW_ONLY_PRIVATE and not is_private_ip(ip):
            try:
                self.raw_requestline = self.rfile.readline(65537)
                if not self.raw_requestline:
                    self.close_connection = True
                    return
                self.send_response(403)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', '0')
                self.end_headers()
            except Exception:
                pass
            self.close_connection = True
            return
        return BaseHTTPRequestHandler.handle_one_request(self)

    # [v134] CORS بسته شد: فقط مبدأهای شبکهٔ داخلی مجاز‌اند (نه wildcard)
    def send_security_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        origin = (self.headers.get('Origin') or '').strip()
        if not origin:
            return          # هم‌مبدأ یا ابزار داخلی: هدر CORS لازم نیست
        if is_allowed_origin(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.send_header('Vary', 'Origin')

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_security_headers()
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_security_headers()
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '600')
        self.send_header('Content-Length', '0')
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
        # [v127] پیش از این، نقش «مدیر» بدون توجه به تیک‌ها True برمی‌گرداند.
        # یعنی صفحه دسترسی برای مدیر فقط منو را مخفی می‌کرد و در سرور همه‌چیز
        # باز بود؛ هر کاربر مدیر می‌توانست از راه API هر کاری بکند.
        # حالا تیک‌ها واقعا اعمال می‌شوند. پیش از فعال‌سازی، اسکریپت
        # «تنظیم_دسترسی_مدیران.py» تیک‌های مدیران موجود را با دسترسی فعلی‌شان
        # برابر می‌کند تا کسی چیزی از دست ندهد.
        if perms.get('readonly') and perm not in ('view_financial', 'view_reports', 'export_excel', 'view_all_purchases'):
            return False
        return bool(perms.get(perm, False))

    # ── مالی: دامنه‌ی دید واقعی در سمت سرور ─────────────────────────────
    # [v120] پیش از این مجوز view_financial فقط منو را مخفی می‌کرد و همه‌ی
    # مبالغ (پرداخت‌ها، قراردادها، فاکتورها) برای هر کاربر واردشده ارسال می‌شد.
    # حالا داده‌ی مالی دیگران اصلاً از سرور خارج نمی‌شود.
    def fin_can_view(self, session_user):
        """آیا اصلاً اجازه‌ی دیدن اعداد مالی را دارد؟"""
        if session_user is None:
            return False
        if session_user['role'] == 'admin':
            return True
        return self.session_can(session_user, 'view_financial')

    def fin_can_view_all(self, session_user):
        """آیا مالی همه را می‌بیند یا فقط مالِ خودش؟"""
        if session_user is None:
            return False
        if session_user['role'] == 'admin':
            return True
        return (self.session_can(session_user, 'view_all') or
                self.session_can(session_user, 'view_all_purchases'))

    def invoice_can_view_all(self, session_user):
        """[v131] آیا این کاربر همهٔ اسناد تحویل مدارک را می‌بیند؟
        تجمیع‌کنندهٔ مدارک (ساریخانی) باید همه را ببیند تا بتواند یک‌جا به
        واحد مالی تحویل دهد؛ ولی این به‌معنای دسترسی به کل داده‌های مالی نیست."""
        if session_user is None:
            return False
        if self.fin_can_view_all(session_user):
            return True
        return self.session_can(session_user, 'invoice_docs_view_all')

    def contracts_can_view_all(self, session_user):
        """[v142.3] آیا این کاربر همهٔ قراردادها را در فرم «تحویل مدارک به مالی» می‌بیند؟
        قانون کسب‌وکار: تجمیع‌کنندهٔ مدارک (ساریخانی) و کسانی که مجوز مدیریت
        قراردادها دارند باید بتوانند برای ثبت فاکتور، قرارداد را انتخاب کنند.
        کارشناس عادی همچنان فقط قراردادهای مالک خودش را می‌بیند.
        """
        if session_user is None:
            return False
        if self.fin_can_view_all(session_user):
            return True
        # تجمیع‌کننده مدارک (ساریخانی و مشابه)
        if self.session_can(session_user, 'invoice_docs_view_all'):
            return True
        # دارندگان مجوز مدیریت/ویرایش قرارداد
        if self.session_can(session_user, 'manage_contracts'):
            return True
        if self.session_can(session_user, 'edit_contract'):
            return True
        return False

    def fin_owns(self, rec, session_user):
        """آیا این رکورد متعلق به همین کاربر است؟"""
        if session_user is None or not isinstance(rec, dict):
            return False
        me = _norm_sup_name(session_user['name'])
        if not me:
            return False
        for f in ('expert', 'created_by', 'owner', 'requester', 'actor'):
            if _norm_sup_name(rec.get(f)) == me:
                return True
        return False

    def fin_my_purchase_ids(self, conn, session_user):
        """شناسه و شماره‌ی خریدهایی که این کاربر کارشناسشان است."""
        if session_user is None:
            return set(), set()
        me = _norm_sup_name(session_user['name'])
        ids, reqs = set(), set()
        for r in conn.execute('SELECT id, req_number, expert FROM purchases'):
            if _norm_sup_name(r['expert']) == me:
                ids.add(r['id'])
                if r['req_number']:
                    reqs.add(str(r['req_number']))
        return ids, reqs

    def is_manager(self, session_user):
        return session_user is not None and session_user['role'] in ('admin', 'manager')

    # ── تنخواه: کنترل واقعی دسترسی در سمت سرور ──────────────────────────
    def petty_can_view_all(self, session_user):
        """آیا این کاربر مجاز است صورت‌های تنخواه همه را ببیند؟"""
        if session_user is None:
            return False
        if session_user['role'] == 'admin':
            return True
        return (self.session_can(session_user, 'petty_view_all') or
                self.session_can(session_user, 'manage_petty_cash'))

    def petty_owns(self, doc, session_user):
        """آیا این رکورد تنخواه متعلق به همین کاربر است؟"""
        if session_user is None or not isinstance(doc, dict):
            return False
        me = (session_user['name'] or '').strip()
        for f in PETTY_OWNER_FIELDS:
            if (str(doc.get(f) or '').strip()) == me:
                return True
        return False

    def petty_filter_docs(self, docs, session_user):
        """اعمال دامنه‌ی دید: اگر کاربر مجوز «مشاهده همه» ندارد، فقط رکوردهای خودش.
        این فیلتر در سرور اعمال می‌شود، نه در مرورگر — یعنی داده‌ی دیگران اصلاً
        از سرور خارج نمی‌شود."""
        if self.petty_can_view_all(session_user):
            return docs
        return [d for d in docs if self.petty_owns(d, session_user)]

    def petty_deposit_field_guard(self, body, session_user):
        """بررسی می‌کند کاربر فقط فیلدهایی را تغییر دهد که مجوزش را دارد.
        اگر فیلدی خارج از اختیارش باشد، نام آن برگردانده می‌شود."""
        if session_user is None:
            return ['(بدون نشست)']
        # [v127] دسترسی کامل به فیلدهای واریز از مجوز می‌آید، نه از نقش
        if session_user['role'] == 'admin' or self.petty_can_view_all(session_user):
            return []
        denied = []
        for perm, fields in PETTY_DEPOSIT_FIELD_PERM.items():
            if self.session_can(session_user, perm):
                continue
            for f in fields:
                if f in body:
                    denied.append(f)
        return denied

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
            # [v135] دروازهٔ مرکزی: هیچ مسیر داده‌ای بدون ورود به سیستم پاسخ نمی‌دهد.
            # پیش از این ۲۷ مسیر (از جمله users و audit_log و settings) باز بودند.
            if path not in GET_PUBLIC_PATHS:
                if self.get_session_user(conn) is None:
                    self.send_json({'ok': False,
                                    'error': 'لطفاً دوباره وارد شوید (نشست منقضی شده)'}, status=401)
                    return
            if path == '/api/me':
                su = self.get_session_user(conn)
                if su is None:
                    self.send_json({'ok': False}, status=401)
                else:
                    self.send_json({'ok': True, 'user': user_public_dict(su),
                                    'net_locked': bool(ALLOW_ONLY_PRIVATE)})
            elif path == '/api/trash':
                # [v124] سطل بازیافت — فهرست حذف‌شده‌های ۳۰ روز اخیر
                _su = self.get_session_user(conn)
                if not self.require(_su, self.session_can(_su, 'manage_backup')): return
                self.send_json({'ok': True, 'days': TRASH_DAYS, 'rows': trash_list(conn)})
            elif path == '/api/backups':
                # [v124] فهرست نسخه‌های پشتیبان + زمان آخرین نسخه
                _su = self.get_session_user(conn)
                if not self.require(_su, self.session_can(_su, 'manage_backup')): return
                lst = backup_list()
                self.send_json({'ok': True, 'every_hours': BACKUP_EVERY_HOURS,
                                'last': lst[0] if lst else None, 'rows': lst})
            elif path == '/api/items':
                self.send_json(get_docs(conn, 'items'))
            elif path == '/api/requests':
                rows = conn.execute('SELECT * FROM requests ORDER BY id').fetchall()
                self.send_json([request_row_to_dict(r) for r in rows])
            elif path == '/api/purchases':
                _su = self.get_session_user(conn)
                rows = conn.execute('SELECT * FROM purchases ORDER BY id').fetchall()
                out = [purchase_row_to_dict(conn, r) for r in rows]
                if not self.fin_can_view_all(_su):
                    # فقط خریدهای خودِ کاربر (ردیف‌های دیگران اصلاً ارسال نمی‌شوند)
                    out = [p for p in out if self.fin_owns(p, _su)]
                if not self.fin_can_view(_su):
                    out = [strip_financial_fields(p) for p in out]
                self.send_json(out)
            elif path == '/api/shippings':
                rows = conn.execute('SELECT * FROM shippings ORDER BY id').fetchall()
                self.send_json([shipping_row_to_dict(conn, r) for r in rows])
            elif path == '/api/sales':
                _su = self.get_session_user(conn)
                if not self.fin_can_view(_su):
                    self.send_json([])
                else:
                    rows = conn.execute('SELECT * FROM sales ORDER BY id').fetchall()
                    out = [sale_row_to_dict(conn, r) for r in rows]
                    if not self.fin_can_view_all(_su):
                        out = [x for x in out if self.fin_owns(x, _su)]
                    self.send_json(out)
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
                # [v117] فقط تأمین‌کنندگان فعال. پیش از این غیرفعال‌ها هم برمی‌گشتند
                # و به همین دلیل نامی که حذف می‌شد، همان لحظه دوباره در فهرست ظاهر می‌شد.
                rows = conn.execute(
                    'SELECT name FROM suppliers WHERE COALESCE(is_active,1)=1 ORDER BY name').fetchall()
                self.send_json([r['name'] for r in rows])
            elif path == '/api/supplier_profiles':
                rows = conn.execute('SELECT * FROM suppliers ORDER BY name').fetchall()
                self.send_json([supplier_row_to_dict(r) for r in rows])
            elif path == '/api/supplier_payments':
                _su = self.get_session_user(conn)
                if not self.fin_can_view(_su):
                    self.send_json([])          # بدون مجوز مالی: هیچ عددی ارسال نمی‌شود
                elif self.fin_can_view_all(_su):
                    self.send_json([dict(r) for r in
                                    conn.execute('SELECT * FROM supplier_payments ORDER BY id')])
                else:
                    _ids, _ = self.fin_my_purchase_ids(conn, _su)
                    out = []
                    for r in conn.execute('SELECT * FROM supplier_payments ORDER BY id'):
                        d = dict(r)
                        if d.get('purchase_id') in _ids or self.fin_owns(d, _su):
                            out.append(d)
                    self.send_json(out)
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
                _su = self.get_session_user(conn)
                _d = get_docs(conn, 'contracts')
                if not self.fin_can_view(_su):
                    self.send_json([])
                # [v142.3] ساریخانی (تجمیع‌کنندهٔ مدارک) و دارندگان مجوز
                # مدیریت/ویرایش قرارداد هم باید همهٔ قراردادها را ببینند
                # تا بتوانند در فرم «تحویل مدارک به مالی» فاکتور مربوط به
                # قرارداد ثبت کنند. پیش از این فقط view_all_purchases کار می‌کرد.
                elif self.contracts_can_view_all(_su):
                    self.send_json(_d)
                else:
                    self.send_json([x for x in _d if self.fin_owns(x, _su)])
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
                # دامنه‌ی دید در سرور اعمال می‌شود: بدون مجوز «مشاهده همه»،
                # فقط صورت‌های خودِ کاربر ارسال می‌شوند.
                self.send_json(self.petty_filter_docs(
                    get_docs(conn, 'petty_cash'), self.get_session_user(conn)))
            elif path == '/api/petty_holders':
                self.send_json(get_simple_list(conn, 'petty_holders'))
            elif path == '/api/car_models':
                self.send_json(get_simple_list(conn, 'car_models'))
            elif path == '/api/petty_card_persons':
                self.send_json(get_simple_list(conn, 'petty_card_persons'))
            elif path == '/api/petty_deposits':
                _su = self.get_session_user(conn)
                if not (self.petty_can_view_all(_su) or
                        self.session_can(_su, 'petty_deposit_view')):
                    self.send_json(self.petty_filter_docs(
                        get_docs(conn, 'petty_deposits'), _su))
                else:
                    self.send_json(get_docs(conn, 'petty_deposits'))
            elif path == '/api/ship_queue':
                self.send_json(get_docs(conn, 'ship_queue'))
            elif path == '/api/petty_charges':
                self.send_json(self.petty_filter_docs(
                    get_docs(conn, 'petty_charges'), self.get_session_user(conn)))
            elif path == '/api/manual_receipts':
                self.send_json(get_docs(conn, 'manual_receipts'))
            elif path == '/api/invoice_docs':
                _su = self.get_session_user(conn)
                _d = get_docs(conn, 'invoice_docs')
                if not self.fin_can_view(_su):
                    self.send_json([])
                elif self.invoice_can_view_all(_su):     # [v131]
                    self.send_json(_d)
                else:
                    self.send_json([x for x in _d if self.fin_owns(x, _su)])
            elif path == '/api/settings':
                self.send_json(get_all_settings(conn))
            elif path == '/api/users':
                # [v136] کاربر عادی فقط نام/سمت را می‌بیند (برای فهرست‌های کشویی).
                # مجوزها، گزارش تغییر مجوز و وضعیت رمز فقط برای مدیر کاربران.
                _su = self.get_session_user(conn)
                _full = (_su is not None and (_su['role'] == 'admin'
                         or self.session_can(_su, 'manage_users')))
                rows = conn.execute('SELECT * FROM users ORDER BY id').fetchall()
                if _full:
                    self.send_json([user_public_dict(r) for r in rows])
                else:
                    self.send_json([user_listing_dict(r) for r in rows])
            elif path == '/api/audit_log':
                # [v136] رویدادنامه فقط برای دارندگان مجوز؛ پیش از این هر کاربری
                # می‌توانست کل تاریخچهٔ عملیات شرکت را بخواند.
                _su = self.get_session_user(conn)
                if not self.require(_su, self.session_can(_su, 'page_audit_log')): return
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
        # کاربر جاری برای اعمال دامنه‌ی دید روی مجموعه‌های تنخواه
        _su = self.get_session_user(conn)
        requests_ = [request_row_to_dict(r) for r in conn.execute('SELECT * FROM requests ORDER BY id')]
        purchases_ = [purchase_row_to_dict(conn, r) for r in conn.execute('SELECT * FROM purchases ORDER BY id')]
        shippings_ = [shipping_row_to_dict(conn, r) for r in conn.execute('SELECT * FROM shippings ORDER BY id')]
        sales_ = [sale_row_to_dict(conn, r) for r in conn.execute('SELECT * FROM sales ORDER BY id')]
        sales_returns_ = [salesreturn_row_to_dict(conn, r) for r in conn.execute('SELECT * FROM sales_returns ORDER BY id')]

        # [v120] اعمال دامنه‌ی دید مالی روی پاسخ یکجا (/api/all).
        # این مسیر لحظه‌ی ورود صدا زده می‌شود و پیش از این کل داده‌ی مالی شرکت
        # را برای هر کاربری می‌فرستاد — حتی کسی که مجوز مالی نداشت.
        _fin_all = self.fin_can_view_all(_su)
        _fin_any = self.fin_can_view(_su)
        if not _fin_all:
            purchases_ = [p for p in purchases_ if self.fin_owns(p, _su)]
            sales_ = [x for x in sales_ if self.fin_owns(x, _su)]
        if not _fin_any:
            purchases_ = [strip_financial_fields(p) for p in purchases_]
            sales_ = []
            sales_returns_ = []
        _my_pids, _ = self.fin_my_purchase_ids(conn, _su)

        def _fin_docs(coll):
            d = get_docs(conn, coll)
            if not _fin_any:
                return []
            if _fin_all:
                return d
            return [x for x in d if self.fin_owns(x, _su)]

        # [v142.3] قراردادها: ساریخانی (تجمیع‌کنندهٔ مدارک) و دارندگان مجوز
        # مدیریت/ویرایش قرارداد باید همه قراردادها را در /api/all دریافت کنند
        # تا فرم «تحویل مدارک به مالی» بتواند قرارداد را در گزینه‌ها نشان دهد.
        def _contract_docs(coll):
            d = get_docs(conn, coll)
            if not _fin_any:
                return []
            if self.contracts_can_view_all(_su):
                return d
            return [x for x in d if self.fin_owns(x, _su)]

        def _fin_pays():
            rows = [dict(r) for r in conn.execute('SELECT * FROM supplier_payments ORDER BY id')]
            if not _fin_any:
                return []
            if _fin_all:
                return rows
            return [r for r in rows if r.get('purchase_id') in _my_pids or self.fin_owns(r, _su)]
        suppliers_names = [r['name'] for r in conn.execute(
            'SELECT name FROM suppliers WHERE COALESCE(is_active,1)=1 ORDER BY name')]
        suppliers_full = [supplier_row_to_dict(r) for r in conn.execute('SELECT * FROM suppliers ORDER BY name')]
        users_ = [user_public_dict(r) for r in conn.execute('SELECT * FROM users ORDER BY id')]
        destinations_ = [dict(r) for r in conn.execute('SELECT * FROM destinations ORDER BY id')]
        self.send_json({
            'items': get_docs(conn, 'items'), 'requests': requests_, 'purchases': purchases_,
            'shippings': shippings_, 'sales': sales_, 'sales_returns': sales_returns_,
            'units': get_simple_list(conn, 'units'), 'destinations': destinations_,
            'suppliers': suppliers_names, 'supplier_profiles': suppliers_full,
            'supplier_payments': _fin_pays(),
            'reasons': get_simple_list(conn, 'non_fulfillment_reasons'),
            'transport_types': get_simple_list(conn, 'transport_types'),
            'ship_statuses': get_simple_list(conn, 'ship_statuses'),
            'supply_statuses': get_simple_list(conn, 'supply_statuses'),
            'requester_units': get_simple_list(conn, 'requester_units'),
            'locations': get_simple_list(conn, 'locations'),
            'contract_types': get_simple_list(conn, 'contract_types'),
            'contracts': _contract_docs('contracts'), 'contract_payments': _fin_docs('contract_payments'),
            'settings': get_all_settings(conn),
            'returns': get_docs(conn, 'returns'), 'return_reasons': get_simple_list(conn, 'return_reasons'),
            'supply_plans': get_docs(conn, 'supply_plans'),
            'need_declarations': get_docs(conn, 'need_declarations'),
            'nf_records': get_docs(conn, 'nf_records'),   # [v125] بایگانی عدم تحقق
            # [v125] petty_tracking در جدول settings ذخیره می‌شود ولی فرانت آن را
            # در سطح بالا (D.petty_tracking) می‌خواند. پیش‌تر ارسال نمی‌شد و
            # همیشه خالی می‌ماند؛ داده‌اش فقط از نسخه سخت‌کد می‌آمد.
            'petty_tracking': get_setting(conn, 'petty_tracking', []),
            'inquiry_three_page': get_setting(conn, 'inquiry_three_page', []),  # [v125]
            'petty_cash': self.petty_filter_docs(get_docs(conn, 'petty_cash'), _su),
            'petty_holders': get_simple_list(conn, 'petty_holders'),
            'car_models': get_simple_list(conn, 'car_models'),
            'petty_card_persons': get_simple_list(conn, 'petty_card_persons'),
            'petty_deposits': (get_docs(conn, 'petty_deposits')
                               if (self.petty_can_view_all(_su) or
                                   self.session_can(_su, 'petty_deposit_view'))
                               else self.petty_filter_docs(get_docs(conn, 'petty_deposits'), _su)),
            'petty_charges': self.petty_filter_docs(get_docs(conn, 'petty_charges'), _su),
            'petty_fund': get_setting(conn, 'petty_fund', {'manager': 'زارع', 'total': 0, 'year': '', 'note': ''}),
            'manual_receipts': get_docs(conn, 'manual_receipts'),
            # [v131] تجمیع‌کنندهٔ مدارک همهٔ اسناد را می‌بیند
            'invoice_docs': (get_docs(conn, 'invoice_docs')
                             if (_fin_any and self.invoice_can_view_all(_su))
                             else _fin_docs('invoice_docs')),
            'ship_queue': get_docs(conn, 'ship_queue'),
            'users': users_
        })

    def compute_stats(self, conn):
        """[v142] بازنویسی: پیش از این ship_status روی خودِ purchase خوانده می‌شد
        (که چنین ستونی ندارد؛ ship_status روی purchase_items است) و مقدار همیشه ۰
        بود. همچنین delivery_date روی purchase وجود ندارد؛ ستون واقعی due_date است.
        شکل خروجی JSON برای سازگاری کامل با فرانت‌اند دست‌نخورده مانده است.
        """
        today = datetime.date.today().strftime('%Y/%m/%d')
        total = conn.execute('SELECT COUNT(*) c FROM purchases').fetchone()['c']

        # یک خرید «تحویل‌شده» است اگر همه اقلامش ship_status='shipped' باشند.
        # با یک SQL می‌شماریم: تعداد خریدهایی که حداقل یک قلم دارند و همه‌شان shipped.
        shipped = conn.execute("""
            SELECT COUNT(*) c FROM (
              SELECT p.id
              FROM purchases p
              JOIN purchase_items pi ON pi.purchase_id = p.id
              GROUP BY p.id
              HAVING SUM(CASE WHEN pi.ship_status='shipped' THEN 0 ELSE 1 END) = 0
            )
        """).fetchone()['c']

        # «در انتظار» = خریدی که هیچ قلمش هنوز ارسال نشده (همه pending یا nf)
        pending = conn.execute("""
            SELECT COUNT(*) c FROM (
              SELECT p.id
              FROM purchases p
              JOIN purchase_items pi ON pi.purchase_id = p.id
              GROUP BY p.id
              HAVING SUM(CASE WHEN pi.ship_status='shipped' OR pi.ship_status='partial' THEN 1 ELSE 0 END) = 0
            )
        """).fetchone()['c']

        # «عدم تحقق» = خریدی که حداقل یک قلمش عدم تحقق (no_fulfill=1 یا nf_qty>0) دارد
        non_fulfilled = conn.execute("""
            SELECT COUNT(DISTINCT purchase_id) c
            FROM purchase_items
            WHERE no_fulfill=1 OR (nf_qty IS NOT NULL AND nf_qty > 0)
        """).fetchone()['c']

        # مبلغ کل: از invoice_amount در extra_json خوانده می‌شود
        total_amount = 0.0
        for r in conn.execute("SELECT extra_json FROM purchases"):
            try:
                e = json.loads(r['extra_json'] or '{}')
                total_amount += float(e.get('invoice_amount', 0) or 0)
            except (TypeError, ValueError, json.JSONDecodeError):
                pass

        # سررسیدهای گذشته: due_date < today و هنوز مانده دارد یا هنوز کاملاً ارسال نشده
        overdue_rows = conn.execute("""
            SELECT p.id, p.req_number, p.supplier, p.due_date, p.remaining_amount
            FROM purchases p
            WHERE p.due_date IS NOT NULL AND p.due_date <> '' AND p.due_date < ?
              AND (
                p.remaining_amount > 0
                OR EXISTS (
                  SELECT 1 FROM purchase_items pi
                  WHERE pi.purchase_id = p.id AND pi.ship_status <> 'shipped'
                )
              )
            ORDER BY p.due_date
            LIMIT 10
        """, (today,)).fetchall()

        overdue_count = conn.execute("""
            SELECT COUNT(*) c FROM purchases p
            WHERE p.due_date IS NOT NULL AND p.due_date <> '' AND p.due_date < ?
              AND (
                p.remaining_amount > 0
                OR EXISTS (
                  SELECT 1 FROM purchase_items pi
                  WHERE pi.purchase_id = p.id AND pi.ship_status <> 'shipped'
                )
              )
        """, (today,)).fetchone()['c']

        req_count = conn.execute('SELECT COUNT(*) c FROM requests').fetchone()['c']

        return {
            'total': total, 'shipped': shipped, 'pending': pending,
            'non_fulfilled': non_fulfilled, 'total_amount': total_amount,
            'overdue_count': overdue_count,
            'overdue': [dict(r) for r in overdue_rows],
            'request_count': req_count,
        }

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
            # [v142] دروازهٔ مرکزی POST: بدون نشست معتبر فقط login/logout/password-check
            if session_user is None and path not in POST_PUBLIC_PATHS:
                self.send_json({'ok': False,
                                'error': 'لطفاً دوباره وارد شوید (نشست منقضی شده)'}, status=401)
                return
            # [v142] actor فقط از نشست معتبر؛ هرگز از بدنه‌ی درخواست خوانده نمی‌شود
            # (پیش از این body.get('_actor') می‌توانست هویت جعلی تحمیل کند).
            actor = session_user['name'] if session_user is not None else None
            self.handle_post(conn, path, body, actor, session_user)
        finally:
            conn.close()

    def handle_post(self, conn, path, body, actor, session_user):
        parts = path.lstrip('/').split('/')

        if path == '/api/login':
            uname = (body.get('username') or '').strip()
            raw_pw = body.get('password', '')

            # [v124] قفل موقت بعد از تلاش‌های ناموفق پیاپی
            wait = login_locked_for(uname)
            if wait:
                self.send_json({'ok': False, 'locked': True,
                                'error': f'به دلیل {LOGIN_MAX_ATTEMPTS} تلاش ناموفق، ورود این کاربر '
                                         f'{wait // 60 + 1} دقیقه قفل شده است.'})
                return

            u = conn.execute('SELECT * FROM users WHERE name=?', (uname,)).fetchone()
            ok, needs_upgrade = (False, False)
            if u is not None:
                ok, needs_upgrade = verify_password(raw_pw, u['password'])

            if ok:
                login_note_success(uname)
                # مهاجرت نرم: رمز درست بود ولی با فرمت ناامن قدیمی ذخیره شده
                if needs_upgrade:
                    conn.execute('UPDATE users SET password=? WHERE id=?',
                                 (hash_password(raw_pw), u['id']))
                    conn.commit()
                    db.log_audit(conn, uname, 'update', 'users', u['id'],
                                 note='ارتقای خودکار رمز به فرمت امن PBKDF2')
                    conn.commit()
                token = db.create_session(conn, u['id'])
                self.send_json({'ok': True, 'user': user_public_dict(u), 'token': token,
                                'password_weak': bool(password_problems(raw_pw, uname))})
            else:
                left = login_note_failure(uname)
                msg = 'نام کاربری یا رمز عبور اشتباه است'
                if 0 < left <= 2:
                    msg += f' — {left} تلاش دیگر باقی مانده، سپس حساب موقتاً قفل می‌شود'
                self.send_json({'ok': False, 'error': msg})
            return

        if path == '/api/logout':
            tok = self.get_token()
            if tok:
                db.destroy_session(conn, tok)
            self.send_json({'ok': True})
            return

        # [v143] بازگشت به جریان — اقدام مستقیم برای ردیف‌های عدم تحقق.
        # بدون صدور فرم جدید: قلم(های) انتخابیِ همان خرید به جریان تأمین برمی‌گردند،
        # شماره فرم مسکوت می‌شود و رویداد با علت ثبت می‌شود.
        if path == '/api/nf/return':
            if not self.require(session_user, True): return
            purchase_id = body.get('purchase_id')
            line_ids = body.get('line_ids') or []
            reason = (body.get('reason') or '').strip()
            note = (body.get('note') or '').strip()
            if not purchase_id or not line_ids:
                self.send_json({'ok': False, 'error': 'خرید یا قلم مشخص نشده است'}, 400); return
            if not reason:
                self.send_json({'ok': False, 'error': 'انتخاب علت بازگشت به جریان الزامی است'}, 400); return
            try:
                purchase_id = int(purchase_id)
                line_ids = [int(x) for x in line_ids]
            except (TypeError, ValueError):
                self.send_json({'ok': False, 'error': 'شناسه نامعتبر است'}, 400); return
            prow = conn.execute('SELECT * FROM purchases WHERE id=?', (purchase_id,)).fetchone()
            if not prow:
                self.send_json({'ok': False, 'error': 'خرید یافت نشد'}, 404); return
            # سطح دسترسی: صاحب رکورد یا مجوز «ثبت عدم تحقق»/«ویرایش هر خرید»
            allowed = (session_user is not None and prow['expert'] == session_user['name']) or \
                self.session_can(session_user, 'register_nonfulfill') or \
                self.session_can(session_user, 'edit_any_purchase')
            if not self.require(session_user, allowed): return
            # شماره‌های فرم پیش از پاک‌سازی (مبنای سیاست مسکوت)
            nums_before = _nf_nums_of_purchase(conn, purchase_id)
            updated = 0
            for lid in line_ids:
                it = conn.execute(
                    'SELECT id, extra_json FROM purchase_items WHERE id=? AND purchase_id=?',
                    (lid, purchase_id)).fetchone()
                if not it:
                    continue
                try:
                    e = json.loads(it['extra_json'] or '{}')
                except Exception:
                    e = {}
                for k in ('nf_number', 'line_nf_number', 'form_no', 'nf_reason', 'nf_qty_meta'):
                    e.pop(k, None)
                conn.execute('UPDATE purchase_items SET nf_qty=0, nf_reason=?, no_fulfill=0, extra_json=? WHERE id=?',
                             ('', json.dumps(e, ensure_ascii=False), lid))
                updated += 1
            if updated == 0:
                self.send_json({'ok': False, 'error': 'قلم یافت نشد'}, 404); return
            # اگر سربرگ خرید هم پرچم عدم تحقق داشت، پاک شود
            try:
                pe = json.loads(prow['extra_json'] or '{}')
            except Exception:
                pe = {}
            changed_head = False
            for k in ('nf_number', 'form_no', 'nf_reason'):
                if pe.get(k):
                    pe.pop(k, None); changed_head = True
            if changed_head:
                conn.execute('UPDATE purchases SET extra_json=? WHERE id=?',
                             (json.dumps(pe, ensure_ascii=False), purchase_id))
            # سیاست مسکوت: شماره‌هایی که دیگر در هیچ قلم این خرید نیستند و رزرو نشده‌اند
            nums_after = _nf_nums_of_purchase(conn, purchase_id)
            cleared = nums_before - nums_after
            if cleared:
                reserved = reserved_nf_numbers(conn, exclude_purchase_id=purchase_id)
                for num in cleared:
                    if num and num not in reserved:
                        create_doc(conn, 'nf_records', {
                            'nf_number': num, 'muted': True, 'muted_at': now_iso(),
                            'purchase_id': purchase_id, 'muted_by': actor,
                            'reason': 'بازگشت به جریان: ' + reason,
                        }, actor)
            recompute_request_status(conn, prow['req_number'])
            db.log_audit(conn, actor, 'update', 'purchases', purchase_id,
                         note=f'بازگشت به جریان ({reason}) — {updated} قلم' + ((' — ' + note) if note else ''))
            conn.commit()
            self.send_json({'ok': True, 'updated': updated, 'returned': True, 'purchase_id': purchase_id}); return

        if path == '/api/audit_log':
            # [v136] رویدادهای امنیتی رابط کاربری تا امروز به ۴۰۴ می‌خوردند و
            # بی‌صدا دور ریخته می‌شدند. حالا واقعا ثبت می‌شوند. هویت ثبت‌کننده
            # از روی نشست گرفته می‌شود، نه از بدنهٔ پیام.
            if not self.require(session_user, True): return
            db.log_audit(conn, session_user['name'],
                         str(body.get('action') or 'security')[:60],
                         str(body.get('entity') or 'system')[:60],
                         str(body.get('entity_id') or ''),
                         note=str(body.get('note') or '')[:500])
            conn.commit()
            self.send_json({'ok': True})
            return

        if path == '/api/items':
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
            item = dict(body); item.pop('_actor', None)
            item['id'] = next_doc_id(conn, 'items')
            conn.execute('INSERT INTO docs (collection, id, data, created_at) VALUES (?,?,?,?)',
                         ('items', item['id'], json.dumps(item, ensure_ascii=False), now_iso()))
            db.log_audit(conn, actor, 'create', 'items', item['id'], after=item); conn.commit()
            self.send_json(item); return

        if path == '/api/items/bulk':
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
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
                # کاربر صریحاً «افزودن» زده → اگر قبلاً حذف شده بود، دوباره فعال شود
                resolve_or_create_supplier(conn, name, actor, revive=True)
                conn.commit()
            rows = conn.execute(
                'SELECT name FROM suppliers WHERE COALESCE(is_active,1)=1 ORDER BY name').fetchall()
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
                'petty_charges': 'create_petty_charge',      # شارژ = واریز پول (مالی)
                'petty_cash': 'create_petty_statement',      # صورت تنخواه = هزینه‌ها (کارشناس)
                'petty_deposits': 'petty_deposit_view',
                'invoice_docs': 'invoice_docs_edit',         # [v140]
            }
            need_perm = DOC_CREATE_PERM.get(collection)
            if need_perm:
                allowed = self.session_can(session_user, need_perm)
                # [v114] مجوزهای هم‌ارز: بعضی مجوزهای «مدیریت/ویرایش» در صفحه‌ی کاربران
                # نمایش داده می‌شوند ولی هم‌تای «ثبت» آن‌ها برچسب ندارد و قابل تیک‌زدن نیست.
                # اگر کاربر مجوز مدیریت یا ویرایش همان بخش را دارد، ثبت هم مجاز است.
                # (بدون این، کاربر می‌توانست ویرایش کند ولی رکورد جدید ثبت نکند.)
                if not allowed:
                    for alt in PERM_EQUIVALENT.get(need_perm, ()):
                        if self.session_can(session_user, alt):
                            allowed = True
                            break
            else:
                allowed = session_user is not None
            if not self.require(session_user, allowed): return
            # کنترل فیلدی واریز تنخواه: هر نقش فقط فیلدهای خودش را تغییر دهد
            if collection == 'petty_deposits':
                denied = self.petty_deposit_field_guard(body, session_user)
                if denied:
                    self.send_json({'ok': False,
                                    'error': 'برای تغییر این فیلدها دسترسی ندارید: ' + '، '.join(denied)},
                                   403); return
            doc = create_doc(conn, collection, body, actor)
            self.send_json(doc); return

        if path == '/api/merge_suppliers':
            # ادغام واقعی تامین‌کنندگان در یک تراکنش.
            # با preview=true فقط پیش‌نمایش می‌دهد و چیزی را تغییر نمی‌دهد.
            allowed = (self.session_can(session_user, 'manage_suppliers') or
                       self.session_can(session_user, 'edit_supplier'))
            if not self.require(session_user, allowed): return
            target = body.get('target') or body.get('targetName') or ''
            aliases = body.get('aliases') or []
            if isinstance(aliases, str):
                aliases = [aliases]
            preview = bool(body.get('preview'))
            try:
                res = merge_suppliers_tx(conn, target, aliases, actor, dry_run=preview)
            except Exception as e:
                conn.rollback()
                self.send_json({'ok': False, 'error': 'خطا در ادغام: ' + str(e)}, 500); return
            if res.get('error'):
                self.send_json({'ok': False, 'error': res['error']}, 400); return
            res['ok'] = True
            res['preview'] = preview
            res['updated'] = (res['purchases'] + res['purchase_items'] +
                              res['shipping_items'] + res['supplier_payments'] + res['docs'])
            res['removed'] = res['suppliers_removed']
            self.send_json(res); return

        if path == '/api/settings':
            # ذخیره‌ی یکجای تنظیمات (فرانت‌اند ابتدا PUT و سپس POST را امتحان می‌کند)
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
            self.handle_settings_bulk(conn, body, actor); return

        if path.startswith('/api/settings/'):
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
            self.handle_settings_post(conn, path, body); return

        if path == '/api/close_purchase':
            pid = body.get('id'); close = body.get('close', True); reason = body.get('reason', '')
            row = conn.execute('SELECT * FROM purchases WHERE id=?', (pid,)).fetchone()
            allowed = self.session_can(session_user, 'edit_any_purchase') or \
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
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
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
            # [v143] نگهبان یکتایی شماره فرم عدم تحقق — دو فرم جدا نباید یک شماره داشته باشند
            sub_nf = submitted_nf_numbers(purchase, line_items)
            if sub_nf:
                conflicts = sorted(sub_nf & reserved_nf_numbers(conn))
                if conflicts:
                    self.send_json({'ok': False, 'nf_duplicate': True,
                                    'error': 'شماره فرم عدم تحقق ' + '، '.join(conflicts) +
                                             ' قبلاً برای فرم دیگری استفاده شده است؛ شماره‌ای یکتا وارد کنید.',
                                    'conflicts': conflicts}, 409)
                    return
            # [v126] نگهبان ثبت تکراری — پیش از این هیچ کنترلی نبود.
            # نمونه واقعی: درخواست ۱۶۲۸۱، کارشناس احمدی، پنج بار «مواد ABS-70»
            # را در فاصله ۱۰:۲۷ تا ۱۵:۰۶ همان روز ثبت کرد و سیستم هر پنج بار
            # را پذیرفت → ۱۹.۹ میلیارد ریال اضافه‌شمارش در گزارش‌ها.
            if not purchase.get('_force_duplicate'):
                dup = find_duplicate_purchase(conn, purchase, line_items)
                if dup:
                    self.send_json({
                        'ok': False, 'duplicate': True, 'existing_id': dup['id'],
                        'error': dup['message'], 'detail': dup['detail']}, 409)
                    return
            purchase.pop('_force_duplicate', None)
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
                # [v142.6] no_delivery_needed: قلم بدون نیاز به تحویل انبار
                _no_delivery = 1 if it.get('no_delivery_needed') else 0
                conn.execute(
                    '''INSERT INTO purchase_items (purchase_id, item_code, item_name, qty, unit, unit_price,
                       shipped_qty, ship_status, nf_qty, nf_reason, no_fulfill, price_pending,
                       no_delivery_needed, extra_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (pid, it.get('item_code', ''), it.get('item_name'), it.get('qty'), it.get('unit'),
                     it.get('unit_price'), 0, 'pending', 0, '', 0, 0,
                     _no_delivery, json.dumps(li_extra, ensure_ascii=False))
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
            # [v124] رمز ساده پذیرفته نمی‌شود
            new_pw = body.get('password', '')
            problems = password_problems(new_pw, body.get('name', ''))
            if problems:
                self.send_json({'ok': False, 'error': 'رمز عبور به‌اندازه کافی قوی نیست',
                                'password_problems': problems}, 400); return
            perms = body.get('perms') if body.get('perms') is not None else default_perms(role)
            cur = conn.execute(
                '''INSERT INTO users (name, role, title, password, is_expert_listed, unit, fiscal_year, perms_json, perm_log_json)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (body['name'], role, body.get('title', ''), hash_password(new_pw),
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
            res = make_backup(reason=body.get('reason', 'دستی'), actor=actor)
            self.send_json(res if res.get('ok') else res, 200 if res.get('ok') else 500); return

        if path.startswith('/api/restore/'):
            # [v124] بازگرداندن یک رکورد حذف‌شده از سطل بازیافت
            if not self.require(session_user, self.session_can(session_user, 'manage_backup')): return
            aid = path.rsplit('/', 1)[-1]
            if not aid.isdigit():
                self.send_json({'ok': False, 'error': 'شناسه نامعتبر'}, 400); return
            res = trash_restore(conn, int(aid), actor)
            self.send_json(res, 200 if res.get('ok') else 400); return

        if path == '/api/password/check':
            # [v124] بررسی زنده قدرت رمز، پیش از ذخیره
            pw = body.get('password', '')
            problems = password_problems(pw, body.get('username', ''))
            self.send_json({'ok': not problems, 'problems': problems,
                            'min_len': PASSWORD_MIN_LEN}); return

        self.send_json({'error': 'not found'}, 404)

    def handle_settings_post(self, conn, path, body):
        key = unquote(path.split('/')[-1])
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
        elif key in GENERIC_SETTING_KEYS:
            # کلیدهای عمومی تنظیمات: فرانت‌اند مقدار را زیر همین نام می‌فرستد.
            # قبلاً این کلیدها به هیچ شاخه‌ای نمی‌خوردند و بی‌صدا دور ریخته می‌شدند.
            if key in body:
                value = body[key]
            else:
                # سازگاری: اگر فرانت کل شیء را بدون نام کلید فرستاده باشد
                value = {k: v for k, v in body.items() if k != '_actor'} if isinstance(body, dict) else body
            set_setting(conn, key, value)
        else:
            # هرگز برای کلید ناشناخته ok:True برنگردان — این دقیقاً همان اشتباهی بود که
            # باعث شد ماه‌ها داده بی‌صدا گم شود و کسی متوجه نشود.
            self.send_json({'ok': False, 'error': f'کلید تنظیمات ناشناخته است: {key}'}, 400)
            return
        self.send_json({'ok': True})

    def handle_settings_bulk(self, conn, body, actor):
        """ذخیره‌ی یکجای مجموعه‌ای از تنظیمات (معادل PUT /api/settings در فرانت‌اند).
        فقط کلیدهای مجاز نوشته می‌شوند؛ بقیه در پاسخ به‌عنوان skipped گزارش می‌شوند
        تا هیچ داده‌ای بی‌سروصدا گم نشود."""
        if not isinstance(body, dict):
            self.send_json({'ok': False, 'error': 'بدنه‌ی نامعتبر'}, 400); return
        saved, skipped = [], []
        for k, v in body.items():
            if k == '_actor':
                continue
            if k in ALLOWED_SETTING_KEYS:
                set_setting(conn, k, v)
                saved.append(k)
            else:
                skipped.append(k)
        db.log_audit(conn, actor, 'update', 'settings', 0,
                     note='ذخیره تنظیمات: ' + ', '.join(saved) + (' | نادیده: ' + ', '.join(skipped) if skipped else ''))
        conn.commit()
        self.send_json({'ok': True, 'saved': saved, 'skipped': skipped})

    # -----------------------------------------------------------------
    def do_PUT(self):
        p = urlparse(self.path)
        body = self.get_body()
        parts = [unquote(x) for x in p.path.strip('/').split('/')]
        conn = db.get_conn()
        try:
            session_user = self.get_session_user(conn)
            # [v142] دروازهٔ مرکزی PUT: هیچ PUT عمومی‌ای وجود ندارد
            if session_user is None:
                self.send_json({'ok': False,
                                'error': 'لطفاً دوباره وارد شوید (نشست منقضی شده)'}, status=401)
                return
            # [v142] actor فقط از نشست معتبر (بدون fallback به body)
            actor = session_user['name']
            self.handle_put(conn, parts, body, actor, session_user)
        finally:
            conn.close()

    def handle_put(self, conn, parts, body, actor, session_user):
        # PUT /api/settings  (دو بخشی) — پیش از این به دلیل شرط len(parts)==3 همیشه 404 می‌شد
        # و فرانت‌اند بی‌آنکه بداند، تنظیمات را از دست می‌داد.
        if parts[0] == 'api' and len(parts) == 2 and parts[1] == 'settings':
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
            self.handle_settings_bulk(conn, body, actor); return
        if not (parts[0] == 'api' and len(parts) == 3):
            self.send_json({'error': 'not found'}, 404); return
        collection, rid = parts[1], parts[2]

        if collection == 'users':
            u = conn.execute('SELECT * FROM users WHERE id=?', (rid,)).fetchone()
            if not u:
                self.send_json({'error': 'not found'}, 404); return
            is_self = session_user is not None and str(session_user['id']) == str(rid)
            only_own_password = is_self and set(body.keys()) <= {'password', '_actor'}
            # [v141] تنظیمات شخصی (سال مالی و مسیر اسکن) نیازی به مجوز مدیریت کاربران
            # ندارد. پیش از این تغییر سال مالی برای کارشناس ۴۰۳ می‌گرفت و بی‌صدا
            # ذخیره نمی‌شد.
            only_own_prefs = is_self and set(body.keys()) <= {'fiscal_year', 'scan_path', '_actor'}
            allowed = only_own_password or only_own_prefs or self.session_can(session_user, 'manage_users')
            if not self.require(session_user, allowed): return
            # فقط ادمین می‌تواند نقش کسی را به admin تغییر دهد یا نقش یک ادمین را تغییر دهد
            if 'role' in body and (body['role'] == 'admin' or u['role'] == 'admin') and \
                    (session_user is None or session_user['role'] != 'admin'):
                self.send_json({'ok': False, 'error': 'فقط ادمین به این کار مجاز است'}, 403); return
            now = datetime.datetime.now().strftime('%Y/%m/%d %H:%M')
            changes = []
            updates = {}
            if body.get('password'):
                # [v124] همان قانون رمز قوی هنگام تغییر رمز هم اعمال می‌شود
                problems = password_problems(body['password'], u['name'])
                if problems:
                    self.send_json({'ok': False, 'error': 'رمز عبور به‌اندازه کافی قوی نیست',
                                    'password_problems': problems}, 400); return
                updates['password'] = hash_password(body['password']); changes.append('تغییر رمز عبور')
            # [v141] مجوزها فقط با مجوز «مدیریت کاربران» قابل تغییرند. اگر کاربری
            # بدون این مجوز، perms را در بدنه بفرستد (مثلاً چون رابط کاربری کل شیء
            # را ارسال می‌کرد) نادیده گرفته می‌شود تا مجوزها تصادفی بازنویسی نشوند.
            if 'perms' in body and not self.session_can(session_user, 'manage_users'):
                body = {k: v for k, v in body.items() if k != 'perms'}
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
            if not self.require(session_user, self.session_can(session_user, 'edit_supplier')): return
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
            allowed = (session_user is not None and row['expert'] == session_user['name']) or \
                self.session_can(session_user, 'edit_any_purchase')
            if not self.require(session_user, allowed): return
            before = purchase_row_to_dict(conn, row)
            body = dict(body)
            line_items = body.pop('line_items', None)
            # [v143] نگهبان یکتایی شماره فرم عدم تحقق هنگام ویرایش.
            # شماره‌های همین خرید (rid) مجازند (چند قلم یک فرم)؛ درگیری با سایر فرم‌ها/بایگانی ممنوع است.
            # _old_nf_nums باید پیش از هر تغییر دیتابیس گرفته شود (مبنای سیاست مسکوت).
            _old_nf_nums = _nf_nums_of_purchase(conn, int(rid)) if line_items is not None else set()
            if line_items is not None:
                sub_nf = submitted_nf_numbers(body, line_items)
                if sub_nf:
                    conflicts = sorted(sub_nf & reserved_nf_numbers(conn, exclude_purchase_id=int(rid)))
                    if conflicts:
                        self.send_json({'ok': False, 'nf_duplicate': True,
                                        'error': 'شماره فرم عدم تحقق ' + '، '.join(conflicts) +
                                                 ' قبلاً برای فرم دیگری استفاده شده است؛ شماره‌ای یکتا وارد کنید.',
                                        'conflicts': conflicts}, 409)
                        return
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
                # [v113] نقشه‌ی کد کالا → شناسه ردیف، برای تطبیق وقتی فرانت line_id نمی‌فرستد.
                # باگ قبلی: اگر line_id خالی بود، سرور کورکورانه INSERT می‌کرد و هر بار
                # ویرایش یک نسخه‌ی تکراری از همان قلم می‌ساخت (ریشه‌ی «از هر ردیف دوتا»).
                code_map = {}
                for r_ in conn.execute(
                        'SELECT id, item_code, item_name FROM purchase_items WHERE purchase_id=?', (rid,)):
                    ck = (str(r_['item_code'] or '').strip(),
                          ' '.join(str(r_['item_name'] or '').split()))
                    code_map.setdefault(ck, r_['id'])
                kept_ids = set()
                for it in line_items:
                    it = dict(it)
                    lid = it.get('line_id')
                    li_extra = extras(it, KNOWN_LINEITEM)
                    # اگر line_id نیامده بود، با کد کالا (و در نبود آن، با نام) تطبیق بده
                    if not (lid and lid in existing_ids):
                        ck = (str(it.get('item_code') or '').strip(),
                              ' '.join(str(it.get('item_name') or '').split()))
                        cand = code_map.get(ck)
                        if cand and cand not in kept_ids:
                            lid = cand
                    # [v142.6] no_delivery_needed از فرم به‌روزرسانی می‌شود
                    _no_delivery = 1 if it.get('no_delivery_needed') else 0
                    if lid and lid in existing_ids:
                        try:
                            up = float(it.get('unit_price') or 0)
                        except (TypeError, ValueError):
                            up = 0.0
                        price_pending = 0 if up > 0 else 1
                        # [v7] ship_status نیز به‌روزرسانی شود؛ پیش از این فقط no_delivery_needed آپدیت
                        # می‌شد و وضعیت ارسال قلم «pending/در انتظار» می‌ماند حتی وقتی تیک
                        # «نیازی به اعلام ارسال ندارد» روشن بود.
                        _ship_st = it.get('ship_status') or 'pending'
                        conn.execute(
                            '''UPDATE purchase_items SET item_code=?, item_name=?, qty=?, unit=?, unit_price=?,
                               price_pending=?, ship_status=?, no_delivery_needed=?, extra_json=? WHERE id=?''',
                            (it.get('item_code', ''), it.get('item_name'), it.get('qty'), it.get('unit'),
                             it.get('unit_price'), price_pending, _ship_st, _no_delivery,
                             json.dumps(li_extra, ensure_ascii=False), lid)
                        )
                        kept_ids.add(lid)
                    else:
                        conn.execute(
                            '''INSERT INTO purchase_items (purchase_id, item_code, item_name, qty, unit, unit_price,
                               shipped_qty, ship_status, nf_qty, nf_reason, no_fulfill, price_pending,
                               no_delivery_needed, extra_json)
                               VALUES (?,?,?,?,?,?,0,'pending',0,'',0,0,?,?)''',
                            (rid, it.get('item_code', ''), it.get('item_name'), it.get('qty'), it.get('unit'),
                             it.get('unit_price'), _no_delivery, json.dumps(li_extra, ensure_ascii=False))
                        )
                # ردیف‌هایی که در ارسال جدید نبودند حذف شوند (مطابق رفتار قبلی replace کامل آرایه)
                for old_id in existing_ids - kept_ids:
                    conn.execute('DELETE FROM purchase_items WHERE id=?', (old_id,))
                # [v143] سیاست مسکوت: شماره‌های فرمی که هنگام ویرایش حذف/حل شدند،
                # برای همیشه رزرو می‌مانند تا دوباره در فرم دیگری استفاده نشوند.
                # (قدیم/جدید از روی پیش از ویرایش محاسبه می‌شود)
                new_nums = submitted_nf_numbers(body, line_items)
                cleared = _old_nf_nums - new_nums
                if cleared:
                    reserved = reserved_nf_numbers(conn, exclude_purchase_id=int(rid))
                    for num in cleared:
                        if num and num not in reserved:
                            create_doc(conn, 'nf_records', {
                                'nf_number': num,
                                'muted': True,
                                'muted_at': now_iso(),
                                'purchase_id': int(rid),
                                'muted_by': actor,
                                'reason': 'فرم عدم تحقق هنگام ویرایش حل/ابطال شد (سیاست مسکوت)',
                            }, actor)
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
            allowed = (session_user is not None and row['created_by'] == session_user['name']) or \
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
            if not self.require(session_user, self.session_can(session_user, 'edit_shipping')): return
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
            allowed = (session_user is not None and row['expert'] == session_user['name']) or \
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
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
            out = update_doc(conn, 'items', int(rid), body, actor)
            self.send_json(out if out else {'error': 'not found'}, 200 if out else 404); return

        if collection in DOC_PATHS:
            target = DOC_PATHS[collection]
            DOC_EDIT_PERM = {'contracts': 'edit_contract', 'contract_payments': 'edit_contract',
                              'supply_plans': 'edit_supply_plan',
                              'petty_charges': 'edit_petty_charge', 'petty_cash': 'edit_petty_statement',
                              'invoice_docs': 'invoice_docs_edit'}   # [v140]
            need_perm = DOC_EDIT_PERM.get(target)
            if need_perm:
                allowed = self.session_can(session_user, need_perm)
                if not allowed:
                    for alt in PERM_EQUIVALENT.get(need_perm, ()):
                        if self.session_can(session_user, alt):
                            allowed = True
                            break
            else:
                allowed = session_user is not None
            if not self.require(session_user, allowed): return
            # کنترل فیلدی واریز تنخواه (همان قانون trackCanEdit، این بار در سرور)
            if target == 'petty_deposits':
                denied = self.petty_deposit_field_guard(body, session_user)
                if denied:
                    self.send_json({'ok': False,
                                    'error': 'برای تغییر این فیلدها دسترسی ندارید: ' + '، '.join(denied)},
                                   403); return
            # دامنه‌ی دید: بدون مجوز «مشاهده همه»، فقط رکورد خودش قابل ویرایش است
            if target in ('petty_cash', 'petty_charges') and not self.petty_can_view_all(session_user):
                _existing = next((d for d in get_docs(conn, target) if str(d.get('id')) == str(rid)), None)
                if _existing is not None and not self.petty_owns(_existing, session_user):
                    self.send_json({'ok': False,
                                    'error': 'این رکورد متعلق به شما نیست'}, 403); return
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
            # [v142] دروازهٔ مرکزی DELETE: هیچ DELETE عمومی‌ای وجود ندارد.
            # این جلوی حذف‌های anonymous را می‌گیرد که در تحقیق روی audit_log
            # گذشته دیده شد (۱۸ حذف بدون هویت روی petty_cash در روز v125).
            if session_user is None:
                self.send_json({'ok': False,
                                'error': 'لطفاً دوباره وارد شوید (نشست منقضی شده)'}, status=401)
                return
            actor = session_user['name']
            self.handle_delete(conn, parts, actor, session_user)
        finally:
            conn.close()

    def handle_delete(self, conn, parts, actor, session_user):
        if not (parts[0] == 'api' and len(parts) == 3):
            self.send_json({'error': 'not found'}, 404); return
        collection, rid = parts[1], parts[2]

        if collection in SIMPLE_LISTS:
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
            del_simple_list_value(conn, SIMPLE_LISTS[collection], rid)
            self.send_json({'ok': True}); return

        if collection == 'suppliers':
            if not self.require(session_user, self.session_can(session_user, 'delete_supplier')): return
            row = None
            if rid.isdigit():
                row = conn.execute('SELECT * FROM suppliers WHERE id=?', (rid,)).fetchone()
            if not row:
                row = conn.execute('SELECT * FROM suppliers WHERE name=?', (rid,)).fetchone()
            if not row:
                self.send_json({'ok': True, 'note': 'یافت نشد'}); return
            # [v117] سرفصل‌های هزینه هرگز حذف نمی‌شوند
            if is_protected_supplier(row['name']):
                self.send_json({'ok': False,
                                'error': 'این یک سرفصل هزینه است و قابل حذف نیست: ' + row['name']},
                               400); return
            used = supplier_usage_count(conn, row['id'], row['name'])
            before = supplier_row_to_dict(row)
            if used == 0:
                # هیچ رکوردی به آن وصل نیست → حذف کامل، وگرنه دوباره در فهرست ظاهر می‌شود
                conn.execute('DELETE FROM suppliers WHERE id=?', (row['id'],))
                db.log_audit(conn, actor, 'delete', 'suppliers', row['id'], before=before,
                             note='حذف کامل (هیچ رکوردی به آن وصل نبود)')
                conn.commit()
                self.send_json({'ok': True, 'deleted': True, 'used': 0}); return
            # رکورد دارد → فقط غیرفعال، تا سوابق نشکند
            conn.execute('UPDATE suppliers SET is_active=0 WHERE id=?', (row['id'],))
            db.log_audit(conn, actor, 'deactivate', 'suppliers', row['id'], before=before,
                         note=f'غیرفعال شد ({used} رکورد به آن وصل است)')
            conn.commit()
            self.send_json({'ok': True, 'deleted': False, 'used': used,
                            'note': f'{used} رکورد به این تأمین‌کننده وصل است، بنابراین فقط غیرفعال شد'})
            return

        if collection == 'shippings':
            row = conn.execute('SELECT * FROM shippings WHERE id=?', (rid,)).fetchone()
            if not self.require(session_user, self.session_can(session_user, 'delete_shipping')): return
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
            allowed = self.session_can(session_user, 'delete_purchase') or \
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
            allowed = self.session_can(session_user, 'delete_sale') or \
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
            if not self.require(session_user, self.session_can(session_user, 'register_sale_return')): return
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
            if not self.require(session_user, self.session_can(session_user, 'register_return')): return
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
            allowed = self.session_can(session_user, 'delete_request') or \
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
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
            conn.execute('DELETE FROM destinations WHERE id=?', (rid,))
            conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'supplier_payments':
            if not self.require(session_user, self.session_can(session_user, 'register_payment')): return
            conn.execute('DELETE FROM supplier_payments WHERE id=?', (rid,))
            db.log_audit(conn, actor, 'delete', 'supplier_payments', rid)
            conn.commit()
            self.send_json({'ok': True}); return

        if collection == 'items':
            if not self.require(session_user, self.session_can(session_user, 'manage_lists')): return
            delete_doc(conn, 'items', int(rid))
            self.send_json({'ok': True}); return

        if collection in DOC_PATHS:
            target = DOC_PATHS[collection]
            DOC_DELETE_PERM = {'contracts': 'delete_contract', 'contract_payments': 'delete_contract',
                                'supply_plans': 'delete_supply_plan',
                                'petty_charges': 'delete_petty_charge', 'petty_cash': 'delete_petty_statement',
                                'invoice_docs': 'invoice_docs_edit'}   # [v140]
            need_perm = DOC_DELETE_PERM.get(target)
            if need_perm:
                allowed = self.session_can(session_user, need_perm)
                if not allowed:
                    for alt in PERM_EQUIVALENT.get(need_perm, ()):
                        if self.session_can(session_user, alt):
                            allowed = True
                            break
            else:
                allowed = session_user is not None
            if not self.require(session_user, allowed): return
            # دامنه‌ی دید: بدون مجوز «مشاهده همه»، فقط رکورد خودش قابل حذف است
            if target in ('petty_cash', 'petty_charges', 'petty_deposits') and \
                    not self.petty_can_view_all(session_user):
                _existing = next((d for d in get_docs(conn, target) if str(d.get('id')) == str(rid)), None)
                if _existing is not None and not self.petty_owns(_existing, session_user):
                    self.send_json({'ok': False,
                                    'error': 'این رکورد متعلق به شما نیست'}, 403); return
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


def migrate_ghost_perms_v136():
    """[v136] چهار مجوز تازه‌واقعی‌شده را به کسانی می‌دهد که پیش از این عملاً
    دسترسی داشتند، تا کسی چیزی از دست ندهد. فقط یک‌بار اجرا می‌شود."""
    conn = db.get_conn()
    try:
        if get_setting(conn, 'migrated_ghost_perms_v136'):
            return
        changed = 0
        for u in conn.execute('SELECT id, name, role, perms_json FROM users').fetchall():
            perms = json.loads(u['perms_json'] or '{}')
            before = dict(perms)
            if u['role'] == 'admin':
                grant = True
            elif u['role'] == 'manager':
                grant = bool(perms.get('manage_backup') or perms.get('manage_lists'))
            else:
                grant = False
            if grant:
                for k in ('page_audit_log', 'page_data_health', 'manage_items'):
                    perms.setdefault(k, True)
                    if perms.get(k) is False:
                        perms[k] = True
            # سرپرست تنخواه: مجوز صدور صورت تنخواه
            if perms.get('manage_petty_cash') or perms.get('create_petty_statement'):
                if not perms.get('issue_statement_cover'):
                    perms['issue_statement_cover'] = True
            for k in PERM_KEYS:
                perms.setdefault(k, False)
            if perms != before:
                conn.execute('UPDATE users SET perms_json=? WHERE id=?',
                             (json.dumps(perms, ensure_ascii=False), u['id']))
                changed += 1
        set_setting(conn, 'migrated_ghost_perms_v136', True)
        conn.commit()
        if changed:
            safe_print(f'{changed} کاربر: مجوزهای تازه‌واقعی‌شده اعمال شد')
    finally:
        conn.close()


def migrate_invoice_perms_v140():
    """[v140] تفکیک «مشاهدهٔ همهٔ صورت‌وضعیت‌ها» از «ثبت و ویرایش».
    طبق تصمیم کاربر: ویرایش فقط برای ساریخانی (تجمیع‌کننده) و مدیران.
    مشاهدهٔ همه هم برای همان‌ها روشن می‌شود؛ بقیه را خودِ کاربر با تیک می‌دهد."""
    conn = db.get_conn()
    try:
        if get_setting(conn, 'migrated_invoice_perms_v140'):
            return
        changed = 0
        for u in conn.execute('SELECT id, name, role, perms_json FROM users').fetchall():
            perms = json.loads(u['perms_json'] or '{}')
            before = dict(perms)
            nm = (u['name'] or '').strip()
            is_aggregator = ('ساریخانی' in nm)
            is_boss = u['role'] in ('admin', 'manager')
            if is_aggregator or is_boss:
                perms['invoice_docs_view_all'] = True
                perms['invoice_docs_edit'] = True
            else:
                perms.setdefault('invoice_docs_view_all', False)
                perms['invoice_docs_edit'] = False
            for k in PERM_KEYS:
                perms.setdefault(k, False)
            if perms != before:
                conn.execute('UPDATE users SET perms_json=? WHERE id=?',
                             (json.dumps(perms, ensure_ascii=False), u['id']))
                changed += 1
        set_setting(conn, 'migrated_invoice_perms_v140', True)
        conn.commit()
        if changed:
            safe_print(f'{changed} کاربر: مجوزهای تحویل مدارک تفکیک شد')
    finally:
        conn.close()


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
    migrate_ghost_perms_v136()
    migrate_invoice_perms_v140()
    # [v142] پاک‌سازی نشست‌های منقضی هنگام راه‌اندازی
    try:
        _c = db.get_conn()
        _n = db.cleanup_expired_sessions(_c)
        _c.close()
        if _n:
            safe_print(f'پاک‌سازی نشست‌ها: {_n} نشست منقضی حذف شد')
    except Exception as _e:
        safe_print(f'خطای پاک‌سازی نشست‌ها: {_e}')
    # [v124] یک پشتیبان هنگام بالا آمدن + زمان‌بند هر ۶ ساعت
    make_backup(reason='هنگام راه‌اندازی سرور')
    _backup_scheduler()
    port = int(os.environ.get("PORT", "8765"))
    server = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    safe_print(f'Server running on port {port} (SQLite: {db.DB_FILE})')
    safe_print(f'پشتیبان خودکار: هر {BACKUP_EVERY_HOURS} ساعت → {BACKUP_DIR}')
    safe_print('امنیت شبکه: ' + ('فقط شبکهٔ داخلی مجاز است' if ALLOW_ONLY_PRIVATE
                                 else 'هشدار — اتصال از همه شبکه‌ها باز است'))
    server.serve_forever()


