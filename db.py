#!/usr/bin/env python3
"""
لایه دیتابیس سیستم بازرگانی مهر (SQLite)
جایگزین ذخیره‌سازی JSON تک‌فایلی قبلی.

اصول طراحی:
- موجودیت‌های اصلی (suppliers, requests, purchases, purchase_items,
  shippings, shipping_items, supplier_payments, users, audit_log)
  جدول واقعی با ایندکس دارند.
- مجموعه‌های فرعی/کم‌حجم فعلی (contracts, returns, supply_plans, ...)
  در جدول عمومی docs به‌صورت سند JSON نگه داشته می‌شوند تا بدون ریسک
  بازنویسی کامل منطق قبلی، از مزیت SQLite (نوشتن فقط رکورد تغییریافته،
  نه کل فایل) بهره ببرند. در فاز بعد در صورت نیاز نرمال می‌شوند.
"""
import sqlite3, os, json, datetime, secrets

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE, 'mehr.db')

SESSION_TTL_HOURS = 12


def cleanup_expired_sessions(conn):
    """[v142] پاک‌سازی نشست‌های منقضی‌شده.
    پیش از این جدول sessions بی‌نهایت رشد می‌کرد (نمونه: ۱۳۸ از ۱۴۲ منقضی
    ولی همچنان در جدول). این تابع رکوردهای منقضی را حذف می‌کند و تعداد
    پاک‌شده را برمی‌گرداند.
    """
    cur = conn.execute('DELETE FROM sessions WHERE expires_at <= ?',
                       (datetime.datetime.now().isoformat(),))
    conn.commit()
    return cur.rowcount


def create_session(conn, user_id):
    # [v142] هر ورود جدید یک نوبت پاک‌سازی نشست‌های منقضی هم می‌کند
    # (تنبل و ارزان: در بدترین حالت هر چند ساعت یک‌بار اجرا می‌شود).
    try:
        cleanup_expired_sessions(conn)
    except Exception:
        pass  # پاک‌سازی نباید جلوی ورود کاربر را بگیرد
    token = secrets.token_hex(32)
    now = datetime.datetime.now()
    expires = now + datetime.timedelta(hours=SESSION_TTL_HOURS)
    conn.execute('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)',
                 (token, user_id, now.isoformat(), expires.isoformat()))
    conn.commit()
    return token


def resolve_session(conn, token):
    """اگر توکن معتبر و منقضی‌نشده باشد، سطر کامل کاربر را برمی‌گرداند؛ در غیر این صورت None.
    نشست‌های منقضی‌شده هم‌زمان حذف می‌شوند (پاک‌سازی تنبل)."""
    if not token:
        return None
    row = conn.execute(
        'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id '
        'WHERE s.token=? AND s.expires_at > ?',
        (token, datetime.datetime.now().isoformat())
    ).fetchone()
    return row


def destroy_session(conn, token):
    conn.execute('DELETE FROM sessions WHERE token=?', (token,))
    conn.commit()


def destroy_all_sessions_for_user(conn, user_id):
    conn.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
    conn.commit()

DOC_COLLECTIONS = [
    'items', 'contracts', 'contract_payments', 'returns', 'supply_plans',
    'need_declarations', 'petty_cash', 'petty_deposits', 'petty_charges',
    'manual_receipts', 'ship_queue', 'invoice_docs'
]

SIMPLE_LIST_NAMES = [
    'units', 'non_fulfillment_reasons', 'transport_types', 'ship_statuses',
    'supply_statuses', 'requester_units', 'locations', 'contract_types',
    'return_reasons', 'petty_holders'
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS suppliers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  contact_person TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  address TEXT DEFAULT '',
  category TEXT DEFAULT '',
  payment_terms TEXT DEFAULT '',
  bank_account TEXT DEFAULT '',
  rating REAL,
  is_active INTEGER DEFAULT 1,
  note TEXT DEFAULT '',
  created_at TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_suppliers_name ON suppliers(name);

CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  req_number TEXT, expert TEXT, req_date TEXT, status TEXT,
  created_by TEXT, created_at TEXT, imported INTEGER DEFAULT 0,
  extra_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_requests_reqnum ON requests(req_number);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
CREATE INDEX IF NOT EXISTS idx_requests_expert ON requests(expert);

CREATE TABLE IF NOT EXISTS purchases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  req_number TEXT, expert TEXT,
  supplier_id INTEGER REFERENCES suppliers(id),
  supplier TEXT,
  date TEXT, is_contract INTEGER DEFAULT 0, no_request INTEGER DEFAULT 0,
  created_at TEXT, imported INTEGER DEFAULT 0,
  paid_amount REAL DEFAULT 0,
  remaining_amount REAL DEFAULT 0,
  due_date TEXT DEFAULT '',
  payment_method TEXT DEFAULT '',
  financial_status TEXT,
  closed INTEGER DEFAULT 0, close_reason TEXT, closed_by TEXT, closed_at TEXT,
  extra_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_purchases_reqnum ON purchases(req_number);
CREATE INDEX IF NOT EXISTS idx_purchases_supplier ON purchases(supplier_id);
CREATE INDEX IF NOT EXISTS idx_purchases_date ON purchases(date);
CREATE INDEX IF NOT EXISTS idx_purchases_finstatus ON purchases(financial_status);
CREATE INDEX IF NOT EXISTS idx_purchases_duedate ON purchases(due_date);

CREATE TABLE IF NOT EXISTS purchase_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  purchase_id INTEGER REFERENCES purchases(id),
  item_code TEXT DEFAULT '', item_name TEXT, qty TEXT, unit TEXT, unit_price TEXT,
  shipped_qty REAL DEFAULT 0, ship_status TEXT DEFAULT 'pending',
  nf_qty REAL DEFAULT 0, nf_reason TEXT DEFAULT '', no_fulfill INTEGER DEFAULT 0,
  price_pending INTEGER DEFAULT 0,
  legacy_line_no INTEGER,
  -- [v142.6] برای اقلامی که نیاز به تحویل انبار ندارند (خدمات، هزینه‌های
  -- متفرقه، آزمون‌ها، بلیط، کرایه، ...) — سیستم آن را به‌صورت خودکار
  -- «تحویل‌شده کامل» فرض می‌کند و در گزارش‌های معلقی نمی‌آورد.
  no_delivery_needed INTEGER DEFAULT 0,
  extra_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_pitems_purchase ON purchase_items(purchase_id);
CREATE INDEX IF NOT EXISTS idx_pitems_code ON purchase_items(item_code);

CREATE TABLE IF NOT EXISTS shippings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  number TEXT, date TEXT, transport TEXT, driver TEXT,
  destination TEXT, created_by TEXT, warehouse_no TEXT, year TEXT,
  created_at TEXT, imported INTEGER DEFAULT 0,
  extra_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_shippings_date ON shippings(date);

CREATE TABLE IF NOT EXISTS shipping_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shipping_id INTEGER REFERENCES shippings(id),
  item_name TEXT, item_code TEXT DEFAULT '', qty TEXT, unit TEXT,
  req_number TEXT DEFAULT '', supplier TEXT DEFAULT '',
  purchase_id INTEGER, line_id INTEGER,
  notes TEXT DEFAULT '', no_request_item INTEGER DEFAULT 0,
  extra_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sitems_shipping ON shipping_items(shipping_id);
CREATE INDEX IF NOT EXISTS idx_sitems_purchase ON shipping_items(purchase_id);
CREATE INDEX IF NOT EXISTS idx_sitems_reqnum ON shipping_items(req_number);

CREATE TABLE IF NOT EXISTS supplier_payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  supplier_id INTEGER REFERENCES suppliers(id),
  supplier TEXT,
  purchase_id INTEGER,
  amount REAL DEFAULT 0, date TEXT, method TEXT DEFAULT '', note TEXT DEFAULT '',
  created_by TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_suppay_supplier ON supplier_payments(supplier_id);
CREATE INDEX IF NOT EXISTS idx_suppay_date ON supplier_payments(date);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE, role TEXT, title TEXT DEFAULT '', password TEXT,
  is_expert_listed INTEGER DEFAULT 1, unit TEXT DEFAULT 'بازرگانی و پشتیبانی',
  fiscal_year TEXT DEFAULT '',
  perms_json TEXT DEFAULT '{}', perm_log_json TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS destinations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT
);

CREATE TABLE IF NOT EXISTS simple_lists (
  list_name TEXT, value TEXT, sort_order INTEGER DEFAULT 0,
  PRIMARY KEY (list_name, value)
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY, value TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  created_at TEXT,
  expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS docs (
  collection TEXT, id INTEGER, data TEXT, created_at TEXT,
  PRIMARY KEY (collection, id)
);
CREATE INDEX IF NOT EXISTS idx_docs_collection ON docs(collection);

CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  number TEXT, date TEXT, customer TEXT,
  offset_supplier TEXT DEFAULT '',
  created_by TEXT, created_at TEXT,
  paid_amount REAL DEFAULT 0, remaining_amount REAL DEFAULT 0,
  payment_method TEXT DEFAULT '', financial_status TEXT DEFAULT '',
  closed INTEGER DEFAULT 0,
  extra_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sales_date ON sales(date);
CREATE INDEX IF NOT EXISTS idx_sales_customer ON sales(customer);

CREATE TABLE IF NOT EXISTS sale_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sale_id INTEGER REFERENCES sales(id),
  item_code TEXT DEFAULT '', item_name TEXT, qty TEXT, unit TEXT, unit_price TEXT,
  returned_qty REAL DEFAULT 0,
  extra_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_saleitems_sale ON sale_items(sale_id);

CREATE TABLE IF NOT EXISTS sales_returns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sale_id INTEGER REFERENCES sales(id), number TEXT, date TEXT, note TEXT DEFAULT '',
  created_by TEXT, created_at TEXT,
  extra_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_salesret_sale ON sales_returns(sale_id);

CREATE TABLE IF NOT EXISTS sales_return_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  return_id INTEGER REFERENCES sales_returns(id),
  sale_item_id INTEGER REFERENCES sale_items(id),
  item_code TEXT DEFAULT '', item_name TEXT, qty TEXT, unit TEXT, unit_price TEXT, reason TEXT DEFAULT '',
  extra_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_salesretitems_return ON sales_return_items(return_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT, actor TEXT, action TEXT, entity TEXT, entity_id TEXT,
  before_json TEXT, after_json TEXT, note TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
"""


def get_conn():
    # [v142.14] timeout=30s در سطح اتصال (ثانیه) — SQLite تا 30 ثانیه صبر می‌کند
    # قبل از خطای "database is locked". این ریشه‌ی "اتصال به سرور محلی برقرار
    # نشد" را در حالت concurrent requests رفع می‌کند.
    conn = sqlite3.connect(DB_FILE, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA journal_mode = WAL')  # نوشتن سریع‌تر و ایمن‌تر تحت همزمانی
    conn.execute('PRAGMA busy_timeout = 30000')  # 30 ثانیه صبر روی lock
    conn.execute('PRAGMA synchronous = NORMAL')  # سریع‌تر با WAL و همچنان امن
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    # [v142.6] migration نرم: افزودن ستون‌های جدید به دیتابیس‌های قدیمی.
    # این کار idempotent است و اگر ستون از قبل وجود داشته باشد، عملی نمی‌کند.
    _ensure_column(conn, 'purchase_items', 'no_delivery_needed', 'INTEGER DEFAULT 0')
    conn.commit()
    conn.close()


def _ensure_column(conn, table, column, coldef):
    """اگر ستون در جدول موجود نباشد، آن را اضافه می‌کند. برای migration نرم."""
    cols = [c[1] for c in conn.execute(f'PRAGMA table_info({table})')]
    if column not in cols:
        try:
            conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {coldef}')
        except Exception:
            pass  # اگر خطای همزمانی پیش آمد، نادیده بگیر


def seed_if_empty():
    """اگر دیتابیس کاملاً خام است (هیچ کاربری ثبت نشده)، یک کاربر مدیر پیش‌فرض و
    لیست‌های ساده‌ی پایه را می‌سازد تا سیستم از روز اول قابل استفاده باشد.
    این تابع idempotent است: اگر حتی یک کاربر وجود داشته باشد، کاری نمی‌کند."""
    import hashlib
    conn = get_conn()
    n_users = conn.execute('SELECT COUNT(*) c FROM users').fetchone()['c']
    if n_users == 0:
        pw = hashlib.sha256('admin'.encode()).hexdigest()
        admin_perms = {k: True for k in [
            'create_request', 'assign_request', 'edit_request', 'delete_request',
            'create_purchase', 'edit_any_purchase', 'delete_purchase',
            'create_shipping', 'edit_shipping', 'delete_shipping', 'ship_consolidate', 'register_return',
            'register_payment', 'register_nonfulfill', 'manage_lists', 'manage_users', 'manage_backup',
            'view_financial', 'view_reports', 'export_excel', 'manage_contracts', 'view_all_purchases',
            'view_all', 'manage_supply_plan', 'manage_petty_cash', 'petty_view_all', 'petty_deposit_view',
            'petty_deposit_finance', 'petty_deposit_delivery', 'petty_deposit_review', 'manage_suppliers'
        ]}
        conn.execute('''INSERT INTO users (name, role, title, password, is_expert_listed, unit,
                        fiscal_year, perms_json, perm_log_json)
                        VALUES (?,?,?,?,1,?,?,?,?)''',
                     ('مدیر', 'admin', 'مدیر بازرگانی', pw, 'بازرگانی و پشتیبانی', '',
                      json.dumps(admin_perms, ensure_ascii=False), '[]'))
        defaults = {
            'units': ['عدد', 'کیلوگرم', 'متر', 'لیتر', 'بسته', 'جفت', 'دست', 'رول', 'شاخه'],
            'non_fulfillment_reasons': ['عدم توان مالی تامین‌کننده', 'کالا موجود نیست', 'قیمت بالا',
                                         'انصراف درخواست‌دهنده', 'سایر'],
            'transport_types': ['کامیون', 'وانت', 'اتوبوس', 'هواپیما', 'قطار', 'پیک'],
            'ship_statuses': ['در انتظار', 'ارسال شده', 'ارسال جزئی'],
            'supply_statuses': ['در حال اقدام', 'تامین شد', 'عدم تحقق', 'عدم تحقق جزئی'],
            'requester_units': ['تولید', 'مهندسی', 'کنترل کیفیت', 'تعمیرات و نگهداری', 'انبار', 'اداری'],
            'locations': ['تهران', 'بم'],
            'contract_types': ['خرید کالا', 'خدمات', 'پیمانکاری'],
            'return_reasons': ['کالای معیوب', 'مغایرت با مشخصات فنی', 'آسیب در حمل', 'اضافه ارسالی', 'سایر'],
            'petty_holders': ['بازرگانی و پشتیبانی'],
            'car_models': ['PS12', 'X5', 'SR3', 'Eagle', 'J4'],
        }
        for list_name, vals in defaults.items():
            for i, val in enumerate(vals):
                conn.execute('INSERT OR IGNORE INTO simple_lists (list_name, value, sort_order) VALUES (?,?,?)',
                             (list_name, val, i))
        for d in ['دفتر مرکزی تهران', 'کارخانه بم']:
            conn.execute('INSERT INTO destinations (name) VALUES (?)', (d,))
        conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)',
                     ('petty_fund', json.dumps({'manager': 'مدیر', 'total': 0, 'year': '', 'note': ''},
                                                ensure_ascii=False)))
        log_audit(conn, 'system', 'seed', 'database', 0, note='راه‌اندازی اولیه با کاربر مدیر پیش‌فرض')
        conn.commit()
        try:
            print("کاربر پیش‌فرض ساخته شد → نام کاربری: مدیر | رمز عبور: admin  (لطفاً فوراً تغییر دهید)")
        except OSError:
            pass
    conn.close()


def now_iso():
    return datetime.datetime.now().isoformat()


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def log_audit(conn, actor, action, entity, entity_id, before=None, after=None, note=''):
    conn.execute(
        'INSERT INTO audit_log (ts, actor, action, entity, entity_id, before_json, after_json, note) VALUES (?,?,?,?,?,?,?,?)',
        (now_iso(), actor or '', action, entity, str(entity_id),
         json.dumps(before, ensure_ascii=False) if before is not None else None,
         json.dumps(after, ensure_ascii=False) if after is not None else None,
         note)
    )


if __name__ == '__main__':
    init_db()
    print('دیتابیس و جدول‌ها با موفقیت ساخته شد:', DB_FILE)
