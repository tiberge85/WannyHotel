import os, sqlite3, hashlib, secrets
from datetime import datetime, timedelta

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, 'hotel.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, salt TEXT NOT NULL, full_name TEXT NOT NULL,
            role TEXT DEFAULT 'receptionniste', active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS room_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT,
            base_price REAL DEFAULT 0, capacity INTEGER DEFAULT 2, amenities TEXT);
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT, number TEXT UNIQUE NOT NULL, floor INTEGER DEFAULT 0,
            room_type_id INTEGER, status TEXT DEFAULT 'disponible', cleaning_status TEXT DEFAULT 'propre', notes TEXT,
            FOREIGN KEY (room_type_id) REFERENCES room_types(id));
        CREATE TABLE IF NOT EXISTS guests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT NOT NULL, last_name TEXT NOT NULL,
            nationality TEXT, id_type TEXT, id_number TEXT, tel TEXT, email TEXT, company TEXT,
            vip INTEGER DEFAULT 0, total_stays INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT UNIQUE, guest_id INTEGER NOT NULL,
            room_id INTEGER, checkin_date TEXT NOT NULL, checkout_date TEXT NOT NULL,
            nights INTEGER DEFAULT 1, adults INTEGER DEFAULT 1, children INTEGER DEFAULT 0,
            rate_per_night REAL DEFAULT 0, total_amount REAL DEFAULT 0, paid_amount REAL DEFAULT 0,
            status TEXT DEFAULT 'confirmee', source TEXT DEFAULT 'direct', notes TEXT,
            created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            checked_in_at TEXT, checked_out_at TEXT,
            FOREIGN KEY (guest_id) REFERENCES guests(id), FOREIGN KEY (room_id) REFERENCES rooms(id));
        CREATE TABLE IF NOT EXISTS charges (
            id INTEGER PRIMARY KEY AUTOINCREMENT, reservation_id INTEGER NOT NULL,
            category TEXT DEFAULT 'hebergement', description TEXT, quantity INTEGER DEFAULT 1,
            unit_price REAL DEFAULT 0, total REAL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (reservation_id) REFERENCES reservations(id));
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, reservation_id INTEGER, amount REAL NOT NULL,
            method TEXT DEFAULT 'espece', reference TEXT, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS housekeeping (
            id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL, assigned_to TEXT,
            task TEXT DEFAULT 'nettoyage', status TEXT DEFAULT 'a_faire', priority TEXT DEFAULT 'normale',
            notes TEXT, completed_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (room_id) REFERENCES rooms(id));
        CREATE TABLE IF NOT EXISTS staff (
            id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT NOT NULL, last_name TEXT NOT NULL,
            position TEXT, department TEXT, tel TEXT, hire_date TEXT, salary REAL DEFAULT 0,
            status TEXT DEFAULT 'actif', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS stock_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT DEFAULT 'restaurant',
            unit TEXT DEFAULT 'piece', quantity REAL DEFAULT 0, min_stock REAL DEFAULT 0,
            unit_price REAL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS stock_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL, movement_type TEXT,
            quantity REAL, notes TEXT, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (item_id) REFERENCES stock_items(id));
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, client_name TEXT,
            room_name TEXT, event_date TEXT, start_time TEXT, end_time TEXT,
            guests_count INTEGER DEFAULT 0, rate REAL DEFAULT 0, status TEXT DEFAULT 'confirme',
            notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_name TEXT,
            action TEXT, detail TEXT, ip TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    ''')
    salt = secrets.token_hex(16)
    pw = hashlib.sha256((salt + 'admin2026').encode()).hexdigest()
    try: conn.execute("INSERT INTO users (username,password_hash,salt,full_name,role) VALUES (?,?,?,?,?)",
                      ('admin',pw,salt,'Administrateur','admin'))
    except: pass
    for name, price, cap in [('Standard', 25000, 2), ('Supérieure', 40000, 2), ('Suite', 75000, 3), ('Suite VIP', 120000, 4), ('Appartement meublé', 50000, 4)]:
        try: conn.execute("INSERT INTO room_types (name, base_price, capacity) VALUES (?,?,?)", (name, price, cap))
        except: pass
    conn.commit(); conn.close()

def authenticate(username, password):
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    conn.close()
    if u and hashlib.sha256((u['salt']+password).encode()).hexdigest() == u['password_hash']: return dict(u)
    return None

def create_user(username, password, full_name, role='receptionniste'):
    conn = get_db(); salt = secrets.token_hex(16)
    pw = hashlib.sha256((salt+password).encode()).hexdigest()
    try: conn.execute("INSERT INTO users (username,password_hash,salt,full_name,role) VALUES (?,?,?,?,?)",
                      (username,pw,salt,full_name,role)); conn.commit()
    except: pass
    conn.close()

def get_user(uid):
    conn = get_db(); u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone(); conn.close()
    return dict(u) if u else None

def get_all_users():
    conn = get_db(); r = conn.execute("SELECT * FROM users ORDER BY full_name").fetchall(); conn.close()
    return [dict(x) for x in r]

def db_insert(table, **kw):
    conn = get_db(); cols=','.join(kw.keys()); vals=','.join(['?']*len(kw))
    conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({vals})", list(kw.values()))
    conn.commit(); rid=conn.execute("SELECT last_insert_rowid()").fetchone()[0]; conn.close(); return rid

def db_all(table, where=None, order='id DESC', limit=500):
    conn = get_db(); q=f"SELECT * FROM {table}"; p=[]
    if where: q+=" WHERE "+" AND ".join(f"{k}=?" for k in where.keys()); p=list(where.values())
    q+=f" ORDER BY {order} LIMIT {limit}"; rows=conn.execute(q,p).fetchall(); conn.close()
    return [dict(r) for r in rows]

def db_get(table, rid):
    conn = get_db(); r=conn.execute(f"SELECT * FROM {table} WHERE id=?", (rid,)).fetchone(); conn.close()
    return dict(r) if r else None

def db_update(table, rid, **kw):
    conn = get_db(); sets=','.join(f"{k}=?" for k in kw.keys())
    conn.execute(f"UPDATE {table} SET {sets} WHERE id=?", list(kw.values())+[rid]); conn.commit(); conn.close()

def db_count(table, where=None):
    conn = get_db(); q=f"SELECT COUNT(*) FROM {table}"; p=[]
    if where: q+=" WHERE "+" AND ".join(f"{k}=?" for k in where.keys()); p=list(where.values())
    c=conn.execute(q,p).fetchone()[0]; conn.close(); return c

def db_sum(table, col, where=None):
    conn = get_db(); q=f"SELECT COALESCE(SUM({col}),0) FROM {table}"; p=[]
    if where: q+=" WHERE "+" AND ".join(f"{k}=?" for k in where.keys()); p=list(where.values())
    s=conn.execute(q,p).fetchone()[0]; conn.close(); return s

def log_activity(uid, name, action, detail='', ip=''):
    conn = get_db(); conn.execute("INSERT INTO activity_logs (user_id,user_name,action,detail,ip) VALUES (?,?,?,?,?)",
                                  (uid,name,action,detail,ip)); conn.commit(); conn.close()

def create_reservation(guest_id, room_id, checkin, checkout, rate, adults=1, children=0, source='direct', notes='', created_by=None):
    d1=datetime.strptime(checkin,'%Y-%m-%d'); d2=datetime.strptime(checkout,'%Y-%m-%d')
    nights=max(1,(d2-d1).days); total=nights*rate
    ref=f"RES-{datetime.now().strftime('%y%m%d')}-{secrets.token_hex(2).upper()}"
    conn = get_db()
    conn.execute("""INSERT INTO reservations (reference,guest_id,room_id,checkin_date,checkout_date,
        nights,rate_per_night,total_amount,adults,children,source,notes,created_by)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ref,guest_id,room_id,checkin,checkout,nights,rate,total,adults,children,source,notes,created_by))
    conn.commit(); rid=conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO charges (reservation_id,category,description,quantity,unit_price,total) VALUES (?,?,?,?,?,?)",
                 (rid,'hebergement',f'Hébergement {nights} nuit(s)',nights,rate,total))
    conn.commit(); conn.close(); return rid, ref

def checkin_res(res_id):
    conn = get_db(); res=conn.execute("SELECT * FROM reservations WHERE id=?", (res_id,)).fetchone()
    if res:
        conn.execute("UPDATE reservations SET status='en_cours', checked_in_at=? WHERE id=?", (datetime.now().isoformat(),res_id))
        conn.execute("UPDATE rooms SET status='occupee' WHERE id=?", (res['room_id'],))
        conn.commit()
    conn.close()

def checkout_res(res_id):
    conn = get_db(); res=conn.execute("SELECT * FROM reservations WHERE id=?", (res_id,)).fetchone()
    if res:
        conn.execute("UPDATE reservations SET status='terminee', checked_out_at=? WHERE id=?", (datetime.now().isoformat(),res_id))
        conn.execute("UPDATE rooms SET status='disponible', cleaning_status='a_nettoyer' WHERE id=?", (res['room_id'],))
        conn.execute("UPDATE guests SET total_stays=total_stays+1 WHERE id=?", (res['guest_id'],))
        conn.commit()
    conn.close()

def get_dashboard_stats():
    conn = get_db(); today=datetime.now().strftime('%Y-%m-%d'); s={}
    s['total_rooms']=conn.execute("SELECT COUNT(*) FROM rooms").fetchone()[0]
    s['occupied']=conn.execute("SELECT COUNT(*) FROM rooms WHERE status='occupee'").fetchone()[0]
    s['available']=conn.execute("SELECT COUNT(*) FROM rooms WHERE status='disponible'").fetchone()[0]
    s['occupancy_rate']=round(s['occupied']/s['total_rooms']*100,1) if s['total_rooms'] else 0
    s['checkins_today']=conn.execute("SELECT COUNT(*) FROM reservations WHERE checkin_date=? AND status IN ('confirmee','en_cours')", (today,)).fetchone()[0]
    s['checkouts_today']=conn.execute("SELECT COUNT(*) FROM reservations WHERE checkout_date=? AND status='en_cours'", (today,)).fetchone()[0]
    s['revenue_month']=conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE created_at >= date('now','start of month')").fetchone()[0]
    s['revenue_today']=conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE date(created_at)=?", (today,)).fetchone()[0]
    s['dirty_rooms']=conn.execute("SELECT COUNT(*) FROM rooms WHERE cleaning_status='a_nettoyer'").fetchone()[0]
    s['pending_hk']=conn.execute("SELECT COUNT(*) FROM housekeeping WHERE status='a_faire'").fetchone()[0]
    s['active_res']=conn.execute("SELECT COUNT(*) FROM reservations WHERE status IN ('confirmee','en_cours')").fetchone()[0]
    s['events']=conn.execute("SELECT COUNT(*) FROM events WHERE event_date>=? AND status='confirme'", (today,)).fetchone()[0]
    conn.close(); return s

def get_recent_reservations(limit=10):
    conn = get_db()
    rows=conn.execute("""SELECT r.*, g.first_name||' '||g.last_name as guest_name, rm.number as room_number
        FROM reservations r LEFT JOIN guests g ON r.guest_id=g.id LEFT JOIN rooms rm ON r.room_id=rm.id
        ORDER BY r.created_at DESC LIMIT ?""", (limit,)).fetchall()
    conn.close(); return [dict(r) for r in rows]

def get_rooms_with_status():
    conn = get_db()
    rows=conn.execute("""SELECT r.*, rt.name as type_name, rt.base_price,
        res.reference as current_ref, g.first_name||' '||g.last_name as current_guest
        FROM rooms r LEFT JOIN room_types rt ON r.room_type_id=rt.id
        LEFT JOIN reservations res ON res.room_id=r.id AND res.status='en_cours'
        LEFT JOIN guests g ON res.guest_id=g.id ORDER BY r.floor, r.number""").fetchall()
    conn.close(); return [dict(r) for r in rows]

def get_res_detail(res_id):
    conn = get_db()
    res=conn.execute("""SELECT r.*, g.first_name||' '||g.last_name as guest_name, g.tel as guest_tel,
        g.email as guest_email, g.nationality, g.id_number, g.company,
        rm.number as room_number, rt.name as room_type_name
        FROM reservations r LEFT JOIN guests g ON r.guest_id=g.id LEFT JOIN rooms rm ON r.room_id=rm.id
        LEFT JOIN room_types rt ON rm.room_type_id=rt.id WHERE r.id=?""", (res_id,)).fetchone()
    charges=conn.execute("SELECT * FROM charges WHERE reservation_id=?", (res_id,)).fetchall()
    payments=conn.execute("SELECT * FROM payments WHERE reservation_id=?", (res_id,)).fetchall()
    conn.close()
    if not res: return None,[],[]
    return dict(res), [dict(c) for c in charges], [dict(p) for p in payments]


# ======================== MIGRATION: ADD IMAGES TO ROOMS ========================

def migrate_db():
    conn = get_db()
    try: conn.execute("ALTER TABLE rooms ADD COLUMN images TEXT DEFAULT ''")
    except: pass
    try: conn.execute("ALTER TABLE room_types ADD COLUMN image TEXT DEFAULT ''")
    except: pass
    # Online reservations table
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS online_bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guest_first_name TEXT NOT NULL, guest_last_name TEXT NOT NULL,
            guest_tel TEXT, guest_email TEXT,
            room_type_id INTEGER, checkin_date TEXT, checkout_date TEXT,
            adults INTEGER DEFAULT 1, children INTEGER DEFAULT 0,
            notes TEXT, status TEXT DEFAULT 'en_attente',
            processed_by INTEGER, reservation_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (room_type_id) REFERENCES room_types(id)
        );
    ''')
    conn.commit(); conn.close()

def get_available_room_types(checkin, checkout):
    """Retourne les types de chambres avec dispo pour les dates données."""
    conn = get_db()
    types = conn.execute("SELECT * FROM room_types ORDER BY base_price ASC").fetchall()
    result = []
    for t in types:
        # Count total rooms of this type
        total = conn.execute("SELECT COUNT(*) FROM rooms WHERE room_type_id=?", (t['id'],)).fetchone()[0]
        # Count rooms occupied during the period
        occupied = conn.execute("""SELECT COUNT(DISTINCT r.room_id) FROM reservations r
            JOIN rooms rm ON r.room_id=rm.id
            WHERE rm.room_type_id=? AND r.status IN ('confirmee','en_cours')
            AND r.checkin_date < ? AND r.checkout_date > ?""",
            (t['id'], checkout, checkin)).fetchone()[0]
        available = total - occupied
        d = dict(t)
        d['total_rooms'] = total
        d['available'] = available
        if total > 0:
            result.append(d)
    conn.close()
    return result

def get_room_images(room_id):
    conn = get_db()
    r = conn.execute("SELECT images FROM rooms WHERE id=?", (room_id,)).fetchone()
    conn.close()
    if r and r['images']:
        return [img.strip() for img in r['images'].split(',') if img.strip()]
    return []

def get_online_bookings(status=None):
    conn = get_db()
    if status:
        rows = conn.execute("""SELECT ob.*, rt.name as type_name, rt.base_price
            FROM online_bookings ob LEFT JOIN room_types rt ON ob.room_type_id=rt.id
            WHERE ob.status=? ORDER BY ob.created_at DESC""", (status,)).fetchall()
    else:
        rows = conn.execute("""SELECT ob.*, rt.name as type_name, rt.base_price
            FROM online_bookings ob LEFT JOIN room_types rt ON ob.room_type_id=rt.id
            ORDER BY ob.created_at DESC""").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ======================== NOTIFICATIONS ========================

def create_notification(guest_id, reservation_id, notif_type, message):
    conn = get_db()
    token = secrets.token_hex(12)
    conn.execute("""INSERT INTO notifications (guest_id, reservation_id, type, message, token)
        VALUES (?,?,?,?,?)""", (guest_id, reservation_id, notif_type, message, token))
    conn.commit(); conn.close()
    return token

def get_notification_by_token(token):
    conn = get_db()
    n = conn.execute("SELECT * FROM notifications WHERE token=?", (token,)).fetchone()
    conn.close()
    return dict(n) if n else None

def migrate_db_v2():
    conn = get_db()
    try: conn.execute("""CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT, guest_id INTEGER, reservation_id INTEGER,
        type TEXT, message TEXT, token TEXT UNIQUE, read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    except: pass
    conn.commit(); conn.close()


# ======================== INVOICE PDF ========================

def get_invoice_data(res_id):
    conn = get_db()
    res = conn.execute("""SELECT r.*, g.first_name, g.last_name, g.tel, g.email, g.nationality, g.company,
        rm.number as room_number, rt.name as room_type_name
        FROM reservations r LEFT JOIN guests g ON r.guest_id=g.id
        LEFT JOIN rooms rm ON r.room_id=rm.id LEFT JOIN room_types rt ON rm.room_type_id=rt.id
        WHERE r.id=?""", (res_id,)).fetchone()
    charges = conn.execute("SELECT * FROM charges WHERE reservation_id=?", (res_id,)).fetchall()
    payments = conn.execute("SELECT * FROM payments WHERE reservation_id=?", (res_id,)).fetchall()
    conn.close()
    if not res: return None, [], []
    return dict(res), [dict(c) for c in charges], [dict(p) for p in payments]


# ======================== RESET ========================

def reset_all_data():
    conn = get_db()
    for table in ['notifications','payments','charges','reservations','housekeeping',
                  'stock_movements','stock_items','events','conf_bookings','conference_rooms',
                  'online_bookings','guests','rooms','staff','activity_logs','login_attempts']:
        try: conn.execute(f"DELETE FROM {table}")
        except: pass
    conn.commit(); conn.close()

def reset_reservations():
    conn = get_db()
    for t in ['notifications','payments','charges','reservations','online_bookings','housekeeping']:
        try: conn.execute(f"DELETE FROM {t}")
        except: pass
    conn.execute("UPDATE rooms SET status='disponible', cleaning_status='propre'")
    conn.commit(); conn.close()


# ======================== CLIENT ACCOUNTS ========================

def migrate_db_v3():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS guest_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guest_id INTEGER UNIQUE,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guest_id) REFERENCES guests(id)
        );
        CREATE TABLE IF NOT EXISTS smtp_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            smtp_host TEXT DEFAULT 'smtp.gmail.com',
            smtp_port INTEGER DEFAULT 587,
            smtp_user TEXT,
            smtp_pass TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit(); conn.close()

def create_guest_account(email, password, first_name, last_name, tel=''):
    conn = get_db()
    salt = secrets.token_hex(16)
    pw = hashlib.sha256((salt + password).encode()).hexdigest()
    # Create guest first
    try:
        conn.execute("INSERT INTO guests (first_name, last_name, tel, email) VALUES (?,?,?,?)",
                     (first_name, last_name, tel, email))
        conn.commit()
    except: pass
    guest = conn.execute("SELECT id FROM guests WHERE email=?", (email,)).fetchone()
    guest_id = guest['id'] if guest else None
    try:
        conn.execute("INSERT INTO guest_accounts (guest_id, email, password_hash, salt) VALUES (?,?,?,?)",
                     (guest_id, email, pw, salt))
        conn.commit()
    except: pass
    conn.close()
    return guest_id

def authenticate_guest(email, password):
    conn = get_db()
    u = conn.execute("SELECT ga.*, g.first_name, g.last_name, g.tel FROM guest_accounts ga LEFT JOIN guests g ON ga.guest_id=g.id WHERE ga.email=? AND ga.active=1", (email,)).fetchone()
    conn.close()
    if u and hashlib.sha256((u['salt'] + password).encode()).hexdigest() == u['password_hash']:
        return dict(u)
    return None

def get_guest_reservations(guest_id):
    conn = get_db()
    rows = conn.execute("""SELECT r.*, rm.number as room_number, rt.name as room_type_name
        FROM reservations r LEFT JOIN rooms rm ON r.room_id=rm.id LEFT JOIN room_types rt ON rm.room_type_id=rt.id
        WHERE r.guest_id=? ORDER BY r.created_at DESC""", (guest_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_guest_notifications(guest_id):
    conn = get_db()
    rows = conn.execute("SELECT * FROM notifications WHERE guest_id=? ORDER BY created_at DESC", (guest_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def save_smtp(host, port, user, pwd):
    conn = get_db()
    conn.execute("DELETE FROM smtp_settings")
    conn.execute("INSERT INTO smtp_settings (smtp_host, smtp_port, smtp_user, smtp_pass) VALUES (?,?,?,?)",
                 (host, port, user, pwd))
    conn.commit(); conn.close()

def get_smtp():
    conn = get_db()
    s = conn.execute("SELECT * FROM smtp_settings LIMIT 1").fetchone()
    conn.close()
    return dict(s) if s else None
