import os, sqlite3, hashlib, secrets
from datetime import datetime, timedelta

PERSISTENT_DIR = os.environ.get('PERSISTENT_DIR', os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PERSISTENT_DIR, 'data')
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
    pw = hashlib.pbkdf2_hmac('sha256', 'admin2026'.encode(), salt.encode(), 100000).hex()
    try: conn.execute("INSERT INTO users (username,password_hash,salt,full_name,role) VALUES (?,?,?,?,?)",
                      ('admin',pw,salt,'Administrateur','admin'))
    except: pass
    for name, price, cap in [('Standard', 25000, 2), ('Supérieure', 40000, 2), ('Suite', 75000, 3), ('Suite VIP', 120000, 4), ('Appartement meublé', 50000, 4)]:
        try: conn.execute("INSERT INTO room_types (name, base_price, capacity) VALUES (?,?,?)", (name, price, cap))
        except: pass
    conn.commit(); conn.close()

def _check_password(stored_hash, salt, password):
    """Vérifie le mot de passe — supporte PBKDF2 et ancien SHA256."""
    # PBKDF2 (nouveau)
    if hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() == stored_hash:
        return True
    # Fallback: ancien SHA256 simple
    if hashlib.sha256((salt + password).encode()).hexdigest() == stored_hash:
        return True
    return False

def _hash_password(password):
    """Hash sécurisé PBKDF2-SHA256 avec 100 000 itérations."""
    salt = secrets.token_hex(16)
    pw = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return pw, salt

def _upgrade_password(table, user_id, password):
    """Met à jour un ancien hash SHA256 vers PBKDF2."""
    pw, salt = _hash_password(password)
    conn = get_db()
    conn.execute(f"UPDATE {table} SET password_hash=?, salt=? WHERE id=?", (pw, salt, user_id))
    conn.commit(); conn.close()

def authenticate(username, password):
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    conn.close()
    if u and _check_password(u['password_hash'], u['salt'], password):
        # Auto-upgrade old sha256 to PBKDF2
        old_check = hashlib.sha256((u['salt']+password).encode()).hexdigest()
        if old_check == u['password_hash']:
            _upgrade_password('users', u['id'], password)
        return dict(u)
    return None

def create_user(username, password, full_name, role='receptionniste'):
    conn = get_db()
    pw, salt = _hash_password(password)
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
        total = conn.execute("SELECT COUNT(*) FROM rooms WHERE room_type_id=?", (t['id'],)).fetchone()[0]
        occupied = conn.execute("""SELECT COUNT(DISTINCT r.room_id) FROM reservations r
            JOIN rooms rm ON r.room_id=rm.id
            WHERE rm.room_type_id=? AND r.status IN ('confirmee','en_cours')
            AND r.checkin_date < ? AND r.checkout_date > ?""",
            (t['id'], checkout, checkin)).fetchone()[0]
        available = total - occupied
        d = dict(t)
        d['total_rooms'] = total
        d['available'] = available
        # Fallback: if room_type has no image, use first room's image
        if not d.get('image'):
            room_img = conn.execute("SELECT images FROM rooms WHERE room_type_id=? AND images != '' AND images IS NOT NULL LIMIT 1", (t['id'],)).fetchone()
            if room_img and room_img['images']:
                d['image'] = room_img['images'].split(',')[0].strip()
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
    pw, salt = _hash_password(password)
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
    if u and _check_password(u['password_hash'], u['salt'], password):
        old_check = hashlib.sha256((u['salt'] + password).encode()).hexdigest()
        if old_check == u['password_hash']:
            _upgrade_password('guest_accounts', u['id'], password)
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


# ======================== MIGRATIONS V3 ========================

def migrate_v3():
    conn = get_db()
    # Restaurant orders
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS restaurant_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_number TEXT, room_id INTEGER,
            guest_name TEXT, items_json TEXT,
            subtotal REAL DEFAULT 0, tax REAL DEFAULT 0, total REAL DEFAULT 0,
            status TEXT DEFAULT 'en_cours',
            payment_method TEXT, reservation_id INTEGER,
            created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS restaurant_menu (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, category TEXT DEFAULT 'plat',
            price REAL DEFAULT 0, available INTEGER DEFAULT 1,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS guest_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reservation_id INTEGER, guest_id INTEGER,
            rating INTEGER DEFAULT 5, comment TEXT,
            token TEXT UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS loyalty_points (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guest_id INTEGER, points INTEGER DEFAULT 0,
            action TEXT, reservation_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    # Room planning
    for col in ['color', 'floor_plan']:
        try: conn.execute(f"ALTER TABLE rooms ADD COLUMN {col} TEXT DEFAULT ''")
        except: pass
    # Guest loyalty
    for col in ['loyalty_points', 'preferred_room_type', 'notes_internes']:
        try: conn.execute(f"ALTER TABLE guests ADD COLUMN {col} TEXT DEFAULT ''")
        except: pass
    conn.commit(); conn.close()


def get_dashboard_stats():
    conn = get_db()
    s = {}
    s['total_rooms'] = conn.execute("SELECT COUNT(*) FROM rooms").fetchone()[0]
    s['occupied'] = conn.execute("SELECT COUNT(*) FROM rooms WHERE status='occupee'").fetchone()[0]
    s['available'] = conn.execute("SELECT COUNT(*) FROM rooms WHERE status='disponible'").fetchone()[0]
    s['cleaning'] = conn.execute("SELECT COUNT(*) FROM rooms WHERE status='a_nettoyer'").fetchone()[0]
    s['occupancy_rate'] = round(s['occupied'] * 100 / max(s['total_rooms'], 1))
    
    s['total_guests'] = conn.execute("SELECT COUNT(*) FROM guests").fetchone()[0]
    s['active_reservations'] = conn.execute("SELECT COUNT(*) FROM reservations WHERE status='en_cours'").fetchone()[0]
    s['pending_reservations'] = conn.execute("SELECT COUNT(*) FROM reservations WHERE status='confirmee'").fetchone()[0]
    s['online_pending'] = conn.execute("SELECT COUNT(*) FROM online_bookings WHERE status='en_attente'").fetchone()[0]
    
    # Revenue
    try:
        s['revenue_month'] = conn.execute("""SELECT COALESCE(SUM(amount),0) FROM payments 
            WHERE created_at >= date('now','start of month')""").fetchone()[0]
    except: s['revenue_month'] = 0
    try:
        s['revenue_total'] = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments").fetchone()[0]
    except: s['revenue_total'] = 0
    try:
        s['charges_month'] = conn.execute("""SELECT COALESCE(SUM(total),0) FROM charges 
            WHERE created_at >= date('now','start of month')""").fetchone()[0]
    except: s['charges_month'] = 0
    
    # Housekeeping
    s['hk_pending'] = conn.execute("SELECT COUNT(*) FROM housekeeping WHERE status='a_faire'").fetchone()[0]
    
    # RevPAR
    s['adr'] = round(s['charges_month'] / max(s['occupied'], 1))
    s['revpar'] = round(s['revenue_month'] / max(s['total_rooms'], 1))
    
    # Recent reservations
    s['recent'] = [dict(r) for r in conn.execute("""SELECT r.*, g.first_name, g.last_name 
        FROM reservations r LEFT JOIN guests g ON r.guest_id=g.id 
        ORDER BY r.created_at DESC LIMIT 5""").fetchall()]
    
    # Restaurant
    try:
        s['restaurant_today'] = conn.execute("""SELECT COALESCE(SUM(total),0) FROM restaurant_orders 
            WHERE date(created_at)=date('now')""").fetchone()[0]
    except: s['restaurant_today'] = 0
    
    conn.close()
    return s


def get_occupancy_data():
    """7 derniers jours d'occupation pour le graphique."""
    conn = get_db()
    data = []
    for i in range(6, -1, -1):
        row = conn.execute("""SELECT COUNT(*) FROM reservations 
            WHERE status IN ('en_cours','terminee') 
            AND checkin_date <= date('now', ? || ' days') 
            AND checkout_date > date('now', ? || ' days')""", (f'-{i}', f'-{i}')).fetchone()
        data.append(row[0] if row else 0)
    conn.close()
    return data


# ======================== PERMISSIONS ========================

def migrate_permissions():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS role_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL, permission TEXT NOT NULL,
            UNIQUE(role, permission)
        );
    ''')
    conn.commit(); conn.close()

def init_default_permissions(default_perms):
    conn = get_db()
    for role, perms in default_perms.items():
        for p in perms:
            try: conn.execute("INSERT OR IGNORE INTO role_permissions (role, permission) VALUES (?,?)", (role, p))
            except: pass
    conn.commit(); conn.close()

def get_role_perms(role):
    conn = get_db()
    rows = conn.execute("SELECT permission FROM role_permissions WHERE role=?", (role,)).fetchall()
    conn.close()
    return [r['permission'] for r in rows]

def update_role_perms(role, perms):
    conn = get_db()
    conn.execute("DELETE FROM role_permissions WHERE role=?", (role,))
    for p in perms:
        conn.execute("INSERT INTO role_permissions (role, permission) VALUES (?,?)", (role, p))
    conn.commit(); conn.close()

def has_perm(role, permission):
    return permission in get_role_perms(role)

def delete_user(uid):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=? AND role != 'admin'", (uid,))
    conn.commit(); conn.close()


# ======================== RH MODULE ========================

def migrate_rh():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS rh_employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            matricule TEXT, first_name TEXT NOT NULL, last_name TEXT NOT NULL,
            email TEXT, tel TEXT, photo TEXT,
            birth_date TEXT, gender TEXT, nationality TEXT,
            position TEXT, department TEXT,
            hire_date TEXT, contract_type TEXT DEFAULT 'CDI',
            contract_end TEXT, salary REAL DEFAULT 0,
            cnps_number TEXT, insurance TEXT, insurance_number TEXT,
            emergency_contact TEXT, emergency_tel TEXT,
            bank_name TEXT, bank_account TEXT,
            status TEXT DEFAULT 'actif',
            notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS rh_leaves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER, leave_type TEXT DEFAULT 'annuel',
            start_date TEXT, end_date TEXT, days INTEGER DEFAULT 1,
            reason TEXT, status TEXT DEFAULT 'en_attente',
            approved_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES rh_employees(id)
        );
        CREATE TABLE IF NOT EXISTS rh_payslips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER, period TEXT,
            base_salary REAL DEFAULT 0,
            prime_transport REAL DEFAULT 0, prime_anciennete REAL DEFAULT 0,
            prime_logement REAL DEFAULT 0, prime_rendement REAL DEFAULT 0,
            heures_sup REAL DEFAULT 0, bonus REAL DEFAULT 0,
            avantages_nature REAL DEFAULT 0,
            salaire_brut REAL DEFAULT 0,
            cnps_employee REAL DEFAULT 0, assurance REAL DEFAULT 0,
            its REAL DEFAULT 0, avances REAL DEFAULT 0,
            autres_retenues REAL DEFAULT 0,
            total_retenues REAL DEFAULT 0,
            net_salary REAL DEFAULT 0,
            jours_travailles INTEGER DEFAULT 26,
            jours_absence INTEGER DEFAULT 0,
            mode_paiement TEXT DEFAULT 'virement',
            status TEXT DEFAULT 'brouillon',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES rh_employees(id)
        );
        CREATE TABLE IF NOT EXISTS rh_contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER, code TEXT,
            contract_type TEXT DEFAULT 'CDI',
            start_date TEXT, end_date TEXT,
            salary REAL DEFAULT 0, status TEXT DEFAULT 'actif',
            notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES rh_employees(id)
        );
        CREATE TABLE IF NOT EXISTS rh_trainings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT, description TEXT,
            trainer TEXT, department TEXT,
            date TEXT, duration TEXT, cost REAL DEFAULT 0,
            status TEXT DEFAULT 'planifie',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS rh_announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT, content TEXT,
            priority TEXT DEFAULT 'normale',
            created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit(); conn.close()

def get_rh_employees(status=None):
    conn = get_db()
    if status:
        rows = conn.execute("SELECT * FROM rh_employees WHERE status=? ORDER BY last_name", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM rh_employees ORDER BY last_name").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_rh_employee(eid):
    conn = get_db()
    e = conn.execute("SELECT * FROM rh_employees WHERE id=?", (eid,)).fetchone()
    conn.close()
    return dict(e) if e else None

def get_rh_stats():
    conn = get_db()
    s = {}
    s['total'] = conn.execute("SELECT COUNT(*) FROM rh_employees WHERE status='actif'").fetchone()[0]
    s['cdi'] = conn.execute("SELECT COUNT(*) FROM rh_employees WHERE contract_type='CDI' AND status='actif'").fetchone()[0]
    s['cdd'] = conn.execute("SELECT COUNT(*) FROM rh_employees WHERE contract_type='CDD' AND status='actif'").fetchone()[0]
    try: s['pending_leaves'] = conn.execute("SELECT COUNT(*) FROM rh_leaves WHERE status='en_attente'").fetchone()[0]
    except: s['pending_leaves'] = 0
    try: s['masse_salariale'] = conn.execute("SELECT COALESCE(SUM(salary),0) FROM rh_employees WHERE status='actif'").fetchone()[0]
    except: s['masse_salariale'] = 0
    conn.close()
    return s


# ======================== MIGRATIONS V4 ========================

def migrate_v4():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS qr_checkins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reservation_id INTEGER, token TEXT UNIQUE,
            guest_data_json TEXT, checked_in INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS night_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_date TEXT UNIQUE, rooms_occupied INTEGER DEFAULT 0,
            rooms_available INTEGER DEFAULT 0, occupancy_rate REAL DEFAULT 0,
            revenue_rooms REAL DEFAULT 0, revenue_restaurant REAL DEFAULT 0,
            revenue_other REAL DEFAULT 0, revenue_total REAL DEFAULT 0,
            checkins INTEGER DEFAULT 0, checkouts INTEGER DEFAULT 0,
            no_shows INTEGER DEFAULT 0, notes TEXT,
            created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS precheckin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reservation_id INTEGER, token TEXT UNIQUE,
            id_type TEXT, id_number TEXT, id_photo TEXT,
            arrival_time TEXT, special_requests TEXT,
            completed INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS loyalty_tiers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, min_points INTEGER DEFAULT 0,
            discount_percent REAL DEFAULT 0, benefits TEXT,
            color TEXT DEFAULT '#B8860B'
        );
        CREATE TABLE IF NOT EXISTS hotel_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE, value TEXT
        );
    ''')
    # Loyalty tiers defaults
    for name, pts, disc, color, benefits in [
        ('Bronze', 0, 0, '#CD7F32', 'Accueil personnalisé'),
        ('Silver', 500, 5, '#C0C0C0', 'Late checkout, -5% sur tarif'),
        ('Gold', 1500, 10, '#FFD700', 'Surclassement, -10%, petit-déj offert'),
        ('Platinum', 5000, 15, '#E5E4E2', 'Suite offerte, -15%, spa gratuit')
    ]:
        try: conn.execute("INSERT OR IGNORE INTO loyalty_tiers (name, min_points, discount_percent, color, benefits) VALUES (?,?,?,?,?)",
                         (name, pts, disc, color, benefits))
        except: pass
    conn.commit(); conn.close()


def run_night_audit(user_id):
    """Exécute l'audit de nuit et retourne le résumé."""
    conn = get_db()
    today = datetime.now().strftime('%Y-%m-%d')
    
    # Check if already done
    existing = conn.execute("SELECT id FROM night_audits WHERE audit_date=?", (today,)).fetchone()
    if existing:
        conn.close()
        return None, "Audit déjà effectué pour aujourd'hui"
    
    rooms_total = conn.execute("SELECT COUNT(*) FROM rooms").fetchone()[0]
    rooms_occ = conn.execute("SELECT COUNT(*) FROM rooms WHERE status='occupee'").fetchone()[0]
    rooms_avail = conn.execute("SELECT COUNT(*) FROM rooms WHERE status='disponible'").fetchone()[0]
    occ_rate = round(rooms_occ * 100 / max(rooms_total, 1), 1)
    
    rev_rooms = conn.execute("""SELECT COALESCE(SUM(total),0) FROM charges 
        WHERE category='hebergement' AND date(created_at)=?""", (today,)).fetchone()[0]
    rev_resto = conn.execute("""SELECT COALESCE(SUM(total),0) FROM restaurant_orders 
        WHERE date(created_at)=?""", (today,)).fetchone()[0]
    rev_other = conn.execute("""SELECT COALESCE(SUM(total),0) FROM charges 
        WHERE category NOT IN ('hebergement','restaurant') AND date(created_at)=?""", (today,)).fetchone()[0]
    
    checkins = conn.execute("""SELECT COUNT(*) FROM reservations 
        WHERE status='en_cours' AND checkin_date=?""", (today,)).fetchone()[0]
    checkouts = conn.execute("""SELECT COUNT(*) FROM reservations 
        WHERE status='terminee' AND checkout_date=?""", (today,)).fetchone()[0]
    
    conn.execute("""INSERT INTO night_audits 
        (audit_date, rooms_occupied, rooms_available, occupancy_rate,
         revenue_rooms, revenue_restaurant, revenue_other, revenue_total,
         checkins, checkouts, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (today, rooms_occ, rooms_avail, occ_rate,
         rev_rooms, rev_resto, rev_other, rev_rooms + rev_resto + rev_other,
         checkins, checkouts, user_id))
    conn.commit()
    
    audit = conn.execute("SELECT * FROM night_audits WHERE audit_date=?", (today,)).fetchone()
    conn.close()
    return dict(audit), "OK"


def get_guest_loyalty(guest_id):
    """Retourne le niveau fidélité d'un client."""
    conn = get_db()
    points = conn.execute("SELECT COALESCE(SUM(points),0) FROM loyalty_points WHERE guest_id=?", (guest_id,)).fetchone()[0]
    tiers = conn.execute("SELECT * FROM loyalty_tiers ORDER BY min_points DESC").fetchall()
    conn.close()
    current_tier = {'name': 'Bronze', 'color': '#CD7F32', 'discount_percent': 0, 'benefits': ''}
    for t in tiers:
        if points >= t['min_points']:
            current_tier = dict(t)
            break
    return {'points': points, 'tier': current_tier}


def get_hotel_setting(key, default=''):
    conn = get_db()
    r = conn.execute("SELECT value FROM hotel_settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return r['value'] if r else default

def set_hotel_setting(key, value):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO hotel_settings (key, value) VALUES (?,?)", (key, value))
    conn.commit(); conn.close()


def get_advanced_stats():
    """Statistiques avancées pour le rapport."""
    conn = get_db()
    s = {}
    # Monthly revenue (12 months)
    s['monthly_revenue'] = [dict(r) for r in conn.execute("""
        SELECT strftime('%Y-%m', created_at) as month, SUM(amount) as total
        FROM payments GROUP BY month ORDER BY month DESC LIMIT 12""").fetchall()]
    # Occupancy by day of week
    s['occ_by_day'] = [dict(r) for r in conn.execute("""
        SELECT CASE CAST(strftime('%w', checkin_date) AS INTEGER)
            WHEN 0 THEN 'Dim' WHEN 1 THEN 'Lun' WHEN 2 THEN 'Mar' WHEN 3 THEN 'Mer'
            WHEN 4 THEN 'Jeu' WHEN 5 THEN 'Ven' WHEN 6 THEN 'Sam' END as day,
            COUNT(*) as count FROM reservations WHERE status IN ('en_cours','terminee')
            GROUP BY strftime('%w', checkin_date) ORDER BY strftime('%w', checkin_date)""").fetchall()]
    # Revenue by room type
    s['rev_by_type'] = [dict(r) for r in conn.execute("""
        SELECT rt.name, COALESCE(SUM(c.total),0) as revenue
        FROM charges c JOIN reservations r ON c.reservation_id=r.id
        JOIN rooms rm ON r.room_id=rm.id JOIN room_types rt ON rm.room_type_id=rt.id
        GROUP BY rt.name ORDER BY revenue DESC""").fetchall()]
    # Source de réservation
    s['by_source'] = [dict(r) for r in conn.execute("""
        SELECT source, COUNT(*) as count FROM reservations GROUP BY source ORDER BY count DESC""").fetchall()]
    # Average stay
    s['avg_stay'] = conn.execute("SELECT AVG(nights) FROM reservations WHERE nights > 0").fetchone()[0] or 0
    # Total revenue
    s['total_revenue'] = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments").fetchone()[0]
    # Night audits
    s['audits'] = [dict(r) for r in conn.execute("SELECT * FROM night_audits ORDER BY audit_date DESC LIMIT 30").fetchall()]
    conn.close()
    return s


# ======================== LICENCE SYSTEM ========================

LICENSE_FEATURES = {
    'starter': {
        'label': 'Starter',
        'max_rooms': 15,
        'max_users': 3,
        'features': ['dashboard', 'reservations', 'chambres', 'guests', 'housekeeping',
                     'stock', 'events', 'rapports', 'payment_mobile', 'booking_online',
                     'invoice', 'notification'],
        'price': '19 900 F/mois'
    },
    'pro': {
        'label': 'Pro',
        'max_rooms': 50,
        'max_users': 10,
        'features': ['dashboard', 'reservations', 'chambres', 'guests', 'housekeeping',
                     'stock', 'events', 'rapports', 'payment_mobile', 'booking_online',
                     'invoice', 'notification',
                     'restaurant', 'rh', 'night_audit', 'qr_checkin',
                     'loyalty', 'whatsapp', 'precheckin'],
        'price': '49 900 F/mois'
    },
    'business': {
        'label': 'Business',
        'max_rooms': 200,
        'max_users': 50,
        'features': ['dashboard', 'reservations', 'chambres', 'guests', 'housekeeping',
                     'stock', 'events', 'rapports', 'payment_mobile', 'booking_online',
                     'invoice', 'notification',
                     'restaurant', 'rh', 'night_audit', 'qr_checkin',
                     'loyalty', 'whatsapp', 'precheckin',
                     'stats', 'export_comptable', 'theme', 'planning',
                     'reviews', 'multi_users'],
        'price': '99 900 F/mois'
    },
    'enterprise': {
        'label': 'Enterprise',
        'max_rooms': 99999,
        'max_users': 99999,
        'features': '__all__',
        'price': 'Sur devis'
    }
}

def get_license():
    """Retourne la licence active."""
    key = get_hotel_setting('license_key', '')
    tier = get_hotel_setting('license_tier', '')
    trial_start = get_hotel_setting('trial_start', '')
    
    # First use: start 72h trial
    if not tier and not trial_start:
        set_hotel_setting('trial_start', datetime.now().isoformat())
        set_hotel_setting('license_tier', 'trial')
        tier = 'trial'
        trial_start = datetime.now().isoformat()
    
    # Check trial expiration
    if tier == 'trial' and trial_start:
        try:
            start = datetime.fromisoformat(trial_start)
            remaining = timedelta(hours=72) - (datetime.now() - start)
            if remaining.total_seconds() <= 0:
                # Trial expired → downgrade to starter
                set_hotel_setting('license_tier', 'starter')
                tier = 'starter'
            else:
                hours_left = int(remaining.total_seconds() // 3600)
                return {
                    'key': '', 'tier': 'trial',
                    'config': LICENSE_FEATURES['enterprise'],  # All features during trial
                    'label': f'Essai gratuit ({hours_left}h restantes)',
                    'is_trial': True, 'hours_left': hours_left,
                    'trial_expired': False
                }
        except:
            tier = 'starter'
    
    if tier not in LICENSE_FEATURES:
        tier = 'starter'
    return {
        'key': key, 'tier': tier,
        'config': LICENSE_FEATURES[tier],
        'label': LICENSE_FEATURES[tier]['label'],
        'is_trial': False, 'hours_left': 0,
        'trial_expired': tier == 'starter' and trial_start != ''
    }

def check_feature(feature):
    """Vérifie si une fonctionnalité est disponible dans la licence."""
    lic = get_license()
    if lic['config']['features'] == '__all__':
        return True
    return feature in lic['config']['features']

def check_room_limit():
    """Vérifie si la limite de chambres est atteinte."""
    lic = get_license()
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM rooms").fetchone()[0]
    conn.close()
    return count < lic['config']['max_rooms'], lic['config']['max_rooms'], count

def check_user_limit():
    """Vérifie si la limite d'utilisateurs est atteinte."""
    lic = get_license()
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return count < lic['config']['max_users'], lic['config']['max_users'], count

def activate_license(key):
    """Active une licence par clé. Retourne le tier ou None."""
    import hashlib as _hl
    key = key.upper().strip()
    
    # Demo keys
    demo_keys = {
        'WANNY-STARTER-2026': 'starter',
        'WANNY-PRO-2026': 'pro',
        'WANNY-BUSINESS-2026': 'business',
        'WANNY-ENTERPRISE-2026': 'enterprise',
    }
    tier = demo_keys.get(key)
    if tier:
        set_hotel_setting('license_key', key)
        set_hotel_setting('license_tier', tier)
        return tier
    
    # Generated keys: WH-{TIER}-{CODE}-{CHECK}
    parts = key.split('-')
    if len(parts) == 4 and parts[0] == 'WH':
        tier_map = {'S': 'starter', 'P': 'pro', 'B': 'business', 'E': 'enterprise'}
        tier_code = parts[1]
        code = parts[2]
        check = parts[3]
        expected = _hl.md5(f"WH-{tier_code}-{code}".encode()).hexdigest()[:4].upper()
        if check == expected and tier_code in tier_map:
            tier = tier_map[tier_code]
            set_hotel_setting('license_key', key)
            set_hotel_setting('license_tier', tier)
            return tier
    
    # Simple format: WH-{TIER}-{CODE} (backward compat)
    if len(parts) == 3 and parts[0] == 'WH':
        tier_map = {'S': 'starter', 'P': 'pro', 'B': 'business', 'E': 'enterprise'}
        tier = tier_map.get(parts[1])
        if tier:
            set_hotel_setting('license_key', key)
            set_hotel_setting('license_tier', tier)
            return tier
    
    return None


# ======================== CLIENT PORTAL V2 ========================

def migrate_client_v2():
    conn = get_db()
    for col, typ in [('photo', 'TEXT'), ('address', 'TEXT'), ('birth_date', 'TEXT'), ('gender', 'TEXT')]:
        try: conn.execute(f"ALTER TABLE guests ADD COLUMN {col} {typ} DEFAULT ''")
        except: pass
    conn.commit(); conn.close()

def mark_notification_read(notif_id):
    conn = get_db()
    conn.execute("UPDATE notifications SET read=1 WHERE id=?", (notif_id,))
    conn.commit(); conn.close()

def get_guest_unread_count(guest_id):
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM notifications WHERE guest_id=? AND read=0", (guest_id,)).fetchone()[0]
    conn.close()
    return count

def get_client_stats(guest_id):
    conn = get_db()
    s = {}
    s['total_reservations'] = conn.execute("SELECT COUNT(*) FROM reservations WHERE guest_id=?", (guest_id,)).fetchone()[0]
    s['active'] = conn.execute("SELECT COUNT(*) FROM reservations WHERE guest_id=? AND status='en_cours'", (guest_id,)).fetchone()[0]
    s['total_nights'] = conn.execute("SELECT COALESCE(SUM(nights),0) FROM reservations WHERE guest_id=?", (guest_id,)).fetchone()[0]
    s['total_spent'] = conn.execute("""SELECT COALESCE(SUM(p.amount),0) FROM payments p 
        JOIN reservations r ON p.reservation_id=r.id WHERE r.guest_id=?""", (guest_id,)).fetchone()[0]
    s['total_charges'] = conn.execute("""SELECT COALESCE(SUM(c.total),0) FROM charges c 
        JOIN reservations r ON c.reservation_id=r.id WHERE r.guest_id=?""", (guest_id,)).fetchone()[0]
    s['balance'] = s['total_charges'] - s['total_spent']
    s['unread_notifs'] = conn.execute("SELECT COUNT(*) FROM notifications WHERE guest_id=? AND read=0", (guest_id,)).fetchone()[0]
    conn.close()
    return s
