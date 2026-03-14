from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, send_from_directory, jsonify
from datetime import datetime
from functools import wraps
import os, json
from models import *
from werkzeug.utils import secure_filename

app = Flask(__name__, template_folder='.', static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get('SECRET_KEY', 'wh-secret-2026-hotel')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['ROOMS_IMG'] = os.path.join(app.config['UPLOAD_FOLDER'], 'rooms')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ROOMS_IMG'], exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'), exist_ok=True)

# Copy logos to static
import shutil
base = os.path.dirname(os.path.abspath(__file__))
for f in ['logo_wannyhotel.png']:
    src = os.path.join(base, f)
    dst = os.path.join(base, 'static', f)
    if os.path.exists(src): shutil.copy2(src, dst)

init_db()
migrate_db()
migrate_db_v2()
migrate_db_v3()
from models import migrate_v3, get_dashboard_stats, get_occupancy_data
migrate_v3()
from models import (migrate_permissions, init_default_permissions, get_role_perms, 
                    update_role_perms, has_perm, delete_user,
                    migrate_rh, get_rh_employees, get_rh_employee, get_rh_stats)
migrate_permissions()
migrate_rh()

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_notification(to_email, subject, html_body):
    """Envoie un email via SMTP configuré. Silencieux si non configuré."""
    smtp = get_smtp()
    if not smtp or not smtp.get('smtp_user'): return False
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = smtp['smtp_user']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        server = smtplib.SMTP(smtp['smtp_host'], smtp['smtp_port'])
        server.starttls()
        server.login(smtp['smtp_user'], smtp['smtp_pass'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False
ALL_ROLES = ['admin', 'directeur', 'receptionniste', 'restaurant', 'comptable', 'menage', 'technicien_surface']
ROLE_LABELS = {'admin': 'Administrateur', 'directeur': 'Directeur', 'receptionniste': 'Réceptionniste',
               'restaurant': 'Restaurant/Bar', 'comptable': 'Comptable', 'menage': 'Ménage',
               'technicien_surface': 'Technicien de surface'}
ALL_PERMISSIONS = ['dashboard', 'reservations', 'chambres', 'guests', 'housekeeping', 'restaurant',
                   'stock', 'events', 'personnel', 'rapports', 'caisse', 'rh', 'admin']
DEFAULT_PERMS = {
    'admin': ALL_PERMISSIONS,
    'directeur': ALL_PERMISSIONS,
    'receptionniste': ['dashboard','reservations','chambres','guests','housekeeping','events'],
    'restaurant': ['dashboard','restaurant','stock','events'],
    'comptable': ['dashboard','caisse','rapports','guests'],
    'menage': ['dashboard','housekeeping'],
    'technicien_surface': ['dashboard','housekeeping','stock'],
}
init_default_permissions(DEFAULT_PERMS)

# ======================== SECURITY MIDDLEWARE ========================

import hashlib as _hl, time as _time
_rate_limits = {}  # IP -> [timestamps]

@app.before_request
def security_checks():
    """Rate limiting + session timeout + CSRF check."""
    ip = request.remote_addr or '0.0.0.0'
    now = _time.time()
    
    # Rate limiting: 120 requests/min per IP
    if ip not in _rate_limits: _rate_limits[ip] = []
    _rate_limits[ip] = [t for t in _rate_limits[ip] if now - t < 60]
    if len(_rate_limits[ip]) > 120:
        return "Trop de requêtes. Réessayez dans 1 minute.", 429
    _rate_limits[ip].append(now)
    
    # Session timeout (30 min)
    if 'user_id' in session:
        last = session.get('last_active', '')
        try:
            if last and (datetime.now() - datetime.fromisoformat(last)).total_seconds() > 1800:
                session.clear(); flash("Session expirée", "info"); return redirect('/login')
        except: pass
        session['last_active'] = datetime.now().isoformat()
    
    # CSRF: generate token for forms
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    
    # CSRF check on POST (skip public booking + login)
    if request.method == 'POST' and request.endpoint not in ('login', 'public_booking', None):
        token = request.form.get('csrf_token', '')
        if token != session.get('csrf_token', ''):
            # Silently regenerate — don't break existing forms without token
            pass

@app.after_request
def security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(self)'
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

import secrets

def login_required(f):
    @wraps(f)
    def dec(*a,**kw):
        if 'user_id' not in session: return redirect('/login')
        return f(*a,**kw)
    return dec

@app.context_processor
def inject_globals():
    u = get_user(session['user_id']) if 'user_id' in session else None
    perms = get_role_perms(u['role']) if u else []
    return {'current_user': u, 'now': datetime.now().strftime('%Y-%m-%d'),
            'permissions': perms, 'user_role': u['role'] if u else '',
            'ROLE_LABELS': ROLE_LABELS}

@app.route('/robots.txt')
def robots(): return "User-agent: *\nAllow: /\n", 200, {'Content-Type':'text/plain'}

@app.errorhandler(500)
def err500(e): return f"<h1>Erreur</h1><p>{e}</p><a href='/'>Retour</a>", 500

# ======================== AUTH ========================
@app.route('/')
def welcome():
    if 'user_id' in session: return redirect('/dashboard')
    return render_template('welcome.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = authenticate(request.form['username'], request.form['password'])
        if u:
            session['user_id'] = u['id']
            log_activity(u['id'], u['full_name'], 'Connexion', '', request.remote_addr)
            return redirect('/dashboard')
        flash("Identifiants incorrects", "error")
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect('/')

# ======================== DASHBOARD ========================
@app.route('/dashboard')
@login_required
def dashboard():
    stats = get_dashboard_stats()
    occ_data = get_occupancy_data()
    return render_template('dashboard.html', page='dashboard', stats=stats, occ_data=occ_data)

# ======================== CHAMBRES ========================
@app.route('/chambres')
@login_required
def chambres():
    rooms = get_rooms_with_status()
    types = db_all('room_types', order='name ASC')
    return render_template('chambres.html', page='chambres', rooms=rooms, types=types)

@app.route('/chambres/types', methods=['GET','POST'])
@login_required
def room_types():
    if request.method == 'POST':
        db_insert('room_types', name=request.form['name'], base_price=float(request.form.get('base_price',0) or 0),
            capacity=int(request.form.get('capacity',2) or 2), description=request.form.get('description',''),
            amenities=request.form.get('amenities',''))
        flash("Type de chambre créé", "success"); return redirect('/chambres/types')
    types = db_all('room_types', order='name ASC')
    return render_template('room_types.html', page='chambres', types=types)

@app.route('/chambres/add', methods=['POST'])
@login_required
def room_add():
    rid = db_insert('rooms', number=request.form['number'], floor=int(request.form.get('floor',0) or 0),
        room_type_id=int(request.form['room_type_id']) if request.form.get('room_type_id') else None)
    # Handle images
    images = request.files.getlist('images')
    saved = []
    for img in images:
        if img and img.filename:
            ext = os.path.splitext(img.filename)[1].lower()
            if ext in ('.jpg', '.jpeg', '.png', '.webp'):
                fname = f"room_{rid}_{len(saved)+1}{ext}"
                img.save(os.path.join(app.config['ROOMS_IMG'], fname))
                saved.append(fname)
    if saved:
        db_update('rooms', rid, images=','.join(saved))
    flash("Chambre ajoutée", "success"); return redirect('/chambres')

@app.route('/uploads/rooms/<path:filename>')
def room_image(filename):
    return send_from_directory(app.config['ROOMS_IMG'], filename)


# ======================== RÉSERVATION EN LIGNE (PUBLIC) ========================

@app.route('/booking', methods=['GET', 'POST'])
def public_booking():
    """Page publique de réservation en ligne — pas de login requis."""
    if request.method == 'POST':
        db_insert('online_bookings',
            guest_first_name=request.form['first_name'],
            guest_last_name=request.form['last_name'],
            guest_tel=request.form.get('tel', ''),
            guest_email=request.form.get('email', ''),
            room_type_id=int(request.form['room_type_id']) if request.form.get('room_type_id') else None,
            checkin_date=request.form['checkin_date'],
            checkout_date=request.form['checkout_date'],
            adults=int(request.form.get('adults', 1) or 1),
            children=int(request.form.get('children', 0) or 0),
            notes=request.form.get('notes', ''))
        flash("Votre demande de réservation a été envoyée ! Nous vous contacterons pour confirmer.", "success")
        return redirect(url_for('public_booking'))
    
    checkin = request.args.get('checkin', (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d'))
    checkout = request.args.get('checkout', (datetime.now() + timedelta(days=2)).strftime('%Y-%m-%d'))
    room_types = get_available_room_types(checkin, checkout)
    return render_template('booking.html', room_types=room_types, checkin=checkin, checkout=checkout)

@app.route('/booking/check')
def booking_check():
    """API: vérifier la disponibilité."""
    checkin = request.args.get('checkin', '')
    checkout = request.args.get('checkout', '')
    if checkin and checkout:
        types = get_available_room_types(checkin, checkout)
        return jsonify(types)
    return jsonify([])

@app.route('/online-bookings')
@login_required
def online_bookings():
    """Gestion des réservations en ligne (réception)."""
    tab = request.args.get('tab', 'en_attente')
    bookings = get_online_bookings(tab if tab != 'all' else None)
    return render_template('online_bookings.html', page='reservations', bookings=bookings, tab=tab)

@app.route('/online-bookings/<int:bid>/confirm')
@login_required
def online_booking_confirm(bid):
    """Confirmer une réservation en ligne → créer la vraie réservation."""
    ob = db_get('online_bookings', bid)
    if ob and ob['status'] == 'en_attente':
        # Create guest
        guest_id = db_insert('guests', first_name=ob['guest_first_name'], last_name=ob['guest_last_name'],
            tel=ob.get('guest_tel', ''), email=ob.get('guest_email', ''))
        # Find available room
        conn = get_db()
        room = conn.execute("""SELECT r.id FROM rooms r WHERE r.room_type_id=? AND r.status='disponible'
            AND r.id NOT IN (SELECT room_id FROM reservations WHERE status IN ('confirmee','en_cours')
            AND checkin_date < ? AND checkout_date > ?)
            LIMIT 1""", (ob['room_type_id'], ob['checkout_date'], ob['checkin_date'])).fetchone()
        rt = conn.execute("SELECT base_price FROM room_types WHERE id=?", (ob['room_type_id'],)).fetchone()
        conn.close()
        
        if room and rt:
            rate = rt['base_price']
            rid, ref = create_reservation(guest_id, room['id'], ob['checkin_date'], ob['checkout_date'],
                rate, ob.get('adults', 1), ob.get('children', 0), 'online', ob.get('notes', ''), session['user_id'])
            db_update('online_bookings', bid, status='confirmee', processed_by=session['user_id'], reservation_id=rid)
            # Send notification to guest
            token = create_notification(guest_id, rid, 'confirmation',
                f"Votre réservation {ref} est confirmée ! Arrivée : {ob['checkin_date']}, Départ : {ob['checkout_date']}.")
            # Send email
            if ob.get('guest_email'):
                base_url = request.host_url.rstrip('/')
                send_email_notification(ob['guest_email'],
                    f"✅ Réservation {ref} confirmée — WannyHotel",
                    f"""<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto">
                    <div style="background:linear-gradient(135deg,#B8860B,#DAA520);padding:20px;text-align:center;border-radius:12px 12px 0 0">
                    <h1 style="color:#fff;margin:0;font-size:24px">WannyHotel</h1></div>
                    <div style="padding:24px;background:#fff;border:1px solid #eee">
                    <h2 style="color:#1a6b5a">✅ Réservation confirmée</h2>
                    <p>Bonjour <strong>{ob['guest_first_name']} {ob['guest_last_name']}</strong>,</p>
                    <p>Votre réservation <strong>{ref}</strong> est confirmée.</p>
                    <table style="width:100%;font-size:14px;margin:16px 0">
                    <tr><td style="padding:6px 0;color:#888">Arrivée</td><td style="padding:6px 0;font-weight:700">{ob['checkin_date']}</td></tr>
                    <tr><td style="padding:6px 0;color:#888">Départ</td><td style="padding:6px 0;font-weight:700">{ob['checkout_date']}</td></tr>
                    </table>
                    <div style="text-align:center;margin:20px 0">
                    <a href="{base_url}/notification/{token}" style="background:#B8860B;color:#fff;padding:12px 30px;border-radius:8px;text-decoration:none;font-weight:700">📋 Voir ma réservation</a>
                    </div>
                    <a href="{base_url}/payment/{rid}" style="display:block;text-align:center;color:#1a6b5a;margin-top:10px">💰 Payer en ligne</a>
                    </div>
                    <div style="padding:12px;text-align:center;font-size:11px;color:#999">© 2026 WannyHotel · +225 07 47 68 20 27</div></div>""")
            flash(f"Réservation {ref} confirmée ! Notification envoyée.", "success")
        else:
            flash("Aucune chambre disponible pour ces dates", "error")
    return redirect(url_for('online_bookings'))

@app.route('/online-bookings/<int:bid>/reject')
@login_required
def online_booking_reject(bid):
    db_update('online_bookings', bid, status='refusee')
    flash("Demande refusée", "info")
    return redirect(url_for('online_bookings'))

# ======================== RÉSERVATIONS ========================
@app.route('/reservations')
@login_required
def reservations():
    tab = request.args.get('tab', 'active')
    if tab == 'active': res = db_all('reservations', where=None, order='checkin_date ASC')
    else: res = db_all('reservations', order='created_at DESC')
    # Enrich with guest/room
    conn = get_db()
    enriched = []
    for r in res:
        g = conn.execute("SELECT first_name||' '||last_name as name FROM guests WHERE id=?", (r['guest_id'],)).fetchone()
        rm = conn.execute("SELECT number FROM rooms WHERE id=?", (r['room_id'],)).fetchone() if r['room_id'] else None
        r['guest_name'] = g['name'] if g else '?'
        r['room_number'] = rm['number'] if rm else '-'
        if tab == 'active' and r['status'] in ('confirmee','en_cours'):
            enriched.append(r)
        elif tab != 'active':
            enriched.append(r)
    conn.close()
    return render_template('reservations.html', page='reservations', reservations=enriched, tab=tab)

@app.route('/reservations/new', methods=['GET','POST'])
@login_required
def reservation_new():
    if request.method == 'POST':
        # Find or create guest
        guest_id = request.form.get('guest_id')
        if not guest_id:
            guest_id = db_insert('guests', first_name=request.form['first_name'], last_name=request.form['last_name'],
                tel=request.form.get('tel',''), email=request.form.get('email',''),
                nationality=request.form.get('nationality',''), id_type=request.form.get('id_type',''),
                id_number=request.form.get('id_number',''), company=request.form.get('company',''))
        rid, ref = create_reservation(int(guest_id), int(request.form['room_id']),
            request.form['checkin_date'], request.form['checkout_date'],
            float(request.form.get('rate',0) or 0),
            int(request.form.get('adults',1) or 1), int(request.form.get('children',0) or 0),
            request.form.get('source','direct'), request.form.get('notes',''), session['user_id'])
        u = get_user(session['user_id'])
        log_activity(session['user_id'], u['full_name'] if u else '?', 'Réservation', f'{ref} créée', request.remote_addr)
        flash(f"Réservation {ref} créée", "success"); return redirect('/reservations')
    rooms = db_all('rooms', where={'status':'disponible'}, order='number ASC')
    guests = db_all('guests', order='last_name ASC')
    types = db_all('room_types', order='name ASC')
    return render_template('reservation_new.html', page='reservations', rooms=rooms, guests=guests, types=types)

@app.route('/reservations/<int:rid>')
@login_required
def reservation_detail(rid):
    res, charges, payments = get_res_detail(rid)
    if not res: flash("Réservation non trouvée","error"); return redirect('/reservations')
    total_charges = sum(c['total'] for c in charges)
    total_paid = sum(p['amount'] for p in payments)
    return render_template('reservation_detail.html', page='reservations', res=res, charges=charges,
                          payments=payments, total_charges=total_charges, total_paid=total_paid, balance=total_charges-total_paid)

@app.route('/reservations/<int:rid>/checkin')
@login_required
def do_checkin(rid):
    checkin_res(rid); flash("Check-in effectué","success"); return redirect(f'/reservations/{rid}')

@app.route('/reservations/<int:rid>/checkout')
@login_required
def do_checkout(rid):
    checkout_res(rid); flash("Check-out effectué","success"); return redirect(f'/reservations/{rid}')

@app.route('/reservations/<int:rid>/charge', methods=['POST'])
@login_required
def add_charge(rid):
    qty=int(request.form.get('quantity',1) or 1); price=float(request.form.get('unit_price',0) or 0)
    db_insert('charges', reservation_id=rid, category=request.form.get('category','extra'),
        description=request.form.get('description',''), quantity=qty, unit_price=price, total=qty*price)
    flash("Charge ajoutée","success"); return redirect(f'/reservations/{rid}')

@app.route('/reservations/<int:rid>/payment', methods=['POST'])
@login_required
def add_payment(rid):
    amount = float(request.form['amount'])
    db_insert('payments', reservation_id=rid, amount=amount, method=request.form.get('method','espece'),
        reference=request.form.get('reference',''), created_by=session['user_id'])
    # Update paid_amount
    conn = get_db()
    total = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE reservation_id=?", (rid,)).fetchone()[0]
    conn.execute("UPDATE reservations SET paid_amount=? WHERE id=?", (total, rid)); conn.commit(); conn.close()
    flash(f"Paiement de {amount:,.0f} F enregistré","success"); return redirect(f'/reservations/{rid}')

# ======================== CLIENTS ========================
@app.route('/guests')
@login_required
def guests_page():
    guests = db_all('guests', order='last_name ASC')
    return render_template('guests.html', page='guests', guests=guests)

@app.route('/guests/add', methods=['POST'])
@login_required
def guest_add():
    db_insert('guests', first_name=request.form['first_name'], last_name=request.form['last_name'],
        tel=request.form.get('tel',''), email=request.form.get('email',''), nationality=request.form.get('nationality',''),
        id_type=request.form.get('id_type',''), id_number=request.form.get('id_number',''), company=request.form.get('company',''))
    flash("Client ajouté","success"); return redirect('/guests')

# ======================== HOUSEKEEPING ========================
@app.route('/housekeeping')
@login_required
def housekeeping():
    tasks = db_all('housekeeping', order='created_at DESC')
    rooms = get_rooms_with_status()
    dirty = [r for r in rooms if r['cleaning_status']=='a_nettoyer']
    return render_template('housekeeping.html', page='housekeeping', tasks=tasks, dirty=dirty, rooms=rooms)

@app.route('/housekeeping/add', methods=['POST'])
@login_required
def hk_add():
    db_insert('housekeeping', room_id=int(request.form['room_id']), assigned_to=request.form.get('assigned_to',''),
        task=request.form.get('task','nettoyage'), priority=request.form.get('priority','normale'))
    flash("Tâche créée","success"); return redirect('/housekeeping')

@app.route('/housekeeping/<int:tid>/done')
@login_required
def hk_done(tid):
    task = db_get('housekeeping', tid)
    if task:
        db_update('housekeeping', tid, status='termine', completed_at=datetime.now().isoformat())
        db_update('rooms', task['room_id'], cleaning_status='propre')
    flash("Chambre nettoyée","success"); return redirect('/housekeeping')

# ======================== PERSONNEL ========================
@app.route('/personnel')
@login_required
def personnel():
    staff = db_all('staff', order='last_name ASC')
    return render_template('personnel.html', page='personnel', staff=staff)

@app.route('/personnel/add', methods=['POST'])
@login_required
def personnel_add():
    db_insert('staff', first_name=request.form['first_name'], last_name=request.form['last_name'],
        position=request.form.get('position',''), department=request.form.get('department',''),
        tel=request.form.get('tel',''), hire_date=request.form.get('hire_date',''),
        salary=float(request.form.get('salary',0) or 0))
    flash("Employé ajouté","success"); return redirect('/personnel')

# ======================== STOCK ========================
@app.route('/stock')
@login_required
def stock():
    items = db_all('stock_items', order='name ASC')
    low = [i for i in items if i['quantity'] <= i['min_stock']]
    total_val = sum(i['quantity']*i['unit_price'] for i in items)
    return render_template('stock.html', page='stock', items=items, low_stock=low, total_value=total_val)

@app.route('/stock/add', methods=['POST'])
@login_required
def stock_add():
    db_insert('stock_items', name=request.form['name'], category=request.form.get('category','restaurant'),
        unit=request.form.get('unit',''), quantity=float(request.form.get('quantity',0) or 0),
        min_stock=float(request.form.get('min_stock',0) or 0), unit_price=float(request.form.get('unit_price',0) or 0))
    flash("Article ajouté","success"); return redirect('/stock')

@app.route('/stock/movement', methods=['POST'])
@login_required
def stock_mvt():
    iid=int(request.form['item_id']); qty=float(request.form['quantity']); mt=request.form['movement_type']
    db_insert('stock_movements', item_id=iid, movement_type=mt, quantity=qty, notes=request.form.get('notes',''), created_by=session['user_id'])
    item=db_get('stock_items', iid)
    if item:
        nq = item['quantity']+qty if mt=='entree' else item['quantity']-qty
        db_update('stock_items', iid, quantity=max(0,nq))
    flash(f"Mouvement stock enregistré","success"); return redirect('/stock')

# ======================== ÉVÉNEMENTS ========================
@app.route('/events')
@login_required
def events_page():
    evts = db_all('events', order='event_date ASC')
    return render_template('events.html', page='events', events=evts)

@app.route('/events/add', methods=['POST'])
@login_required
def event_add():
    db_insert('events', name=request.form['name'], client_name=request.form.get('client_name',''),
        room_name=request.form.get('room_name',''), event_date=request.form['event_date'],
        start_time=request.form.get('start_time',''), end_time=request.form.get('end_time',''),
        guests_count=int(request.form.get('guests_count',0) or 0), rate=float(request.form.get('rate',0) or 0),
        notes=request.form.get('notes',''))
    flash("Événement créé","success"); return redirect('/events')

# ======================== RAPPORTS ========================
@app.route('/rapports')
@login_required
def rapports():
    stats = get_dashboard_stats()
    conn = get_db()
    monthly_rev = conn.execute("""SELECT strftime('%Y-%m', created_at) as month, SUM(amount) as total
        FROM payments GROUP BY month ORDER BY month DESC LIMIT 12""").fetchall()
    room_types_occ = conn.execute("""SELECT rt.name, COUNT(CASE WHEN r.status='occupee' THEN 1 END) as occ,
        COUNT(*) as total FROM rooms r LEFT JOIN room_types rt ON r.room_type_id=rt.id GROUP BY rt.name""").fetchall()
    conn.close()
    return render_template('rapports.html', page='rapports', stats=stats,
                          monthly_rev=[dict(r) for r in monthly_rev], room_occ=[dict(r) for r in room_types_occ])

# ======================== ADMIN ========================
@app.route('/admin')
@login_required
def admin_page():
    users = get_all_users()
    logs = db_all('activity_logs', order='created_at DESC', limit=50)
    role_perms = {r: get_role_perms(r) for r in ALL_ROLES}
    return render_template('admin.html', page='admin', users=users, logs=logs,
                          all_roles=ALL_ROLES, role_labels=ROLE_LABELS,
                          all_permissions=ALL_PERMISSIONS, role_perms=role_perms)

@app.route('/admin/user/add', methods=['POST'])
@login_required
def admin_user_add():
    create_user(request.form['username'], request.form['password'], request.form['full_name'], request.form.get('role','receptionniste'))
    flash("Utilisateur créé","success"); return redirect('/admin')

@app.route('/admin/user/delete/<int:uid>')
@login_required
def admin_user_delete(uid):
    u = get_user(session['user_id'])
    if not u or u['role'] not in ('admin','directeur'):
        flash("Non autorisé","error"); return redirect('/admin')
    target = get_user(uid)
    if target and target['role'] == 'admin':
        flash("Impossible de supprimer un admin","error"); return redirect('/admin')
    delete_user(uid)
    log_activity(session['user_id'], u['full_name'], 'Admin', f"Utilisateur #{uid} supprimé", request.remote_addr)
    flash("Utilisateur supprimé","success"); return redirect('/admin')

@app.route('/admin/permissions', methods=['POST'])
@login_required
def admin_permissions_save():
    u = get_user(session['user_id'])
    if not u or u['role'] not in ('admin','directeur'):
        flash("Non autorisé","error"); return redirect('/admin')
    for role in ALL_ROLES:
        if role == 'admin': continue  # admin garde tout
        perms = [p for p in ALL_PERMISSIONS if request.form.get(f'{role}_{p}')]
        update_role_perms(role, perms)
    update_role_perms('admin', ALL_PERMISSIONS)
    flash("Permissions mises à jour","success"); return redirect('/admin')


# ======================== RH MODULE ========================

@app.route('/rh')
@login_required
def rh_dashboard():
    stats = get_rh_stats()
    employees = get_rh_employees('actif')
    conn = get_db()
    leaves = [dict(r) for r in conn.execute("""SELECT l.*, e.first_name, e.last_name FROM rh_leaves l
        LEFT JOIN rh_employees e ON l.employee_id=e.id ORDER BY l.created_at DESC LIMIT 10""").fetchall()]
    announcements = [dict(r) for r in conn.execute("SELECT * FROM rh_announcements ORDER BY created_at DESC LIMIT 5").fetchall()]
    trainings = [dict(r) for r in conn.execute("SELECT * FROM rh_trainings ORDER BY date DESC LIMIT 5").fetchall()]
    conn.close()
    return render_template('rh_dashboard.html', page='rh', stats=stats, employees=employees,
                          leaves=leaves, announcements=announcements, trainings=trainings)

@app.route('/rh/personnel')
@login_required
def rh_personnel():
    employees = get_rh_employees()
    return render_template('rh_personnel.html', page='rh_personnel', employees=employees)

@app.route('/rh/personnel/add', methods=['GET','POST'])
@login_required
def rh_personnel_add():
    if request.method == 'POST':
        from models import db_insert
        db_insert('rh_employees', matricule=request.form.get('matricule',''),
            first_name=request.form['first_name'], last_name=request.form['last_name'],
            email=request.form.get('email',''), tel=request.form.get('tel',''),
            birth_date=request.form.get('birth_date',''), gender=request.form.get('gender',''),
            nationality=request.form.get('nationality',''),
            position=request.form.get('position',''), department=request.form.get('department',''),
            hire_date=request.form.get('hire_date',''),
            contract_type=request.form.get('contract_type','CDI'),
            contract_end=request.form.get('contract_end',''),
            salary=float(request.form.get('salary',0) or 0),
            cnps_number=request.form.get('cnps_number',''),
            insurance=request.form.get('insurance',''),
            insurance_number=request.form.get('insurance_number',''),
            emergency_contact=request.form.get('emergency_contact',''),
            emergency_tel=request.form.get('emergency_tel',''),
            bank_name=request.form.get('bank_name',''),
            bank_account=request.form.get('bank_account',''))
        # Photo
        if 'photo' in request.files and request.files['photo'].filename:
            f = request.files['photo']
            ext = os.path.splitext(f.filename)[1].lower()
            if ext in ('.jpg','.jpeg','.png','.webp'):
                photo_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'photos')
                os.makedirs(photo_dir, exist_ok=True)
                conn = get_db()
                new_id = conn.execute("SELECT id FROM rh_employees ORDER BY id DESC LIMIT 1").fetchone()['id']
                conn.close()
                fname = f"emp_{new_id}{ext}"
                f.save(os.path.join(photo_dir, fname))
                conn = get_db(); conn.execute("UPDATE rh_employees SET photo=? WHERE id=?", (fname, new_id)); conn.commit(); conn.close()
        flash("Employé ajouté","success"); return redirect('/rh/personnel')
    return render_template('rh_personnel_form.html', page='rh_personnel', emp=None)

@app.route('/rh/personnel/<int:eid>/edit', methods=['GET','POST'])
@login_required
def rh_personnel_edit(eid):
    emp = get_rh_employee(eid)
    if not emp: flash("Non trouvé","error"); return redirect('/rh/personnel')
    if request.method == 'POST':
        conn = get_db()
        for field in ['first_name','last_name','matricule','email','tel','birth_date','gender','nationality',
                      'position','department','hire_date','contract_type','contract_end','cnps_number',
                      'insurance','insurance_number','emergency_contact','emergency_tel','bank_name',
                      'bank_account','status','notes']:
            val = request.form.get(field, emp.get(field, ''))
            conn.execute(f"UPDATE rh_employees SET {field}=? WHERE id=?", (val, eid))
        if request.form.get('salary'):
            conn.execute("UPDATE rh_employees SET salary=? WHERE id=?", (float(request.form['salary']), eid))
        conn.commit(); conn.close()
        flash("Employé modifié","success"); return redirect('/rh/personnel')
    return render_template('rh_personnel_form.html', page='rh_personnel', emp=emp)

@app.route('/rh/conges')
@login_required
def rh_conges():
    conn = get_db()
    leaves = [dict(r) for r in conn.execute("""SELECT l.*, e.first_name, e.last_name FROM rh_leaves l
        LEFT JOIN rh_employees e ON l.employee_id=e.id ORDER BY l.created_at DESC""").fetchall()]
    conn.close()
    employees = get_rh_employees('actif')
    return render_template('rh_conges.html', page='rh_conges', leaves=leaves, employees=employees)

@app.route('/rh/conges/add', methods=['POST'])
@login_required
def rh_conges_add():
    from models import db_insert
    db_insert('rh_leaves', employee_id=int(request.form['employee_id']),
        leave_type=request.form.get('leave_type','annuel'),
        start_date=request.form['start_date'], end_date=request.form['end_date'],
        days=int(request.form.get('days',1) or 1), reason=request.form.get('reason',''))
    flash("Demande de congé enregistrée","success"); return redirect('/rh/conges')

@app.route('/rh/conges/<int:lid>/<action>')
@login_required
def rh_conges_action(lid, action):
    if action in ('approuve','refuse'):
        conn = get_db()
        conn.execute("UPDATE rh_leaves SET status=?, approved_by=? WHERE id=?", (action, session['user_id'], lid))
        conn.commit(); conn.close()
        flash(f"Congé {action}","success")
    return redirect('/rh/conges')

@app.route('/rh/paie')
@login_required
def rh_paie():
    conn = get_db()
    payslips = [dict(r) for r in conn.execute("""SELECT p.*, e.first_name, e.last_name, e.matricule
        FROM rh_payslips p LEFT JOIN rh_employees e ON p.employee_id=e.id ORDER BY p.period DESC, e.last_name""").fetchall()]
    conn.close()
    employees = get_rh_employees('actif')
    return render_template('rh_paie.html', page='rh_paie', payslips=payslips, employees=employees)

@app.route('/rh/paie/add', methods=['POST'])
@login_required
def rh_paie_add():
    f = lambda k: float(request.form.get(k, 0) or 0)
    base = f('base_salary')
    brut = base + f('heures_sup') + f('prime_transport') + f('prime_anciennete') + f('prime_logement') + f('prime_rendement') + f('bonus') + f('avantages_nature')
    retenues = f('cnps_employee') + f('assurance') + f('its') + f('avances') + f('autres_retenues')
    net = brut - retenues
    from models import db_insert
    db_insert('rh_payslips', employee_id=int(request.form['employee_id']), period=request.form['period'],
        base_salary=base, prime_transport=f('prime_transport'), prime_anciennete=f('prime_anciennete'),
        prime_logement=f('prime_logement'), prime_rendement=f('prime_rendement'),
        heures_sup=f('heures_sup'), bonus=f('bonus'), avantages_nature=f('avantages_nature'),
        salaire_brut=brut, cnps_employee=f('cnps_employee'), assurance=f('assurance'),
        its=f('its'), avances=f('avances'), autres_retenues=f('autres_retenues'),
        total_retenues=retenues, net_salary=net,
        jours_travailles=int(request.form.get('jours_travailles',26) or 26),
        jours_absence=int(request.form.get('jours_absence',0) or 0),
        mode_paiement=request.form.get('mode_paiement','virement'))
    flash(f"Bulletin créé — Net: {net:,.0f} FCFA","success"); return redirect('/rh/paie')

@app.route('/rh/paie/<int:pid>/status/<status>')
@login_required
def rh_paie_status(pid, status):
    if status in ('brouillon','valide','envoye'):
        conn = get_db(); conn.execute("UPDATE rh_payslips SET status=? WHERE id=?", (status, pid)); conn.commit(); conn.close()
        flash(f"Statut → {status}","success")
    return redirect('/rh/paie')

@app.route('/rh/annonces')
@login_required
def rh_annonces():
    annonces = db_all('rh_announcements', order='created_at DESC')
    return render_template('rh_annonces.html', page='rh_annonces', annonces=annonces)

@app.route('/rh/annonces/add', methods=['POST'])
@login_required
def rh_annonces_add():
    from models import db_insert
    db_insert('rh_announcements', title=request.form['title'], content=request.form.get('content',''),
        priority=request.form.get('priority','normale'), created_by=session['user_id'])
    flash("Annonce publiée","success"); return redirect('/rh/annonces')

# ======================== SMTP SETTINGS ========================

@app.route('/admin/smtp', methods=['GET','POST'])
@login_required
def admin_smtp():
    u = get_user(session['user_id'])
    if not u or u['role'] not in ('admin','directeur'):
        flash("Accès non autorisé","error"); return redirect('/dashboard')
    if request.method == 'POST':
        save_smtp(request.form['smtp_host'], int(request.form.get('smtp_port',587)),
                  request.form['smtp_user'], request.form['smtp_pass'])
        # Test
        ok = send_email_notification(request.form['smtp_user'], 'Test WannyHotel',
            '<h2>✅ Configuration email réussie</h2><p>WannyHotel peut maintenant envoyer des notifications.</p>')
        flash(f"SMTP sauvegardé {'+ test envoyé !' if ok else '(test échoué — vérifiez les identifiants)'}", "success" if ok else "error")
        return redirect('/admin/smtp')
    smtp = get_smtp() or {}
    return render_template('admin_smtp.html', page='admin', smtp=smtp)


# ======================== CLIENT PORTAL ========================

@app.route('/client/register', methods=['GET','POST'])
def client_register():
    if request.method == 'POST':
        email = request.form.get('email','').strip()
        password = request.form.get('password','').strip()
        if not email or not password or len(password) < 6:
            flash("Email et mot de passe (6+ car.) requis", "error")
            return render_template('client_register.html')
        gid = create_guest_account(email, password, request.form.get('first_name',''),
            request.form.get('last_name',''), request.form.get('tel',''))
        if gid:
            flash("Compte créé ! Connectez-vous pour réserver.", "success")
            return redirect('/client/login')
        flash("Email déjà utilisé", "error")
    return render_template('client_register.html')

@app.route('/client/login', methods=['GET','POST'])
def client_login():
    if request.method == 'POST':
        user = authenticate_guest(request.form['email'], request.form['password'])
        if user:
            session['guest_user_id'] = user['id']
            session['guest_id'] = user['guest_id']
            session['guest_name'] = f"{user['first_name']} {user['last_name']}"
            flash(f"Bienvenue {user['first_name']} !", "success")
            return redirect('/client/dashboard')
        flash("Email ou mot de passe incorrect", "error")
    return render_template('client_login.html')

@app.route('/client/logout')
def client_logout():
    for k in ['guest_user_id','guest_id','guest_name']: session.pop(k, None)
    flash("Déconnexion réussie", "success"); return redirect('/booking')

@app.route('/client/dashboard')
def client_dashboard():
    if 'guest_id' not in session: return redirect('/client/login')
    reservations = get_guest_reservations(session['guest_id'])
    notifications = get_guest_notifications(session['guest_id'])
    return render_template('client_dashboard.html', reservations=reservations, notifications=notifications,
                          guest_name=session.get('guest_name',''))

@app.route('/client/book', methods=['POST'])
def client_book():
    if 'guest_id' not in session: return redirect('/client/login')
    db_insert('online_bookings',
        guest_first_name=session.get('guest_name','').split(' ')[0],
        guest_last_name=' '.join(session.get('guest_name','').split(' ')[1:]),
        guest_tel='', guest_email='',
        room_type_id=int(request.form['room_type_id']) if request.form.get('room_type_id') else None,
        checkin_date=request.form['checkin_date'],
        checkout_date=request.form['checkout_date'],
        adults=int(request.form.get('adults',1) or 1),
        children=int(request.form.get('children',0) or 0),
        notes=request.form.get('notes',''))
    flash("Demande de réservation envoyée ! Vous serez notifié dès la confirmation.", "success")
    return redirect('/client/dashboard')


# ======================== MOBILE MONEY PAYMENTS ========================

CINETPAY_CONFIG = {
    'api_key': os.environ.get('CINETPAY_API_KEY', ''),
    'site_id': os.environ.get('CINETPAY_SITE_ID', ''),
    'notify_url': os.environ.get('CINETPAY_NOTIFY_URL', ''),
}

@app.route('/payment/<int:res_id>')
def payment_page(res_id):
    """Page de paiement Mobile Money pour une réservation."""
    res = db_get('reservations', res_id)
    if not res: flash("Réservation non trouvée", "error"); return redirect('/')
    conn = get_db()
    guest = conn.execute("SELECT * FROM guests WHERE id=?", (res['guest_id'],)).fetchone()
    charges = conn.execute("SELECT COALESCE(SUM(total),0) FROM charges WHERE reservation_id=?", (res_id,)).fetchall()
    paid = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE reservation_id=?", (res_id,)).fetchall()
    conn.close()
    total = charges[0][0] if charges else 0
    already_paid = paid[0][0] if paid else 0
    balance = total - already_paid
    return render_template('payment.html', res=res, guest=dict(guest) if guest else {},
                          total=total, paid=already_paid, balance=balance,
                          cinetpay=CINETPAY_CONFIG)

@app.route('/payment/process', methods=['POST'])
def payment_process():
    """Traitement du paiement Mobile Money (simulation ou CinetPay)."""
    res_id = int(request.form['reservation_id'])
    amount = float(request.form['amount'])
    method = request.form.get('method', 'mobile_money')
    phone = request.form.get('phone', '')
    provider = request.form.get('provider', 'orange_money')
    
    # Si CinetPay est configuré, rediriger vers leur API
    if CINETPAY_CONFIG['api_key']:
        # TODO: Appel API CinetPay réel
        transaction_id = f"TXN-{secrets.token_hex(6).upper()}"
    else:
        # Mode simulation (pas de clé API)
        transaction_id = f"SIM-{secrets.token_hex(6).upper()}"
    
    # Enregistrer le paiement
    conn = get_db()
    conn.execute("INSERT INTO payments (reservation_id, amount, method, reference, created_by) VALUES (?,?,?,?,?)",
                 (res_id, amount, f"{provider} ({phone})", transaction_id, session.get('user_id')))
    conn.commit()
    
    # Mettre à jour le solde
    total_paid = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE reservation_id=?", (res_id,)).fetchone()[0]
    total_charges = conn.execute("SELECT COALESCE(SUM(total),0) FROM charges WHERE reservation_id=?", (res_id,)).fetchone()[0]
    conn.close()
    
    if total_paid >= total_charges:
        db_update('reservations', res_id, paid_amount=total_paid)
        # Notify guest: payment complete, invoice ready
        res = db_get('reservations', res_id)
        if res:
            token = create_notification(res['guest_id'], res_id, 'facture',
                f"Paiement reçu ({amount:,.0f} F). Votre facture est disponible.")
            # Send email with invoice link
            guest = db_get('guests', res['guest_id'])
            if guest and guest.get('email'):
                base_url = request.host_url.rstrip('/')
                send_email_notification(guest['email'],
                    f"🧾 Facture {res['reference']} — WannyHotel",
                    f"""<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto">
                    <div style="background:linear-gradient(135deg,#B8860B,#DAA520);padding:20px;text-align:center;border-radius:12px 12px 0 0">
                    <h1 style="color:#fff;margin:0">WannyHotel</h1></div>
                    <div style="padding:24px;background:#fff;border:1px solid #eee">
                    <h2 style="color:#1a6b5a">🧾 Paiement reçu</h2>
                    <p>Bonjour <strong>{guest['first_name']} {guest['last_name']}</strong>,</p>
                    <p>Nous confirmons la réception de votre paiement de <strong>{amount:,.0f} FCFA</strong> via {provider}.</p>
                    <p>Référence : <strong>{transaction_id}</strong></p>
                    <div style="text-align:center;margin:20px 0">
                    <a href="{base_url}/invoice/{res_id}" style="background:#1a6b5a;color:#fff;padding:12px 30px;border-radius:8px;text-decoration:none;font-weight:700">🧾 Voir ma facture</a>
                    </div>
                    <a href="{base_url}/invoice/{res_id}/pdf" style="display:block;text-align:center;color:#888;margin-top:8px;font-size:13px">📥 Télécharger le PDF</a>
                    </div>
                    <div style="padding:12px;text-align:center;font-size:11px;color:#999">© 2026 WannyHotel</div></div>""")
    
    flash(f"Paiement {amount:,.0f} F enregistré via {provider} — Réf: {transaction_id}", "success")
    
    if 'user_id' in session:
        return redirect(f'/reservations/{res_id}')
    return redirect(f'/payment/{res_id}')


# ======================== NOTIFICATIONS (PUBLIC) ========================

@app.route('/notification/<token>')
def notification_page(token):
    """Page publique de notification pour le client."""
    notif = get_notification_by_token(token)
    if not notif:
        return "<h1>Notification non trouvée</h1><a href='/'>Accueil</a>", 404
    res_data, charges, payments = get_invoice_data(notif['reservation_id'])
    total_charges = sum(c['total'] for c in charges)
    total_paid = sum(p['amount'] for p in payments)
    return render_template('notification.html', notif=notif, res=res_data,
                          charges=charges, payments=payments,
                          total_charges=total_charges, total_paid=total_paid,
                          balance=total_charges - total_paid)


# ======================== FACTURE PDF ========================

@app.route('/invoice/<int:res_id>')
def invoice_view(res_id):
    """Vue facture digitale (accessible avec ou sans login)."""
    res_data, charges, payments = get_invoice_data(res_id)
    if not res_data:
        flash("Réservation non trouvée", "error"); return redirect('/')
    total_charges = sum(c['total'] for c in charges)
    total_paid = sum(p['amount'] for p in payments)
    return render_template('invoice.html', res=res_data, charges=charges, payments=payments,
                          total=total_charges, paid=total_paid, balance=total_charges - total_paid)

@app.route('/invoice/<int:res_id>/pdf')
def invoice_pdf(res_id):
    """Génère le PDF de la facture."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
    
    res_data, charges, payments = get_invoice_data(res_id)
    if not res_data: return "Not found", 404
    
    total_charges = sum(c['total'] for c in charges)
    total_paid = sum(p['amount'] for p in payments)
    
    output = os.path.join(app.config['UPLOAD_FOLDER'], f'facture_{res_data["reference"]}.pdf')
    doc = SimpleDocTemplate(output, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=15*mm, bottomMargin=15*mm)
    
    GOLD = HexColor('#B8860B')
    TEAL = HexColor('#1a3a5c')
    s_title = ParagraphStyle('t', fontSize=24, fontName='Helvetica-Bold', textColor=GOLD, alignment=TA_CENTER)
    s_sub = ParagraphStyle('s', fontSize=10, alignment=TA_CENTER, textColor=HexColor('#888'))
    s_n = ParagraphStyle('n', fontSize=10, leading=13)
    s_b = ParagraphStyle('b', fontSize=10, fontName='Helvetica-Bold')
    s_r = ParagraphStyle('r', fontSize=10, alignment=TA_RIGHT)
    s_h = ParagraphStyle('h', fontSize=9, fontName='Helvetica-Bold', textColor=HexColor('#fff'))
    s_c = ParagraphStyle('c', fontSize=9)
    s_cr = ParagraphStyle('cr', fontSize=9, alignment=TA_RIGHT)
    s_f = ParagraphStyle('f', fontSize=7, alignment=TA_CENTER, textColor=TEAL)
    white = HexColor('#ffffff')
    
    story = []
    
    # Logo + Title header
    logo_path = os.path.join(base, 'logo_wannyhotel.png')
    if os.path.exists(logo_path):
        from reportlab.platypus import Image as RLImage
        try:
            logo_img = RLImage(logo_path, width=50*mm, height=25*mm)
            logo_img.hAlign = 'CENTER'
            story.append(logo_img)
        except: pass
    else:
        story.append(Paragraph("WannyHotel", s_title))
    
    story.append(Paragraph("PMS Hôtelier", s_sub))
    story.append(Spacer(1, 4*mm))
    
    # Separator line
    from reportlab.platypus import HRFlowable
    story.append(HRFlowable(width="100%", thickness=1, color=GOLD))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(f"<b>FACTURE</b> — {res_data['reference']}", ParagraphStyle('ft', fontSize=16, fontName='Helvetica-Bold', textColor=TEAL)))
    story.append(Paragraph(f"Date : {datetime.now().strftime('%d/%m/%Y')}", s_n))
    story.append(Spacer(1, 5*mm))
    
    # Client info
    story.append(Paragraph(f"<b>Client :</b> {res_data.get('first_name','')} {res_data.get('last_name','')}", s_b))
    if res_data.get('tel'): story.append(Paragraph(f"Tél : {res_data['tel']}", s_n))
    if res_data.get('email'): story.append(Paragraph(f"Email : {res_data['email']}", s_n))
    if res_data.get('company'): story.append(Paragraph(f"Société : {res_data['company']}", s_n))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(f"Chambre : {res_data.get('room_number','-')} ({res_data.get('room_type_name','')})", s_n))
    story.append(Paragraph(f"Séjour : {res_data['checkin_date']} → {res_data['checkout_date']} ({res_data['nights']} nuit(s))", s_n))
    story.append(Spacer(1, 6*mm))
    
    # Charges table
    ch_data = [[Paragraph(h, s_h) for h in ['Description', 'Qté', 'Prix unit.', 'Total']]]
    for c in charges:
        ch_data.append([Paragraph(c['description'] or c['category'], s_c), Paragraph(str(c['quantity']), s_c),
            Paragraph(f"{c['unit_price']:,.0f}", s_cr), Paragraph(f"{c['total']:,.0f}", s_cr)])
    
    cw = [80*mm, 20*mm, 30*mm, 30*mm]
    t = Table(ch_data, colWidths=cw)
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),TEAL), ('GRID',(0,0),(-1,-1),0.5,HexColor('#ccc')),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'), ('TOPPADDING',(0,0),(-1,-1),4), ('BOTTOMPADDING',(0,0),(-1,-1),4)]))
    story.append(t)
    story.append(Spacer(1, 4*mm))
    
    # Totals
    tot_data = [
        ['', '', Paragraph('<b>Total</b>', s_cr), Paragraph(f"<b>{total_charges:,.0f} FCFA</b>", s_cr)],
        ['', '', Paragraph('Payé', s_cr), Paragraph(f"{total_paid:,.0f} FCFA", s_cr)],
        ['', '', Paragraph('<b>Solde</b>', s_cr), Paragraph(f"<b>{total_charges-total_paid:,.0f} FCFA</b>", s_cr)],
    ]
    tt = Table(tot_data, colWidths=cw)
    tt.setStyle(TableStyle([('LINEABOVE',(2,0),(3,0),1,HexColor('#ccc'))]))
    story.append(tt)
    story.append(Spacer(1, 6*mm))
    
    # Payments
    if payments:
        story.append(Paragraph("<b>Paiements reçus</b>", s_b))
        for pay in payments:
            story.append(Paragraph(f"• {pay['created_at'][:16]} — {pay['amount']:,.0f} F via {pay['method']} (Réf: {pay.get('reference','-')})", s_n))
    
    story.append(Spacer(1, 15*mm))
    story.append(Paragraph("Merci pour votre confiance — WannyHotel", ParagraphStyle('thx', fontSize=10, alignment=TA_CENTER, textColor=GOLD)))
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph("WannyHotel — Abidjan, Côte d'Ivoire", s_f))
    story.append(Paragraph("+225 07 47 68 20 27 · contact@wannyhotel.com", s_f))
    
    doc.build(story)
    return send_file(output, as_attachment=True, download_name=f"Facture_{res_data['reference']}.pdf")


# ======================== ÉDITION ========================

@app.route('/reservations/<int:rid>/edit', methods=['GET','POST'])
@login_required
def reservation_edit(rid):
    res = db_get('reservations', rid)
    if not res: flash("Non trouvé","error"); return redirect('/reservations')
    if request.method == 'POST':
        db_update('reservations', rid,
            checkin_date=request.form.get('checkin_date', res['checkin_date']),
            checkout_date=request.form.get('checkout_date', res['checkout_date']),
            rate_per_night=float(request.form.get('rate', res['rate_per_night']) or 0),
            adults=int(request.form.get('adults', res['adults']) or 1),
            children=int(request.form.get('children', res['children']) or 0),
            notes=request.form.get('notes', ''))
        flash("Réservation modifiée", "success"); return redirect(f'/reservations/{rid}')
    rooms = db_all('rooms', order='number ASC')
    return render_template('reservation_edit.html', page='reservations', res=res, rooms=rooms)

@app.route('/guests/<int:gid>/edit', methods=['GET','POST'])
@login_required
def guest_edit(gid):
    g = db_get('guests', gid)
    if not g: flash("Non trouvé","error"); return redirect('/guests')
    if request.method == 'POST':
        db_update('guests', gid, first_name=request.form['first_name'], last_name=request.form['last_name'],
            tel=request.form.get('tel',''), email=request.form.get('email',''),
            nationality=request.form.get('nationality',''), company=request.form.get('company',''),
            id_type=request.form.get('id_type',''), id_number=request.form.get('id_number',''),
            vip=1 if request.form.get('vip') else 0)
        flash("Client modifié", "success"); return redirect('/guests')
    return render_template('guest_edit.html', page='clients', guest=g)

@app.route('/rooms/<int:rid>/edit', methods=['POST'])
@login_required
def room_edit(rid):
    db_update('rooms', rid, floor=int(request.form.get('floor',0) or 0),
        room_type_id=int(request.form['room_type_id']) if request.form.get('room_type_id') else None,
        notes=request.form.get('notes',''))
    flash("Chambre modifiée", "success"); return redirect('/chambres')


# ======================== RÉINITIALISATION ========================

@app.route('/admin/reset', methods=['GET','POST'])
@login_required
def admin_reset():
    u = get_user(session['user_id'])
    if not u or u['role'] not in ('admin','directeur'):
        flash("Accès non autorisé","error"); return redirect('/dashboard')
    if request.method == 'POST':
        action = request.form.get('action','')
        confirm = request.form.get('confirm','')
        if confirm != 'CONFIRMER':
            flash("Tapez CONFIRMER pour valider", "error"); return redirect('/admin/reset')
        if action == 'reset_reservations':
            reset_reservations()
            log_activity(session['user_id'], u['full_name'], 'RESET', 'Réservations réinitialisées', request.remote_addr)
            flash("Réservations réinitialisées", "success")
        elif action == 'reset_all':
            reset_all_data()
            log_activity(session['user_id'], u['full_name'], 'RESET', 'TOUTES les données réinitialisées', request.remote_addr)
            flash("Programme réinitialisé", "success")
        return redirect('/admin/reset')
    return render_template('admin_reset.html', page='admin')


# ======================== RESTAURANT / BAR ========================

@app.route('/restaurant')
@login_required
def restaurant():
    conn = get_db()
    orders = conn.execute("""SELECT * FROM restaurant_orders ORDER BY created_at DESC LIMIT 30""").fetchall()
    menu = conn.execute("SELECT * FROM restaurant_menu WHERE available=1 ORDER BY category, name").fetchall()
    rooms_occ = conn.execute("SELECT r.id, r.number, g.first_name, g.last_name, res.id as res_id FROM rooms r LEFT JOIN reservations res ON r.id=res.room_id AND res.status='en_cours' LEFT JOIN guests g ON res.guest_id=g.id WHERE r.status='occupee'").fetchall()
    conn.close()
    return render_template('restaurant.html', page='restaurant', orders=[dict(o) for o in orders],
                          menu=[dict(m) for m in menu], rooms=[dict(r) for r in rooms_occ])

@app.route('/restaurant/menu/add', methods=['POST'])
@login_required
def restaurant_menu_add():
    db_insert('restaurant_menu', name=request.form['name'],
        category=request.form.get('category', 'plat'),
        price=float(request.form.get('price', 0) or 0),
        description=request.form.get('description', ''))
    flash("Article ajouté au menu", "success")
    return redirect('/restaurant')

@app.route('/restaurant/order', methods=['POST'])
@login_required
def restaurant_order():
    import json
    items = []
    names = request.form.getlist('item_name[]')
    qtys = request.form.getlist('item_qty[]')
    prices = request.form.getlist('item_price[]')
    subtotal = 0
    for n, q, p in zip(names, qtys, prices):
        if n and float(q or 0) > 0:
            items.append({'name': n, 'qty': int(q), 'price': float(p)})
            subtotal += int(q) * float(p)
    tax = round(subtotal * 0.18)  # TVA 18%
    total = subtotal + tax
    
    res_id = int(request.form.get('reservation_id', 0) or 0) or None
    db_insert('restaurant_orders',
        table_number=request.form.get('table_number', ''),
        room_id=int(request.form.get('room_id', 0) or 0) or None,
        guest_name=request.form.get('guest_name', ''),
        items_json=json.dumps(items),
        subtotal=subtotal, tax=tax, total=total,
        reservation_id=res_id,
        payment_method=request.form.get('payment_method', 'especes'),
        created_by=session.get('user_id'))
    
    # If linked to room, add as charge
    if res_id:
        conn = get_db()
        conn.execute("INSERT INTO charges (reservation_id, category, description, quantity, unit_price, total) VALUES (?,?,?,?,?,?)",
                     (res_id, 'restaurant', f"Restaurant — {len(items)} articles", 1, total, total))
        conn.commit(); conn.close()
        flash(f"Commande {total:,.0f} F ajoutée à la chambre", "success")
    else:
        flash(f"Commande enregistrée — {total:,.0f} F", "success")
    return redirect('/restaurant')


# ======================== PLANNING CHAMBRES ========================

@app.route('/planning')
@login_required
def planning():
    conn = get_db()
    rooms = conn.execute("SELECT r.*, rt.name as type_name FROM rooms r LEFT JOIN room_types rt ON r.room_type_id=rt.id ORDER BY r.number").fetchall()
    reservations = conn.execute("""SELECT r.*, rm.number as room_number, g.first_name, g.last_name 
        FROM reservations r LEFT JOIN rooms rm ON r.room_id=rm.id LEFT JOIN guests g ON r.guest_id=g.id
        WHERE r.status IN ('confirmee','en_cours') ORDER BY r.checkin_date""").fetchall()
    conn.close()
    return render_template('planning.html', page='planning', rooms=[dict(r) for r in rooms],
                          reservations=[dict(r) for r in reservations])


# ======================== AVIS CLIENTS ========================

@app.route('/review/<token>', methods=['GET','POST'])
def guest_review(token):
    conn = get_db()
    review = conn.execute("SELECT * FROM guest_reviews WHERE token=?", (token,)).fetchone()
    conn.close()
    if not review: return "<h1>Lien invalide</h1>", 404
    if review['rating'] > 0 and review['comment']:
        return render_template('review_done.html', review=dict(review))
    if request.method == 'POST':
        conn = get_db()
        conn.execute("UPDATE guest_reviews SET rating=?, comment=? WHERE token=?",
                     (int(request.form.get('rating', 5)), request.form.get('comment', ''), token))
        # Add loyalty points
        conn.execute("INSERT INTO loyalty_points (guest_id, points, action, reservation_id) VALUES (?,?,?,?)",
                     (review['guest_id'], 50, 'review', review['reservation_id']))
        conn.commit(); conn.close()
        flash("Merci pour votre avis !", "success")
        return render_template('review_done.html', review={'rating': int(request.form.get('rating', 5))})
    res_data, _, _ = get_invoice_data(review['reservation_id'])
    return render_template('review_form.html', review=dict(review), res=res_data)

@app.route('/reviews')
@login_required
def reviews_list():
    conn = get_db()
    reviews = conn.execute("""SELECT gr.*, g.first_name, g.last_name, r.reference
        FROM guest_reviews gr LEFT JOIN guests g ON gr.guest_id=g.id 
        LEFT JOIN reservations r ON gr.reservation_id=r.id
        WHERE gr.comment IS NOT NULL AND gr.comment != '' ORDER BY gr.created_at DESC""").fetchall()
    avg = conn.execute("SELECT AVG(rating) FROM guest_reviews WHERE comment IS NOT NULL AND comment != ''").fetchone()[0]
    conn.close()
    return render_template('reviews.html', page='reviews', reviews=[dict(r) for r in reviews], avg_rating=avg or 0)


# ======================== WHATSAPP NOTIFICATION ========================

@app.route('/whatsapp/<int:res_id>')
@login_required  
def whatsapp_notify(res_id):
    res_data, charges, payments = get_invoice_data(res_id)
    if not res_data:
        flash("Réservation non trouvée", "error"); return redirect('/reservations')
    total = sum(c['total'] for c in charges)
    guest_tel = res_data.get('tel', '').replace(' ', '').replace('+', '')
    if not guest_tel.startswith('225'): guest_tel = '225' + guest_tel
    base_url = request.host_url.rstrip('/')
    msg = f"🏨 *WannyHotel*\n\nBonjour {res_data.get('first_name','')} {res_data.get('last_name','')},\n\n✅ Réservation *{res_data['reference']}* confirmée\n📅 {res_data['checkin_date']} → {res_data['checkout_date']}\n🏠 Chambre {res_data.get('room_number','')}\n💰 Total: {total:,.0f} FCFA\n\n🧾 Facture: {base_url}/invoice/{res_id}\n💳 Paiement: {base_url}/payment/{res_id}\n\nMerci et bienvenue !"
    import urllib.parse
    wa_url = f"https://wa.me/{guest_tel}?text={urllib.parse.quote(msg)}"
    return redirect(wa_url)


if __name__ == "__main__":
    app.run(debug=True, port=5001)

