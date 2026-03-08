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
for f in ['logo_wannygest.png','logo_wannygest_clean.png']:
    src = os.path.join(base, f)
    dst = os.path.join(base, 'static', f)
    if os.path.exists(src) and not os.path.exists(dst): shutil.copy2(src, dst)

init_db()
migrate_db()
ROLES = {'admin': 'all', 'directeur': 'all', 'receptionniste': ['dashboard','reservations','chambres','guests','housekeeping'],
         'restaurant': ['dashboard','stock','events'], 'comptable': ['dashboard','caisse','rapports']}

def login_required(f):
    @wraps(f)
    def dec(*a,**kw):
        if 'user_id' not in session: return redirect('/login')
        return f(*a,**kw)
    return dec

@app.context_processor
def inject_globals():
    u = get_user(session['user_id']) if 'user_id' in session else None
    return {'current_user': u, 'now': datetime.now().strftime('%Y-%m-%d')}

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
    recent = get_recent_reservations(8)
    return render_template('dashboard.html', page='dashboard', stats=stats, recent=recent)

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
            flash(f"Réservation {ref} confirmée !", "success")
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
    return render_template('admin.html', page='admin', users=users, logs=logs)

@app.route('/admin/user/add', methods=['POST'])
@login_required
def admin_user_add():
    create_user(request.form['username'], request.form['password'], request.form['full_name'], request.form.get('role','receptionniste'))
    flash("Utilisateur créé","success"); return redirect('/admin')

if __name__ == '__main__':
    app.run(debug=True, port=5001)
