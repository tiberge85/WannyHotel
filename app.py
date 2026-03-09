#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAMYA TECHNOLOGIE & INNOVATION
Application Web v3 — Gestion des Rapports de Pointage
Auth + Rôles + Dashboard + Clients + Fichiers RH
"""

import os, uuid, shutil, functools, smtplib, json
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from flask import (Flask, render_template, request, send_file, flash,
                   redirect, url_for, jsonify, session, send_from_directory)
from werkzeug.utils import secure_filename

from rapport_core import extract_from_excel, generate_full_pdf
from merge_presence import generate_presence_xlsx
from models import (init_db, create_user, authenticate_user, get_user_by_id,
                    get_all_users, update_user, delete_user,
                    create_client, get_all_clients, get_client_by_id,
                    find_client_by_name, update_client, delete_client,
                    create_job, get_jobs_by_status, get_all_jobs, mark_job_sent,
                    get_dashboard_stats, has_permission, get_role_permissions,
                    update_role_permissions,
                    reset_jobs, reset_clients, reset_users, reset_all,
                    log_activity, get_activity_logs,
                    add_job_comment, get_job_comments, update_job_notes,
                    get_job_by_id, get_db_path,
                    create_contract, get_client_contracts, get_all_contracts,
                    get_contract_by_id, update_contract, delete_contract,
                    get_client_monthly_stats,
                    save_smtp_settings, get_smtp_settings,
                    create_invoice, get_invoices_by_status, get_all_invoices,
                    update_invoice_status, get_invoice_stats,
                    create_visit_report, get_visit_reports, get_visit_by_id,
                    update_visit_proforma, get_visit_stats,
                    create_devis, get_all_devis, get_devis_by_id,
                    update_devis_status, get_devis_stats)
from devis_generator import generate_devis_pdf

app = Flask(__name__, template_folder=BASE_DIR, static_folder=BASE_DIR, static_url_path='/static')
app.secret_key = os.environ.get('SECRET_KEY', 'ramya-tech-2026-secret-v3')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['FILES_FOLDER'] = os.path.join(BASE_DIR, 'files')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['FILES_FOLDER'], exist_ok=True)

init_db()

# Init extra tables
from models import (init_rh_tables, get_all_employees, get_employee_by_id,
                    create_employee, update_employee, get_employee_stats,
                    get_leaves, create_leave, update_leave_status,
                    get_payslips, create_payslip, update_payslip,
                    init_extra_tables, record_login_attempt, get_failed_attempts,
                    save_otp, verify_otp, db_count, db_sum, db_get_all)
init_rh_tables()
init_extra_tables()

from models import init_mg_tables
init_mg_tables()

# Register module routes
from modules_routes import modules_bp
app.register_blueprint(modules_bp)

from models import (init_devis_tables, create_devis, get_all_devis, get_devis_by_id,
                    update_devis_status, get_devis_stats, get_next_devis_ref)
init_devis_tables()

ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
ALL_PERMISSIONS = ['traitement', 'fichiers', 'clients', 'admin', 'dashboard', 'envoyer', 'logs', 'contrats', 'comptabilite', 'visites', 'proforma', 'moyens_generaux', 'informatique', 'projets']

def allowed_file(fn):
    return '.' in fn and fn.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ======================== AUTH HELPERS ========================

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash("Veuillez vous connecter", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def permission_required(perm):
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user = get_user_by_id(session['user_id'])
            if not user or not has_permission(user['role'], perm):
                flash("Accès non autorisé", "error")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.context_processor
def inject_globals():
    """Injecte les variables globales dans tous les templates."""
    ctx = {'current_user': None, 'permissions': [], 'pending_count': 0}
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user:
            ctx['current_user'] = user
            ctx['permissions'] = get_role_permissions(user['role'])
            ctx['pending_count'] = len(get_jobs_by_status('traite'))
    return ctx


# ======================== AUTH ROUTES ========================

@app.route('/robots.txt')
def robots_txt():
    return "User-agent: *\nAllow: /\n", 200, {'Content-Type': 'text/plain'}

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.config.get('STATIC_FOLDER', 'static'), 'logo_wannygest.png', mimetype='image/png')

@app.errorhandler(500)
def internal_error(e):
    import traceback
    traceback.print_exc()
    return f"<h1>Erreur serveur</h1><p>{str(e)}</p><a href='/'>Retour</a>", 500

@app.errorhandler(404)
def not_found(e):
    return f"<h1>Page non trouvée</h1><a href='/'>Retour à l'accueil</a>", 404

@app.route('/')
def welcome():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('welcome.html')

@app.before_request
def check_session_timeout():
    """Déconnexion automatique après 30 min d'inactivité."""
    if 'user_id' in session:
        last = session.get('last_active')
        if last:
            from datetime import datetime, timedelta
            try:
                last_dt = datetime.fromisoformat(last)
                if datetime.now() - last_dt > timedelta(minutes=30):
                    session.clear()
                    flash("Session expirée — veuillez vous reconnecter", "info")
                    return redirect(url_for('login'))
            except:
                pass
        session['last_active'] = datetime.now().isoformat()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        ip = request.remote_addr
        
        # Vérifier verrouillage (5 tentatives en 15 min)
        if get_failed_attempts(username) >= 5:
            flash("Compte temporairement verrouillé (trop de tentatives). Réessayez dans 15 minutes.", "error")
            return render_template('login.html')
        
        user = authenticate_user(username, request.form['password'])
        if user:
            # Vérifier politique mot de passe
            record_login_attempt(username, True, ip)
            session['user_id'] = user['id']
            session['last_active'] = datetime.now().isoformat()
            log_activity(user['id'], user['full_name'], 'Connexion', 
                        f"Connexion réussie", ip)
            flash(f"Bienvenue {user['full_name']} !", "success")
            return redirect(url_for('dashboard'))
        
        record_login_attempt(username, False, ip)
        remaining = 5 - get_failed_attempts(username)
        flash(f"Identifiants incorrects ({remaining} tentative(s) restante(s))", "error")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        pwd = request.form['password']
        pwd2 = request.form['password2']
        if pwd != pwd2:
            flash("Les mots de passe ne correspondent pas", "error")
            return render_template('register.html')
        if len(pwd) < 6:
            flash("Le mot de passe doit faire au moins 6 caractères", "error")
            return render_template('register.html')
        ok, msg = create_user(
            request.form['username'], request.form['email'],
            pwd, request.form['full_name'], 'technicien'
        )
        if ok:
            flash("Compte créé ! Vous pouvez vous connecter.", "success")
            return redirect(url_for('login'))
        flash(msg, "error")
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Déconnexion réussie", "success")
    return redirect(url_for('welcome'))


# ======================== DASHBOARD ========================

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user_by_id(session['user_id'])
    role = user['role'] if user else 'technicien'
    stats = get_dashboard_stats()
    inv_stats = get_invoice_stats()
    v_stats = get_visit_stats()
    d_stats = get_devis_stats()
    emp_stats = get_employee_stats()
    return render_template('dashboard.html', page='dashboard', stats=stats, 
                          inv_stats=inv_stats, v_stats=v_stats, d_stats=d_stats,
                          emp_stats=emp_stats, user_role=role)


# ======================== TRAITEMENT ========================

@app.route('/traitement')
@permission_required('traitement')
def traitement():
    clients = get_all_clients()
    return render_template('traitement.html', page='traitement', clients=clients)

@app.route('/traitement/preview', methods=['POST'])
@login_required
def traitement_preview():
    if 'excel_file' not in request.files:
        return jsonify({"error": "Aucun fichier"}), 400
    file = request.files['excel_file']
    if not allowed_file(file.filename):
        return jsonify({"error": "Format non supporté"}), 400
    job_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'preview')
    os.makedirs(job_dir, exist_ok=True)
    try:
        path = os.path.join(job_dir, secure_filename(file.filename))
        file.save(path)
        emps, client = extract_from_excel(path)
        return jsonify({"client": client, "count": len(emps),
            "employees": [{"name": e['name'], "ref": e['ref'], "days": len(e['records'])} for e in emps]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        shutil.rmtree(job_dir, ignore_errors=True)

@app.route('/traitement/merge', methods=['POST'])
@login_required
def traitement_merge():
    if 'enr_file' not in request.files or 'trans_file' not in request.files:
        return jsonify({"error": "Les 2 fichiers sont requis"}), 400
    enr = request.files['enr_file']
    trans = request.files['trans_file']
    if not enr.filename or not trans.filename:
        return jsonify({"error": "Les 2 fichiers sont requis"}), 400
    merge_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'merge_' + str(uuid.uuid4())[:8])
    os.makedirs(merge_dir, exist_ok=True)
    try:
        enr_path = os.path.join(merge_dir, secure_filename(enr.filename))
        trans_path = os.path.join(merge_dir, secure_filename(trans.filename))
        enr.save(enr_path); trans.save(trans_path)
        out = os.path.join(merge_dir, 'Presence_fusionnee.xlsx')
        result = generate_presence_xlsx(enr_path, trans_path, out)
        if not result:
            return jsonify({"error": "Échec de la fusion."}), 400
        merge_id = os.path.basename(merge_dir)
        return jsonify({"success": True, "merge_id": merge_id, "client": result['client'],
            "employees": result['employees'], "rows": result['rows'], "filename": 'Presence_fusionnee.xlsx'})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/traitement/merge/download/<merge_id>')
@login_required
def traitement_merge_download(merge_id):
    safe_id = secure_filename(merge_id)
    path = os.path.join(app.config['UPLOAD_FOLDER'], safe_id, 'Presence_fusionnee.xlsx')
    if not os.path.exists(path):
        flash("Fichier expiré", "error")
        return redirect(url_for('traitement'))
    return send_file(path, as_attachment=True, download_name='Presence_fusionnee.xlsx')

@app.route('/traitement/generate', methods=['POST'])
@permission_required('traitement')
def traitement_generate():
    merge_id = request.form.get('merge_id', '').strip()
    
    if merge_id:
        merge_dir = os.path.join(app.config['UPLOAD_FOLDER'], merge_id)
        merged_file = os.path.join(merge_dir, 'Presence_fusionnee.xlsx')
        if not os.path.exists(merged_file):
            flash("Fichier fusionné expiré. Refaites la fusion.", "error")
            return redirect(url_for('traitement'))
        xlsx_source = merged_file
        filename = 'Presence_fusionnee.xlsx'
    else:
        if 'excel_file' not in request.files or not request.files['excel_file'].filename:
            flash("Aucun fichier sélectionné", "error")
            return redirect(url_for('traitement'))
        file = request.files['excel_file']
        if not allowed_file(file.filename):
            flash("Format non supporté", "error")
            return redirect(url_for('traitement'))
        xlsx_source = None
        filename = secure_filename(file.filename)
    
    provider_name = request.form.get('provider_name', '').strip() or "RAMYA TECHNOLOGIE & INNOVATION"
    provider_info = request.form.get('provider_info', '').strip() or "Tél: 2722204498 | Email: techniqueramya@gmail.com"
    client_name = request.form.get('client_name', '').strip()
    client_tel = request.form.get('client_tel', '').strip()
    client_email = request.form.get('client_email', '').strip()
    client_id_str = request.form.get('client_id', '').strip()
    hp_str = request.form.get('required_hours', '0').strip()
    
    # Auto-fill from client database
    client_id = int(client_id_str) if client_id_str else None
    if client_id:
        db_client = get_client_by_id(client_id)
        if db_client:
            if not client_name: client_name = db_client['name']
            if not client_tel: client_tel = db_client.get('tel', '')
            if not client_email: client_email = db_client.get('email', '')
    
    client_info_parts = []
    if client_tel: client_info_parts.append(f"Tél: {client_tel}")
    if client_email: client_info_parts.append(f"Email: {client_email}")
    client_info = " | ".join(client_info_parts)
    
    try:
        hp = float(hp_str) if hp_str else 0
    except:
        hp = 0
    
    job_id = str(uuid.uuid4())[:8]
    job_dir = os.path.join(app.config['UPLOAD_FOLDER'], job_id)
    os.makedirs(job_dir, exist_ok=True)
    
    try:
        if xlsx_source:
            xlsx_path = os.path.join(job_dir, filename)
            shutil.copy2(xlsx_source, xlsx_path)
        else:
            file = request.files['excel_file']
            xlsx_path = os.path.join(job_dir, filename)
            file.save(xlsx_path)
        
        # Logo
        logo_path = None
        if 'logo_file' in request.files:
            lf = request.files['logo_file']
            if lf.filename:
                logo_path = os.path.join(job_dir, 'custom_logo.png')
                lf.save(logo_path)
        if not logo_path:
            for n in ['logo_wannygest.png', 'logo.png']:
                c = os.path.join(BASE_DIR, n)
                if os.path.exists(c):
                    logo_path = os.path.join(job_dir, n)
                    shutil.copy2(c, logo_path)
                    break
        
        emps, detected_client = extract_from_excel(xlsx_path)
        if not emps:
            flash("Aucun employé trouvé", "error")
            return redirect(url_for('traitement'))
        
        if not client_name:
            client_name = detected_client
            # Try to find client in database
            db_client = find_client_by_name(detected_client)
            if db_client:
                client_id = db_client['id']
                if not client_tel: client_tel = db_client.get('tel', '')
                if not client_email: client_email = db_client.get('email', '')
                client_info_parts = []
                if client_tel: client_info_parts.append(f"Tél: {client_tel}")
                if client_email: client_info_parts.append(f"Email: {client_email}")
                client_info = " | ".join(client_info_parts)
        
        all_dates = [rec['date'] for emp in emps for rec in emp['records']]
        all_dates.sort()
        period = f"Période du {all_dates[0]} au {all_dates[-1]}" if all_dates else "Rapport"
        
        base = os.path.splitext(filename)[0]
        pdf_name = f"{base}_RAPPORT_DE_PRESENCE.pdf"
        output_path = os.path.join(job_dir, pdf_name)
        
        generate_full_pdf(emps, output_path, provider_name, provider_info,
                         client_name, period, logo_path, hp=hp, client_info=client_info,
                         work_dir=job_dir)
        
        if not os.path.exists(output_path):
            flash("Erreur génération PDF", "error")
            return redirect(url_for('traitement'))
        
        # Sauvegarder dans le dossier files
        files_dir = os.path.join(app.config['FILES_FOLDER'], job_id)
        os.makedirs(files_dir, exist_ok=True)
        shutil.copy2(output_path, os.path.join(files_dir, pdf_name))
        
        # Copier le xlsx fusionné si dispo
        xlsx_out = None
        if merge_id:
            merged_xlsx = os.path.join(app.config['UPLOAD_FOLDER'], merge_id, 'Presence_fusionnee.xlsx')
            if os.path.exists(merged_xlsx):
                xlsx_out = 'Presence_fusionnee.xlsx'
                shutil.copy2(merged_xlsx, os.path.join(files_dir, xlsx_out))
        
        # Enregistrer dans la BDD
        hp_text = f"{hp}h/jour" if hp > 0 else "Auto"
        create_job(job_id, session['user_id'], client_name, provider_name,
                   filename, pdf_name, xlsx_out, len(emps), period, hp_text, client_id)
        
        user = get_user_by_id(session['user_id'])
        log_activity(session['user_id'], user['full_name'] if user else '?',
                    'Traitement', f"Rapport PDF généré — {client_name}, {len(emps)} employés",
                    request.remote_addr)
        flash(f"Rapport généré avec succès — {len(emps)} employés, {client_name}", "success")
        return send_file(output_path, as_attachment=True, download_name=pdf_name, mimetype='application/pdf')
    
    except Exception as e:
        flash(f"Erreur : {str(e)}", "error")
        return redirect(url_for('traitement'))
    finally:
        _cleanup_old(app.config['UPLOAD_FOLDER'])


# ======================== FICHIERS RH ========================

@app.route('/fichiers')
@permission_required('fichiers')
def fichiers():
    tab = request.args.get('tab', 'pending')
    pending = get_jobs_by_status('traite')
    sent = get_jobs_by_status('envoye')
    return render_template('fichiers.html', page='fichiers', tab=tab, pending=pending, sent=sent)

@app.route('/fichiers/download/<job_id>/<ftype>')
@login_required
def fichiers_download(job_id, ftype):
    safe_id = secure_filename(job_id)
    files_dir = os.path.join(app.config['FILES_FOLDER'], safe_id)
    if not os.path.isdir(files_dir):
        flash("Fichier non trouvé", "error")
        return redirect(url_for('fichiers'))
    for f in os.listdir(files_dir):
        if ftype == 'pdf' and f.endswith('.pdf'):
            return send_from_directory(files_dir, f, as_attachment=True)
        if ftype == 'xlsx' and f.endswith('.xlsx'):
            return send_from_directory(files_dir, f, as_attachment=True)
    flash("Fichier non trouvé", "error")
    return redirect(url_for('fichiers'))

@app.route('/fichiers/marquer/<job_id>')
@permission_required('envoyer')
def fichiers_marquer(job_id):
    mark_job_sent(job_id, session['user_id'])
    job = get_job_by_id(job_id)
    if job:
        create_invoice(job_id, job.get('client_id'), job.get('client_name', ''))
    user = get_user_by_id(session['user_id'])
    log_activity(session['user_id'], user['full_name'] if user else '?',
                'Envoi', f"Rapport {job_id} marqué comme envoyé", request.remote_addr)
    flash("Fichier envoyé — facture créée pour la comptabilité", "success")
    return redirect(url_for('fichiers'))


# ======================== CLIENTS ========================

@app.route('/clients')
@permission_required('clients')
def clients_page():
    clients = get_all_clients()
    return render_template('clients.html', page='clients', clients=clients)

@app.route('/clients/add', methods=['POST'])
@permission_required('clients')
def clients_add():
    create_client(
        request.form['name'], request.form.get('tel', ''),
        request.form.get('email', ''), request.form.get('contact_name', ''),
        request.form.get('address', ''), request.form.get('notes', ''),
        session['user_id']
    )
    flash("Client ajouté", "success")
    return redirect(url_for('clients_page'))

@app.route('/clients/edit/<int:cid>', methods=['GET', 'POST'])
@permission_required('clients')
def clients_edit(cid):
    client = get_client_by_id(cid)
    if not client:
        flash("Client non trouvé", "error")
        return redirect(url_for('clients_page'))
    if request.method == 'POST':
        update_client(cid, name=request.form['name'], tel=request.form.get('tel', ''),
                      email=request.form.get('email', ''), contact_name=request.form.get('contact_name', ''),
                      address=request.form.get('address', ''), notes=request.form.get('notes', ''))
        flash("Client modifié", "success")
        return redirect(url_for('clients_page'))
    return render_template('edit_client.html', page='clients', client=client)

@app.route('/clients/delete/<int:cid>')
@permission_required('clients')
def clients_delete(cid):
    delete_client(cid)
    flash("Client supprimé", "success")
    return redirect(url_for('clients_page'))


# ======================== ADMIN ========================

@app.route('/admin')
@permission_required('admin')
def admin_page():
    users = get_all_users()
    stats = get_dashboard_stats()
    role_perms = {r: get_role_permissions(r) for r in ['admin', 'rh', 'technicien']}
    return render_template('admin.html', page='admin', users=users, stats=stats,
                          all_permissions=ALL_PERMISSIONS, role_perms=role_perms)

@app.route('/admin/add', methods=['POST'])
@permission_required('admin')
def admin_add_user():
    ok, msg = create_user(
        request.form['username'], request.form['email'],
        request.form['password'], request.form['full_name'],
        request.form.get('role', 'technicien')
    )
    flash(msg, "success" if ok else "error")
    return redirect(url_for('admin_page'))

@app.route('/admin/reset', methods=['POST'])
@permission_required('admin')
def admin_reset():
    target = request.form.get('target', '')
    user = get_user_by_id(session['user_id'])
    uname = user['full_name'] if user else '?'
    
    if target == 'jobs':
        reset_jobs()
        files_dir = app.config['FILES_FOLDER']
        if os.path.exists(files_dir):
            shutil.rmtree(files_dir)
            os.makedirs(files_dir, exist_ok=True)
        log_activity(session['user_id'], uname, 'Réinitialisation', 'Tous les rapports supprimés', request.remote_addr)
        flash("Tous les rapports ont été supprimés", "success")
    
    elif target == 'clients':
        reset_clients()
        log_activity(session['user_id'], uname, 'Réinitialisation', 'Tous les clients supprimés', request.remote_addr)
        flash("Tous les clients ont été supprimés", "success")
    
    elif target == 'users':
        reset_users()
        log_activity(session['user_id'], uname, 'Réinitialisation', 'Utilisateurs non-admin supprimés', request.remote_addr)
        flash("Tous les utilisateurs (sauf admin) ont été supprimés", "success")
    
    elif target == 'all':
        reset_all()
        for folder in [app.config['FILES_FOLDER'], app.config['UPLOAD_FOLDER']]:
            if os.path.exists(folder):
                shutil.rmtree(folder)
                os.makedirs(folder, exist_ok=True)
        log_activity(session['user_id'], uname, 'Réinitialisation', 'RÉINITIALISATION COMPLÈTE', request.remote_addr)
        flash("Réinitialisation complète effectuée", "success")
    
    return redirect(url_for('admin_page'))

@app.route('/admin/edit/<int:uid>', methods=['GET', 'POST'])
@permission_required('admin')
def admin_edit_user(uid):
    u = get_user_by_id(uid)
    if not u:
        flash("Utilisateur non trouvé", "error")
        return redirect(url_for('admin_page'))
    if request.method == 'POST':
        updates = {'full_name': request.form['full_name'],
                   'email': request.form['email'],
                   'role': request.form['role']}
        pwd = request.form.get('password', '').strip()
        if pwd:
            updates['password'] = pwd
        update_user(uid, **updates)
        flash("Utilisateur modifié", "success")
        return redirect(url_for('admin_page'))
    return render_template('edit_user.html', page='admin', edit_user=u)

@app.route('/admin/toggle/<int:uid>')
@permission_required('admin')
def admin_toggle_user(uid):
    u = get_user_by_id(uid)
    if u and u['role'] != 'admin':
        update_user(uid, is_active=0 if u['is_active'] else 1)
        flash(f"Utilisateur {'désactivé' if u['is_active'] else 'activé'}", "success")
    return redirect(url_for('admin_page'))

@app.route('/admin/permissions', methods=['POST'])
@permission_required('admin')
def admin_permissions():
    for role in ['rh', 'technicien']:
        perms = [p for p in ALL_PERMISSIONS if request.form.get(f'{role}_{p}')]
        update_role_permissions(role, perms)
    # Admin always has all
    update_role_permissions('admin', ALL_PERMISSIONS)
    flash("Permissions mises à jour", "success")
    return redirect(url_for('admin_page'))


# ======================== LOGS D'ACTIVITÉ ========================

@app.route('/logs')
@permission_required('logs')
def logs_page():
    logs = get_activity_logs(200)
    return render_template('logs.html', page='logs', logs=logs)


# ======================== DÉTAIL RAPPORT + COMMENTAIRES ========================

@app.route('/job/<job_id>')
@login_required
def job_detail(job_id):
    job = get_job_by_id(job_id)
    if not job:
        flash("Rapport non trouvé", "error")
        return redirect(url_for('dashboard'))
    comments = get_job_comments(job_id)
    return render_template('job_detail.html', page='fichiers', job=job, comments=comments)

@app.route('/job/<job_id>/comment', methods=['POST'])
@login_required
def job_add_comment(job_id):
    comment = request.form.get('comment', '').strip()
    if comment:
        user = get_user_by_id(session['user_id'])
        add_job_comment(job_id, session['user_id'], user['full_name'] if user else '?', comment)
        log_activity(session['user_id'], user['full_name'] if user else '?',
                    'Commentaire', f"Commentaire ajouté sur rapport {job_id}", request.remote_addr)
    return redirect(url_for('job_detail', job_id=job_id))

@app.route('/job/<job_id>/notes', methods=['POST'])
@login_required
def job_update_notes(job_id):
    notes = request.form.get('notes', '').strip()
    update_job_notes(job_id, notes)
    flash("Notes mises à jour", "success")
    return redirect(url_for('job_detail', job_id=job_id))


# ======================== SAUVEGARDE BDD ========================

@app.route('/admin/backup')
@permission_required('admin')
def admin_backup():
    db_path = get_db_path()
    if os.path.exists(db_path):
        user = get_user_by_id(session['user_id'])
        log_activity(session['user_id'], user['full_name'] if user else '?',
                    'Sauvegarde', 'Téléchargement de la base de données', request.remote_addr)
        return send_file(db_path, as_attachment=True,
                        download_name=f"ramya_backup_{datetime.now().strftime('%Y%m%d_%H%M')}.db")
    flash("Base de données introuvable", "error")
    return redirect(url_for('admin_page'))


# ======================== PWA MANIFEST ========================

@app.route('/manifest.json')
def pwa_manifest():
    manifest = {
        "name": "WannyGest",
        "short_name": "WannyGest",
        "start_url": "/dashboard",
        "display": "standalone",
        "background_color": "#0d2137",
        "theme_color": "#1a3a5c",
        "icons": [
            {"src": "/static/logo_wannygest.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/logo_wannygest.png", "sizes": "512x512", "type": "image/png"}
        ]
    }
    return jsonify(manifest)

@app.route('/sw.js')
def service_worker():
    return app.send_static_file('sw.js') if os.path.exists(os.path.join(BASE_DIR, 'sw.js')) else ('', 204)


# ======================== CONTRATS ========================

@app.route('/contrats')
@permission_required('contrats')
def contrats_page():
    contracts = get_all_contracts()
    clients = get_all_clients()
    return render_template('contrats.html', page='contrats', contracts=contracts, clients=clients)

@app.route('/contrats/add', methods=['POST'])
@permission_required('contrats')
def contrats_add():
    create_contract(
        int(request.form['client_id']),
        request.form.get('reference', ''),
        request.form.get('start_date', ''),
        request.form.get('end_date', ''),
        float(request.form.get('monthly_rate', 0) or 0),
        request.form.get('description', ''),
        session['user_id']
    )
    user = get_user_by_id(session['user_id'])
    log_activity(session['user_id'], user['full_name'] if user else '?',
                'Contrat', 'Nouveau contrat ajouté', request.remote_addr)
    flash("Contrat ajouté", "success")
    return redirect(url_for('contrats_page'))

@app.route('/contrats/edit/<int:cid>', methods=['GET', 'POST'])
@permission_required('contrats')
def contrats_edit(cid):
    contract = get_contract_by_id(cid)
    if not contract:
        flash("Contrat non trouvé", "error")
        return redirect(url_for('contrats_page'))
    if request.method == 'POST':
        update_contract(cid,
            client_id=int(request.form['client_id']),
            reference=request.form.get('reference', ''),
            start_date=request.form.get('start_date', ''),
            end_date=request.form.get('end_date', ''),
            monthly_rate=float(request.form.get('monthly_rate', 0) or 0),
            description=request.form.get('description', ''),
            status=request.form.get('status', 'actif'))
        flash("Contrat modifié", "success")
        return redirect(url_for('contrats_page'))
    clients = get_all_clients()
    return render_template('edit_contract.html', page='contrats', contract=contract, clients=clients)

@app.route('/contrats/delete/<int:cid>')
@permission_required('contrats')
def contrats_delete(cid):
    delete_contract(cid)
    flash("Contrat supprimé", "success")
    return redirect(url_for('contrats_page'))


# ======================== COMPARAISON MENSUELLE ========================

@app.route('/comparaison')
@login_required
def comparaison_page():
    stats = get_client_monthly_stats()
    # Collect all months
    all_months = set()
    for client_data in stats.values():
        all_months.update(client_data.keys())
    months = sorted(all_months)
    return render_template('comparaison.html', page='comparaison', stats=stats, months=months)


# ======================== ALERTES ========================

@app.route('/alertes')
@login_required
def alertes_page():
    # Analyser les derniers rapports pour trouver les alertes
    jobs = get_all_jobs()
    alerts = []
    
    for job in jobs:
        if not job.get('job_id'):
            continue
        # Charger les données du rapport
        files_dir = os.path.join(app.config['FILES_FOLDER'], job['job_id'])
        xlsx_path = None
        if os.path.isdir(files_dir):
            for f in os.listdir(files_dir):
                if f.endswith('.xlsx'):
                    xlsx_path = os.path.join(files_dir, f)
                    break
        
        if not xlsx_path or not os.path.exists(xlsx_path):
            continue
        
        try:
            emps, _ = extract_from_excel(xlsx_path)
            from rapport_core import calc_employee_stats
            for emp in emps:
                enriched, stats = calc_employee_stats(emp)
                # Alertes retards excessifs (>5 jours)
                if stats['days_late'] >= 5:
                    alerts.append({
                        'type': 'retard',
                        'severity': 'high' if stats['days_late'] >= 10 else 'medium',
                        'employee': emp['name'],
                        'client': job['client_name'],
                        'detail': f"{stats['days_late']} jours de retard",
                        'period': job.get('period', ''),
                        'job_id': job['job_id']
                    })
                # Alertes absences (>3 jours)
                if stats['days_absent'] >= 3:
                    alerts.append({
                        'type': 'absence',
                        'severity': 'high' if stats['days_absent'] >= 5 else 'medium',
                        'employee': emp['name'],
                        'client': job['client_name'],
                        'detail': f"{stats['days_absent']} jours d'absence",
                        'period': job.get('period', ''),
                        'job_id': job['job_id']
                    })
        except:
            continue
    
    # Trier: high en premier
    alerts.sort(key=lambda a: (0 if a['severity'] == 'high' else 1, a['client']))
    return render_template('alertes.html', page='alertes', alerts=alerts)


# ======================== ENVOI EMAIL ========================

@app.route('/fichiers/email/<job_id>', methods=['GET', 'POST'])
@permission_required('envoyer')
def fichiers_email(job_id):
    job = get_job_by_id(job_id)
    if not job:
        flash("Rapport non trouvé", "error")
        return redirect(url_for('fichiers'))
    
    # Pré-remplir avec les infos client
    client = get_client_by_id(job['client_id']) if job.get('client_id') else None
    default_email = client['email'] if client and client.get('email') else ''
    
    if request.method == 'POST':
        to_email = request.form.get('to_email', '').strip()
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()
        smtp_host = request.form.get('smtp_host', '').strip()
        smtp_port = int(request.form.get('smtp_port', 587))
        smtp_user = request.form.get('smtp_user', '').strip()
        smtp_pass = request.form.get('smtp_pass', '').strip()
        
        # Sauvegarder les paramètres SMTP
        if smtp_host and smtp_user:
            save_smtp_settings(session['user_id'], smtp_host, smtp_port, smtp_user, smtp_pass)
        
        if not all([to_email, subject, smtp_host, smtp_user, smtp_pass]):
            flash("Tous les champs SMTP sont obligatoires", "error")
            smtp = get_smtp_settings(session['user_id'])
            return render_template('email_send.html', page='fichiers', job=job,
                                 default_email=default_email, smtp=smtp)
        
        # Préparer le fichier PDF
        files_dir = os.path.join(app.config['FILES_FOLDER'], secure_filename(job_id))
        pdf_path = None
        if os.path.isdir(files_dir):
            for f in os.listdir(files_dir):
                if f.endswith('.pdf'):
                    pdf_path = os.path.join(files_dir, f)
                    break
        
        if not pdf_path:
            flash("Fichier PDF non trouvé", "error")
            return redirect(url_for('fichiers'))
        
        try:
            msg = MIMEMultipart()
            msg['From'] = smtp_user
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Joindre le PDF
            with open(pdf_path, 'rb') as f:
                part = MIMEBase('application', 'pdf')
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(pdf_path)}"')
                msg.attach(part)
            
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
            server.quit()
            
            # Marquer comme envoyé
            mark_job_sent(job_id, session['user_id'])
            user = get_user_by_id(session['user_id'])
            log_activity(session['user_id'], user['full_name'] if user else '?',
                        'Email', f"Rapport envoyé par email à {to_email}", request.remote_addr)
            
            flash(f"Email envoyé avec succès à {to_email}", "success")
            return redirect(url_for('fichiers'))
        
        except Exception as e:
            flash(f"Erreur d'envoi : {str(e)}", "error")
    
    smtp = get_smtp_settings(session['user_id'])
    return render_template('email_send.html', page='fichiers', job=job, default_email=default_email, smtp=smtp)


# ======================== COMPTABILITÉ ========================

@app.route('/comptabilite')
@permission_required('comptabilite')
def comptabilite_page():
    tab = request.args.get('tab', 'a_envoyer')
    inv_stats = get_invoice_stats()
    invoices = get_invoices_by_status(tab) if tab != 'all' else get_all_invoices()
    return render_template('comptabilite.html', page='comptabilite', tab=tab,
                          invoices=invoices, inv_stats=inv_stats)

@app.route('/comptabilite/status/<int:inv_id>/<status>')
@permission_required('comptabilite')
def comptabilite_status(inv_id, status):
    if status in ('envoyee', 'en_attente_paiement', 'payee', 'a_envoyer'):
        update_invoice_status(inv_id, status, session.get('user_id'))
        user = get_user_by_id(session['user_id'])
        log_activity(session['user_id'], user['full_name'] if user else '?',
                    'Facture', f"Facture #{inv_id} → {status}", request.remote_addr)
        flash(f"Statut mis à jour : {status}", "success")
    return redirect(url_for('comptabilite_page'))


# ======================== RAPPORTS DE VISITE ========================

@app.route('/visites')
@permission_required('visites')
def visites_page():
    tab = request.args.get('tab', 'en_attente')
    visits = get_visit_reports(tab if tab != 'all' else None)
    v_stats = get_visit_stats()
    return render_template('visites.html', page='visites', tab=tab, visits=visits, v_stats=v_stats)

@app.route('/visites/new', methods=['GET', 'POST'])
@permission_required('visites')
def visites_new():
    if request.method == 'POST':
        client_id = request.form.get('client_id', '')
        client_id = int(client_id) if client_id else None
        client_name = request.form.get('client_name', '').strip()
        
        if client_id and not client_name:
            c = get_client_by_id(client_id)
            if c: client_name = c['name']
        
        create_visit_report(
            client_id, client_name,
            request.form.get('site_name', ''),
            request.form.get('site_address', ''),
            request.form.get('site_location', ''),
            request.form.get('contact_name', ''),
            request.form.get('contact_tel', ''),
            request.form.get('visit_date', ''),
            request.form.get('needs', ''),
            request.form.get('observations', ''),
            request.form.get('equipment', ''),
            session['user_id']
        )
        user = get_user_by_id(session['user_id'])
        log_activity(session['user_id'], user['full_name'] if user else '?',
                    'Visite', f"Rapport de visite créé — {client_name}", request.remote_addr)
        flash("Rapport de visite créé — En attente de proforma", "success")
        return redirect(url_for('visites_page'))
    
    clients = get_all_clients()
    return render_template('visite_new.html', page='visites', clients=clients)

@app.route('/visites/<int:vid>')
@login_required
def visite_detail(vid):
    visit = get_visit_by_id(vid)
    if not visit:
        flash("Rapport non trouvé", "error")
        return redirect(url_for('visites_page'))
    return render_template('visite_detail.html', page='visites', visit=visit)

@app.route('/visites/proforma/<int:vid>', methods=['POST'])
@permission_required('proforma')
def visites_proforma(vid):
    ref = request.form.get('proforma_ref', '').strip()
    amount = float(request.form.get('proforma_amount', 0) or 0)
    update_visit_proforma(vid, ref, amount, session['user_id'])
    user = get_user_by_id(session['user_id'])
    log_activity(session['user_id'], user['full_name'] if user else '?',
                'Proforma', f"Proforma {ref} envoyé pour visite #{vid}", request.remote_addr)
    flash(f"Proforma {ref} envoyé", "success")
    return redirect(url_for('visites_page'))


# ======================== LANGUE ========================

@app.route('/lang/<lang>')
def set_language(lang):
    if lang in ('fr', 'en'):
        session['lang'] = lang
    return redirect(request.referrer or url_for('dashboard'))


# ======================== EXPORT STATS ========================

@app.route('/export/stats')
@permission_required('admin')
def export_stats():
    """Exporte les statistiques en PDF avec graphiques."""
    from rapport_core import _generate_chart_image
    
    stats = get_dashboard_stats()
    monthly = get_client_monthly_stats()
    
    # Générer un rapport simple avec reportlab
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.colors import HexColor
    
    export_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'export')
    os.makedirs(export_dir, exist_ok=True)
    output = os.path.join(export_dir, 'statistiques_ramya.pdf')
    
    doc = SimpleDocTemplate(output, pagesize=A4)
    story = []
    
    title_style = ParagraphStyle('title', fontSize=18, alignment=TA_CENTER,
                                  textColor=HexColor('#1a3a5c'), spaceAfter=20)
    h2_style = ParagraphStyle('h2', fontSize=14, textColor=HexColor('#1a3a5c'),
                               spaceAfter=10, spaceBefore=20)
    normal = ParagraphStyle('normal', fontSize=11, spaceAfter=6)
    
    story.append(Paragraph("RAMYA TECHNOLOGIE & INNOVATION", title_style))
    story.append(Paragraph("Rapport Statistique", title_style))
    story.append(Spacer(1, 10*mm))
    
    story.append(Paragraph("Vue d'ensemble", h2_style))
    story.append(Paragraph(f"Rapports traités : {stats['total_jobs']}", normal))
    story.append(Paragraph(f"En attente d'envoi : {stats['pending_jobs']}", normal))
    story.append(Paragraph(f"Envoyés : {stats['sent_jobs']}", normal))
    story.append(Paragraph(f"Clients : {stats['total_clients']}", normal))
    story.append(Paragraph(f"Utilisateurs : {stats['total_users']}", normal))
    
    if monthly:
        story.append(Paragraph("Détail par client et par mois", h2_style))
        for client, months in monthly.items():
            story.append(Paragraph(f"<b>{client}</b>", normal))
            data = [['Mois', 'Rapports', 'Employés', 'Envoyés', 'En attente']]
            for month, m_stats in sorted(months.items()):
                data.append([month, m_stats['count'], m_stats['employees'],
                           m_stats['sent'], m_stats['pending']])
            t = Table(data, colWidths=[35*mm, 25*mm, 25*mm, 25*mm, 25*mm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), HexColor('#1a3a5c')),
                ('TEXTCOLOR', (0,0), (-1,0), HexColor('#ffffff')),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t)
            story.append(Spacer(1, 5*mm))
    
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph(f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}", normal))
    
    doc.build(story)
    
    user = get_user_by_id(session['user_id'])
    log_activity(session['user_id'], user['full_name'] if user else '?',
                'Export', 'Export statistiques PDF', request.remote_addr)
    
    return send_file(output, as_attachment=True,
                    download_name=f"stats_ramya_{datetime.now().strftime('%Y%m')}.pdf")


# ======================== DEVIS / PROFORMA ========================

@app.route('/devis')
@permission_required('proforma')
def devis_page():
    tab = request.args.get('tab', 'all')
    d_stats = get_devis_stats()
    devis_list = get_all_devis(tab if tab in ('devis', 'proforma') else None)
    return render_template('devis.html', page='devis', tab=tab, devis_list=devis_list, d_stats=d_stats)

@app.route('/devis/new', methods=['GET', 'POST'])
@permission_required('proforma')
def devis_new():
    if request.method == 'POST':
        items = []
        i = 1
        while request.form.get(f'item_{i}_designation'):
            items.append({
                'num': i,
                'designation': request.form.get(f'item_{i}_designation', ''),
                'detail': request.form.get(f'item_{i}_detail', ''),
                'qty': int(request.form.get(f'item_{i}_qty', 1) or 1),
                'prix': float(request.form.get(f'item_{i}_prix', 0) or 0),
                'remise': float(request.form.get(f'item_{i}_remise', 0) or 0),
            })
            i += 1
        
        total_ht = sum(it['qty'] * it['prix'] - it['remise'] for it in items)
        main_oeuvre = float(request.form.get('main_oeuvre', 0) or 0)
        petites_fourn = float(request.form.get('petites_fournitures', 0) or 0)
        remise_glob = float(request.form.get('remise', 0) or 0)
        total_ttc = total_ht + petites_fourn - remise_glob
        
        client_id = request.form.get('client_id', '')
        client_id = int(client_id) if client_id else None
        
        did, ref = create_devis(
            client_id, request.form.get('client_name', ''),
            request.form.get('client_code', ''),
            request.form.get('contact_commercial', ''),
            request.form.get('objet', ''),
            json.dumps(items), total_ht, petites_fourn, total_ttc,
            main_oeuvre, remise_glob,
            request.form.get('notes', ''),
            session['user_id'],
            request.form.get('doc_type', 'devis')
        )
        
        user = get_user_by_id(session['user_id'])
        log_activity(session['user_id'], user['full_name'] if user else '?',
                    'Devis', f"{ref} créé pour {request.form.get('client_name', '')}", request.remote_addr)
        flash(f"Devis {ref} créé — {total_ttc:,.0f} FCFA TTC", "success")
        return redirect(url_for('devis_page'))
    
    clients = get_all_clients()
    return render_template('devis_new.html', page='devis', clients=clients)

@app.route('/devis/pdf/<int:did>')
@login_required
def devis_pdf(did):
    devis = get_devis_by_id(did)
    if not devis:
        flash("Devis non trouvé", "error")
        return redirect(url_for('devis_page'))
    
    export_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'devis')
    os.makedirs(export_dir, exist_ok=True)
    output = os.path.join(export_dir, f"{devis['reference']}.pdf")
    
    devis['date'] = devis.get('created_at', '')[:10]
    generate_devis_pdf(devis, output)
    
    return send_file(output, as_attachment=True, download_name=f"{devis['reference']}.pdf")

@app.route('/devis/status/<int:did>/<status>')
@permission_required('proforma')
def devis_status(did, status):
    if status in ('brouillon', 'envoye', 'accepte', 'refuse'):
        update_devis_status(did, status)
        flash(f"Statut mis à jour : {status}", "success")
    return redirect(url_for('devis_page'))


# ======================== RH MODULE ========================

@app.route('/rh')
@permission_required('fichiers')
def rh_dashboard():
    emp_stats = get_employee_stats()
    return render_template('rh_dashboard.html', page='rh', emp_stats=emp_stats)

@app.route('/rh/personnel')
@permission_required('fichiers')
def rh_personnel():
    employees = get_all_employees()
    return render_template('rh_personnel.html', page='personnel', employees=employees)

@app.route('/rh/personnel/add', methods=['GET', 'POST'])
@permission_required('fichiers')
def rh_personnel_add():
    if request.method == 'POST':
        create_employee(
            first_name=request.form['first_name'],
            last_name=request.form['last_name'],
            matricule=request.form.get('matricule', ''),
            email=request.form.get('email', ''),
            tel=request.form.get('tel', ''),
            position=request.form.get('position', ''),
            department=request.form.get('department', ''),
            hire_date=request.form.get('hire_date', ''),
            contract_type=request.form.get('contract_type', 'CDI'),
            salary=float(request.form.get('salary', 0) or 0),
            insurance=request.form.get('insurance', ''),
            insurance_number=request.form.get('insurance_number', ''),
            emergency_contact=request.form.get('emergency_contact', ''),
            emergency_tel=request.form.get('emergency_tel', ''),
        )
        user = get_user_by_id(session['user_id'])
        log_activity(session['user_id'], user['full_name'] if user else '?', 'RH',
                    f"Employé ajouté: {request.form['first_name']} {request.form['last_name']}", request.remote_addr)
        flash("Employé ajouté", "success")
        return redirect(url_for('rh_personnel'))
    return render_template('rh_personnel_add.html', page='personnel')

@app.route('/rh/personnel/edit/<int:eid>', methods=['GET', 'POST'])
@permission_required('fichiers')
def rh_personnel_edit(eid):
    emp = get_employee_by_id(eid)
    if not emp:
        flash("Employé non trouvé", "error")
        return redirect(url_for('rh_personnel'))
    if request.method == 'POST':
        update_employee(eid,
            first_name=request.form['first_name'], last_name=request.form['last_name'],
            matricule=request.form.get('matricule', ''), email=request.form.get('email', ''),
            tel=request.form.get('tel', ''), position=request.form.get('position', ''),
            department=request.form.get('department', ''), hire_date=request.form.get('hire_date', ''),
            contract_type=request.form.get('contract_type', 'CDI'),
            salary=float(request.form.get('salary', 0) or 0),
            insurance=request.form.get('insurance', ''), insurance_number=request.form.get('insurance_number', ''),
            status=request.form.get('status', 'actif'))
        flash("Employé modifié", "success")
        return redirect(url_for('rh_personnel'))
    return render_template('rh_personnel_edit.html', page='personnel', emp=emp)

@app.route('/rh/conges')
@permission_required('fichiers')
def rh_conges():
    tab = request.args.get('tab', 'en_attente')
    leaves = get_leaves(tab if tab != 'all' else None)
    employees = get_all_employees()
    return render_template('rh_conges.html', page='conges', tab=tab, leaves=leaves, employees=employees)

@app.route('/rh/conges/add', methods=['POST'])
@permission_required('fichiers')
def rh_conges_add():
    create_leave(
        int(request.form['employee_id']),
        request.form.get('leave_type', 'conge_annuel'),
        request.form['start_date'],
        request.form['end_date'],
        int(request.form.get('days', 0) or 0),
        request.form.get('reason', '')
    )
    flash("Demande de congé créée", "success")
    return redirect(url_for('rh_conges'))

@app.route('/rh/conges/approve/<int:lid>/<status>')
@permission_required('fichiers')
def rh_conges_status(lid, status):
    if status in ('approuve', 'refuse'):
        update_leave_status(lid, status, session.get('user_id'))
        flash(f"Congé {'approuvé' if status == 'approuve' else 'refusé'}", "success")
    return redirect(url_for('rh_conges'))

@app.route('/rh/paie')
@permission_required('fichiers')
def rh_paie():
    period = request.args.get('period', '')
    payslips = get_payslips(period if period else None)
    employees = get_all_employees()
    return render_template('rh_paie.html', page='paie', payslips=payslips, employees=employees, period=period)

@app.route('/rh/paie/add', methods=['POST'])
@permission_required('fichiers')
def rh_paie_add():
    base = float(request.form.get('base_salary', 0) or 0)
    bonus = float(request.form.get('bonus', 0) or 0)
    commission = float(request.form.get('commission', 0) or 0)
    overtime = float(request.form.get('overtime_amount', 0) or 0)
    deductions = float(request.form.get('deductions', 0) or 0)
    insurance = float(request.form.get('insurance_amount', 0) or 0)
    tax = float(request.form.get('tax_amount', 0) or 0)
    net = base + bonus + commission + overtime - deductions - insurance - tax
    
    create_payslip(
        employee_id=int(request.form['employee_id']),
        period=request.form['period'],
        base_salary=base, bonus=bonus, commission=commission,
        overtime_amount=overtime, deductions=deductions,
        insurance_amount=insurance, tax_amount=tax, net_salary=net
    )
    flash(f"Bulletin de paie créé — Net: {net:,.0f} FCFA", "success")
    return redirect(url_for('rh_paie'))


# ======================== UTILS ========================

def _cleanup_old(upload_dir, max_age_hours=2):
    import time
    now = time.time()
    try:
        for name in os.listdir(upload_dir):
            path = os.path.join(upload_dir, name)
            if os.path.isdir(path) and (now - os.path.getmtime(path)) > max_age_hours * 3600:
                shutil.rmtree(path, ignore_errors=True)
    except:
        pass


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
