#!/usr/bin/env python3
"""
beOtop · Serveur complet
Auth + Multi-clients + Rôles (admin / client / kiosque)
"""

from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, csv, io, secrets
from datetime import datetime, date
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

DB_PATH = os.path.join(os.path.dirname(__file__), 'beotop.db')

# ══════════════════════════════════════════════════════════════════════
# BASE DE DONNÉES
# ══════════════════════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_db() as db:

        # Clients (entreprises)
        db.execute('''CREATE TABLE IF NOT EXISTS clients (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at  TEXT    DEFAULT (datetime('now','localtime')),
            nom         TEXT    NOT NULL,
            slug        TEXT    NOT NULL UNIQUE,
            contact_nom TEXT,
            contact_email TEXT,
            actif       INTEGER DEFAULT 1
        )''')

        # Sites (un client peut avoir plusieurs sites)
        db.execute('''CREATE TABLE IF NOT EXISTS sites (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at  TEXT    DEFAULT (datetime('now','localtime')),
            client_id   INTEGER NOT NULL REFERENCES clients(id),
            nom         TEXT    NOT NULL,
            slug        TEXT    NOT NULL UNIQUE,
            ville       TEXT,
            nb_salaries INTEGER DEFAULT 0,
            actif       INTEGER DEFAULT 1
        )''')

        # Utilisateurs
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at  TEXT    DEFAULT (datetime('now','localtime')),
            email       TEXT    NOT NULL UNIQUE,
            password    TEXT    NOT NULL,
            nom         TEXT,
            role        TEXT    NOT NULL DEFAULT 'client',
            client_id   INTEGER REFERENCES clients(id),
            actif       INTEGER DEFAULT 1
        )''')

        # Sessions kiosque
        db.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at  TEXT    DEFAULT (datetime('now','localtime')),
            date        TEXT    NOT NULL,
            heure       TEXT    NOT NULL,
            departement TEXT    NOT NULL,
            ateliers    TEXT,
            mood        TEXT,
            site_id     INTEGER REFERENCES sites(id),
            site_slug   TEXT
        )''')

        db.execute('CREATE INDEX IF NOT EXISTS idx_sessions_date     ON sessions(date)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_sessions_site     ON sessions(site_slug)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_sessions_dept     ON sessions(departement)')

        db.commit()

    # Créer admin par défaut si aucun user
    with get_db() as db:
        count = db.execute("SELECT COUNT(*) as n FROM users").fetchone()['n']
        if count == 0:
            db.execute(
                "INSERT INTO users (email, password, nom, role) VALUES (?,?,?,?)",
                ['admin@beotop.fr', generate_password_hash('beotop2026'), 'Admin beOtop', 'admin']
            )
            db.commit()
            print("✓ Admin créé : admin@beotop.fr / beotop2026")

    print(f"✓ Base initialisée : {DB_PATH}")

# ══════════════════════════════════════════════════════════════════════
# AUTH HELPERS
# ══════════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Non authentifié', 'redirect': '/login'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            return jsonify({'error': 'Accès refusé'}), 403
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' not in session:
        return None
    with get_db() as db:
        return db.execute("SELECT * FROM users WHERE id=?", [session['user_id']]).fetchone()

# ══════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email=? AND actif=1", [email]).fetchone()

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

    session.permanent = True
    session['user_id']   = user['id']
    session['role']      = user['role']
    session['client_id'] = user['client_id']
    session['nom']       = user['nom']

    return jsonify({
        'ok': True,
        'role': user['role'],
        'nom': user['nom'],
        'redirect': '/admin' if user['role'] == 'admin' else '/dashboard'
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def me():
    user = get_current_user()
    return jsonify({
        'id': user['id'], 'email': user['email'],
        'nom': user['nom'], 'role': user['role'],
        'client_id': user['client_id']
    })

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')
    if len(new_pw) < 6:
        return jsonify({'error': 'Mot de passe trop court (6 car. min)'}), 400
    user = get_current_user()
    if not check_password_hash(user['password'], old_pw):
        return jsonify({'error': 'Ancien mot de passe incorrect'}), 401
    with get_db() as db:
        db.execute("UPDATE users SET password=? WHERE id=?", [generate_password_hash(new_pw), user['id']])
        db.commit()
    return jsonify({'ok': True})

# ══════════════════════════════════════════════════════════════════════
# ADMIN — CLIENTS
# ══════════════════════════════════════════════════════════════════════

@app.route('/api/admin/clients', methods=['GET'])
@login_required
@admin_required
def admin_get_clients():
    with get_db() as db:
        clients = db.execute('''
            SELECT c.*, COUNT(DISTINCT s.id) as nb_sites,
                   (SELECT COUNT(*) FROM sessions se JOIN sites si ON se.site_id=si.id WHERE si.client_id=c.id) as nb_sessions
            FROM clients c
            LEFT JOIN sites s ON s.client_id=c.id
            GROUP BY c.id ORDER BY c.created_at DESC
        ''').fetchall()
    return jsonify([dict(c) for c in clients])

@app.route('/api/admin/clients', methods=['POST'])
@login_required
@admin_required
def admin_create_client():
    data = request.get_json()
    nom = data.get('nom', '').strip()
    if not nom:
        return jsonify({'error': 'Nom requis'}), 400

    slug = nom.lower().replace(' ', '-').replace("'", '').replace('é','e').replace('è','e').replace('ê','e')
    slug = ''.join(c for c in slug if c.isalnum() or c == '-')

    # Mot de passe temporaire
    tmp_pw = secrets.token_urlsafe(8)

    with get_db() as db:
        try:
            cur = db.execute(
                "INSERT INTO clients (nom, slug, contact_nom, contact_email) VALUES (?,?,?,?)",
                [nom, slug, data.get('contact_nom',''), data.get('contact_email','')]
            )
            client_id = cur.lastrowid

            # Créer user client automatiquement
            if data.get('contact_email'):
                db.execute(
                    "INSERT INTO users (email, password, nom, role, client_id) VALUES (?,?,?,?,?)",
                    [data['contact_email'].lower(), generate_password_hash(tmp_pw),
                     data.get('contact_nom', nom), 'client', client_id]
                )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Ce client existe déjà'}), 409

    return jsonify({'ok': True, 'client_id': client_id, 'slug': slug, 'tmp_password': tmp_pw}), 201

@app.route('/api/admin/clients/<int:client_id>', methods=['PUT'])
@login_required
@admin_required
def admin_update_client(client_id):
    data = request.get_json()
    with get_db() as db:
        db.execute(
            "UPDATE clients SET nom=?, contact_nom=?, contact_email=?, actif=? WHERE id=?",
            [data.get('nom'), data.get('contact_nom'), data.get('contact_email'), data.get('actif', 1), client_id]
        )
        db.commit()
    return jsonify({'ok': True})

# ══════════════════════════════════════════════════════════════════════
# ADMIN — SITES
# ══════════════════════════════════════════════════════════════════════

@app.route('/api/admin/sites', methods=['GET'])
@login_required
@admin_required
def admin_get_sites():
    with get_db() as db:
        sites = db.execute('''
            SELECT s.*, c.nom as client_nom,
                   (SELECT COUNT(*) FROM sessions se WHERE se.site_id=s.id) as nb_sessions
            FROM sites s JOIN clients c ON s.client_id=c.id
            ORDER BY c.nom, s.nom
        ''').fetchall()
    return jsonify([dict(s) for s in sites])

@app.route('/api/admin/sites', methods=['POST'])
@login_required
@admin_required
def admin_create_site():
    data = request.get_json()
    nom = data.get('nom', '').strip()
    client_id = data.get('client_id')
    if not nom or not client_id:
        return jsonify({'error': 'Nom et client_id requis'}), 400

    with get_db() as db:
        client = db.execute("SELECT slug FROM clients WHERE id=?", [client_id]).fetchone()
        if not client:
            return jsonify({'error': 'Client introuvable'}), 404

        slug_nom = nom.lower().replace(' ', '-').replace("'", '')
        slug = f"{client['slug']}-{slug_nom}"
        slug = ''.join(c for c in slug if c.isalnum() or c == '-')

        try:
            cur = db.execute(
                "INSERT INTO sites (client_id, nom, slug, ville, nb_salaries) VALUES (?,?,?,?,?)",
                [client_id, nom, slug, data.get('ville',''), data.get('nb_salaries', 0)]
            )
            db.commit()
            site_id = cur.lastrowid
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Ce site existe déjà'}), 409

    return jsonify({'ok': True, 'site_id': site_id, 'slug': slug, 'kiosk_url': f'/kiosk/{slug}'}), 201

# ══════════════════════════════════════════════════════════════════════
# ADMIN — USERS
# ══════════════════════════════════════════════════════════════════════

@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_get_users():
    with get_db() as db:
        users = db.execute('''
            SELECT u.id, u.email, u.nom, u.role, u.actif, u.created_at,
                   c.nom as client_nom
            FROM users u LEFT JOIN clients c ON u.client_id=c.id
            ORDER BY u.role, u.created_at DESC
        ''').fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/api/admin/users', methods=['POST'])
@login_required
@admin_required
def admin_create_user():
    data = request.get_json()
    email = data.get('email','').strip().lower()
    if not email:
        return jsonify({'error': 'Email requis'}), 400
    tmp_pw = data.get('password') or secrets.token_urlsafe(8)
    with get_db() as db:
        try:
            db.execute(
                "INSERT INTO users (email, password, nom, role, client_id) VALUES (?,?,?,?,?)",
                [email, generate_password_hash(tmp_pw), data.get('nom',''), data.get('role','client'), data.get('client_id')]
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Email déjà utilisé'}), 409
    return jsonify({'ok': True, 'tmp_password': tmp_pw}), 201

@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    new_pw = secrets.token_urlsafe(8)
    with get_db() as db:
        db.execute("UPDATE users SET password=? WHERE id=?", [generate_password_hash(new_pw), user_id])
        db.commit()
    return jsonify({'ok': True, 'new_password': new_pw})

# ══════════════════════════════════════════════════════════════════════
# KIOSQUE — Sessions (public, authentifié par slug de site)
# ══════════════════════════════════════════════════════════════════════

@app.route('/api/kiosk/<site_slug>/session', methods=['POST'])
def kiosk_save_session(site_slug):
    """Enregistre une séance depuis le kiosque — pas de login requis"""
    with get_db() as db:
        site = db.execute("SELECT * FROM sites WHERE slug=? AND actif=1", [site_slug]).fetchone()
    if not site:
        return jsonify({'error': 'Site introuvable'}), 404

    data = request.get_json()
    if not data or not data.get('departement'):
        return jsonify({'error': 'Champ departement requis'}), 400

    now = datetime.now()
    ateliers = data.get('ateliers', [])
    if isinstance(ateliers, list):
        ateliers = ', '.join(ateliers)

    with get_db() as db:
        cur = db.execute(
            "INSERT INTO sessions (date, heure, departement, ateliers, mood, site_id, site_slug) VALUES (?,?,?,?,?,?,?)",
            [now.strftime('%Y-%m-%d'), now.strftime('%H:%M'),
             data.get('departement'), ateliers,
             data.get('mood', ''), site['id'], site_slug]
        )
        db.commit()

    return jsonify({'ok': True, 'id': cur.lastrowid, 'heure': now.strftime('%H:%M')}), 201

@app.route('/api/kiosk/<site_slug>/info', methods=['GET'])
def kiosk_info(site_slug):
    """Infos du site pour le kiosque"""
    with get_db() as db:
        site = db.execute('''
            SELECT s.*, c.nom as client_nom
            FROM sites s JOIN clients c ON s.client_id=c.id
            WHERE s.slug=? AND s.actif=1
        ''', [site_slug]).fetchone()
    if not site:
        return jsonify({'error': 'Site introuvable'}), 404
    return jsonify(dict(site))

# ══════════════════════════════════════════════════════════════════════
# STATS & SESSIONS — Admin voit tout, Client voit son périmètre
# ══════════════════════════════════════════════════════════════════════

def build_date_clause(period, prefix=''):
    p = f"{prefix}." if prefix else ""
    if period == 'today':   return f"{p}date = date('now','localtime')"
    if period == 'week':    return f"{p}date >= date('now','localtime','-7 days')"
    if period == 'month':   return f"{p}date >= date('now','localtime','-30 days')"
    if period == 'year':    return f"{p}date >= date('now','localtime','-365 days')"
    return "1=1"

def get_site_filter(site_slug=None):
    """Retourne clause WHERE et params selon le rôle de l'utilisateur"""
    role = session.get('role')
    client_id = session.get('client_id')

    if role == 'admin':
        if site_slug:
            return "site_slug = ?", [site_slug]
        return "1=1", []
    else:
        # Client : uniquement ses sites
        with get_db() as db:
            sites = db.execute("SELECT slug FROM sites WHERE client_id=?", [client_id]).fetchall()
        slugs = [s['slug'] for s in sites]
        if not slugs:
            return "1=0", []
        if site_slug and site_slug in slugs:
            return "site_slug = ?", [site_slug]
        placeholders = ','.join(['?'] * len(slugs))
        return f"site_slug IN ({placeholders})", slugs

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    period    = request.args.get('period', 'today')
    site_slug = request.args.get('site')
    date_clause  = build_date_clause(period)
    site_clause, site_params = get_site_filter(site_slug)

    where = f"WHERE {date_clause} AND {site_clause}"

    with get_db() as db:
        total = db.execute(f'SELECT COUNT(*) as n FROM sessions {where}', site_params).fetchone()['n']

        by_dept = db.execute(f'''
            SELECT departement as label, COUNT(*) as n FROM sessions {where}
            GROUP BY departement ORDER BY n DESC
        ''', site_params).fetchall()

        by_hour = db.execute(f'''
            SELECT substr(heure,1,2) as h, COUNT(*) as n FROM sessions {where}
            GROUP BY h ORDER BY h
        ''', site_params).fetchall()

        by_mood = db.execute(f'''
            SELECT mood, COUNT(*) as n FROM sessions {where} AND mood != ''
            GROUP BY mood ORDER BY n DESC
        ''', site_params).fetchall()

        by_day = db.execute(f'''
            SELECT date, COUNT(*) as n FROM sessions
            WHERE date >= date('now','localtime','-30 days') AND {site_clause}
            GROUP BY date ORDER BY date
        ''', site_params).fetchall()

        raw_at = db.execute(f'SELECT ateliers FROM sessions {where} AND ateliers != ""', site_params).fetchall()

        # Sites summary (admin)
        if session.get('role') == 'admin':
            by_site = db.execute(f'''
                SELECT site_slug, COUNT(*) as n FROM sessions {where}
                GROUP BY site_slug ORDER BY n DESC
            ''', site_params).fetchall()
        else:
            by_site = []

    atelier_count = {}
    for row in raw_at:
        for a in (row['ateliers'] or '').split(', '):
            a = a.strip()
            if a: atelier_count[a] = atelier_count.get(a, 0) + 1
    by_atelier = sorted([{'atelier': k, 'n': v} for k,v in atelier_count.items()], key=lambda x: -x['n'])

    return jsonify({
        'period': period, 'total_seances': total,
        'by_departement': [dict(r) for r in by_dept],
        'by_hour':        [dict(r) for r in by_hour],
        'by_atelier':     by_atelier,
        'by_mood':        [dict(r) for r in by_mood],
        'by_day':         [dict(r) for r in by_day],
        'by_site':        [dict(r) for r in by_site],
    })

@app.route('/api/sessions', methods=['GET'])
@login_required
def get_sessions():
    period    = request.args.get('period', 'month')
    site_slug = request.args.get('site')
    dept      = request.args.get('departement')
    limit     = int(request.args.get('limit', 500))

    date_clause  = build_date_clause(period)
    site_clause, params = get_site_filter(site_slug)

    where = f"WHERE {date_clause} AND {site_clause}"
    if dept:
        where += " AND departement = ?"
        params.append(dept)

    with get_db() as db:
        rows = db.execute(
            f"SELECT * FROM sessions {where} ORDER BY created_at DESC LIMIT ?",
            params + [limit]
        ).fetchall()

    return jsonify([dict(r) for r in rows])

@app.route('/api/export', methods=['GET'])
@login_required
def export_csv():
    from_date = request.args.get('from', '2025-01-01')
    to_date   = request.args.get('to', date.today().isoformat())
    site_slug = request.args.get('site')

    site_clause, params = get_site_filter(site_slug)
    where = f"WHERE date BETWEEN ? AND ? AND {site_clause}"

    with get_db() as db:
        rows = db.execute(
            f"SELECT date, heure, departement, ateliers, mood, site_slug FROM sessions {where} ORDER BY date, heure",
            [from_date, to_date] + params
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['date', 'heure', 'departement', 'ateliers', 'mood', 'site'])
    for r in rows:
        writer.writerow([r['date'], r['heure'], r['departement'], r['ateliers'], r['mood'], r['site_slug']])

    return Response(
        output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=beotop_{from_date}_{to_date}.csv'}
    )

# ══════════════════════════════════════════════════════════════════════
# CLIENT — Ses propres sites
# ══════════════════════════════════════════════════════════════════════

@app.route('/api/client/sites', methods=['GET'])
@login_required
def client_get_sites():
    client_id = session.get('client_id')
    if not client_id and session.get('role') != 'admin':
        return jsonify([])
    with get_db() as db:
        if session.get('role') == 'admin':
            sites = db.execute("SELECT s.*, c.nom as client_nom FROM sites s JOIN clients c ON s.client_id=c.id ORDER BY c.nom, s.nom").fetchall()
        else:
            sites = db.execute("SELECT * FROM sites WHERE client_id=? AND actif=1 ORDER BY nom", [client_id]).fetchall()
    return jsonify([dict(s) for s in sites])

# ══════════════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════════════

@app.route('/api/health', methods=['GET'])
def health():
    with get_db() as db:
        nb_sessions = db.execute('SELECT COUNT(*) as n FROM sessions').fetchone()['n']
        nb_clients  = db.execute('SELECT COUNT(*) as n FROM clients').fetchone()['n']
        nb_sites    = db.execute('SELECT COUNT(*) as n FROM sites').fetchone()['n']
    return jsonify({
        'status': 'ok', 'version': '2.0',
        'sessions': nb_sessions, 'clients': nb_clients, 'sites': nb_sites
    })

# ══════════════════════════════════════════════════════════════════════
# PAGES HTML (servies par Flask)
# ══════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    if session.get('role') == 'admin':
        return redirect('/admin')
    return redirect('/dashboard')

@app.route('/login')
def login_page():
    return open(os.path.join(os.path.dirname(__file__), 'login.html'), encoding='utf-8').read()

@app.route('/admin')
def admin_page():
    if session.get('role') != 'admin':
        return redirect('/login')
    return open(os.path.join(os.path.dirname(__file__), 'admin.html'), encoding='utf-8').read()

@app.route('/dashboard')
def dashboard_page():
    if 'user_id' not in session:
        return redirect('/login')
    return open(os.path.join(os.path.dirname(__file__), 'dashboard.html'), encoding='utf-8').read()

@app.route('/kiosk/<site_slug>')
def kiosk_page(site_slug):
    html = open(os.path.join(os.path.dirname(__file__), 'kiosk.html'), encoding='utf-8').read()
    html = html.replace("var SITE_SLUG = ''", f"var SITE_SLUG = '{site_slug}'")
    return html

# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    init_db()
    print("\n🌿 beOtop v2.0 — Serveur complet")
    print("─" * 45)
    print("  http://localhost:5000          → App principale")
    print("  http://localhost:5000/login    → Connexion")
    print("  http://localhost:5000/admin    → Back-office beOtop")
    print("  http://localhost:5000/dashboard → Espace client")
    print("  http://localhost:5000/kiosk/SLUG → Kiosque iPad")
    print("─" * 45)
    print("  Admin par défaut : admin@beotop.fr / beotop2026")
    print("─" * 45 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)

