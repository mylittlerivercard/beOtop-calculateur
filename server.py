#!/usr/bin/env python3
"""
beOtop - Serveur complet
Auth + Multi-clients + Roles (admin / client / kiosque)
Version PostgreSQL
"""

from flask import Flask, request, jsonify, session, redirect, url_for, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
import csv
import io
import secrets
from datetime import datetime, date
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

def get_db():
    """Connexion a la base de donnees PostgreSQL."""
    try:
        conn = psycopg2.connect(os.environ['DATABASE_URL'], cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print("Erreur de connexion a la base :", e)
        raise e

def init_db():
    """Cree les tables et l'admin par defaut si necessaire."""
    print("Initialisation de la base de donnees...")
    try:
        conn = get_db()
        cur = conn.cursor()
        # Table clients
        cur.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                nom         TEXT NOT NULL,
                slug        TEXT NOT NULL UNIQUE,
                contact_nom TEXT,
                contact_email TEXT,
                actif       INTEGER DEFAULT 1
            )
        ''')
        # Table sites
        cur.execute('''
            CREATE TABLE IF NOT EXISTS sites (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                nom         TEXT NOT NULL,
                slug        TEXT NOT NULL UNIQUE,
                ville       TEXT,
                nb_salaries INTEGER DEFAULT 0,
                actif       INTEGER DEFAULT 1
            )
        ''')
        # Table users
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                email       TEXT NOT NULL UNIQUE,
                password    TEXT NOT NULL,
                nom         TEXT,
                role        TEXT NOT NULL DEFAULT 'client',
                client_id   INTEGER REFERENCES clients(id),
                actif       INTEGER DEFAULT 1
            )
        ''')
        # Table sessions
        cur.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date        DATE NOT NULL,
                heure       TIME NOT NULL,
                departement TEXT NOT NULL,
                ateliers    TEXT,
                mood        TEXT,
                site_id     INTEGER REFERENCES sites(id),
                site_slug   TEXT
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_sessions_date ON sessions(date)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_sessions_site ON sessions(site_slug)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_sessions_dept ON sessions(departement)')
        conn.commit()

        # Creer l'admin par defaut si aucun utilisateur
        cur.execute("SELECT COUNT(*) as n FROM users")
        if cur.fetchone()['n'] == 0:
            cur.execute(
                "INSERT INTO users (email, password, nom, role) VALUES (%s, %s, %s, %s)",
                ['admin@beotop.fr', generate_password_hash('beotop2026'), 'Admin beOtop', 'admin']
            )
            conn.commit()
            print("Admin cree : admin@beotop.fr / beotop2026")
        print("Base initialisee avec succes (PostgreSQL)")
    except Exception as e:
        print("ERREUR lors de l'initialisation de la base :", e)
        raise e
    finally:
        cur.close()
        conn.close()

# Appel de l'initialisation au demarrage
init_db()

# ========== DECORATEURS ==========
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Non authentifie', 'redirect': '/login'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            return jsonify({'error': 'Acces refuse'}), 403
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' not in session:
        return None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", [session['user_id']])
            return cur.fetchone()

# ========== AUTH ==========
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email=%s AND actif=1", [email])
            user = cur.fetchone()

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
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password=%s WHERE id=%s", [generate_password_hash(new_pw), user['id']])
            conn.commit()
    return jsonify({'ok': True})

# ========== ADMIN - CLIENTS ==========
@app.route('/api/admin/clients', methods=['GET'])
@login_required
@admin_required
def admin_get_clients():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT c.*, COUNT(DISTINCT s.id) as nb_sites,
                       (SELECT COUNT(*) FROM sessions se JOIN sites si ON se.site_id=si.id WHERE si.client_id=c.id) as nb_sessions
                FROM clients c
                LEFT JOIN sites s ON s.client_id=c.id
                GROUP BY c.id ORDER BY c.created_at DESC
            ''')
            clients = cur.fetchall()
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

    tmp_pw = secrets.token_urlsafe(8)

    with get_db() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO clients (nom, slug, contact_nom, contact_email) VALUES (%s,%s,%s,%s) RETURNING id",
                    [nom, slug, data.get('contact_nom',''), data.get('contact_email','')]
                )
                client_id = cur.fetchone()['id']
                if data.get('contact_email'):
                    cur.execute(
                        "INSERT INTO users (email, password, nom, role, client_id) VALUES (%s,%s,%s,%s,%s)",
                        [data['contact_email'].lower(), generate_password_hash(tmp_pw),
                         data.get('contact_nom', nom), 'client', client_id]
                    )
                conn.commit()
            except psycopg2.IntegrityError:
                return jsonify({'error': 'Ce client existe deja'}), 409

    return jsonify({'ok': True, 'client_id': client_id, 'slug': slug, 'tmp_password': tmp_pw}), 201

@app.route('/api/admin/clients/<int:client_id>', methods=['PUT'])
@login_required
@admin_required
def admin_update_client(client_id):
    data = request.get_json()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE clients SET nom=%s, contact_nom=%s, contact_email=%s, actif=%s WHERE id=%s",
                [data.get('nom'), data.get('contact_nom'), data.get('contact_email'), data.get('actif', 1), client_id]
            )
            conn.commit()
    return jsonify({'ok': True})

# ========== ADMIN - SITES ==========
@app.route('/api/admin/sites', methods=['GET'])
@login_required
@admin_required
def admin_get_sites():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT s.*, c.nom as client_nom,
                       (SELECT COUNT(*) FROM sessions se WHERE se.site_id=s.id) as nb_sessions
                FROM sites s JOIN clients c ON s.client_id=c.id
                ORDER BY c.nom, s.nom
            ''')
            sites = cur.fetchall()
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

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT slug FROM clients WHERE id=%s", [client_id])
            client = cur.fetchone()
            if not client:
                return jsonify({'error': 'Client introuvable'}), 404

            slug_nom = nom.lower().replace(' ', '-').replace("'", '')
            slug = f"{client['slug']}-{slug_nom}"
            slug = ''.join(c for c in slug if c.isalnum() or c == '-')

            try:
                cur.execute(
                    "INSERT INTO sites (client_id, nom, slug, ville, nb_salaries) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                    [client_id, nom, slug, data.get('ville',''), data.get('nb_salaries', 0)]
                )
                site_id = cur.fetchone()['id']
                conn.commit()
            except psycopg2.IntegrityError:
                return jsonify({'error': 'Ce site existe deja'}), 409

    return jsonify({'ok': True, 'site_id': site_id, 'slug': slug, 'kiosk_url': f'/kiosk/{slug}'}), 201

# ========== ADMIN - USERS ==========
@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_get_users():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT u.id, u.email, u.nom, u.role, u.actif, u.created_at,
                       c.nom as client_nom
                FROM users u LEFT JOIN clients c ON u.client_id=c.id
                ORDER BY u.role, u.created_at DESC
            ''')
            users = cur.fetchall()
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
    with get_db() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO users (email, password, nom, role, client_id) VALUES (%s,%s,%s,%s,%s)",
                    [email, generate_password_hash(tmp_pw), data.get('nom',''), data.get('role','client'), data.get('client_id')]
                )
                conn.commit()
            except psycopg2.IntegrityError:
                return jsonify({'error': 'Email deja utilise'}), 409
    return jsonify({'ok': True, 'tmp_password': tmp_pw}), 201

@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    new_pw = secrets.token_urlsafe(8)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password=%s WHERE id=%s", [generate_password_hash(new_pw), user_id])
            conn.commit()
    return jsonify({'ok': True, 'new_password': new_pw})

# ========== KIOSQUE ==========
@app.route('/api/kiosk/<site_slug>/session', methods=['POST'])
def kiosk_save_session(site_slug):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM sites WHERE slug=%s AND actif=1", [site_slug])
            site = cur.fetchone()
    if not site:
        return jsonify({'error': 'Site introuvable'}), 404

    data = request.get_json()
    if not data or not data.get('departement'):
        return jsonify({'error': 'Champ departement requis'}), 400

    now = datetime.now()
    ateliers = data.get('ateliers', [])
    if isinstance(ateliers, list):
        ateliers = ', '.join(ateliers)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sessions (date, heure, departement, ateliers, mood, site_id, site_slug) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                [now.strftime('%Y-%m-%d'), now.strftime('%H:%M'),
                 data.get('departement'), ateliers,
                 data.get('mood', ''), site['id'], site_slug]
            )
            new_id = cur.fetchone()['id']
            conn.commit()

    return jsonify({'ok': True, 'id': new_id, 'heure': now.strftime('%H:%M')}), 201

@app.route('/api/kiosk/<site_slug>/info', methods=['GET'])
def kiosk_info(site_slug):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT s.*, c.nom as client_nom
                FROM sites s JOIN clients c ON s.client_id=c.id
                WHERE s.slug=%s AND s.actif=1
            ''', [site_slug])
            site = cur.fetchone()
    if not site:
        return jsonify({'error': 'Site introuvable'}), 404
    return jsonify(dict(site))

# ========== STATISTIQUES ==========
def build_date_clause(period, prefix=''):
    p = f"{prefix}." if prefix else ""
    if period == 'today':   return f"{p}date = CURRENT_DATE"
    if period == 'week':    return f"{p}date >= CURRENT_DATE - INTERVAL '7 days'"
    if period == 'month':   return f"{p}date >= CURRENT_DATE - INTERVAL '30 days'"
    if period == 'year':    return f"{p}date >= CURRENT_DATE - INTERVAL '365 days'"
    return "1=1"

def get_site_filter(site_slug=None):
    role = session.get('role')
    client_id = session.get('client_id')

    if role == 'admin':
        if site_slug:
            return "site_slug = %s", [site_slug]
        return "1=1", []
    else:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                sites = cur.fetchall()
        slugs = [s['slug'] for s in sites]
        if not slugs:
            return "1=0", []
        if site_slug and site_slug in slugs:
            return "site_slug = %s", [site_slug]
        placeholders = ','.join(['%s'] * len(slugs))
        return f"site_slug IN ({placeholders})", slugs

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    period    = request.args.get('period', 'today')
    site_slug = request.args.get('site')
    date_clause  = build_date_clause(period)
    site_clause, site_params = get_site_filter(site_slug)

    where = f"WHERE {date_clause} AND {site_clause}"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f'SELECT COUNT(*) as n FROM sessions {where}', site_params)
            total = cur.fetchone()['n']

            cur.execute(f'''
                SELECT departement as label, COUNT(*) as n FROM sessions {where}
                GROUP BY departement ORDER BY n DESC
            ''', site_params)
            by_dept = cur.fetchall()

            # Correction : utiliser EXTRACT pour l'heure
            cur.execute(f'''
                SELECT EXTRACT(HOUR FROM heure) as h, COUNT(*) as n FROM sessions {where}
                GROUP BY h ORDER BY h
            ''', site_params)
            by_hour = cur.fetchall()

            cur.execute(f'''
                SELECT mood, COUNT(*) as n FROM sessions {where} AND mood != ''
                GROUP BY mood ORDER BY n DESC
            ''', site_params)
            by_mood = cur.fetchall()

            cur.execute(f'''
                SELECT date, COUNT(*) as n FROM sessions
                WHERE date >= CURRENT_DATE - INTERVAL '30 days' AND {site_clause}
                GROUP BY date ORDER BY date
            ''', site_params)
            by_day = cur.fetchall()

            cur.execute(f'SELECT ateliers FROM sessions {where} AND ateliers != ""', site_params)
            raw_at = cur.fetchall()

            if session.get('role') == 'admin':
                cur.execute(f'''
                    SELECT site_slug, COUNT(*) as n FROM sessions {where}
                    GROUP BY site_slug ORDER BY n DESC
                ''', site_params)
                by_site = cur.fetchall()
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
        where += " AND departement = %s"
        params.append(dept)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT * FROM sessions {where} ORDER BY created_at DESC LIMIT %s",
                params + [limit]
            )
            rows = cur.fetchall()

    return jsonify([dict(r) for r in rows])

@app.route('/api/export', methods=['GET'])
@login_required
def export_csv():
    from_date = request.args.get('from', '2025-01-01')
    to_date   = request.args.get('to', date.today().isoformat())
    site_slug = request.args.get('site')

    site_clause, params = get_site_filter(site_slug)
    where = f"WHERE date BETWEEN %s AND %s AND {site_clause}"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT date, heure, departement, ateliers, mood, site_slug FROM sessions {where} ORDER BY date, heure",
                [from_date, to_date] + params
            )
            rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['date', 'heure', 'departement', 'ateliers', 'mood', 'site'])
    for r in rows:
        writer.writerow([r['date'], r['heure'], r['departement'], r['ateliers'], r['mood'], r['site_slug']])

    return Response(
        output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=beotop_{from_date}_{to_date}.csv'}
    )

# ========== CLIENT - SES SITES ==========
@app.route('/api/client/sites', methods=['GET'])
@login_required
def client_get_sites():
    client_id = session.get('client_id')
    if not client_id and session.get('role') != 'admin':
        return jsonify([])
    with get_db() as conn:
        with conn.cursor() as cur:
            if session.get('role') == 'admin':
                cur.execute("SELECT s.*, c.nom as client_nom FROM sites s JOIN clients c ON s.client_id=c.id ORDER BY c.nom, s.nom")
            else:
                cur.execute("SELECT * FROM sites WHERE client_id=%s AND actif=1 ORDER BY nom", [client_id])
            sites = cur.fetchall()
    return jsonify([dict(s) for s in sites])

# ========== HEALTH ==========
@app.route('/api/health', methods=['GET'])
def health():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) as n FROM sessions')
            nb_sessions = cur.fetchone()['n']
            cur.execute('SELECT COUNT(*) as n FROM clients')
            nb_clients = cur.fetchone()['n']
            cur.execute('SELECT COUNT(*) as n FROM sites')
            nb_sites = cur.fetchone()['n']
    return jsonify({
        'status': 'ok', 'version': '2.0',
        'sessions': nb_sessions, 'clients': nb_clients, 'sites': nb_sites
    })

# ========== PAGES HTML ==========
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
    # Correction du nom de fichier : utiliser beOtop_Kiosk.html
    html = open(os.path.join(os.path.dirname(__file__), 'beOtop_Kiosk.html'), encoding='utf-8').read()
    html = html.replace("var SITE_SLUG = ''", f"var SITE_SLUG = '{site_slug}'")
    return html

if __name__ == '__main__':
    print("\nbeOtop v2.0 - Serveur complet (PostgreSQL)")
    print("-" * 45)
    print("  http://localhost:5000          -> App principale")
    print("  http://localhost:5000/login    -> Connexion")
    print("  http://localhost:5000/admin    -> Back-office beOtop")
    print("  http://localhost:5000/dashboard -> Espace client")
    print("  http://localhost:5000/kiosk/SLUG -> Kiosque iPad")
    print("-" * 45)
    print("  Admin par defaut : admin@beotop.fr / beotop2026")
    print("-" * 45 + "\n")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)#!/usr/bin/env python3
"""
beOtop - Serveur complet
Auth + Multi-clients + Roles (admin / client / kiosque)
Version PostgreSQL
"""

from flask import Flask, request, jsonify, session, redirect, url_for, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
import csv
import io
import secrets
from datetime import datetime, date
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor

app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

def get_db():
    try:
        conn = psycopg2.connect(os.environ['DATABASE_URL'], cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print("Erreur de connexion a la base :", e)
        raise e

def init_db():
    print("Initialisation de la base de donnees...")
    try:
        conn = get_db()
        cur = conn.cursor()
        # Table clients
        cur.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                nom         TEXT NOT NULL,
                slug        TEXT NOT NULL UNIQUE,
                contact_nom TEXT,
                contact_email TEXT,
                actif       INTEGER DEFAULT 1
            )
        ''')
        # Table sites
        cur.execute('''
            CREATE TABLE IF NOT EXISTS sites (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                nom         TEXT NOT NULL,
                slug        TEXT NOT NULL UNIQUE,
                ville       TEXT,
                nb_salaries INTEGER DEFAULT 0,
                actif       INTEGER DEFAULT 1
            )
        ''')
        # Table users
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                email       TEXT NOT NULL UNIQUE,
                password    TEXT NOT NULL,
                nom         TEXT,
                role        TEXT NOT NULL DEFAULT 'client',
                client_id   INTEGER REFERENCES clients(id),
                actif       INTEGER DEFAULT 1
            )
        ''')
        # Table sessions
        cur.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date        DATE NOT NULL,
                heure       TIME NOT NULL,
                departement TEXT NOT NULL,
                ateliers    TEXT,
                mood        TEXT,
                site_id     INTEGER REFERENCES sites(id),
                site_slug   TEXT
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_sessions_date ON sessions(date)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_sessions_site ON sessions(site_slug)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_sessions_dept ON sessions(departement)')
        conn.commit()

        # Creer admin par defaut si aucun user
        cur.execute("SELECT COUNT(*) as n FROM users")
        if cur.fetchone()['n'] == 0:
            cur.execute(
                "INSERT INTO users (email, password, nom, role) VALUES (%s, %s, %s, %s)",
                ['admin@beotop.fr', generate_password_hash('beotop2026'), 'Admin beOtop', 'admin']
            )
            conn.commit()
            print("Admin cree : admin@beotop.fr / beotop2026")
        print("Base initialisee avec succes (PostgreSQL)")
    except Exception as e:
        print("ERREUR lors de l'initialisation de la base :", e)
        raise e
    finally:
        cur.close()
        conn.close()

# Appel global pour initialiser la base au demarrage
init_db()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Non authentifie', 'redirect': '/login'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            return jsonify({'error': 'Acces refuse'}), 403
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' not in session:
        return None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", [session['user_id']])
            return cur.fetchone()

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email=%s AND actif=1", [email])
            user = cur.fetchone()

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
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password=%s WHERE id=%s", [generate_password_hash(new_pw), user['id']])
            conn.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/clients', methods=['GET'])
@login_required
@admin_required
def admin_get_clients():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT c.*, COUNT(DISTINCT s.id) as nb_sites,
                       (SELECT COUNT(*) FROM sessions se JOIN sites si ON se.site_id=si.id WHERE si.client_id=c.id) as nb_sessions
                FROM clients c
                LEFT JOIN sites s ON s.client_id=c.id
                GROUP BY c.id ORDER BY c.created_at DESC
            ''')
            clients = cur.fetchall()
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

    tmp_pw = secrets.token_urlsafe(8)

    with get_db() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO clients (nom, slug, contact_nom, contact_email) VALUES (%s,%s,%s,%s) RETURNING id",
                    [nom, slug, data.get('contact_nom',''), data.get('contact_email','')]
                )
                client_id = cur.fetchone()['id']
                if data.get('contact_email'):
                    cur.execute(
                        "INSERT INTO users (email, password, nom, role, client_id) VALUES (%s,%s,%s,%s,%s)",
                        [data['contact_email'].lower(), generate_password_hash(tmp_pw),
                         data.get('contact_nom', nom), 'client', client_id]
                    )
                conn.commit()
            except psycopg2.IntegrityError:
                return jsonify({'error': 'Ce client existe deja'}), 409

    return jsonify({'ok': True, 'client_id': client_id, 'slug': slug, 'tmp_password': tmp_pw}), 201

@app.route('/api/admin/clients/<int:client_id>', methods=['PUT'])
@login_required
@admin_required
def admin_update_client(client_id):
    data = request.get_json()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE clients SET nom=%s, contact_nom=%s, contact_email=%s, actif=%s WHERE id=%s",
                [data.get('nom'), data.get('contact_nom'), data.get('contact_email'), data.get('actif', 1), client_id]
            )
            conn.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/sites', methods=['GET'])
@login_required
@admin_required
def admin_get_sites():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT s.*, c.nom as client_nom,
                       (SELECT COUNT(*) FROM sessions se WHERE se.site_id=s.id) as nb_sessions
                FROM sites s JOIN clients c ON s.client_id=c.id
                ORDER BY c.nom, s.nom
            ''')
            sites = cur.fetchall()
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

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT slug FROM clients WHERE id=%s", [client_id])
            client = cur.fetchone()
            if not client:
                return jsonify({'error': 'Client introuvable'}), 404

            slug_nom = nom.lower().replace(' ', '-').replace("'", '')
            slug = f"{client['slug']}-{slug_nom}"
            slug = ''.join(c for c in slug if c.isalnum() or c == '-')

            try:
                cur.execute(
                    "INSERT INTO sites (client_id, nom, slug, ville, nb_salaries) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                    [client_id, nom, slug, data.get('ville',''), data.get('nb_salaries', 0)]
                )
                site_id = cur.fetchone()['id']
                conn.commit()
            except psycopg2.IntegrityError:
                return jsonify({'error': 'Ce site existe deja'}), 409

    return jsonify({'ok': True, 'site_id': site_id, 'slug': slug, 'kiosk_url': f'/kiosk/{slug}'}), 201

@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_get_users():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT u.id, u.email, u.nom, u.role, u.actif, u.created_at,
                       c.nom as client_nom
                FROM users u LEFT JOIN clients c ON u.client_id=c.id
                ORDER BY u.role, u.created_at DESC
            ''')
            users = cur.fetchall()
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
    with get_db() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO users (email, password, nom, role, client_id) VALUES (%s,%s,%s,%s,%s)",
                    [email, generate_password_hash(tmp_pw), data.get('nom',''), data.get('role','client'), data.get('client_id')]
                )
                conn.commit()
            except psycopg2.IntegrityError:
                return jsonify({'error': 'Email deja utilise'}), 409
    return jsonify({'ok': True, 'tmp_password': tmp_pw}), 201

@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    new_pw = secrets.token_urlsafe(8)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password=%s WHERE id=%s", [generate_password_hash(new_pw), user_id])
            conn.commit()
    return jsonify({'ok': True, 'new_password': new_pw})

@app.route('/api/kiosk/<site_slug>/session', methods=['POST'])
def kiosk_save_session(site_slug):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM sites WHERE slug=%s AND actif=1", [site_slug])
            site = cur.fetchone()
    if not site:
        return jsonify({'error': 'Site introuvable'}), 404

    data = request.get_json()
    if not data or not data.get('departement'):
        return jsonify({'error': 'Champ departement requis'}), 400

    now = datetime.now()
    ateliers = data.get('ateliers', [])
    if isinstance(ateliers, list):
        ateliers = ', '.join(ateliers)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sessions (date, heure, departement, ateliers, mood, site_id, site_slug) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                [now.strftime('%Y-%m-%d'), now.strftime('%H:%M'),
                 data.get('departement'), ateliers,
                 data.get('mood', ''), site['id'], site_slug]
            )
            new_id = cur.fetchone()['id']
            conn.commit()

    return jsonify({'ok': True, 'id': new_id, 'heure': now.strftime('%H:%M')}), 201

@app.route('/api/kiosk/<site_slug>/info', methods=['GET'])
def kiosk_info(site_slug):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT s.*, c.nom as client_nom
                FROM sites s JOIN clients c ON s.client_id=c.id
                WHERE s.slug=%s AND s.actif=1
            ''', [site_slug])
            site = cur.fetchone()
    if not site:
        return jsonify({'error': 'Site introuvable'}), 404
    return jsonify(dict(site))

def build_date_clause(period, prefix=''):
    p = f"{prefix}." if prefix else ""
    if period == 'today':
        return f"{p}date = CURRENT_DATE"
    if period == 'week':
        return f"{p}date >= CURRENT_DATE - INTERVAL '7 days'"
    if period == 'month':
        return f"{p}date >= CURRENT_DATE - INTERVAL '30 days'"
    if period == 'year':
        return f"{p}date >= CURRENT_DATE - INTERVAL '365 days'"
    return "1=1"

def get_site_filter(site_slug=None):
    role = session.get('role')
    client_id = session.get('client_id')

    if role == 'admin':
        if site_slug:
            return "site_slug = %s", [site_slug]
        return "1=1", []
    else:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                sites = cur.fetchall()
        slugs = [s['slug'] for s in sites]
        if not slugs:
            return "1=0", []
        if site_slug and site_slug in slugs:
            return "site_slug = %s", [site_slug]
        placeholders = ','.join(['%s'] * len(slugs))
        return f"site_slug IN ({placeholders})", slugs

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    period    = request.args.get('period', 'today')
    site_slug = request.args.get('site')
    date_clause  = build_date_clause(period)
    site_clause, site_params = get_site_filter(site_slug)

    where = f"WHERE {date_clause} AND {site_clause}"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f'SELECT COUNT(*) as n FROM sessions {where}', site_params)
            total = cur.fetchone()['n']

            cur.execute(f'''
                SELECT departement as label, COUNT(*) as n FROM sessions {where}
                GROUP BY departement ORDER BY n DESC
            ''', site_params)
            by_dept = cur.fetchall()

            cur.execute(f'''
                SELECT SUBSTRING(heure,1,2) as h, COUNT(*) as n FROM sessions {where}
                GROUP BY h ORDER BY h
            ''', site_params)
            by_hour = cur.fetchall()

            cur.execute(f'''
                SELECT mood, COUNT(*) as n FROM sessions {where} AND mood != ''
                GROUP BY mood ORDER BY n DESC
            ''', site_params)
            by_mood = cur.fetchall()

            cur.execute(f'''
                SELECT date, COUNT(*) as n FROM sessions
                WHERE date >= CURRENT_DATE - INTERVAL '30 days' AND {site_clause}
                GROUP BY date ORDER BY date
            ''', site_params)
            by_day = cur.fetchall()

            cur.execute(f'SELECT ateliers FROM sessions {where} AND ateliers != ""', site_params)
            raw_at = cur.fetchall()

            if session.get('role') == 'admin':
                cur.execute(f'''
                    SELECT site_slug, COUNT(*) as n FROM sessions {where}
                    GROUP BY site_slug ORDER BY n DESC
                ''', site_params)
                by_site = cur.fetchall()
            else:
                by_site = []

    atelier_count = {}
    for row in raw_at:
        for a in (row['ateliers'] or '').split(', '):
            a = a.strip()
            if a:
                atelier_count[a] = atelier_count.get(a, 0) + 1
    by_atelier = sorted([{'atelier': k, 'n': v} for k, v in atelier_count.items()], key=lambda x: -x['n'])

    return jsonify({
        'period': period,
        'total_seances': total,
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
        where += " AND departement = %s"
        params.append(dept)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT * FROM sessions {where} ORDER BY created_at DESC LIMIT %s",
                params + [limit]
            )
            rows = cur.fetchall()

    return jsonify([dict(r) for r in rows])

@app.route('/api/export', methods=['GET'])
@login_required
def export_csv():
    from_date = request.args.get('from', '2025-01-01')
    to_date   = request.args.get('to', date.today().isoformat())
    site_slug = request.args.get('site')

    site_clause, params = get_site_filter(site_slug)
    where = f"WHERE date BETWEEN %s AND %s AND {site_clause}"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT date, heure, departement, ateliers, mood, site_slug FROM sessions {where} ORDER BY date, heure",
                [from_date, to_date] + params
            )
            rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['date', 'heure', 'departement', 'ateliers', 'mood', 'site'])
    for r in rows:
        writer.writerow([r['date'], r['heure'], r['departement'], r['ateliers'], r['mood'], r['site_slug']])

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=beotop_{from_date}_{to_date}.csv'}
    )

@app.route('/api/client/sites', methods=['GET'])
@login_required
def client_get_sites():
    client_id = session.get('client_id')
    if not client_id and session.get('role') != 'admin':
        return jsonify([])
    with get_db() as conn:
        with conn.cursor() as cur:
            if session.get('role') == 'admin':
                cur.execute("SELECT s.*, c.nom as client_nom FROM sites s JOIN clients c ON s.client_id=c.id ORDER BY c.nom, s.nom")
            else:
                cur.execute("SELECT * FROM sites WHERE client_id=%s AND actif=1 ORDER BY nom", [client_id])
            sites = cur.fetchall()
    return jsonify([dict(s) for s in sites])

@app.route('/api/health', methods=['GET'])
def health():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) as n FROM sessions')
            nb_sessions = cur.fetchone()['n']
            cur.execute('SELECT COUNT(*) as n FROM clients')
            nb_clients = cur.fetchone()['n']
            cur.execute('SELECT COUNT(*) as n FROM sites')
            nb_sites = cur.fetchone()['n']
    return jsonify({
        'status': 'ok',
        'version': '2.0',
        'sessions': nb_sessions,
        'clients': nb_clients,
        'sites': nb_sites
    })

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

if __name__ == '__main__':
    print("\nbeOtop v2.0 - Serveur complet (PostgreSQL)")
    print("-" * 45)
    print("  http://localhost:5000          -> App principale")
    print("  http://localhost:5000/login    -> Connexion")
    print("  http://localhost:5000/admin    -> Back-office beOtop")
    print("  http://localhost:5000/dashboard -> Espace client")
    print("  http://localhost:5000/kiosk/SLUG -> Kiosque iPad")
    print("-" * 45)
    print("  Admin par defaut : admin@beotop.fr / beotop2026")
    print("-" * 45 + "\n")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
