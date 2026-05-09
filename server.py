#!/usr/bin/env python3
"""
beOtop - Serveur complet
Auth + Multi-clients + Roles (admin / client / kiosque)
Version PostgreSQL
"""

from flask import Flask, request, jsonify, session, redirect, Response, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
import csv
import io
import sys
import secrets
from datetime import datetime, date
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def serve_html(filename):
    """Lit et retourne un fichier HTML avec le bon Content-Type."""
    path = os.path.join(BASE_DIR, filename)
    try:
        with open(path, encoding='utf-8') as f:
            return Response(f.read(), mimetype='text/html; charset=utf-8')
    except FileNotFoundError:
        return Response(f'<h1>Fichier introuvable : {filename}</h1>', status=404, mimetype='text/html')

# ========== BASE DE DONNEES ==========

def get_db():
    try:
        conn = psycopg2.connect(
            os.environ['DATABASE_URL'],
            cursor_factory=RealDictCursor,
            connect_timeout=10
        )
        return conn
    except Exception as e:
        print("Erreur de connexion a la base :", e, file=sys.stderr)
        raise e

# ── Normalisation noms d'ateliers ────────────────────────────────────────────
ATELIER_CANON = {
    'meridienne-p127':    'Méridienne P127',
    'cocon-sieste':       'Cocon de Sieste',
    'lit-neurosonic':     'Neurosonic Lit',
    'siege-massant-127':  'Siège Massant 0 Gravité',
    'siege-shiatsu':      'Siège Massant Shiatsu',
    'transat-127':        'Transat 127',
    'siege-lecture':      'Siège Lecture',
    'bol-air':            "Bol d'Air Jacquier",
    'bain-lumiere':       'Bain de Lumière Rouge',
    'photobiomodulation': 'Photobiomodulation',
    'sensosphere':        'Sensosphère',
    'lunettes-psio':      'Lunettes Psio',
    'P127':               'Méridienne P127',
    'Neurosonic lit':     'Neurosonic Lit',
    "Bol d'Air":          "Bol d'Air Jacquier",
    'Siège massant':      'Siège Massant 0 Gravité',
}

def normalize_atelier(name):
    return ATELIER_CANON.get(name, name) if name else name
# ─────────────────────────────────────────────────────────────────────────────

def serialize_row(row):
    d = dict(row)
    for k, v in d.items():
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d

def init_db():
    print(">>> Initialisation de la base de donnees...", file=sys.stderr)
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id            SERIAL PRIMARY KEY,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                nom           TEXT NOT NULL,
                slug          TEXT NOT NULL UNIQUE,
                contact_nom   TEXT,
                contact_email TEXT,
                actif         INTEGER DEFAULT 1
            )
        ''')
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

        # ========== TABLES CAPTEURS ==========

        cur.execute('''
            CREATE TABLE IF NOT EXISTS sensor_passages (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                site_slug   TEXT NOT NULL,
                direction   TEXT,
                timestamp   TIMESTAMP NOT NULL
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_passages_site ON sensor_passages(site_slug)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_passages_ts   ON sensor_passages(timestamp)')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS sensor_occupation (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                site_slug   TEXT NOT NULL,
                atelier     TEXT NOT NULL,
                occupe      BOOLEAN NOT NULL,
                timestamp   TIMESTAMP NOT NULL
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_occupation_site    ON sensor_occupation(site_slug)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_occupation_atelier ON sensor_occupation(atelier)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_occupation_ts      ON sensor_occupation(timestamp)')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS sensor_sessions (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                site_slug   TEXT NOT NULL,
                atelier     TEXT,
                debut       TIMESTAMP NOT NULL,
                fin         TIMESTAMP NOT NULL,
                duree_sec   INTEGER NOT NULL
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_sensor_sessions_site ON sensor_sessions(site_slug)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_sensor_sessions_ts   ON sensor_sessions(debut)')

        conn.commit()

        cur.execute("SELECT COUNT(*) as n FROM users")
        count = cur.fetchone()['n']
        if count == 0:
            cur.execute(
                "INSERT INTO users (email, password, nom, role) VALUES (%s, %s, %s, %s)",
                ['admin@beotop.fr', generate_password_hash('beotop2026'), 'Admin beOtop', 'admin']
            )
            conn.commit()
            print(">>> Admin créé : admin@beotop.fr / beotop2026", file=sys.stderr)

        print(">>> Base initialisée avec succès", file=sys.stderr)
    except Exception as e:
        print(">>> ERREUR init_db :", e, file=sys.stderr)
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

try:
    init_db()
except Exception as e:
    print(">>> init_db ignorée au démarrage :", e, file=sys.stderr)

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
def auth_login():
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
            cur.execute(
                "UPDATE users SET password=%s WHERE id=%s",
                [generate_password_hash(new_pw), user['id']]
            )
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
    return jsonify([serialize_row(c) for c in clients])

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
    return jsonify([serialize_row(s) for s in sites])

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

# ── AJOUT 1 : PUT /api/admin/sites/<id> ──────────────────────────────────────
@app.route('/api/admin/sites/<int:site_id>', methods=['PUT'])
@login_required
@admin_required
def admin_update_site(site_id):
    """
    Modifie les informations d'un site.
    Body JSON : { "nom", "ville", "nb_salaries", "actif" }
    nb_salaries est utilisé par l'onglet QVCT pour calculer le taux de pénétration.
    """
    data = request.get_json()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE sites
                   SET nom=%s, ville=%s, nb_salaries=%s, actif=%s
                   WHERE id=%s""",
                [
                    data.get('nom'),
                    data.get('ville'),
                    int(data.get('nb_salaries') or 0),
                    int(data.get('actif', 1)),
                    site_id
                ]
            )
            conn.commit()
    return jsonify({'ok': True})
# ─────────────────────────────────────────────────────────────────────────────

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
    return jsonify([serialize_row(u) for u in users])

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
    return jsonify(serialize_row(site))

# ========== CAPTEURS — RÉCEPTION DONNÉES RPi ==========

@app.route('/api/sensors/passage', methods=['POST'])
def sensors_passage():
    data = request.get_json()
    if not data or not data.get('site_slug'):
        return jsonify({'error': 'site_slug requis'}), 400
    site_slug = data['site_slug']
    direction = data.get('direction')
    ts_raw    = data.get('timestamp')
    try:
        ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.now()
    except ValueError:
        ts = datetime.now()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensor_passages (site_slug, direction, timestamp) VALUES (%s, %s, %s) RETURNING id",
                [site_slug, direction, ts]
            )
            new_id = cur.fetchone()['id']
            conn.commit()
    return jsonify({'ok': True, 'id': new_id}), 201


@app.route('/api/sensors/occupation', methods=['POST'])
def sensors_occupation():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body JSON requis'}), 400
    events = data if isinstance(data, list) else [data]
    inserted = 0
    with get_db() as conn:
        with conn.cursor() as cur:
            for evt in events:
                site_slug = evt.get('site_slug')
                atelier   = normalize_atelier(evt.get('atelier'))
                occupe    = evt.get('occupe', True)
                ts_raw    = evt.get('timestamp')
                if not site_slug or not atelier:
                    continue
                try:
                    ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.now()
                except ValueError:
                    ts = datetime.now()
                cur.execute(
                    "INSERT INTO sensor_occupation (site_slug, atelier, occupe, timestamp) VALUES (%s, %s, %s, %s)",
                    [site_slug, atelier, occupe, ts]
                )
                inserted += 1
            conn.commit()
    return jsonify({'ok': True, 'inserted': inserted}), 201


@app.route('/api/sensors/session', methods=['POST'])
def sensors_session():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body JSON requis'}), 400
    site_slug = data.get('site_slug')
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    debut_raw = data.get('debut')
    fin_raw   = data.get('fin')
    if not debut_raw or not fin_raw:
        return jsonify({'error': 'debut et fin requis'}), 400
    try:
        debut     = datetime.fromisoformat(debut_raw)
        fin       = datetime.fromisoformat(fin_raw)
        duree_sec = data.get('duree_sec') or int((fin - debut).total_seconds())
    except (ValueError, TypeError) as e:
        return jsonify({'error': f'Format de date invalide : {e}'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensor_sessions (site_slug, atelier, debut, fin, duree_sec) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                [site_slug, normalize_atelier(data.get('atelier')), debut, fin, duree_sec]
            )
            new_id = cur.fetchone()['id']
            conn.commit()
    return jsonify({'ok': True, 'id': new_id}), 201


# ========== CAPTEURS — STATISTIQUES ==========

@app.route('/api/sensors/stats', methods=['GET'])
@login_required
def sensors_stats():
    site_slug = request.args.get('site_slug')
    period    = request.args.get('period', 'today')
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                slugs = [r['slug'] for r in cur.fetchall()]
        if site_slug not in slugs:
            return jsonify({'error': 'Accès refusé'}), 403

    if period == 'today':
        ts_clause = '"timestamp" >= CURRENT_DATE AND "timestamp" < CURRENT_DATE + INTERVAL \'1 day\''
    elif period == 'week':
        ts_clause = '"timestamp" >= NOW() - INTERVAL \'7 days\''
    elif period == 'month':
        ts_clause = '"timestamp" >= NOW() - INTERVAL \'30 days\''
    elif period == 'year':
        ts_clause = '"timestamp" >= NOW() - INTERVAL \'365 days\''
    elif period == 'ytd':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE)'
    elif period == 'q1':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) AND "timestamp" < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'3 months\''
    elif period == 'q2':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'3 months\' AND "timestamp" < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'6 months\''
    elif period == 'q3':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'6 months\' AND "timestamp" < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'9 months\''
    elif period == 'q4':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'9 months\''
    else:
        ts_clause = "1=1" 

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT COUNT(*) as n FROM sensor_passages WHERE site_slug=%s AND {ts_clause}",
                [site_slug]
            )
            total_passages = cur.fetchone()['n']

            cur.execute(
                f"""SELECT EXTRACT(HOUR FROM timestamp)::int as h, COUNT(*) as n
                    FROM sensor_passages
                    WHERE site_slug=%s AND {ts_clause}
                    GROUP BY h ORDER BY h""",
                [site_slug]
            )
            passages_par_heure = cur.fetchall()

            cur.execute(
                f"""SELECT atelier,
                           COUNT(*) as total_signaux,
                           SUM(CASE WHEN occupe THEN 1 ELSE 0 END) as signaux_actifs
                    FROM sensor_occupation
                    WHERE site_slug=%s AND {ts_clause}
                    GROUP BY atelier ORDER BY atelier""",
                [site_slug]
            )
            raw_occ = cur.fetchall()
            occupation_par_atelier = []
            for row in raw_occ:
                total = row['total_signaux']
                actifs = row['signaux_actifs']
                taux = round((actifs / total * 100), 1) if total > 0 else 0
                occupation_par_atelier.append({
                    'atelier': row['atelier'],
                    'taux_occupation': taux,
                    'total_signaux': total,
                    'signaux_actifs': actifs
                })

            ts_clause_sessions = ts_clause.replace('"timestamp"', 'debut')
            cur.execute(
                f"""SELECT atelier,
                           COUNT(*) as nb_sessions,
                           ROUND(AVG(duree_sec))::int as duree_moy_sec,
                           MIN(duree_sec) as duree_min_sec,
                           MAX(duree_sec) as duree_max_sec
                    FROM sensor_sessions
                    WHERE site_slug=%s AND {ts_clause_sessions}
                    GROUP BY atelier ORDER BY nb_sessions DESC""",
                [site_slug]
            )
            sessions_par_atelier = cur.fetchall()

    return jsonify({
        'site_slug': site_slug,
        'period': period,
        'total_passages': total_passages,
        'passages_par_heure': [serialize_row(r) for r in passages_par_heure],
        'occupation_par_atelier': occupation_par_atelier,
        'sessions_par_atelier': [serialize_row(r) for r in sessions_par_atelier],
    })


@app.route('/api/sensors/passages/list', methods=['GET'])
@login_required
def sensors_passages_list():
    site_slug = request.args.get('site_slug')
    period    = request.args.get('period', 'today')
    limit     = int(request.args.get('limit', 200))
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                slugs = [r['slug'] for r in cur.fetchall()]
        if site_slug not in slugs:
            return jsonify({'error': 'Accès refusé'}), 403

    if period == 'today':
        ts_clause = '"timestamp" >= CURRENT_DATE AND "timestamp" < CURRENT_DATE + INTERVAL \'1 day\' AND EXTRACT(HOUR FROM "timestamp") BETWEEN 8 AND 19'
    elif period == 'week':
        ts_clause = '"timestamp" >= NOW() - INTERVAL \'7 days\''
    elif period == 'month':
        ts_clause = '"timestamp" >= NOW() - INTERVAL \'30 days\''
    elif period == 'year':
        ts_clause = '"timestamp" >= NOW() - INTERVAL \'365 days\''
    elif period == 'ytd':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE)'
    elif period == 'q1':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) AND "timestamp" < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'3 months\''
    elif period == 'q2':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'3 months\' AND "timestamp" < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'6 months\''
    elif period == 'q3':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'6 months\' AND "timestamp" < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'9 months\''
    elif period == 'q4':
        ts_clause = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'9 months\''
    else:
        ts_clause = "1=1"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""SELECT id, "timestamp", direction
                    FROM sensor_passages
                    WHERE site_slug=%s AND {ts_clause}
                    ORDER BY "timestamp" DESC
                    LIMIT %s""",
                [site_slug, limit]
            )
            rows = cur.fetchall()

    return jsonify({
        'site_slug': site_slug,
        'period': period,
        'total': len(rows),
        'passages': [serialize_row(r) for r in rows]
    })


@app.route('/api/sensors/passages/export', methods=['GET'])
@login_required
def sensors_passages_export():
    site_slug  = request.args.get('site_slug')
    from_date  = request.args.get('from', date.today().isoformat())
    to_date    = request.args.get('to', date.today().isoformat())
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                slugs = [r['slug'] for r in cur.fetchall()]
        if site_slug not in slugs:
            return jsonify({'error': 'Accès refusé'}), 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT "timestamp", direction
                   FROM sensor_passages
                   WHERE site_slug=%s
                   AND "timestamp"::date BETWEEN %s AND %s
                   ORDER BY "timestamp" ASC""",
                [site_slug, from_date, to_date]
            )
            rows = cur.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['date', 'heure', 'direction', 'site'])
    for r in rows:
        sr = serialize_row(r)
        ts = sr['timestamp']
        writer.writerow([ts[:10], ts[11:19], sr.get('direction') or 'entree', site_slug])
    return Response(
        output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=passages_{site_slug}_{from_date}_{to_date}.csv'}
    )

# ========== STATISTIQUES ==========

def build_date_clause(period, prefix=''):
    p = f"{prefix}." if prefix else ""
    if period == 'today':  return f"{p}date = CURRENT_DATE"
    if period == 'week':   return f"{p}date >= CURRENT_DATE - INTERVAL '7 days'"
    if period == 'month':  return f"{p}date >= CURRENT_DATE - INTERVAL '30 days'"
    if period == 'year':   return f"{p}date >= CURRENT_DATE - INTERVAL '365 days'"
    if period == 'ytd':    return f"{p}date >= DATE_TRUNC('year', CURRENT_DATE)"
    if period == 'q1':     return f"{p}date >= DATE_TRUNC('year', CURRENT_DATE) AND {p}date < DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '3 months'"
    if period == 'q2':     return f"{p}date >= DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '3 months' AND {p}date < DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '6 months'"
    if period == 'q3':     return f"{p}date >= DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '6 months' AND {p}date < DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '9 months'"
    if period == 'q4':     return f"{p}date >= DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '9 months'"
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
    date_clause = build_date_clause(period)
    site_clause, site_params = get_site_filter(site_slug)
    where = f"WHERE {date_clause} AND {site_clause}"

    # ── AJOUT 2 : by_day respecte la période sélectionnée ────────────────────
    # Fenêtre temporelle pour by_day selon la période (au lieu du hardcodé 30j)
    if period == 'today':
        day_interval = "INTERVAL '1 day'"
    elif period == 'week':
        day_interval = "INTERVAL '7 days'"
    elif period == 'year':
        day_interval = "INTERVAL '365 days'"
    elif period == 'ytd':
        day_interval = "INTERVAL '365 days'"
    elif period in ('q1', 'q2', 'q3', 'q4'):
        day_interval = "INTERVAL '365 days'"
    else:
        day_interval = "INTERVAL '30 days'"
    # ─────────────────────────────────────────────────────────────────────────

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f'SELECT COUNT(*) as n FROM sessions {where}', site_params)
            total = cur.fetchone()['n']

            cur.execute(
                f'SELECT departement as label, COUNT(*) as n FROM sessions {where} GROUP BY departement ORDER BY n DESC',
                site_params
            )
            by_dept = cur.fetchall()

            # by_hour : depuis sensor_passages (faisceau réel), pas le kiosque
            if period == 'today':
                ts_h     = '"timestamp" >= CURRENT_DATE AND "timestamp" < CURRENT_DATE + INTERVAL \'1 day\''
                ts_debut = 'debut >= CURRENT_DATE AND debut < CURRENT_DATE + INTERVAL \'1 day\''
            elif period == 'week':
                ts_h     = '"timestamp" >= NOW() - INTERVAL \'7 days\''
                ts_debut = 'debut >= NOW() - INTERVAL \'7 days\''
            elif period == 'month':
                ts_h     = '"timestamp" >= NOW() - INTERVAL \'30 days\''
                ts_debut = 'debut >= NOW() - INTERVAL \'30 days\''
            elif period == 'year':
                ts_h     = '"timestamp" >= NOW() - INTERVAL \'365 days\''
                ts_debut = 'debut >= NOW() - INTERVAL \'365 days\''
            elif period == 'ytd':
                ts_h     = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE)'
                ts_debut = 'debut >= DATE_TRUNC(\'year\', CURRENT_DATE)'
            elif period == 'q1':
                ts_h     = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) AND "timestamp" < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'3 months\''
                ts_debut = 'debut >= DATE_TRUNC(\'year\', CURRENT_DATE) AND debut < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'3 months\''
            elif period == 'q2':
                ts_h     = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'3 months\' AND "timestamp" < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'6 months\''
                ts_debut = 'debut >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'3 months\' AND debut < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'6 months\''
            elif period == 'q3':
                ts_h     = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'6 months\' AND "timestamp" < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'9 months\''
                ts_debut = 'debut >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'6 months\' AND debut < DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'9 months\''
            elif period == 'q4':
                ts_h     = '"timestamp" >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'9 months\''
                ts_debut = 'debut >= DATE_TRUNC(\'year\', CURRENT_DATE) + INTERVAL \'9 months\''
            else:
                ts_h     = '1=1'
                ts_debut = '1=1'

            # Construire le filtre site pour sensor_passages
            if session.get('role') == 'admin':
                if site_slug:
                    sp_clause = 'site_slug = %s'
                    sp_params = [site_slug]
                else:
                    sp_clause = '1=1'
                    sp_params = []
            else:
                sp_clause = f"site_slug IN ({','.join(['%s']*len(site_params))})" if site_params else '1=0'
                sp_params = list(site_params)

            cur.execute(
                f"""SELECT EXTRACT(HOUR FROM timestamp)::int as h, COUNT(*) as n
                    FROM sensor_passages
                    WHERE {ts_h} AND {sp_clause}
                    GROUP BY h ORDER BY h""",
                sp_params
            )
            by_hour_raw = cur.fetchall()
            # Fallback sur kiosque si pas de données capteurs
            if not by_hour_raw:
                cur.execute(
                    f"SELECT EXTRACT(HOUR FROM heure)::int as h, COUNT(*) as n FROM sessions {where} GROUP BY h ORDER BY h",
                    site_params
                )
                by_hour_raw = cur.fetchall()
            by_hour = by_hour_raw

            cur.execute(
                f"SELECT mood, COUNT(*) as n FROM sessions {where} AND mood != '' GROUP BY mood ORDER BY n DESC",
                site_params
            )
            by_mood = cur.fetchall()

            # ── AJOUT 2 suite : by_day sur la période effective ──────────────
            cur.execute(
                f"""SELECT date, COUNT(*) as n
                    FROM sessions
                    WHERE date >= CURRENT_DATE - {day_interval} AND {site_clause}
                    GROUP BY date ORDER BY date""",
                site_params
            )
            by_day = cur.fetchall()
            # ─────────────────────────────────────────────────────────────────

            # by_atelier : depuis sensor_sessions (PIR réel)
            cur.execute(
                f"""SELECT atelier, COUNT(*) as nb_sessions,
                           ROUND(AVG(duree_sec))::int as duree_moy_sec
                    FROM sensor_sessions
                    WHERE {ts_debut} AND {sp_clause} AND atelier IS NOT NULL
                    GROUP BY atelier ORDER BY nb_sessions DESC""",
                sp_params
            )
            raw_sensor_at = cur.fetchall()

            # Fallback : si pas de données capteurs, utiliser les déclarations kiosque
            cur.execute(
                f"SELECT ateliers FROM sessions {where} AND ateliers != ''",
                site_params
            )
            raw_at = cur.fetchall()

            # ── AJOUT 3 : by_departement_mood (croisement pour l'onglet QVCT) ─
            # Retourne le ressenti par département pour la matrice CSSCT.
            # Chaque ligne : { departement, mood, n }
            cur.execute(
                f"""SELECT departement, mood, COUNT(*) as n
                    FROM sessions
                    {where} AND mood != '' AND departement != ''
                    GROUP BY departement, mood
                    ORDER BY departement, n DESC""",
                site_params
            )
            by_departement_mood = cur.fetchall()
            # ─────────────────────────────────────────────────────────────────

            if session.get('role') == 'admin':
                cur.execute(
                    f'SELECT site_slug, COUNT(*) as n FROM sessions {where} GROUP BY site_slug ORDER BY n DESC',
                    site_params
                )
                by_site = cur.fetchall()
            else:
                by_site = []

    # by_atelier : priorité sensor_sessions (PIR), fallback kiosque
    if raw_sensor_at:
        by_atelier = [
            {'atelier': r['atelier'], 'n': r['nb_sessions'], 'duree_moy_sec': r['duree_moy_sec']}
            for r in raw_sensor_at
        ]
    else:
        # Fallback : déclarations kiosque
        atelier_count = {}
        for row in raw_at:
            for a in (row['ateliers'] or '').split(', '):
                a = a.strip()
                if a:
                    atelier_count[a] = atelier_count.get(a, 0) + 1
        by_atelier = sorted(
            [{'atelier': k, 'n': v} for k, v in atelier_count.items()],
            key=lambda x: -x['n']
        )

    # ── AJOUT 5 : fréquences horaires par département ─────────────────────────
    # SOURCE : sessions kiosque (seule source avec département + heure)
    # Département = déclaratif kiosque / Heure = heure de la séance kiosque
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""SELECT departement,
                           EXTRACT(HOUR FROM heure)::int as h,
                           COUNT(*) as n
                    FROM sessions {where}
                    AND departement != ''
                    GROUP BY departement, h
                    ORDER BY departement, h""",
                site_params
            )
            by_departement_hour = cur.fetchall()
    # ─────────────────────────────────────────────────────────────────────────

    # ── AJOUT 6 : fréquences horaires par atelier — depuis sensor_sessions ──────
    # SOURCE : sensor_sessions (heure de début de session PIR)
    # Fallback : sessions kiosque si pas de données capteurs
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""SELECT atelier,
                           EXTRACT(HOUR FROM debut)::int as h,
                           COUNT(*) as n
                    FROM sensor_sessions
                    WHERE {ts_debut} AND {sp_clause} AND atelier IS NOT NULL
                    GROUP BY atelier, h
                    ORDER BY atelier, h""",
                sp_params
            )
            raw_at_hour_sensor = cur.fetchall()

    if raw_at_hour_sensor:
        by_atelier_hour = [serialize_row(r) for r in raw_at_hour_sensor]
    else:
        # Fallback kiosque
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""SELECT EXTRACT(HOUR FROM heure)::int as h,
                               ateliers as atelier_raw,
                               COUNT(*) as n
                        FROM sessions {where}
                        AND ateliers != ''
                        GROUP BY h, ateliers
                        ORDER BY h""",
                    site_params
                )
                raw_at_hour = cur.fetchall()
        atelier_hour = {}
        for row in raw_at_hour:
            h = row['h']
            n = row['n']
            for a in (row['atelier_raw'] or '').split(', '):
                a = a.strip()
                if not a:
                    continue
                key = (a, h)
                atelier_hour[key] = atelier_hour.get(key, 0) + n
        by_atelier_hour = sorted(
            [{'atelier': k[0], 'h': k[1], 'n': v} for k, v in atelier_hour.items()],
            key=lambda x: (x['atelier'], x['h'])
        )
    # ─────────────────────────────────────────────────────────────────────────

    # ── AJOUT 7 : ateliers préférés par département ───────────────────────────
    # SOURCE : sessions kiosque (seule table croisant département + atelier déclaré)
    # Le département et l'atelier sont tous deux déclaratifs (saisis par l'utilisateur)
    # Note : les slugs capteurs (meridienne-p127) et noms kiosque (Méridienne P127)
    # sont deux référentiels distincts — ce croisement utilise les noms kiosque.
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""SELECT departement, ateliers as atelier_raw, COUNT(*) as n
                    FROM sessions {where}
                    AND ateliers != '' AND departement != ''
                    GROUP BY departement, ateliers
                    ORDER BY departement, n DESC""",
                site_params
            )
            raw_dept_at = cur.fetchall()

    dept_atelier = {}
    for row in raw_dept_at:
        dept = row['departement']
        n = row['n']
        for a in (row['atelier_raw'] or '').split(', '):
            a = a.strip()
            if not a:
                continue
            if dept not in dept_atelier:
                dept_atelier[dept] = {}
            dept_atelier[dept][a] = dept_atelier[dept].get(a, 0) + n

    by_departement_atelier = []
    for dept, ateliers in dept_atelier.items():
        for atelier, n in sorted(ateliers.items(), key=lambda x: -x[1]):
            by_departement_atelier.append({'departement': dept, 'atelier': atelier, 'n': n})
    # ─────────────────────────────────────────────────────────────────────────

    return jsonify({
        'period': period,
        'total_seances': total,
        'by_departement':         [serialize_row(r) for r in by_dept],
        'by_hour':                [serialize_row(r) for r in by_hour],
        'by_atelier':             by_atelier,
        'by_mood':                [serialize_row(r) for r in by_mood],
        'by_day':                 [serialize_row(r) for r in by_day],
        'by_site':                [serialize_row(r) for r in by_site],
        'by_departement_mood':    [serialize_row(r) for r in by_departement_mood],
        # ── AJOUTS 5, 6, 7 ───────────────────────────────────────────────────
        'by_departement_hour':    [serialize_row(r) for r in by_departement_hour],
        'by_atelier_hour':        by_atelier_hour,
        'by_departement_atelier': by_departement_atelier,
        # ─────────────────────────────────────────────────────────────────────
    })


@app.route('/api/sessions', methods=['GET'])
@login_required
def get_sessions():
    period    = request.args.get('period', 'month')
    site_slug = request.args.get('site')
    dept      = request.args.get('departement')
    limit     = int(request.args.get('limit', 500))
    date_clause = build_date_clause(period)
    site_clause, params = get_site_filter(site_slug)
    where = f"WHERE {date_clause} AND {site_clause}"
    if dept:
        where += " AND departement = %s"
        params.append(dept)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM sessions {where} ORDER BY created_at DESC LIMIT %s", params + [limit])
            rows = cur.fetchall()
    return jsonify([serialize_row(r) for r in rows])


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
        sr = serialize_row(r)
        writer.writerow([sr['date'], sr['heure'], sr['departement'], sr['ateliers'], sr['mood'], sr['site_slug']])
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
                cur.execute(
                    "SELECT s.*, c.nom as client_nom FROM sites s JOIN clients c ON s.client_id=c.id ORDER BY c.nom, s.nom"
                )
            else:
                cur.execute(
                    "SELECT * FROM sites WHERE client_id=%s AND actif=1 ORDER BY nom",
                    [client_id]
                )
            sites = cur.fetchall()
    return jsonify([serialize_row(s) for s in sites])


# ── AJOUT 4 : PATCH /api/client/sites/<slug>/effectif ────────────────────────
@app.route('/api/client/sites/<site_slug>/effectif', methods=['PATCH'])
@login_required
def client_update_effectif(site_slug):
    """
    Permet au client (ou à l'admin) de mettre à jour le nombre de salariés
    d'un site directement depuis l'onglet QVCT du dashboard.
    Body JSON : { "nb_salaries": 400 }

    Note : le dashboard stocke également la valeur en localStorage pour
    une réactivité immédiate sans appel réseau. Cette route synchronise
    la valeur en base pour la persistance multi-navigateurs et l'export DUERP.
    """
    data = request.get_json()
    nb = data.get('nb_salaries')
    if nb is None or int(nb) < 0:
        return jsonify({'error': 'nb_salaries requis et doit être >= 0'}), 400

    # Vérification d'accès : admin libre, client limité à ses sites
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM sites WHERE slug=%s AND client_id=%s AND actif=1",
                    [site_slug, client_id]
                )
                site = cur.fetchone()
        if not site:
            return jsonify({'error': 'Site introuvable ou accès refusé'}), 403

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE sites SET nb_salaries=%s WHERE slug=%s",
                [int(nb), site_slug]
            )
            if cur.rowcount == 0:
                return jsonify({'error': 'Site introuvable'}), 404
            conn.commit()

    return jsonify({'ok': True, 'site_slug': site_slug, 'nb_salaries': int(nb)})
# ─────────────────────────────────────────────────────────────────────────────

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
    return jsonify({'status': 'ok', 'version': '2.2', 'sessions': nb_sessions, 'clients': nb_clients, 'sites': nb_sites})

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
    return serve_html('login.html')

@app.route('/admin')
def admin_page():
    if session.get('role') != 'admin':
        return redirect('/login')
    return serve_html('admin.html')

@app.route('/dashboard')
def dashboard_page():
    if 'user_id' not in session:
        return redirect('/login')
    return serve_html('dashboard.html')

@app.route('/roi')
def roi_page():
    return serve_html('ROI_beOtop.html')

@app.route('/kiosk/<site_slug>')
def kiosk_page(site_slug):
    path = os.path.join(BASE_DIR, 'beOtop_Kiosk.html')
    with open(path, encoding='utf-8') as f:
        html = f.read()
    html = html.replace("var SITE_SLUG = ''", f"var SITE_SLUG = '{site_slug}'")
    return Response(html, mimetype='text/html; charset=utf-8')

# ========== CONTACT FORMULAIRE ==========
import smtplib
from email.message import EmailMessage

@app.route('/api/contact', methods=['POST'])
def contact_form():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Données JSON requises'}), 400
    prenom    = data.get('prenom', '').strip()
    nom       = data.get('nom', '').strip()
    email     = data.get('email', '').strip()
    if not prenom or not nom or not email:
        return jsonify({'error': 'Prénom, nom et email requis'}), 400
    role       = data.get('role', '')
    entreprise = data.get('entreprise', '')
    effectif   = data.get('effectif', '')
    priorite   = data.get('priorite', '')
    message    = data.get('message', '')

    msg = EmailMessage()
    msg['Subject'] = f"[beOtop] Nouveau lead - {entreprise or 'non renseigné'}"
    msg['From']    = f"Formulaire beOtop <{os.environ.get('SMTP_USER', 'no-reply@beotop.fr')}>"
    msg['To']      = 'nj@beotop.fr'
    msg['Reply-To'] = email

    body = f"""
Nouvelle demande depuis le site beOtop

--- Contact ---
Prénom : {prenom}
Nom    : {nom}
Email  : {email}
Rôle   : {role}
Entreprise : {entreprise}
Effectif   : {effectif}
Priorité   : {priorite}

--- Message ---
{message if message else '(aucun message)'}

---
Envoyé depuis le formulaire public.
"""
    msg.set_content(body.strip())

    try:
        smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
        smtp_port = int(os.environ.get('SMTP_PORT', 587))
        smtp_user = os.environ.get('SMTP_USER')
        smtp_pass = os.environ.get('SMTP_PASSWORD')
        if smtp_user and smtp_pass:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        else:
            print(">>> Formulaire contact (SMTP non configuré) :", body, file=sys.stderr)
    except Exception as e:
        print(f"Erreur envoi email : {e}", file=sys.stderr)

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS leads (
                        id SERIAL PRIMARY KEY,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        prenom TEXT, nom TEXT, email TEXT,
                        role TEXT, entreprise TEXT, effectif TEXT,
                        priorite TEXT, message TEXT
                    )
                """)
                cur.execute("""
                    INSERT INTO leads (prenom, nom, email, role, entreprise, effectif, priorite, message)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (prenom, nom, email, role, entreprise, effectif, priorite, message))
                conn.commit()
    except Exception as e:
        print("Erreur insertion lead en base :", e, file=sys.stderr)

    return jsonify({'ok': True, 'message': 'Demande envoyée'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
