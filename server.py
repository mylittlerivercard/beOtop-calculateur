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

        # ========== NOUVELLES TABLES CAPTEURS ==========

        # Passage : chaque franchissement du faisceau (entrée ou sortie)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS sensor_passages (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                site_slug   TEXT NOT NULL,
                direction   TEXT,          -- 'entree' | 'sortie' | null si inconnu
                timestamp   TIMESTAMP NOT NULL
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_passages_site ON sensor_passages(site_slug)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_passages_ts   ON sensor_passages(timestamp)')

        # Occupation : signal PIR par atelier, toutes les N secondes
        cur.execute('''
            CREATE TABLE IF NOT EXISTS sensor_occupation (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                site_slug   TEXT NOT NULL,
                atelier     TEXT NOT NULL,  -- ex: 'fauteuil-massage', 'bain-lumiere'
                occupe      BOOLEAN NOT NULL,
                timestamp   TIMESTAMP NOT NULL
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_occupation_site    ON sensor_occupation(site_slug)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_occupation_atelier ON sensor_occupation(atelier)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_occupation_ts      ON sensor_occupation(timestamp)')

        # Sessions capteurs : durée calculée par le RPi (début/fin de présence dans l'espace)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS sensor_sessions (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                site_slug   TEXT NOT NULL,
                atelier     TEXT,           -- null = session globale espace, sinon atelier spécifique
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
    """
    Reçoit un événement de franchissement du faisceau depuis le RPi.
    Body JSON attendu :
    {
        "site_slug": "bpce-paris-19",
        "direction": "entree",       # optionnel : 'entree' | 'sortie'
        "timestamp": "2026-03-26T10:30:00"  # optionnel, sinon now()
    }
    """
    data = request.get_json()
    if not data or not data.get('site_slug'):
        return jsonify({'error': 'site_slug requis'}), 400

    site_slug = data['site_slug']
    direction = data.get('direction')  # peut être null
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
    """
    Reçoit un signal PIR depuis le RPi (toutes les N secondes par atelier).
    Body JSON attendu :
    {
        "site_slug": "bpce-paris-19",
        "atelier": "fauteuil-massage",
        "occupe": true,
        "timestamp": "2026-03-26T10:30:00"  # optionnel
    }
    Accepte aussi un tableau d'événements pour envoi groupé :
    [
        {"site_slug": "...", "atelier": "...", "occupe": true, "timestamp": "..."},
        ...
    ]
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body JSON requis'}), 400

    # Normalise : accepte un objet unique ou un tableau
    events = data if isinstance(data, list) else [data]

    inserted = 0
    with get_db() as conn:
        with conn.cursor() as cur:
            for evt in events:
                site_slug = evt.get('site_slug')
                atelier   = evt.get('atelier')
                occupe    = evt.get('occupe', True)
                ts_raw    = evt.get('timestamp')

                if not site_slug or not atelier:
                    continue  # ignore les lignes invalides, ne bloque pas le batch

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
    """
    Reçoit une session complète calculée par le RPi (début + fin + durée).
    Body JSON attendu :
    {
        "site_slug": "bpce-paris-19",
        "atelier": "fauteuil-massage",  # optionnel — null = session globale espace
        "debut": "2026-03-26T10:15:00",
        "fin":   "2026-03-26T10:33:00",
        "duree_sec": 1080
    }
    """
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
                [site_slug, data.get('atelier'), debut, fin, duree_sec]
            )
            new_id = cur.fetchone()['id']
            conn.commit()

    return jsonify({'ok': True, 'id': new_id}), 201


# ========== CAPTEURS — STATISTIQUES ==========

@app.route('/api/sensors/stats', methods=['GET'])
@login_required
def sensors_stats():
    """
    Retourne les métriques capteurs pour un site et une période.
    Params : site_slug (requis), period (today|week|month|year)
    """
    site_slug = request.args.get('site_slug')
    period    = request.args.get('period', 'today')

    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400

    # Vérification d'accès : admin voit tout, client voit son périmètre
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                slugs = [r['slug'] for r in cur.fetchall()]
        if site_slug not in slugs:
            return jsonify({'error': 'Accès refusé'}), 403

    # Clause de date adaptée aux colonnes timestamp des tables capteurs
    if period == 'today':
        ts_clause = '"timestamp" >= CURRENT_DATE AND "timestamp" < CURRENT_DATE + INTERVAL \'1 day\''
    elif period == 'week':
        ts_clause = '"timestamp" >= NOW() - INTERVAL \'7 days\''
    elif period == 'month':
        ts_clause = '"timestamp" >= NOW() - INTERVAL \'30 days\''
    elif period == 'year':
        ts_clause = '"timestamp" >= NOW() - INTERVAL \'365 days\''
    else:
        ts_clause = "1=1"

    with get_db() as conn:
        with conn.cursor() as cur:

            # Nombre total de passages
            cur.execute(
                f"SELECT COUNT(*) as n FROM sensor_passages WHERE site_slug=%s AND {ts_clause}",
                [site_slug]
            )
            total_passages = cur.fetchone()['n']

            # Passages par heure
            cur.execute(
                f"""SELECT EXTRACT(HOUR FROM timestamp)::int as h, COUNT(*) as n
                    FROM sensor_passages
                    WHERE site_slug=%s AND {ts_clause}
                    GROUP BY h ORDER BY h""",
                [site_slug]
            )
            passages_par_heure = cur.fetchall()

            # Taux d'occupation par atelier (% de signaux PIR actifs sur la période)
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

            # Sessions : sensor_sessions utilise 'debut', pas 'timestamp'
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


# ========== STATISTIQUES ==========

def build_date_clause(period, prefix=''):
    p = f"{prefix}." if prefix else ""
    if period == 'today':  return f"{p}date = CURRENT_DATE"
    if period == 'week':   return f"{p}date >= CURRENT_DATE - INTERVAL '7 days'"
    if period == 'month':  return f"{p}date >= CURRENT_DATE - INTERVAL '30 days'"
    if period == 'year':   return f"{p}date >= CURRENT_DATE - INTERVAL '365 days'"
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

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f'SELECT COUNT(*) as n FROM sessions {where}', site_params)
            total = cur.fetchone()['n']
            cur.execute(f'SELECT departement as label, COUNT(*) as n FROM sessions {where} GROUP BY departement ORDER BY n DESC', site_params)
            by_dept = cur.fetchall()
            cur.execute(f"SELECT EXTRACT(HOUR FROM heure)::int as h, COUNT(*) as n FROM sessions {where} GROUP BY h ORDER BY h", site_params)
            by_hour = cur.fetchall()
            cur.execute(f"SELECT mood, COUNT(*) as n FROM sessions {where} AND mood != '' GROUP BY mood ORDER BY n DESC", site_params)
            by_mood = cur.fetchall()
            cur.execute(f"SELECT date, COUNT(*) as n FROM sessions WHERE date >= CURRENT_DATE - INTERVAL '30 days' AND {site_clause} GROUP BY date ORDER BY date", site_params)
            by_day = cur.fetchall()
            cur.execute(f"SELECT ateliers FROM sessions {where} AND ateliers != ''", site_params)
            raw_at = cur.fetchall()
            if session.get('role') == 'admin':
                cur.execute(f'SELECT site_slug, COUNT(*) as n FROM sessions {where} GROUP BY site_slug ORDER BY n DESC', site_params)
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
        'by_departement': [serialize_row(r) for r in by_dept],
        'by_hour':        [serialize_row(r) for r in by_hour],
        'by_atelier':     by_atelier,
        'by_mood':        [serialize_row(r) for r in by_mood],
        'by_day':         [serialize_row(r) for r in by_day],
        'by_site':        [serialize_row(r) for r in by_site],
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
                cur.execute("SELECT s.*, c.nom as client_nom FROM sites s JOIN clients c ON s.client_id=c.id ORDER BY c.nom, s.nom")
            else:
                cur.execute("SELECT * FROM sites WHERE client_id=%s AND actif=1 ORDER BY nom", [client_id])
            sites = cur.fetchall()
    return jsonify([serialize_row(s) for s in sites])

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
    return jsonify({'status': 'ok', 'version': '2.1', 'sessions': nb_sessions, 'clients': nb_clients, 'sites': nb_sites})

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
    """
    Reçoit les données du formulaire de contact (page statique beOtop)
    et envoie un email à nj@beotop.fr
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Données JSON requises'}), 400

    # Champs obligatoires
    prenom = data.get('prennom', '').strip()  # attention faute possible dans le HTML
    nom    = data.get('nom', '').strip()
    email  = data.get('email', '').strip()
    if not prenom or not nom or not email:
        return jsonify({'error': 'Prénom, nom et email requis'}), 400

    # Champs optionnels
    role      = data.get('role', '')
    entreprise = data.get('entreprise', '')
    effectif   = data.get('effectif', '')
    priorite   = data.get('priorite', '')
    message    = data.get('message', '')

    # Construction de l'email
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

    # Envoi via SMTP (à configurer dans les variables d'environnement Render)
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
            # Fallback : afficher dans les logs (pour test)
            print(">>> Formulaire contact (email non envoyé, SMTP non configuré) :", body, file=sys.stderr)
            # Tu peux aussi stocker en base si tu préfères
    except Exception as e:
        print(f"Erreur envoi email : {e}", file=sys.stderr)
        # On retourne quand même un succès pour ne pas bloquer l'utilisateur
        # mais tu peux aussi retourner une erreur 500

    # Optionnel : stocker le lead dans une table dédiée
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
