#!/usr/bin/env python3
"""
beOtop - Serveur complet v2.2
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
import json
import secrets
from datetime import datetime, date
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

@app.after_request
def add_headers(response):
    # Pas de CSP sur les fichiers statiques/audio
    if request.path.startswith('/audio/') or request.path.startswith('/static/'):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Accept-Ranges'] = 'bytes'
        return response
    # Autoriser YouTube et Vimeo en iframe (contenu Companion)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "frame-src https://www.youtube.com https://player.vimeo.com https://w.soundcloud.com; "
        "img-src 'self' data: https:; "
        "media-src 'self' https://mylittlerivercard.github.io https://beotop-api.onrender.com https://soundcloud.com https://*.sndcdn.com blob:; "
        "connect-src 'self' https://mylittlerivercard.github.io https://api.qrserver.com https://soundcloud.com https://api.soundcloud.com https://speech.platform.bing.com wss://speech.platform.bing.com; "
    )
    return response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def serve_html(filename):
    path = os.path.join(BASE_DIR, filename)
    try:
        with open(path, encoding='utf-8') as f:
            return Response(f.read(), mimetype='text/html; charset=utf-8')
    except FileNotFoundError:
        return Response(f'<h1>Fichier introuvable : {filename}</h1>', status=404, mimetype='text/html')

@app.route('/manifest.json')
def serve_manifest():
    path = os.path.join(BASE_DIR, 'manifest.json')
    try:
        with open(path, encoding='utf-8') as f:
            return Response(f.read(), mimetype='application/manifest+json')
    except FileNotFoundError:
        return Response('{}', status=404, mimetype='application/json')

@app.route('/sw.js')
def serve_sw():
    path = os.path.join(BASE_DIR, 'sw.js')
    try:
        with open(path, encoding='utf-8') as f:
            return Response(f.read(), mimetype='application/javascript', headers={'Service-Worker-Allowed': '/'})
    except FileNotFoundError:
        return Response('', status=404, mimetype='application/javascript')

@app.route('/companion_pwa')
def companion_pwa_page():
    if 'user_id' not in session:
        return redirect('/login')
    return serve_html('companion_pwa.html')

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

# ── Normalisation noms d'ateliers ─────────────────────────────────────────────
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

# ── K-anonymisation (k=5) ──────────────────────────────────────────────────────
K_ANONYMAT = 5

def kanon_filter(rows, key_field, count_field='n', label_autres='Autres'):
    kept   = [r for r in rows if (r.get(count_field) or 0) >= K_ANONYMAT]
    others = [r for r in rows if (r.get(count_field) or 0) < K_ANONYMAT]
    if others:
        total_others = sum(r.get(count_field, 0) for r in others)
        if total_others >= K_ANONYMAT:
            kept.append({key_field: label_autres, count_field: total_others, '_aggregated': True})
    return kept, bool(others)

def kanon_filter_cross(rows, key1, key2, count_field='n'):
    totaux = {}
    for r in rows:
        k = r.get(key1, '')
        totaux[k] = totaux.get(k, 0) + (r.get(count_field) or 0)
    kept = [
        r for r in rows
        if totaux.get(r.get(key1, ''), 0) >= K_ANONYMAT
        and (r.get(count_field) or 0) >= K_ANONYMAT
    ]
    return kept

def serialize_row(row):
    d = dict(row)
    for k, v in d.items():
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d

# Tables de contenus Companion (une table dédiée par type) → colonnes TEXT
COMPANION_CONTENT_TABLES = {
    'videos':    ['titre', 'categorie', 'description', 'url_video', 'duree', 'icon', 'intervenant'],
    'audios':    ['titre', 'categorie', 'description', 'url_audio', 'duree', 'icon', 'photo', 'intervenant'],
    'exercices': ['titre', 'categorie', 'indication', 'description', 'duree', 'icon', 'intervenant'],
    'defis':     ['titre', 'categorie', 'description', 'url_audio', 'duree', 'icon', 'photo', 'intervenant'],
    'podcasts':  ['titre', 'categorie', 'description', 'url', 'type_url', 'duree', 'icon', 'intervenant'],
    'posts':     ['titre', 'categorie', 'contenu', 'image', 'lien', 'auteur'],
    'huiles':    ['titre', 'categorie', 'description', 'contenu', 'url_video', 'url_externe', 'photo', 'icon', 'intervenant'],
    'recettes':  ['titre', 'categorie', 'description', 'contenu', 'url_externe', 'photo', 'duree', 'icon', 'intervenant'],
}

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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS devis (
                id              SERIAL PRIMARY KEY,
                numero          TEXT NOT NULL,
                created_at      TIMESTAMP DEFAULT NOW(),
                valid_until     TEXT,
                prospect        TEXT,
                contact         TEXT,
                commercial      TEXT,
                nb_employes     INTEGER,
                salaire_moyen   NUMERIC,
                mode_travail    TEXT,
                jours_hybride   INTEGER,
                posture         TEXT,
                scenario        TEXT,
                option_espace   TEXT,
                surface_m2      NUMERIC,
                nb_postes       INTEGER,
                equipements     JSONB,
                capex_total     NUMERIC,
                cout_annuel     NUMERIC,
                gain_annuel     NUMERIC,
                economie_nette  NUMERIC,
                roi_pct         NUMERIC,
                payback_mois    NUMERIC,
                taux_dysf       NUMERIC,
                part_adressable NUMERIC,
                deco_pm2        NUMERIC,
                im_pm2          NUMERIC,
                formation       NUMERIC,
                animation       NUMERIC,
                site_slug       TEXT,
                client_id       INTEGER REFERENCES clients(id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reservations (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                site_slug   TEXT NOT NULL,
                atelier     TEXT NOT NULL,
                user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
                date        DATE NOT NULL,
                heure_debut TIME NOT NULL,
                duree_min   INTEGER NOT NULL DEFAULT 20,
                statut      TEXT NOT NULL DEFAULT 'confirmee',
                notes       TEXT
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_res_site    ON reservations(site_slug)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_res_date    ON reservations(date)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_res_atelier ON reservations(atelier)')

        # Tables Companion
        cur.execute("""
            CREATE TABLE IF NOT EXISTS companion_checkins (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
                site_slug   TEXT,
                date        DATE NOT NULL DEFAULT CURRENT_DATE,
                energie     SMALLINT NOT NULL CHECK (energie BETWEEN 1 AND 10),
                stress      SMALLINT NOT NULL CHECK (stress BETWEEN 1 AND 10),
                focus       SMALLINT NOT NULL CHECK (focus BETWEEN 1 AND 10)
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_checkins_user ON companion_checkins(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_checkins_date ON companion_checkins(date)')
        # Tokens d'inscription par site
        cur.execute('''
            CREATE TABLE IF NOT EXISTS site_invite_tokens (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                site_id     INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                site_slug   TEXT NOT NULL,
                token       TEXT NOT NULL UNIQUE,
                actif       INTEGER DEFAULT 1,
                nb_inscrits INTEGER DEFAULT 0
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_tokens_token ON site_invite_tokens(token)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_tokens_site ON site_invite_tokens(site_slug)')

        cur.execute("""
            CREATE TABLE IF NOT EXISTS companion_cc_sessions (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
                site_slug   TEXT,
                date        DATE NOT NULL DEFAULT CURRENT_DATE,
                protocole   TEXT NOT NULL DEFAULT '365',
                duree_min   SMALLINT NOT NULL DEFAULT 5,
                complete    BOOLEAN NOT NULL DEFAULT TRUE
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_cc_user ON companion_cc_sessions(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_cc_date ON companion_cc_sessions(date)')

        cur.execute("""
            CREATE TABLE IF NOT EXISTS companion_points (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                site_slug   TEXT,
                action      TEXT NOT NULL,
                label       TEXT,
                points      SMALLINT NOT NULL,
                date        DATE NOT NULL DEFAULT CURRENT_DATE
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_pts_user ON companion_points(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_pts_date ON companion_points(date)')

        # Tracking lectures par contenu/intervenant (rétribution)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS companion_content_plays (
                id              SERIAL PRIMARY KEY,
                created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                site_slug       TEXT,
                user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
                content_type    TEXT NOT NULL,
                content_label   TEXT NOT NULL,
                intervenant_id  INTEGER,
                intervenant_nom TEXT,
                duree_sec       INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_plays_intervenant ON companion_content_plays(intervenant_nom)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_plays_date        ON companion_content_plays(created_at)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_plays_site        ON companion_content_plays(site_slug)')

        # ── Table intervenants (V1 rétribution) ──────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS intervenants (
                id              SERIAL PRIMARY KEY,
                created_at      TIMESTAMP DEFAULT NOW(),
                user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
                nom             TEXT NOT NULL,
                email           TEXT,
                specialite      TEXT,
                bio             TEXT,
                photo_url       TEXT,
                taux_contenu    NUMERIC DEFAULT 30,
                apporteur_affaire BOOLEAN DEFAULT FALSE,
                actif           BOOLEAN DEFAULT TRUE
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_intervenants_user  ON intervenants(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_intervenants_email ON intervenants(email)')

        # Distingue les intervenants de contenu (visibles dans Companion)
        # des simples apporteurs d'affaire.
        cur.execute("""
            ALTER TABLE intervenants
            ADD COLUMN IF NOT EXISTS est_intervenant BOOLEAN DEFAULT TRUE
        """)

        # Migration douce — colonnes V2 sur clients
        cur.execute("""
            ALTER TABLE clients
            ADD COLUMN IF NOT EXISTS apporteur_id INTEGER REFERENCES intervenants(id) ON DELETE SET NULL
        """)
        cur.execute("""
            ALTER TABLE clients
            ADD COLUMN IF NOT EXISTS tarif_utilisateur_mensuel NUMERIC DEFAULT 0
        """)
        cur.execute("""
            ALTER TABLE sites
            ADD COLUMN IF NOT EXISTS has_companion  INTEGER DEFAULT 0
        """)
        cur.execute("""
            ALTER TABLE sites
            ADD COLUMN IF NOT EXISTS tarif_annuel   NUMERIC DEFAULT 0
        """)

        # ── Semestres de rétribution ──────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS retribution_semestres (
                id                  SERIAL PRIMARY KEY,
                created_at          TIMESTAMP DEFAULT NOW(),
                annee               INTEGER NOT NULL,
                semestre            SMALLINT NOT NULL CHECK (semestre IN (1,2)),
                intervenant_id      INTEGER NOT NULL REFERENCES intervenants(id) ON DELETE CASCADE,
                site_slug           TEXT,
                nb_clics            INTEGER DEFAULT 0,
                pct_clics           NUMERIC DEFAULT 0,
                ca_site             NUMERIC DEFAULT 0,
                montant_contenu     NUMERIC DEFAULT 0,
                statut              TEXT DEFAULT 'calcule',
                UNIQUE (annee, semestre, intervenant_id, site_slug)
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_retrib_intervenant ON retribution_semestres(intervenant_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_retrib_periode     ON retribution_semestres(annee, semestre)')

        # ── Contenus Companion ajoutés par les intervenants ───────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS companion_contenus (
                id              SERIAL PRIMARY KEY,
                created_at      TIMESTAMP DEFAULT NOW(),
                type            TEXT NOT NULL,
                titre           TEXT NOT NULL,
                intervenant_id  INTEGER REFERENCES intervenants(id) ON DELETE SET NULL,
                intervenant_nom TEXT,
                actif           BOOLEAN DEFAULT TRUE,
                data            JSONB NOT NULL DEFAULT '{}'
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_contenus_type        ON companion_contenus(type)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_contenus_intervenant ON companion_contenus(intervenant_id)')

        # ── Sons immersifs Companion (gérés par site) ─────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS companion_sons (
                id          SERIAL PRIMARY KEY,
                site_slug   TEXT,
                nom         TEXT NOT NULL,
                label       TEXT NOT NULL,
                photo       TEXT,
                audio       TEXT,
                actif       BOOLEAN DEFAULT TRUE,
                ordre       INTEGER DEFAULT 0
            )
        """)
        cur.execute("ALTER TABLE companion_sons ADD COLUMN IF NOT EXISTS audio TEXT")
        cur.execute('CREATE INDEX IF NOT EXISTS idx_sons_site ON companion_sons(site_slug)')

        # ── Intervenants Companion (persistance dédiée, par site) ─────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS companion_intervenants (
                id          SERIAL PRIMARY KEY,
                site_slug   TEXT,
                nom         TEXT,
                specialite  TEXT,
                bio         TEXT,
                photo       TEXT,
                photo_url   TEXT,
                titre       TEXT,
                tags        TEXT,
                actif       BOOLEAN DEFAULT TRUE,
                created_at  TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_cint_site ON companion_intervenants(site_slug)')
        cur.execute("ALTER TABLE companion_intervenants ADD COLUMN IF NOT EXISTS site_url TEXT")
        cur.execute("ALTER TABLE companion_intervenants ADD COLUMN IF NOT EXISTS linkedin_url TEXT")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL")

        # ── Tables de contenus Companion (une par type) ───────────────────────
        for _t, _cols in COMPANION_CONTENT_TABLES.items():
            _coldef = ', '.join(c + ' TEXT' for c in _cols)
            cur.execute(
                "CREATE TABLE IF NOT EXISTS companion_" + _t + " ("
                "id SERIAL PRIMARY KEY, site_slug TEXT, " + _coldef + ", "
                "actif BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW())"
            )
            # Auto-réparation : ajoute toute colonne manquante aux tables existantes
            for _c in _cols:
                cur.execute("ALTER TABLE companion_" + _t + " ADD COLUMN IF NOT EXISTS " + _c + " TEXT")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_c" + _t + "_site ON companion_" + _t + "(site_slug)")

        # ── Migration unique : ancienne table JSONB companion_contenus → tables par type ──
        cur.execute("SELECT to_regclass('public.companion_contenus') AS t")
        if cur.fetchone()['t'] is not None:
            _type_map = {'audio': 'audios', 'video': 'videos', 'exercice': 'exercices',
                         'defi': 'defis', 'podcast': 'podcasts'}
            for _old, _new in _type_map.items():
                cur.execute("SELECT COUNT(*) AS n FROM companion_" + _new)
                if cur.fetchone()['n'] != 0:
                    continue   # déjà des données → on ne migre pas
                cur.execute("SELECT * FROM companion_contenus WHERE type=%s", [_old])
                _rows = cur.fetchall()
                _cols = COMPANION_CONTENT_TABLES[_new]
                for _r in _rows:
                    _data = _r.get('data') or {}
                    if isinstance(_data, str):
                        try: _data = json.loads(_data)
                        except Exception: _data = {}
                    _fields = ['site_slug'] + _cols + ['actif']
                    _vals = [_data.get('site_slug', '') or '']
                    for _c in _cols:
                        if _c == 'intervenant':
                            _vals.append(_r.get('intervenant_nom') or _data.get('intervenant') or '')
                        elif _c == 'titre':
                            _vals.append(_r.get('titre') or _data.get('titre') or '')
                        else:
                            _vals.append(_data.get(_c, '') or '')
                    _vals.append(_r.get('actif', True))
                    _ph = ', '.join(['%s'] * len(_fields))
                    cur.execute("INSERT INTO companion_" + _new + " (" + ', '.join(_fields) + ") VALUES (" + _ph + ")", _vals)
            print(">>> Migration companion_contenus → tables par type vérifiée", file=sys.stderr)

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
        # Le role 'demo' (acces public lecture seule) est autorise ; les ecritures
        # sont bloquees globalement par _demo_guard (before_request).
        if 'user_id' not in session and session.get('role') != 'demo':
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

def intervenant_required(f):
    """Autorise admin ET intervenant."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') not in ('admin', 'intervenant'):
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
    session['site_id']   = user.get('site_id')
    session['nom']       = user['nom']
    return jsonify({
        'ok': True, 'role': user['role'], 'nom': user['nom'],
        'redirect': '/admin' if user['role'] == 'admin' else ('/mon-espace' if user['role'] == 'intervenant' else ('/dashboard' if user['role'] in ('manager', 'client') else '/companion_pwa'))
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def me():
    user = get_current_user()
    if user is None:
        # Mode demo : pas de ligne users (user_id=0), on renvoie une identite synthetique.
        if session.get('role') == 'demo':
            return jsonify({
                'id': 0,
                'email': session.get('email', 'demo@beotop.fr'),
                'nom': session.get('nom', 'Visiteur démo'),
                'role': 'demo',
                'client_id': session.get('client_id'),
                'intervenant_id': None,
                'intervenant_nom': None
            })
        return jsonify({'error': 'Non authentifie', 'redirect': '/login'}), 401
    inv_id, inv_nom = _resolve_intervenant()
    return jsonify({
        'id': user['id'], 'email': user['email'],
        'nom': user['nom'], 'role': user['role'],
        'client_id': user['client_id'],
        'site_id': user.get('site_id'),
        'intervenant_id': inv_id,
        'intervenant_nom': inv_nom
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
            cur.execute("UPDATE users SET password=%s WHERE id=%s",
                        [generate_password_hash(new_pw), user['id']])
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
                SELECT c.*,
                       COUNT(DISTINCT s.id) as nb_sites,
                       (SELECT COUNT(*) FROM sessions se JOIN sites si ON se.site_id=si.id WHERE si.client_id=c.id) as nb_sessions,
                       i.nom as apporteur_nom
                FROM clients c
                LEFT JOIN sites s ON s.client_id=c.id
                LEFT JOIN intervenants i ON i.id = c.apporteur_id
                GROUP BY c.id, i.nom ORDER BY c.created_at DESC
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

@app.route('/api/admin/clients/<int:client_id>/apporteur', methods=['PATCH'])
@login_required
@admin_required
def admin_set_apporteur(client_id):
    """Définit l'intervenant apporteur d'affaire et le tarif mensuel d'un client."""
    data = request.get_json() or {}
    apporteur_id = data.get('apporteur_id')  # None pour supprimer
    tarif        = float(data.get('tarif_utilisateur_mensuel', 0) or 0)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE clients
                SET apporteur_id = %s, tarif_utilisateur_mensuel = %s
                WHERE id = %s
            """, [apporteur_id, tarif, client_id])
            if cur.rowcount == 0:
                return jsonify({'error': 'Client introuvable'}), 404
            conn.commit()
    return jsonify({'ok': True, 'client_id': client_id,
                    'apporteur_id': apporteur_id, 'tarif': tarif})


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
                has_companion = 1 if data.get('has_companion') else 0
                tarif_annuel  = float(data.get('tarif_annuel', 0) or 0)
                cur.execute(
                    "INSERT INTO sites (client_id, nom, slug, ville, nb_salaries, has_companion, tarif_annuel) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                    [client_id, nom, slug, data.get('ville',''), data.get('nb_salaries', 0), has_companion, tarif_annuel]
                )
                site_id = cur.fetchone()['id']
                conn.commit()
            except psycopg2.IntegrityError:
                return jsonify({'error': 'Ce site existe deja'}), 409
    return jsonify({'ok': True, 'site_id': site_id, 'slug': slug, 'kiosk_url': f'/kiosk/{slug}'}), 201

@app.route('/api/admin/sites/<int:site_id>', methods=['PUT'])
@login_required
@admin_required
def admin_update_site(site_id):
    data = request.get_json()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE sites SET nom=%s, ville=%s, nb_salaries=%s, actif=%s, has_companion=%s, tarif_annuel=%s WHERE id=%s",
                [data.get('nom'), data.get('ville'), int(data.get('nb_salaries') or 0),
                 int(data.get('actif', 1)),
                 1 if data.get('has_companion') else 0,
                 float(data.get('tarif_annuel', 0) or 0),
                 site_id]
            )
            conn.commit()
    return jsonify({'ok': True})

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
                    "INSERT INTO users (email, password, nom, role, client_id, site_id) VALUES (%s,%s,%s,%s,%s,%s)",
                    [email, generate_password_hash(tmp_pw), data.get('nom',''),
                     data.get('role','client'), data.get('client_id'), data.get('site_id')]
                )
                conn.commit()
            except psycopg2.IntegrityError:
                return jsonify({'error': 'Email deja utilise'}), 409
    return jsonify({'ok': True, 'tmp_password': tmp_pw}), 201

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def admin_update_user(user_id):
    data = request.get_json() or {}
    role = (data.get('role') or 'client').strip()
    if role not in ('admin', 'client', 'intervenant', 'manager'):
        return jsonify({'error': 'Rôle invalide'}), 400
    client_id = data.get('client_id') or None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET nom=%s, role=%s, client_id=%s, actif=%s WHERE id=%s",
                [data.get('nom', ''), role, client_id,
                 int(data.get('actif', 1)), user_id]
            )
            if cur.rowcount == 0:
                return jsonify({'error': 'Utilisateur introuvable'}), 404
            conn.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    new_pw = secrets.token_urlsafe(8)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password=%s WHERE id=%s",
                        [generate_password_hash(new_pw), user_id])
            conn.commit()
    return jsonify({'ok': True, 'new_password': new_pw})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'error': 'Impossible de supprimer votre propre compte'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id=%s", [user_id])
            if cur.rowcount == 0:
                return jsonify({'error': 'Utilisateur introuvable'}), 404
            conn.commit()
    return jsonify({'ok': True})

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
@app.route('/api/kiosk/<site_slug>/join-link', methods=['GET'])
def kiosk_join_link(site_slug):
    """Retourne le lien d'inscription Companion pour un site donné"""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT token FROM site_invite_tokens
                WHERE site_slug=%s AND actif=1
                ORDER BY created_at DESC LIMIT 1
            """, [site_slug])
            row = cur.fetchone()
    if not row:
        return jsonify({'url': None}), 200
    return jsonify({'url': f'/join/{row["token"]}'})



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

# ── NOUVELLE ROUTE PUBLIQUE — état actuel occupation (temps réel) ─────────────
@app.route('/api/sensors/occupation/current', methods=['GET'])
def sensors_occupation_current():
    """
    Retourne l'état d'occupation actuel de chaque atelier (dernière valeur connue).
    Route publique — pas d'authentification requise.
    Utilisée par la page temps réel realtime.html
    """
    site_slug = request.args.get('site_slug')
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT ON (atelier) atelier, occupe, timestamp
                FROM sensor_occupation
                WHERE site_slug=%s
                ORDER BY atelier, timestamp DESC
            """, [site_slug])
            rows = cur.fetchall()
    result = {r['atelier']: r['occupe'] for r in rows}
    return jsonify({
        'site_slug': site_slug,
        'ateliers': result,
        'updated_at': datetime.now().isoformat()
    })

# ── NOUVELLE ROUTE PUBLIQUE — passages du jour ────────────────────────────────
@app.route('/api/sensors/passages/today', methods=['GET'])
def sensors_passages_today():
    """
    Retourne le nombre de passages du jour.
    Route publique — pas d'authentification requise.
    Utilisée par la page temps réel realtime.html
    """
    site_slug = request.args.get('site_slug')
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) as n FROM sensor_passages
                WHERE site_slug=%s
                AND "timestamp" >= CURRENT_DATE
                AND "timestamp" < CURRENT_DATE + INTERVAL '1 day'
            """, [site_slug])
            n = cur.fetchone()['n']
    return jsonify({'site_slug': site_slug, 'passages_today': n})

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

# ========== CAPTEURS — STATISTIQUES (authentifié) ==========

@app.route('/api/sensors/stats', methods=['GET'])
@login_required
def sensors_stats():
    site_slug = request.args.get('site_slug')
    period    = request.args.get('period', 'today')
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        mgr_site_id = session.get('site_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                if mgr_site_id:
                    cur.execute("SELECT slug FROM sites WHERE id=%s AND client_id=%s", [mgr_site_id, client_id])
                else:
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
            cur.execute(f"SELECT COUNT(*) as n FROM sensor_passages WHERE site_slug=%s AND {ts_clause}", [site_slug])
            total_passages = cur.fetchone()['n']
            cur.execute(
                f"""SELECT EXTRACT(HOUR FROM timestamp)::int as h, COUNT(*) as n
                    FROM sensor_passages WHERE site_slug=%s AND {ts_clause}
                    GROUP BY h ORDER BY h""", [site_slug])
            passages_par_heure = cur.fetchall()
            cur.execute(
                f"""SELECT atelier,
                           COUNT(*) as total_signaux,
                           SUM(CASE WHEN occupe THEN 1 ELSE 0 END) as signaux_actifs
                    FROM sensor_occupation WHERE site_slug=%s AND {ts_clause}
                    GROUP BY atelier ORDER BY atelier""", [site_slug])
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
                f"""SELECT atelier, COUNT(*) as nb_sessions,
                           ROUND(AVG(duree_sec))::int as duree_moy_sec,
                           MIN(duree_sec) as duree_min_sec,
                           MAX(duree_sec) as duree_max_sec
                    FROM sensor_sessions WHERE site_slug=%s AND {ts_clause_sessions}
                    GROUP BY atelier ORDER BY nb_sessions DESC""", [site_slug])
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
        mgr_site_id = session.get('site_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                if mgr_site_id:
                    cur.execute("SELECT slug FROM sites WHERE id=%s AND client_id=%s", [mgr_site_id, client_id])
                else:
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
    else:
        ts_clause = "1=1"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""SELECT id, "timestamp", direction FROM sensor_passages
                    WHERE site_slug=%s AND {ts_clause}
                    ORDER BY "timestamp" DESC LIMIT %s""",
                [site_slug, limit])
            rows = cur.fetchall()
    return jsonify({'site_slug': site_slug, 'period': period, 'total': len(rows),
                    'passages': [serialize_row(r) for r in rows]})

@app.route('/api/sensors/passages/export', methods=['GET'])
@login_required
def sensors_passages_export():
    site_slug = request.args.get('site_slug')
    from_date = request.args.get('from', date.today().isoformat())
    to_date   = request.args.get('to', date.today().isoformat())
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        mgr_site_id = session.get('site_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                if mgr_site_id:
                    cur.execute("SELECT slug FROM sites WHERE id=%s AND client_id=%s", [mgr_site_id, client_id])
                else:
                    cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                slugs = [r['slug'] for r in cur.fetchall()]
        if site_slug not in slugs:
            return jsonify({'error': 'Accès refusé'}), 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT "timestamp", direction FROM sensor_passages
                   WHERE site_slug=%s AND "timestamp"::date BETWEEN %s AND %s
                   ORDER BY "timestamp" ASC""",
                [site_slug, from_date, to_date])
            rows = cur.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['date', 'heure', 'direction', 'site'])
    for r in rows:
        sr = serialize_row(r)
        ts = sr['timestamp']
        writer.writerow([ts[:10], ts[11:19], sr.get('direction') or 'entree', site_slug])
    return Response(output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=passages_{site_slug}_{from_date}_{to_date}.csv'})

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
        mgr_site_id = session.get('site_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                if mgr_site_id:
                    cur.execute("SELECT slug FROM sites WHERE id=%s AND client_id=%s", [mgr_site_id, client_id])
                else:
                    cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                sites = cur.fetchall()
        slugs = [s['slug'] for s in sites]
        if not slugs:
            return "1=0", []
        if site_slug and site_slug in slugs:
            return "site_slug = %s", [site_slug]
        placeholders = ','.join(['%s'] * len(slugs))
        return f"site_slug IN ({placeholders})", slugs

# ========== DEVIS ==========

@app.route('/api/devis/save', methods=['POST'])
@login_required
def save_devis():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body JSON requis'}), 400
    import json as _json
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO devis (
                    numero, valid_until, prospect, contact, commercial,
                    nb_employes, salaire_moyen, mode_travail, jours_hybride,
                    posture, scenario, option_espace, surface_m2, nb_postes,
                    equipements, capex_total, cout_annuel, gain_annuel,
                    economie_nette, roi_pct, payback_mois,
                    taux_dysf, part_adressable, deco_pm2, im_pm2,
                    formation, animation, site_slug, client_id
                ) VALUES (
                    %(numero)s, %(valid_until)s, %(prospect)s, %(contact)s, %(commercial)s,
                    %(nb_employes)s, %(salaire_moyen)s, %(mode_travail)s, %(jours_hybride)s,
                    %(posture)s, %(scenario)s, %(option_espace)s, %(surface_m2)s, %(nb_postes)s,
                    %(equipements)s, %(capex_total)s, %(cout_annuel)s, %(gain_annuel)s,
                    %(economie_nette)s, %(roi_pct)s, %(payback_mois)s,
                    %(taux_dysf)s, %(part_adressable)s, %(deco_pm2)s, %(im_pm2)s,
                    %(formation)s, %(animation)s, %(site_slug)s, %(client_id)s
                ) RETURNING id
            """, {
                'numero': data.get('numero'), 'valid_until': data.get('valid_until'),
                'prospect': data.get('prospect'), 'contact': data.get('contact'),
                'commercial': data.get('commercial'), 'nb_employes': data.get('nb_employes'),
                'salaire_moyen': data.get('salaire_moyen'), 'mode_travail': data.get('mode_travail'),
                'jours_hybride': data.get('jours_hybride'), 'posture': data.get('posture'),
                'scenario': data.get('scenario'), 'option_espace': data.get('option_espace'),
                'surface_m2': data.get('surface_m2'), 'nb_postes': data.get('nb_postes'),
                'equipements': _json.dumps(data.get('equipements', [])),
                'capex_total': data.get('capex_total'), 'cout_annuel': data.get('cout_annuel'),
                'gain_annuel': data.get('gain_annuel'), 'economie_nette': data.get('economie_nette'),
                'roi_pct': data.get('roi_pct'), 'payback_mois': data.get('payback_mois'),
                'taux_dysf': data.get('taux_dysf'), 'part_adressable': data.get('part_adressable'),
                'deco_pm2': data.get('deco_pm2'), 'im_pm2': data.get('im_pm2'),
                'formation': data.get('formation'), 'animation': data.get('animation'),
                'site_slug': data.get('site_slug'), 'client_id': session.get('client_id'),
            })
            devis_id = cur.fetchone()['id']
        conn.commit()
    return jsonify({'ok': True, 'id': devis_id, 'numero': data.get('numero')}), 201

@app.route('/api/devis', methods=['GET'])
@login_required
def list_devis():
    role = session.get('role')
    client_id = session.get('client_id')
    with get_db() as conn:
        with conn.cursor() as cur:
            if role == 'admin':
                cur.execute("""
                    SELECT id, numero, created_at, valid_until, prospect, commercial,
                           nb_employes, capex_total, roi_pct, economie_nette, site_slug
                    FROM devis ORDER BY created_at DESC LIMIT 200
                """)
            else:
                cur.execute("""
                    SELECT id, numero, created_at, valid_until, prospect, commercial,
                           nb_employes, capex_total, roi_pct, economie_nette, site_slug
                    FROM devis WHERE client_id=%s ORDER BY created_at DESC LIMIT 100
                """, [client_id])
            rows = cur.fetchall()
    return jsonify([serialize_row(r) for r in rows])

@app.route('/api/devis/<int:devis_id>', methods=['GET'])
@login_required
def get_devis(devis_id):
    role = session.get('role')
    client_id = session.get('client_id')
    with get_db() as conn:
        with conn.cursor() as cur:
            if role == 'admin':
                cur.execute("SELECT * FROM devis WHERE id=%s", [devis_id])
            else:
                cur.execute("SELECT * FROM devis WHERE id=%s AND client_id=%s", [devis_id, client_id])
            row = cur.fetchone()
    if not row:
        return jsonify({'error': 'Devis introuvable'}), 404
    return jsonify(serialize_row(row))

# ========== STATS KIOSQUE ==========

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    period    = request.args.get('period', 'today')
    site_slug = request.args.get('site')
    date_clause = build_date_clause(period)
    site_clause, site_params = get_site_filter(site_slug)
    where = f"WHERE {date_clause} AND {site_clause}"

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

    if session.get('role') == 'admin':
        sp_clause = 'site_slug = %s' if site_slug else '1=1'
        sp_params = [site_slug] if site_slug else []
    else:
        sp_clause = f"site_slug IN ({','.join(['%s']*len(site_params))})" if site_params else '1=0'
        sp_params = list(site_params)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f'SELECT COUNT(*) as n FROM sessions {where}', site_params)
            total = cur.fetchone()['n']
            cur.execute(f'SELECT departement as label, COUNT(*) as n FROM sessions {where} GROUP BY departement ORDER BY n DESC', site_params)
            by_dept = cur.fetchall()
            cur.execute(f"""SELECT EXTRACT(HOUR FROM timestamp)::int as h, COUNT(*) as n
                FROM sensor_passages WHERE {ts_h} AND {sp_clause} GROUP BY h ORDER BY h""", sp_params)
            by_hour_raw = cur.fetchall()
            if not by_hour_raw:
                cur.execute(f"SELECT EXTRACT(HOUR FROM heure)::int as h, COUNT(*) as n FROM sessions {where} GROUP BY h ORDER BY h", site_params)
                by_hour_raw = cur.fetchall()
            cur.execute(f"SELECT mood, COUNT(*) as n FROM sessions {where} AND mood != '' GROUP BY mood ORDER BY n DESC", site_params)
            by_mood = cur.fetchall()
            cur.execute(f"SELECT date, COUNT(*) as n FROM sessions WHERE {build_date_clause(period)} AND {site_clause} GROUP BY date ORDER BY date", site_params)
            by_day = cur.fetchall()
            cur.execute(f"""SELECT atelier, COUNT(*) as nb_sessions, ROUND(AVG(duree_sec))::int as duree_moy_sec
                FROM sensor_sessions WHERE {ts_debut} AND {sp_clause} AND atelier IS NOT NULL
                GROUP BY atelier ORDER BY nb_sessions DESC""", sp_params)
            raw_sensor_at = cur.fetchall()
            cur.execute(f"SELECT ateliers FROM sessions {where} AND ateliers != ''", site_params)
            raw_at = cur.fetchall()
            cur.execute(f"""SELECT departement, mood, COUNT(*) as n FROM sessions {where} AND mood != '' AND departement != ''
                GROUP BY departement, mood ORDER BY departement, n DESC""", site_params)
            by_departement_mood = cur.fetchall()
            cur.execute(f"""SELECT ateliers as atelier_raw, mood, COUNT(*) as n FROM sessions {where} AND mood != '' AND ateliers != ''
                GROUP BY ateliers, mood ORDER BY ateliers, n DESC""", site_params)
            by_atelier_mood_raw = cur.fetchall()
            if session.get('role') == 'admin':
                cur.execute(f'SELECT site_slug, COUNT(*) as n FROM sessions {where} GROUP BY site_slug ORDER BY n DESC', site_params)
                by_site = cur.fetchall()
            else:
                by_site = []

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""SELECT departement, EXTRACT(HOUR FROM heure)::int as h, COUNT(*) as n
                FROM sessions {where} AND departement != '' GROUP BY departement, h ORDER BY departement, h""", site_params)
            by_departement_hour = cur.fetchall()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""SELECT atelier, EXTRACT(HOUR FROM debut)::int as h, COUNT(*) as n
                FROM sensor_sessions WHERE {ts_debut} AND {sp_clause} AND atelier IS NOT NULL
                GROUP BY atelier, h ORDER BY atelier, h""", sp_params)
            raw_at_hour_sensor = cur.fetchall()

    if raw_at_hour_sensor:
        by_atelier_hour = [serialize_row(r) for r in raw_at_hour_sensor]
    else:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""SELECT EXTRACT(HOUR FROM heure)::int as h, ateliers as atelier_raw, COUNT(*) as n
                    FROM sessions {where} AND ateliers != '' GROUP BY h, ateliers ORDER BY h""", site_params)
                raw_at_hour = cur.fetchall()
        atelier_hour = {}
        for row in raw_at_hour:
            h = row['h']; n = row['n']
            for a in (row['atelier_raw'] or '').split(', '):
                a = a.strip()
                if a:
                    atelier_hour[(a, h)] = atelier_hour.get((a, h), 0) + n
        by_atelier_hour = sorted(
            [{'atelier': k[0], 'h': k[1], 'n': v} for k, v in atelier_hour.items()],
            key=lambda x: (x['atelier'], x['h'])
        )

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""SELECT departement, ateliers as atelier_raw, COUNT(*) as n
                FROM sessions {where} AND ateliers != '' AND departement != ''
                GROUP BY departement, ateliers ORDER BY departement, n DESC""", site_params)
            raw_dept_at = cur.fetchall()

    dept_atelier = {}
    for row in raw_dept_at:
        dept = row['departement']; n = row['n']
        for a in (row['atelier_raw'] or '').split(', '):
            a = a.strip()
            if a:
                if dept not in dept_atelier: dept_atelier[dept] = {}
                dept_atelier[dept][a] = dept_atelier[dept].get(a, 0) + n
    by_departement_atelier = [
        {'departement': dept, 'atelier': atelier, 'n': n}
        for dept, ateliers in dept_atelier.items()
        for atelier, n in sorted(ateliers.items(), key=lambda x: -x[1])
    ]

    atelier_count = {}
    for row in raw_at:
        for a in (row['ateliers'] or '').split(', '):
            a = a.strip()
            if a: atelier_count[a] = atelier_count.get(a, 0) + 1
    by_atelier = sorted([{'atelier': k, 'n': v} for k, v in atelier_count.items()], key=lambda x: -x['n'])

    by_dept_k,  _ = kanon_filter([serialize_row(r) for r in by_dept], 'label')
    by_mood_k,  _ = kanon_filter([serialize_row(r) for r in by_mood], 'mood')
    by_dept_mood_k = kanon_filter_cross([serialize_row(r) for r in by_departement_mood], 'departement', 'mood')
    by_dept_hour_k = kanon_filter_cross([serialize_row(r) for r in by_departement_hour], 'departement', 'h')
    by_dept_at_k   = kanon_filter_cross(by_departement_atelier, 'departement', 'atelier')
    by_atelier_mood_k = kanon_filter_cross([serialize_row(r) for r in by_atelier_mood_raw], 'atelier_raw', 'mood')

    return jsonify({
        'period': period, 'total_seances': total,
        'by_departement': by_dept_k,
        'by_hour': [serialize_row(r) for r in by_hour_raw],
        'by_atelier': by_atelier,
        'by_mood': by_mood_k,
        'by_day': [serialize_row(r) for r in by_day],
        'by_site': [serialize_row(r) for r in by_site],
        'by_departement_mood': by_dept_mood_k,
        'by_departement_hour': by_dept_hour_k,
        'by_atelier_hour': by_atelier_hour,
        'by_departement_atelier': by_dept_at_k,
        'by_atelier_mood': by_atelier_mood_k,
        '_kanon_k': K_ANONYMAT,
    })

# ========== RAPPORT NARRATIF IA ==========

PERIODE_LABELS = {
    'today': "Aujourd'hui",
    'week':  '7 jours',
    'month': '30 jours',
    'ytd':   'Depuis janvier',
    'q1':    '1er trimestre',
    'q2':    '2e trimestre',
    'q3':    '3e trimestre',
    'q4':    '4e trimestre',
}

def _periode_clause_col(periode, col):
    if periode == 'today':  return f"{col} >= CURRENT_DATE AND {col} < CURRENT_DATE + INTERVAL '1 day'"
    if periode == 'week':   return f"{col} >= CURRENT_DATE - INTERVAL '7 days'"
    if periode == 'month':  return f"{col} >= CURRENT_DATE - INTERVAL '30 days'"
    if periode == 'ytd':    return f"{col} >= DATE_TRUNC('year', CURRENT_DATE)"
    if periode == 'q1':     return f"{col} >= DATE_TRUNC('year', CURRENT_DATE) AND {col} < DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '3 months'"
    if periode == 'q2':     return f"{col} >= DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '3 months' AND {col} < DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '6 months'"
    if periode == 'q3':     return f"{col} >= DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '6 months' AND {col} < DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '9 months'"
    if periode == 'q4':     return f"{col} >= DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '9 months'"
    return "1=1"

def _periode_prev_clause(periode, col):
    """Fenêtre précédente de même durée, pour comparaison."""
    if periode == 'today':  return f"{col} = CURRENT_DATE - 1"
    if periode == 'week':   return f"{col} >= CURRENT_DATE - INTERVAL '14 days' AND {col} < CURRENT_DATE - INTERVAL '7 days'"
    if periode == 'month':  return f"{col} >= CURRENT_DATE - INTERVAL '60 days' AND {col} < CURRENT_DATE - INTERVAL '30 days'"
    if periode == 'ytd':    return f"{col} >= DATE_TRUNC('year', CURRENT_DATE) - INTERVAL '1 year' AND {col} < CURRENT_DATE - INTERVAL '1 year'"
    if periode == 'q1':     return f"{col} >= DATE_TRUNC('year', CURRENT_DATE) - INTERVAL '3 months' AND {col} < DATE_TRUNC('year', CURRENT_DATE)"
    if periode == 'q2':     return f"{col} >= DATE_TRUNC('year', CURRENT_DATE) AND {col} < DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '3 months'"
    if periode == 'q3':     return f"{col} >= DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '3 months' AND {col} < DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '6 months'"
    if periode == 'q4':     return f"{col} >= DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '6 months' AND {col} < DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '9 months'"
    return "1=0"

@app.route('/api/dashboard/rapport-data', methods=['GET'])
@login_required
def dashboard_rapport_data():
    site_slug = request.args.get('site_slug', '') or None
    periode   = request.args.get('periode', 'month')
    if periode not in PERIODE_LABELS:
        periode = 'month'
    periode_label = PERIODE_LABELS[periode]

    date_clause = build_date_clause(periode)
    prev_clause = _periode_prev_clause(periode, 'date')
    site_clause, site_params = get_site_filter(site_slug)
    where = f"WHERE {date_clause} AND {site_clause}"

    total = 0
    by_dept = []
    by_mood = []
    by_hour = []
    by_week = []
    dept_mood_raw = []
    prev_total = 0
    atelier_count = {}
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(f'SELECT COUNT(*) AS n FROM sessions {where}', site_params)
                total = cur.fetchone()['n']
                cur.execute(f"SELECT departement AS label, COUNT(*) AS n FROM sessions {where} AND departement != '' GROUP BY departement ORDER BY n DESC LIMIT 8", site_params)
                by_dept = cur.fetchall()
                cur.execute(f"SELECT mood, COUNT(*) AS n FROM sessions {where} AND mood != '' GROUP BY mood ORDER BY n DESC", site_params)
                by_mood = cur.fetchall()
                cur.execute(f"SELECT EXTRACT(HOUR FROM heure)::int AS h, COUNT(*) AS n FROM sessions {where} GROUP BY h ORDER BY n DESC LIMIT 3", site_params)
                by_hour = cur.fetchall()
                cur.execute(f"SELECT TO_CHAR(DATE_TRUNC('week', date), 'DD/MM') AS semaine, COUNT(*) AS n FROM sessions {where} GROUP BY DATE_TRUNC('week', date) ORDER BY DATE_TRUNC('week', date)", site_params)
                by_week = cur.fetchall()
                cur.execute(f"SELECT departement, mood, COUNT(*) AS n FROM sessions {where} AND mood != '' AND departement != '' GROUP BY departement, mood ORDER BY departement, n DESC", site_params)
                dept_mood_raw = cur.fetchall()
                cur.execute(f"SELECT COUNT(*) AS n FROM sessions WHERE {prev_clause} AND {site_clause}", site_params)
                prev_total = cur.fetchone()['n']
                cur.execute(f"SELECT ateliers FROM sessions {where} AND ateliers != ''", site_params)
                for row in cur.fetchall():
                    for a in (row['ateliers'] or '').split(', '):
                        a = a.strip()
                        if a:
                            atelier_count[a] = atelier_count.get(a, 0) + 1
    except Exception as e:
        return jsonify({'ok': False, 'error': "Erreur d'agrégation des données : " + str(e)}), 500

    # ── Données Companion (incluses uniquement si présentes) ────────────────
    comp_created = _periode_clause_col(periode, 'created_at')
    comp_date    = _periode_clause_col(periode, 'date')
    comp = {'present': False, 'top_contenus': [], 'actifs': 0, 'checkins': 0,
            'energie': None, 'stress': None, 'focus': None, 'barometre': 0, 'retour_taux': None}
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT content_label, COUNT(*) AS n FROM companion_content_plays WHERE {comp_created} AND {site_clause} GROUP BY content_label ORDER BY n DESC LIMIT 5", site_params)
                comp['top_contenus'] = cur.fetchall()
                cur.execute(f"SELECT COUNT(*) AS n FROM companion_content_plays WHERE {comp_created} AND {site_clause} AND content_type = 'questionnaire'", site_params)
                comp['barometre'] = cur.fetchone()['n']
                cur.execute(f"SELECT COUNT(DISTINCT user_id) AS n FROM companion_points WHERE {comp_date} AND {site_clause} AND user_id IS NOT NULL", site_params)
                comp['actifs'] = cur.fetchone()['n']
                cur.execute(f"SELECT COUNT(*) AS n, ROUND(AVG(energie),1) AS e, ROUND(AVG(stress),1) AS s, ROUND(AVG(focus),1) AS f FROM companion_checkins WHERE {comp_date} AND {site_clause}", site_params)
                ck = cur.fetchone()
                comp['checkins'] = ck['n']
                comp['energie'], comp['stress'], comp['focus'] = ck['e'], ck['s'], ck['f']
                cur.execute(f"""SELECT COUNT(*) FILTER (WHERE jours > 1) AS retours, COUNT(*) AS tot FROM (
                                    SELECT user_id, COUNT(DISTINCT date) AS jours
                                    FROM companion_checkins
                                    WHERE {comp_date} AND {site_clause} AND user_id IS NOT NULL
                                    GROUP BY user_id) t""", site_params)
                rr = cur.fetchone()
                if rr['tot']:
                    comp['retour_taux'] = round(100.0 * rr['retours'] / rr['tot'])
        comp['present'] = bool(comp['top_contenus'] or comp['actifs'] or comp['checkins'] or comp['barometre'])
    except Exception:
        comp = {'present': False}

    if not total and not comp.get('present'):
        return jsonify({
            'ok': True,
            'periode_label': periode_label,
            'total_seances': 0,
            'rapport': f"Aucune donnée d'activité (espace physique ni application Companion) n'a été "
                       f"enregistrée sur la période analysée ({periode_label}). Dès que des collaborateurs "
                       "utiliseront l'espace beOtop, leur activité alimentera automatiquement ce rapport.",
        })

    top_ateliers = sorted(atelier_count.items(), key=lambda x: -x[1])[:6]
    dept_mood_k = kanon_filter_cross([serialize_row(r) for r in dept_mood_raw], 'departement', 'mood')
    dom = {}
    for r in dept_mood_k:
        dom.setdefault(r['departement'], []).append(f"{r['mood']} ({r['n']})")

    # Chiffres clés uniquement (pas de listes complètes) pour limiter le coût API
    top_dept    = by_dept[0] if by_dept else None
    top_atelier = top_ateliers[0] if top_ateliers else None
    top_mood    = by_mood[0] if by_mood else None
    top_hour    = by_hour[0] if by_hour else None

    lignes = [
        f"Site : {site_slug or 'tous les sites'}",
        f"Période : {periode_label}",
        f"Séances enregistrées : {total}",
    ]
    if prev_total:
        pct = round(100.0 * (total - prev_total) / prev_total)
        lignes.append(f"Évolution vs période précédente (même durée) : {pct:+d}%")
    if top_dept:
        lignes.append(f"Département le plus actif : {top_dept['label']} ({top_dept['n']})")
    if top_atelier:
        lignes.append(f"Atelier phare : {top_atelier[0]} ({top_atelier[1]})")
    if top_mood:
        lignes.append(f"Ressenti dominant : {top_mood['mood']} ({top_mood['n']})")
    if top_hour:
        lignes.append(f"Créneau de pointe : {top_hour['h']}h ({top_hour['n']})")
    if comp.get('present'):
        cps = []
        if comp.get('actifs'):
            cps.append(f"{comp['actifs']} utilisateurs actifs")
        if comp.get('top_contenus'):
            cps.append(f"top contenu {comp['top_contenus'][0]['content_label']} ({comp['top_contenus'][0]['n']})")
        if comp.get('retour_taux') is not None:
            cps.append(f"taux de retour {comp['retour_taux']}%")
        if comp.get('barometre'):
            cps.append(f"{comp['barometre']} baromètres complétés")
        if cps:
            lignes.append("Companion : " + " ; ".join(cps))

    data_str = "\n".join(lignes)

    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        return jsonify({'ok': False, 'error': "Clé API IA non configurée sur le serveur (variable ANTHROPIC_API_KEY)."}), 500
    try:
        import anthropic
    except ImportError:
        return jsonify({'ok': False, 'error': "Bibliothèque 'anthropic' non installée sur le serveur (pip install anthropic)."}), 500

    system_prompt = (
        "Tu es consultant QVCT senior pour beOtop ; tu conseilles la DRH et la CSSCT. "
        "À partir des chiffres clés fournis, rédige en français une synthèse stratégique "
        "CONCISE (300 à 400 mots maximum). Interprète les chiffres (sens et implications "
        "pour l'organisation) au lieu de seulement les répéter, et n'invente aucune donnée. "
        "Structure, en texte simple sans markdown : un court paragraphe de synthèse ; "
        "un paragraphe « Points de vigilance » ; un paragraphe « Recommandations prioritaires » "
        "(2 à 3 actions concrètes, chacune avec un responsable suggéré : DRH, manager de "
        "proximité, CSSCT ou référent QVCT) ; une phrase de projection sur le trimestre suivant. "
        "Si des données Companion sont fournies, intègre brièvement l'engagement digital. "
        "Réfère-toi aux repères ANACT uniquement si pertinent. Paragraphes séparés par une "
        "ligne vide ; aucun symbole markdown."
    )
    user_prompt = (
        "Chiffres clés d'utilisation de l'espace beOtop sur la période « " + periode_label
        + " » :\n\n" + data_str + "\n\nRédige la synthèse stratégique demandée."
    )
    try:
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=800,
            thinking={"type": "disabled"},
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        rapport = "".join(b.text for b in msg.content if b.type == "text").strip()
    except Exception as e:
        return jsonify({'ok': False, 'error': "Erreur lors de l'appel à l'IA : " + str(e)}), 502

    return jsonify({
        'ok': True,
        'rapport': rapport,
        'periode_label': periode_label,
        'total_seances': total,
        'companion': comp.get('present', False),
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
                [from_date, to_date] + params)
            rows = cur.fetchall()
    from collections import Counter
    dept_counts = Counter(serialize_row(r)['departement'] for r in rows)
    rows_kanon  = [r for r in rows if dept_counts.get(serialize_row(r)['departement'], 0) >= K_ANONYMAT]
    filtered    = len(rows) - len(rows_kanon)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['# Export DUERP beOtop — Données agrégées et anonymisées'])
    writer.writerow([f'# K-anonymat k≥{K_ANONYMAT} appliqué — {filtered} enregistrements filtrés'])
    writer.writerow([f'# Période : {from_date} → {to_date} — Généré le {date.today().isoformat()}'])
    writer.writerow(["# Conformité RGPD Art. 89 — Finalité : mesure d'impact QVCT (DUERP)"])
    writer.writerow([])
    writer.writerow(['date', 'heure', 'departement', 'ateliers', 'mood', 'site'])
    for r in rows_kanon:
        sr = serialize_row(r)
        writer.writerow([sr['date'], sr['heure'], sr['departement'], sr['ateliers'], sr['mood'], sr['site_slug']])
    return Response(output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=beotop_{from_date}_{to_date}.csv'})

# ========== CLIENT - SES SITES ==========

@app.route('/api/client/sites', methods=['GET'])
@login_required
def client_get_sites():
    # Mode demo : n'exposer que le site vitrine demo-beotop.
    if session.get('role') == 'demo':
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM sites WHERE slug='demo-beotop'")
                sites = cur.fetchall()
        return jsonify([serialize_row(s) for s in sites])
    client_id = session.get('client_id')
    if not client_id and session.get('role') != 'admin':
        return jsonify([])
    with get_db() as conn:
        with conn.cursor() as cur:
            if session.get('role') == 'admin':
                cur.execute("SELECT s.*, c.nom as client_nom FROM sites s JOIN clients c ON s.client_id=c.id ORDER BY c.nom, s.nom")
            elif session.get('site_id'):
                cur.execute("SELECT * FROM sites WHERE id=%s AND client_id=%s AND actif=1 ORDER BY nom", [session.get('site_id'), client_id])
            else:
                cur.execute("SELECT * FROM sites WHERE client_id=%s AND actif=1 ORDER BY nom", [client_id])
            sites = cur.fetchall()
    return jsonify([serialize_row(s) for s in sites])

@app.route('/api/client/sites/<site_slug>/effectif', methods=['PATCH'])
@login_required
def client_update_effectif(site_slug):
    data = request.get_json()
    nb = data.get('nb_salaries')
    if nb is None or int(nb) < 0:
        return jsonify({'error': 'nb_salaries requis et doit être >= 0'}), 400
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM sites WHERE slug=%s AND client_id=%s AND actif=1", [site_slug, client_id])
                site = cur.fetchone()
        if not site:
            return jsonify({'error': 'Site introuvable ou accès refusé'}), 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE sites SET nb_salaries=%s WHERE slug=%s", [int(nb), site_slug])
            if cur.rowcount == 0:
                return jsonify({'error': 'Site introuvable'}), 404
            conn.commit()
    return jsonify({'ok': True, 'site_slug': site_slug, 'nb_salaries': int(nb)})

@app.route('/api/client/stats/consolidated', methods=['GET'])
@login_required
def client_stats_consolidated():
    """Stats agrégées sur tous les sites du client (ou d'un client ciblé pour admin)."""
    role = session.get('role')
    period = request.args.get('period', 'month')

    if role == 'admin':
        client_id = request.args.get('client_id')
        if not client_id:
            return jsonify({'error': 'client_id requis pour un admin'}), 400
        try:
            client_id = int(client_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'client_id invalide'}), 400
    else:
        client_id = session.get('client_id')
        if not client_id:
            return jsonify({'error': 'Aucun client associé à ce compte'}), 403

    period_clauses = {
        'today': "se.created_at >= CURRENT_DATE",
        'week':  "se.created_at >= NOW() - INTERVAL '7 days'",
        'month': "se.created_at >= NOW() - INTERVAL '30 days'",
        'ytd':   "se.created_at >= DATE_TRUNC('year', CURRENT_DATE)",
    }
    ts_clause = period_clauses.get(period, period_clauses['month'])

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT
                    si.id, si.nom, si.slug, si.ville, si.nb_salaries,
                    COUNT(se.id)                                                   AS nb_seances,
                    ROUND(100.0 * COUNT(
                        CASE WHEN se.mood IN ('Rechargé','Mieux') THEN 1 END
                    ) / NULLIF(COUNT(se.id), 0), 1)                                AS taux_recuperation
                FROM sites si
                LEFT JOIN sessions se
                    ON se.site_id = si.id AND {ts_clause}
                WHERE si.client_id = %s AND si.actif = 1
                GROUP BY si.id, si.nom, si.slug, si.ville, si.nb_salaries
                ORDER BY nb_seances DESC
            """, [client_id])
            rows = cur.fetchall()

            cur.execute(f"""
                SELECT
                    COUNT(se.id)                                                   AS nb_seances,
                    ROUND(100.0 * COUNT(
                        CASE WHEN se.mood IN ('Rechargé','Mieux') THEN 1 END
                    ) / NULLIF(COUNT(se.id), 0), 1)                                AS taux_recuperation
                FROM sites si
                LEFT JOIN sessions se
                    ON se.site_id = si.id AND {ts_clause}
                WHERE si.client_id = %s AND si.actif = 1
            """, [client_id])
            totaux_row = cur.fetchone()

    return jsonify({
        'client_id': client_id,
        'period':    period,
        'sites':     [serialize_row(r) for r in rows],
        'totaux': {
            'nb_sites':          len(rows),
            'nb_seances':        totaux_row['nb_seances']        or 0,
            'taux_recuperation': totaux_row['taux_recuperation'] or 0,
        }
    })

# ========== RÉSERVATIONS ==========

@app.route('/api/reservations', methods=['GET'])
@login_required
def get_reservations():
    site_slug = request.args.get('site_slug')
    date_str  = request.args.get('date', date.today().isoformat())
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        mgr_site_id = session.get('site_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                if mgr_site_id:
                    cur.execute("SELECT slug FROM sites WHERE id=%s AND client_id=%s", [mgr_site_id, client_id])
                else:
                    cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                slugs = [r['slug'] for r in cur.fetchall()]
        if site_slug not in slugs:
            return jsonify({'error': 'Accès refusé'}), 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, atelier, date::text as date,
                       heure_debut::text as heure_debut,
                       (heure_debut + (duree_min || ' minutes')::INTERVAL)::time::text as heure_fin,
                       duree_min, statut
                FROM reservations
                WHERE site_slug=%s AND date=%s AND statut != 'annulee'
                ORDER BY heure_debut, atelier
            """, [site_slug, date_str])
            rows = cur.fetchall()
    return jsonify([serialize_row(r) for r in rows])


@app.route('/api/reservations', methods=['POST'])
@login_required
def create_reservation():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body JSON requis'}), 400
    site_slug   = data.get('site_slug')
    atelier     = data.get('atelier')
    date_str    = data.get('date', date.today().isoformat())
    heure_debut = data.get('heure_debut')
    duree_min   = int(data.get('duree_min', 20))
    if not all([site_slug, atelier, heure_debut]):
        return jsonify({'error': 'site_slug, atelier, heure_debut requis'}), 400
    if duree_min not in [10, 15, 20, 30]:
        return jsonify({'error': 'duree_min doit être 10, 15 ou 20'}), 400
    # Vérifier accès
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        mgr_site_id = session.get('site_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                if mgr_site_id:
                    cur.execute("SELECT slug FROM sites WHERE id=%s AND client_id=%s", [mgr_site_id, client_id])
                else:
                    cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                slugs = [r['slug'] for r in cur.fetchall()]
        if site_slug not in slugs:
            return jsonify({'error': 'Accès refusé'}), 403
    # Vérifier conflit (même atelier, même créneau)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id FROM reservations
                WHERE site_slug=%s AND atelier=%s AND date=%s AND statut != 'annulee'
                AND heure_debut < (%s::time + (%s || ' minutes')::INTERVAL)
                AND (heure_debut + (duree_min || ' minutes')::INTERVAL) > %s::time
            """, [site_slug, atelier, date_str, heure_debut, duree_min, heure_debut])
            conflict = cur.fetchone()
    if conflict:
        return jsonify({'error': 'Créneau déjà réservé pour cet atelier'}), 409
    user_id  = session.get('user_id')
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO reservations
                    (site_slug, atelier, user_id, date, heure_debut, duree_min, statut)
                VALUES (%s, %s, %s, %s, %s, %s, 'confirmee')
                RETURNING id
            """, [site_slug, atelier, user_id, date_str, heure_debut, duree_min])
            new_id = cur.fetchone()['id']
            conn.commit()
    user_id_pts = session.get('user_id')
    award_points(user_id_pts, 'reservation', f'Réservation · {atelier}', site_slug)
    return jsonify({'ok': True, 'id': new_id}), 201


@app.route('/api/reservations/<int:res_id>', methods=['DELETE'])
@login_required
def cancel_reservation(res_id):
    user_id = session.get('user_id')
    role    = session.get('role')
    with get_db() as conn:
        with conn.cursor() as cur:
            if role == 'admin':
                cur.execute("UPDATE reservations SET statut='annulee' WHERE id=%s", [res_id])
            else:
                cur.execute(
                    "UPDATE reservations SET statut='annulee' WHERE id=%s AND user_id=%s",
                    [res_id, user_id])
            if cur.rowcount == 0:
                return jsonify({'error': 'Réservation introuvable ou accès refusé'}), 404
            conn.commit()
    return jsonify({'ok': True})


# ========== COMPANION — CHECK-IN & COHÉRENCE CARDIAQUE ==========

@app.route('/api/companion/checkin', methods=['POST'])
@login_required
def companion_save_checkin():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body JSON requis'}), 400
    energie = int(data.get('energie', 0))
    stress  = int(data.get('stress', 0))
    focus   = int(data.get('focus', 0))
    if not all(1 <= v <= 10 for v in [energie, stress, focus]):
        return jsonify({'error': 'Valeurs entre 1 et 10 requises'}), 400
    user_id   = session.get('user_id')
    site_slug = data.get('site_slug')
    with get_db() as conn:
        with conn.cursor() as cur:
            # Un seul check-in par jour et par user
            cur.execute("""
                INSERT INTO companion_checkins (user_id, site_slug, date, energie, stress, focus)
                VALUES (%s, %s, CURRENT_DATE, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING id
            """, [user_id, site_slug, energie, stress, focus])
            row = cur.fetchone()
            if not row:
                # Mise à jour si déjà fait aujourd'hui
                cur.execute("""
                    UPDATE companion_checkins
                    SET energie=%s, stress=%s, focus=%s, created_at=CURRENT_TIMESTAMP
                    WHERE user_id=%s AND date=CURRENT_DATE
                    RETURNING id
                """, [energie, stress, focus, user_id])
                row = cur.fetchone()
            conn.commit()
    pts = award_points(user_id, 'checkin', 'Check-in quotidien', site_slug)
    return jsonify({'ok': True, 'id': row['id'] if row else None, 'points': pts}), 201


@app.route('/api/companion/checkin/history', methods=['GET'])
@login_required
def companion_checkin_history():
    user_id = session.get('user_id')
    periode = request.args.get('periode', 'mois')
    from datetime import date as dt, timedelta
    today = dt.today()
    if periode == 'semaine':
        date_debut = today - timedelta(days=today.weekday())
    elif periode == 'annee':
        date_debut = dt(today.year, 1, 1)
    else:
        date_debut = dt(today.year, today.month, 1)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT date::text, energie, stress, focus
                FROM companion_checkins
                WHERE user_id=%s AND date >= %s
                ORDER BY date ASC
                """,
                [user_id, date_debut.isoformat()])
            rows = cur.fetchall()
    return jsonify([serialize_row(r) for r in rows])


@app.route('/api/companion/cc', methods=['POST'])
@login_required
def companion_save_cc():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body JSON requis'}), 400
    duree_min = int(data.get('duree_min', 5))
    if duree_min < 1 or duree_min > 60:
        return jsonify({'error': 'duree_min entre 1 et 60'}), 400
    user_id   = session.get('user_id')
    site_slug = data.get('site_slug')
    protocole = data.get('protocole', '365')
    complete  = bool(data.get('complete', True))
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO companion_cc_sessions
                    (user_id, site_slug, date, protocole, duree_min, complete)
                VALUES (%s, %s, CURRENT_DATE, %s, %s, %s)
                RETURNING id
            """, [user_id, site_slug, protocole, duree_min, complete])
            new_id = cur.fetchone()['id']
            conn.commit()
    pts = award_points(user_id, 'cc', f'Cohérence cardiaque · {protocole}', site_slug)
    return jsonify({'ok': True, 'id': new_id, 'points': pts}), 201


@app.route('/api/companion/cc/history', methods=['GET'])
@login_required
def companion_cc_history():
    user_id = session.get('user_id')
    limit   = int(request.args.get('limit', 30))
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT date::text, protocole, duree_min, complete, created_at
                FROM companion_cc_sessions
                WHERE user_id=%s
                ORDER BY date DESC
                LIMIT %s
            """, [user_id, limit])
            rows = cur.fetchall()
    return jsonify([serialize_row(r) for r in rows])


@app.route('/api/companion/stats', methods=['GET'])
@login_required
def companion_stats():
    """KPIs mensuels pour l'onglet Companion du dashboard."""
    user_id = session.get('user_id')
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    COUNT(*) as nb_checkins,
                    ROUND(AVG(energie), 1) as avg_energie,
                    ROUND(AVG(stress), 1)  as avg_stress,
                    ROUND(AVG(focus), 1)   as avg_focus
                FROM companion_checkins
                WHERE user_id=%s AND date >= DATE_TRUNC('month', CURRENT_DATE)
            """, [user_id])
            checkins = serialize_row(cur.fetchone())
            cur.execute("""
                SELECT
                    COUNT(*) as nb_sessions,
                    COALESCE(SUM(duree_min), 0) as total_minutes,
                    COUNT(*) FILTER (WHERE complete) as nb_completes
                FROM companion_cc_sessions
                WHERE user_id=%s AND date >= DATE_TRUNC('month', CURRENT_DATE)
            """, [user_id])
            cc = serialize_row(cur.fetchone())
            # Streak : jours consécutifs avec au moins une activité
            cur.execute("""
                SELECT date::text FROM (
                    SELECT date FROM companion_checkins WHERE user_id=%s
                    UNION
                    SELECT date FROM companion_cc_sessions WHERE user_id=%s
                ) t ORDER BY date DESC LIMIT 60
            """, [user_id, user_id])
            dates = [r['date'] for r in cur.fetchall()]
    streak = 0
    if dates:
        from datetime import date as dt, timedelta
        today = dt.today()
        cur_date = today
        for d_str in dates:
            d = dt.fromisoformat(d_str)
            if d == cur_date or d == cur_date - timedelta(days=1):
                streak += 1
                cur_date = d
            else:
                break
    return jsonify({
        'checkins': checkins,
        'cc': cc,
        'streak_jours': streak,
    })



# ========== GAMIFICATION POINTS ==========

# Barème
POINTS_BAREME = {
    'checkin':      10,
    'cc':           20,
    'audio':        15,
    'exercice':     15,
    'jeu':          10,
    'reservation':  25,
    'sons':         10,
    'video':        15,
    'podcast':      15,
}

# Niveaux
NIVEAUX = [
    { 'seuil':    0, 'label': 'Débutant',    'emoji': '🌱' },
    { 'seuil':  100, 'label': 'Actif',        'emoji': '🌿' },
    { 'seuil':  300, 'label': 'Régulier',     'emoji': '💪' },
    { 'seuil':  600, 'label': 'Engagé',       'emoji': '🌟' },
    { 'seuil': 1000, 'label': 'Expert',       'emoji': '🏆' },
    { 'seuil': 1500, 'label': 'Ambassadeur',  'emoji': '💎' },
]

def get_niveau(total_pts):
    niveau = NIVEAUX[0]
    for n in NIVEAUX:
        if total_pts >= n['seuil']:
            niveau = n
    idx = NIVEAUX.index(niveau)
    next_n = NIVEAUX[idx + 1] if idx + 1 < len(NIVEAUX) else None
    pts_dans_niveau = total_pts - niveau['seuil']
    pts_prochain    = (next_n['seuil'] - niveau['seuil']) if next_n else None
    pct = int(pts_dans_niveau / pts_prochain * 100) if pts_prochain else 100
    return {
        'niveau':         niveau,
        'next':           next_n,
        'pts_dans_niveau': pts_dans_niveau,
        'pts_prochain':   pts_prochain,
        'pct':            pct,
    }


def award_points(user_id, action, label, site_slug=None):
    """Attribuer des points et retourner le nombre de points ajoutés."""
    pts = POINTS_BAREME.get(action, 0)
    if pts <= 0:
        return 0
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO companion_points (user_id, site_slug, action, label, points)
                    VALUES (%s, %s, %s, %s, %s)
                """, [user_id, site_slug, action, label, pts])
                conn.commit()
    except Exception as e:
        print(f">>> award_points error: {e}", file=sys.stderr)
    return pts


@app.route('/api/companion/points', methods=['POST'])
@login_required
def add_points():
    """Route générique pour attribuer des points depuis le front."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body JSON requis'}), 400
    action    = data.get('action')
    label     = data.get('label', action)
    site_slug = data.get('site_slug')
    if action not in POINTS_BAREME:
        return jsonify({'error': f'Action inconnue : {action}'}), 400
    user_id = session.get('user_id')
    pts = award_points(user_id, action, label, site_slug)
    return jsonify({'ok': True, 'points': pts}), 201


@app.route('/api/companion/scores', methods=['GET'])
@login_required
def get_scores():
    """KPIs gamification : total, niveau, historique 30 jours, classement."""
    user_id   = session.get('user_id')
    site_slug = request.args.get('site_slug')

    with get_db() as conn:
        with conn.cursor() as cur:
            # Total tous temps
            cur.execute("""
                SELECT COALESCE(SUM(points), 0) as total
                FROM companion_points WHERE user_id=%s
            """, [user_id])
            total = cur.fetchone()['total']

            # Points ce mois
            cur.execute("""
                SELECT COALESCE(SUM(points), 0) as mois
                FROM companion_points
                WHERE user_id=%s AND date >= DATE_TRUNC('month', CURRENT_DATE)
            """, [user_id])
            mois = cur.fetchone()['mois']

            # Points cette semaine
            cur.execute("""
                SELECT COALESCE(SUM(points), 0) as semaine
                FROM companion_points
                WHERE user_id=%s AND date >= DATE_TRUNC('week', CURRENT_DATE)
            """, [user_id])
            semaine = cur.fetchone()['semaine']

            # Historique 30 dernières actions
            cur.execute("""
                SELECT action, label, points, date::text, created_at
                FROM companion_points
                WHERE user_id=%s
                ORDER BY created_at DESC LIMIT 30
            """, [user_id])
            historique = [serialize_row(r) for r in cur.fetchall()]

            # Répartition par action (ce mois)
            cur.execute("""
                SELECT action, COUNT(*) as nb, SUM(points) as pts
                FROM companion_points
                WHERE user_id=%s AND date >= DATE_TRUNC('month', CURRENT_DATE)
                GROUP BY action ORDER BY pts DESC
            """, [user_id])
            repartition = [serialize_row(r) for r in cur.fetchall()]

            # Streak (jours consécutifs avec au moins 1 action)
            cur.execute("""
                SELECT DISTINCT date::text FROM companion_points
                WHERE user_id=%s ORDER BY date DESC LIMIT 60
            """, [user_id])
            dates = [r['date'] for r in cur.fetchall()]

    streak = 0
    if dates:
        from datetime import date as dt, timedelta
        today = dt.today()
        cur_d = today
        for d_str in dates:
            d = dt.fromisoformat(d_str)
            if d == cur_d or d == cur_d - timedelta(days=1):
                streak += 1
                cur_d = d
            else:
                break

    niveau_info = get_niveau(int(total))

    return jsonify({
        'total':        int(total),
        'mois':         int(mois),
        'semaine':      int(semaine),
        'streak':       streak,
        'niveau':       niveau_info['niveau'],
        'next_niveau':  niveau_info['next'],
        'pct_niveau':   niveau_info['pct'],
        'pts_restants': niveau_info['pts_prochain'],
        'historique':   historique,
        'repartition':  repartition,
    })



# ========== LIVRE D'OR ==========

@app.route('/api/companion/livreor', methods=['GET'])
@login_required
def livreor_get():
    """Lire les témoignages du livre d'or (partagés entre tous les users du site)"""
    site_slug = request.args.get('site_slug')
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS companion_livreor (
                    id          SERIAL PRIMARY KEY,
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    site_slug   TEXT,
                    prenom      TEXT,
                    texte       TEXT NOT NULL
                )
            """)
            conn.commit()
            if site_slug:
                cur.execute("""
                    SELECT id, created_at, prenom, texte
                    FROM companion_livreor
                    WHERE site_slug = %s
                    ORDER BY created_at DESC
                    LIMIT 100
                """, [site_slug])
            else:
                cur.execute("""
                    SELECT id, created_at, prenom, texte
                    FROM companion_livreor
                    ORDER BY created_at DESC
                    LIMIT 100
                """)
            rows = cur.fetchall()
    return jsonify([serialize_row(r) for r in rows])


@app.route('/api/companion/livreor', methods=['POST'])
@login_required
def livreor_post():
    """Publier un témoignage dans le livre d'or"""
    data = request.get_json() or {}
    texte = (data.get('texte') or '').strip()
    if len(texte) < 10:
        return jsonify({'error': 'Minimum 10 caractères'}), 400
    if len(texte) > 500:
        return jsonify({'error': 'Maximum 500 caractères'}), 400

    user_id   = session.get('user_id')
    site_slug = data.get('site_slug')

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT nom FROM users WHERE id=%s", [user_id])
            user = cur.fetchone()
            prenom = ''
            if user and user['nom']:
                prenom = user['nom'].strip().split()[0]
            cur.execute("""
                CREATE TABLE IF NOT EXISTS companion_livreor (
                    id          SERIAL PRIMARY KEY,
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    site_slug   TEXT,
                    prenom      TEXT,
                    texte       TEXT NOT NULL
                )
            """)
            cur.execute("""
                INSERT INTO companion_livreor (user_id, site_slug, prenom, texte)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, [user_id, site_slug, prenom, texte])
            new_id = cur.fetchone()['id']
            conn.commit()

    return jsonify({'ok': True, 'id': new_id}), 201


# ========== COMPANION — TRACKING LECTURES (rétribution intervenants) ==========

@app.route('/api/companion/play', methods=['POST'])
@login_required
def companion_log_play():
    """
    Enregistre un clic de lecture et la durée d'écoute pour un contenu.
    Appelé par le front à l'ouverture (duree_sec=0) puis à la fermeture (duree_sec réelle).
    """
    data = request.get_json() or {}
    content_type    = data.get('content_type', '')
    content_label   = data.get('content_label', '')
    intervenant_nom = data.get('intervenant_nom', '') or ''
    intervenant_id  = data.get('intervenant_id')
    duree_sec       = int(data.get('duree_sec', 0))
    site_slug       = data.get('site_slug', '')
    user_id         = session.get('user_id')

    if not content_type or not content_label:
        return jsonify({'error': 'content_type et content_label requis'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO companion_content_plays
                    (site_slug, user_id, content_type, content_label, intervenant_id, intervenant_nom, duree_sec)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, [site_slug, user_id, content_type, content_label,
                  intervenant_id, intervenant_nom, duree_sec])
            new_id = cur.fetchone()['id']
            conn.commit()
    return jsonify({'ok': True, 'id': new_id}), 201


# ========== COMPANION — CONTENUS AJOUTÉS PAR LES INTERVENANTS ==========

CONTENU_TYPES = ('audio', 'video', 'exercice', 'defi', 'podcast')


def _resolve_intervenant():
    """Retourne (id, nom) de l'intervenant lié à l'utilisateur connecté, sinon (None, None)."""
    uid = session.get('user_id')
    if not uid:
        return None, None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, nom FROM intervenants WHERE user_id=%s ORDER BY id LIMIT 1",
                [uid]
            )
            row = cur.fetchone()
    return (row['id'], row['nom']) if row else (None, None)


def _row_to_contenu(row):
    """Aplati une ligne SQL en objet contenu pour le front."""
    data = row.get('data') or {}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}
    item = dict(data)
    item['db_id']           = row['id']
    item['type']            = row['type']
    item['titre']           = row['titre']
    item['intervenant']     = row.get('intervenant_nom') or item.get('intervenant') or ''
    item['intervenant_nom'] = row.get('intervenant_nom') or ''
    item['actif']           = row.get('actif', True)
    return item


@app.route('/api/companion/contenus', methods=['GET'])
@login_required
def companion_contenus_list():
    """Liste les contenus ajoutés par les intervenants (visibles par tous les connectés)."""
    type_filter = request.args.get('type')
    with get_db() as conn:
        with conn.cursor() as cur:
            if type_filter:
                cur.execute(
                    "SELECT * FROM companion_contenus WHERE actif=TRUE AND type=%s ORDER BY id",
                    [type_filter]
                )
            else:
                cur.execute("SELECT * FROM companion_contenus WHERE actif=TRUE ORDER BY id")
            rows = cur.fetchall()
    return jsonify({'contenus': [_row_to_contenu(r) for r in rows]})


@app.route('/api/companion/contenus', methods=['POST'])
@intervenant_required
def companion_contenus_create():
    """Crée un contenu, rattaché à l'intervenant connecté."""
    body = request.get_json() or {}
    ctype = (body.get('type') or '').strip()
    item  = body.get('item') or {}
    titre = (item.get('titre') or '').strip()
    if ctype not in CONTENU_TYPES:
        return jsonify({'error': 'Type de contenu invalide'}), 400
    if not titre:
        return jsonify({'error': 'Titre requis'}), 400

    inv_id, inv_nom = _resolve_intervenant()
    # Admin sans fiche intervenant : on garde le nom choisi dans le formulaire
    if not inv_nom:
        inv_nom = (item.get('intervenant') or '').strip()

    # On ne stocke pas les champs de contrôle dans data
    clean = {k: v for k, v in item.items() if k not in ('db_id',)}

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO companion_contenus (type, titre, intervenant_id, intervenant_nom, actif, data)
                VALUES (%s, %s, %s, %s, TRUE, %s::jsonb)
                RETURNING *
            """, [ctype, titre, inv_id, inv_nom, json.dumps(clean)])
            row = cur.fetchone()
            conn.commit()
    return jsonify(_row_to_contenu(row)), 201


@app.route('/api/companion/contenus/<int:cid>', methods=['PUT'])
@intervenant_required
def companion_contenus_update(cid):
    """Modifie un contenu (propriétaire ou admin)."""
    body = request.get_json() or {}
    item = body.get('item') or {}
    titre = (item.get('titre') or '').strip()
    if not titre:
        return jsonify({'error': 'Titre requis'}), 400

    inv_id, _ = _resolve_intervenant()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT intervenant_id FROM companion_contenus WHERE id=%s", [cid])
            row = cur.fetchone()
            if not row:
                return jsonify({'error': 'Contenu introuvable'}), 404
            if session.get('role') != 'admin' and row['intervenant_id'] != inv_id:
                return jsonify({'error': 'Accès refusé'}), 403
            clean = {k: v for k, v in item.items() if k not in ('db_id',)}
            actif = item.get('actif', True)
            cur.execute("""
                UPDATE companion_contenus
                SET titre=%s, actif=%s, data=%s::jsonb
                WHERE id=%s
                RETURNING *
            """, [titre, bool(actif), json.dumps(clean), cid])
            updated = cur.fetchone()
            conn.commit()
    return jsonify(_row_to_contenu(updated))


@app.route('/api/companion/contenus/<int:cid>', methods=['DELETE'])
@intervenant_required
def companion_contenus_delete(cid):
    """Supprime un contenu (propriétaire ou admin)."""
    inv_id, _ = _resolve_intervenant()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT intervenant_id FROM companion_contenus WHERE id=%s", [cid])
            row = cur.fetchone()
            if not row:
                return jsonify({'error': 'Contenu introuvable'}), 404
            if session.get('role') != 'admin' and row['intervenant_id'] != inv_id:
                return jsonify({'error': 'Accès refusé'}), 403
            cur.execute("DELETE FROM companion_contenus WHERE id=%s", [cid])
            conn.commit()
    return jsonify({'ok': True})


def _cint_to_dict(row):
    tags = row.get('tags')
    if isinstance(tags, str) and tags.strip():
        try:
            tags = json.loads(tags)
        except Exception:
            tags = [t.strip() for t in tags.split(',') if t.strip()]
    if not isinstance(tags, list):
        tags = []
    return {
        'id': row['id'], 'site_slug': row.get('site_slug'),
        'nom': row.get('nom'), 'specialite': row.get('specialite'),
        'bio': row.get('bio'), 'photo': row.get('photo'),
        'photo_url': row.get('photo_url'), 'titre': row.get('titre'),
        'site_url': row.get('site_url'), 'linkedin_url': row.get('linkedin_url'),
        'tags': tags, 'actif': row.get('actif', True)
    }


def _cint_tags_str(value):
    if isinstance(value, list):
        return json.dumps(value)
    return value or ''


@app.route('/api/companion/intervenants', methods=['GET'])
@login_required
def companion_intervenants_list():
    """Liste les intervenants actifs (table companion_intervenants)."""
    site_slug = request.args.get('site_slug')
    with get_db() as conn:
        with conn.cursor() as cur:
            if site_slug:
                cur.execute("""
                    SELECT * FROM companion_intervenants
                    WHERE actif = TRUE AND (COALESCE(site_slug,'') = %s OR COALESCE(site_slug,'') = '')
                    ORDER BY id
                """, [site_slug])
            else:
                cur.execute("SELECT * FROM companion_intervenants WHERE actif = TRUE ORDER BY id")
            rows = cur.fetchall()
    return jsonify({'intervenants': [_cint_to_dict(r) for r in rows]})


@app.route('/api/companion/intervenants', methods=['POST'])
@login_required
def companion_intervenants_create():
    data = request.get_json() or {}
    nom = (data.get('nom') or '').strip()
    if not nom:
        return jsonify({'error': 'Nom requis'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO companion_intervenants
                    (site_slug, nom, specialite, bio, photo, photo_url, titre, site_url, linkedin_url, tags, actif)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,TRUE) RETURNING *
            """, [data.get('site_slug', '') or '', nom, data.get('specialite', '') or '',
                  data.get('bio', '') or '', data.get('photo', '') or '', data.get('photo_url', '') or '',
                  data.get('titre', '') or '', data.get('site_url', '') or '', data.get('linkedin_url', '') or '',
                  _cint_tags_str(data.get('tags'))])
            row = cur.fetchone()
            conn.commit()
    return jsonify(_cint_to_dict(row)), 201


@app.route('/api/companion/intervenants/<int:iid>', methods=['PUT'])
@login_required
def companion_intervenants_update(iid):
    data = request.get_json() or {}
    cols = []; vals = []
    for key in ('site_slug', 'nom', 'specialite', 'bio', 'photo', 'photo_url', 'titre', 'site_url', 'linkedin_url'):
        if key in data:
            cols.append(key + '=%s'); vals.append(data[key])
    if 'tags' in data:
        cols.append('tags=%s'); vals.append(_cint_tags_str(data['tags']))
    if 'actif' in data:
        cols.append('actif=%s'); vals.append(bool(data['actif']))
    if not cols:
        return jsonify({'error': 'Aucun champ à mettre à jour'}), 400
    vals.append(iid)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE companion_intervenants SET " + ", ".join(cols) + " WHERE id=%s RETURNING *", vals)
            row = cur.fetchone()
            if not row:
                return jsonify({'error': 'Intervenant introuvable'}), 404
            conn.commit()
    return jsonify(_cint_to_dict(row))


@app.route('/api/companion/intervenants/<int:iid>', methods=['DELETE'])
@login_required
def companion_intervenants_delete(iid):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM companion_intervenants WHERE id=%s", [iid])
            conn.commit()
    return jsonify({'ok': True})


# ========== COMPANION — CONTENUS PAR TYPE (CRUD générique) ==========

def _register_companion_crud(typ, cols):
    """Enregistre GET/POST/PUT/DELETE /api/companion/<typ> sur companion_<typ>."""
    table = 'companion_' + typ

    def _list():
        with get_db() as conn:
            with conn.cursor() as cur:
                if typ == 'posts':
                    site_slug = request.args.get('site_slug', '') or ''
                    cur.execute("SELECT * FROM " + table + " WHERE actif=TRUE AND COALESCE(site_slug,'')=%s ORDER BY id", [site_slug])
                else:
                    cur.execute("SELECT * FROM " + table + " WHERE actif=TRUE ORDER BY id")
                rows = cur.fetchall()
        return jsonify({typ: [serialize_row(r) for r in rows]})

    def _create():
        data = request.get_json() or {}
        fields = ['site_slug'] + cols
        vals = [data.get('site_slug', '') or ''] + [data.get(c, '') or '' for c in cols]
        # Rattachement automatique à l'intervenant connecté (sauf admin)
        if 'intervenant' in cols and session.get('role') != 'admin':
            _, _inv_nom = _resolve_intervenant()
            if _inv_nom:
                vals[fields.index('intervenant')] = _inv_nom
        ph = ', '.join(['%s'] * len(fields))
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO " + table + " (" + ', '.join(fields) + ", actif) "
                            "VALUES (" + ph + ", TRUE) RETURNING *", vals)
                row = cur.fetchone()
                conn.commit()
        return jsonify(serialize_row(row)), 201

    def _update(rid):
        data = request.get_json() or {}
        sets = []; vals = []
        for c in (['site_slug'] + cols):
            if c in data:
                sets.append(c + '=%s'); vals.append(data[c])
        if 'actif' in data:
            sets.append('actif=%s'); vals.append(bool(data['actif']))
        if not sets:
            return jsonify({'error': 'Aucun champ à mettre à jour'}), 400
        vals.append(rid)
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE " + table + " SET " + ', '.join(sets) + " WHERE id=%s RETURNING *", vals)
                row = cur.fetchone()
                if not row:
                    return jsonify({'error': 'Introuvable'}), 404
                conn.commit()
        return jsonify(serialize_row(row))

    def _delete(rid):
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM " + table + " WHERE id=%s", [rid])
                conn.commit()
        return jsonify({'ok': True})

    base = 'cc_' + typ
    app.add_url_rule('/api/companion/' + typ, base + '_list', login_required(_list), methods=['GET'])
    app.add_url_rule('/api/companion/' + typ, base + '_create', login_required(_create), methods=['POST'])
    app.add_url_rule('/api/companion/' + typ + '/<int:rid>', base + '_update', login_required(_update), methods=['PUT'])
    app.add_url_rule('/api/companion/' + typ + '/<int:rid>', base + '_delete', login_required(_delete), methods=['DELETE'])


for _typ, _cols in COMPANION_CONTENT_TABLES.items():
    _register_companion_crud(_typ, _cols)


# ========== COMPANION — SONS IMMERSIFS ==========

DEFAULT_SONS = [
    ('foret',   'Forêt',   'foret.jpg'),
    ('pluie',   'Pluie',   'pluie.jpg'),
    ('ocean',   'Océan',   'ocean.jpg'),
    ('cafe',    'Café',    'cafe.jpg'),
    ('orage',   'Orage',   'orage.jpg'),
    ('clavier', 'Clavier', 'clavier.jpg'),
    ('creche',  'Crèche',  'creche.jpg'),
    ('noel',    'Noël',    'noel.jpg'),
    ('paques',  'Pâques',  'paques.jpg'),
]


def _son_to_dict(row):
    return {
        'id': row['id'], 'site_slug': row.get('site_slug'),
        'nom': row['nom'], 'label': row['label'],
        'photo': row.get('photo'), 'audio': row.get('audio'),
        'actif': row.get('actif', True), 'ordre': row.get('ordre', 0)
    }


@app.route('/api/companion/sons', methods=['GET'])
@login_required
def companion_sons_list():
    """Liste les sons immersifs d'un site ; sème les 9 sons par défaut si vide."""
    site_slug = request.args.get('site_slug', '') or ''
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM companion_sons WHERE COALESCE(site_slug,'') = %s", [site_slug])
            if cur.fetchone()['n'] == 0:
                for i, (nom, label, photo) in enumerate(DEFAULT_SONS):
                    cur.execute(
                        "INSERT INTO companion_sons (site_slug, nom, label, photo, actif, ordre) VALUES (%s,%s,%s,%s,TRUE,%s)",
                        [site_slug, nom, label, photo, i]
                    )
                conn.commit()
            cur.execute("SELECT * FROM companion_sons WHERE COALESCE(site_slug,'') = %s ORDER BY ordre, id", [site_slug])
            rows = cur.fetchall()
    return jsonify({'sons': [_son_to_dict(r) for r in rows]})


@app.route('/api/companion/sons', methods=['POST'])
@login_required
def companion_sons_create():
    data = request.get_json() or {}
    nom = (data.get('nom') or '').strip()
    label = (data.get('label') or '').strip()
    if not nom or not label:
        return jsonify({'error': 'Nom et label requis'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO companion_sons (site_slug, nom, label, photo, audio, actif, ordre) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                [data.get('site_slug', '') or '', nom, label, data.get('photo', '') or '',
                 data.get('audio', '') or '', bool(data.get('actif', True)), int(data.get('ordre', 0) or 0)]
            )
            row = cur.fetchone()
            conn.commit()
    return jsonify(_son_to_dict(row)), 201


@app.route('/api/companion/sons/<int:son_id>', methods=['PUT'])
@login_required
def companion_sons_update(son_id):
    data = request.get_json() or {}
    cols = []; vals = []
    for key in ('nom', 'label', 'photo', 'audio', 'site_slug'):
        if key in data:
            cols.append(key + '=%s'); vals.append(data[key])
    if 'actif' in data:
        cols.append('actif=%s'); vals.append(bool(data['actif']))
    if 'ordre' in data:
        cols.append('ordre=%s'); vals.append(int(data['ordre'] or 0))
    if not cols:
        return jsonify({'error': 'Aucun champ à mettre à jour'}), 400
    vals.append(son_id)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE companion_sons SET " + ", ".join(cols) + " WHERE id=%s RETURNING *", vals)
            row = cur.fetchone()
            if not row:
                return jsonify({'error': 'Son introuvable'}), 404
            conn.commit()
    return jsonify(_son_to_dict(row))


@app.route('/api/companion/sons/<int:son_id>', methods=['DELETE'])
@login_required
def companion_sons_delete(son_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM companion_sons WHERE id=%s", [son_id])
            conn.commit()
    return jsonify({'ok': True})


@app.route('/api/admin/intervenants/stats', methods=['GET'])
@login_required
@admin_required
def admin_intervenants_stats():
    """
    Statistiques de rétribution par intervenant.
    Params : date_from, date_to (YYYY-MM-DD), site_slug (optionnel)
    Retourne : par intervenant — nb_clics, duree_totale_sec, duree_totale_min,
               pct_clics, pct_duree (part relative sur la période)
    """
    from datetime import date as dt
    date_from = request.args.get('date_from', dt(dt.today().year, 1, 1).isoformat())
    date_to   = request.args.get('date_to',   dt.today().isoformat())
    site_slug = request.args.get('site_slug')

    site_clause = "AND site_slug = %s" if site_slug else ""
    params_base = [date_from, date_to] + ([site_slug] if site_slug else [])

    with get_db() as conn:
        with conn.cursor() as cur:

            cur.execute(f"""
                SELECT
                    COALESCE(NULLIF(TRIM(intervenant_nom), ''), '(sans intervenant)') AS intervenant,
                    content_type,
                    COUNT(*)                          AS nb_clics,
                    COALESCE(SUM(duree_sec), 0)       AS duree_totale_sec,
                    ROUND(COALESCE(SUM(duree_sec), 0) / 60.0, 1) AS duree_totale_min,
                    MIN(created_at)::date::text       AS premiere_lecture,
                    MAX(created_at)::date::text       AS derniere_lecture
                FROM companion_content_plays
                WHERE created_at::date BETWEEN %s AND %s
                  AND content_type != 'post_interne'
                  {site_clause}
                GROUP BY intervenant, content_type
                ORDER BY intervenant, nb_clics DESC
            """, params_base)
            rows_detail = [serialize_row(r) for r in cur.fetchall()]

            cur.execute(f"""
                SELECT
                    COUNT(*)                    AS total_clics,
                    COALESCE(SUM(duree_sec), 0) AS total_duree_sec
                FROM companion_content_plays
                WHERE created_at::date BETWEEN %s AND %s
                  AND content_type != 'post_interne'
                  {site_clause}
            """, params_base)
            totaux = cur.fetchone() or {}
            total_clics = int(totaux.get('total_clics', 0) or 0)
            total_duree = int(totaux.get('total_duree_sec', 0) or 0)

            cur.execute(f"""
                SELECT
                    COALESCE(NULLIF(TRIM(intervenant_nom), ''), '(sans intervenant)') AS intervenant,
                    COUNT(*)                          AS nb_clics,
                    COALESCE(SUM(duree_sec), 0)       AS duree_totale_sec,
                    ROUND(COALESCE(SUM(duree_sec), 0) / 60.0, 1) AS duree_totale_min,
                    MIN(created_at)::date::text       AS premiere_lecture,
                    MAX(created_at)::date::text       AS derniere_lecture
                FROM companion_content_plays
                WHERE created_at::date BETWEEN %s AND %s
                  AND content_type != 'post_interne'
                  {site_clause}
                GROUP BY intervenant
                ORDER BY nb_clics DESC
            """, params_base)
            rows_global = []
            for r in cur.fetchall():
                sr = serialize_row(r)
                sr['pct_clics'] = round(int(sr['nb_clics']) / total_clics * 100, 1) if total_clics else 0
                sr['pct_duree'] = round(int(sr['duree_totale_sec']) / total_duree * 100, 1) if total_duree else 0
                rows_global.append(sr)

    return jsonify({
        'date_from':       date_from,
        'date_to':         date_to,
        'site_slug':       site_slug,
        'total_clics':     total_clics,
        'total_duree_sec': total_duree,
        'total_duree_min': round(total_duree / 60, 1),
        'par_intervenant': rows_global,
        'detail_par_type': rows_detail,
    })


@app.route('/api/companion/qvct', methods=['GET'])
@login_required
def companion_qvct():
    site_slug = request.args.get('site_slug')
    period    = request.args.get('period', 'mois')
    from datetime import date as dt, timedelta
    today = dt.today()
    if period == 'semaine':
        date_debut = today - timedelta(days=today.weekday())
    elif period == 'annee':
        date_debut = dt(today.year, 1, 1)
    else:
        date_debut = dt(today.year, today.month, 1)

    with get_db() as conn:
        with conn.cursor() as cur:

            # ── Bien-être global (pas de dept dans users → on regroupe par site_slug) ──
            cur.execute(
                """
                SELECT COALESCE(site_slug, 'Site principal') AS dept,
                       COUNT(id)            AS nb_checkins,
                       AVG(energie)         AS energie_moy,
                       AVG(stress)          AS stress_moy,
                       AVG(focus)           AS focus_moy
                FROM companion_checkins
                WHERE date >= %s
                  AND (%s IS NULL OR site_slug = %s)
                GROUP BY site_slug
                ORDER BY nb_checkins DESC
                """,
                [date_debut, site_slug, site_slug])
            dept_wellbeing = []
            for r in cur.fetchall():
                dept_wellbeing.append({
                    'dept': r['dept'],
                    'nb_checkins': r['nb_checkins'],
                    'energie_moy': round(float(r['energie_moy'] or 0), 1),
                    'stress_moy':  round(float(r['stress_moy']  or 0), 1),
                    'focus_moy':   round(float(r['focus_moy']   or 0), 1),
                })

            # ── Utilisateurs actifs ──
            cur.execute(
                """
                SELECT COUNT(DISTINCT user_id) AS actifs
                FROM companion_points
                WHERE created_at::date >= %s
                  AND (%s IS NULL OR site_slug = %s)
                """,
                [date_debut, site_slug, site_slug])
            users_actifs = int((cur.fetchone() or {}).get('actifs', 0) or 0)

            cur.execute(
                """
                SELECT COUNT(DISTINCT user_id) AS total
                FROM companion_points
                WHERE (%s IS NULL OR site_slug = %s)
                """,
                [site_slug, site_slug])
            users_total = int((cur.fetchone() or {}).get('total', 0) or 0)

            # ── Durée totale CC ──
            cur.execute(
                """
                SELECT COALESCE(SUM(duree_min), 0) AS duree
                FROM companion_cc_sessions
                WHERE created_at::date >= %s
                  AND (%s IS NULL OR site_slug = %s)
                """,
                [date_debut, site_slug, site_slug])
            duree_cc = int((cur.fetchone() or {}).get('duree', 0) or 0)

            # ── Top activités ──
            cur.execute(
                """
                SELECT action,
                       COUNT(*)      AS nb_sessions,
                       SUM(points)   AS total_points
                FROM companion_points
                WHERE created_at::date >= %s
                  AND (%s IS NULL OR site_slug = %s)
                GROUP BY action
                ORDER BY total_points DESC
                LIMIT 8
                """,
                [date_debut, site_slug, site_slug])
            top_activites = []
            for r in cur.fetchall():
                top_activites.append({
                    'action': r['action'],
                    'nb_sessions': int(r['nb_sessions'] or 0),
                    'total_points': int(r['total_points'] or 0),
                })

            # ── Tendance hebdomadaire ──
            cur.execute(
                """
                SELECT DATE_TRUNC('week', date)  AS semaine,
                       AVG(energie)              AS energie_moy,
                       AVG(stress)               AS stress_moy,
                       AVG(focus)                AS focus_moy,
                       COUNT(*)                  AS nb_checkins
                FROM companion_checkins
                WHERE date >= %s
                  AND (%s IS NULL OR site_slug = %s)
                GROUP BY semaine
                ORDER BY semaine ASC
                """,
                [date_debut, site_slug, site_slug])
            trend_hebdo = []
            for r in cur.fetchall():
                trend_hebdo.append({
                    'semaine': str(r['semaine'])[:10] if r['semaine'] else None,
                    'energie_moy': round(float(r['energie_moy'] or 0), 1),
                    'stress_inv':  round(10 - float(r['stress_moy'] or 5), 1),
                    'focus_moy':   round(float(r['focus_moy'] or 0), 1),
                    'nb_checkins': int(r['nb_checkins'] or 0),
                })

            # ── Streak moyen (jours avec checkin / nb users) ──
            cur.execute(
                """
                SELECT user_id, COUNT(DISTINCT date) AS jours
                FROM companion_checkins
                WHERE date >= %s
                  AND (%s IS NULL OR site_slug = %s)
                GROUP BY user_id
                """,
                [date_debut, site_slug, site_slug])
            streak_rows = cur.fetchall()
            streak_moyen = round(sum(int(r['jours'] or 0) for r in streak_rows) / len(streak_rows), 1) if streak_rows else 0

            # ── Alertes QVCT ──
            alertes = []
            for dept in dept_wellbeing:
                if dept['stress_moy'] >= 7:
                    alertes.append({
                        'niveau': 'rouge', 'icone': '🔴',
                        'titre': f"Stress élevé · {dept['dept']}",
                        'detail': f"Moyenne {dept['stress_moy']}/10 sur {dept['nb_checkins']} check-in(s)"
                    })
                elif dept['stress_moy'] >= 6:
                    alertes.append({
                        'niveau': 'orange', 'icone': '🟠',
                        'titre': f"Stress modéré · {dept['dept']}",
                        'detail': f"Moyenne {dept['stress_moy']}/10 — à surveiller"
                    })
                if dept['energie_moy'] < 4:
                    alertes.append({
                        'niveau': 'orange', 'icone': '⚡',
                        'titre': f"Énergie faible · {dept['dept']}",
                        'detail': f"Moyenne {dept['energie_moy']}/10 — actions recommandées"
                    })
            cur.execute(
                """
                SELECT COUNT(DISTINCT user_id) AS inactifs
                FROM companion_checkins
                WHERE (%s IS NULL OR site_slug = %s)
                  AND user_id NOT IN (
                    SELECT DISTINCT user_id FROM companion_points
                    WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
                    AND user_id IS NOT NULL
                  )
                  AND user_id IS NOT NULL
                """,
                [site_slug, site_slug])
            inactifs = int((cur.fetchone() or {}).get('inactifs', 0) or 0)
            if inactifs > 0:
                alertes.append({
                    'niveau': 'orange', 'icone': '😴',
                    'titre': f'{inactifs} utilisateur(s) sans activité depuis 7 jours',
                    'detail': 'Aucune action Companion enregistrée cette semaine'
                })

    return jsonify({
        'users_actifs':     users_actifs,
        'users_total':      users_total,
        'duree_totale_min': duree_cc,
        'streak_moyen':     streak_moyen,
        'dept_wellbeing':   dept_wellbeing,
        'top_activites':    top_activites,
        'trend_hebdo':      trend_hebdo,
        'alertes':          alertes,
    })

# ========== ADMIN — INTERVENANTS (base PostgreSQL) ==========

@app.route('/api/admin/intervenants', methods=['GET'])
@login_required
@admin_required
def admin_get_intervenants():
    """Liste tous les intervenants avec leurs stats globales de clics."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT i.*,
                       u.email as user_email,
                       COALESCE(p.nb_clics, 0)    as total_clics,
                       COALESCE(p.duree_min, 0)   as total_duree_min
                FROM intervenants i
                LEFT JOIN users u ON i.user_id = u.id
                LEFT JOIN (
                    SELECT intervenant_nom,
                           COUNT(*) as nb_clics,
                           ROUND(COALESCE(SUM(duree_sec),0)/60.0,1) as duree_min
                    FROM companion_content_plays
                    WHERE content_type != 'post_interne'
                    GROUP BY intervenant_nom
                ) p ON p.intervenant_nom = i.nom
                ORDER BY i.created_at DESC
            """)
            rows = cur.fetchall()
    return jsonify([serialize_row(r) for r in rows])


@app.route('/api/admin/intervenants', methods=['POST'])
@login_required
@admin_required
def admin_create_intervenant():
    """Crée un intervenant + son compte user avec role='intervenant'."""
    data = request.get_json() or {}
    nom   = (data.get('nom') or '').strip()
    email = (data.get('email') or '').strip().lower()
    if not nom:
        return jsonify({'error': 'Nom requis'}), 400

    tmp_pw = secrets.token_urlsafe(10)
    with get_db() as conn:
        with conn.cursor() as cur:
            # Créer le compte user si email fourni
            user_id = None
            if email:
                try:
                    cur.execute("""
                        INSERT INTO users (email, password, nom, role, actif)
                        VALUES (%s, %s, %s, 'intervenant', 1) RETURNING id
                    """, [email, generate_password_hash(tmp_pw), nom])
                    user_id = cur.fetchone()['id']
                except psycopg2.IntegrityError:
                    return jsonify({'error': 'Email déjà utilisé'}), 409

            cur.execute("""
                INSERT INTO intervenants (user_id, nom, email, specialite, bio, photo_url, taux_contenu, apporteur_affaire, est_intervenant, actif)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, [user_id, nom, email,
                  data.get('specialite', ''), data.get('bio', ''),
                  data.get('photo_url', ''),
                  float(data.get('taux_contenu', 30)),
                  bool(data.get('apporteur_affaire', False)),
                  bool(data.get('est_intervenant', True)),
                  True])
            inv_id = cur.fetchone()['id']
            conn.commit()

    return jsonify({'ok': True, 'id': inv_id,
                    'tmp_password': tmp_pw if email else None}), 201


@app.route('/api/admin/intervenants/<int:inv_id>', methods=['PUT'])
@login_required
@admin_required
def admin_update_intervenant(inv_id):
    data = request.get_json() or {}
    # Mise à jour partielle : seuls les champs présents dans la requête sont modifiés.
    cols = []
    vals = []
    for key in ('nom', 'email', 'specialite', 'bio', 'photo_url'):
        if key in data:
            cols.append(key + '=%s'); vals.append(data[key])
    if 'taux_contenu' in data:
        cols.append('taux_contenu=%s'); vals.append(float(data['taux_contenu']))
    for key in ('apporteur_affaire', 'actif', 'est_intervenant'):
        if key in data:
            cols.append(key + '=%s'); vals.append(bool(data[key]))
    if not cols:
        return jsonify({'error': 'Aucun champ à mettre à jour'}), 400
    vals.append(inv_id)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE intervenants SET " + ", ".join(cols) + " WHERE id=%s", vals)
            conn.commit()
    return jsonify({'ok': True})


@app.route('/api/admin/intervenants/<int:inv_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_intervenant(inv_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE intervenants SET actif=FALSE WHERE id=%s", [inv_id])
            conn.commit()
    return jsonify({'ok': True})


# ========== ESPACE INTERVENANT — Stats & Rétribution ==========

def _get_semestre_clause(annee, semestre):
    """Retourne la clause SQL pour un semestre donné sur companion_content_plays."""
    if semestre == 1:
        return f"created_at >= '{annee}-01-01' AND created_at < '{annee}-07-01'"
    else:
        return f"created_at >= '{annee}-07-01' AND created_at < '{annee+1}-01-01'"


@app.route('/api/intervenant/stats', methods=['GET'])
@login_required
@intervenant_required
def intervenant_stats():
    """
    Stats de clics et rétribution estimée pour l'intervenant connecté.
    Admin peut passer ?intervenant_id=X pour voir n'importe quel intervenant.
    """
    user_id = session.get('user_id')
    role    = session.get('role')

    # Admin peut consulter n'importe quel intervenant
    if role == 'admin' and request.args.get('intervenant_id'):
        inv_id = int(request.args.get('intervenant_id'))
    else:
        # Trouver l'intervenant lié au user connecté (par user_id, sinon par email)
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM users WHERE id=%s", [user_id])
                _u = cur.fetchone()
                _email = (_u['email'] if _u else '') or ''
                cur.execute("""
                    SELECT id FROM intervenants
                    WHERE user_id = %s
                       OR (COALESCE(email,'') <> '' AND LOWER(email) = LOWER(%s))
                    ORDER BY (user_id = %s) DESC, actif DESC, id
                    LIMIT 1
                """, [user_id, _email, user_id])
                row = cur.fetchone()
        if not row:
            return jsonify({'error': 'Intervenant introuvable (connectez-vous avec le compte intervenant)'}), 404
        inv_id = row['id']

    # Période : semestre en cours par défaut
    today = date.today()
    annee    = int(request.args.get('annee',    today.year))
    semestre = int(request.args.get('semestre', 1 if today.month <= 6 else 2))
    sem_clause = _get_semestre_clause(annee, semestre)

    with get_db() as conn:
        with conn.cursor() as cur:
            # Infos intervenant
            cur.execute("SELECT * FROM intervenants WHERE id=%s", [inv_id])
            _invrow = cur.fetchone()
            inv = serialize_row(_invrow) if _invrow else None
            if not inv:
                return jsonify({'error': 'Intervenant introuvable'}), 404

            # Clics par contenu sur la période
            cur.execute(f"""
                SELECT content_type, content_label, site_slug,
                       COUNT(*) as nb_clics,
                       ROUND(COALESCE(SUM(duree_sec),0)/60.0,1) as duree_min
                FROM companion_content_plays
                WHERE intervenant_nom = %s
                  AND content_type != 'post_interne'
                  AND {sem_clause}
                GROUP BY content_type, content_label, site_slug
                ORDER BY nb_clics DESC
            """, [inv['nom']])
            clics_detail = [serialize_row(r) for r in cur.fetchall()]

            # Total clics intervenant sur la période
            nb_clics_inv = sum(r['nb_clics'] for r in clics_detail)

            # Total des clics de TOUS les intervenants sur la période
            # (dénominateur de la part : on ne compte que les clics attribués à
            #  un intervenant, pas l'ensemble des clics tous contenus confondus)
            cur.execute(f"""
                SELECT COUNT(*) as total
                FROM companion_content_plays
                WHERE intervenant_nom IS NOT NULL
                  AND TRIM(intervenant_nom) != ''
                  AND content_type != 'post_interne'
                  AND {sem_clause}
            """)
            total_clics = (cur.fetchone() or {}).get('total', 0) or 0

            # CA global beOtop du semestre = somme des sites companion
            # (tarif annuel × nb salariés / 2). Base de la rétribution contenu,
            # et non le CA des seuls sites où l'intervenant a des clics.
            try:
                cur.execute("""
                    SELECT COALESCE(SUM(tarif_annuel * nb_salaries), 0) / 2 AS ca_global
                    FROM sites
                    WHERE has_companion = 1 AND tarif_annuel > 0 AND nb_salaries > 0 AND actif = 1
                """)
                ca_global = float((cur.fetchone() or {}).get('ca_global', 0) or 0)
            except Exception:
                conn.rollback()
                ca_global = 0.0

            # Clics par site pour calcul rétribution
            # Les colonnes tarif_annuel/has_companion peuvent ne pas exister encore
            # Prefixer created_at par cp. pour éviter ambiguïté avec LEFT JOIN sites
            cp_sem_clause = sem_clause.replace('created_at', 'cp.created_at')
            try:
                cur.execute(f"""
                    SELECT cp.site_slug,
                           COUNT(*) as nb_clics_inv,
                           (SELECT COUNT(*) FROM companion_content_plays cp2
                            WHERE cp2.site_slug = cp.site_slug
                            AND cp2.content_type != 'post_interne'
                            AND {sem_clause}) as nb_clics_total,
                           COALESCE(s.tarif_annuel, 0)  as tarif_annuel,
                           COALESCE(s.nb_salaries, 0)   as nb_salaries
                    FROM companion_content_plays cp
                    LEFT JOIN sites s ON s.slug = cp.site_slug
                    WHERE cp.intervenant_nom = %s
                      AND cp.content_type != 'post_interne'
                      AND {cp_sem_clause}
                    GROUP BY cp.site_slug, s.tarif_annuel, s.nb_salaries
                """, [inv['nom']])
                clics_par_site = [serialize_row(r) for r in cur.fetchall()]
            except Exception:
                conn.rollback()
                cur.execute(f"""
                    SELECT site_slug,
                           COUNT(*) as nb_clics_inv,
                           (SELECT COUNT(*) FROM companion_content_plays cp2
                            WHERE cp2.site_slug = cp.site_slug
                            AND cp2.content_type != 'post_interne'
                            AND {sem_clause}) as nb_clics_total,
                           0 as tarif_annuel,
                           0 as nb_salaries
                    FROM companion_content_plays cp
                    WHERE intervenant_nom = %s
                      AND content_type != 'post_interne'
                      AND {sem_clause}
                    GROUP BY site_slug
                """, [inv['nom']])
                clics_par_site = [serialize_row(r) for r in cur.fetchall()]

            # Historique semestres précédents
            cur.execute("""
                SELECT annee, semestre, nb_clics, pct_clics,
                       ca_site, montant_contenu, statut
                FROM retribution_semestres
                WHERE intervenant_id = %s
                ORDER BY annee DESC, semestre DESC
                LIMIT 10
            """, [inv_id])
            historique = [serialize_row(r) for r in cur.fetchall()]

            # ── Clients apportés (V2) ──
            clients_apportes = []
            try:
                cur.execute("""
                    SELECT c.id, c.nom,
                           COALESCE(s.tarif_annuel, 0)  as tarif_annuel,
                           COALESCE(s.nb_salaries, 0)   as nb_salaries,
                           s.slug as site_slug
                    FROM clients c
                    JOIN sites s ON s.client_id = c.id
                    WHERE c.apporteur_id = %s AND c.actif = 1
                    GROUP BY c.id, c.nom, s.tarif_annuel, s.nb_salaries, s.slug
                """, [inv_id])
                for r in cur.fetchall():
                    sr = serialize_row(r)
                    tarif_annuel = float(sr.get('tarif_annuel') or 0)
                    nb_salaries  = int(sr.get('nb_salaries') or 0)
                    # CA semestriel = tarif annuel × nb employés déclarés / 2
                    ca_semestre  = round(tarif_annuel * nb_salaries / 2, 2)
                    commission   = round(ca_semestre * 0.20, 2)
                    sr['tarif_annuel']       = tarif_annuel
                    sr['ca_semestre']        = ca_semestre
                    sr['commission_20pct']   = commission
                    clients_apportes.append(sr)
            except Exception:
                pass  # table clients.apporteur_id peut ne pas exister encore

            total_commission_apport = sum(c['commission_20pct'] for c in clients_apportes)

    # Rétribution estimée = part des clics intervenants × taux contenu × CA global beOtop
    pct_global = round(nb_clics_inv / total_clics * 100, 1) if total_clics else 0
    taux       = float(inv.get('taux_contenu') or 30) / 100
    remuneration_estimee = round((nb_clics_inv / total_clics) * taux * ca_global, 2) if total_clics else 0.0

    return jsonify({
        'intervenant':              inv,
        'annee':                    annee,
        'semestre':                 semestre,
        'nb_clics':                 nb_clics_inv,
        'total_clics':              int(total_clics),
        'pct_global':               pct_global,
        'taux_contenu':             float(inv.get('taux_contenu') or 30),
        'ca_global':                round(ca_global, 2),
        'remuneration_estimee':     remuneration_estimee,
        'clics_detail':             clics_detail,
        'clics_par_site':           clics_par_site,
        'historique':               historique,
        'clients_apportes':         clients_apportes,
        'total_commission_apport':  total_commission_apport,
        'note':                     'Rétribution en € calculée lors de la clôture semestrielle par beOtop',
    })



@app.route('/api/admin/retribution/synthese', methods=['GET'])
@login_required
@admin_required
def admin_retribution_synthese():
    """
    Synthèse semestrielle de rétribution pour tous les intervenants actifs.
    Agrège en une seule requête : rétribution contenu + commission apport.
    Params : annee, semestre
    """
    from datetime import date as dt
    annee    = int(request.args.get('annee',    dt.today().year))
    semestre = int(request.args.get('semestre', 1 if dt.today().month <= 6 else 2))
    date_from = f'{annee}-01-01' if semestre == 1 else f'{annee}-07-01'
    date_to   = f'{annee}-06-30' if semestre == 1 else f'{annee}-12-31'

    with get_db() as conn:
        with conn.cursor() as cur:

            # 1. TOUS les intervenants déclarés actifs + leurs clics (LEFT JOIN)
            cur.execute("""
                SELECT
                    i.id                AS inv_id,
                    i.nom               AS intervenant,
                    i.taux_contenu      AS taux,
                    i.apporteur_affaire AS est_apporteur,
                    COALESCE(cp.nb_clics, 0)    AS nb_clics,
                    COALESCE(cp.total_clics, 0) AS total_clics
                FROM intervenants i
                LEFT JOIN (
                    SELECT
                        TRIM(intervenant_nom) AS intervenant_nom,
                        COUNT(*) AS nb_clics,
                        (SELECT COUNT(*) FROM companion_content_plays cp2
                         WHERE cp2.created_at::date BETWEEN %s AND %s
                           AND cp2.content_type != 'post_interne') AS total_clics
                    FROM companion_content_plays
                    WHERE created_at::date BETWEEN %s AND %s
                      AND content_type != 'post_interne'
                    GROUP BY TRIM(intervenant_nom)
                ) cp ON TRIM(cp.intervenant_nom) = TRIM(i.nom)
                WHERE i.actif = TRUE
                ORDER BY nb_clics DESC
            """, [date_from, date_to, date_from, date_to])
            intervenants = [serialize_row(r) for r in cur.fetchall()]

            # 2. CA semestriel total des sites companion
            cur.execute("""
                SELECT
                    COALESCE(SUM(tarif_annuel * nb_salaries), 0) / 2 AS ca_semestre_total
                FROM sites
                WHERE has_companion = 1 AND tarif_annuel > 0 AND nb_salaries > 0 AND actif = 1
            """)
            row = cur.fetchone()
            ca_semestre_total = float(row['ca_semestre_total'] or 0) if row else 0

            # 3. CA semestriel par site pour calcul par intervenant
            cur.execute("""
                SELECT slug, tarif_annuel, nb_salaries,
                       (tarif_annuel * nb_salaries) / 2 AS ca_semestre
                FROM sites
                WHERE has_companion = 1 AND tarif_annuel > 0 AND nb_salaries > 0 AND actif = 1
            """)
            sites = [serialize_row(r) for r in cur.fetchall()]

            # 4. Clics par intervenant par site
            cur.execute("""
                SELECT
                    TRIM(intervenant_nom) AS intervenant,
                    site_slug,
                    COUNT(*) AS nb_clics_site,
                    (SELECT COUNT(*) FROM companion_content_plays cp2
                     WHERE cp2.site_slug = cp.site_slug
                     AND cp2.created_at::date BETWEEN %s AND %s
                     AND cp2.content_type != 'post_interne') AS total_clics_site
                FROM companion_content_plays cp
                WHERE created_at::date BETWEEN %s AND %s
                  AND content_type != 'post_interne'
                  AND TRIM(intervenant_nom) IN (
                      SELECT TRIM(nom) FROM intervenants WHERE actif = TRUE
                  )
                GROUP BY TRIM(intervenant_nom), site_slug
            """, [date_from, date_to, date_from, date_to])
            clics_par_site = {}
            for r in cur.fetchall():
                sr = serialize_row(r)
                inv = sr['intervenant']
                if inv not in clics_par_site:
                    clics_par_site[inv] = []
                clics_par_site[inv].append(sr)

            # 5. Commission apport par intervenant
            cur.execute("""
                SELECT
                    i.id AS inv_id,
                    i.nom AS intervenant,
                    COALESCE(SUM(s.tarif_annuel * s.nb_salaries) / 2, 0) AS ca_clients_semestre
                FROM intervenants i
                JOIN clients c ON c.apporteur_id = i.id AND c.actif = 1
                JOIN sites s ON s.client_id = c.id
                    AND s.has_companion = 1
                    AND s.tarif_annuel > 0
                    AND s.nb_salaries > 0
                    AND s.actif = 1
                WHERE i.actif = TRUE
                GROUP BY i.id, i.nom
            """)
            apports = {serialize_row(r)['intervenant']: float(serialize_row(r)['ca_clients_semestre'] or 0)
                       for r in cur.fetchall()}

    # Calculer rétribution contenu par intervenant
    sites_dict = {s['slug']: s for s in sites}
    resultats = []
    total_contenu = 0
    total_apport  = 0

    for inv in intervenants:
        nom  = inv['intervenant']
        taux = float(inv['taux'] or 30) / 100

        # Rétribution contenu = somme sur chaque site (CA site × part clics inv × taux)
        retrib_contenu = 0
        for cs in clics_par_site.get(nom, []):
            site = sites_dict.get(cs['site_slug'])
            if site and cs['total_clics_site']:
                ca_site = float(site['ca_semestre'] or 0)
                pct = int(cs['nb_clics_site']) / int(cs['total_clics_site'])
                retrib_contenu += ca_site * pct * taux

        retrib_contenu = round(retrib_contenu, 2)

        # Commission apport
        ca_apport   = apports.get(nom, 0)
        commission  = round(ca_apport * 0.20, 2) if inv['est_apporteur'] else 0

        total_inv   = round(retrib_contenu + commission, 2)
        total_contenu += retrib_contenu
        total_apport  += commission

        resultats.append({
            'intervenant':    nom,
            'nb_clics':       int(inv['nb_clics'] or 0),
            'pct_clics':      round(int(inv['nb_clics'] or 0) / int(inv['total_clics'] or 1) * 100, 1) if inv['total_clics'] else 0,
            'taux':           float(inv['taux'] or 30),
            'est_apporteur':  bool(inv['est_apporteur']),
            'retrib_contenu': retrib_contenu,
            'ca_apport':      round(ca_apport, 2),
            'commission_apport': commission,
            'total':          total_inv,
        })

    return jsonify({
        'annee':             annee,
        'semestre':          semestre,
        'date_from':         date_from,
        'date_to':           date_to,
        'ca_semestre_total': round(ca_semestre_total, 2),
        'resultats':         resultats,
        'total_contenu':     round(total_contenu, 2),
        'total_apport':      round(total_apport, 2),
        'total_global':      round(total_contenu + total_apport, 2),
    })

@app.route('/api/admin/retribution/calcul-semestre', methods=['POST'])
@login_required
@admin_required
def admin_calcul_semestre():
    """
    Calcule et persiste la rétribution semestrielle pour tous les intervenants.
    Corps JSON : { annee: 2026, semestre: 1, tarif_par_utilisateur: 5.0 }
    """
    data      = request.get_json() or {}
    annee     = int(data.get('annee',    date.today().year))
    semestre  = int(data.get('semestre', 1 if date.today().month <= 6 else 2))
    tarif     = float(data.get('tarif_par_utilisateur', 0))
    sem_clause = _get_semestre_clause(annee, semestre)

    with get_db() as conn:
        with conn.cursor() as cur:
            # Total clics période
            cur.execute(f"""
                SELECT COUNT(*) as total FROM companion_content_plays
                WHERE content_type != 'post_interne' AND {sem_clause}
            """)
            total_clics = int((cur.fetchone() or {}).get('total', 0) or 0)

            # Utilisateurs actifs par site sur la période
            cur.execute(f"""
                SELECT site_slug, COUNT(DISTINCT user_id) as nb_actifs
                FROM companion_content_plays
                WHERE {sem_clause} AND user_id IS NOT NULL
                GROUP BY site_slug
            """)
            actifs_par_site = {r['site_slug']: int(r['nb_actifs']) for r in cur.fetchall()}

            # Clics par intervenant et par site
            cur.execute(f"""
                SELECT intervenant_nom, site_slug, COUNT(*) as nb_clics
                FROM companion_content_plays
                WHERE content_type != 'post_interne'
                  AND intervenant_nom IS NOT NULL
                  AND intervenant_nom != ''
                  AND {sem_clause}
                GROUP BY intervenant_nom, site_slug
            """)
            clics_rows = cur.fetchall()

            # Intervenants actifs
            cur.execute("SELECT id, nom, taux_contenu FROM intervenants WHERE actif=TRUE")
            intervenants = {r['nom']: r for r in cur.fetchall()}

            inserted = 0
            for row in clics_rows:
                nom      = row['intervenant_nom']
                slug     = row['site_slug']
                nb_clics = int(row['nb_clics'])
                inv      = intervenants.get(nom)
                if not inv:
                    continue

                pct      = round(nb_clics / total_clics * 100, 2) if total_clics else 0
                nb_actifs = actifs_par_site.get(slug, 0)
                ca_site   = nb_actifs * tarif * 6  # 6 mois
                taux      = float(inv['taux_contenu'] or 30) / 100
                montant   = round(ca_site * taux * (nb_clics / total_clics), 2) if total_clics else 0

                cur.execute("""
                    INSERT INTO retribution_semestres
                        (annee, semestre, intervenant_id, site_slug, nb_clics,
                         pct_clics, ca_site, montant_contenu, statut)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'calcule')
                    ON CONFLICT (annee, semestre, intervenant_id, site_slug)
                    DO UPDATE SET nb_clics=%s, pct_clics=%s, ca_site=%s,
                                  montant_contenu=%s, statut='calcule'
                """, [annee, semestre, inv['id'], slug, nb_clics,
                      pct, ca_site, montant,
                      nb_clics, pct, ca_site, montant])
                inserted += 1

            conn.commit()

    return jsonify({'ok': True, 'annee': annee, 'semestre': semestre,
                    'lignes': inserted, 'total_clics': total_clics})


# ========== PAGES HTML — Espace intervenant ==========
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) as n FROM sessions')
            nb_sessions = cur.fetchone()['n']
            cur.execute('SELECT COUNT(*) as n FROM clients')
            nb_clients = cur.fetchone()['n']
            cur.execute('SELECT COUNT(*) as n FROM sites')
            nb_sites = cur.fetchone()['n']
    return jsonify({'status': 'ok', 'version': '2.2', 'sessions': nb_sessions,
                    'clients': nb_clients, 'sites': nb_sites})

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
                        id SERIAL PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        prenom TEXT, nom TEXT, email TEXT, role TEXT,
                        entreprise TEXT, effectif TEXT, priorite TEXT, message TEXT
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

# ========== PAGES HTML ==========

@app.route('/realtime/<site_slug>')
def realtime_page(site_slug):
    """
    Page temps réel publique — pas d'authentification requise.
    Accessible depuis un écran à l'entrée de l'espace.
    """
    path = os.path.join(BASE_DIR, 'realtime.html')
    try:
        with open(path, encoding='utf-8') as f:
            html = f.read()
        # Injecter le site_slug dans la page
        html = html.replace("const SITE = 'dmmf-agde'", f"const SITE = '{site_slug}'")
        return Response(html, mimetype='text/html; charset=utf-8')
    except FileNotFoundError:
        return Response('<h1>Page realtime.html introuvable</h1>', status=404, mimetype='text/html')

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    role = session.get('role')
    if role == 'admin':
        return redirect('/admin')
    if role == 'intervenant':
        return redirect('/mon-espace')
    return redirect('/dashboard')

@app.route('/mon-espace')
def mon_espace_page():
    if 'user_id' not in session:
        return redirect('/login')
    if session.get('role') not in ('admin', 'intervenant'):
        return redirect('/dashboard')
    return serve_html('mon_espace.html')

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

@app.route('/companion')
def companion_page():
    if 'user_id' not in session:
        return redirect('/login')
    return serve_html('companion.html')

@app.route('/roi')
def roi_page():
    return serve_html('ROI_beOtop.html')

@app.route('/kiosk/<site_slug>')
def kiosk_page(site_slug):
    # Chercher le fichier kiosk (plusieurs noms possibles)
    candidates = ['beOtop_Kiosk.html', 'BeOtop_Kiosk.html', 'kiosk.html', 'Kiosk.html']
    html = None
    for fname in candidates:
        path = os.path.join(BASE_DIR, fname)
        try:
            with open(path, encoding='utf-8') as f:
                html = f.read()
            break
        except FileNotFoundError:
            continue
    if html is None:
        return Response(
            f'<h1>Kiosk introuvable</h1><p>Fichiers cherchés : {candidates}</p><p>BASE_DIR : {BASE_DIR}</p>',
            status=404, mimetype='text/html'
        )
    html = html.replace("var SITE_SLUG = ''", f"var SITE_SLUG = '{site_slug}'")
    return Response(html, mimetype='text/html; charset=utf-8')



# ========== INSCRIPTION COMPANION ==========

import secrets as _secrets

@app.route('/api/admin/sites/<int:site_id>/invite-token', methods=['POST'])
@login_required
def generate_invite_token(site_id):
    """Génère ou régénère un token d'invitation pour un site"""
    user = get_current_user()
    with get_db() as conn:
        with conn.cursor() as cur:
            # Vérifier que le site existe et appartient au client
            if user['role'] == 'admin':
                cur.execute("SELECT slug, nom FROM sites WHERE id=%s", [site_id])
            else:
                cur.execute("SELECT slug, nom FROM sites WHERE id=%s AND client_id=%s", [site_id, user['client_id']])
            site = cur.fetchone()
            if not site:
                return jsonify({'error': 'Site introuvable'}), 404
            # Générer un token sans caractères ambigus (O/0, I/l/1)
            _alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789-_'
            token = ''.join(_secrets.choice(_alphabet) for _ in range(32))
            # Désactiver l'ancien token si existant
            cur.execute("UPDATE site_invite_tokens SET actif=0 WHERE site_id=%s", [site_id])
            cur.execute("""
                INSERT INTO site_invite_tokens (site_id, site_slug, token, actif)
                VALUES (%s, %s, %s, 1)
            """, [site_id, site['slug'], token])
            conn.commit()
    return jsonify({
        'token': token,
        'url': f'/join/{token}',
        'site_slug': site['slug'],
        'site_nom': site['nom']
    })

@app.route('/api/admin/sites/tokens', methods=['GET'])
@login_required
def get_all_tokens():
    """Liste les tokens actifs — filtrés par client si role=client"""
    user = get_current_user()
    with get_db() as conn:
        with conn.cursor() as cur:
            if user['role'] == 'admin':
                cur.execute("""
                    SELECT t.token, t.site_slug, t.nb_inscrits, t.actif, t.created_at::text,
                           s.id AS site_id, s.nom AS site_nom, s.ville, c.nom AS client_nom
                    FROM site_invite_tokens t
                    JOIN sites s ON t.site_id = s.id
                    JOIN clients c ON s.client_id = c.id
                    WHERE t.actif = 1
                    ORDER BY c.nom, s.nom
                """)
            else:
                cur.execute("""
                    SELECT t.token, t.site_slug, t.nb_inscrits, t.actif, t.created_at::text,
                           s.id AS site_id, s.nom AS site_nom, s.ville, c.nom AS client_nom
                    FROM site_invite_tokens t
                    JOIN sites s ON t.site_id = s.id
                    JOIN clients c ON s.client_id = c.id
                    WHERE t.actif = 1 AND s.client_id = %s
                    ORDER BY s.nom
                """, [user['client_id']])
            rows = cur.fetchall()
    return jsonify([serialize_row(r) for r in rows])

@app.route('/join/<token>')
def join_page(token):
    """Page d'inscription via token"""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT t.site_slug, t.actif, s.nom AS site_nom, s.ville, c.nom AS client_nom
                FROM site_invite_tokens t
                JOIN sites s ON t.site_id = s.id
                JOIN clients c ON s.client_id = c.id
                WHERE t.token = %s
            """, [token])
            row = cur.fetchone()

    if not row or not row['actif']:
        return Response('''<!DOCTYPE html><html lang="fr"><head>
<meta charset="UTF-8"><title>Lien invalide</title>
<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5fafa}
.box{text-align:center;padding:2rem;background:white;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.1)}
h2{color:#e8641e}p{color:#666}</style></head>
<body><div class="box"><h2>Lien invalide ou expiré</h2>
<p>Ce lien d'inscription n'est plus actif.<br>Contactez votre administrateur beOtop.</p></div></body></html>''',
            mimetype='text/html; charset=utf-8')

    # Servir la page d'inscription avec les infos du site
    page = _build_register_page(token, row['site_nom'], row.get('ville',''), row.get('client_nom',''), row['site_slug'])
    return Response(page, mimetype='text/html; charset=utf-8')

def _build_register_page(token, site_nom, ville, client_nom, site_slug):
    location = f"{site_nom}" + (f" · {ville}" if ville else "") + (f" — {client_nom}" if client_nom else "")
    return f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rejoindre beOtop Companion</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"DM Sans",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(135deg,#f8fafa 0%,#e8f8f8 50%,#fff5f0 100%);padding:1rem}}
.card{{background:white;border-radius:20px;padding:2.5rem 2rem;width:100%;max-width:420px;
  box-shadow:0 8px 40px rgba(0,180,180,.12);border:1px solid rgba(0,180,180,.15)}}
.logo{{text-align:center;margin-bottom:1.5rem}}
.logo-txt{{font-size:1.8rem;font-weight:300;color:#00b4b4;letter-spacing:.08em}}
.logo-txt span{{color:#f5855a;font-style:italic}}
.site-badge{{display:flex;align-items:center;gap:.6rem;background:rgba(0,180,180,.08);
  border:1px solid rgba(0,180,180,.2);border-radius:10px;padding:.7rem 1rem;margin-bottom:1.5rem}}
.site-badge .icon{{font-size:1.4rem}}
.site-info .label{{font-size:.58rem;color:#7a9898;text-transform:uppercase;letter-spacing:.1em;font-weight:600}}
.site-info .name{{font-size:.88rem;color:#0d1f1f;font-weight:500;margin-top:.1rem}}
.field{{margin-bottom:1rem}}
label{{font-size:.62rem;color:#3a5858;text-transform:uppercase;letter-spacing:.1em;font-weight:600;display:block;margin-bottom:.4rem}}
input{{width:100%;padding:.7rem .9rem;border:1.5px solid rgba(0,180,180,.25);border-radius:10px;
  font-size:.9rem;font-family:inherit;color:#0d1f1f;outline:none;transition:border-color .2s;background:#fafefe}}
input:focus{{border-color:#00b4b4;background:white}}
.btn{{width:100%;padding:.85rem;border:none;border-radius:12px;
  background:linear-gradient(135deg,#f5855a,#e8641e);color:white;font-size:.9rem;
  font-weight:600;cursor:pointer;letter-spacing:.02em;margin-top:.5rem;
  box-shadow:0 4px 16px rgba(245,133,90,.35);transition:all .2s}}
.btn:hover{{transform:translateY(-1px);box-shadow:0 6px 20px rgba(245,133,90,.45)}}
.btn:disabled{{opacity:.6;cursor:not-allowed;transform:none}}
.msg{{text-align:center;font-size:.78rem;margin-top:.8rem;min-height:1.2em}}
.msg.ok{{color:#00b4b4;font-weight:500}}
.msg.err{{color:#e8641e;font-weight:500}}
.login-link{{text-align:center;margin-top:1.2rem;font-size:.72rem;color:#7a9898}}
.login-link a{{color:#00b4b4;font-weight:500;text-decoration:none}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-txt">beOtop <span>Companion</span></div>
    <div style="font-size:.7rem;color:#7a9898;margin-top:.3rem">Votre espace bien-être digital</div>
  </div>

  <div class="site-badge">
    <div class="icon">🏢</div>
    <div class="site-info">
      <div class="label">Votre espace</div>
      <div class="name">{location}</div>
    </div>
  </div>

  <div class="field">
    <label>Prénom et Nom</label>
    <input type="text" id="reg-nom" placeholder="Marie Dupont" autocomplete="name" required>
  </div>
  <div class="field">
    <label>Adresse e-mail professionnelle</label>
    <input type="email" id="reg-email" placeholder="marie.dupont@entreprise.fr" autocomplete="email" required>
  </div>
  <div class="field">
    <label>Mot de passe</label>
    <input type="password" id="reg-pw" placeholder="8 caractères minimum" autocomplete="new-password" required>
  </div>
  <div class="field">
    <label>Confirmer le mot de passe</label>
    <input type="password" id="reg-pw2" placeholder="Répétez votre mot de passe" autocomplete="new-password" required>
  </div>

  <button class="btn" id="reg-btn" onclick="doRegister()">Créer mon compte →</button>
  <div class="msg" id="reg-msg"></div>
  <div class="login-link">Déjà un compte ? <a href="/companion">Se connecter</a></div>
</div>

<script>
function doRegister() {{
  var nom   = document.getElementById('reg-nom').value.trim();
  var email = document.getElementById('reg-email').value.trim();
  var pw    = document.getElementById('reg-pw').value;
  var pw2   = document.getElementById('reg-pw2').value;
  var msg   = document.getElementById('reg-msg');
  var btn   = document.getElementById('reg-btn');

  if (!nom || !email || !pw) {{ msg.className='msg err'; msg.textContent='Tous les champs sont requis.'; return; }}
  if (pw.length < 8) {{ msg.className='msg err'; msg.textContent='Mot de passe trop court (8 caractères min).'; return; }}
  if (pw !== pw2) {{ msg.className='msg err'; msg.textContent='Les mots de passe ne correspondent pas.'; return; }}

  btn.disabled = true; btn.textContent = 'Création en cours…';
  msg.textContent = '';

  fetch('/api/auth/register', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{ nom: nom, email: email, password: pw, token: '{token}' }})
  }})
  .then(function(r) {{ return r.json().then(function(d) {{ return {{ok:r.ok, d:d}}; }}); }})
  .then(function(res) {{
    if (res.ok) {{
      msg.className='msg ok';
      msg.textContent='✓ Compte créé ! Redirection…';
      setTimeout(function(){{ window.location.href='/companion'; }}, 1500);
    }} else {{
      msg.className='msg err';
      msg.textContent = res.d.error || "Erreur lors de l'inscription.";
      btn.disabled=false; btn.textContent='Créer mon compte →';
    }}
  }})
  .catch(function() {{
    msg.className='msg err'; msg.textContent='Erreur réseau. Réessayez.';
    btn.disabled=false; btn.textContent='Créer mon compte →';
  }});
}}

// Entrée = soumettre
document.addEventListener('keydown', function(e){{ if(e.key==='Enter') doRegister(); }});
</script>
</body>
</html>'''

@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    """Inscription via token d'invitation"""
    data = request.get_json() or {}
    token    = (data.get('token') or '').strip()
    nom      = (data.get('nom') or '').strip()[:100]
    email    = (data.get('email') or '').strip().lower()[:200]
    password = (data.get('password') or '')

    if not all([token, nom, email, password]):
        return jsonify({'error': 'Champs manquants'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Mot de passe trop court (8 caractères min)'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            # Vérifier token
            cur.execute("""
                SELECT t.site_id, t.site_slug, t.id AS token_id, s.client_id
                FROM site_invite_tokens t
                JOIN sites s ON t.site_id = s.id
                WHERE t.token = %s AND t.actif = 1
            """, [token])
            tok = cur.fetchone()
            if not tok:
                return jsonify({'error': 'Lien invitation invalide ou expire'}), 403

            # Vérifier email unique
            cur.execute("SELECT id FROM users WHERE email=%s", [email])
            if cur.fetchone():
                return jsonify({'error': 'Cette adresse e-mail est deja utilisee'}), 409

            # Créer l'utilisateur
            pw_hash = generate_password_hash(password)
            cur.execute("""
                INSERT INTO users (email, password, nom, role, client_id, actif)
                VALUES (%s, %s, %s, 'client', %s, 1)
                RETURNING id
            """, [email, pw_hash, nom, tok['client_id']])
            user_id = cur.fetchone()['id']

            # Incrémenter compteur inscriptions
            cur.execute("UPDATE site_invite_tokens SET nb_inscrits=nb_inscrits+1 WHERE id=%s", [tok['token_id']])
            conn.commit()

    # Auto-login après inscription - effacer toute session existante
    session.clear()
    session['user_id'] = user_id
    session['role'] = 'client'
    session['client_id'] = tok['client_id']
    return jsonify({'ok': True, 'user_id': user_id})


@app.route('/audio/<path:filename>')
def serve_audio(filename):
    """Sert les fichiers audio depuis /static/ avec headers corrects"""
    import mimetypes
    path = os.path.join(BASE_DIR, 'static', filename)
    if not os.path.exists(path):
        return jsonify({'error': 'Fichier introuvable'}), 404
    mime = mimetypes.guess_type(path)[0] or 'audio/mpeg'
    response = send_from_directory(os.path.join(BASE_DIR, 'static'), filename, mimetype=mime)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Accept-Ranges'] = 'bytes'
    response.headers['Cache-Control'] = 'public, max-age=86400'
    return response



# ========== COMPANION ANALYTICS (dashboard client) ==========

@app.route('/api/dashboard/companion-analytics', methods=['GET'])
@login_required
def companion_analytics():
    """Analytics Companion pour l'onglet dashboard client."""
    site_slug = request.args.get('site_slug')
    days      = int(request.args.get('days', 30))

    with get_db() as conn:
        with conn.cursor() as cur:

            # Utilisateurs actifs
            cur.execute("""
                SELECT COUNT(DISTINCT user_id) as n
                FROM companion_points
                WHERE site_slug = %s
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
            """, [site_slug, days])
            users_actifs = (cur.fetchone() or {}).get('n', 0)

            # Utilisateurs total
            cur.execute("""
                SELECT COUNT(DISTINCT u.id) as n
                FROM users u
                JOIN clients c ON u.client_id = c.id
                JOIN sites s ON s.client_id = c.id
                WHERE s.slug = %s
            """, [site_slug])
            users_total = (cur.fetchone() or {}).get('n', 0)

            # Sessions totales
            cur.execute("""
                SELECT COUNT(*) as n FROM companion_points
                WHERE site_slug = %s
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
            """, [site_slug, days])
            sessions_total = (cur.fetchone() or {}).get('n', 0)

            # Check-ins
            cur.execute("""
                SELECT COUNT(*) as nb,
                       ROUND(AVG(energie),1) as avg_energie,
                       ROUND(AVG(stress),1)  as avg_stress,
                       ROUND(AVG(focus),1)   as avg_focus
                FROM companion_checkins
                WHERE site_slug = %s
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
            """, [site_slug, days])
            row = cur.fetchone() or {}
            nb_checkins = row.get('nb', 0)
            avg_energie = row.get('avg_energie', 0)
            avg_stress  = row.get('avg_stress', 0)
            avg_focus   = row.get('avg_focus', 0)

            # Cohérence cardiaque
            cur.execute("""
                SELECT COUNT(*) as nb, COALESCE(SUM(duree_min),0) as minutes
                FROM companion_cc_sessions
                WHERE site_slug = %s
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
            """, [site_slug, days])
            cc_row     = cur.fetchone() or {}
            nb_cc      = cc_row.get('nb', 0)
            cc_minutes = cc_row.get('minutes', 0)

            # Livre d'or
            cur.execute("""
                SELECT COUNT(*) as nb FROM companion_livreor
                WHERE site_slug = %s
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
            """, [site_slug, days])
            nb_livreor = (cur.fetchone() or {}).get('nb', 0)

            # Répartition activités
            cur.execute("""
                SELECT action, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                GROUP BY action ORDER BY nb DESC LIMIT 8
            """, [site_slug, days])
            actions_repartition = [serialize_row(r) for r in cur.fetchall()]

            # Activité par jour de semaine
            cur.execute("""
                SELECT EXTRACT(DOW FROM created_at)::int as dow, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                GROUP BY dow ORDER BY dow
            """, [site_slug, days])
            weekdays = [serialize_row(r) for r in cur.fetchall()]

            # Timeline 12 mois
            cur.execute("""
                SELECT TO_CHAR(DATE_TRUNC('month', created_at), 'Mon') as label,
                       COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s
                AND created_at >= CURRENT_DATE - INTERVAL '12 months'
                GROUP BY DATE_TRUNC('month', created_at), label
                ORDER BY DATE_TRUNC('month', created_at)
            """, [site_slug])
            timeline = [serialize_row(r) for r in cur.fetchall()]

            # ── Top contenus par type ──
            # Audio
            cur.execute("""
                SELECT label, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s AND action = 'audio'
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                AND label IS NOT NULL AND label != 'audio'
                GROUP BY label ORDER BY nb DESC LIMIT 5
            """, [site_slug, days])
            top_audio = [serialize_row(r) for r in cur.fetchall()]

            # Vidéo
            cur.execute("""
                SELECT label, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s AND action = 'video'
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                AND label IS NOT NULL AND label != 'video'
                GROUP BY label ORDER BY nb DESC LIMIT 5
            """, [site_slug, days])
            top_video = [serialize_row(r) for r in cur.fetchall()]

            # Exercices
            cur.execute("""
                SELECT label, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s AND action = 'exercice'
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                AND label IS NOT NULL AND label != 'exercice'
                GROUP BY label ORDER BY nb DESC LIMIT 5
            """, [site_slug, days])
            top_exercices = [serialize_row(r) for r in cur.fetchall()]

            # Sons
            cur.execute("""
                SELECT label, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s AND action = 'sons'
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                AND label IS NOT NULL AND label != 'sons'
                GROUP BY label ORDER BY nb DESC LIMIT 5
            """, [site_slug, days])
            top_sons = [serialize_row(r) for r in cur.fetchall()]

            # Jeux cognitifs
            cur.execute("""
                SELECT label, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s AND action = 'jeu'
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                AND label IS NOT NULL AND label != 'jeu'
                GROUP BY label ORDER BY nb DESC LIMIT 5
            """, [site_slug, days])
            top_jeux = [serialize_row(r) for r in cur.fetchall()]

            # Cohérence cardiaque
            cur.execute("""
                SELECT label, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s AND action = 'cc'
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                AND label IS NOT NULL AND label != 'cc'
                GROUP BY label ORDER BY nb DESC LIMIT 5
            """, [site_slug, days])
            top_cc = [serialize_row(r) for r in cur.fetchall()]

            # Podcasts
            cur.execute("""
                SELECT label, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s AND action = 'podcast'
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                AND label IS NOT NULL AND label != 'podcast'
                GROUP BY label ORDER BY nb DESC LIMIT 5
            """, [site_slug, days])
            top_podcast = [serialize_row(r) for r in cur.fetchall()]

            # Posts internes
            cur.execute("""
                SELECT label, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s AND action = 'posts'
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                AND label IS NOT NULL AND label != 'posts'
                GROUP BY label ORDER BY nb DESC LIMIT 5
            """, [site_slug, days])
            top_posts = [serialize_row(r) for r in cur.fetchall()]

            # Top global toutes catégories confondues
            cur.execute("""
                SELECT action, label, COUNT(*) as nb
                FROM companion_points
                WHERE site_slug = %s
                AND created_at >= CURRENT_DATE - (%s * INTERVAL '1 day')
                AND label IS NOT NULL
                AND label NOT IN ('audio','video','exercice','sons','jeu','checkin','cc','reservation')
                GROUP BY action, label ORDER BY nb DESC LIMIT 10
            """, [site_slug, days])
            top_global = [serialize_row(r) for r in cur.fetchall()]

    return jsonify({
        'users_actifs':        users_actifs,
        'users_total':         users_total,
        'sessions_total':      sessions_total,
        'nb_checkins':         nb_checkins,
        'avg_energie':         float(avg_energie) if avg_energie else 0,
        'avg_stress':          float(avg_stress)  if avg_stress  else 0,
        'avg_focus':           float(avg_focus)   if avg_focus   else 0,
        'nb_cc':               nb_cc,
        'cc_minutes':          cc_minutes,
        'nb_livreor':          nb_livreor,
        'actions_repartition': actions_repartition,
        'top_actions':         actions_repartition[:6],
        'weekdays':            weekdays,
        'timeline':            timeline,
        'top_audio':           top_audio,
        'top_video':           top_video,
        'top_exercices':       top_exercices,
        'top_sons':            top_sons,
        'top_jeux':            top_jeux,
        'top_cc':              top_cc,
        'top_podcast':         top_podcast,
        'top_posts':           top_posts,
        'top_global':          top_global,
    })


@app.route('/api/v1/correlation', methods=['GET'])
@login_required
def v1_correlation():
    site_slug = request.args.get('site_slug')
    period    = request.args.get('period', 'month')
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    if session.get('role') != 'admin':
        client_id = session.get('client_id')
        mgr_site_id = session.get('site_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                if mgr_site_id:
                    cur.execute("SELECT slug FROM sites WHERE id=%s AND client_id=%s", [mgr_site_id, client_id])
                else:
                    cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                slugs = [r['slug'] for r in cur.fetchall()]
        if site_slug not in slugs:
            return jsonify({'error': 'Accès refusé'}), 403
    period_clauses = {
        'today': "s.created_at >= CURRENT_DATE",
        'week':  "s.created_at >= NOW() - INTERVAL '7 days'",
        'month': "s.created_at >= NOW() - INTERVAL '30 days'",
        'ytd':   "s.created_at >= DATE_TRUNC('year', CURRENT_DATE)",
    }
    ts_clause = period_clauses.get(period, period_clauses['month'])
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT
                    split_part(s.ateliers, ',', 1) as atelier,
                    COUNT(*) as n,
                    ROUND(100.0 * COUNT(CASE WHEN s.mood IN ('Rechargé','Mieux') THEN 1 END) / COUNT(*), 1) as taux_recuperation,
                    ROUND(AVG(ss.duree_sec)/60.0, 1) as duree_moy_min,
                    COUNT(CASE WHEN s.mood = 'Mieux'    THEN 1 END) as n_mieux,
                    COUNT(CASE WHEN s.mood = 'Rechargé' THEN 1 END) as n_recharge,
                    COUNT(CASE WHEN s.mood = 'Neutre'   THEN 1 END) as n_neutre,
                    COUNT(CASE WHEN s.mood = 'Épuisé'   THEN 1 END) as n_epuise
                FROM sessions s
                JOIN sensor_sessions ss
                    ON ss.site_slug = s.site_slug
                    AND ss.atelier ILIKE '%%' || split_part(s.ateliers, ',', 1) || '%%'
                    AND (s.date + s.heure) BETWEEN ss.debut - INTERVAL '45 min'
                                                AND ss.fin   + INTERVAL '45 min'
                WHERE s.site_slug = %s
                    AND {ts_clause}
                    AND s.mood IS NOT NULL
                    AND s.ateliers IS NOT NULL
                    AND ss.duree_sec > 180
                GROUP BY split_part(s.ateliers, ',', 1)
                HAVING COUNT(*) >= 3
                ORDER BY taux_recuperation DESC
            """, [site_slug])
            ateliers = [serialize_row(r) for r in cur.fetchall()]
            cur.execute(f"""
                SELECT
                    COUNT(*) as n_total,
                    ROUND(100.0 * COUNT(CASE WHEN s.mood IN ('Rechargé','Mieux') THEN 1 END) / COUNT(*), 1) as score_global,
                    ROUND(AVG(ss.duree_sec)/60.0, 1) as duree_moy_globale
                FROM sessions s
                JOIN sensor_sessions ss
                    ON ss.site_slug = s.site_slug
                    AND ss.atelier ILIKE '%%' || split_part(s.ateliers, ',', 1) || '%%'
                    AND (s.date + s.heure) BETWEEN ss.debut - INTERVAL '45 min'
                                                AND ss.fin   + INTERVAL '45 min'
                WHERE s.site_slug = %s
                    AND {ts_clause}
                    AND s.mood IS NOT NULL
                    AND s.ateliers IS NOT NULL
                    AND ss.duree_sec > 180
            """, [site_slug])
            global_row = serialize_row(cur.fetchone())
            # Score de récupération Companion — delta énergie/stress/focus
            # Principe : check-in Companion dans les 2h précédant une session kiosque
            # = mood objectif avant. Session kiosque = mood déclaré après.
            cur.execute(f"""
                SELECT
                    COUNT(*) as n_companion,
                    ROUND(AVG(cc.energie), 1) as energie_moy_avant,
                    ROUND(AVG(cc.stress), 1) as stress_moy_avant,
                    ROUND(AVG(cc.focus), 1) as focus_moy_avant,
                    ROUND(100.0 * COUNT(
                        CASE WHEN s.mood IN ('Rechargé','Mieux') THEN 1 END
                    ) / NULLIF(COUNT(*), 0), 1) as taux_recuperation_companion,
                    ROUND(AVG(
                        CASE WHEN s.mood = 'Mieux'    THEN 10
                             WHEN s.mood = 'Rechargé' THEN 7
                             WHEN s.mood = 'Neutre'   THEN 4
                             WHEN s.mood = 'Épuisé'   THEN 1
                        END
                    ), 1) as score_mood_sortie
                FROM companion_checkins cc
                JOIN sessions s
                    ON s.site_slug = cc.site_slug
                    AND (s.date + s.heure) BETWEEN cc.created_at
                                                AND cc.created_at + INTERVAL '2 hours'
                WHERE cc.site_slug = %s
                    AND {ts_clause.replace('s.created_at', 'cc.created_at')}
                    AND cc.energie IS NOT NULL
                    AND s.mood IS NOT NULL
            """, [site_slug])
            companion_row = serialize_row(cur.fetchone()) or {}
    return jsonify({
        'site_slug':    site_slug,
        'period':       period,
        'score_global': global_row.get('score_global', 0),
        'n_total':      global_row.get('n_total', 0),
        'duree_moy':    global_row.get('duree_moy_globale', 0),
        'ateliers':     ateliers,
        'methode':      'croisement kiosque×PIR ±45min, sessions>3min, n≥3',
        'companion_correlation': {
            'n':                 companion_row.get('n_companion', 0),
            'energie_moy_avant': companion_row.get('energie_moy_avant', 0),
            'stress_moy_avant':  companion_row.get('stress_moy_avant', 0),
            'focus_moy_avant':   companion_row.get('focus_moy_avant', 0),
            'taux_recuperation': companion_row.get('taux_recuperation_companion', 0),
            'score_mood_sortie': companion_row.get('score_mood_sortie', 0),
            'interpretation':    'check-in Companion ±2h avant session kiosque',
        },
    })


@app.route('/api/v1/companion-impact', methods=['GET'])
@login_required
def v1_companion_impact():
    """
    Calcule l'impact de l'usage Companion sur la récupération.
    Compare les sessions kiosque précédées d'un check-in Companion
    vs les sessions sans check-in préalable.
    """
    site_slug = request.args.get('site_slug')
    period    = request.args.get('period', 'month')
    if not site_slug:
        return jsonify({'error': 'site_slug requis'}), 400
    # Contrôle accès identique à v1_correlation
    if session.get('role') not in ('admin', 'demo'):
        client_id = session.get('client_id')
        mgr_site_id = session.get('site_id')
        with get_db() as conn:
            with conn.cursor() as cur:
                if mgr_site_id:
                    cur.execute("SELECT slug FROM sites WHERE id=%s AND client_id=%s", [mgr_site_id, client_id])
                else:
                    cur.execute("SELECT slug FROM sites WHERE client_id=%s", [client_id])
                slugs = [r['slug'] for r in cur.fetchall()]
        if site_slug not in slugs:
            return jsonify({'error': 'Accès refusé'}), 403
    period_clauses = {
        'today': "s.created_at >= CURRENT_DATE",
        'week':  "s.created_at >= NOW() - INTERVAL '7 days'",
        'month': "s.created_at >= NOW() - INTERVAL '30 days'",
        'ytd':   "s.created_at >= DATE_TRUNC('year', CURRENT_DATE)",
    }
    ts_clause = period_clauses.get(period, period_clauses['month'])
    with get_db() as conn:
        with conn.cursor() as cur:
            # Sessions AVEC check-in Companion préalable
            cur.execute(f"""
                SELECT
                    COUNT(*) as n,
                    ROUND(100.0 * COUNT(
                        CASE WHEN s.mood IN ('Rechargé','Mieux') THEN 1 END
                    ) / NULLIF(COUNT(*), 0), 1) as taux_recuperation,
                    ROUND(AVG(cc.energie), 1) as energie_avant,
                    ROUND(AVG(cc.stress), 1) as stress_avant
                FROM sessions s
                JOIN companion_checkins cc
                    ON cc.site_slug = s.site_slug
                    AND cc.created_at BETWEEN (s.date + s.heure) - INTERVAL '2 hours'
                                          AND (s.date + s.heure)
                WHERE s.site_slug = %s
                    AND {ts_clause}
                    AND s.mood IS NOT NULL
            """, [site_slug])
            avec_companion = serialize_row(cur.fetchone()) or {}

            # Sessions SANS check-in Companion préalable
            cur.execute(f"""
                SELECT
                    COUNT(*) as n,
                    ROUND(100.0 * COUNT(
                        CASE WHEN s.mood IN ('Rechargé','Mieux') THEN 1 END
                    ) / NULLIF(COUNT(*), 0), 1) as taux_recuperation
                FROM sessions s
                WHERE s.site_slug = %s
                    AND {ts_clause}
                    AND s.mood IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM companion_checkins cc
                        WHERE cc.site_slug = s.site_slug
                        AND cc.created_at BETWEEN (s.date + s.heure) - INTERVAL '2 hours'
                                              AND (s.date + s.heure)
                    )
            """, [site_slug])
            sans_companion = serialize_row(cur.fetchone()) or {}

            # Evolution score énergie/stress sur la période (timeline)
            cur.execute(f"""
                SELECT
                    DATE_TRUNC('week', created_at) as semaine,
                    ROUND(AVG(energie), 1) as energie_moy,
                    ROUND(AVG(stress), 1) as stress_moy,
                    ROUND(AVG(focus), 1) as focus_moy,
                    COUNT(*) as n_checkins
                FROM companion_checkins
                WHERE site_slug = %s
                    AND {ts_clause.replace('s.created_at', 'created_at')}
                    AND energie IS NOT NULL
                GROUP BY DATE_TRUNC('week', created_at)
                ORDER BY semaine ASC
            """, [site_slug])
            timeline = [serialize_row(r) for r in cur.fetchall()]

    # Delta taux récupération avec vs sans Companion
    taux_avec  = float(avec_companion.get('taux_recuperation') or 0)
    taux_sans  = float(sans_companion.get('taux_recuperation') or 0)
    delta      = round(taux_avec - taux_sans, 1)

    return jsonify({
        'site_slug':        site_slug,
        'period':           period,
        'avec_companion':   avec_companion,
        'sans_companion':   sans_companion,
        'delta_recuperation': delta,
        'timeline':         timeline,
        'interpretation':   'Sessions précédées check-in ±2h vs sessions sans check-in',
    })


@app.route('/demo')
def demo_access():
    """
    Connecte automatiquement tout visiteur en lecture seule sur demo-beotop.
    Pas de mot de passe. Redirige vers /dashboard.
    Rôle 'demo' : accès lecture seule, pas d'écriture, pas de back-office.
    """
    session.clear()
    session['user_id'] = 0
    session['role'] = 'demo'
    session['client_id'] = 18
    session['nom'] = 'Visiteur démo'
    session['email'] = 'demo@beotop.fr'
    return redirect('/dashboard')


@app.route('/demo-pwa')
def demo_pwa_access():
    """
    Accès public sans mot de passe au Companion PWA en lecture seule.
    Même logique que /demo mais redirige vers /companion_pwa.
    """
    session.clear()
    session['user_id'] = 0
    session['role'] = 'demo'
    session['client_id'] = 18
    session['nom'] = 'Visiteur démo'
    session['email'] = 'demo@beotop.fr'
    return redirect('/companion_pwa')


# Garde-fou global du mode démo : verrouille toute écriture et le back-office.
# Centralisé ici (plutôt que route par route) pour garantir qu'aucune route
# d'écriture POST/PUT/PATCH/DELETE ne puisse jamais être atteinte en démo.
_DEMO_WRITE_OK = {'/api/auth/login', '/api/auth/logout'}

@app.before_request
def _demo_guard():
    if session.get('role') != 'demo':
        return  # comportement inchangé pour les sessions authentifiées / anonymes
    path = request.path or ''
    # Connexion réelle / déconnexion : autorisées (n'écrivent pas de données métier).
    if path in _DEMO_WRITE_OK:
        return
    # Lecture seule stricte : aucune écriture en base.
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        return jsonify({'error': 'Accès démo — lecture seule'}), 403
    # Back-office interdit en démo : on renvoie vers le dashboard.
    if path == '/admin' or path.startswith('/api/admin'):
        return redirect('/dashboard')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
