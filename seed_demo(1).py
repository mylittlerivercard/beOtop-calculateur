#!/usr/bin/env python3
"""
beOtop — Script d'injection de données de démonstration
Période : 8 avril 2026 → 6 mai 2026
Tables alimentées : sessions, sensor_passages, sensor_occupation, sensor_sessions

Usage :
  DATABASE_URL=postgres://... python3 seed_demo.py
  python3 seed_demo.py --dry-run       # affiche les stats sans insérer
  python3 seed_demo.py --wipe          # supprime d'abord les données existantes sur la période
  python3 seed_demo.py --site dmmf-agde
"""

import os
import sys
import random
import argparse
from datetime import date, datetime, time, timedelta

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SITE_SLUG  = 'dmmf-agde'   # modifiable via --site
DATE_START = date(2026, 4, 8)
DATE_END   = date(2026, 5, 6)

random.seed(42)  # reproductibilité

# ── Référentiel ateliers ──────────────────────────────────────────────────────
ATELIERS = [
    'meridienne-p127',
    'cocon-sieste',
    'lit-neurosonic',
    'siege-massant-127',
    'transat-127',
    'siege-shiatsu',
    'siege-lecture',
    'bol-air',
]

# Poids d'usage par atelier — calés sur les taux d'occupation réels
# meridienne 22.8%, cocon 22.3%, transat 15.8%, siege-massant 15.6%,
# siege-shiatsu 11.7%, siege-lecture 11.1%, lit-neurosonic 18.9%, bol-air 5.4%
ATELIER_WEIGHTS = [23, 22, 19, 16, 16, 12, 11, 5]

# ── Référentiel départements ──────────────────────────────────────────────────
DEPARTEMENTS = [
    ('RH',          24),
    ('Finance',     18),
    ('Marketing',   14),
    ('IT',          14),
    ('Direction',   13),
    ('Commercial',  11),
    ('Operations',   6),
]
DEPT_NAMES   = [d[0] for d in DEPARTEMENTS]
DEPT_WEIGHTS = [d[1] for d in DEPARTEMENTS]

# ── Moods kiosque ─────────────────────────────────────────────────────────────
# Distribution réaliste : majorité positive, quelques épuisés en début de semaine
MOODS = ['Épuisé', 'Neutre', 'Mieux', 'Rechargé']

def mood_weights(weekday, hour):
    """Poids du mood selon le jour et l'heure — réalisme comportemental."""
    if weekday == 0:   # lundi : plus d'épuisés
        base = [15, 25, 35, 25]
    elif weekday == 4: # vendredi : plus de rechargés
        base = [5, 18, 37, 40]
    else:
        base = [8, 20, 38, 34]
    # Matin (< 10h) : légèrement plus épuisé
    if hour < 10:
        base[0] = min(base[0] + 5, 25)
        base[3] = max(base[3] - 5, 15)
    return base

# ── Profil horaire d'affluence ────────────────────────────────────────────────
# Poids par heure (7h à 19h)
HOUR_WEIGHTS = {
    7:  2,  8:  8,  9: 14, 10: 12, 11: 10,
    12: 6,  13: 9,  14: 13, 15: 12, 16: 11,
    17: 8,  18: 4,  19: 1,
}
HOURS = sorted(HOUR_WEIGHTS.keys())
H_WEIGHTS = [HOUR_WEIGHTS[h] for h in HOURS]

# ── Volume de séances par semaine (adoption progressive) ─────────────────────
# Semaine 1 (08/04) : démarrage timide
# Semaine 2 (13/04) : montée
# Semaine 3 (22/04) : pic
# Semaine 4 (28/04) : consolidation légèrement au-dessus
WEEK_SESSIONS = {
    1: 12,   # sem 1 : 12 séances/jour en moy
    2: 18,   # sem 2
    3: 26,   # sem 3 : pic (com interne ?)
    4: 22,   # sem 4 : consolidation
    5: 24,   # sem 5 : partielle (6 mai)
}

# Variabilité jour de semaine (multiplicateur)
DAY_MULT = {0: 0.8, 1: 1.1, 2: 1.0, 3: 1.15, 4: 0.95}

# Ateliers préférés par département (pour cohérence cross-stats)
DEPT_ATELIER_PREF = {
    'RH':         [0, 1, 3],   # meridienne, cocon-sieste, siege-massant
    'Finance':    [1, 4, 2],   # cocon-sieste, transat, lit-neurosonic
    'Marketing':  [0, 5, 6],   # meridienne, siege-shiatsu, siege-lecture
    'IT':         [2, 3, 0],   # lit-neurosonic, siege-massant, meridienne
    'Direction':  [0, 4, 3],   # meridienne, transat, siege-massant
    'Commercial': [0, 1, 5],   # meridienne, cocon-sieste, siege-shiatsu
    'Operations': [3, 6, 7],   # siege-massant, siege-lecture, bol-air
}

def pick_atelier(dept):
    """Sélectionne 1 ou 2 ateliers selon les préférences du département."""
    prefs = DEPT_ATELIER_PREF.get(dept, list(range(len(ATELIERS))))
    # 70% : 1 atelier, 30% : 2 ateliers
    n = 2 if random.random() < 0.30 else 1
    # 75% chance de choisir parmi les préférences, 25% aléatoire
    result = []
    for _ in range(n):
        if random.random() < 0.75 and prefs:
            idx = random.choice(prefs)
        else:
            idx = random.choices(range(len(ATELIERS)), weights=ATELIER_WEIGHTS)[0]
        at = ATELIERS[idx]
        if at not in result:
            result.append(at)
    return result

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITAIRES
# ═══════════════════════════════════════════════════════════════════════════════

def get_workdays():
    days = []
    d = DATE_START
    while d <= DATE_END:
        if d.weekday() < 5:
            days.append(d)
        d += timedelta(days=1)
    return days

def week_num(d):
    """Semaine numérotée à partir de DATE_START."""
    delta = (d - DATE_START).days
    return delta // 7 + 1

def rand_time(hour):
    """Heure aléatoire dans le créneau donné (heure pile ± 55 min)."""
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return time(hour, minute, second)

def rand_dt(d, hour):
    """Datetime aléatoire dans le créneau donné."""
    t = rand_time(hour)
    return datetime(d.year, d.month, d.day, t.hour, t.minute, t.second)

# ═══════════════════════════════════════════════════════════════════════════════
# GÉNÉRATION
# ═══════════════════════════════════════════════════════════════════════════════

def _gen_kiosk(slug, site_id=1):
    """Génère les sessions kiosque — table sessions."""
    rows = []
    for d in get_workdays():
        wk = week_num(d)
        base = WEEK_SESSIONS.get(wk, 20)
        mult = DAY_MULT.get(d.weekday(), 1.0)
        # Variation aléatoire ±20%
        n_sessions = max(3, int(base * mult * random.uniform(0.8, 1.2)))

        for _ in range(n_sessions):
            hour = random.choices(HOURS, weights=H_WEIGHTS)[0]
            dept = random.choices(DEPT_NAMES, weights=DEPT_WEIGHTS)[0]
            ateliers = pick_atelier(dept)
            mw = mood_weights(d.weekday(), hour)
            mood = random.choices(MOODS, weights=mw)[0]
            t = rand_time(hour)
            rows.append((
                d,                    # date
                t.strftime('%H:%M'),  # heure
                dept,                 # departement
                ', '.join(ateliers),  # ateliers
                mood,                 # mood
                site_id,              # site_id
                slug,                 # site_slug
            ))
    return rows

def _gen_passages(slug):
    """
    Génère les passages faisceau — table sensor_passages.
    Logique : chaque séance kiosque génère 1 entrée + 1 sortie (± décalage),
    plus des passages sans séance (visites rapides, 30% du total).
    """
    rows = []
    for d in get_workdays():
        wk = week_num(d)
        base = WEEK_SESSIONS.get(wk, 20)
        mult = DAY_MULT.get(d.weekday(), 1.0)
        n_core = max(3, int(base * mult * random.uniform(0.85, 1.15)))

        # Passages liés à des séances (entrée + sortie)
        for _ in range(n_core):
            hour = random.choices(HOURS, weights=H_WEIGHTS)[0]
            dt_entree = rand_dt(d, hour)
            # Durée de visite : 10-35 min
            duree = random.randint(10, 35) * 60
            dt_sortie = dt_entree + timedelta(seconds=duree)

            if dt_sortie.date() == d:  # ne pas déborder sur le lendemain
                rows.append((slug, 'entree', dt_entree))
                rows.append((slug, 'sortie', dt_sortie))
            else:
                rows.append((slug, 'entree', dt_entree))

        # Passages rapides sans séance kiosque (curiosité, visite éclair)
        n_extra = max(0, int(n_core * 0.3 * random.uniform(0.5, 1.5)))
        for _ in range(n_extra):
            hour = random.choices(HOURS, weights=H_WEIGHTS)[0]
            dt = rand_dt(d, hour)
            rows.append((SITE_SLUG, None, dt))

    return rows

def _gen_occupation(slug):
    """
    Génère les signaux PIR d'occupation — table sensor_occupation.
    Logique : pour chaque atelier, signal toutes les 60 secondes quand occupé.
    Modélise des sessions chevauchantes selon l'affluence de la journée.
    """
    rows = []
    for d in get_workdays():
        wk = week_num(d)
        base = WEEK_SESSIONS.get(wk, 20)
        mult = DAY_MULT.get(d.weekday(), 1.0)
        # Nombre de sessions par atelier dans la journée
        sessions_total = max(3, int(base * mult))

        for at_idx, atelier in enumerate(ATELIERS):
            # Chaque atelier reçoit une fraction des sessions totales
            at_weight = ATELIER_WEIGHTS[at_idx] / 100
            n_at_sessions = max(1, int(sessions_total * at_weight * random.uniform(0.7, 1.3)))

            for _ in range(n_at_sessions):
                hour = random.choices(HOURS, weights=H_WEIGHTS)[0]
                dt_start = rand_dt(d, hour)
                # Durée d'occupation : 8-30 min selon l'atelier
                if atelier in ('Sieste flash', 'Cohérence cardiaque'):
                    duree_min, duree_max = 8, 20
                elif atelier in ('Méridienne P127', 'Bain de lumière'):
                    duree_min, duree_max = 15, 35
                else:
                    duree_min, duree_max = 10, 25
                duree_sec = random.randint(duree_min * 60, duree_max * 60)

                # Émettre un signal PIR par minute pendant la session
                current = dt_start
                end_dt  = dt_start + timedelta(seconds=duree_sec)
                while current <= end_dt:
                    if current.date() == d:
                        rows.append((slug, atelier, True, current))
                    current += timedelta(seconds=60)

                # Quelques signaux inactifs après (atelier vide)
                n_idle = random.randint(2, 5)
                for i in range(1, n_idle + 1):
                    idle_dt = end_dt + timedelta(seconds=60 * i)
                    if idle_dt.date() == d:
                        rows.append((slug, atelier, False, idle_dt))

    return rows

def _gen_sensor_sessions(slug):
    """
    Génère les sessions capteurs calculées — table sensor_sessions.
    Une par utilisation d'atelier, avec début/fin/durée cohérents.
    """
    rows = []
    for d in get_workdays():
        wk = week_num(d)
        base = WEEK_SESSIONS.get(wk, 20)
        mult = DAY_MULT.get(d.weekday(), 1.0)
        sessions_total = max(3, int(base * mult * random.uniform(0.8, 1.1)))

        for at_idx, atelier in enumerate(ATELIERS):
            at_weight = ATELIER_WEIGHTS[at_idx] / 100
            n_at = max(1, int(sessions_total * at_weight * random.uniform(0.6, 1.4)))

            for _ in range(n_at):
                hour = random.choices(HOURS, weights=H_WEIGHTS)[0]
                debut = rand_dt(d, hour)
                if atelier in ('Sieste flash', 'Cohérence cardiaque'):
                    duree_sec = random.randint(8 * 60, 18 * 60)
                elif atelier in ('Méridienne P127', 'Bain de lumière'):
                    duree_sec = random.randint(15 * 60, 32 * 60)
                else:
                    duree_sec = random.randint(10 * 60, 25 * 60)
                fin = debut + timedelta(seconds=duree_sec)
                if fin.date() == d:
                    rows.append((slug, atelier, debut, fin, duree_sec))

    return rows

# ═══════════════════════════════════════════════════════════════════════════════
# BASE DE DONNÉES
# ═══════════════════════════════════════════════════════════════════════════════

def get_db(db_url):
    return psycopg2.connect(db_url, cursor_factory=RealDictCursor, connect_timeout=10)

def _get_site_id(conn, slug):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM sites WHERE slug=%s", [slug])
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Site '{slug}' introuvable en base. Créez-le d'abord dans l'interface admin.")
        return row['id']

def _wipe_period(conn, slug):
    """Supprime les données existantes sur la période pour éviter les doublons."""
    print(f"  Suppression des données existantes ({DATE_START} → {DATE_END})...")
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM sessions WHERE date BETWEEN %s AND %s AND site_slug=%s",
            [DATE_START, DATE_END, slug]
        )
        n1 = cur.rowcount
        cur.execute(
            "DELETE FROM sensor_passages WHERE timestamp::date BETWEEN %s AND %s AND site_slug=%s",
            [DATE_START, DATE_END, slug]
        )
        n2 = cur.rowcount
        cur.execute(
            "DELETE FROM sensor_occupation WHERE timestamp::date BETWEEN %s AND %s AND site_slug=%s",
            [DATE_START, DATE_END, slug]
        )
        n3 = cur.rowcount
        cur.execute(
            "DELETE FROM sensor_sessions WHERE debut::date BETWEEN %s AND %s AND site_slug=%s",
            [DATE_START, DATE_END, slug]
        )
        n4 = cur.rowcount
    conn.commit()
    print(f"  Supprimé : {n1} sessions kiosque, {n2} passages, {n3} signaux PIR, {n4} sessions capteurs")

def insert_sessions(conn, rows):
    sql = """
        INSERT INTO sessions (date, heure, departement, ateliers, mood, site_id, site_slug)
        VALUES %s
    """
    with conn.cursor() as cur:
        execute_values(cur, sql, rows, page_size=500)
    conn.commit()

def insert_passages(conn, rows):
    sql = """
        INSERT INTO sensor_passages (site_slug, direction, timestamp)
        VALUES %s
    """
    with conn.cursor() as cur:
        execute_values(cur, sql, rows, page_size=500)
    conn.commit()

def insert_occupation(conn, rows):
    sql = """
        INSERT INTO sensor_occupation (site_slug, atelier, occupe, timestamp)
        VALUES %s
    """
    with conn.cursor() as cur:
        execute_values(cur, sql, rows, page_size=1000)
    conn.commit()

def insert_sensor_sessions(conn, rows):
    sql = """
        INSERT INTO sensor_sessions (site_slug, atelier, debut, fin, duree_sec)
        VALUES %s
    """
    with conn.cursor() as cur:
        execute_values(cur, sql, rows, page_size=500)
    conn.commit()

# ═══════════════════════════════════════════════════════════════════════════════
# RAPPORT / DRY RUN
# ═══════════════════════════════════════════════════════════════════════════════

def print_stats(kiosk, passages, occupation, sensor_sess):
    from collections import Counter

    print()
    print("═" * 60)
    print("  APERÇU DES DONNÉES GÉNÉRÉES")
    print("═" * 60)
    print(f"  Période         : {DATE_START} → {DATE_END}")
    print(f"  Site            : {SITE_SLUG}")
    print(f"  Jours ouvrés    : {len(get_workdays())}")
    print()

    print(f"  Sessions kiosque : {len(kiosk)}")
    moods = Counter(r[4] for r in kiosk)
    total_m = sum(moods.values())
    for m in ['Rechargé', 'Mieux', 'Neutre', 'Épuisé']:
        n = moods.get(m, 0)
        pct = round(n / total_m * 100) if total_m else 0
        print(f"    {m:<12} : {n:>4} ({pct}%)")
    indice = round((moods.get('Rechargé', 0) + moods.get('Mieux', 0)) / total_m * 100) if total_m else 0
    print(f"  → Indice récupération : {indice}%")
    print()

    depts = Counter(r[2] for r in kiosk)
    print("  Répartition départements (top 5) :")
    for dept, n in depts.most_common(5):
        print(f"    {dept:<18} : {n}")
    print()

    ats = Counter()
    for r in kiosk:
        for a in r[3].split(', '):
            if a.strip():
                ats[a.strip()] += 1
    print("  Ateliers (top 5) :")
    for at, n in ats.most_common(5):
        print(f"    {at:<22} : {n}")
    print()

    # Volume par semaine
    by_week = Counter()
    for r in kiosk:
        d = r[0]
        wk = (d - DATE_START).days // 7 + 1
        by_week[wk] += 1
    print("  Volume par semaine :")
    for wk in sorted(by_week):
        print(f"    Semaine {wk} : {by_week[wk]} séances")
    print()

    print(f"  Passages faisceau  : {len(passages)}")
    dirs = Counter(r[1] for r in passages)
    print(f"    Entrées : {dirs.get('entree', 0)} | Sorties : {dirs.get('sortie', 0)} | Non renseigné : {dirs.get(None, 0)}")
    print()

    print(f"  Signaux PIR        : {len(occupation)}")
    occupe_n = sum(1 for r in occupation if r[2])
    print(f"    Occupé : {occupe_n} | Libre : {len(occupation) - occupe_n}")
    print()

    print(f"  Sessions capteurs  : {len(sensor_sess)}")
    if sensor_sess:
        durees = [r[4] for r in sensor_sess]
        print(f"    Durée moy : {round(sum(durees)/len(durees)/60, 1)} min")
        print(f"    Durée min : {min(durees)//60} min | max : {max(durees)//60} min")
    print()
    print("═" * 60)

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='beOtop — injection données démo')
    parser.add_argument('--dry-run', action='store_true', help='Affiche les stats sans insérer')
    parser.add_argument('--wipe',    action='store_true', help='Supprime les données existantes sur la période avant insertion')
    parser.add_argument('--site',    default=SITE_SLUG,   help=f'Slug du site (défaut: {SITE_SLUG})')
    args = parser.parse_args()

    slug = args.site  # slug local, pas de global

    db_url = os.environ.get('DATABASE_URL')
    if not db_url and not args.dry_run:
        print("ERREUR : variable DATABASE_URL non définie.")
        print("Usage : DATABASE_URL=postgres://... python3 seed_demo.py")
        sys.exit(1)

    print(f"\n  beOtop — Génération des données démo")
    print(f"  Site : {slug} | Période : {DATE_START} → {DATE_END}\n")

    print("  Génération en cours...")
    kiosk       = _gen_kiosk(slug)
    passages    = _gen_passages(slug)
    occupation  = _gen_occupation(slug)
    sensor_sess = _gen_sensor_sessions(slug)
    print(f"  Généré : {len(kiosk)} sessions, {len(passages)} passages, "
          f"{len(occupation)} signaux PIR, {len(sensor_sess)} sessions capteurs")

    print_stats(kiosk, passages, occupation, sensor_sess)

    if args.dry_run:
        print("  Mode dry-run : aucune insertion effectuée.\n")
        return

    print("  Connexion à la base...")
    conn = get_db(db_url)

    site_id = _get_site_id(conn, slug)
    print(f"  Site '{slug}' trouvé → id={site_id}")

    # Reconstruire kiosk avec le bon site_id
    kiosk = [(r[0], r[1], r[2], r[3], r[4], site_id, slug) for r in kiosk]

    if args.wipe:
        _wipe_period(conn, slug)

    print("  Insertion sessions kiosque...", end=' ', flush=True)
    insert_sessions(conn, kiosk)
    print(f"{len(kiosk)} lignes")

    print("  Insertion passages faisceau...", end=' ', flush=True)
    insert_passages(conn, passages)
    print(f"{len(passages)} lignes")

    print("  Insertion signaux PIR...", end=' ', flush=True)
    insert_occupation(conn, occupation)
    print(f"{len(occupation)} lignes")

    print("  Insertion sessions capteurs...", end=' ', flush=True)
    insert_sensor_sessions(conn, sensor_sess)
    print(f"{len(sensor_sess)} lignes")

    conn.close()
    print(f"\n  Terminé. Le dashboard est prêt à afficher les données.\n")


if __name__ == '__main__':
    main()
