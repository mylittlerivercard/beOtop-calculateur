# CLAUDE.md — beOtop-calculateur

Fichier de contexte permanent lu par Claude Code à chaque session. À placer à la racine du repo.

## Projet

Calculateur de ROI des solutions beOtop (QVCT / bien-être au travail). Application web :
- **Production** : be-otop-calculateur.vercel.app (Vercel)
- **Miroir** : déploiement GitHub Pages (`github-pages`)
- Logique de calcul ROI principalement en JavaScript côté client.

## Distinction d'entités — IMPÉRATIF

**beOtop** (EURL, SIREN 481 980 076, gérante Nathalie Jalenques, Paris) et **DMMF / Delta Multimedia France** (SARL, gérant Cyril Barbe, Agde) sont **deux entités juridiques distinctes**. Ne jamais les confondre dans les contenus, mentions légales, textes commerciaux ou en-têtes générés. Ce projet relève de beOtop.

## Stack

- **Backend** : Flask (`server.py`), Python — dépendances dans `requirements.txt`
- **Frontend** : pages HTML (≈ 93 %) + assets `static/`
- **Déploiement** : Vercel (prod) + GitHub Pages

## Structure des fichiers

- `server.py` — backend Flask
- `requirements.txt` — dépendances Python
- `ROI_beOtop.html` — calculateur ROI principal
- `dashboard.html` — tableau de bord
- `admin.html` / `login.html` / `mon_espace.html` — espace admin / authentification / espace utilisateur
- `beOtop_Kiosk.html` — kiosque bien-être (suivi département / session / humeur, parcours 4 écrans)
- `companion.html` / `companion_gamification.html` — companion / gamification
- `intervenants-beotop.html` — intervenants
- `beotop-solution-RH-2026.html` / `resultats_solutions_RH.html` — solutions RH
- `immobilier.html` — [À DOCUMENTER : rôle de ce fichier]
- `realtime.html` — [À DOCUMENTER : rôle de ce fichier]
- `static/` — assets (CSS, JS, images)
- `Logo_espace_beotop_baseline*.svg` — logos (version standard + version blanche)

## Commandes

Lancement local (à confirmer selon `server.py`) :

```bash
pip install -r requirements.txt
python server.py
# Vérifier le port exposé dans server.py
```

## Paramètres ROI de référence — À CONFIRMER

Valeurs issues de l'audit du calculateur (v9). **À vérifier et figer par Cyril** ; servent de garde-fou : signaler toute incohérence entre le code, ces valeurs et les supports commerciaux.

- Scénario de référence **Option B** : 400 salariés, posture Libre 60 %, médiane −10 % → **ROI +329 %**
- **CTP Option B ≈ 17 619 €/an** (après correction du coefficient de surface ×1.5 → ×2.0)
- Taux de **charges patronales : 47,5 %**
- **Base adressable : 4,382 %** de la masse salariale

> Avant tout commit modifiant un chiffre ROI : vérifier la cohérence avec ces paramètres et avec l'étude papier de référence.

## Conventions

- **Commits** : messages descriptifs, atomiques, en français. Décrire le **changement réel** — proscrire les messages génériques (« Update X.html ») et les messages déconnectés du contenu (ex. « Hello → Goodbye », références `fmt.Println` dans des fichiers HTML). Un commit = un changement cohérent.
- **Cohérence des chiffres** : les valeurs ROI affichées dans les différentes pages doivent rester alignées entre elles et avec les paramètres de référence ci-dessus.
- **Langue** : interface et contenus en français.

## Vigilance sécurité / RGPD

- **Repo PUBLIC** : ne jamais committer de secret (clé API, identifiant, mot de passe) ni de donnée personnelle. Auditer en priorité `login.html`, `admin.html`, `server.py`. Si la confidentialité est requise, passer le repo en privé.
- **RGPD** : l'app traite du bien-être au travail (données potentiellement sensibles). Pas de collecte ni de log de données personnelles identifiantes non strictement nécessaires.

## À faire en priorité (audit d'entrée)

1. Vérifier l'absence de secret en clair dans le repo public.
2. Documenter le rôle de `immobilier.html` et `realtime.html`.
3. Confirmer / figer les paramètres ROI de référence.
4. Assainir la convention de commits pour les changements à venir.
