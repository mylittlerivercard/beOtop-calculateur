# AUDIT — beOtop-calculateur

**Date :** 2026-06-24
**Périmètre :** `server.py`, `dashboard.html`, `companion.html`, `companion_pwa.html`, `admin.html`, `mon_espace.html`, `login.html`
**Méthode :** analyse statique multi-agents en parallèle (inventaire routes, inventaire appels API frontend, désync companion, code mort) **+ vérification manuelle** des affirmations critiques (sécurité, routes manquantes).
**Niveaux :** 🔴 Critique · 🟡 Avertissement · 🟢 Proposition

> **Limites méthodologiques.** Environnement sans navigateur, sans moteur JS (node absent) et sans base PostgreSQL : aucune exécution end-to-end n'a été possible. Les constats reposent sur la lecture du code. Les affirmations de sécurité et de routes manquantes ont été **revérifiées manuellement** (grep/lecture ciblée). Un faux positif d'agent (prétendu appel `/api/stats/export`) a été écarté après vérification (le frontend appelle bien `/api/export`).

---

## Résumé exécutif

| # | Constat | Niveau | Emplacement |
|---|---------|--------|-------------|
| 1 | XSS réfléchie : `site_slug` injecté non échappé dans du HTML/JS servi | 🔴 | server.py 4051, 4119 |
| 2 | Contrôle d'accès cassé : suppression de profil intervenant accessible à **tout compte connecté** | 🔴 | server.py 2911 |
| 3 | Appel frontend vers route inexistante `/api/health` → vue « Vue d'ensemble » admin cassée | 🔴 | admin.html 660 / server.py (absente) |
| 4 | CRUD `sons` et création `intervenants` : `@login_required` sans contrôle de rôle (incohérent avec les contenus) | 🟡 | server.py 2843, 3038, 3058, 3083 |
| 5 | Routes d'écriture sans authentification (kiosk/sensors/contact/register) — données falsifiables | 🟡 | server.py 1004, 1063, 1085, 1162, 3969, 4341 |
| 6 | Route orpheline : `POST /api/companion/intervenants` jamais appelée par le frontend | 🟡 | server.py 2843 |
| 7 | Désynchronisations companion.html ↔ companion_pwa.html (logout, haptic, persistance de vue) | 🟡 | voir sections |
| 8 | Code mort : 1 variable inutilisée (dashboard) + 5 tableaux inutilisés (companion ×2) | 🟡 | voir sections |

**Points positifs :** requêtes SQL paramétrées (`%s`) partout ; noms de tables dynamiques validés par whitelist (`COMPANION_CONTENT_TABLES`) → **pas d'injection SQL** ; aucune route dupliquée ; aucune fonction JS morte détectée sur les 6 fichiers HTML.

---

## server.py

### 🔴 Critique

- **XSS réfléchie via `site_slug` (lignes 4051 et 4119).**
  `serve` de `realtime.html` (route `/realtime/<site_slug>`, ligne 4040, **sans auth**) et de `kiosk` (route `/kiosk/<site_slug>`, ligne 4101, **sans auth**) injectent le segment d'URL directement dans le HTML/JS via f-string :
  ```python
  html = html.replace("const SITE = 'dmmf-agde'", f"const SITE = '{site_slug}'")   # 4051
  html = html.replace("var SITE_SLUG = ''",        f"var SITE_SLUG = '{site_slug}'") # 4119
  ```
  `site_slug` n'étant pas échappé, un payload du type `/realtime/x');<script>…</script>//` injecte du code exécuté côté client. **Correctif recommandé :** échapper avec `json.dumps(site_slug)` (produit une littérale JS sûre) au lieu d'insérer la valeur brute entre quotes.

- **Contrôle d'accès cassé — `DELETE /api/companion/intervenants/<iid>` (ligne 2911).**
  Décorée `@login_required` uniquement, **aucune vérification de rôle** ni de propriété :
  ```python
  @app.route('/api/companion/intervenants/<int:iid>', methods=['DELETE'])
  @login_required
  def companion_intervenants_delete(iid):
      ... DELETE FROM companion_intervenants WHERE id=%s ...
  ```
  N'importe quel utilisateur authentifié (y compris rôle `demo`/collaborateur) peut supprimer le profil de n'importe quel intervenant. À comparer au `PUT` (2865) qui, lui, contrôle le rôle dans le corps. **Correctif :** ajouter `@admin_required` (ou contrôle de rôle équivalent).

### 🟡 Avertissement

- **CRUD `sons` et création `intervenants` sans contrôle de rôle.**
  `POST /api/companion/intervenants` (2843), `POST/PUT/DELETE /api/companion/sons` (3038, 3058, 3083) sont protégés par `@login_required` seul. Incohérent avec les contenus (`/api/companion/contenus` et CRUD par type) qui utilisent `@intervenant_required`. Un simple compte connecté peut créer des intervenants et gérer les « sons immersifs ».

- **Routes d'écriture sans authentification.**
  - `POST /api/kiosk/<site_slug>/session` (1004) — INSERT sessions
  - `POST /api/sensors/passage` (1063), `POST /api/sensors/occupation` (1085), `POST /api/sensors/session` (1162) — INSERT données capteurs
  - `POST /api/contact` (3969) — INSERT lead + envoi e-mail (pas de captcha / rate-limit visible → risque de spam)
  - `POST /api/auth/register` (4341) — création de compte
  Les routes capteurs/kiosk sont sans-auth **par conception** (matériel terrain), mais elles sont **falsifiables** par un tiers : toute personne peut injecter de fausses séances/passages, ce qui fausse les KPI (cf. dashboard « Intensité d'usage »). Recommandation : clé partagée / token par site sur les endpoints capteurs ; rate-limit + captcha sur `/api/contact` ; vérifier que `auth_register` (4342) valide bien un token d'invitation avant création (la page `/join` l'appelle, ligne 4312).

- **Route orpheline `POST /api/companion/intervenants` (2843).**
  Aucun des 7 frontends n'émet de POST vers cette route (la création de profils passe par `/api/admin/intervenants`). Route morte côté usage — à supprimer ou à documenter.

### 🟢 Proposition

- **Routes hors périmètre des 7 fichiers (non orphelines).** `GET/POST /api/devis*` (1400, 1448, 1470) ne sont appelées par aucun des 7 fichiers, mais le sont vraisemblablement par `ROI_beOtop.html` (hors périmètre) — à confirmer, ne pas supprimer sans vérifier.
- **`GET /api/v1/companion-impact` (4778)** : bien appelée (dashboard.html 1849) → **non orpheline** (corrige un doute initial).
- **Deux tables d'intervenants distinctes** : `intervenants` (rétribution V1, routes `/api/admin/intervenants*`, `/api/intervenant/stats`) et `companion_intervenants` (profils Companion, routes `/api/companion/intervenants*`). Cohérent mais source de confusion — à documenter dans le code.
- **Aucune route dupliquée** et **aucune injection SQL** (requêtes paramétrées ; whitelist pour noms de tables dynamiques lignes ~2751).

---

## dashboard.html

### 🟡 Avertissement
- **Variable morte `cpRefreshTimer` (ligne 1838)** : déclarée `var cpRefreshTimer = null`, jamais lue ni réassignée.

### 🟢 Proposition
- Toutes les fonctions JS (~87) sont appelées.
- **Pas de bug d'export** : `exportCSV` (937) et l'export QVCT (1641) appellent correctement `/api/export` (défini server.py 1885). *(Un agent avait signalé à tort un appel `/api/stats/export` ; vérifié inexistant.)*
- L'appel `/api/v1/companion-impact` (1849) est correctement adressé.

---

## companion.html

### 🟡 Avertissement
- **Tableaux globaux inutilisés (jamais itérés ni lus) :**
  - `SANS_CAPTEUR_PIR` (4126)
  - `DUREES` (4134)
  - `CATS_VIDEO` (5754)
  - `CATS_AUDIO` (6575)
  - `CATS_EX` (6831)
- **Désynchronisation logout vs companion_pwa.html :** `logoutCompanion()` (3243) — `async/await` + redirection directe, **sans confirmation** ; côté PWA, `logoutPwa()` (10422) — `confirm('Se déconnecter ?')` + `.then/.catch`. Comportement utilisateur différent pour la même action.

### 🟢 Proposition
- Aucune fonction JS morte (≈267 fonctions, toutes appelées).

---

## companion_pwa.html

### 🟡 Avertissement
- **Mêmes tableaux globaux inutilisés que companion.html :**
  - `SANS_CAPTEUR_PIR` (5242), `DUREES` (5250), `CATS_VIDEO` (6872), `CATS_AUDIO` (7693), `CATS_EX` (7949).
- **Désynchronisations companion.html ↔ companion_pwa.html** (rappel : les deux fichiers doivent rester synchronisés) :
  - `awardPoints()` : la version PWA (6236) ajoute `haptic('medium')` — absent côté companion.html (5113). Feedback différent pour l'attribution de points.
  - `switchView()` : la PWA (4345) persiste la vue active (`sessionStorage 'beotop_last_view'`, 4349) — pas companion.html (3252). Retour d'onglet différent.
  - `renderDashboard()` : la PWA (4573) ajoute un skeleton loader ; companion.html (3474) non.
  - `logoutPwa()` vs `logoutCompanion()` (cf. section companion.html).

### 🟢 Proposition
- Aucune fonction JS morte (≈287 fonctions, toutes appelées).
- Fonctions présentes **uniquement** dans la PWA et **légitimes par conception** (UI mobile/PWA — à NE PAS porter vers companion.html) : `maybeSeedDemo` (3957, seed démo `?seed=demo|reset`), `haptic` (10453), `hideSplash` (10318), onboarding `obShowSlide/obNext/obSkip/obFinish` (10331-10362), `maybeShowOnboarding` (10383), navigation `bnavSwitch/bnavSwitchContenus` (10389-10411), drawers `openContenuDrawer/closeContenuDrawer` (10413-10420) et `openMoreDrawer/closeMoreDrawer` (10443-10450), `toggleFab/closeFab` (10463-10481), bannière install `showPwaBanner/closePwaBanner` (10588-10606), modale mdp `openPwdModal/closePwdModal/submitPwd` (10428-10441).

---

## admin.html

### 🔴 Critique
- **Appel vers une route inexistante `/api/health` (ligne 660).**
  `loadOverview()` fait un `Promise.all([... fetch('/api/health') ...])` puis lit `health.clients`, `health.sites`, `health.sessions` (lignes 666-668). **`/api/health` n'est défini nulle part dans server.py** (vérifié). Le `r.json()` sur la réponse 404 (HTML) lève une exception → `Promise.all` rejette → la vue « Vue d'ensemble » ne se remplit pas (compteurs clients/sites/sessions). **Correctif :** soit créer la route `/api/health` (renvoyant `{clients, sites, sessions}`), soit remplacer l'appel par les agrégats déjà disponibles (`/api/admin/clients`, `/api/admin/sites`, `/api/stats`).

### 🟢 Proposition
- Aucune fonction JS morte (~25), aucune variable globale morte.
- Tous les autres appels admin ciblent des routes existantes (`/api/admin/*`, `/api/stats`).

---

## mon_espace.html

### 🟢 Proposition
- Aucun code mort détecté (~32 fonctions, 8 variables globales — toutes utilisées).
- Appels API cohérents avec server.py : `/api/intervenant/stats` (599), `/api/companion/categories?type=` (878), CRUD `/api/companion/:ep` (1022/1038/1059), `/api/auth/me` (1144), `/api/companion/intervenants` GET + `/:id` PUT (1149, 1193).
- **À surveiller (cohérence API/front, faible criticité) :** la page lit de nombreux champs de `/api/intervenant/stats` (`intervenant.nom`, `nb_clics`, `pct_global`, `taux_contenu`, `clics_detail[]`, `clics_par_site[]`, `historique[]`, `clients_apportes[]`, `remuneration_estimee`, `total_commission_apport`). Une vérification ciblée de la réponse réelle de la route (server.py 3485) est conseillée pour garantir qu'aucun de ces champs n'est `undefined` (non vérifiable statiquement ici, sans base de données).

---

## login.html

### 🟢 Proposition
- Fichier minimal et propre : un seul appel `/api/auth/login` (59), lecture `d.ok` / `d.redirect` / `d.error`. Aucune fonction ni variable au niveau module, aucun code mort.

---

## Annexe — Incohérences API / frontend (synthèse cross-fichiers)

| Type | Détail | Réf. |
|------|--------|------|
| Route appelée mais inexistante | `/api/health` | admin.html 660 |
| Route définie mais non appelée (frontend) | `POST /api/companion/intervenants` | server.py 2843 |
| Faux positif écarté | `/api/stats/export` n'est PAS appelé ; `/api/export` OK | dashboard.html 937, 1641 |
| Champs réponse non vérifiables statiquement | structures de `/api/intervenant/stats`, `/api/admin/retribution/*`, `/api/companion/checkin/history`, `/api/companion/livreor` — à confirmer à l'exécution | — |

> Les incohérences au niveau **champ** (champ retourné non lu / champ attendu absent) ne peuvent être confirmées sans exécuter l'API contre la base. Elles sont signalées comme **à confirmer** plutôt qu'affirmées.
