# AUDIT — beOtop-calculateur

**Date :** 2026-06-24
**Périmètre :** `server.py`, `dashboard.html`, `companion.html`, `companion_pwa.html`, `admin.html`, `mon_espace.html`, `login.html`
**Méthode :** analyse statique multi-agents en parallèle (inventaire routes, inventaire appels API frontend, désync companion, code mort) **+ vérification manuelle** des affirmations critiques (sécurité, routes manquantes).
**Niveaux :** 🔴 Critique · 🟡 Avertissement · 🟢 Proposition · ✅ Corrigé

> **Mise à jour 2026-06-24 :** les 3 constats critiques (🔴 #1 XSS, #2 contrôle d'accès DELETE, #3 route `/api/health`) ont été **corrigés** (commits `f39a43a`, `c43053d`, `de0103d`). Voir les marqueurs ✅ ci-dessous.

> **Limites méthodologiques.** Environnement sans navigateur, sans moteur JS (node absent) et sans base PostgreSQL : aucune exécution end-to-end n'a été possible. Les constats reposent sur la lecture du code. Les affirmations de sécurité et de routes manquantes ont été **revérifiées manuellement** (grep/lecture ciblée). Un faux positif d'agent (prétendu appel `/api/stats/export`) a été écarté après vérification (le frontend appelle bien `/api/export`).

---

## Résumé exécutif

| # | Constat | Niveau | Emplacement |
|---|---------|--------|-------------|
| 1 | ~~XSS réfléchie : `site_slug` injecté non échappé dans du HTML/JS servi~~ → **corrigé** (`json.dumps`) | ✅ | server.py 4051, 4119 |
| 2 | ~~Contrôle d'accès cassé : suppression de profil intervenant accessible à tout compte connecté~~ → **corrigé** (contrôle par nom) | ✅ | server.py 2911 |
| 3 | ~~Appel frontend vers route inexistante `/api/health`~~ → **corrigé** (route créée) | ✅ | admin.html 660 / server.py 753 |
| 4 | ~~CRUD `sons` et création `intervenants` sans contrôle de rôle~~ → **corrigé** (`@intervenant_required`) | ✅ | server.py |
| 5 | ~~Routes d'écriture sans auth~~ → **traité** : rate-limit `/api/contact` ; `register` valide déjà le token ; capteurs/kiosk laissés (RPi) | ✅ | server.py |
| 6 | ~~Route orpheline `POST /api/companion/intervenants`~~ → **supprimée** | ✅ | server.py |
| 7 | ~~Désync logout~~ → **corrigé** (`confirm()` ajouté à `logoutCompanion`) ; haptic/persistance vue = specifics PWA conservés | ✅ | companion.html |
| 8 | ~~Code mort~~ → **supprimé** (1 var dashboard + 5 tableaux ×2 companion) | ✅ | dashboard/companion ×2 |

**Points positifs :** requêtes SQL paramétrées (`%s`) partout ; noms de tables dynamiques validés par whitelist (`COMPANION_CONTENT_TABLES`) → **pas d'injection SQL** ; aucune route dupliquée ; aucune fonction JS morte détectée sur les 6 fichiers HTML.

---

## server.py

### ✅ Corrigé (anciennement 🔴)

- **XSS réfléchie via `site_slug` (lignes 4051 et 4119).** *Contexte initial :* `realtime.html` (`/realtime/<site_slug>`, sans auth) et `kiosk` (`/kiosk/<site_slug>`, sans auth) injectaient le segment d'URL brut dans une littérale JS (`const SITE = '{site_slug}'`), permettant l'injection de code côté client.
  **CORRIGÉ (commit `f39a43a`)** : injection via `json.dumps(site_slug)` (littérale JS échappée). Non exploitable par `</script>` car le convertisseur de route `<site_slug>` interdit le caractère `/`.

- **Contrôle d'accès cassé — `DELETE /api/companion/intervenants/<iid>` (ligne 2911).** *Contexte initial :* décorée `@login_required` seul, sans contrôle de rôle/propriété → tout utilisateur authentifié pouvait supprimer le profil de n'importe quel intervenant.
  **CORRIGÉ (commit `c43053d`)** : ajout du même contrôle d'appartenance que le `PUT` (comparaison de nom normalisée `_norm_nom`, 403 si non-propriétaire, admin exempté).

### ✅ Corrigé (anciennement 🟡)

- **CRUD `sons` et création `intervenants` sans contrôle de rôle.** **CORRIGÉ (Point 1)** : `@intervenant_required` (role ∈ admin/intervenant) ajouté sur `POST /api/companion/sons`, `PUT`/`DELETE /api/companion/sons/:id` (et momentanément sur `POST /api/companion/intervenants` avant sa suppression au Point 3). Aligné sur le CRUD des contenus.

- **Routes d'écriture sans authentification.** **TRAITÉ (Point 2)** :
  - `POST /api/contact` → **rate-limit en mémoire 5 req/h/IP** (HTTP 429 au-delà), via `_contact_rate_ok` + en-tête `X-Forwarded-For`.
  - `POST /api/auth/register` → **déjà sécurisé** : la route exige un token d'invitation et renvoie 403 (`site_invite_tokens … actif=1`) avant toute création — aucune création possible sans token valide. Inchangé.
  - Routes capteurs/kiosk (`/api/kiosk/.../session`, `/api/sensors/*`) → **laissées sans auth par conception** (boîtiers RPi terrain), comme demandé.

- **Route orpheline `POST /api/companion/intervenants`.** **SUPPRIMÉE (Point 3)** après vérification (aucun POST émis par les frontends ; la création passe par `/api/admin/intervenants`). Les routes GET/PUT/DELETE `/api/companion/intervenants` sont conservées.

### 🟢 Proposition

- **Routes hors périmètre des 7 fichiers (non orphelines).** `GET/POST /api/devis*` (1400, 1448, 1470) ne sont appelées par aucun des 7 fichiers, mais le sont vraisemblablement par `ROI_beOtop.html` (hors périmètre) — à confirmer, ne pas supprimer sans vérifier.
- **`GET /api/v1/companion-impact` (4778)** : bien appelée (dashboard.html 1849) → **non orpheline** (corrige un doute initial).
- **Deux tables d'intervenants distinctes** : `intervenants` (rétribution V1, routes `/api/admin/intervenants*`, `/api/intervenant/stats`) et `companion_intervenants` (profils Companion, routes `/api/companion/intervenants*`). Cohérent mais source de confusion — à documenter dans le code.
- **Aucune route dupliquée** et **aucune injection SQL** (requêtes paramétrées ; whitelist pour noms de tables dynamiques lignes ~2751).

---

## dashboard.html

### ✅ Corrigé (anciennement 🟡)
- **Variable morte `cpRefreshTimer`.** **SUPPRIMÉE (Point 5)**.

### 🟢 Proposition
- Toutes les fonctions JS (~87) sont appelées.
- **Pas de bug d'export** : `exportCSV` (937) et l'export QVCT (1641) appellent correctement `/api/export` (défini server.py 1885). *(Un agent avait signalé à tort un appel `/api/stats/export` ; vérifié inexistant.)*
- L'appel `/api/v1/companion-impact` (1849) est correctement adressé.

---

## companion.html

### ✅ Corrigé (anciennement 🟡)
- **Tableaux globaux inutilisés** (`SANS_CAPTEUR_PIR`, `DUREES`, `CATS_VIDEO`, `CATS_AUDIO`, `CATS_EX`). **SUPPRIMÉS (Point 5)** (les vars utilisées `currentVideoCat/currentAudioCat/currentExCat` conservées).
- **Désynchronisation logout.** **CORRIGÉ (Point 4)** : `logoutCompanion()` demande désormais `confirm('Se déconnecter ?')`, aligné sur `logoutPwa()`.

### 🟢 Proposition
- Aucune fonction JS morte (≈267 fonctions, toutes appelées).

---

## companion_pwa.html

### ✅ Corrigé (anciennement 🟡)
- **Mêmes tableaux globaux inutilisés que companion.html** (`SANS_CAPTEUR_PIR`, `DUREES`, `CATS_VIDEO`, `CATS_AUDIO`, `CATS_EX`). **SUPPRIMÉS (Point 5)**.
- **Désynchronisations companion.html ↔ companion_pwa.html** :
  - `logoutPwa()` vs `logoutCompanion()` → **résolu (Point 4)** : confirmation ajoutée côté companion.html.
  - `awardPoints()` + `haptic('medium')`, `switchView()` persistance de vue, `renderDashboard()` skeleton loader → **spécificités PWA légitimes, conservées intentionnellement** (non corrigées par conception).

### 🟢 Proposition
- Aucune fonction JS morte (≈287 fonctions, toutes appelées).
- Fonctions présentes **uniquement** dans la PWA et **légitimes par conception** (UI mobile/PWA — à NE PAS porter vers companion.html) : `maybeSeedDemo` (3957, seed démo `?seed=demo|reset`), `haptic` (10453), `hideSplash` (10318), onboarding `obShowSlide/obNext/obSkip/obFinish` (10331-10362), `maybeShowOnboarding` (10383), navigation `bnavSwitch/bnavSwitchContenus` (10389-10411), drawers `openContenuDrawer/closeContenuDrawer` (10413-10420) et `openMoreDrawer/closeMoreDrawer` (10443-10450), `toggleFab/closeFab` (10463-10481), bannière install `showPwaBanner/closePwaBanner` (10588-10606), modale mdp `openPwdModal/closePwdModal/submitPwd` (10428-10441).

---

## admin.html

### ✅ Corrigé (anciennement 🔴)
- **Appel vers une route inexistante `/api/health` (ligne 660).** *Contexte initial :* `loadOverview()` lisait `health.clients/sites/sessions` depuis `/api/health`, route **absente** de server.py → la vue « Vue d'ensemble » ne se remplissait pas.
  **CORRIGÉ (commit `de0103d`)** : création de `GET /api/health` (`@login_required`, server.py ligne 753) renvoyant `{clients, sites, sessions, database}` via `COUNT(*)` sur `clients`/`sites`/`sessions`.

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
| Route appelée mais inexistante | `/api/health` — ✅ **corrigée** (créée, commit `de0103d`) | admin.html 660 / server.py 753 |
| Route définie mais non appelée (frontend) | `POST /api/companion/intervenants` | server.py 2843 |
| Faux positif écarté | `/api/stats/export` n'est PAS appelé ; `/api/export` OK | dashboard.html 937, 1641 |
| Champs réponse non vérifiables statiquement | structures de `/api/intervenant/stats`, `/api/admin/retribution/*`, `/api/companion/checkin/history`, `/api/companion/livreor` — à confirmer à l'exécution | — |

> Les incohérences au niveau **champ** (champ retourné non lu / champ attendu absent) ne peuvent être confirmées sans exécuter l'API contre la base. Elles sont signalées comme **à confirmer** plutôt qu'affirmées.
