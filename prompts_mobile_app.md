# Prompts Claude Code — App mobile beOtop Companion
# Exécuter dans l'ordre. Un prompt = un commit.

---

## PROMPT 1 — Vues adaptées mobile (dashboard hero + cards)

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html avant tout.

Étape 1 — Ajoute ces règles CSS dans le bloc @media (max-width: 768px) existant :

  /* Hero */
  .hero { padding: 1.2rem 1rem 1rem; }
  .hero-inner { flex-direction: column; gap: .8rem; }
  .hero-right { display: none; }
  .hero-time { font-size: 2.8rem; }
  .hero-greeting { font-size: 1.15rem; margin-top: .4rem; }
  .hero-chips { gap: .5rem; }
  .hero-chip { font-size: .65rem; padding: .28rem .7rem; }

  /* Ticker */
  .ticker-bar { height: 36px; }
  .ticker-item { font-size: .65rem; padding: 0 .8rem; }

  /* Vues */
  .view { padding: 1rem; }

  /* Cards stats (grille 2 colonnes sur mobile) */
  .stats-grid,
  .kpi-grid,
  .metric-grid { grid-template-columns: 1fr 1fr !important; gap: .6rem !important; }

  /* Cards génériques */
  .card, .stat-card, .kpi-card {
    padding: .9rem !important;
    border-radius: 14px !important;
  }

  /* Sections titres */
  .section-title, .view-title {
    font-size: .9rem !important;
    margin-bottom: .8rem !important;
  }

  /* Check-in sliders */
  .checkin-card { padding: 1rem !important; }
  .checkin-sliders { gap: .8rem !important; }

Étape 2 — Vérification :
- grep -c "max-width: 768px" companion_pwa.html → doit retourner au moins 1
- grep -c "hero-right" companion_pwa.html → doit retourner au moins 2

Étape 3 — git add companion_pwa.html && git commit -m "feat: mobile — hero et vues adaptés petit écran" && git push
```

---

## PROMPT 2 — Topbar mobile allégée

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html avant tout.
Repère le CSS .topbar, .topbar-right, .notif-btn, .user-pill et le HTML <!-- TOPBAR -->.

Étape 1 — Dans le bloc @media (max-width: 768px) existant, ajoute :

  /* Topbar compacte */
  .topbar { padding: .6rem 1rem; }
  .logo { font-size: 1rem; }
  .user-pill span#user-display { display: none; }
  .notif-btn { width: 28px; height: 28px; font-size: .85rem; }
  .avatar { width: 28px; height: 28px; font-size: .58rem; }
  .user-pill { padding: .25rem .5rem .25rem .3rem; gap: .35rem; }

Étape 2 — Vérification :
- grep -c "user-display" companion_pwa.html → doit retourner au moins 1

Étape 3 — git add companion_pwa.html && git commit -m "feat: mobile — topbar compacte" && git push
```

---

## PROMPT 3 — Carousel ateliers → scroll vertical mobile

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html avant tout.
Repère les classes CSS du carousel / ticker d'ateliers dans le dashboard
(cherche .atelier-carousel, .atelier-list, .atelier-scroll, ou similaire).
Repère aussi les cards d'ateliers individuelles.

Étape 1 — Dans le bloc @media (max-width: 768px), ajoute des règles pour
transformer le scroll horizontal en grille verticale 2 colonnes.
Utilise les vrais noms de classes trouvés à l'étape 0.

Le pattern général à appliquer :
  .NOM_CAROUSEL {
    display: grid !important;
    grid-template-columns: 1fr 1fr !important;
    overflow-x: visible !important;
    flex-wrap: wrap !important;
    gap: .6rem !important;
    padding-bottom: 0 !important;
  }
  .NOM_CARD_ATELIER {
    min-width: 0 !important;
    width: 100% !important;
    flex-shrink: 0 !important;
  }

Remplace NOM_CAROUSEL et NOM_CARD_ATELIER par les vrais noms trouvés.

Étape 2 — Vérification :
- grep -c "grid-template-columns: 1fr 1fr" companion_pwa.html → doit retourner au moins 1

Étape 3 — git add companion_pwa.html && git commit -m "feat: mobile — ateliers en grille verticale" && git push
```

---

## PROMPT 4 — Touch feedback natif

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html avant tout.

Étape 1 — Ajoute ces règles CSS dans le bloc @media (max-width: 768px) existant :

  /* Touch feedback — compression au tap */
  .bottom-nav-item:active,
  .more-drawer-item:active,
  .nav-item:active,
  .btn:active,
  button:active,
  .card:active,
  .atelier-card:active,
  .quick-card:active,
  .content-card:active {
    transform: scale(0.96) !important;
    opacity: 0.85 !important;
    transition: transform 0.08s, opacity 0.08s !important;
  }

  /* Supprimer le highlight bleu natif iOS/Android au tap */
  * { -webkit-tap-highlight-color: transparent; }

  /* Curseur pointer sur tous les éléments cliquables */
  [onclick], button, .nav-item, .bottom-nav-item, .more-drawer-item {
    cursor: pointer;
  }

Étape 2 — Ajoute dans la section CSS globale (hors media query) :
  /* Désactiver sélection texte sur éléments interactifs */
  .bottom-nav-item, .more-drawer-item, .nav-item {
    -webkit-user-select: none;
    user-select: none;
  }

Étape 3 — Vérification :
- grep -c "tap-highlight-color" companion_pwa.html → doit retourner 1
- grep -c "scale(0.96)" companion_pwa.html → doit retourner au moins 1

Étape 4 — git add companion_pwa.html && git commit -m "feat: mobile — touch feedback natif au tap" && git push
```

---

## PROMPT 5 — Splash screen au lancement

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html avant tout.
Repère la balise <body> ouvrante et le premier bloc HTML après (le bandeau PWA ou le topbar).

Étape 1 — Ajoute ce CSS juste avant </style> dans le <head> :

/* ══ SPLASH SCREEN ══ */
#splash {
  position: fixed; inset: 0; z-index: 9998;
  background: linear-gradient(145deg, #002626 0%, #004d4d 50%, #001a1a 100%);
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  gap: 1.2rem;
  transition: opacity .5s ease, visibility .5s ease;
}
#splash.hidden {
  opacity: 0; visibility: hidden; pointer-events: none;
}
#splash .splash-logo {
  font-family: 'Cormorant Garamond', serif;
  font-size: 2.4rem; font-weight: 300; letter-spacing: .12em;
  background: linear-gradient(135deg, #00b4b4, #f5855a);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}
#splash .splash-logo span { font-style: italic; font-weight: 300; }
#splash .splash-sub {
  font-size: .65rem; color: rgba(255,255,255,.4);
  letter-spacing: .2em; text-transform: uppercase;
  font-family: 'DM Sans', sans-serif;
}
#splash .splash-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: #00b4b4; animation: splashPulse 1.2s infinite;
}
@keyframes splashPulse {
  0%, 100% { opacity: .3; transform: scale(1); }
  50% { opacity: 1; transform: scale(1.4); }
}

Étape 2 — Ajoute ce HTML juste après la balise <body> ouvrante,
avant tout autre contenu :

<div id="splash">
  <div class="splash-logo">beOtop <span>Companion</span></div>
  <div class="splash-sub">Espace bien-être</div>
  <div class="splash-dot"></div>
</div>

Étape 3 — Dans le bloc <script> PWA existant, ajoute cette fonction
et appelle-la au chargement :

function hideSplash() {
  var splash = document.getElementById('splash');
  if (!splash) return;
  setTimeout(function() {
    splash.classList.add('hidden');
    setTimeout(function() { splash.remove(); }, 500);
  }, 1200);
}
window.addEventListener('load', hideSplash);

Étape 4 — Vérification :
- grep -c "splash" companion_pwa.html → doit retourner au moins 6
- grep -c "hideSplash" companion_pwa.html → doit retourner au moins 2

Étape 5 — git add companion_pwa.html && git commit -m "feat: mobile — splash screen au lancement" && git push
```

---

## PROMPT 6 — Transitions entre vues

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html avant tout.
Repère exactement la fonction switchView() dans le JS.
Repère les règles CSS .view et .view.active.

Étape 1 — Remplace les règles CSS .view et .view.active existantes par :

.view {
  display: none;
  padding: 2rem;
  animation: viewFadeIn .22s ease both;
}
.view.active { display: block; }

@keyframes viewFadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0); }
}

Étape 2 — Dans la fonction switchView(), ajoute une ligne pour
forcer le re-déclenchement de l'animation à chaque changement de vue.
Trouve la ligne : if (view) view.classList.add('active');
Remplace-la par :

if (view) {
  view.style.animation = 'none';
  view.offsetHeight; /* force reflow */
  view.style.animation = '';
  view.classList.add('active');
}

Étape 3 — Dans le bloc @media (max-width: 768px), ajoute :

  .view { padding: 1rem; }
  @keyframes viewFadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to   { opacity: 1; transform: translateY(0); }
  }

Étape 4 — Vérification :
- grep -c "viewFadeIn" companion_pwa.html → doit retourner au moins 2
- grep -c "offsetHeight" companion_pwa.html → doit retourner 1
- python3 -c "import py_compile; py_compile.compile('server.py')"

Étape 5 — git add companion_pwa.html && git commit -m "feat: mobile — transitions fluides entre vues" && git push
```
