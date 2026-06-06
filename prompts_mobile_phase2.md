# Prompts Claude Code — App mobile beOtop Phase 2
# Exécuter dans l'ordre. Un prompt = un commit.
# Breakpoint mobile = @media (max-width: 900px) dans tout ce fichier.

---

## PROMPT 7 — Onboarding première connexion

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Repère le bloc <body> et le div id="splash".

Étape 1 — Ajoute ce CSS juste avant </style> dans le <head> :

/* ══ ONBOARDING ══ */
#onboarding {
  display: none;
  position: fixed; inset: 0; z-index: 9997;
  background: linear-gradient(160deg, #001a1a 0%, #003030 50%, #001010 100%);
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2rem 1.5rem;
  overflow: hidden;
}
#onboarding.active { display: flex; }
.ob-logo {
  font-family: 'Cormorant Garamond', serif;
  font-size: 2rem; font-weight: 300; letter-spacing: .12em;
  background: linear-gradient(135deg, #00b4b4, #f5855a);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text; margin-bottom: .3rem;
}
.ob-tagline {
  font-size: .65rem; color: rgba(255,255,255,.4);
  letter-spacing: .2em; text-transform: uppercase;
  margin-bottom: 2.5rem;
}
.ob-slides {
  width: 100%; max-width: 360px;
  position: relative; overflow: hidden;
  flex: 1; max-height: 320px;
}
.ob-slide {
  position: absolute; inset: 0;
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  text-align: center; padding: 0 1rem;
  opacity: 0; transform: translateX(40px);
  transition: all .35s cubic-bezier(.4,0,.2,1);
  pointer-events: none;
}
.ob-slide.active {
  opacity: 1; transform: translateX(0);
  pointer-events: auto;
}
.ob-slide.exit {
  opacity: 0; transform: translateX(-40px);
}
.ob-icon {
  font-size: 3.5rem; margin-bottom: 1.2rem;
  filter: drop-shadow(0 0 20px rgba(0,180,180,.4));
}
.ob-title {
  font-family: 'Cormorant Garamond', serif;
  font-size: 1.5rem; font-weight: 300;
  color: rgba(255,255,255,.95); margin-bottom: .6rem;
}
.ob-desc {
  font-size: .78rem; color: rgba(255,255,255,.55);
  line-height: 1.7; max-width: 280px;
}
.ob-dots {
  display: flex; gap: .5rem; margin: 1.5rem 0 1.2rem;
}
.ob-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: rgba(255,255,255,.25);
  transition: all .3s;
}
.ob-dot.active {
  background: #00b4b4; width: 20px; border-radius: 3px;
}
.ob-btn {
  width: 100%; max-width: 360px;
  padding: .9rem; border-radius: 14px;
  background: linear-gradient(135deg, #00b4b4, #02C39A);
  color: #fff; border: none;
  font-family: 'DM Sans', sans-serif;
  font-size: .9rem; font-weight: 600;
  cursor: pointer; letter-spacing: .03em;
  box-shadow: 0 4px 20px rgba(0,180,180,.35);
  transition: transform .15s, box-shadow .15s;
}
.ob-btn:active { transform: scale(.97); }
.ob-skip {
  margin-top: .8rem;
  background: none; border: none;
  color: rgba(255,255,255,.3); font-size: .7rem;
  cursor: pointer; padding: .4rem;
  font-family: 'DM Sans', sans-serif;
}

Étape 2 — Ajoute ce HTML juste après le div id="splash" et avant div id="pwa-install-banner" :

<div id="onboarding">
  <div class="ob-logo">beOtop <span style="font-style:italic;font-weight:300">Companion</span></div>
  <div class="ob-tagline">Votre espace bien-être</div>
  <div class="ob-slides">
    <div class="ob-slide active" data-slide="0">
      <div class="ob-icon">🌿</div>
      <div class="ob-title">Bienvenue</div>
      <div class="ob-desc">Votre espace personnel de récupération et de bien-être au travail, disponible à tout moment.</div>
    </div>
    <div class="ob-slide" data-slide="1">
      <div class="ob-icon">🏃</div>
      <div class="ob-title">Réservez en 2 taps</div>
      <div class="ob-desc">Consultez les ateliers disponibles en temps réel et réservez votre créneau directement depuis l'app.</div>
    </div>
    <div class="ob-slide" data-slide="2">
      <div class="ob-icon">🧠</div>
      <div class="ob-title">Contenus bien-être</div>
      <div class="ob-desc">Cohérence cardiaque, sons immersifs, défis cognitifs, exercices express — tout pour recharger vos ressources.</div>
    </div>
    <div class="ob-slide" data-slide="3">
      <div class="ob-icon">🔥</div>
      <div class="ob-title">Suivez vos progrès</div>
      <div class="ob-desc">Streaks, points, niveau — chaque séance compte. Construisez une habitude de récupération durable.</div>
    </div>
  </div>
  <div class="ob-dots" id="ob-dots">
    <div class="ob-dot active"></div>
    <div class="ob-dot"></div>
    <div class="ob-dot"></div>
    <div class="ob-dot"></div>
  </div>
  <button class="ob-btn" id="ob-btn" onclick="obNext()">Suivant</button>
  <button class="ob-skip" onclick="obSkip()">Passer</button>
</div>

Étape 3 — Dans le bloc <script> PWA existant (celui qui contient hideSplash),
ajoute ces fonctions après hideSplash() :

var _obSlide = 0;
var _obTotal = 4;

function obShowSlide(idx) {
  document.querySelectorAll('.ob-slide').forEach(function(s, i) {
    s.classList.remove('active', 'exit');
    if (i === idx) s.classList.add('active');
    else if (i < idx) s.classList.add('exit');
  });
  document.querySelectorAll('.ob-dot').forEach(function(d, i) {
    d.classList.toggle('active', i === idx);
  });
  var btn = document.getElementById('ob-btn');
  if (btn) btn.textContent = idx >= _obTotal - 1 ? 'Commencer' : 'Suivant';
}

function obNext() {
  _obSlide++;
  if (_obSlide >= _obTotal) { obFinish(); return; }
  obShowSlide(_obSlide);
}

function obSkip() { obFinish(); }

function obFinish() {
  var ob = document.getElementById('onboarding');
  if (ob) {
    ob.style.opacity = '0';
    ob.style.transition = 'opacity .4s';
    setTimeout(function() { ob.remove(); }, 400);
  }
  localStorage.setItem('beotop_onboarding_done', '1');
}

function maybeShowOnboarding() {
  if (localStorage.getItem('beotop_onboarding_done')) return;
  var ob = document.getElementById('onboarding');
  if (ob) ob.classList.add('active');
}

Étape 4 — Dans la fonction hideSplash(), après splash.remove(),
ajoute un appel à maybeShowOnboarding() :

Trouve la ligne : setTimeout(function() { splash.remove(); }, 500);
Remplace-la par : setTimeout(function() { splash.remove(); maybeShowOnboarding(); }, 500);

Étape 5 — Vérification :
- grep -c "onboarding" companion_pwa.html → doit retourner au moins 8
- grep -c "obNext" companion_pwa.html → doit retourner au moins 2

Étape 6 — git add companion_pwa.html && git commit -m "feat: mobile — onboarding première connexion (4 slides)" && git push
```

---

## PROMPT 8 — Mode offline (bannière + cache)

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Repère le div class="topbar".

Étape 1 — Ajoute ce CSS juste avant </style> dans le <head> :

/* ══ BANNIÈRE OFFLINE ══ */
#offline-banner {
  display: none;
  position: fixed; top: 0; left: 0; right: 0; z-index: 9990;
  background: #1a2e35;
  border-bottom: 1px solid rgba(245,133,90,.3);
  padding: .5rem 1rem;
  text-align: center;
  font-size: .72rem; color: rgba(255,255,255,.8);
  font-family: 'DM Sans', sans-serif;
  animation: slideDown .3s ease;
}
#offline-banner.visible { display: block; }
@keyframes slideDown {
  from { transform: translateY(-100%); opacity: 0; }
  to   { transform: translateY(0);     opacity: 1; }
}
#offline-banner span { color: #f5855a; font-weight: 600; }

Étape 2 — Ajoute ce HTML juste après la balise <body> ouvrante,
avant div id="splash" :

<div id="offline-banner">
  <span>📡 Hors ligne</span> — Les données affichées sont issues du cache.
  La synchronisation reprendra automatiquement.
</div>

Étape 3 — Dans le bloc <script> PWA existant, ajoute après la fonction obFinish() :

window.addEventListener('online', function() {
  var b = document.getElementById('offline-banner');
  if (b) { b.classList.remove('visible'); }
  showToast('✓ Connexion rétablie');
});

window.addEventListener('offline', function() {
  var b = document.getElementById('offline-banner');
  if (b) { b.classList.add('visible'); }
});

// Vérifier l'état au chargement
if (!navigator.onLine) {
  window.addEventListener('load', function() {
    var b = document.getElementById('offline-banner');
    if (b) b.classList.add('visible');
  });
}

Étape 4 — Dans sw.js (à la racine du repo), ajoute ces URLs dans le tableau PRECACHE_URLS :
'/static/icons/icon-192.png',
'/static/icons/icon-512.png'
sont déjà présents. Ajoute uniquement si absentes :
'/manifest.json'

Étape 5 — Vérification :
- grep -c "offline-banner" companion_pwa.html → doit retourner au moins 3
- grep -c "navigator.onLine" companion_pwa.html → doit retourner au moins 1

Étape 6 — git add companion_pwa.html sw.js && git commit -m "feat: mobile — bannière mode offline + détection réseau" && git push
```

---

## PROMPT 9 — Skeleton screens (chargement)

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Repère les fonctions renderDashboard() et _v3KPIs().

Étape 1 — Ajoute ce CSS juste avant </style> dans le <head> :

/* ══ SKELETON SCREENS ══ */
@keyframes shimmer {
  0%   { background-position: -400px 0; }
  100% { background-position: 400px 0; }
}
.skeleton {
  background: linear-gradient(90deg,
    rgba(0,180,180,.06) 25%,
    rgba(0,180,180,.12) 50%,
    rgba(0,180,180,.06) 75%
  );
  background-size: 400px 100%;
  animation: shimmer 1.4s ease-in-out infinite;
  border-radius: 6px;
}
.sk-line   { height: 12px; margin-bottom: 8px; }
.sk-line.w80 { width: 80%; }
.sk-line.w60 { width: 60%; }
.sk-line.w40 { width: 40%; }
.sk-block  { border-radius: 12px; }
.sk-card {
  background: rgba(255,255,255,.9);
  border: 1px solid rgba(0,180,180,.1);
  border-radius: 14px; padding: 1rem;
  margin-bottom: .8rem;
}
#sk-dashboard {
  padding: 1rem;
  display: none;
}
#sk-dashboard.visible { display: block; }

Étape 2 — Ajoute ce HTML juste avant </div><!-- /main-content --> :

<!-- SKELETON DASHBOARD -->
<div id="sk-dashboard">
  <!-- Hero skeleton -->
  <div style="background:linear-gradient(125deg,#002626,#004d4d);padding:1.5rem 1rem;margin-bottom:0">
    <div class="skeleton sk-line" style="width:120px;height:48px;margin-bottom:.8rem"></div>
    <div class="skeleton sk-line w60" style="height:18px;margin-bottom:.5rem"></div>
    <div class="skeleton sk-line w40" style="height:14px"></div>
  </div>
  <!-- KPIs skeleton -->
  <div style="padding:1rem">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:.8rem;margin-bottom:1rem">
      <div class="sk-card"><div class="skeleton sk-line w40" style="height:10px;margin-bottom:.5rem"></div><div class="skeleton sk-line" style="height:28px;width:60px"></div></div>
      <div class="sk-card"><div class="skeleton sk-line w40" style="height:10px;margin-bottom:.5rem"></div><div class="skeleton sk-line" style="height:28px;width:60px"></div></div>
      <div class="sk-card"><div class="skeleton sk-line w40" style="height:10px;margin-bottom:.5rem"></div><div class="skeleton sk-line" style="height:28px;width:60px"></div></div>
      <div class="sk-card"><div class="skeleton sk-line w40" style="height:10px;margin-bottom:.5rem"></div><div class="skeleton sk-line" style="height:28px;width:60px"></div></div>
    </div>
    <!-- Cards skeleton -->
    <div class="sk-card">
      <div class="skeleton sk-line w60" style="height:14px;margin-bottom:.8rem"></div>
      <div class="skeleton sk-line w80" style="height:10px"></div>
      <div class="skeleton sk-line w60" style="height:10px"></div>
      <div class="skeleton sk-line w40" style="height:10px"></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:.8rem">
      <div class="sk-card"><div class="skeleton sk-block" style="height:80px;margin-bottom:.6rem"></div><div class="skeleton sk-line w80" style="height:10px"></div></div>
      <div class="sk-card"><div class="skeleton sk-block" style="height:80px;margin-bottom:.6rem"></div><div class="skeleton sk-line w80" style="height:10px"></div></div>
    </div>
  </div>
</div>

Étape 3 — Dans la fonction renderDashboard(), au tout début de la fonction,
avant var u = DB.user;, ajoute :

var skEl = document.getElementById('sk-dashboard');
var dashView = document.getElementById('view-dashboard');
if (skEl && dashView) {
  skEl.classList.add('visible');
  dashView.style.visibility = 'hidden';
}

Puis trouve la ligne renderHistoryRecent(); dans renderDashboard() et ajoute après :

var skEl2 = document.getElementById('sk-dashboard');
var dashView2 = document.getElementById('view-dashboard');
if (skEl2) skEl2.classList.remove('visible');
if (dashView2) dashView2.style.visibility = 'visible';

Étape 4 — Vérification :
- grep -c "sk-dashboard" companion_pwa.html → doit retourner au moins 3
- grep -c "shimmer" companion_pwa.html → doit retourner au moins 2

Étape 5 — git add companion_pwa.html && git commit -m "feat: mobile — skeleton screens dashboard" && git push
```

---

## PROMPT 10 — Swipe horizontal entre les 5 onglets principaux

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Repère le div class="main-content"
et les fonctions bnavSwitch, switchView.

Étape 1 — Dans le bloc <script> PWA existant, ajoute après closeMoreDrawer() :

/* ══ SWIPE HORIZONTAL entre les 5 onglets principaux ══ */
(function() {
  var _swipeStartX = 0;
  var _swipeStartY = 0;
  var _swipeActive = false;
  var MAIN_VIEWS = ['dashboard', 'reservation', 'coherence', 'progres'];
  var BNAV_IDS   = ['bnav-dashboard', 'bnav-reservation', 'bnav-contenus', 'bnav-progres', 'bnav-more'];

  function currentMainIdx() {
    var active = document.querySelector('.view.active');
    if (!active) return 0;
    var id = active.id.replace('view-', '');
    var idx = MAIN_VIEWS.indexOf(id);
    return idx >= 0 ? idx : -1;
  }

  document.addEventListener('touchstart', function(e) {
    if (e.touches.length !== 1) return;
    var t = e.touches[0];
    _swipeStartX = t.clientX;
    _swipeStartY = t.clientY;
    _swipeActive = true;
  }, { passive: true });

  document.addEventListener('touchend', function(e) {
    if (!_swipeActive) return;
    _swipeActive = false;
    var t = e.changedTouches[0];
    var dx = t.clientX - _swipeStartX;
    var dy = t.clientY - _swipeStartY;
    if (Math.abs(dx) < 60) return;
    if (Math.abs(dy) > Math.abs(dx) * 0.8) return;
    /* Ne pas swiper si un drawer est ouvert */
    if (document.getElementById('contenus-drawer').classList.contains('open')) return;
    if (document.getElementById('more-drawer').classList.contains('open')) return;
    /* Ne pas swiper si l'utilisateur fait défiler dans un input/range */
    var tag = (e.target || {}).tagName || '';
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
    var idx = currentMainIdx();
    if (idx < 0) return;
    if (dx < 0 && idx < MAIN_VIEWS.length - 1) {
      bnavSwitch(MAIN_VIEWS[idx + 1]);
    } else if (dx > 0 && idx > 0) {
      bnavSwitch(MAIN_VIEWS[idx - 1]);
    }
  }, { passive: true });
})();

Étape 2 — Vérification :
- grep -c "touchstart" companion_pwa.html → doit retourner au moins 1
- grep -c "MAIN_VIEWS" companion_pwa.html → doit retourner au moins 2

Étape 3 — git add companion_pwa.html && git commit -m "feat: mobile — swipe horizontal entre onglets principaux" && git push
```

---

## PROMPT 11 — Pull to refresh

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Repère le div class="main-content".

Étape 1 — Ajoute ce CSS juste avant </style> dans le <head> :

/* ══ PULL TO REFRESH ══ */
#ptr-indicator {
  position: fixed; top: 0; left: 50%; transform: translateX(-50%);
  z-index: 500; pointer-events: none;
  width: 44px; height: 44px; border-radius: 50%;
  background: rgba(0,180,180,.15);
  border: 1px solid rgba(0,180,180,.3);
  display: flex; align-items: center; justify-content: center;
  font-size: 1.2rem;
  opacity: 0; transition: opacity .2s;
  backdrop-filter: blur(10px);
  margin-top: -44px;
}
#ptr-indicator.pulling { opacity: 1; }
#ptr-indicator.refreshing {
  opacity: 1;
  animation: ptrSpin .8s linear infinite;
}
@keyframes ptrSpin {
  from { transform: translateX(-50%) rotate(0deg); }
  to   { transform: translateX(-50%) rotate(360deg); }
}

Étape 2 — Ajoute ce HTML juste après la balise <body> ouvrante :

<div id="ptr-indicator">↓</div>

Étape 3 — Dans le bloc <script> PWA existant, ajoute ces fonctions
après le bloc swipe (touchstart/touchend) :

/* ══ PULL TO REFRESH ══ */
(function() {
  var _ptrStart = 0;
  var _ptrActive = false;
  var _ptrRefreshing = false;
  var PTR_THRESHOLD = 80;
  var ind = null;

  function getInd() { return ind || (ind = document.getElementById('ptr-indicator')); }

  document.addEventListener('touchstart', function(e) {
    if (e.touches.length !== 1) return;
    var mc = document.querySelector('.main-content');
    if (mc && mc.scrollTop > 0) return;
    _ptrStart = e.touches[0].clientY;
    _ptrActive = true;
  }, { passive: true });

  document.addEventListener('touchmove', function(e) {
    if (!_ptrActive || _ptrRefreshing) return;
    var dy = e.touches[0].clientY - _ptrStart;
    if (dy < 10) return;
    var mc = document.querySelector('.main-content');
    if (mc && mc.scrollTop > 0) { _ptrActive = false; return; }
    var el = getInd();
    if (!el) return;
    var pct = Math.min(dy / PTR_THRESHOLD, 1);
    el.classList.add('pulling');
    el.style.marginTop = (Math.min(dy * 0.4, 44) - 44) + 'px';
    el.textContent = dy >= PTR_THRESHOLD ? '↻' : '↓';
  }, { passive: true });

  document.addEventListener('touchend', function(e) {
    if (!_ptrActive) return;
    _ptrActive = false;
    var dy = e.changedTouches[0].clientY - _ptrStart;
    var el = getInd();
    if (dy < PTR_THRESHOLD || !el) {
      if (el) { el.classList.remove('pulling'); el.style.marginTop = '-44px'; }
      return;
    }
    _ptrRefreshing = true;
    el.classList.remove('pulling');
    el.classList.add('refreshing');
    el.style.marginTop = '8px';
    el.textContent = '↻';
    var active = document.querySelector('.view.active');
    var viewId = active ? active.id.replace('view-', '') : 'dashboard';
    if (typeof switchView === 'function') switchView(viewId);
    setTimeout(function() {
      _ptrRefreshing = false;
      el.classList.remove('refreshing');
      el.style.marginTop = '-44px';
    }, 1200);
  }, { passive: true });
})();

Étape 4 — Vérification :
- grep -c "ptr-indicator" companion_pwa.html → doit retourner au moins 3
- grep -c "PTR_THRESHOLD" companion_pwa.html → doit retourner au moins 2

Étape 5 — git add companion_pwa.html && git commit -m "feat: mobile — pull to refresh" && git push
```

---

## PROMPT 12 — Haptic feedback

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Repère les fonctions bnavSwitch,
submitCheckin, confirmerReservation, awardPoints.

Étape 1 — Dans le bloc <script> PWA existant, ajoute cette fonction utilitaire
juste après la fonction closeMoreDrawer() :

/* ══ HAPTIC FEEDBACK ══ */
function haptic(type) {
  if (!navigator.vibrate) return;
  if (type === 'light')    navigator.vibrate(10);
  else if (type === 'medium') navigator.vibrate(25);
  else if (type === 'success') navigator.vibrate([15, 30, 15]);
  else if (type === 'error')   navigator.vibrate([50, 30, 50]);
  else navigator.vibrate(10);
}

Étape 2 — Modifie les fonctions suivantes pour appeler haptic() au bon moment.
Pour chaque modification, trouve la ligne EXACTE et ajoute uniquement haptic().
Ne modifie rien d'autre.

Modification A — Dans bnavSwitch(), avant switchView(view) :
Ajoute : haptic('light');

Modification B — Dans openContenuDrawer(), avant la ligne existante :
Ajoute : haptic('light');

Modification C — Dans openMoreDrawer(), avant la ligne existante :
Ajoute : haptic('light');

Modification D — Dans la fonction obNext(), au début :
Ajoute : haptic('light');

Modification E — Dans submitCheckin(), après la ligne saveDB(DB); :
Ajoute : haptic('success');

Modification F — Dans confirmerReservation(), après closeResModal(); :
Ajoute : haptic('success');

Modification G — Dans la fonction awardPoints(), après la ligne saveDB(DB); :
Ajoute : haptic('medium');

Étape 3 — Vérification :
- grep -c "haptic(" companion_pwa.html → doit retourner au moins 7
- grep -c "navigator.vibrate" companion_pwa.html → doit retourner au moins 4

Étape 4 — git add companion_pwa.html && git commit -m "feat: mobile — haptic feedback natif (vibration)" && git push
```

---

## PROMPT 13 — Dashboard mobile-first redesigné

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Repère le bloc @media (max-width: 900px)
et les classes .kpi-grid-v3, .qa-grid-v3, .sliders-v3, .checkin-v3.

Étape 1 — Dans le bloc @media (max-width: 900px) existant, ajoute :

  /* Dashboard mobile-first */
  .kpi-grid-v3 { grid-template-columns: 1fr 1fr !important; gap: .6rem !important; }
  .qa-grid-v3  { grid-template-columns: 1fr 1fr !important; gap: .6rem !important; }
  .kpi-val-v3  { font-size: 1.6rem !important; }
  .qa-card-v3  { padding: .7rem !important; }
  .qa-icon-v3  { font-size: 1.4rem !important; }
  .qa-label-v3 { font-size: .68rem !important; }

  /* Check-in mobile : sliders en colonne */
  .sliders-v3  { grid-template-columns: 1fr !important; gap: .8rem !important; }
  .checkin-v3  { padding: 1rem !important; border-radius: 1rem !important; }
  .checkin-v3-label { font-size: .6rem !important; }
  .btn-cta-v3  { font-size: .78rem !important; padding: .65rem 1.2rem !important; }

  /* Suggestion carousel : cartes plus larges */
  .sug-card    { flex: 0 0 160px !important; }
  .sug-photo   { height: 85px !important; }
  .sug-title   { font-size: .78rem !important; }
  .sug-sub     { font-size: .6rem !important; }
  .sug-cta     { font-size: .6rem !important; margin-top: .5rem !important; }

  /* Sections labels */
  .sec { font-size: .55rem !important; margin-bottom: .7rem !important; }

  /* Padding contenu dashboard */
  #view-dashboard > div[style*="padding"] {
    padding: 1rem !important;
  }

  /* KPI cohérence (ring) — masqué mobile déjà géré, forcer */
  .hero-right { display: none !important; }

  /* Constellation canvas mobile */
  #bcst-home-canvas { height: 200px !important; }
  #home-ciel-wrap > div[style*="height:300px"] { height: 200px !important; }

Étape 2 — Vérification :
- grep -c "sliders-v3" companion_pwa.html → doit retourner au moins 3
- grep -c "sug-card" companion_pwa.html → doit retourner au moins 3

Étape 3 — git add companion_pwa.html && git commit -m "feat: mobile — dashboard mobile-first, grilles adaptées" && git push
```

---

## PROMPT 14 — Bouton flottant "Démarrer une session"

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Repère le bloc @media (max-width: 900px)
et les classes .bottom-nav.

Étape 1 — Ajoute ce CSS juste avant </style> dans le <head> :

/* ══ FAB — Bouton flottant session rapide ══ */
#fab-session {
  display: none;
  position: fixed;
  bottom: 80px;
  right: 1rem;
  z-index: 8000;
  width: 52px; height: 52px;
  border-radius: 50%;
  background: linear-gradient(135deg, #00b4b4, #02C39A);
  border: none;
  box-shadow: 0 4px 20px rgba(0,180,180,.4);
  cursor: pointer;
  font-size: 1.4rem;
  color: #fff;
  transition: transform .15s, box-shadow .15s;
  align-items: center; justify-content: center;
}
#fab-session:active {
  transform: scale(.92);
  box-shadow: 0 2px 10px rgba(0,180,180,.3);
}
#fab-menu {
  display: none;
  position: fixed;
  bottom: 142px;
  right: 1rem;
  z-index: 8000;
  flex-direction: column;
  gap: .5rem;
  align-items: flex-end;
}
#fab-menu.open { display: flex; }
.fab-item {
  display: flex; align-items: center; gap: .6rem;
  background: rgba(255,255,255,.97);
  border: 1px solid rgba(0,180,180,.2);
  border-radius: 24px;
  padding: .5rem 1rem .5rem .7rem;
  box-shadow: 0 2px 12px rgba(0,0,0,.12);
  cursor: pointer;
  font-size: .78rem; font-weight: 600; color: #1a3535;
  white-space: nowrap;
  animation: fabItemIn .2s ease both;
}
.fab-item i { font-size: 1.1rem; }
@keyframes fabItemIn {
  from { opacity: 0; transform: translateY(10px) scale(.9); }
  to   { opacity: 1; transform: translateY(0) scale(1); }
}
.fab-overlay {
  display: none;
  position: fixed; inset: 0; z-index: 7999;
}
.fab-overlay.open { display: block; }

@media (max-width: 900px) {
  #fab-session { display: inline-flex; }
}
@media (min-width: 901px) {
  #fab-session { display: none !important; }
  #fab-menu    { display: none !important; }
}

Étape 2 — Ajoute ce HTML juste avant </body> (avant les blocs <script>) :

<div class="fab-overlay" id="fab-overlay" onclick="closeFab()"></div>
<div id="fab-menu">
  <div class="fab-item" onclick="closeFab();bnavSwitch('reservation')">
    <i class="ti ti-calendar" style="color:#F0A500"></i>Réserver un atelier
  </div>
  <div class="fab-item" onclick="closeFab();bnavSwitch('coherence')">
    <i class="ti ti-heart-rate" style="color:#02C39A"></i>Cohérence cardiaque
  </div>
  <div class="fab-item" onclick="closeFab();bnavSwitchContenus('audio')">
    <i class="ti ti-headphones" style="color:#8264DC"></i>Bibliothèque audio
  </div>
  <div class="fab-item" onclick="closeFab();bnavSwitchContenus('jeux')">
    <i class="ti ti-puzzle" style="color:#02C39A"></i>Défi cognitif
  </div>
</div>
<button id="fab-session" onclick="toggleFab()">
  <i class="ti ti-plus"></i>
</button>

Étape 3 — Dans le bloc <script> PWA existant, ajoute après la fonction haptic() :

var _fabOpen = false;
function toggleFab() {
  _fabOpen = !_fabOpen;
  haptic('light');
  var menu    = document.getElementById('fab-menu');
  var overlay = document.getElementById('fab-overlay');
  var btn     = document.getElementById('fab-session');
  if (menu)    menu.classList.toggle('open', _fabOpen);
  if (overlay) overlay.classList.toggle('open', _fabOpen);
  if (btn)     btn.style.transform = _fabOpen ? 'rotate(45deg)' : '';
}
function closeFab() {
  _fabOpen = false;
  var menu    = document.getElementById('fab-menu');
  var overlay = document.getElementById('fab-overlay');
  var btn     = document.getElementById('fab-session');
  if (menu)    menu.classList.remove('open');
  if (overlay) overlay.classList.remove('open');
  if (btn)     btn.style.transform = '';
}

Étape 4 — Vérification :
- grep -c "fab-session" companion_pwa.html → doit retourner au moins 3
- grep -c "toggleFab" companion_pwa.html → doit retourner au moins 2

Étape 5 — git add companion_pwa.html && git commit -m "feat: mobile — FAB bouton flottant session rapide" && git push
```

---

## PROMPT 15 — Vues Cohérence et Réservation adaptées mobile

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Repère les classes .cc-container,
.cc-player, .cc-sidebar, et la section calendrier (cal-header-fixed, calendrier-wrap).

Étape 1 — Dans le bloc @media (max-width: 900px) existant, ajoute :

  /* ── Cohérence cardiaque mobile ── */
  .cc-container {
    grid-template-columns: 1fr !important;
  }
  .cc-sidebar {
    display: grid !important;
    grid-template-columns: 1fr 1fr !important;
    gap: .6rem !important;
  }
  .cc-player {
    padding: 1.2rem !important;
    min-height: 280px !important;
  }
  .breathe-ring {
    width: 140px !important;
    height: 140px !important;
  }
  .cc-timer {
    font-size: 2rem !important;
  }
  #cc-protocols {
    flex-wrap: wrap !important;
    gap: .4rem !important;
  }
  .cc-protocol-btn {
    font-size: .65rem !important;
    padding: .35rem .7rem !important;
  }

  /* ── Calendrier réservation mobile ── */
  #cal-header-fixed {
    position: relative !important;
    top: auto !important;
  }
  #view-reservation .page-header h1 {
    font-size: 1.4rem !important;
  }
  #view-reservation > div[style*="flex-wrap:wrap"] {
    flex-direction: column !important;
    gap: .5rem !important;
  }

  /* ── Vues génériques mobile ── */
  .page-header h1 {
    font-size: 1.4rem !important;
  }
  .page-header p {
    font-size: .68rem !important;
  }
  .cc-stats {
    grid-template-columns: 1fr 1fr !important;
  }

  /* ── Profil mobile ── */
  .grid-2 {
    grid-template-columns: 1fr !important;
  }
  .profile-header {
    flex-direction: column !important;
    align-items: flex-start !important;
    gap: .8rem !important;
  }

  /* ── Audio/Exercices mobile ── */
  .audio-grid, .exercise-grid {
    grid-template-columns: 1fr 1fr !important;
    gap: .6rem !important;
  }
  .audio-card { padding: 0 0 .8rem !important; }
  .audio-title { font-size: .75rem !important; padding: 0 .8rem !important; }
  .audio-meta  { padding: 0 .8rem !important; }
  .audio-play-btn { margin: .5rem .8rem 0 !important; }

Étape 2 — Vérification :
- grep -c "cc-container" companion_pwa.html → doit retourner au moins 3
- grep -c "cc-sidebar" companion_pwa.html → doit retourner au moins 3

Étape 3 — git add companion_pwa.html && git commit -m "feat: mobile — vues cohérence et réservation adaptées" && git push
```

---

## PROMPT 16 — Checklist de validation finale

```
Dans companion_pwa.html uniquement. Ne touche pas à companion.html.

Étape 0 — Lis companion_pwa.html. Effectue les vérifications suivantes
et corrige uniquement ce qui est cassé.

Vérification 1 — La sidenav est masquée sur mobile :
grep -c "sidenav.*display.*none" companion_pwa.html → doit retourner au moins 1
Si absent, ajoute dans @media (max-width: 900px) : .sidenav { display: none !important; }

Vérification 2 — Le splash screen existe :
grep -c "id=\"splash\"" companion_pwa.html → doit retourner 1

Vérification 3 — L'onboarding existe :
grep -c "id=\"onboarding\"" companion_pwa.html → doit retourner 1

Vérification 4 — La bottom nav existe :
grep -c "id=\"bottom-nav\"" companion_pwa.html → doit retourner 1

Vérification 5 — Le FAB existe :
grep -c "id=\"fab-session\"" companion_pwa.html → doit retourner 1

Vérification 6 — Le pull-to-refresh existe :
grep -c "id=\"ptr-indicator\"" companion_pwa.html → doit retourner 1

Vérification 7 — La bannière offline existe :
grep -c "id=\"offline-banner\"" companion_pwa.html → doit retourner 1

Vérification 8 — Le swipe existe :
grep -c "MAIN_VIEWS" companion_pwa.html → doit retourner au moins 2

Vérification 9 — L'haptic existe :
grep -c "navigator.vibrate" companion_pwa.html → doit retourner au moins 1

Vérification 10 — Aucune erreur de syntaxe JS :
Ouvre companion_pwa.html dans un onglet Chrome en mode file:// et vérifie
la console DevTools — 0 SyntaxError.

Si tout est OK, retire du fichier :
- Le texte "Base de données locale" dans la version-tag (remplace par "beOtop Companion")
- Le texte "v0.1" dans la version-tag (remplace par "")

Puis : git add companion_pwa.html && git commit -m "fix: validation finale PWA mobile — nettoyage version-tag" && git push
```
