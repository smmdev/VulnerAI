(function () {
  'use strict';

  const STORAGE_KEY = 'vulnerai_consent';
  const SHOW_DELAY  = 1200; // ms after page load before banner appears

  function getConsent() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  function saveConsent(analytics) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        essential: true,
        analytics: analytics,
        timestamp: Date.now()
      }));
    } catch (_) {}
  }

  function dismissBanner(banner) {
    banner.classList.add('is-hiding');
    banner.addEventListener('animationend', () => banner.remove(), { once: true });
  }

  function buildBanner() {
    const el = document.createElement('div');
    el.className = 'cookie-banner';
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-modal', 'false');
    el.setAttribute('aria-label', 'Preferencias de cookies');

    el.innerHTML = `
      <div class="cookie-banner__header">
        <p class="cookie-banner__title">Este sitio usa cookies técnicas</p>
        <button type="button" class="cookie-banner__close" aria-label="Cerrar sin guardar preferencia">×</button>
      </div>
      <p class="cookie-banner__desc">
        VulnerAI utiliza únicamente una cookie técnica propia para recordar tu preferencia de consentimiento.
        No empleamos cookies de analítica ni publicidad.
        Más información en nuestra <a href="cookies.html">Política de Cookies</a>.
      </p>
      <div class="cookie-banner__actions">
        <button type="button" class="cookie-banner__btn cookie-banner__btn--accept" data-action="accept">
          Aceptar todas
        </button>
        <button type="button" class="cookie-banner__btn cookie-banner__btn--essential" data-action="essential">
          Solo esenciales
        </button>
        <a href="cookies.html" class="cookie-banner__btn cookie-banner__btn--manage">
          Gestionar cookies
        </a>
      </div>
    `;

    el.querySelector('[data-action="accept"]').addEventListener('click', () => {
      saveConsent(true);
      dismissBanner(el);
    });

    el.querySelector('[data-action="essential"]').addEventListener('click', () => {
      saveConsent(false);
      dismissBanner(el);
    });

    el.querySelector('.cookie-banner__close').addEventListener('click', () => {
      dismissBanner(el);
    });

    document.body.appendChild(el);

    el.querySelector('[data-action="accept"]').focus();
  }

  function init() {
    if (getConsent() !== null) return;
    setTimeout(buildBanner, SHOW_DELAY);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
