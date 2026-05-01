(function () {
  'use strict';

  const KEY  = 'vulnerai_theme';
  const html = document.documentElement;

  /* ── Apply immediately — prevents flash of wrong theme ── */
  const stored     = localStorage.getItem(KEY);
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const initial    = stored ?? (prefersDark ? 'dark' : 'light');
  if (initial === 'light') html.classList.add('theme-light');

  /* ── Toggle (called from button onclick) ── */
  window.__vulneraiToggleTheme = function () {
    const isLight = html.classList.toggle('theme-light');
    localStorage.setItem(KEY, isLight ? 'light' : 'dark');
    updateAriaLabel();
  };

  function updateAriaLabel() {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    const isLight = html.classList.contains('theme-light');
    btn.setAttribute('aria-label',  isLight ? 'Cambiar a tema oscuro' : 'Cambiar a tema claro');
    btn.setAttribute('aria-pressed', String(isLight));
  }

  /* ── Update aria when header component finishes loading ── */
  document.addEventListener('DOMContentLoaded', function () {
    const observer = new MutationObserver(function () {
      if (document.getElementById('theme-toggle')) {
        updateAriaLabel();
        observer.disconnect();
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  });
})();
