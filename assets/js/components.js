function normalizePath(path) {
  return path.replace(/\/index\.html$/, '/').replace(/\/$/, '');
}

async function loadComponent(el, name) {
  const url = `/assets/components/${name}.html`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`No se pudo cargar ${name}`);
  el.innerHTML = await res.text();
}

function initMobileMenu() {
  const burger = document.getElementById('burger-btn');
  const menu = document.getElementById('mobile-menu');
  if (!burger || !menu) return;

  burger.addEventListener('click', () => {
    const open = menu.classList.toggle('is-open');
    burger.setAttribute('aria-expanded', String(open));
    menu.setAttribute('aria-hidden', String(!open));
  });
}

function highlightActiveNav() {
  const current = normalizePath(location.pathname);
  document.querySelectorAll('[data-nav]').forEach((link) => {
    const href = normalizePath(new URL(link.getAttribute('href'), location.origin).pathname);
    if (href && href === current) {
      link.classList.add('is-active');
      link.setAttribute('aria-current', 'page');
    }
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  const targets = document.querySelectorAll('[data-component]');
  if (!targets.length) return;

  await Promise.all(
    Array.from(targets).map(async (el) => {
      const name = el.dataset.component;
      await loadComponent(el, name);
    })
  );

  initMobileMenu();
  highlightActiveNav();

  // Auth en el header (módulo ES — dynamic import funciona en scripts clásicos modernos)
  import('./header-auth.js').then(m => m.initHeaderAuth()).catch(() => {});
});
