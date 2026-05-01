import { getVulnerabilities, getStandards, getModels, getSnippets } from './data.js';

/* ── Stat counters ──────────────────────────────────────────────────────── */

function animateCounter(el) {
  const target = parseInt(el.dataset.target, 10);
  if (isNaN(target)) return;
  const duration = 1200;
  const startTime = performance.now();
  function tick(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(eased * target);
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function initStatCounters() {
  const stats = document.querySelectorAll('.hero__stat-number[data-target]');
  if (!stats.length) return;
  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) { animateCounter(e.target); observer.unobserve(e.target); }
    });
  }, { threshold: 0.6 });
  stats.forEach(el => observer.observe(el));
}

async function updateStatTargets() {
  try {
    const [vulns, staticSnippets] = await Promise.all([getVulnerabilities(), getSnippets()]);
    const totalVulns = vulns.length;

    // Snippet count = snippets reales navegables desde la página Snippets (JSON)
    const snippetCount = staticSnippets.length;

    // Model count comes from the authoritative models.json catalog
    const staticModels = await getModels();
    const modelCount   = staticModels.length;

    const stats  = document.querySelectorAll('.hero__stat-number[data-target]');
    const values = [totalVulns, 3, modelCount, snippetCount];
    stats.forEach((el, i) => {
      if (values[i] !== undefined) {
        el.dataset.target = values[i];
        el.setAttribute('aria-label', values[i]);
        el.textContent = values[i];
      }
    });

    // Update terminal "more" count (total - 5 shown in terminal)
    const moreCount = document.getElementById('terminal-more-count');
    if (moreCount && totalVulns > 5) moreCount.textContent = totalVulns - 5;
  } catch (_) {}
}

/* ── Category chips ─────────────────────────────────────────────────────── */

async function renderCategoryChips() {
  const container = document.getElementById('categories-track');
  if (!container) return;
  try {
    const data = await getStandards();
    const categories = data.standards.owasp_llm.categories;
    container.innerHTML = categories.map(cat => {
      const [code] = cat.id.split(':');
      return `
        <a href="vulnerabilities.html?categoria=${encodeURIComponent(cat.id)}"
           class="chip" role="listitem" aria-label="Filtrar por ${cat.name}">
          <strong>${code}</strong>&nbsp;${cat.name}
        </a>`;
    }).join('');
  } catch {
    container.innerHTML = '<span style="font-size:var(--text-sm);color:var(--text-muted)">No se pudieron cargar las categorías.</span>';
  }
}

/* ── Vuln cards ─────────────────────────────────────────────────────────── */

function cvssColor(score) {
  if (score >= 9.0) return 'var(--severity-critical)';
  if (score >= 7.0) return 'var(--severity-high)';
  if (score >= 4.0) return 'var(--severity-medium)';
  return 'var(--severity-low)';
}

function sevLabel(sev) {
  return { critical: 'CRÍTICA', high: 'ALTA', medium: 'MEDIA', low: 'BAJA' }[sev] ?? sev.toUpperCase();
}

function vulnCardHTML(v) {
  const desc = v.short_description.length > 120
    ? v.short_description.slice(0, 117) + '…'
    : v.short_description;
  const cvssColor_ = cvssColor(v.cvss_score);

  return `
     <a href="vulnerability.html?id=${v.id}"
       class="vuln-card vuln-card--${v.severity}"
       aria-label="${v.title}, severidad ${v.severity}, CVSS ${v.cvss_score}">
      <div class="vuln-card__header">
        <span class="vuln-card__id">${v.id}</span>
        <span class="badge badge--${v.severity}">${sevLabel(v.severity)}</span>
      </div>
      <h3 class="vuln-card__title">${v.title}</h3>
      <p class="vuln-card__description">${desc}</p>
      <div class="vuln-card__footer">
        <span class="vuln-card__standard">${v.standards?.owasp_llm ?? ''}</span>
        <span class="vuln-card__cvss" style="color:${cvssColor_}">
          CVSS&nbsp;<strong class="vuln-card__cvss-large">${v.cvss_score}</strong>
        </span>
      </div>
    </a>`;
}

async function renderFeaturedVulns() {
  const grid = document.getElementById('vuln-grid');
  if (!grid) return;
  try {
    const vulns = await getVulnerabilities();
    const top6 = [...vulns].sort((a, b) => b.cvss_score - a.cvss_score).slice(0, 6);
    grid.innerHTML = top6.map(vulnCardHTML).join('');
    grid.setAttribute('aria-busy', 'false');
  } catch {
    grid.innerHTML = `
      <div class="empty-state" style="grid-column:1/-1">
        <div class="empty-state__icon">⚠</div>
        <p class="empty-state__title">Error al cargar</p>
        <a href="vulnerabilities.html" class="btn btn--secondary btn--sm">Ir al catálogo</a>
      </div>`;
  }
}

/* ── Standards cards ────────────────────────────────────────────────────── */

const STD_ICON_SVG = {
  owasp_llm: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  mitre_atlas: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg>`,
  nist_ai_rmf: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>`,
};

function stdCount(std, key) {
  if (key === 'owasp_llm')   return `${std.categories?.length ?? 0} categorías`;
  if (key === 'mitre_atlas') {
    const total = std.tactics?.reduce((a, t) => a + (t.techniques?.length ?? 0), 0) ?? 0;
    return `${total} técnicas`;
  }
  if (key === 'nist_ai_rmf') {
    const total = std.functions?.reduce((a, f) => a + (f.controls?.length ?? 0), 0) ?? 0;
    return `${total} controles`;
  }
  return '';
}

async function renderStandards() {
  const grid = document.getElementById('standards-grid');
  if (!grid) return;
  try {
    const data = await getStandards();
    const stds = data.standards;
    const keys = ['owasp_llm', 'mitre_atlas', 'nist_ai_rmf'];

    grid.innerHTML = keys.map(key => {
      const std = stds[key];
      if (!std) return '';
      return `
        <a href="${std.url}" target="_blank" rel="noopener noreferrer"
           class="std-card" aria-label="${std.name} — abre en nueva pestaña">
          <div class="std-card__header">
            <div class="std-card__icon-wrap" aria-hidden="true">
              ${STD_ICON_SVG[key] ?? ''}
            </div>
            <span class="std-card__version-tag">v${std.version}</span>
          </div>
          <div class="std-card__name">${std.name}</div>
          <p class="std-card__desc">${std.description ?? ''}</p>
          <div class="std-card__meta">
            <span class="std-card__count">${stdCount(std, key)}</span>
            <span class="std-card__link">
              Visitar
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2.5"
                   stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M7 17L17 7"/><path d="M7 7h10v10"/>
              </svg>
            </span>
          </div>
        </a>`;
    }).join('');
  } catch {
    grid.innerHTML = '<p style="color:var(--text-muted);font-size:var(--text-sm)">Error al cargar estándares.</p>';
  }
}

/* ── Bootstrap ──────────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  // Fetch live counts first so counters animate to correct values
  await updateStatTargets();
  initStatCounters();
  renderCategoryChips();
  renderFeaturedVulns();
  renderStandards();
});
