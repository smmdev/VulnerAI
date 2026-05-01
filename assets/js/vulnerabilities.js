import { getVulnerabilities, getStandards } from './data.js';
import Fuse from 'https://cdn.jsdelivr.net/npm/fuse.js@7/dist/fuse.mjs';

const FUSE_OPTIONS = {
  keys: [
    { name: 'title',             weight: 3   },
    { name: 'id',                weight: 2   },
    { name: 'short_description', weight: 1   },
    { name: 'category',          weight: 0.8 },
    { name: 'tags',              weight: 0.6 },
  ],
  threshold:        0.38,
  ignoreLocation:   true,
  minMatchCharLength: 2,
  shouldSort:       true,
  includeScore:     true,
};

/* ── State ─────────────────────────────────────────────────────────────── */

const state = {
  query:      '',
  severities: new Set(),
  categories: new Set(),
  models:     new Set(),
  sort:       'cvss-desc',
};

let allVulns = [];

/* ── URL sync ──────────────────────────────────────────────────────────── */

function readURL() {
  const p = new URLSearchParams(location.search);
  state.query      = p.get('q') ?? '';
  state.severities = new Set(p.get('severidad')?.split(',').filter(Boolean) ?? []);
  state.categories = new Set(p.get('categoria')?.split(',').filter(Boolean) ?? []);
  state.models     = new Set(p.get('modelo')?.split(',').filter(Boolean) ?? []);
  state.sort       = p.get('orden') ?? 'cvss-desc';
}

function pushURL() {
  const p = new URLSearchParams();
  if (state.query)           p.set('q',         state.query);
  if (state.severities.size) p.set('severidad',  [...state.severities].join(','));
  if (state.categories.size) p.set('categoria',  [...state.categories].join(','));
  if (state.models.size)     p.set('modelo',     [...state.models].join(','));
  if (state.sort !== 'cvss-desc') p.set('orden', state.sort);
  const qs = p.toString();
  history.pushState(null, '', qs ? `?${qs}` : location.pathname);
}

/* ── Filter logic ──────────────────────────────────────────────────────── */

function applyFilters() {
  let result = [...allVulns];

  // Structural filters first (severity, category, model)
  if (state.severities.size)
    result = result.filter(v => state.severities.has(v.severity));

  if (state.categories.size)
    result = result.filter(v => state.categories.has(v.standards?.owasp_llm));

  if (state.models.size)
    result = result.filter(v => v.affected_models?.some(m => state.models.has(m)));

  // Text search with fuzzy matching on the already-filtered set
  if (state.query) {
    const q = state.query;
    if (q.length === 1) {
      // Single character: strict prefix/contains
      const ql = q.toLowerCase();
      result = result.filter(v =>
        v.id.toLowerCase().includes(ql) ||
        v.title.toLowerCase().includes(ql)
      );
    } else {
      const f = new Fuse(result, FUSE_OPTIONS);
      const fuzzy = f.search(q).map(r => r.item);
      // Fuzzy search already sorts by relevance; keep that order for default sort
      if (state.sort === 'cvss-desc') return fuzzy;
      result = fuzzy;
    }
  }

  switch (state.sort) {
    case 'cvss-asc':  result.sort((a, b) => a.cvss_score - b.cvss_score); break;
    case 'alpha-asc': result.sort((a, b) => a.title.localeCompare(b.title, 'es')); break;
    case 'recent':    result.sort((a, b) => b.id.localeCompare(a.id)); break;
    default:          result.sort((a, b) => b.cvss_score - a.cvss_score);
  }

  return result;
}

/* ── Card renderer ─────────────────────────────────────────────────────── */

function cvssColor(score) {
  if (score >= 9.0) return 'var(--severity-critical)';
  if (score >= 7.0) return 'var(--severity-high)';
  if (score >= 4.0) return 'var(--severity-medium)';
  return 'var(--severity-low)';
}

function sevLabel(sev) {
  return { critical: 'CRÍTICA', high: 'ALTA', medium: 'MEDIA', low: 'BAJA' }[sev] ?? sev.toUpperCase();
}

const SUS_COLORS = {
  high:    'var(--severity-high)',
  medium:  'var(--severity-medium)',
  low:     'var(--severity-low)',
  unknown: 'var(--text-muted)',
};
const SUS_LABELS = { high: 'Alto', medium: 'Medio', low: 'Bajo', unknown: 'Desconocido' };

function modelChipsHTML(models) {
  if (!models?.length) return '';
  const MAX = 3;
  const shown = models.slice(0, MAX);
  const rest  = models.length - MAX;
  const chips = shown.map(id =>
    `<span class="vuln-card__model-chip">${MODEL_LABELS[id] ?? id}</span>`
  ).join('');
  const more = rest > 0
    ? `<span class="vuln-card__model-chip vuln-card__model-chip--more">+${rest}</span>`
    : '';
  return `<div class="vuln-card__models">${chips}${more}</div>`;
}

function vulnCardHTML(v) {
  const desc = (v.short_description ?? '').length > 120
    ? v.short_description.slice(0, 117) + '…'
    : (v.short_description ?? '');
  const color = cvssColor(v.cvss_score);

  return `
    <a href="vulnerability.html?id=${v.id}"
       class="vuln-card vuln-card--${v.severity}"
       aria-label="${v.title}, severidad ${v.severity}, CVSS ${v.cvss_score}">
      <div class="vuln-card__header">
        <span class="vuln-card__id">${v.id}</span>
        <span class="badge badge--${v.severity}">${sevLabel(v.severity)}</span>
      </div>
      <h2 class="vuln-card__title">${v.title}</h2>
      <p class="vuln-card__description">${desc}</p>
      ${modelChipsHTML(v.affected_models)}
      <div class="vuln-card__footer">
        <span class="vuln-card__standard">${v.standards?.owasp_llm ?? ''}</span>
        <span class="vuln-card__cvss" style="color:${color}">
          CVSS&nbsp;<strong class="vuln-card__cvss-large">${v.cvss_score}</strong>
        </span>
      </div>
    </a>`;
}

/* ── Skeleton ──────────────────────────────────────────────────────────── */

function skelCard() {
  return `
    <div class="skeleton-card" aria-hidden="true">
      <div class="skeleton-card__badge skeleton"></div>
      <div class="skeleton-card__title skeleton"></div>
      <div class="skeleton-card__line skeleton"></div>
      <div class="skeleton-card__line skeleton-card__line--short skeleton"></div>
      <div class="skeleton-card__footer">
        <div class="skeleton-card__footer-left skeleton"></div>
        <div class="skeleton-card__footer-right skeleton"></div>
      </div>
    </div>`;
}

/* ── Active filter chips ───────────────────────────────────────────────── */

const SEV_LABELS   = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' };
const MODEL_LABELS = {
  'gpt-4o':            'GPT-4o',
  'gpt-4o-mini':       'GPT-4o mini',
  'gpt-4-turbo':       'GPT-4 Turbo',
  'gpt-3-5-turbo':     'GPT-3.5 Turbo',
  'o1':                'o1',
  'o3-mini':           'o3-mini',
  'claude-3-5-sonnet': 'Claude 3.5 Sonnet',
  'claude-3-5-haiku':  'Claude 3.5 Haiku',
  'claude-3-opus':     'Claude 3 Opus',
  'claude-3-haiku':    'Claude 3 Haiku',
  'gemini-2.0-flash':  'Gemini 2.0 Flash',
  'gemini-1.5-pro':    'Gemini 1.5 Pro',
  'gemini-1.0-pro':    'Gemini 1.0 Pro',
  'llama-3-70b':       'LLaMA 3 70B',
  'llama-3-8b':        'LLaMA 3 8B',
  'llama-2-70b':       'LLaMA 2 70B',
  'mistral-large':     'Mistral Large',
  'mistral-7b':        'Mistral 7B',
  'mixtral-8x7b':      'Mixtral 8x7B',
  'grok-3':            'Grok-3',
  'grok-2':            'Grok-2',
  'deepseek-r1':       'DeepSeek R1',
  'deepseek-v3':       'DeepSeek V3',
  'phi-3-mini':        'Phi-3 Mini',
  'phi-3-medium':      'Phi-3 Medium',
  'command-r-plus':    'Command R+',
  'command-r':         'Command R',
  'falcon-40b':        'Falcon 40B',
  'qwen-2.5-72b':      'Qwen 2.5 72B',
  'multiple':          'Múltiples modelos',
  'other':             'Otro',
};

function renderActiveChips() {
  const container = document.getElementById('active-chips');
  if (!container) return;

  const actions = [];

  if (state.query)
    actions.push({ label: `"${state.query}"`, remove() { state.query = ''; const el = document.getElementById('search-input'); if (el) el.value = ''; } });

  state.severities.forEach(s =>
    actions.push({ label: SEV_LABELS[s] ?? s, remove() { state.severities.delete(s); } }));

  state.categories.forEach(c =>
    actions.push({ label: c.split(':')[0], remove() { state.categories.delete(c); } }));

  state.models.forEach(m =>
    actions.push({ label: MODEL_LABELS[m] ?? m, remove() { state.models.delete(m); } }));

  if (!actions.length) { container.innerHTML = ''; return; }

  container.innerHTML =
    actions.map((a, i) => `
      <button class="active-chip" data-idx="${i}" aria-label="Quitar filtro: ${a.label}">
        ${a.label}<span class="active-chip__remove" aria-hidden="true">×</span>
      </button>`).join('') +
    (actions.length > 1 ? `
      <button class="active-chip active-chip--clear" id="clear-all-chips">
        Limpiar todo <span aria-hidden="true">×</span>
      </button>` : '');

  container.querySelectorAll('[data-idx]').forEach(btn => {
    btn.addEventListener('click', () => {
      actions[+btn.dataset.idx].remove();
      syncCheckboxes();
      render();
      pushURL();
    });
  });

  document.getElementById('clear-all-chips')?.addEventListener('click', () => {
    clearAllFilters(); render(); pushURL();
  });
}

/* ── Main render ───────────────────────────────────────────────────────── */

function render() {
  const results = applyFilters();
  const grid    = document.getElementById('catalog-grid');
  const countEl = document.getElementById('result-count');
  const emptyEl = document.getElementById('empty-state');

  if (countEl)
    countEl.innerHTML = `<strong>${results.length}</strong> de <strong>${allVulns.length}</strong>`;

  renderActiveChips();

  if (!results.length) {
    grid.hidden    = true;
    emptyEl.hidden = false;
    return;
  }

  grid.hidden    = false;
  emptyEl.hidden = true;
  grid.classList.add('catalog-grid-transition');
  grid.innerHTML = results.map(vulnCardHTML).join('');
}

/* ── Sync UI ───────────────────────────────────────────────────────────── */

function syncCheckboxes() {
  document.querySelectorAll('[data-filter="severity"]').forEach(cb => { cb.checked = state.severities.has(cb.value); });
  document.querySelectorAll('[data-filter="category"]').forEach(cb => { cb.checked = state.categories.has(cb.value); });
  document.querySelectorAll('[data-filter="model"]').forEach(cb =>    { cb.checked = state.models.has(cb.value); });
  const sortEl = document.getElementById('catalog-sort');
  if (sortEl) sortEl.value = state.sort;
}

/* ── Clear all ─────────────────────────────────────────────────────────── */

function clearAllFilters() {
  state.query = '';
  state.severities.clear();
  state.categories.clear();
  state.models.clear();
  state.sort = 'cvss-desc';
  const searchEl = document.getElementById('search-input');
  if (searchEl) searchEl.value = '';
  syncCheckboxes();
}

/* ── Build OWASP category filters ──────────────────────────────────────── */

async function buildCategoryFilters() {
  const container = document.getElementById('filter-categories');
  if (!container) return;
  try {
    const data = await getStandards();
    const cats = data.standards.owasp_llm.categories;
    container.innerHTML = cats.map(cat => {
      const [code] = cat.id.split(':');
      return `
        <label class="filter-check">
          <input type="checkbox" data-filter="category" value="${cat.id}" />
          <span class="filter-check__box"></span>
          <span class="filter-check__text">
            <span class="filter-check__code">${code}</span>
            ${cat.name}
          </span>
        </label>`;
    }).join('');
    syncCheckboxes();
  } catch { /* non-blocking */ }
}

function buildModelFilters() {
  const container = document.getElementById('filter-models');
  if (!container) return;
  // Derive unique model IDs from the loaded vulnerability data so new models
  // added via admin automatically appear in the filter list.
  const modelIds = [...new Set(allVulns.flatMap(v => v.affected_models ?? []))].sort();
  if (!modelIds.length) {
    container.innerHTML = '<span class="filter-loading">Sin modelos</span>';
    return;
  }
  container.innerHTML = modelIds.map(id => `
    <label class="filter-check">
      <input type="checkbox" data-filter="model" value="${id}" />
      <span class="filter-check__box"></span>
      <span class="filter-check__text">${MODEL_LABELS[id] ?? id}</span>
    </label>`).join('');
  syncCheckboxes();
}

/* ── Event listeners ───────────────────────────────────────────────────── */

let searchDebounce;

function initListeners() {
  const searchEl = document.getElementById('search-input');
  if (searchEl) {
    searchEl.value = state.query;
    searchEl.addEventListener('input', () => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        state.query = searchEl.value.trim();
        render(); pushURL();
      }, 220);
    });
  }

  document.addEventListener('change', e => {
    const inp = e.target;
    if (inp.dataset.filter === 'severity') {
      inp.checked ? state.severities.add(inp.value) : state.severities.delete(inp.value);
      render(); pushURL();
    } else if (inp.dataset.filter === 'category') {
      inp.checked ? state.categories.add(inp.value) : state.categories.delete(inp.value);
      render(); pushURL();
    } else if (inp.dataset.filter === 'model') {
      inp.checked ? state.models.add(inp.value) : state.models.delete(inp.value);
      render(); pushURL();
    }
  });

  document.getElementById('catalog-sort')?.addEventListener('change', e => {
    state.sort = e.target.value; render(); pushURL();
  });

  document.getElementById('reset-filters')?.addEventListener('click', () => {
    clearAllFilters(); render(); pushURL();
  });

  document.getElementById('empty-clear')?.addEventListener('click', () => {
    clearAllFilters(); render(); pushURL();
  });

  // Mobile filter toggle
  document.getElementById('filter-panel-toggle')?.addEventListener('click', () => {
    const panel = document.getElementById('filter-panel');
    const btn   = document.getElementById('filter-panel-toggle');
    if (!panel) return;
    const open = panel.classList.toggle('is-open');
    panel.classList.toggle('is-collapsed', !open);
    btn?.setAttribute('aria-expanded', String(open));
  });

  window.addEventListener('popstate', () => { readURL(); syncCheckboxes(); render(); });
}

/* ── Bootstrap ─────────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  readURL();

  const grid = document.getElementById('catalog-grid');
  if (grid) grid.innerHTML = Array.from({ length: 6 }, skelCard).join('');

  try {
    allVulns = await getVulnerabilities();
    const countEl = document.getElementById("catalog-vuln-count");
    if (countEl) countEl.textContent = allVulns.length;
  } catch {
    if (grid)
      grid.innerHTML = `
        <div class="empty-state" style="grid-column:1/-1">
          <div class="empty-state__icon">⚠</div>
          <p class="empty-state__title">Error al cargar datos</p>
          <p class="empty-state__message">No se pudo conectar con el servidor de datos.</p>
        </div>`;
    return;
  }

  buildModelFilters();
  await buildCategoryFilters();
  syncCheckboxes();
  render();
  initListeners();
});
