import {
  getVulnerabilityById,
  getVulnerabilities,
  getSnippetsByVulnId,
  getModels,
} from './data.js';

/* ── Utilidades ─────────────────────────────────────────────────────────── */

function cvssColor(score) {
  if (score >= 9.0) return 'var(--severity-critical)';
  if (score >= 7.0) return 'var(--severity-high)';
  if (score >= 4.0) return 'var(--severity-medium)';
  return 'var(--severity-low)';
}

function impactColor(level) {
  switch (level?.toLowerCase()) {
    case 'high':   return 'var(--severity-critical)';
    case 'medium': return 'var(--severity-medium)';
    case 'low':    return 'var(--severity-low)';
    default:       return 'var(--text-muted)';
  }
}

function sevLabel(s) {
  return { critical: 'CRÍTICA', high: 'ALTA', medium: 'MEDIA', low: 'BAJA' }[s]
    ?? s?.toUpperCase() ?? '—';
}

function impactLevelLabel(val) {
  return { high: 'ALTO', medium: 'MEDIO', low: 'BAJO', none: 'NINGUNO' }[val?.toLowerCase()]
    ?? val?.toUpperCase() ?? '—';
}

function mitigTypeLabel(type) {
  return { preventive: 'Preventiva', detective: 'Detectiva', corrective: 'Correctiva' }[type]
    ?? type ?? '';
}

function susLabel(sus) {
  return { high: 'Alta', medium: 'Media', low: 'Baja', unknown: 'Desconocida' }[sus]
    ?? sus ?? '—';
}

function attackVectorLabel(vec) {
  return {
    user_input:        'Entrada de usuario',
    external_content:  'Contenido externo',
    inference:         'Inferencia',
    training_pipeline: 'Pipeline de entrenamiento',
    output_pipeline:   'Pipeline de salida',
    agent_pipeline:    'Pipeline agéntico',
    api:               'API',
  }[vec] ?? (vec ?? '—').replace(/_/g, ' ');
}

function esc(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(str ?? '')));
  return d.innerHTML;
}

function hide(id) {
  document.getElementById(id)?.setAttribute('hidden', '');
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text ?? '';
}

/* ── Progreso de lectura ────────────────────────────────────────────────── */

function initReadingProgress() {
  const bar = document.getElementById('reading-progress');
  if (!bar) return;
  window.addEventListener(
    'scroll',
    () => {
      const doc = document.documentElement;
      const max = doc.scrollHeight - doc.clientHeight;
      const pct = max > 0 ? (doc.scrollTop / max) * 100 : 0;
      bar.style.width = `${pct}%`;
      bar.setAttribute('aria-valuenow', Math.round(pct));
    },
    { passive: true }
  );
}

/* ── Tabla de contenidos ────────────────────────────────────────────────── */

const TOC_SECTIONS = [
  { id: 'section-description', label: 'Descripción' },
  { id: 'section-impact',      label: 'Impacto' },
  { id: 'section-models',      label: 'Modelos afectados' },
  { id: 'section-standards',   label: 'Mapeo de estándares' },
  { id: 'section-related',     label: 'Relacionadas' },
  { id: 'section-examples',    label: 'Vectores y ejemplos' },
  { id: 'section-mitigations', label: 'Mitigaciones' },
  { id: 'section-snippets',    label: 'Snippets de código' },
  { id: 'section-references',  label: 'Referencias' },
];

let tocObserver = null;

function buildTOC() {
  const toc = document.getElementById('toc');
  if (!toc) return;

  if (tocObserver) { tocObserver.disconnect(); tocObserver = null; }

  const visible = TOC_SECTIONS.filter((s) => {
    const el = document.getElementById(s.id);
    return el && !el.hidden && !el.closest('[hidden]');
  });

  toc.innerHTML = visible
    .map((s) => `<a href="#${s.id}" class="toc-level-2">${s.label}</a>`)
    .join('');

  tocObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        const link = toc.querySelector(`[href="#${entry.target.id}"]`);
        if (link) link.classList.toggle('is-active', entry.isIntersecting);
      });
    },
    { threshold: 0.25, rootMargin: '-5% 0px -65% 0px' }
  );

  visible.forEach((s) => {
    const el = document.getElementById(s.id);
    if (el) tocObserver.observe(el);
  });
}

/* ── Tabs ───────────────────────────────────────────────────────────────── */

function initTabs() {
  const tabs = document.querySelectorAll('.vuln-tab');
  if (!tabs.length) return;

  function switchTab(tabId) {
    tabs.forEach((tab) => {
      const active = tab.id === tabId;
      tab.setAttribute('aria-selected', String(active));
      const panel = document.getElementById(tab.getAttribute('aria-controls'));
      if (panel) panel.hidden = !active;
    });
    buildTOC();
    history.replaceState(null, '', `#${tabId.replace('tab-', '')}`);
  }

  const hash = location.hash.slice(1);
  switchTab(hash === 'tecnico' ? 'tab-tecnico' : 'tab-ejecutiva');

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => switchTab(tab.id));
    tab.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const arr = Array.from(tabs);
      const idx = arr.indexOf(tab);
      const next = e.key === 'ArrowRight'
        ? arr[(idx + 1) % arr.length]
        : arr[(idx - 1 + arr.length) % arr.length];
      next.focus();
      switchTab(next.id);
    });
  });
}

/* ── Cabecera de la ficha ───────────────────────────────────────────────── */

function renderHeader(v) {
  document.title = `VulnerAI — ${v.title}`;

  setText('breadcrumb-current', v.title);
  setText('vuln-id', v.id);
  setText('vuln-title', v.title);
  setText('vuln-subtitle', v.short_description);

  const sevEl = document.getElementById('vuln-severity');
  if (sevEl) {
    sevEl.className = `badge badge--${v.severity}`;
    sevEl.textContent = sevLabel(v.severity);
  }

  const cvssEl = document.getElementById('vuln-cvss');
  if (cvssEl) {
    const color = cvssColor(v.cvss_score);
    cvssEl.innerHTML = `CVSS <strong style="color:${color};font-size:1.35em;font-family:var(--font-heading)">${v.cvss_score}</strong>`;
  }

  const stdsEl = document.getElementById('vuln-standards');
  if (stdsEl && v.standards) {
    stdsEl.innerHTML = Object.values(v.standards)
      .filter(Boolean)
      .map((val) => `<span class="chip">${esc(val)}</span>`)
      .join('');
  }

  const gradColors = {
    critical: 'rgba(239,68,68,0.14)',
    high:     'rgba(249,115,22,0.12)',
    medium:   'rgba(234,179,8,0.10)',
    low:      'rgba(34,197,94,0.10)',
  };
  const hero = document.querySelector('.vulnerability-hero');
  if (hero) {
    const c = gradColors[v.severity] ?? 'rgba(124,58,237,0.12)';
    hero.style.backgroundImage = [
      `radial-gradient(circle at 10% -20%, ${c}, transparent 50%)`,
      `radial-gradient(circle at 80% -10%, rgba(6,182,212,0.08), transparent 55%)`,
    ].join(', ');
  }
}

/* ── Descripción ────────────────────────────────────────────────────────── */

function renderDescription(v) {
  setText('vuln-description', v.full_description);
}

/* ── Impacto ────────────────────────────────────────────────────────────── */

function renderImpact(v) {
  const grid = document.getElementById('impact-grid');
  if (!grid || !v.impact) { hide('section-impact'); return; }

  const dims = [
    { key: 'confidentiality', label: 'Confidencialidad' },
    { key: 'integrity',       label: 'Integridad' },
    { key: 'availability',    label: 'Disponibilidad' },
  ];

  const cards = dims
    .map((d) => {
      const val = v.impact[d.key] ?? 'none';
      return `
        <div class="impact-card">
          <div class="impact-card__label">${d.label}</div>
          <div class="impact-card__value" style="color:${impactColor(val)}">${impactLevelLabel(val)}</div>
        </div>`;
    })
    .join('');

  const desc = v.impact.description
    ? `<div class="impact-card" style="grid-column:1/-1">
         <div class="impact-card__label">Consecuencias</div>
         <p style="color:var(--text-secondary);font-size:var(--text-sm);margin-top:var(--space-2);line-height:1.65">${esc(v.impact.description)}</p>
       </div>`
    : '';

  grid.innerHTML = cards + desc;
}

/* ── Vectores y ejemplos ────────────────────────────────────────────────── */

function renderExamples(v) {
  const el = document.getElementById('example-list');
  if (!el || !v.examples?.length) { hide('section-examples'); return; }

  el.innerHTML = v.examples
    .map(
      (ex) => `
      <div class="example-card">
        <h3>${esc(ex.title)}</h3>
        ${
          ex.payload
            ? `<pre style="
                background:var(--bg-base);
                border:1px solid var(--border-default);
                border-radius:var(--radius-md);
                padding:var(--space-4);
                margin-top:var(--space-3);
                overflow-x:auto;
                font-family:var(--font-mono);
                font-size:var(--text-xs);
                color:var(--severity-medium);
                line-height:1.6;
                white-space:pre-wrap;
                word-break:break-word
               ">${esc(ex.payload)}</pre>`
            : ''
        }
        ${ex.description ? `<p style="margin-top:var(--space-3)">${esc(ex.description)}</p>` : ''}
      </div>`
    )
    .join('');
}

/* ── Mitigaciones ───────────────────────────────────────────────────────── */

function renderMitigations(v) {
  const el = document.getElementById('mitigation-list');
  if (!el || !v.mitigations?.length) { hide('section-mitigations'); return; }

  const typeColor = {
    preventive: 'var(--severity-low)',
    detective:  'var(--severity-medium)',
    corrective: 'var(--severity-high)',
  };

  el.innerHTML = v.mitigations
    .map(
      (m) => `
      <div class="mitigation-card">
        <div style="display:flex;align-items:flex-start;gap:var(--space-2);margin-bottom:var(--space-2);flex-wrap:wrap">
          <h3 style="margin:0;flex:1">${esc(m.title)}</h3>
          ${m.type ? `<span class="chip" style="color:${typeColor[m.type] ?? 'var(--text-muted)'};">${mitigTypeLabel(m.type)}</span>` : ''}
        </div>
        ${m.implementation ? `<p>${esc(m.implementation)}</p>` : ''}
      </div>`
    )
    .join('');
}

/* ── Snippets de código ─────────────────────────────────────────────────── */

function renderSnippets(snippets) {
  const el = document.getElementById('snippet-list');
  if (!el || !snippets?.length) { hide('section-snippets'); return; }

  el.innerHTML = snippets
    .map((s) => {
      const isAttack = s.type === 'attack';
      const typeColor = isAttack ? 'var(--severity-critical)' : 'var(--severity-low)';
      const typeLabel = isAttack ? '⚠ Ataque' : '✓ Defensa';
      const codeId = `code-${s.id}`;

      return `
        <div class="snippet-card">
          <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:var(--space-3);flex-wrap:wrap">
            <h3 style="margin:0;flex:1">${esc(s.title)}</h3>
            <span class="chip" style="color:${typeColor}">${typeLabel}</span>
          </div>
          ${s.explanation ? `<p style="margin-bottom:var(--space-4);color:var(--text-secondary);font-size:var(--text-sm);line-height:1.65">${esc(s.explanation)}</p>` : ''}
          <div class="code-block">
            <div class="code-block__header">
              <span class="code-block__lang">${esc(s.language ?? 'code')}</span>
              <button class="code-block__copy" data-copy-target="${codeId}" aria-label="Copiar código">
                Copiar
              </button>
            </div>
            <pre id="${codeId}"><code>${esc(s.code)}</code></pre>
          </div>
        </div>`;
    })
    .join('');

  el.querySelectorAll('[data-copy-target]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const code = document.getElementById(btn.dataset.copyTarget)?.textContent ?? '';
      try {
        await navigator.clipboard.writeText(code);
        const orig = btn.textContent;
        btn.textContent = '✓ Copiado';
        setTimeout(() => { btn.textContent = orig; }, 1800);
      } catch { /* silently ignore */ }
    });
  });
}

/* ── Modelos afectados ──────────────────────────────────────────────────── */

function renderModels(v, models) {
  const el = document.getElementById('model-list');
  if (!el) return;

  const affectedIds = v.affected_models ?? [];
  if (!affectedIds.length) { hide('section-models'); return; }

  const modelMap = new Map(models.map(m => [m.id, m]));
  const modelImpacts = v.model_impacts ?? v.impact?.model_impacts ?? {};

  const susColors = {
    high:     'var(--severity-high)',
    medium:   'var(--severity-medium)',
    low:      'var(--severity-low)',
    critical: 'var(--severity-critical)',
  };
  const susLabels = {
    high:     'Alta',
    medium:   'Media',
    low:      'Baja',
    critical: 'Crítica',
    unknown:  'Desconocida',
    none:     'Sin impacto',
  };

  el.innerHTML = affectedIds
    .map((id) => {
      const m = modelMap.get(id);
      // Prefer model_impacts (from new contributions) over legacy vulnerability_profile
      const impactLevel = modelImpacts[id];
      const profile = m?.vulnerability_profile?.[v.id];
      const sus = impactLevel ?? profile?.susceptibility ?? 'unknown';
      const color = susColors[sus] ?? 'var(--text-muted)';
      const label = susLabels[sus] ?? sus;

      if (m) {
        return `
          <div class="model-card">
            <div style="display:flex;align-items:flex-start;gap:var(--space-3);flex-wrap:wrap;margin-bottom:var(--space-2)">
              <h3 style="margin:0;flex:1">${esc(m.name)}</h3>
              <span class="chip" style="color:${color}">${esc(label)}</span>
            </div>
            <p style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:${profile?.notes ? 'var(--space-3)' : '0'}">
              ${esc(m.provider)} · ${esc(m.architecture)}
            </p>
            ${profile?.notes ? `<p>${esc(profile.notes)}</p>` : ''}
          </div>`;
      }
      // Model not in static JSON — show minimal card
      return `
        <div class="model-card">
          <div style="display:flex;align-items:flex-start;gap:var(--space-3);flex-wrap:wrap;margin-bottom:var(--space-2)">
            <h3 style="margin:0;flex:1">${esc(id)}</h3>
            <span class="chip" style="color:${color}">${esc(label)}</span>
          </div>
        </div>`;
    })
    .join('');
}

/* ── Mapeo de estándares ────────────────────────────────────────────────── */

function renderStandards(v) {
  const el = document.getElementById('standards-map');
  if (!el || !v.standards) { hide('section-standards'); return; }

  const meta = {
    owasp_llm:   { name: 'OWASP LLM Top 10',                 url: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/' },
    mitre_atlas: { name: 'MITRE ATLAS',                       url: 'https://atlas.mitre.org/' },
    nist_ai_rmf: { name: 'NIST AI Risk Management Framework', url: 'https://airc.nist.gov/' },
  };

  const rows = Object.entries(v.standards).filter(([, val]) => val);
  if (!rows.length) { hide('section-standards'); return; }

  el.innerHTML = rows
    .map(([key, val]) => {
      const m = meta[key] ?? { name: key, url: '#' };
      return `
        <div class="standards-map__row">
          <strong style="color:var(--text-primary);min-width:200px;flex-shrink:0">${esc(m.name)}</strong>
          <a href="${m.url}" target="_blank" rel="noopener noreferrer" class="chip">
            ${esc(val)} ↗
          </a>
        </div>`;
    })
    .join('');
}

/* ── Vulnerabilidades relacionadas ──────────────────────────────────────── */

function renderRelated(v, allVulns) {
  const el = document.getElementById('related-grid');
  const ids = v.related_vulnerabilities ?? [];
  if (!el || !ids.length) { hide('section-related'); return; }

  const related = ids.map((id) => allVulns.find((x) => x.id === id)).filter(Boolean);
  if (!related.length) { hide('section-related'); return; }

  el.innerHTML = related
    .map(
      (r) => `
      <a href="vulnerability.html?id=${r.id}"
         class="vuln-card vuln-card--${r.severity}"
         aria-label="${esc(r.title)}, CVSS ${r.cvss_score}">
        <div class="vuln-card__header">
          <span class="vuln-card__id">${r.id}</span>
          <span class="badge badge--${r.severity}">${sevLabel(r.severity)}</span>
        </div>
        <h3 class="vuln-card__title">${esc(r.title)}</h3>
        <p class="vuln-card__description">${esc(r.short_description.slice(0, 115))}…</p>
        <div class="vuln-card__footer">
          <span class="vuln-card__standard">${r.standards?.owasp_llm ?? ''}</span>
          <span class="vuln-card__cvss" style="color:${cvssColor(r.cvss_score)}">CVSS ${r.cvss_score}</span>
        </div>
      </a>`
    )
    .join('');
}

/* ── Referencias ────────────────────────────────────────────────────────── */

function renderReferences(v) {
  const el = document.getElementById('reference-list');
  if (!el || !v.references?.length) { hide('section-references'); return; }

  el.innerHTML = v.references
    .map(
      (ref) => `
      <li>
        <a href="${esc(ref.url)}" target="_blank" rel="noopener noreferrer">
          ${esc(ref.title)}
          <span aria-hidden="true" style="opacity:.5;margin-left:.3em">↗</span>
        </a>
      </li>`
    )
    .join('');
}

/* ── Sidebar ────────────────────────────────────────────────────────────── */

function renderSidebarSummary(v) {
  const el = document.getElementById('sidebar-summary');
  if (!el) return;

  const items = [
    { label: 'ID',               value: v.id },
    { label: 'Categoría',        value: v.category },
    { label: 'Subcategoría',     value: v.subcategory },
    { label: 'Severidad',        value: sevLabel(v.severity) },
    { label: 'CVSS Score',       value: v.cvss_score },
    { label: 'Vector de ataque', value: attackVectorLabel(v.attack_vector) },
    { label: 'Actualizado',      value: v.updated ? new Date(v.updated).toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' }) : '—' },
  ];

  el.innerHTML = items
    .map(
      (item) => `
      <li>
        <span style="color:var(--text-muted);font-size:var(--text-xs);display:block;margin-bottom:.2em">${item.label}</span>
        <strong>${esc(item.value)}</strong>
      </li>`
    )
    .join('');
}

/* ── Acciones del sidebar ───────────────────────────────────────────────── */

function initActions() {
  document.getElementById('copy-url')?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(location.href);
      const btn = document.getElementById('copy-url');
      const orig = btn.textContent;
      btn.textContent = '✓ Copiado';
      setTimeout(() => { btn.textContent = orig; }, 1800);
    } catch { /* clipboard no disponible */ }
  });

  document.getElementById('print-page')?.addEventListener('click', () => window.print());
}

/* ── Error ──────────────────────────────────────────────────────────────── */

function showError(msg) {
  const main = document.getElementById('main-content');
  if (!main) return;
  main.innerHTML = `
    <div class="container section">
      <div class="empty-state">
        <div class="empty-state__icon">⚠</div>
        <h2 class="empty-state__title">${esc(msg)}</h2>
        <p class="empty-state__message">Comprueba que el identificador de la URL es correcto.</p>
        <a href="vulnerabilities.html" class="btn btn--primary">Ver catálogo completo</a>
      </div>
    </div>`;
}

/* ── Bootstrap ──────────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  initReadingProgress();
  initActions();

  const id = new URLSearchParams(location.search).get('id');
  if (!id) { showError('No se especificó ninguna vulnerabilidad'); return; }

  try {
    const [vuln, jsonSnippets, models, allVulns] = await Promise.all([
      getVulnerabilityById(id),
      getSnippetsByVulnId(id),
      getModels(),
      getVulnerabilities(),
    ]);

    // For Supabase-created vulns, code_snippets may contain inline objects instead of IDs
    let snippets = jsonSnippets;
    if (!snippets.length && vuln?.code_snippets?.length) {
      const inline = vuln.code_snippets.filter(s => s && typeof s === 'object');
      if (inline.length) snippets = inline.map((s, i) => ({ id: s.id ?? `inline-${i}`, ...s }));
    }

    if (!vuln) { showError(`Vulnerabilidad "${esc(id)}" no encontrada`); return; }

    renderHeader(vuln);
    renderSidebarSummary(vuln);
    renderDescription(vuln);
    renderImpact(vuln);
    renderExamples(vuln);
    renderMitigations(vuln);
    renderSnippets(snippets);
    renderModels(vuln, models);
    renderStandards(vuln);
    renderRelated(vuln, allVulns);
    renderReferences(vuln);

    initTabs();
  } catch (err) {
    console.error('[detail.js]', err);
    showError('Error al cargar la vulnerabilidad');
  }
});
