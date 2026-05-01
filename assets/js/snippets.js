import { getVulnerabilities, getSnippetsByVulnId, getVulnerabilityById } from './data.js';

/* ── State ──────────────────────────────────────────────────────────────── */

let allVulns    = [];
let snippets    = [];
let snippetIdx  = 0;
let activeType  = 'attack'; // 'attack' | 'defense'

/* ── Utilities ──────────────────────────────────────────────────────────── */

function esc(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(str ?? '')));
  return d.innerHTML;
}

function escCode(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/* ── Populate vuln selector ─────────────────────────────────────────────── */

function populateVulnSelect(vulns) {
  const select = document.getElementById('vuln-select');
  if (!select) return;

  const sorted = [...vulns].sort((a, b) => b.cvss_score - a.cvss_score);

  select.innerHTML =
    '<option value="">— Elige una vulnerabilidad —</option>' +
    sorted.map(v =>
      `<option value="${v.id}">[${v.id}] ${v.title}</option>`
    ).join('');
}

/* ── Render output ──────────────────────────────────────────────────────── */

function renderOutput() {
  const area = document.getElementById('output-area');
  if (!area) return;

  const filtered = snippets.filter(s => s.type === activeType);

  if (!filtered.length) {
    const other = activeType === 'attack' ? 'defense' : 'attack';
    const otherLabel = other === 'attack' ? 'ataque' : 'defensa';
    area.innerHTML = `
      <div class="no-snippet">
        <div class="no-snippet__icon">◈</div>
        <p class="no-snippet__text">
          No hay snippets de tipo <strong>${activeType === 'attack' ? 'ataque' : 'defensa'}</strong>
          para esta vulnerabilidad.<br>
          Prueba con el tipo <em>${otherLabel}</em>.
        </p>
      </div>`;
    return;
  }

  const s = filtered[Math.min(snippetIdx, filtered.length - 1)];
  const currentNum = Math.min(snippetIdx, filtered.length - 1) + 1;

  const navHTML = filtered.length > 1 ? `
    <div class="snippet-nav">
      <span class="snippet-nav__label">Snippet ${currentNum} de ${filtered.length}</span>
      <button class="snippet-nav__btn" id="prev-snippet" ${snippetIdx <= 0 ? 'disabled' : ''}>← Anterior</button>
      <button class="snippet-nav__btn" id="next-snippet" ${currentNum >= filtered.length ? 'disabled' : ''}>Siguiente →</button>
    </div>` : '';

  area.innerHTML = `
    ${navHTML}
    <div class="snippet-output">
      <div class="snippet-output__head">
        <div class="snippet-output__meta">
          <span class="snippet-output__title">${esc(s.title)}</span>
          <span class="snippet-output__lang">${esc(s.language)}</span>
          <span class="snippet-output__type-badge snippet-output__type-badge--${s.type}">
            ${s.type === 'attack' ? 'ataque' : 'defensa'}
          </span>
        </div>
        <div class="snippet-output__actions">
          <button class="snippet-output__copy-btn" id="copy-snippet">
            <span>⧉</span> Copiar
          </button>
        </div>
      </div>
      <pre class="snippet-output__code" id="snippet-code">${escCode(s.code)}</pre>
    </div>
    <div class="explanation-card">
      <p class="explanation-card__label">¿Cómo funciona?</p>
      <p class="explanation-card__text">${esc(s.explanation)}</p>
    </div>
    <div class="output-actions" id="output-actions"></div>`;

  initSnippetActions(s, filtered);
}

function initSnippetActions(s, filtered) {
  // Copy button
  const copyBtn = document.getElementById('copy-snippet');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      navigator.clipboard?.writeText(s.code).then(() => {
        copyBtn.classList.add('is-copied');
        copyBtn.innerHTML = '<span>✓</span> Copiado';
        setTimeout(() => {
          copyBtn.classList.remove('is-copied');
          copyBtn.innerHTML = '<span>⧉</span> Copiar';
        }, 2000);
      }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = s.code;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      });
    });
  }

  // Snippet navigation
  document.getElementById('prev-snippet')?.addEventListener('click', () => {
    if (snippetIdx > 0) { snippetIdx--; renderOutput(); }
  });
  document.getElementById('next-snippet')?.addEventListener('click', () => {
    if (snippetIdx < filtered.length - 1) { snippetIdx++; renderOutput(); }
  });

  // Action links
  const actionsEl = document.getElementById('output-actions');
  if (actionsEl && s.vulnerability_id) {
    actionsEl.innerHTML = `
      <a href="vulnerability.html?id=${esc(s.vulnerability_id)}"
         class="btn btn--secondary btn--sm">
        Ver vulnerabilidad completa →
      </a>
      <a href="vulnerabilities.html" class="btn btn--ghost btn--sm">Explorar catálogo</a>`;
  }
}

/* ── On vuln selected ───────────────────────────────────────────────────── */

async function onVulnSelected(vulnId) {
  const area = document.getElementById('output-area');
  const vulnInfo = document.getElementById('vuln-info');

  if (!vulnId) {
    showEmptyState();
    if (vulnInfo) vulnInfo.hidden = true;
    return;
  }

  if (area) {
    area.innerHTML = `
      <div class="generator-empty">
        <div class="generator-empty__icon" style="opacity:0.15">⟳</div>
        <p class="generator-empty__title">Cargando snippets…</p>
      </div>`;
  }

  try {
    const [newSnippets, vuln] = await Promise.all([
      getSnippetsByVulnId(vulnId),
      getVulnerabilityById(vulnId),
    ]);

    snippets   = newSnippets;
    snippetIdx = 0;

    if (vuln && vulnInfo) {
      vulnInfo.hidden = false;
      vulnInfo.innerHTML = `
        <div style="display:flex;align-items:center;gap:var(--space-3);flex-wrap:wrap">
          <span style="font-family:var(--font-mono);font-size:var(--text-xs);color:var(--text-muted)">${esc(vuln.id)}</span>
          <span class="badge badge--${vuln.severity}">${vuln.severity}</span>
          <span style="font-family:var(--font-mono);font-size:var(--text-xs);color:var(--text-muted)">CVSS ${vuln.cvss_score}</span>
        </div>
        <p style="margin-top:var(--space-2);font-size:var(--text-sm);color:var(--text-secondary);line-height:1.6">
          ${esc(vuln.short_description)}
        </p>`;
    } else if (vulnInfo) {
      vulnInfo.hidden = true;
    }

    renderOutput();
  } catch (err) {
    console.error('[snippets.js]', err);
    if (area) {
      area.innerHTML = `
        <div class="generator-empty">
          <div class="generator-empty__icon">⚠</div>
          <p class="generator-empty__title">Error al cargar los snippets.</p>
        </div>`;
    }
  }
}

/* ── Empty state ────────────────────────────────────────────────────────── */

function showEmptyState() {
  const area = document.getElementById('output-area');
  if (!area) return;
  area.innerHTML = `
    <div class="generator-empty">
      <div class="generator-empty__icon">&lt;/&gt;</div>
      <p class="generator-empty__title">Configura el generador</p>
      <p class="generator-empty__text">
        Elige una vulnerabilidad y el tipo de snippet para visualizar
        el código de ejemplo.
      </p>
    </div>`;
}

/* ── Listeners ──────────────────────────────────────────────────────────── */

function initListeners() {
  // Vuln selector
  document.getElementById('vuln-select')?.addEventListener('change', (e) => {
    onVulnSelected(e.target.value);
  });

  // Type toggles
  document.querySelectorAll('.type-toggle__btn').forEach(btn => {
    btn.addEventListener('click', () => {
      activeType = btn.dataset.type;
      snippetIdx = 0;
      document.querySelectorAll('.type-toggle__btn').forEach(b => {
        b.classList.toggle('is-active', b.dataset.type === activeType);
      });
      const vulnId = document.getElementById('vuln-select')?.value;
      if (vulnId) renderOutput();
    });
  });

  // URL param: ?vuln=VAI-2026-001
  const urlParam = new URLSearchParams(location.search).get('vuln');
  if (urlParam) {
    const select = document.getElementById('vuln-select');
    if (select) {
      select.value = urlParam;
      onVulnSelected(urlParam);
    }
  }
}

/* ── Bootstrap ──────────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  try {
    allVulns = await getVulnerabilities();
    populateVulnSelect(allVulns);
    showEmptyState();
    initListeners();
  } catch (err) {
    console.error('[snippets.js bootstrap]', err);
  }
});
