import { getVulnerabilities, getModels } from './data.js';

/* ── Estado de selección ────────────────────────────────────────────────── */

const selectedVulns  = new Set();
const selectedModels = new Set();

let allVulns  = [];
let allModels = [];

/* ── Utilidades ─────────────────────────────────────────────────────────── */

function cvssColor(score) {
  if (score >= 9.0) return 'var(--severity-critical)';
  if (score >= 7.0) return 'var(--severity-high)';
  if (score >= 4.0) return 'var(--severity-medium)';
  return 'var(--severity-low)';
}

function riskColor(score) {
  if (score >= 8.0) return 'var(--severity-critical)';
  if (score >= 6.5) return 'var(--severity-high)';
  if (score >= 4.0) return 'var(--severity-medium)';
  return 'var(--severity-low)';
}

function esc(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(str ?? '')));
  return d.innerHTML;
}

function sevLabel(s) {
  return { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }[s]
    ?? s?.toUpperCase() ?? '—';
}

function susLabel(sus) {
  return { high: 'Alta', medium: 'Media', low: 'Baja', unknown: 'Desconocida' }[sus]
    ?? sus ?? '—';
}

/* ── Render: lista de vulnerabilidades ──────────────────────────────────── */

function renderVulnList() {
  const container = document.getElementById('vuln-list');
  if (!container) return;

  container.innerHTML = allVulns
    .sort((a, b) => b.cvss_score - a.cvss_score)
    .map(
      (v) => `
      <label class="sel-check" title="${esc(v.short_description)}">
        <input type="checkbox"
               data-type="vuln"
               value="${v.id}"
               ${selectedVulns.has(v.id) ? 'checked' : ''}
               aria-label="${esc(v.title)}" />
        <span class="sel-check__box"></span>
        <span class="sel-check__id">${v.id}</span>
        <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(v.title)}</span>
        <span class="badge badge--${v.severity} sel-check__badge">${sevLabel(v.severity)}</span>
      </label>`
    )
    .join('');
}

/* ── Render: lista de modelos ───────────────────────────────────────────── */

function renderModelList() {
  const container = document.getElementById('model-list');
  if (!container) return;

  container.innerHTML = allModels
    .sort((a, b) => (b.overall_risk_score ?? 0) - (a.overall_risk_score ?? 0))
    .map(
      (m) => {
        const score = m.overall_risk_score;
        const scoreDisplay = score != null ? score : '—';
        return `
        <label class="sel-check">
          <input type="checkbox"
                 data-type="model"
                 value="${m.id}"
                 ${selectedModels.has(m.id) ? 'checked' : ''}
                 aria-label="${esc(m.name)}" />
          <span class="sel-check__box"></span>
          <span style="flex:1">${esc(m.name)}</span>
          <span class="sel-check__score" style="color:${score != null ? riskColor(score) : 'var(--text-muted)'}">
            ${scoreDisplay}
          </span>
        </label>`;
      }
    )
    .join('');
}

/* ── Render: matriz ─────────────────────────────────────────────────────── */

function renderMatrix() {
  const area   = document.getElementById('matrix-area');
  const status = document.getElementById('comparator-status-text');

  const vulns  = allVulns.filter((v) => selectedVulns.has(v.id))
                          .sort((a, b) => b.cvss_score - a.cvss_score);
  const models = allModels.filter((m) => selectedModels.has(m.id))
                           .sort((a, b) => b.overall_risk_score - a.overall_risk_score);

  // Status bar
  if (status) {
    status.innerHTML =
      `<strong>${vulns.length}</strong> vulnerabilidades &times; <strong>${models.length}</strong> modelos`;
  }

  if (!area) return;

  // Empty state
  if (!vulns.length || !models.length) {
    area.innerHTML = `
      <div class="comparator-empty">
        <div class="comparator-empty__icon">⊞</div>
        <p class="comparator-empty__text">
          ${
            !vulns.length && !models.length
              ? 'Selecciona al menos una vulnerabilidad y un modelo para comparar.'
              : !vulns.length
              ? 'Selecciona al menos una vulnerabilidad.'
              : 'Selecciona al menos un modelo.'
          }
        </p>
      </div>`;
    return;
  }

  // Tabla
  const headerCells = models
    .map(
      (m) => {
        const score = m.overall_risk_score;
        const riskLine = score != null
          ? `<div class="matrix-th__risk" style="color:${riskColor(score)};margin-top:var(--space-1)">Riesgo ${score}</div>`
          : '';
        return `
        <th scope="col">
          <div class="matrix-th__name">${esc(m.name)}</div>
          <div class="matrix-th__meta">${esc(m.provider ?? m.vendor ?? '')}</div>
          ${riskLine}
        </th>`;
      }
    )
    .join('');

  const bodyRows = vulns
    .map((v) => {
      const cells = models
        .map((m) => {
          const affected = v.affected_models ?? [];
          const isAffected = !affected.length || affected.includes(m.id);
          const profile = isAffected ? m.vulnerability_profile?.[v.id] : null;
          const sus     = profile?.susceptibility ?? 'unknown';
          const notes   = profile?.notes ?? '';
          const cls     = `matrix-cell matrix-cell--${sus}`;
          return `
            <td class="${cls}" title="${esc(notes)}">
              <div class="matrix-cell__badge">${susLabel(sus)}</div>
              ${notes ? `<div class="matrix-cell__note">${esc(notes)}</div>` : ''}
            </td>`;
        })
        .join('');

      return `
        <tr class="matrix-row--${v.severity}">
          <td>
            <a href="vulnerability.html?id=${v.id}" class="matrix-vuln__id">${v.id}</a>
            <span class="matrix-vuln__title">${esc(v.title)}</span>
            <div style="margin-top:var(--space-1)">
              <span class="badge badge--${v.severity}">${sevLabel(v.severity)}</span>
              <span style="font-family:var(--font-mono);font-size:var(--text-xs);color:${cvssColor(v.cvss_score)};margin-left:var(--space-2)">
                CVSS ${v.cvss_score}
              </span>
            </div>
          </td>
          ${cells}
        </tr>`;
    })
    .join('');

  area.innerHTML = `
    <div class="matrix-wrapper">
      <table class="matrix-table" aria-label="Matriz de susceptibilidad vulnerabilidades × modelos">
        <thead>
          <tr>
            <th scope="col">Vulnerabilidad</th>
            ${headerCells}
          </tr>
        </thead>
        <tbody>${bodyRows}</tbody>
      </table>
    </div>`;
}

/* ── Event listeners ────────────────────────────────────────────────────── */

function initListeners() {
  // Checkboxes por delegación
  document.addEventListener('change', (e) => {
    const inp = e.target;
    if (inp.dataset.type === 'vuln') {
      inp.checked ? selectedVulns.add(inp.value) : selectedVulns.delete(inp.value);
      renderMatrix();
    } else if (inp.dataset.type === 'model') {
      inp.checked ? selectedModels.add(inp.value) : selectedModels.delete(inp.value);
      renderMatrix();
    }
  });

  // Seleccionar / deseleccionar todas las vulnerabilidades
  document.getElementById('vuln-select-all')?.addEventListener('click', () => {
    allVulns.forEach((v) => selectedVulns.add(v.id));
    renderVulnList();
    renderMatrix();
  });
  document.getElementById('vuln-clear')?.addEventListener('click', () => {
    selectedVulns.clear();
    renderVulnList();
    renderMatrix();
  });

  // Seleccionar / deseleccionar todos los modelos
  document.getElementById('model-select-all')?.addEventListener('click', () => {
    allModels.forEach((m) => selectedModels.add(m.id));
    renderModelList();
    renderMatrix();
  });
  document.getElementById('model-clear')?.addEventListener('click', () => {
    selectedModels.clear();
    renderModelList();
    renderMatrix();
  });
}

/* ── Bootstrap ──────────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  try {
    [allVulns, allModels] = await Promise.all([getVulnerabilities(), getModels()]);

    // Por defecto: todos los modelos seleccionados, ninguna vulnerabilidad
    allModels.forEach((m) => selectedModels.add(m.id));

    renderVulnList();
    renderModelList();
    renderMatrix();
    initListeners();
  } catch (err) {
    console.error('[comparator.js]', err);
    const area = document.getElementById('matrix-area');
    if (area)
      area.innerHTML = `<div class="comparator-empty">
        <div class="comparator-empty__icon">⚠</div>
        <p class="comparator-empty__text">Error al cargar los datos.</p>
      </div>`;
  }
});
