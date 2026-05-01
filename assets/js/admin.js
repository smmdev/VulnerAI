import { supabase } from './supabase.js';
import { getVulnerabilities, getModels, getSnippets } from './data.js';

/* ── Config ──────────────────────────────────────────────────────────────── */

const ADMIN_EMAILS = [
  'carb0003@red.ujaen.es',
  'smm00156@red.ujaen.es',
  'lina@ujaen.es',
];

/* ── State ───────────────────────────────────────────────────────────────── */

let currentUser      = null;
let contributions    = [];
let activeFilter     = 'all';
let contribQuery     = '';
let contribSort      = 'newest';
let vulnCollection   = [];
let activeCollFilter = 'all';
let collQuery        = '';
let collSevFilter    = '';
let selectedVuln     = null;

let pendingApproveContribution = null;

/* ── Utilities ───────────────────────────────────────────────────────────── */

function normalizeVulnAdmin(v) {
  if (!Array.isArray(v.standards)) return v;
  const obj = {};
  v.standards.forEach(s => { if (s.framework && s.id) obj[s.framework] = s.id; });
  return { ...v, standards: obj };
}

function esc(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(str ?? '')));
  return d.innerHTML;
}

function formatDate(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleDateString('es-ES', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function statusBadge(status) {
  const label = { pending: 'Pendiente', approved: 'Aprobada', rejected: 'Rechazada' }[status] ?? status;
  return `<span class="status-badge status-badge--${status}">${label}</span>`;
}

function sevLabel(sev) {
  return { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }[sev] ?? sev ?? '—';
}

function publishedBadge(isPublished) {
  return isPublished
    ? `<span class="status-badge status-badge--published">Publicada</span>`
    : `<span class="status-badge status-badge--unpublished">No publicada</span>`;
}

function slugify(str) {
  return str
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 80);
}

/* ── Auth gate ───────────────────────────────────────────────────────────── */

function isAdmin(user) {
  return user && ADMIN_EMAILS.includes(user.email);
}

function showAuthGate(message) {
  const main = document.getElementById('admin-content');
  if (!main) return;
  main.innerHTML = `
    <div class="admin-auth-gate">
      <div class="admin-auth-gate__icon">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </div>
      <h2 class="admin-auth-gate__title">Acceso restringido</h2>
      <p class="admin-auth-gate__message">${esc(message)}</p>
      <a href="index.html" class="btn btn--secondary">Volver al inicio</a>
    </div>`;
  main.removeAttribute('hidden');
}

/* ── Navigation ──────────────────────────────────────────────────────────── */

function switchPage(pageId) {
  document.querySelectorAll('.admin-page').forEach(p => p.classList.remove('is-active'));
  document.querySelectorAll('.admin-nav-item[data-page]').forEach(n => n.classList.remove('is-active'));

  document.getElementById(`page-${pageId}`)?.classList.add('is-active');
  document.querySelector(`.admin-nav-item[data-page="${pageId}"]`)?.classList.add('is-active');

  if (pageId === 'collection') loadVulnerabilities();
}

/* ── Stats ───────────────────────────────────────────────────────────────── */

function renderStats() {
  const pending  = contributions.filter(c => c.status === 'pending').length;
  const approved = contributions.filter(c => c.status === 'approved').length;
  const rejected = contributions.filter(c => c.status === 'rejected').length;

  setText('stat-total',    contributions.length);
  setText('stat-pending',  pending);
  setText('stat-approved', approved);
  setText('stat-rejected', rejected);

  const badge = document.getElementById('nav-badge-pending');
  if (badge) {
    badge.textContent = pending;
    badge.style.display = pending > 0 ? '' : 'none';
  }

  updateOverviewCatalogStats();
}

async function updateOverviewCatalogStats() {
  try {
    const [{ getVulnerabilities: getV, getSnippets: getS, getModels: getM }] = [await import('./data.js')];
    const [vulns, snippets, models] = await Promise.all([getV(), getS(), getM()]);
    const published = vulns.filter(v => v.is_published !== false);
    setText('ov-vulns',    published.length);
    setText('ov-models',   models.length);
    setText('ov-snippets', snippets.length);
  } catch { /* silently ignore */ }
}

/* ── Clear processed contributions ──────────────────────────────────────── */

async function clearProcessedContributions() {
  const processed = contributions.filter(c => c.status === 'approved' || c.status === 'rejected');
  if (!processed.length) { showToast('No hay contribuciones procesadas que limpiar'); return; }

  if (!confirm(`¿Eliminar ${processed.length} contribuciones aprobadas/rechazadas del historial? Esta acción no se puede deshacer.`)) return;

  try {
    const ids = processed.map(c => c.id);
    const { error } = await supabase.from('contributions').delete().in('id', ids);
    if (error) throw error;
    contributions = contributions.filter(c => !ids.includes(c.id));
    renderStats();
    renderContributions();
    showToast(`${ids.length} contribuciones eliminadas del historial`);
  } catch (err) {
    showToast('Error al limpiar: ' + err.message, true);
  }
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? '';
}

/* ── Contributions list ──────────────────────────────────────────────────── */

function applyFilter(filter) {
  activeFilter = filter;
  document.querySelectorAll('.admin-filter-btn[data-filter]').forEach(btn => {
    btn.classList.toggle('is-active', btn.dataset.filter === filter);
  });
  renderContributions();
}

function renderContributions() {
  const tbody = document.getElementById('contributions-tbody');
  if (!tbody) return;

  let filtered = activeFilter === 'all'
    ? [...contributions]
    : contributions.filter(c => c.status === activeFilter);

  if (contribQuery) {
    const q = contribQuery.toLowerCase();
    filtered = filtered.filter(c =>
      c.threat_name?.toLowerCase().includes(q)    ||
      c.submitter_name?.toLowerCase().includes(q) ||
      c.submitter_email?.toLowerCase().includes(q)||
      c.affected_model?.toLowerCase().includes(q) ||
      c.attack_category?.toLowerCase().includes(q)
    );
  }

  filtered.sort((a, b) => {
    const ta = new Date(a.created_at ?? 0).getTime();
    const tb = new Date(b.created_at ?? 0).getTime();
    return contribSort === 'oldest' ? ta - tb : tb - ta;
  });

  setText('contributions-count', `${filtered.length} contribución${filtered.length !== 1 ? 'es' : ''}`);

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="admin-empty">No hay contribuciones${contribQuery ? ` que coincidan con "${esc(contribQuery)}"` : ''}.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(c => `
    <tr>
      <td class="admin-table__id">${c.id?.slice(0, 8)}…</td>
      <td>
        <div class="admin-table__title">${esc(c.threat_name)}</div>
        <div class="admin-table__meta">${esc(c.affected_model ?? '—')} · ${esc(c.attack_category ?? '—')}</div>
      </td>
      <td>${esc(c.submitter_name ?? '—')}<br><span class="admin-table__meta">${esc(c.submitter_email ?? '')}</span></td>
      <td>${sevLabel(c.severity ?? '—')}</td>
      <td>${statusBadge(c.status)}<br><span class="admin-table__meta" style="font-size:var(--text-2xs)">${formatDate(c.created_at)}</span></td>
      <td>
        <div style="display:flex;gap:var(--space-2);flex-wrap:wrap">
          <button class="admin-action-btn admin-action-btn--view" data-action="view" data-id="${c.id}">Ver</button>
          ${c.status === 'pending' ? `
            <button class="admin-action-btn admin-action-btn--approve" data-action="approve-edit" data-id="${c.id}">Editar y Aprobar</button>
            <button class="admin-action-btn admin-action-btn--reject"  data-action="reject"       data-id="${c.id}">Rechazar</button>
          ` : ''}
        </div>
      </td>
    </tr>`).join('');
}

/* ── Contribution detail modal ───────────────────────────────────────────── */

function renderExtraData(extra) {
  if (!extra || !Object.keys(extra).length) return '';

  const rows = [];

  if (extra.short_description)
    rows.push(`<div class="admin-field"><span class="admin-field__label">Descripción breve</span><div class="admin-field__value">${esc(extra.short_description)}</div></div>`);

  if (extra.cvss_score != null)
    rows.push(`<div class="admin-field"><span class="admin-field__label">Puntuación CVSS</span><div class="admin-field__value">${esc(extra.cvss_score)}</div></div>`);

  if (extra.attack_vector)
    rows.push(`<div class="admin-field"><span class="admin-field__label">Vector de ataque</span><div class="admin-field__value">${esc(extra.attack_vector)}</div></div>`);

  if (extra.cvss_vector)
    rows.push(`<div class="admin-field"><span class="admin-field__label">Vector CVSS</span><div class="admin-field__value">${esc(extra.cvss_vector)}</div></div>`);

  if (extra.standards) {
    const s = extra.standards;
    const parts = [];
    if (s.owasp_llm)  parts.push(`OWASP: ${esc(s.owasp_llm)}`);
    if (s.mitre_atlas) parts.push(`MITRE: ${esc(s.mitre_atlas)}`);
    if (s.nist_ai_rmf) parts.push(`NIST: ${esc(s.nist_ai_rmf)}`);
    if (parts.length)
      rows.push(`<div class="admin-field"><span class="admin-field__label">Estándares</span><div class="admin-field__value">${parts.join(' · ')}</div></div>`);
  }

  if (extra.impact) {
    const imp = extra.impact;
    const parts = [];
    if (imp.confidentiality) parts.push(`C: ${esc(imp.confidentiality)}`);
    if (imp.integrity)       parts.push(`I: ${esc(imp.integrity)}`);
    if (imp.availability)    parts.push(`A: ${esc(imp.availability)}`);
    const desc = imp.description ? `<br><em>${esc(imp.description)}</em>` : '';
    if (parts.length || desc)
      rows.push(`<div class="admin-field"><span class="admin-field__label">Impacto CIA</span><div class="admin-field__value">${parts.join(' · ')}${desc}</div></div>`);
  }

  if (extra.prerequisites?.length)
    rows.push(`<div class="admin-field"><span class="admin-field__label">Prerequisitos</span><div class="admin-field__value">${Array.isArray(extra.prerequisites) ? extra.prerequisites.map(esc).join(', ') : esc(extra.prerequisites)}</div></div>`);

  if (extra.tags?.length)
    rows.push(`<div class="admin-field"><span class="admin-field__label">Tags</span><div class="admin-field__value">${Array.isArray(extra.tags) ? extra.tags.map(t => `<span class="chip chip--sm">${esc(t)}</span>`).join(' ') : esc(extra.tags)}</div></div>`);

  if (extra.related_vulnerabilities?.length)
    rows.push(`<div class="admin-field"><span class="admin-field__label">Vulnerabilidades relacionadas</span><div class="admin-field__value">${Array.isArray(extra.related_vulnerabilities) ? extra.related_vulnerabilities.map(esc).join(', ') : esc(extra.related_vulnerabilities)}</div></div>`);

  if (extra.model_impacts && typeof extra.model_impacts === 'object' && Object.keys(extra.model_impacts).length) {
    const SEV_COLORS = { critical: 'var(--severity-critical)', high: 'var(--severity-high)', medium: 'var(--severity-medium)', low: 'var(--severity-low)', none: 'var(--text-muted)' };
    const chips = Object.entries(extra.model_impacts).map(([model, level]) =>
      `<span class="chip chip--sm" style="color:${SEV_COLORS[level] ?? 'var(--text-muted)'}">
        ${esc(model)}: ${esc(level)}
      </span>`).join(' ');
    rows.push(`<div class="admin-field"><span class="admin-field__label">Impacto por modelo</span><div class="admin-field__value" style="display:flex;flex-wrap:wrap;gap:4px">${chips}</div></div>`);
  }

  if (extra.mitigations?.length) {
    const list = extra.mitigations.map(m =>
      `<li><strong>${esc(m.title || '—')}</strong> <em>(${esc(m.type || '?')})</em>${m.implementation ? `<br>${esc(m.implementation)}` : ''}</li>`
    ).join('');
    rows.push(`<div class="admin-field"><span class="admin-field__label">Mitigaciones</span><div class="admin-field__value"><ul style="margin:0;padding-left:1.2em">${list}</ul></div></div>`);
  }

  if (extra.examples?.length) {
    const list = extra.examples.map(ex =>
      `<li><strong>${esc(ex.title || '—')}</strong>${ex.payload ? `<pre style="font-size:var(--text-xs);margin:4px 0;white-space:pre-wrap">${esc(ex.payload)}</pre>` : ''}${ex.description ? `<span style="color:var(--text-muted)">${esc(ex.description)}</span>` : ''}</li>`
    ).join('');
    rows.push(`<div class="admin-field"><span class="admin-field__label">Ejemplos de ataque</span><div class="admin-field__value"><ul style="margin:0;padding-left:1.2em">${list}</ul></div></div>`);
  }

  if (extra.code_snippets?.length) {
    const list = extra.code_snippets.map(s =>
      `<li><strong>${esc(s.title || '—')}</strong> <em>(${esc(s.language || '?')}, ${esc(s.type || '?')})</em>${s.explanation ? `<br><span style="color:var(--text-muted)">${esc(s.explanation)}</span>` : ''}${s.code ? `<pre style="font-size:var(--text-xs);margin:4px 0;white-space:pre-wrap">${esc(s.code)}</pre>` : ''}</li>`
    ).join('');
    rows.push(`<div class="admin-field"><span class="admin-field__label">Snippets de código</span><div class="admin-field__value"><ul style="margin:0;padding-left:1.2em">${list}</ul></div></div>`);
  }

  if (extra.references?.length) {
    const list = extra.references.map(r =>
      `<li>${r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.title || r.url)}</a>` : esc(r.title || '—')}</li>`
    ).join('');
    rows.push(`<div class="admin-field"><span class="admin-field__label">Referencias</span><div class="admin-field__value"><ul style="margin:0;padding-left:1.2em">${list}</ul></div></div>`);
  }

  if (!rows.length) return '';
  return `
    <details style="margin:var(--space-5) 0;border:1px solid var(--border-subtle);border-radius:var(--radius-md);overflow:hidden" open>
      <summary style="padding:var(--space-3) var(--space-4);background:var(--bg-raised);cursor:pointer;font-weight:600;font-size:var(--text-sm);list-style:none">
        Datos adicionales del contribuidor
      </summary>
      <div style="padding:var(--space-4)">
        ${rows.join('')}
      </div>
    </details>`;
}

function openModal(contribution, viewOnly = false) {
  const overlay = document.getElementById('contribution-modal');
  if (!overlay) return;

  document.getElementById('modal-title').textContent    = contribution.threat_name;
  document.getElementById('modal-status').innerHTML     = statusBadge(contribution.status);
  document.getElementById('modal-severity').innerHTML   = contribution.severity
    ? `<span class="badge badge--${contribution.severity}">${sevLabel(contribution.severity)}</span>`
    : '—';

  // Affected models as chips
  const modelsArr = (contribution.affected_model ?? '').split(',').map(s => s.trim()).filter(Boolean);
  document.getElementById('modal-model').innerHTML = modelsArr.length
    ? modelsArr.map(m => `<span class="chip chip--sm" style="margin:2px">${esc(m)}</span>`).join('')
    : '—';

  document.getElementById('modal-category').textContent    = categoryLabel(contribution.attack_category ?? '') ?? '—';
  document.getElementById('modal-subcategory').textContent = contribution.attack_subcategory  ?? '—';
  document.getElementById('modal-payload').textContent     = contribution.attack_payload      ?? '—';
  document.getElementById('modal-description').textContent = contribution.tech_description    ?? '—';
  document.getElementById('modal-mitigation').textContent  = contribution.mitigation_proposal ?? '—';
  document.getElementById('modal-cve').textContent         = contribution.cve_reference       ?? '—';
  document.getElementById('modal-submitter').textContent   = `${contribution.submitter_name ?? '—'} (${contribution.submitter_email ?? '—'})`;
  document.getElementById('modal-date').textContent        = formatDate(contribution.created_at);

  const extraEl = document.getElementById('modal-extra-data');
  if (extraEl) extraEl.innerHTML = renderExtraData(contribution.extra_data ?? {});

  const actionsEl = document.getElementById('modal-actions');
  if (actionsEl) {
    if (viewOnly) {
      const statusText = contribution.status === 'approved'
        ? 'aprobada' : contribution.status === 'rejected' ? 'rechazada' : 'pendiente';
      actionsEl.innerHTML = `
        <p style="color:var(--text-muted);font-size:var(--text-sm);flex:1">
          Esta contribución está <strong>${statusText}</strong>.
        </p>
        <button class="btn btn--ghost" id="modal-close-view-btn">Cerrar</button>
      `;
      document.getElementById('modal-close-view-btn')?.addEventListener('click', closeModal);
    } else if (contribution.status === 'pending') {
      actionsEl.innerHTML = `
        <textarea id="reject-reason" class="admin-reject-reason" placeholder="Motivo del rechazo (opcional)…"></textarea>
        <button class="btn btn--primary"  id="modal-approve-edit-btn">Editar y Aprobar</button>
        <button class="btn btn--ghost"    id="modal-reject-btn" style="color:var(--severity-critical)">Rechazar</button>
      `;
      document.getElementById('modal-approve-edit-btn')?.addEventListener('click', () => {
        closeModal();
        openApproveEditModal(contribution);
      });
      document.getElementById('modal-reject-btn')?.addEventListener('click', () => {
        const reason = document.getElementById('reject-reason')?.value?.trim() ?? '';
        rejectContribution(contribution.id, reason);
      });
    } else {
      actionsEl.innerHTML = `<p style="color:var(--text-muted);font-size:var(--text-sm)">
        Esta contribución ya fue ${contribution.status === 'approved' ? 'aprobada' : 'rechazada'}.
      </p>`;
    }
  }

  overlay.hidden = false;
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  const overlay = document.getElementById('contribution-modal');
  if (overlay) overlay.hidden = true;
  document.body.style.overflow = '';
}

/* ── Reject confirmation dialog ──────────────────────────────────────────── */

function showRejectConfirm(contribution) {
  const existing = document.getElementById('reject-confirm-overlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'reject-confirm-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:var(--space-4)';
  overlay.innerHTML = `
    <div role="dialog" aria-modal="true" aria-labelledby="reject-dlg-title"
         style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius-lg);padding:var(--space-8);max-width:600px;width:100%;box-shadow:0 24px 48px rgba(0,0,0,0.5)">
      <div style="font-size:2.6rem;text-align:center;margin-bottom:var(--space-4)">⚠</div>
      <h3 id="reject-dlg-title" style="text-align:center;margin-bottom:var(--space-3);font-size:var(--text-xl)">Rechazar contribución</h3>
      <p style="text-align:center;color:var(--text-secondary);font-size:var(--text-sm);margin-bottom:var(--space-6);line-height:1.6">
        La contribución <strong>"${esc(contribution.threat_name)}"</strong> será rechazada de forma definitiva.
        ¿Estás seguro?
      </p>
      <label style="display:block;font-size:var(--text-sm);font-weight:500;color:var(--text-secondary);margin-bottom:var(--space-2)">Motivo del rechazo (opcional)</label>
      <textarea id="reject-reason-inline" rows="5"
        style="width:100%;box-sizing:border-box;padding:var(--space-3) var(--space-4);border:1px solid var(--border-subtle);border-radius:var(--radius-md);background:var(--bg-raised);color:var(--text-primary);font-size:var(--text-sm);resize:vertical;margin-bottom:var(--space-7);line-height:1.5"
        placeholder="Describe el motivo del rechazo para informar al contribuidor…"></textarea>
      <div style="display:flex;gap:var(--space-4);justify-content:center">
        <button id="reject-cancel-btn" class="btn btn--ghost" style="min-width:120px">Cancelar</button>
        <button id="reject-confirm-btn" class="btn btn--primary" style="min-width:140px;background:var(--severity-critical);border-color:var(--severity-critical)">
          Sí, rechazar
        </button>
      </div>
    </div>`;

  document.body.appendChild(overlay);

  const close = () => overlay.remove();
  document.getElementById('reject-cancel-btn').addEventListener('click', close);
  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });

  function onEsc(e) {
    if (e.key === 'Escape') { close(); document.removeEventListener('keydown', onEsc); }
  }
  document.addEventListener('keydown', onEsc);

  document.getElementById('reject-confirm-btn').addEventListener('click', () => {
    const reason = document.getElementById('reject-reason-inline')?.value.trim() ?? '';
    close();
    rejectContribution(contribution.id, reason);
  });
}

/* ── Email notification ──────────────────────────────────────────────────── */

async function sendEmailNotification(contribution, action, reason = '', vulnId = '') {
  const to = contribution.submitter_email;
  if (!to) return;
  try {
    const { error, data } = await supabase.functions.invoke('send-contribution-email', {
      body: {
        to,
        name:        contribution.submitter_name ?? '',
        threat_name: contribution.threat_name,
        action,
        reason:      reason || undefined,
        vuln_id:     vulnId || undefined,
      },
    });
    if (error) {
      console.warn('[email] función error:', error.message);
      showToast(`Aviso: email no enviado a ${to} (${error.message})`, true);
    } else if (data?.ok === false) {
      console.warn('[email] brevo error:', data.error);
      showToast(`Aviso: email no enviado a ${to}`, true);
    } else {
      showToast(`Email de notificación enviado a ${to}`);
    }
  } catch (err) {
    console.warn('[email] no enviado:', err.message);
    showToast(`Aviso: email no pudo enviarse a ${to}`, true);
  }
}

/* ── Reject ──────────────────────────────────────────────────────────────── */

async function rejectContribution(id, reason = '') {
  const contribution = contributions.find(c => c.id === id);
  if (!contribution) return;

  try {
    const { error } = await supabase
      .from('contributions')
      .update({
        status:           'rejected',
        updated_at:       new Date().toISOString(),
        admin_notes:      `(${new Date().toLocaleString('es-ES')}) Rechazado${reason ? ': ' + reason : ''}`,
        rejection_reason: reason || null,
      })
      .eq('id', id);

    if (error) throw error;

    contributions = contributions.filter(c => c.id !== id);
    closeModal();
    showToast(`Contribución "${contribution.threat_name}" rechazada`);
    renderStats();
    renderContributions();

    sendEmailNotification(contribution, 'rejected', reason);
  } catch (err) {
    showToast('Error al rechazar: ' + err.message, true);
  }
}

/* ── Per-model impact UI (admin edit modal) ─────────────────────────────── */

const ADMIN_IMPACT_OPTIONS = ['critical', 'high', 'medium', 'low', 'unknown'];
const ADMIN_IMPACT_LABELS  = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', unknown: 'Desconocido' };

function renderAdminModelImpactRows(modelIdsStr, existingImpacts = {}) {
  const section   = document.getElementById('admin-model-impact-section');
  const container = document.getElementById('admin-model-impact-rows');
  if (!section || !container) return;

  const modelIds = (modelIdsStr ?? '').split(',').map(s => s.trim()).filter(Boolean);
  if (!modelIds.length) { section.style.display = 'none'; return; }

  container.innerHTML = modelIds.map(id => {
    const prev = existingImpacts[id] ?? 'unknown';
    const opts = ADMIN_IMPACT_OPTIONS.map(v =>
      `<option value="${v}"${prev === v ? ' selected' : ''}>${ADMIN_IMPACT_LABELS[v]}</option>`
    ).join('');
    return `
      <div class="model-impact-row" data-model-id="${esc(id)}"
           style="display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) var(--space-3);border-bottom:1px solid var(--border-subtle);flex-wrap:wrap">
        <span style="flex:1;min-width:80px;font-size:var(--text-sm);color:var(--text-secondary);word-break:break-all">${esc(id)}</span>
        <select class="admin-edit-input" style="flex:0 0 140px">${opts}</select>
      </div>`;
  }).join('');

  section.style.display = '';
}

function collectAdminModelImpacts() {
  const impacts = {};
  document.querySelectorAll('#admin-model-impact-rows .model-impact-row').forEach(row => {
    const id  = row.dataset.modelId;
    const val = row.querySelector('select')?.value;
    if (id && val && val !== 'unknown') impacts[id] = val;
    else if (id && val === 'unknown')   impacts[id] = val;
  });
  return impacts;
}

/* ── Approve-edit flow ───────────────────────────────────────────────────── */

function openApproveEditModal(contribution) {
  pendingApproveContribution = contribution;

  const modelsRaw      = contribution.affected_model ?? '';
  const affectedModels = modelsRaw.split(',').map(s => s.trim()).filter(Boolean);
  const extra          = contribution.extra_data ?? {};

  document.getElementById('vuln-edit-id').value            = '';
  document.getElementById('vuln-edit-title').textContent   = `Revisión: ${contribution.threat_name}`;
  document.getElementById('vuln-edit-title-input').value   = contribution.threat_name ?? '';
  document.getElementById('vuln-edit-severity').value      = contribution.severity ?? 'medium';
  document.getElementById('vuln-edit-model').value         = affectedModels.join(', ');
  document.getElementById('vuln-edit-category').value      = categoryLabel(contribution.attack_category);
  document.getElementById('vuln-edit-subcategory').value   = contribution.attack_subcategory ?? '';
  document.getElementById('vuln-edit-cve').value           = contribution.cve_reference ?? '';
  document.getElementById('vuln-edit-cvss').value          = '';
  document.getElementById('vuln-edit-published').checked   = true;
  document.getElementById('vuln-edit-short-desc').value    = extra.short_description || (contribution.tech_description ?? '').slice(0, 300);
  document.getElementById('vuln-edit-full-desc').value     = contribution.tech_description ?? '';

  document.getElementById('vuln-edit-attack-vector').value = extra.attack_vector ?? '';
  document.getElementById('vuln-edit-cvss-vector').value   = extra.cvss_vector   ?? '';
  document.getElementById('vuln-edit-std-owasp').value     = extra.standards?.owasp_llm   ?? '';
  document.getElementById('vuln-edit-std-mitre').value     = extra.standards?.mitre_atlas
    ?? (contribution.cve_reference?.startsWith('AML.') ? contribution.cve_reference : '');
  document.getElementById('vuln-edit-std-nist').value      = extra.standards?.nist_ai_rmf ?? '';

  const imp = extra.impact ?? {};
  document.getElementById('vuln-edit-impact-c').value    = imp.confidentiality ?? extra.impact_confidentiality ?? 'none';
  document.getElementById('vuln-edit-impact-i').value    = imp.integrity       ?? extra.impact_integrity       ?? 'none';
  document.getElementById('vuln-edit-impact-a').value    = imp.availability    ?? extra.impact_availability    ?? 'none';
  document.getElementById('vuln-edit-impact-desc').value = imp.description     ?? '';

  const prereqRaw = extra.prerequisites;
  document.getElementById('vuln-edit-prerequisites').value =
    Array.isArray(prereqRaw) ? prereqRaw.join(', ') : (prereqRaw ?? '');
  const tagsRaw = extra.tags;
  document.getElementById('vuln-edit-tags').value =
    Array.isArray(tagsRaw) ? tagsRaw.join(', ') : (tagsRaw ?? '');
  const relatedRaw = extra.related_vulnerabilities;
  document.getElementById('vuln-edit-related').value =
    Array.isArray(relatedRaw) ? relatedRaw.join(', ') : (relatedRaw ?? '');

  // Pre-fill dynamic lists from contribution data
  // Pre-fill dynamic lists from extra_data if available, else from core fields
  const initExamples = extra.examples?.length
    ? extra.examples
    : [{ title: contribution.threat_name ?? 'Ejemplo de ataque', payload: contribution.attack_payload ?? '', description: '' }];
  populateExamples(initExamples);

  const initMitigations = extra.mitigations?.length
    ? extra.mitigations
    : (contribution.mitigation_proposal
      ? [{ type: 'preventive', title: 'Mitigación propuesta', implementation: contribution.mitigation_proposal }]
      : []);
  populateMitigations(initMitigations);

  populateReferences(extra.references ?? []);
  populateSnippet(extra.code_snippets ?? []);
  renderAdminModelImpactRows(affectedModels.join(', '), extra.model_impacts ?? {});

  const saveBtn = document.getElementById('vuln-edit-save-btn');
  if (saveBtn) {
    saveBtn.textContent = 'Aceptar contribución';
    saveBtn.style.background = 'var(--severity-low)';
  }

  // Show approval reason field
  const approvalWrap = document.getElementById('approval-reason-wrap');
  const approvalReason = document.getElementById('approval-reason');
  if (approvalWrap) approvalWrap.style.display = '';
  if (approvalReason) approvalReason.value = '';

  const overlay = document.getElementById('vuln-edit-modal');
  if (overlay) {
    overlay.hidden = false;
    document.body.style.overflow = 'hidden';
  }
}

/* ── Approve contribution ────────────────────────────────────────────────── */

async function approveContribution(contribution, vulnData) {
  try {
    const newId = await generateVulnId();
    const vuln  = {
      id:                      newId,
      slug:                    slugify(vulnData.title) || newId,
      title:                   vulnData.title,
      short_description:       vulnData.short_description,
      full_description:        vulnData.full_description,
      severity:                vulnData.severity,
      category:                vulnData.category,
      subcategory:             vulnData.subcategory ?? null,
      affected_models:         vulnData.affected_models,
      standards:               vulnData.standards ?? [],
      is_published:            vulnData.is_published,
      cvss_score:              vulnData.cvss_score ?? 0.0,
      attack_vector:           vulnData.attack_vector ?? null,
      cvss_vector:             vulnData.cvss_vector ?? null,
      impact:                  vulnData.impact ?? {},
      prerequisites:           vulnData.prerequisites ?? [],
      tags:                    vulnData.tags ?? [],
      related_vulnerabilities: vulnData.related_vulnerabilities ?? [],
      examples:                vulnData.examples ?? [],
      mitigations:             vulnData.mitigations ?? [],
      references:              vulnData.references ?? [],
      code_snippets:           vulnData.code_snippets ?? [],
      ...(vulnData.cve_reference ? { cve_reference: vulnData.cve_reference } : {}),
    };

    const { error: insertErr } = await supabase.from('vulnerabilities').insert(vuln);
    if (insertErr) throw new Error('Error al crear vulnerabilidad: ' + insertErr.message);

    const approvalReason = document.getElementById('approval-reason')?.value.trim() ?? '';
    const { error: updateErr } = await supabase
      .from('contributions')
      .update({
        status:      'approved',
        updated_at:  new Date().toISOString(),
        admin_notes: `(${new Date().toLocaleString('es-ES')}) Aprobado${approvalReason ? ': ' + approvalReason : ''} — vulnerabilidad creada: ${newId}`,
        ...(approvalReason ? { acceptance_reason: approvalReason } : {}),
      })
      .eq('id', contribution.id);

    if (updateErr) console.warn('[admin] contribution update error:', updateErr.message);

    contributions = contributions.filter(c => c.id !== contribution.id);
    renderStats();
    renderContributions();
    showToast(`Contribución aprobada. Vulnerabilidad ${newId} creada correctamente`);

    sendEmailNotification(contribution, 'approved', approvalReason, newId);

    if (document.getElementById('page-collection')?.classList.contains('is-active')) {
      await loadVulnerabilities();
    } else {
      vulnCollection = [];
    }
  } catch (err) {
    throw err;
  }
}

/* ── Toast ───────────────────────────────────────────────────────────────── */

function showToast(message, isError = false) {
  const existing = document.getElementById('admin-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'admin-toast';
  toast.style.cssText = `
    position:fixed;bottom:var(--space-6);right:var(--space-6);
    background:${isError ? 'var(--severity-critical)' : 'var(--accent-primary)'};
    color:#fff;padding:var(--space-3) var(--space-5);border-radius:var(--radius-lg);
    font-size:var(--text-sm);font-weight:500;z-index:300;max-width:420px;
    box-shadow:0 4px 24px rgba(0,0,0,0.2);animation:fadeInUp 0.2s ease;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4500);
}

/* ── Load contributions ──────────────────────────────────────────────────── */

async function loadContributions() {
  try {
    const { data, error } = await supabase
      .from('contributions')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    contributions = data ?? [];
    renderStats();
    renderContributions();
  } catch (err) {
    console.error('[admin] loadContributions error:', err);
    const tbody = document.getElementById('contributions-tbody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="admin-empty">Error al cargar contribuciones.</td></tr>';
  }
}

/* ── Collection: vulnerabilities CRUD ───────────────────────────────────── */

async function loadVulnerabilities() {
  const tbody = document.getElementById('collection-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="admin-empty">Cargando…</td></tr>';
  try {
    const { data, error } = await supabase
      .from('vulnerabilities')
      .select('*')
      .order('id', { ascending: true });

    if (error) throw error;
    vulnCollection = (data ?? []).map(normalizeVulnAdmin);
    renderVulnerabilities();
  } catch (err) {
    console.error('[admin] loadVulnerabilities error:', err);
    if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="admin-empty">Error: ${esc(err.message)}</td></tr>`;
  }
}

function applyCollFilter(filter) {
  activeCollFilter = filter;
  document.querySelectorAll('.admin-filter-btn[data-collection-filter]').forEach(btn => {
    btn.classList.toggle('is-active', btn.dataset.collectionFilter === filter);
  });
  renderVulnerabilities();
}

function renderVulnerabilities() {
  const tbody = document.getElementById('collection-tbody');
  if (!tbody) return;

  let filtered = activeCollFilter === 'all'
    ? [...vulnCollection]
    : vulnCollection.filter(v =>
        activeCollFilter === 'published' ? v.is_published : !v.is_published
      );

  if (collSevFilter)
    filtered = filtered.filter(v => v.severity === collSevFilter);

  if (collQuery) {
    const q = collQuery.toLowerCase();
    filtered = filtered.filter(v =>
      v.id?.toLowerCase().includes(q)       ||
      v.title?.toLowerCase().includes(q)    ||
      v.category?.toLowerCase().includes(q) ||
      v.slug?.toLowerCase().includes(q)
    );
  }

  setText('collection-count', `${filtered.length} vulnerabilidad${filtered.length !== 1 ? 'es' : ''}`);

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="admin-empty">No hay vulnerabilidades${collQuery ? ` que coincidan con "${esc(collQuery)}"` : ''}.</td></tr>`;
    return;
  }

  const SEV_LABELS_ES = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' };

  tbody.innerHTML = filtered.map(v => `
    <tr>
      <td class="admin-table__id">${esc(v.id ?? '—')}</td>
      <td>
        <div class="admin-table__title">${esc(v.title ?? '—')}</div>
        <div class="admin-table__meta">${esc(v.slug ?? '')}</div>
      </td>
      <td>
        <div>${esc(v.category ?? '—')}</div>
        ${v.subcategory ? `<div class="admin-table__meta">${esc(v.subcategory)}</div>` : ''}
      </td>
      <td><span class="badge badge--${v.severity ?? 'low'}">${SEV_LABELS_ES[v.severity] ?? esc(v.severity ?? '—')}</span></td>
      <td>${publishedBadge(v.is_published)}</td>
      <td>
        <div style="display:flex;gap:var(--space-2)">
          <button class="admin-action-btn admin-action-btn--edit"   data-vuln-action="edit"   data-vuln-id="${esc(v.id)}">Editar</button>
          <button class="admin-action-btn admin-action-btn--delete" data-vuln-action="delete" data-vuln-id="${esc(v.id)}">Eliminar</button>
        </div>
      </td>
    </tr>`).join('');
}

/* ── Dynamic examples list ───────────────────────────────────────────────── */

let examplesCount = 0;

function addExampleRow(ex = {}) {
  examplesCount++;
  const n = examplesCount;
  const row = document.createElement('div');
  row.className = 'admin-dynamic-row';
  row.innerHTML = `
    <div style="border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:var(--space-4);margin-bottom:var(--space-3)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-3)">
        <span style="font-weight:600;font-size:var(--text-sm);color:var(--text-secondary)">Ejemplo ${n}</span>
        <button type="button" class="admin-action-btn admin-action-btn--delete row-remove-btn">Eliminar</button>
      </div>
      <div style="display:flex;flex-direction:column;gap:var(--space-3)">
        <div class="admin-field">
          <label class="admin-field__label">Título</label>
          <input type="text" class="admin-edit-input ex-title" value="${esc(ex.title ?? '')}" placeholder="Ej. Inyección vía PDF malicioso" />
        </div>
        <div class="admin-field">
          <label class="admin-field__label">Payload / Prompt</label>
          <textarea class="admin-edit-input ex-payload" rows="4" style="font-family:var(--font-mono);font-size:var(--text-xs)">${esc(ex.payload ?? '')}</textarea>
        </div>
        <div class="admin-field">
          <label class="admin-field__label">Descripción del escenario</label>
          <textarea class="admin-edit-input ex-description" rows="2" placeholder="Contexto y condiciones del ataque…">${esc(ex.description ?? ex.context ?? '')}</textarea>
        </div>
      </div>
    </div>`;
  row.querySelector('.row-remove-btn').addEventListener('click', () => row.remove());
  document.getElementById('examples-list').appendChild(row);
}

function populateExamples(examples) {
  const container = document.getElementById('examples-list');
  if (!container) return;
  container.innerHTML = '';
  examplesCount = 0;
  if (Array.isArray(examples) && examples.length) examples.forEach(ex => addExampleRow(ex));
}

function collectExamples() {
  return Array.from(document.getElementById('examples-list')?.querySelectorAll('.admin-dynamic-row') ?? [])
    .map(row => ({
      title:       row.querySelector('.ex-title')?.value.trim() ?? '',
      payload:     row.querySelector('.ex-payload')?.value.trim() ?? '',
      description: row.querySelector('.ex-description')?.value.trim() ?? '',
    }))
    .filter(ex => ex.title || ex.payload);
}

/* ── Dynamic mitigations list ────────────────────────────────────────────── */

let mitigationsCount = 0;

function addMitigationRow(m = {}) {
  mitigationsCount++;
  const n = mitigationsCount;
  const row = document.createElement('div');
  row.className = 'admin-dynamic-row';
  row.innerHTML = `
    <div style="border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:var(--space-4);margin-bottom:var(--space-3)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-3)">
        <span style="font-weight:600;font-size:var(--text-sm);color:var(--text-secondary)">Mitigación ${n}</span>
        <button type="button" class="admin-action-btn admin-action-btn--delete row-remove-btn">Eliminar</button>
      </div>
      <div style="display:grid;grid-template-columns:1fr 2fr;gap:var(--space-3)">
        <div class="admin-field">
          <label class="admin-field__label">Tipo</label>
          <select class="admin-edit-input mit-type">
            <option value="preventive" ${(m.type === 'preventive' || !m.type) ? 'selected' : ''}>Preventiva</option>
            <option value="detective"  ${m.type === 'detective'  ? 'selected' : ''}>Detectiva</option>
            <option value="corrective" ${m.type === 'corrective' ? 'selected' : ''}>Correctiva</option>
          </select>
        </div>
        <div class="admin-field">
          <label class="admin-field__label">Título</label>
          <input type="text" class="admin-edit-input mit-title" value="${esc(m.title ?? '')}" placeholder="Nombre de la medida" />
        </div>
        <div class="admin-field" style="grid-column:1/-1">
          <label class="admin-field__label">Implementación</label>
          <textarea class="admin-edit-input mit-implementation" rows="3" placeholder="Describe cómo implementar esta mitigación…">${esc(m.implementation ?? '')}</textarea>
        </div>
      </div>
    </div>`;
  row.querySelector('.row-remove-btn').addEventListener('click', () => row.remove());
  document.getElementById('mitigations-list').appendChild(row);
}

function populateMitigations(mitigations) {
  const container = document.getElementById('mitigations-list');
  if (!container) return;
  container.innerHTML = '';
  mitigationsCount = 0;
  const list = Array.isArray(mitigations) ? mitigations : [];
  list.forEach(m => addMitigationRow(m));
}

function collectMitigations() {
  return Array.from(document.getElementById('mitigations-list')?.querySelectorAll('.admin-dynamic-row') ?? [])
    .map(row => ({
      type:           row.querySelector('.mit-type')?.value ?? 'preventive',
      title:          row.querySelector('.mit-title')?.value.trim() ?? '',
      implementation: row.querySelector('.mit-implementation')?.value.trim() ?? '',
    }))
    .filter(m => m.title || m.implementation);
}

/* ── Dynamic references list ─────────────────────────────────────────────── */

let referencesCount = 0;

function addReferenceRow(ref = {}) {
  referencesCount++;
  const n = referencesCount;
  const row = document.createElement('div');
  row.className = 'admin-dynamic-row';
  row.innerHTML = `
    <div style="border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:var(--space-4);margin-bottom:var(--space-3)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-3)">
        <span style="font-weight:600;font-size:var(--text-sm);color:var(--text-secondary)">Referencia ${n}</span>
        <button type="button" class="admin-action-btn admin-action-btn--delete row-remove-btn">Eliminar</button>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-3)">
        <div class="admin-field">
          <label class="admin-field__label">Título</label>
          <input type="text" class="admin-edit-input ref-title" value="${esc(ref.title ?? '')}" placeholder="OWASP LLM01" />
        </div>
        <div class="admin-field">
          <label class="admin-field__label">URL</label>
          <input type="url" class="admin-edit-input ref-url" value="${esc(ref.url ?? '')}" placeholder="https://owasp.org/…" />
        </div>
      </div>
    </div>`;
  row.querySelector('.row-remove-btn').addEventListener('click', () => row.remove());
  document.getElementById('references-list').appendChild(row);
}

function populateReferences(references) {
  const container = document.getElementById('references-list');
  if (!container) return;
  container.innerHTML = '';
  referencesCount = 0;
  if (Array.isArray(references) && references.length) references.forEach(ref => addReferenceRow(ref));
}

function collectReferences() {
  return Array.from(document.getElementById('references-list')?.querySelectorAll('.admin-dynamic-row') ?? [])
    .map(row => ({
      title: row.querySelector('.ref-title')?.value.trim() ?? '',
      url:   row.querySelector('.ref-url')?.value.trim() ?? '',
      type:  'article',
    }))
    .filter(ref => ref.title || ref.url);
}

/* ── Snippet (single) ────────────────────────────────────────────────────── */

function populateSnippet(codeSnippets) {
  const snippet = Array.isArray(codeSnippets) && codeSnippets.length && typeof codeSnippets[0] === 'object'
    ? codeSnippets[0]
    : {};
  const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val ?? ''; };
  setVal('snippet-title',       snippet.title);
  setVal('snippet-type',        snippet.type);
  setVal('snippet-language',    snippet.language);
  setVal('snippet-explanation', snippet.explanation);
  setVal('snippet-code',        snippet.code);
}

function collectSnippet() {
  const title = document.getElementById('snippet-title')?.value.trim();
  const code  = document.getElementById('snippet-code')?.value.trim();
  if (!title && !code) return [];
  return [{
    id:          `snippet-${Date.now()}`,
    title:       title ?? '',
    type:        document.getElementById('snippet-type')?.value || 'attack',
    language:    document.getElementById('snippet-language')?.value.trim() || 'text',
    explanation: document.getElementById('snippet-explanation')?.value.trim() ?? '',
    code:        code ?? '',
    vulnerability_id: document.getElementById('vuln-edit-id')?.value || null,
  }];
}

/* ── Edit vulnerability modal ────────────────────────────────────────────── */

async function openEditVulnModal(vuln) {
  selectedVuln = vuln;
  pendingApproveContribution = null;

  const modelsVal = Array.isArray(vuln.affected_models)
    ? vuln.affected_models.join(', ')
    : (vuln.affected_model ?? '');

  const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val ?? ''; };
  const setChk = (id, val) => { const el = document.getElementById(id); if (el) el.checked = !!val; };

  setVal('vuln-edit-id',            vuln.id ?? '');
  setText('vuln-edit-title',        `Editar: ${vuln.title ?? vuln.id}`);
  setVal('vuln-edit-title-input',   vuln.title ?? '');
  setVal('vuln-edit-severity',      vuln.severity ?? 'medium');
  setVal('vuln-edit-model',         modelsVal);
  setVal('vuln-edit-category',      vuln.category    ?? '');
  setVal('vuln-edit-subcategory',   vuln.subcategory ?? '');
  setVal('vuln-edit-cve',           vuln.cve_reference ?? '');
  setVal('vuln-edit-cvss',          vuln.cvss_score ?? '');
  setChk('vuln-edit-published',     vuln.is_published);
  setVal('vuln-edit-short-desc',    vuln.short_description ?? '');
  setVal('vuln-edit-full-desc',     vuln.full_description ?? '');

  setVal('vuln-edit-attack-vector', vuln.attack_vector ?? '');
  setVal('vuln-edit-cvss-vector',   vuln.cvss_vector ?? '');
  const stds = normalizeVulnAdmin(vuln).standards ?? {};
  setVal('vuln-edit-std-owasp',     stds.owasp_llm   ?? '');
  setVal('vuln-edit-std-mitre',     stds.mitre_atlas ?? '');
  setVal('vuln-edit-std-nist',      stds.nist_ai_rmf ?? '');

  const impact = vuln.impact ?? {};
  setVal('vuln-edit-impact-c',    impact.confidentiality ?? 'none');
  setVal('vuln-edit-impact-i',    impact.integrity       ?? 'none');
  setVal('vuln-edit-impact-a',    impact.availability    ?? 'none');
  setVal('vuln-edit-impact-desc', impact.description     ?? '');

  setVal('vuln-edit-prerequisites', (vuln.prerequisites ?? []).join(', '));
  setVal('vuln-edit-tags',          (vuln.tags ?? []).join(', '));
  setVal('vuln-edit-related',       (vuln.related_vulnerabilities ?? []).join(', '));

  populateExamples(vuln.examples ?? []);
  populateMitigations(vuln.mitigations ?? []);
  populateReferences(vuln.references ?? []);

  // If code_snippets are string IDs, look them up from snippets JSON
  const rawSnippets = vuln.code_snippets ?? [];
  if (rawSnippets.length && typeof rawSnippets[0] === 'string') {
    try {
      const { getSnippets } = await import('./data.js');
      const allSnippets = await getSnippets();
      const matched = allSnippets.filter(s => rawSnippets.includes(s.id) || s.vulnerability_id === vuln.id);
      populateSnippet(matched.length ? matched : rawSnippets);
    } catch {
      populateSnippet(rawSnippets);
    }
  } else {
    populateSnippet(rawSnippets);
  }

  // Per-model impact — match what the detail page shows (vulnerability_profile fallback)
  const savedModelImpacts = vuln.impact?.model_impacts ?? vuln.model_impacts ?? {};
  let displayImpacts = savedModelImpacts;
  if (Object.keys(savedModelImpacts).length === 0) {
    try {
      const allModels = await getModels();
      displayImpacts = {};
      for (const mid of modelsVal.split(',').map(s => s.trim()).filter(Boolean)) {
        const m = allModels.find(m => m.id === mid);
        const sus = m?.vulnerability_profile?.[vuln.id]?.susceptibility ?? vuln.severity ?? 'unknown';
        displayImpacts[mid] = ADMIN_IMPACT_OPTIONS.includes(sus) ? sus : 'unknown';
      }
    } catch { displayImpacts = {}; }
  }
  renderAdminModelImpactRows(modelsVal, displayImpacts);

  // Hide approval reason wrap (edit mode only shows it for contribution approval)
  const approvalWrap = document.getElementById('approval-reason-wrap');
  if (approvalWrap) approvalWrap.style.display = 'none';

  const saveBtn = document.getElementById('vuln-edit-save-btn');
  if (saveBtn) { saveBtn.textContent = 'Guardar cambios'; saveBtn.style.background = ''; }

  const overlay = document.getElementById('vuln-edit-modal');
  if (overlay) { overlay.hidden = false; document.body.style.overflow = 'hidden'; }
}

function closeEditVulnModal() {
  const overlay = document.getElementById('vuln-edit-modal');
  if (overlay) overlay.hidden = true;
  document.body.style.overflow = '';
  selectedVuln = null;

  const saveBtn = document.getElementById('vuln-edit-save-btn');
  if (saveBtn) { saveBtn.textContent = 'Guardar cambios'; saveBtn.style.background = ''; }

  const approvalWrap = document.getElementById('approval-reason-wrap');
  if (approvalWrap) approvalWrap.style.display = 'none';

  pendingApproveContribution = null;
}

/* ── Save vulnerability ──────────────────────────────────────────────────── */

async function saveVulnerability(e) {
  e.preventDefault();

  // Basic validation before save
  const titleVal = document.getElementById('vuln-edit-title-input')?.value.trim() ?? '';
  if (!titleVal) {
    showToast('El título de la vulnerabilidad es obligatorio.', true);
    document.getElementById('vuln-edit-title-input')?.focus();
    return;
  }
  const cvssRaw2 = document.getElementById('vuln-edit-cvss')?.value ?? '';
  if (cvssRaw2 !== '') {
    const cv = parseFloat(cvssRaw2);
    if (isNaN(cv) || cv < 0 || cv > 10) {
      showToast('La puntuación CVSS debe estar entre 0.0 y 10.0.', true);
      document.getElementById('vuln-edit-cvss')?.focus();
      return;
    }
  }

  const btn = document.getElementById('vuln-edit-save-btn');
  btn.disabled    = true;
  const origText  = btn.textContent;
  btn.textContent = 'Guardando…';

  const rawModels      = document.getElementById('vuln-edit-model').value.trim();
  const affectedModels = rawModels.split(',').map(s => s.trim()).filter(Boolean);
  const cvssRaw         = parseFloat(document.getElementById('vuln-edit-cvss')?.value);

  const owaspVal = document.getElementById('vuln-edit-std-owasp')?.value.trim();
  const mitreVal = document.getElementById('vuln-edit-std-mitre')?.value.trim();
  const nistVal  = document.getElementById('vuln-edit-std-nist')?.value.trim();
  const standards = {};
  if (owaspVal) standards.owasp_llm   = owaspVal;
  if (mitreVal) standards.mitre_atlas = mitreVal;
  if (nistVal)  standards.nist_ai_rmf = nistVal;

  const modelImpactsCollected = collectAdminModelImpacts();
  const impact = {
    confidentiality: document.getElementById('vuln-edit-impact-c')?.value ?? 'none',
    integrity:       document.getElementById('vuln-edit-impact-i')?.value ?? 'none',
    availability:    document.getElementById('vuln-edit-impact-a')?.value ?? 'none',
    description:     document.getElementById('vuln-edit-impact-desc')?.value.trim() ?? '',
    ...(Object.keys(modelImpactsCollected).length ? { model_impacts: modelImpactsCollected } : {}),
  };

  const prereqRaw  = document.getElementById('vuln-edit-prerequisites')?.value.trim();
  const tagsRaw    = document.getElementById('vuln-edit-tags')?.value.trim();
  const relatedRaw = document.getElementById('vuln-edit-related')?.value.trim();

  const vulnData = {
    title:                   document.getElementById('vuln-edit-title-input').value.trim(),
    severity:                document.getElementById('vuln-edit-severity').value,
    affected_models:         affectedModels,
    category:                document.getElementById('vuln-edit-category').value.trim(),
    subcategory:             document.getElementById('vuln-edit-subcategory')?.value.trim() || null,
    cve_reference:           document.getElementById('vuln-edit-cve').value.trim() || null,
    is_published:            document.getElementById('vuln-edit-published').checked,
    short_description:       document.getElementById('vuln-edit-short-desc').value.trim(),
    full_description:        document.getElementById('vuln-edit-full-desc').value.trim(),
    cvss_score:              isNaN(cvssRaw) ? null : Math.min(10, Math.max(0, cvssRaw)),
    attack_vector:           document.getElementById('vuln-edit-attack-vector')?.value || null,
    cvss_vector:             document.getElementById('vuln-edit-cvss-vector')?.value.trim() || null,
    standards:               Object.keys(standards).length ? standards : [],
    impact,
    prerequisites:           prereqRaw  ? prereqRaw.split(',').map(s => s.trim()).filter(Boolean) : [],
    tags:                    tagsRaw    ? tagsRaw.split(',').map(s => s.trim()).filter(Boolean)    : [],
    related_vulnerabilities: relatedRaw ? relatedRaw.split(',').map(s => s.trim()).filter(Boolean) : [],
    examples:                collectExamples(),
    mitigations:             collectMitigations(),
    references:              collectReferences(),
    code_snippets:           collectSnippet(),
  };

  try {
    if (pendingApproveContribution) {
      await approveContribution(pendingApproveContribution, vulnData);
      closeEditVulnModal();
    } else {
      const id = document.getElementById('vuln-edit-id').value;
      if (!id) throw new Error('ID de vulnerabilidad no encontrado');

      const { error } = await supabase
        .from('vulnerabilities')
        .update({ ...vulnData, updated: new Date().toISOString() })
        .eq('id', id);

      if (error) throw error;

      vulnCollection = vulnCollection.map(v => v.id === id ? { ...v, ...vulnData } : v);
      closeEditVulnModal();
      showToast(`"${vulnData.title}" actualizada correctamente`);
      renderVulnerabilities();
      loadOverviewStats();
    }
  } catch (err) {
    console.error('[admin] saveVulnerability error:', err);
    showToast('Error: ' + err.message, true);
    btn.disabled    = false;
    btn.textContent = origText;
  }
}

/* ── Delete vulnerability ────────────────────────────────────────────────── */

async function deleteVulnerability(id) {
  const vuln = vulnCollection.find(v => v.id === id);
  if (!vuln) return;

  if (!window.confirm(`¿Eliminar "${vuln.title ?? id}"?\n\nEsta acción es irreversible y eliminará la vulnerabilidad del catálogo.`)) return;

  try {
    const { error } = await supabase.from('vulnerabilities').delete().eq('id', id);
    if (error) throw error;

    vulnCollection = vulnCollection.filter(v => v.id !== id);
    showToast(`"${vuln.title}" eliminada`);
    renderVulnerabilities();
    loadOverviewStats();
  } catch (err) {
    console.error('[admin] deleteVulnerability error:', err);
    showToast('Error al eliminar: ' + err.message, true);
  }
}

/* ── Generate next VAI ID ────────────────────────────────────────────────── */

async function generateVulnId() {
  const year   = new Date().getFullYear();
  const prefix = `VAI-${year}-`;
  try {
    const { data } = await supabase
      .from('vulnerabilities')
      .select('id')
      .like('id', `${prefix}%`);

    const nums = (data ?? [])
      .map(v => parseInt(v.id.replace(prefix, ''), 10))
      .filter(n => !isNaN(n));
    const next = nums.length ? Math.max(...nums) + 1 : 51;
    return `${prefix}${String(next).padStart(3, '0')}`;
  } catch (_) {
    return `${prefix}${Date.now().toString().slice(-3)}`;
  }
}

function categoryLabel(cat) {
  const map = {
    injection:    'Prompt Injection',
    evasion:      'Evasión de Filtros',
    extraction:   'Extracción de Datos',
    poisoning:    'Envenenamiento de Datos',
    manipulation: 'Manipulación',
    other:        'Otro',
  };
  return map[cat] ?? cat ?? 'Otro';
}

/* ── Event listeners ─────────────────────────────────────────────────────── */

function initListeners() {
  document.querySelectorAll('.admin-nav-item[data-page]').forEach(btn => {
    btn.addEventListener('click', () => switchPage(btn.dataset.page));
  });

  document.querySelectorAll('.admin-filter-btn[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => applyFilter(btn.dataset.filter));
  });

  document.querySelectorAll('.admin-filter-btn[data-collection-filter]').forEach(btn => {
    btn.addEventListener('click', () => applyCollFilter(btn.dataset.collectionFilter));
  });

  document.getElementById('btn-clear-processed')?.addEventListener('click', clearProcessedContributions);

  // Contributions search
  let contribSearchTimer;
  document.getElementById('contrib-search')?.addEventListener('input', e => {
    clearTimeout(contribSearchTimer);
    contribSearchTimer = setTimeout(() => {
      contribQuery = e.target.value.trim();
      renderContributions();
    }, 220);
  });

  // Contributions date sort
  document.querySelectorAll('[data-contrib-sort]').forEach(btn => {
    btn.addEventListener('click', () => {
      contribSort = btn.dataset.contribSort;
      document.querySelectorAll('[data-contrib-sort]').forEach(b =>
        b.classList.toggle('is-active', b === btn));
      renderContributions();
    });
  });

  // Collection search
  let collSearchTimer;
  document.getElementById('coll-search')?.addEventListener('input', e => {
    clearTimeout(collSearchTimer);
    collSearchTimer = setTimeout(() => {
      collQuery = e.target.value.trim();
      renderVulnerabilities();
    }, 220);
  });

  // Collection severity filter
  document.querySelectorAll('[data-coll-sev]').forEach(btn => {
    btn.addEventListener('click', () => {
      collSevFilter = btn.dataset.collSev;
      document.querySelectorAll('[data-coll-sev]').forEach(b =>
        b.classList.toggle('is-active', b === btn));
      renderVulnerabilities();
    });
  });

  document.getElementById('contributions-tbody')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const id = btn.dataset.id;
    const contribution = contributions.find(c => c.id === id);
    if (!contribution) return;

    switch (btn.dataset.action) {
      case 'view':         openModal(contribution, true);       break;
      case 'approve-edit': openApproveEditModal(contribution);  break;
      case 'reject':       showRejectConfirm(contribution);     break;
    }
  });

  document.getElementById('collection-tbody')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-vuln-action]');
    if (!btn) return;
    const id   = btn.dataset.vulnId;
    const vuln = vulnCollection.find(v => v.id === id);
    if (!vuln) return;
    if (btn.dataset.vulnAction === 'edit')   openEditVulnModal(vuln);
    if (btn.dataset.vulnAction === 'delete') deleteVulnerability(id);
  });

  document.getElementById('modal-close-btn')?.addEventListener('click', closeModal);
  document.getElementById('contribution-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeModal();
  });

  document.getElementById('vuln-edit-close-btn')?.addEventListener('click', closeEditVulnModal);
  document.getElementById('vuln-edit-cancel-btn')?.addEventListener('click', closeEditVulnModal);
  document.getElementById('vuln-edit-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeEditVulnModal();
  });

  document.getElementById('vuln-edit-form')?.addEventListener('submit', saveVulnerability);

  // CVSS ↔ Severity coherence warning in edit modal
  const ADMIN_CVSS_RANGES = {
    critical: { min: 9.0, max: 10.0, label: 'Crítica (9.0–10.0)' },
    high:     { min: 7.0, max: 8.9,  label: 'Alta (7.0–8.9)' },
    medium:   { min: 4.0, max: 6.9,  label: 'Media (4.0–6.9)' },
    low:      { min: 0.1, max: 3.9,  label: 'Baja (0.1–3.9)' },
  };
  function checkAdminCvssCoherence() {
    const severity = document.getElementById('vuln-edit-severity')?.value ?? '';
    const cvssRaw  = document.getElementById('vuln-edit-cvss')?.value ?? '';
    const warning  = document.getElementById('admin-cvss-coherence');
    if (!warning) return;
    if (!cvssRaw || !severity) { warning.style.display = 'none'; return; }
    const cvss  = parseFloat(cvssRaw);
    const range = ADMIN_CVSS_RANGES[severity];
    if (!range || isNaN(cvss)) { warning.style.display = 'none'; return; }
    if (cvss < range.min || cvss > range.max) {
      warning.textContent = `⚠ CVSS ${cvss.toFixed(1)} no corresponde a severidad ${range.label}.`;
      warning.style.display = '';
    } else {
      warning.style.display = 'none';
    }
  }
  document.getElementById('vuln-edit-severity')?.addEventListener('change', checkAdminCvssCoherence);
  document.getElementById('vuln-edit-cvss')?.addEventListener('input', checkAdminCvssCoherence);

  // Re-render model impact rows when models field loses focus
  document.getElementById('vuln-edit-model')?.addEventListener('blur', () => {
    const val      = document.getElementById('vuln-edit-model').value.trim();
    const existing = collectAdminModelImpacts();
    renderAdminModelImpactRows(val, existing);
  });

  // Dynamic list buttons
  document.getElementById('add-example-btn')?.addEventListener('click',    () => addExampleRow());
  document.getElementById('add-mitigation-btn')?.addEventListener('click', () => addMitigationRow());
  document.getElementById('add-reference-btn')?.addEventListener('click',  () => addReferenceRow());

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeModal(); closeEditVulnModal(); }
  });
}

/* ── Overview stats ─────────────────────────────────────────────────────── */

async function loadOverviewStats() {
  try {
    const [vulns, models, snippets] = await Promise.all([
      getVulnerabilities(), getModels(), getSnippets()
    ]);
    setText('ov-vulns',    vulns.length);
    setText('ov-models',   models.length);
    setText('ov-snippets', snippets.length);
  } catch (_) {}
}

/* ── Bootstrap ───────────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  const { data: { session } } = await supabase.auth.getSession();
  currentUser = session?.user ?? null;

  supabase.auth.onAuthStateChange((_event, session) => {
    if (!session && currentUser) window.location.reload();
  });

  const loading = document.getElementById('admin-content-loading');
  if (loading) loading.style.display = 'none';

  if (!currentUser) {
    showAuthGate('Debes iniciar sesión para acceder al panel de administración.');
    return;
  }
  if (!isAdmin(currentUser)) {
    showAuthGate('No tienes permisos de administrador.');
    return;
  }

  document.getElementById('admin-content')?.removeAttribute('hidden');
  const emailEl = document.getElementById('admin-user-email');
  if (emailEl) emailEl.textContent = currentUser.email;

  initListeners();
  await loadContributions();
  loadOverviewStats();
  switchPage('contributions');
});
