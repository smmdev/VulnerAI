import { supabase } from './supabase.js';

/* ── Auth gate ──────────────────────────────────────────────────────────── */
const authGate          = document.getElementById('auth-gate');
const contributeContent = document.getElementById('contribute-content');
const authUserBar       = document.getElementById('auth-user-bar');
const userAvatar        = document.getElementById('user-avatar');
const userDisplayName   = document.getElementById('user-display-name');

function showForm(user) {
  authGate.setAttribute('aria-hidden', 'true');
  authGate.style.display   = 'none';
  contributeContent.hidden = false;
  authUserBar.hidden       = false;

  const meta     = user.user_metadata ?? {};
  const name     = meta.full_name ?? meta.name ?? meta.user_name ?? user.email ?? '';
  const provider = user.app_metadata?.provider ?? 'oauth';
  const avatar   = meta.avatar_url ?? '';
  const handle   = meta.user_name ? `@${meta.user_name}` : name;

  userDisplayName.textContent = `${handle} (${provider})`;

  if (avatar) {
    userAvatar.src    = avatar;
    userAvatar.alt    = name;
    userAvatar.hidden = false;
  }

  const emailInput = document.getElementById('researcher-email');
  if (emailInput && user.email) {
    emailInput.value    = user.email;
    emailInput.readOnly = true;
    emailInput.setAttribute('aria-readonly', 'true');
    emailInput.classList.add('is-prefilled');
  }
}

function showGate() {
  authGate.style.display   = '';
  authGate.removeAttribute('aria-hidden');
  contributeContent.hidden = true;
  authUserBar.hidden       = true;
}

supabase.auth.getSession().then(({ data: { session } }) => {
  if (session) showForm(session.user);
});

supabase.auth.onAuthStateChange((_event, session) => {
  if (session) showForm(session.user);
  else showGate();
});

document.getElementById('btn-login-github')?.addEventListener('click', () => {
  supabase.auth.signInWithOAuth({ provider: 'github', options: { redirectTo: window.location.href } });
});

document.getElementById('btn-login-google')?.addEventListener('click', () => {
  supabase.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: window.location.href } });
});

document.getElementById('btn-signout')?.addEventListener('click', async () => {
  await supabase.auth.signOut();
  showGate();
});

/* ── Estado del formulario ─────────────────────────────────────────────── */
let currentStep = 1;
const TOTAL_STEPS = 5;

const formData = {
  // Step 1
  threatName:           '',
  affectedModel:        '',
  affectedModels:       [],
  affectedModelDisplay: '',
  severity:             '',
  attackCategory:       '',
  // Step 2
  shortDescription:     '',
  attackPayload:        '',
  techDescription:      '',
  cveReference:         '',
  cvssScore:            '',
  // Step 3
  attackVector:         '',
  cvssVector:           '',
  stdOwasp:             '',
  stdMitre:             '',
  stdNist:              '',
  impactConfidentiality: 'none',
  impactIntegrity:       'none',
  impactAvailability:    'none',
  impactDescription:     '',
  prerequisites:         '',
  tags:                  '',
  relatedVulns:          '',
  modelImpacts:          {},
  // Step 4
  mitigations:          [],
  examples:             [],
  snippet:              null,
  references:           [],
  mitigationProposal:   '',
  // Step 5
  researcherEmail:      '',
};

/* ── Referencias DOM ───────────────────────────────────────────────────── */
const steps          = [1, 2, 3, 4, 5].map(n => document.getElementById(`step-${n}`));
const stepIndicators = [1, 2, 3, 4, 5].map(n => document.getElementById(`step-indicator-${n}`));
const progressFill   = document.getElementById('progress-fill');
const stepCounter    = document.getElementById('step-counter');
const form           = document.getElementById('contribute-form');
const successPanel   = document.getElementById('contribute-success');

/* ── Navegación entre pasos ────────────────────────────────────────────── */
function goToStep(n) {
  steps[currentStep - 1].hidden = true;
  steps[currentStep - 1].classList.remove('is-visible');

  currentStep = n;
  const target = steps[n - 1];
  target.hidden = false;
  target.classList.add('is-visible');

  updateProgress();
  target.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function updateProgress() {
  const pct = (currentStep / TOTAL_STEPS) * 100;
  progressFill.style.width = `${pct}%`;
  stepCounter.textContent  = `Paso ${currentStep} de ${TOTAL_STEPS}`;

  stepIndicators.forEach((el, i) => {
    el.classList.remove('is-active', 'is-done');
    if (i + 1 < currentStep)   el.classList.add('is-done');
    if (i + 1 === currentStep) el.classList.add('is-active');
  });

  stepIndicators[currentStep - 1]?.setAttribute('aria-current', 'step');
  stepIndicators.forEach((el, i) => {
    if (i + 1 !== currentStep) el.removeAttribute('aria-current');
  });
}

/* ── Validación ─────────────────────────────────────────────────────────── */
function showError(inputId, errorId, message) {
  const input = document.getElementById(inputId);
  const error = document.getElementById(errorId);
  if (!input || !error) return;
  input.classList.add('is-invalid');
  input.classList.remove('is-valid');
  error.textContent = message;
  error.hidden = false;
}

function clearError(inputId, errorId) {
  const input = document.getElementById(inputId);
  const error = document.getElementById(errorId);
  if (!input || !error) return;
  input.classList.remove('is-invalid');
  input.classList.add('is-valid');
  error.hidden = true;
}

function validateStep1() {
  let valid = true;

  const name = document.getElementById('threat-name').value.trim();
  if (!name) {
    showError('threat-name', 'threat-name-error', 'El nombre de la amenaza es obligatorio.');
    valid = false;
  } else if (name.length < 5) {
    showError('threat-name', 'threat-name-error', 'Introduce un nombre más descriptivo (mínimo 5 caracteres).');
    valid = false;
  } else {
    clearError('threat-name', 'threat-name-error');
  }

  const checkedModels = document.querySelectorAll('input[name="affectedModels"]:checked');
  const modelError    = document.getElementById('affected-model-error');
  const modelTrigger  = document.getElementById('model-select-trigger');
  if (checkedModels.length === 0) {
    modelTrigger?.classList.add('is-invalid');
    if (modelError) { modelError.textContent = 'Selecciona al menos un modelo afectado.'; modelError.hidden = false; }
    valid = false;
  } else {
    modelTrigger?.classList.remove('is-invalid');
    if (modelError) modelError.hidden = true;
  }

  const severity = document.getElementById('severity').value;
  if (!severity) {
    showError('severity', 'severity-error', 'Selecciona el nivel de gravedad.');
    valid = false;
  } else {
    clearError('severity', 'severity-error');
  }

  const category = document.querySelector('input[name="attackCategory"]:checked');
  const catError  = document.getElementById('attack-category-error');
  if (!category) {
    catError.textContent = 'Selecciona una categoría de ataque.';
    catError.hidden = false;
    valid = false;
  } else {
    catError.hidden = true;
  }

  return valid;
}

function validateStep2() {
  let valid = true;

  const payload = document.getElementById('attack-payload').value.trim();
  if (!payload) {
    showError('attack-payload', 'payload-error', 'El vector de ataque o payload de prueba es obligatorio.');
    valid = false;
  } else {
    clearError('attack-payload', 'payload-error');
  }

  const desc = document.getElementById('tech-description').value.trim();
  if (!desc) {
    showError('tech-description', 'description-error', 'La descripción técnica es obligatoria.');
    valid = false;
  } else if (desc.length < 80) {
    showError('tech-description', 'description-error', `Amplía la descripción (${desc.length}/80 caracteres mínimos).`);
    valid = false;
  } else {
    clearError('tech-description', 'description-error');
  }

  const cveField = document.getElementById('cve-reference');
  if (cveField.value.trim() && !cveField.validity.valid) {
    showError('cve-reference', 'cve-error', 'Formato incorrecto. Usa CVE-YYYY-NNNNN o AML.TXXXX.');
    valid = false;
  } else if (cveField.value.trim()) {
    clearError('cve-reference', 'cve-error');
  }

  // CVSS range: reject if out of 0-10 bounds
  const cvssVal = document.getElementById('cvss-score')?.value ?? '';
  const errEl   = document.getElementById('cvss-score-error');
  const scoreEl = document.getElementById('cvss-score');
  if (cvssVal !== '') {
    const cvss = parseFloat(cvssVal);
    if (isNaN(cvss) || cvss < 0 || cvss > 10) {
      if (errEl) { errEl.textContent = 'La puntuación CVSS debe ser un número entre 0.0 y 10.0.'; errEl.hidden = false; }
      scoreEl?.classList.add('is-invalid');
      valid = false;
    } else {
      if (errEl) errEl.hidden = true;
      scoreEl?.classList.remove('is-invalid');
    }
  }

  return valid;
}

// Steps 3 & 4 are fully optional — always valid
function validateStep3() { return true; }
function validateStep4() { return true; }

function validateStep5() {
  let valid = true;

  const email   = document.getElementById('researcher-email').value.trim();
  const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email) {
    showError('researcher-email', 'email-error', 'Tu correo electrónico es obligatorio para notificarte.');
    valid = false;
  } else if (!emailRx.test(email)) {
    showError('researcher-email', 'email-error', 'Introduce una dirección de correo válida.');
    valid = false;
  } else {
    clearError('researcher-email', 'email-error');
  }

  const confirm      = document.getElementById('confirm-accuracy').checked;
  const confirmError = document.getElementById('confirm-error');
  if (!confirm) {
    confirmError.textContent = 'Debes confirmar la veracidad de la información antes de enviar.';
    confirmError.hidden = false;
    valid = false;
  } else {
    confirmError.hidden = true;
  }

  return valid;
}

/* ── Guardar datos ──────────────────────────────────────────────────────── */
function collectStep1() {
  formData.threatName = document.getElementById('threat-name').value.trim();
  const checked = [...document.querySelectorAll('input[name="affectedModels"]:checked')];
  formData.affectedModels       = checked.map(cb => cb.value);
  formData.affectedModel        = formData.affectedModels.join(', ');
  formData.affectedModelDisplay = checked.map(cb => cb.nextElementSibling?.textContent ?? cb.value).join(', ');
  formData.severity             = document.getElementById('severity').value;
  const cat = document.querySelector('input[name="attackCategory"]:checked');
  formData.attackCategory    = cat?.value ?? '';
  formData.attackSubcategory = document.getElementById('attack-subcategory')?.value.trim() ?? '';
}

function collectStep2() {
  formData.shortDescription = document.getElementById('short-description')?.value.trim() ?? '';
  formData.attackPayload    = document.getElementById('attack-payload').value.trim();
  formData.techDescription  = document.getElementById('tech-description').value.trim();
  formData.cveReference     = document.getElementById('cve-reference').value.trim();
  formData.cvssScore        = document.getElementById('cvss-score')?.value ?? '';
}

function collectStep3() {
  formData.attackVector          = document.getElementById('contrib-attack-vector')?.value       ?? '';
  formData.cvssVector            = document.getElementById('cvss-vector')?.value.trim()          ?? '';
  formData.stdOwasp              = document.getElementById('std-owasp')?.value.trim()             ?? '';
  formData.stdMitre              = document.getElementById('std-mitre')?.value.trim()             ?? '';
  formData.stdNist               = document.getElementById('std-nist')?.value.trim()              ?? '';
  formData.impactConfidentiality = document.getElementById('impact-confidentiality')?.value       ?? 'none';
  formData.impactIntegrity       = document.getElementById('impact-integrity')?.value             ?? 'none';
  formData.impactAvailability    = document.getElementById('impact-availability')?.value          ?? 'none';
  formData.impactDescription     = document.getElementById('impact-description')?.value.trim()    ?? '';
  formData.prerequisites         = document.getElementById('contrib-prerequisites')?.value.trim() ?? '';
  formData.tags                  = document.getElementById('contrib-tags')?.value.trim()          ?? '';
  formData.relatedVulns          = document.getElementById('contrib-related')?.value.trim()       ?? '';
  formData.modelImpacts          = collectModelImpacts();
}

function collectStep4() {
  formData.mitigations        = collectContribMitigations();
  formData.examples           = collectContribExamples();
  formData.references         = collectContribReferences();
  formData.snippet            = collectContribSnippet();
  formData.mitigationProposal = document.getElementById('mitigation-proposal')?.value.trim() ?? '';
}

/* ── Dynamic list helpers (contribute form) ─────────────────────────────── */
function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function addContribMitigationRow(m = {}) {
  const container = document.getElementById('contrib-mitigations-list');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'contrib-list-row';
  row.style.cssText = 'border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:var(--space-4);margin-bottom:var(--space-3)';
  row.innerHTML = `
    <div style="display:flex;gap:var(--space-3);flex-wrap:wrap">
      <div class="form-group" style="flex:0 0 160px;min-width:120px">
        <label class="form-label" style="font-weight:400;color:var(--text-secondary)">Tipo</label>
        <div class="form-select-wrap">
          <select class="form-select contrib-mit-type">
            <option value="preventive">Preventiva</option>
            <option value="detective">Detectora</option>
            <option value="corrective">Correctiva</option>
          </select>
        </div>
      </div>
      <div class="form-group" style="flex:1;min-width:180px">
        <label class="form-label" style="font-weight:400;color:var(--text-secondary)">Título</label>
        <input type="text" class="form-input contrib-mit-title" placeholder="Validación de entrada" value="${escHtml(m.title ?? '')}" />
      </div>
    </div>
    <div class="form-group" style="margin-top:var(--space-3)">
      <label class="form-label" style="font-weight:400;color:var(--text-secondary)">Implementación</label>
      <textarea class="form-textarea contrib-mit-impl" rows="2" placeholder="Cómo implementar esta mitigación…">${escHtml(m.implementation ?? '')}</textarea>
    </div>
    <button type="button" class="btn btn--ghost btn--sm contrib-list-row__remove" style="margin-top:var(--space-2);color:var(--severity-critical)">Eliminar</button>
  `;
  row.querySelector('.contrib-list-row__remove').addEventListener('click', () => row.remove());
  if (m.type) row.querySelector('.contrib-mit-type').value = m.type;
  container.appendChild(row);
}

function collectContribMitigations() {
  return [...document.querySelectorAll('#contrib-mitigations-list .contrib-list-row')].map(row => ({
    type:           row.querySelector('.contrib-mit-type')?.value  ?? 'preventive',
    title:          row.querySelector('.contrib-mit-title')?.value.trim() ?? '',
    implementation: row.querySelector('.contrib-mit-impl')?.value.trim() ?? '',
  })).filter(m => m.title);
}

function addContribExampleRow(ex = {}) {
  const container = document.getElementById('contrib-examples-list');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'contrib-list-row';
  row.style.cssText = 'border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:var(--space-4);margin-bottom:var(--space-3)';
  row.innerHTML = `
    <div class="form-group">
      <label class="form-label" style="font-weight:400;color:var(--text-secondary)">Título del ejemplo</label>
      <input type="text" class="form-input contrib-ex-title" placeholder="Variante con herramienta agéntica" value="${escHtml(ex.title ?? '')}" />
    </div>
    <div class="form-group" style="margin-top:var(--space-3)">
      <label class="form-label" style="font-weight:400;color:var(--text-secondary)">Payload</label>
      <div class="code-textarea-wrap">
        <span class="code-textarea-wrap__lang" aria-hidden="true">PROMPT / CÓDIGO</span>
        <textarea class="form-textarea form-textarea--code contrib-ex-payload" rows="3">${escHtml(ex.payload ?? '')}</textarea>
      </div>
    </div>
    <div class="form-group" style="margin-top:var(--space-3)">
      <label class="form-label" style="font-weight:400;color:var(--text-secondary)">Descripción</label>
      <textarea class="form-textarea contrib-ex-desc" rows="2" placeholder="Contexto de este ejemplo…">${escHtml(ex.description ?? '')}</textarea>
    </div>
    <button type="button" class="btn btn--ghost btn--sm contrib-list-row__remove" style="margin-top:var(--space-2);color:var(--severity-critical)">Eliminar</button>
  `;
  row.querySelector('.contrib-list-row__remove').addEventListener('click', () => row.remove());
  container.appendChild(row);
}

function collectContribExamples() {
  return [...document.querySelectorAll('#contrib-examples-list .contrib-list-row')].map(row => ({
    title:       row.querySelector('.contrib-ex-title')?.value.trim()   ?? '',
    payload:     row.querySelector('.contrib-ex-payload')?.value.trim() ?? '',
    description: row.querySelector('.contrib-ex-desc')?.value.trim()   ?? '',
  })).filter(ex => ex.title || ex.payload);
}

function addContribReferenceRow(ref = {}) {
  const container = document.getElementById('contrib-references-list');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'contrib-list-row';
  row.style.cssText = 'border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:var(--space-4);margin-bottom:var(--space-3)';
  row.innerHTML = `
    <div style="display:flex;gap:var(--space-3);flex-wrap:wrap">
      <div class="form-group" style="flex:1;min-width:160px">
        <label class="form-label" style="font-weight:400;color:var(--text-secondary)">Título</label>
        <input type="text" class="form-input contrib-ref-title" placeholder="Nombre del paper o artículo" value="${escHtml(ref.title ?? '')}" />
      </div>
      <div class="form-group" style="flex:2;min-width:200px">
        <label class="form-label" style="font-weight:400;color:var(--text-secondary)">URL</label>
        <input type="url" class="form-input contrib-ref-url" placeholder="https://…" value="${escHtml(ref.url ?? '')}" />
      </div>
    </div>
    <button type="button" class="btn btn--ghost btn--sm contrib-list-row__remove" style="margin-top:var(--space-2);color:var(--severity-critical)">Eliminar</button>
  `;
  row.querySelector('.contrib-list-row__remove').addEventListener('click', () => row.remove());
  container.appendChild(row);
}

function collectContribReferences() {
  return [...document.querySelectorAll('#contrib-references-list .contrib-list-row')].map(row => ({
    title: row.querySelector('.contrib-ref-title')?.value.trim() ?? '',
    url:   row.querySelector('.contrib-ref-url')?.value.trim()   ?? '',
  })).filter(ref => ref.title || ref.url);
}

function collectContribSnippet() {
  const title = document.getElementById('snippet-title')?.value.trim()       ?? '';
  const code  = document.getElementById('snippet-code')?.value.trim()        ?? '';
  if (!title && !code) return null;
  return {
    id:          `contrib-${Date.now()}`,
    title,
    type:        document.getElementById('snippet-type')?.value              ?? 'attack',
    language:    document.getElementById('snippet-language')?.value.trim()   ?? '',
    explanation: document.getElementById('snippet-explanation')?.value.trim() ?? '',
    code,
  };
}

/* ── Resumen del paso 5 ─────────────────────────────────────────────────── */
const SEVERITY_LABELS = {
  critical: 'Crítica (9.0–10.0)',
  high:     'Alta (7.0–8.9)',
  medium:   'Media (4.0–6.9)',
  low:      'Baja (0.1–3.9)',
};

const CATEGORY_LABELS = {
  injection:    'Inyección',
  evasion:      'Evasión',
  extraction:   'Extracción',
  poisoning:    'Envenenamiento',
  manipulation: 'Manipulación',
  other:        'Otra',
};

function truncate(str, max) {
  return str.length > max ? str.slice(0, max) + '…' : str;
}

function buildReview() {
  const dl1 = document.getElementById('review-dl-1');
  const dl2 = document.getElementById('review-dl-2');
  const dl3 = document.getElementById('review-dl-3');
  const dl4 = document.getElementById('review-dl-4');

  // Block 1: Identification
  dl1.innerHTML = `
    <dt>Amenaza</dt>   <dd>${escHtml(formData.threatName)}</dd>
    <dt>Modelos</dt>   <dd>${escHtml(formData.affectedModelDisplay || formData.affectedModel)}</dd>
    <dt>Gravedad</dt>  <dd>${escHtml(SEVERITY_LABELS[formData.severity] ?? formData.severity)}</dd>
    <dt>Categoría</dt> <dd>${escHtml(CATEGORY_LABELS[formData.attackCategory] ?? formData.attackCategory)}</dd>
  `;

  // Block 2: Description
  const shortRow  = formData.shortDescription
    ? `<dt>Resumen</dt><dd>${escHtml(truncate(formData.shortDescription, 200))}</dd>` : '';
  const cveRow    = formData.cveReference
    ? `<dt>CVE/MITRE</dt><dd>${escHtml(formData.cveReference)}</dd>` : '';
  const cvssRow   = formData.cvssScore
    ? `<dt>Puntuación CVSS</dt><dd>${escHtml(formData.cvssScore)}</dd>` : '';

  dl2.innerHTML = `
    ${shortRow}
    <dt>Payload</dt>
    <dd><pre class="review-code">${escHtml(truncate(formData.attackPayload, 400))}</pre></dd>
    <dt>Descripción</dt>
    <dd>${escHtml(truncate(formData.techDescription, 300))}</dd>
    ${cveRow}${cvssRow}
  `;

  // Block 3: Classification
  const items3 = [];
  if (formData.attackVector)  items3.push(`<dt>Vector de ataque</dt><dd>${escHtml(formData.attackVector)}</dd>`);
  if (formData.cvssVector)    items3.push(`<dt>Vector CVSS</dt><dd>${escHtml(formData.cvssVector)}</dd>`);
  if (formData.stdOwasp)      items3.push(`<dt>OWASP</dt><dd>${escHtml(formData.stdOwasp)}</dd>`);
  if (formData.stdMitre)      items3.push(`<dt>MITRE ATLAS</dt><dd>${escHtml(formData.stdMitre)}</dd>`);
  if (formData.stdNist)       items3.push(`<dt>NIST AI RMF</dt><dd>${escHtml(formData.stdNist)}</dd>`);
  if (formData.impactDescription) items3.push(`<dt>Descripción del impacto</dt><dd>${escHtml(truncate(formData.impactDescription, 200))}</dd>`);
  if (formData.prerequisites) items3.push(`<dt>Prerequisitos</dt><dd>${escHtml(formData.prerequisites)}</dd>`);
  if (formData.tags)          items3.push(`<dt>Tags</dt><dd>${escHtml(formData.tags)}</dd>`);
  if (formData.relatedVulns)  items3.push(`<dt>Vulnerabilidades relacionadas</dt><dd>${escHtml(formData.relatedVulns)}</dd>`);
  const impactEntries = Object.entries(formData.modelImpacts ?? {});
  if (impactEntries.length) {
    const chips = impactEntries.map(([m, lvl]) => `<span style="white-space:nowrap">${escHtml(m)}: <strong>${escHtml(IMPACT_LABELS[lvl] ?? lvl)}</strong></span>`).join(' · ');
    items3.push(`<dt>Impacto por modelo</dt><dd>${chips}</dd>`);
  }
  dl3.innerHTML = items3.length
    ? items3.join('')
    : '<dt></dt><dd><em style="color:var(--text-muted)">Sin datos de clasificación opcionales</em></dd>';

  // Block 4: Evidence
  const items4 = [];
  if (formData.mitigations.length)
    items4.push(`<dt>Mitigaciones</dt><dd>${formData.mitigations.length} registrada${formData.mitigations.length !== 1 ? 's' : ''}</dd>`);
  if (formData.examples.length)
    items4.push(`<dt>Ejemplos</dt><dd>${formData.examples.length} registrado${formData.examples.length !== 1 ? 's' : ''}</dd>`);
  if (formData.snippet)
    items4.push(`<dt>Snippet</dt><dd>${escHtml(formData.snippet.title || '—')} (${escHtml(formData.snippet.language || '?')})</dd>`);
  if (formData.references.length)
    items4.push(`<dt>Referencias</dt><dd>${formData.references.length} registrada${formData.references.length !== 1 ? 's' : ''}</dd>`);
  if (formData.mitigationProposal)
    items4.push(`<dt>Estrategia libre</dt><dd>${escHtml(truncate(formData.mitigationProposal, 200))}</dd>`);
  dl4.innerHTML = items4.length
    ? items4.join('')
    : '<dt></dt><dd><em style="color:var(--text-muted)">Sin evidencia adicional</em></dd>';
}

/* ── Per-model impact rows ──────────────────────────────────────────────── */
const IMPACT_OPTIONS = ['critical', 'high', 'medium', 'low', 'unknown'];
const IMPACT_LABELS  = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', unknown: 'Desconocido' };

function renderModelImpactRows() {
  const section = document.getElementById('model-impact-section');
  const container = document.getElementById('model-impact-rows');
  if (!section || !container) return;

  const checked = [...document.querySelectorAll('input[name="affectedModels"]:checked')];
  if (!checked.length) { section.style.display = 'none'; return; }

  const existing = {};
  container.querySelectorAll('.model-impact-row').forEach(row => {
    const modelId = row.dataset.modelId;
    const sel = row.querySelector('select');
    if (modelId && sel) existing[modelId] = sel.value;
  });

  container.innerHTML = checked.map(cb => {
    const id   = cb.value;
    const name = cb.nextElementSibling?.textContent?.trim() ?? id;
    const prev = existing[id] ?? formData.modelImpacts[id] ?? 'unknown';
    const opts = IMPACT_OPTIONS.map(v =>
      `<option value="${v}"${prev === v ? ' selected' : ''}>${IMPACT_LABELS[v]}</option>`
    ).join('');
    return `
      <div class="model-impact-row" data-model-id="${escHtml(id)}"
           style="display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) var(--space-3);border-bottom:1px solid var(--border-subtle)">
        <span class="model-impact-row__name" style="flex:1;font-size:var(--text-sm);color:var(--text-secondary)">${escHtml(name)}</span>
        <div class="form-select-wrap" style="flex:0 0 160px;min-width:120px">
          <select class="form-select" style="padding-top:var(--space-1);padding-bottom:var(--space-1)">${opts}</select>
        </div>
      </div>`;
  }).join('');

  section.style.display = '';
}

function collectModelImpacts() {
  const impacts = {};
  document.querySelectorAll('#model-impact-rows .model-impact-row').forEach(row => {
    const id  = row.dataset.modelId;
    const val = row.querySelector('select')?.value;
    if (id && val) impacts[id] = val;
  });
  return impacts;
}

/* ── Model multi-select dropdown ────────────────────────────────────────── */
(function initModelDropdown() {
  const trigger = document.getElementById('model-select-trigger');
  const panel   = document.getElementById('model-select-panel');
  const label   = document.getElementById('model-select-label');
  if (!trigger || !panel) return;

  function updateLabel() {
    const checked = document.querySelectorAll('input[name="affectedModels"]:checked');
    if (checked.length === 0) {
      label.textContent = 'Seleccionar modelos…';
    } else if (checked.length === 1) {
      label.textContent = checked[0].nextElementSibling?.textContent ?? checked[0].value;
    } else {
      label.textContent = `${checked.length} modelos seleccionados`;
    }
  }

  trigger.addEventListener('click', () => {
    const open = trigger.getAttribute('aria-expanded') === 'true';
    trigger.setAttribute('aria-expanded', String(!open));
    panel.hidden = open;
  });

  panel.addEventListener('change', updateLabel);

  document.addEventListener('click', (e) => {
    if (!trigger.closest('.model-multiselect').contains(e.target)) {
      trigger.setAttribute('aria-expanded', 'false');
      panel.hidden = true;
    }
  });
})();

/* ── Botones de navegación ──────────────────────────────────────────────── */

// Step 1 → 2
document.getElementById('btn-next-1')?.addEventListener('click', () => {
  if (!validateStep1()) { focusFirstError(); return; }
  collectStep1();
  goToStep(2);
});

// Step 2 ← → 3
document.getElementById('btn-back-2')?.addEventListener('click', () => goToStep(1));
document.getElementById('btn-next-2')?.addEventListener('click', () => {
  if (!validateStep2()) { focusFirstError(); return; }
  collectStep2();
  renderModelImpactRows();
  goToStep(3);
});

// Step 3 ← → 4
document.getElementById('btn-back-3')?.addEventListener('click', () => goToStep(2));
document.getElementById('btn-next-3')?.addEventListener('click', () => {
  collectStep3();
  goToStep(4);
});

// Step 4 ← → 5
document.getElementById('btn-back-4')?.addEventListener('click', () => goToStep(3));
document.getElementById('btn-next-4')?.addEventListener('click', () => {
  collectStep4();
  buildReview();
  goToStep(5);
});

// Step 5 ←
document.getElementById('btn-back-5')?.addEventListener('click', () => goToStep(4));

/* ── Dynamic list buttons ───────────────────────────────────────────────── */
document.getElementById('btn-add-mitigation')?.addEventListener('click', () => addContribMitigationRow());
document.getElementById('btn-add-example')?.addEventListener('click', () => addContribExampleRow());
document.getElementById('btn-add-reference')?.addEventListener('click', () => addContribReferenceRow());

/* ── Envío a Supabase ───────────────────────────────────────────────────── */
const SUBMIT_LABEL = `
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg>
  Enviar para revisión técnica`;

form?.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!validateStep5()) { focusFirstError(); return; }

  formData.researcherEmail = document.getElementById('researcher-email').value.trim();

  const btn = document.getElementById('btn-submit');
  btn.disabled    = true;
  btn.textContent = 'Enviando…';

  document.getElementById('submit-error')?.remove();

  const { data: { session } } = await supabase.auth.getSession();
  const userMeta       = session?.user?.user_metadata ?? {};
  const submitterName  = userMeta.user_name ?? userMeta.full_name ?? userMeta.name ?? session?.user?.email ?? 'Anónimo';

  // Build extra_data from steps 2–4 optional fields
  const extraData = {};

  if (formData.shortDescription) extraData.short_description = formData.shortDescription;
  if (formData.cvssScore)        extraData.cvss_score        = parseFloat(formData.cvssScore) || null;

  // Step 3
  if (formData.attackVector) extraData.attack_vector = formData.attackVector;
  if (formData.cvssVector)   extraData.cvss_vector   = formData.cvssVector;

  const standards = {};
  if (formData.stdOwasp) standards.owasp_llm  = formData.stdOwasp;
  if (formData.stdMitre) standards.mitre_atlas = formData.stdMitre;
  if (formData.stdNist)  standards.nist_ai_rmf = formData.stdNist;
  if (Object.keys(standards).length) extraData.standards = standards;

  const impact = {};
  if (formData.impactConfidentiality !== 'none') impact.confidentiality = formData.impactConfidentiality;
  if (formData.impactIntegrity       !== 'none') impact.integrity       = formData.impactIntegrity;
  if (formData.impactAvailability    !== 'none') impact.availability    = formData.impactAvailability;
  if (formData.impactDescription)                impact.description     = formData.impactDescription;
  if (Object.keys(impact).length) extraData.impact = impact;

  if (formData.prerequisites)
    extraData.prerequisites = formData.prerequisites.split(',').map(s => s.trim()).filter(Boolean);
  if (formData.tags)
    extraData.tags = formData.tags.split(',').map(s => s.trim()).filter(Boolean);
  if (formData.relatedVulns)
    extraData.related_vulnerabilities = formData.relatedVulns.split(',').map(s => s.trim()).filter(Boolean);

  // Step 4
  if (formData.mitigations.length) extraData.mitigations   = formData.mitigations;
  if (formData.examples.length)    extraData.examples      = formData.examples;
  if (formData.snippet)            extraData.code_snippets = [formData.snippet];
  if (formData.references.length)  extraData.references    = formData.references;
  if (Object.keys(formData.modelImpacts ?? {}).length) extraData.model_impacts = formData.modelImpacts;

  const { error } = await supabase.from('contributions').insert({
    user_id:             session?.user?.id    ?? null,
    threat_name:         formData.threatName,
    affected_model:      formData.affectedModel,
    severity:            formData.severity,
    attack_category:     formData.attackCategory,
    attack_subcategory:  formData.attackSubcategory || null,
    attack_payload:      formData.attackPayload,
    tech_description:    formData.techDescription,
    mitigation_proposal: formData.mitigationProposal || null,
    cve_reference:       formData.cveReference       || null,
    submitter_email:     formData.researcherEmail,
    submitter_name:      submitterName,
    extra_data:          Object.keys(extraData).length ? extraData : null,
  });

  if (error) {
    btn.disabled  = false;
    btn.innerHTML = SUBMIT_LABEL;
    const errEl = document.createElement('p');
    errEl.id           = 'submit-error';
    errEl.className    = 'form-error';
    errEl.style.marginTop = '1rem';
    errEl.textContent  = `No se pudo enviar el reporte: ${error.message}`;
    btn.closest('.form-actions')?.after(errEl);
    return;
  }

  form.hidden         = true;
  successPanel.hidden = false;
  successPanel.focus?.();
  window.scrollTo({ top: 0, behavior: 'smooth' });
  progressFill.style.width = '100%';
  stepIndicators.forEach(el => { el.classList.remove('is-active'); el.classList.add('is-done'); });
  stepCounter.textContent = 'Reporte enviado';
});

/* ── Validación en tiempo real ──────────────────────────────────────────── */
document.getElementById('threat-name')?.addEventListener('input', function () {
  if (this.value.trim().length >= 5) clearError('threat-name', 'threat-name-error');
});

document.getElementById('severity')?.addEventListener('change', function () {
  if (this.value) clearError('severity', 'severity-error');
});

document.getElementById('tech-description')?.addEventListener('input', function () {
  const count   = this.value.length;
  const counter = document.getElementById('description-count');
  const min     = 80;
  counter.textContent = `${count} / ${min}`;
  if (count >= min) {
    counter.classList.add('is-ok');
    clearError('tech-description', 'description-error');
  } else {
    counter.classList.remove('is-ok');
  }
});

document.getElementById('cve-reference')?.addEventListener('input', function () {
  if (!this.value.trim()) {
    document.getElementById('cve-error').hidden = true;
    this.classList.remove('is-invalid', 'is-valid');
    return;
  }
  if (this.validity.valid) clearError('cve-reference', 'cve-error');
});

document.getElementById('researcher-email')?.addEventListener('input', function () {
  const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (emailRx.test(this.value.trim())) clearError('researcher-email', 'email-error');
});

/* ── Validación coherencia CVSS ↔ Severidad ─────────────────────────────── */
const CVSS_RANGES = {
  critical: { min: 9.0, max: 10.0, label: 'Crítica (9.0–10.0)' },
  high:     { min: 7.0, max: 8.9,  label: 'Alta (7.0–8.9)' },
  medium:   { min: 4.0, max: 6.9,  label: 'Media (4.0–6.9)' },
  low:      { min: 0.1, max: 3.9,  label: 'Baja (0.1–3.9)' },
};

function checkCvssCoherence() {
  const severity = document.getElementById('severity')?.value ?? '';
  const cvssRaw  = document.getElementById('cvss-score')?.value ?? '';
  const warning  = document.getElementById('cvss-coherence-warning');
  const errEl    = document.getElementById('cvss-score-error');
  const scoreEl  = document.getElementById('cvss-score');
  if (!warning) return;

  if (!cvssRaw || !severity) { warning.hidden = true; return; }

  const cvss  = parseFloat(cvssRaw);
  const range = CVSS_RANGES[severity];
  if (!range) { warning.hidden = true; return; }

  // Range error (0-10 bounds)
  if (cvss < 0 || cvss > 10) {
    if (errEl) { errEl.textContent = 'La puntuación CVSS debe estar entre 0.0 y 10.0.'; errEl.hidden = false; }
    scoreEl?.classList.add('is-invalid');
    warning.hidden = true;
    return;
  }
  if (errEl) { errEl.hidden = true; }
  scoreEl?.classList.remove('is-invalid');

  // Coherence warning
  if (cvss < range.min || cvss > range.max) {
    warning.textContent = `⚠ CVSS ${cvss.toFixed(1)} no corresponde a severidad ${range.label}. Ajusta uno de los dos campos.`;
    warning.hidden = false;
  } else {
    warning.hidden = true;
  }
}

// Suggest CVSS range when severity changes
function suggestCvssFromSeverity() {
  const severity = document.getElementById('severity')?.value ?? '';
  const scoreEl  = document.getElementById('cvss-score');
  const hintEl   = document.getElementById('cvss-hint');
  const range    = CVSS_RANGES[severity];
  if (!range || !hintEl) return;
  hintEl.textContent = `Para severidad ${range.label} el rango esperado es ${range.min.toFixed(1)}–${range.max.toFixed(1)}.`;
  checkCvssCoherence();
}

document.getElementById('severity')?.addEventListener('change', suggestCvssFromSeverity);
document.getElementById('cvss-score')?.addEventListener('input', checkCvssCoherence);

/* ── Validación formato estándares ──────────────────────────────────────── */
const OWASP_RE  = /^LLM\d{2}:\d{4}$/i;
const MITRE_RE  = /^AML\.[A-Z]\d{4}(\.\d{3})?$/i;

function checkStdFormat(inputId, warningId, regex, example) {
  const el      = document.getElementById(inputId);
  const warning = document.getElementById(warningId);
  if (!el || !warning) return;
  const val = el.value.trim();
  if (!val) { warning.hidden = true; el.classList.remove('is-invalid', 'is-valid'); return; }
  if (!regex.test(val)) {
    warning.textContent = `⚠ Formato no reconocido. Ejemplo válido: ${example}`;
    warning.hidden = false;
    el.classList.add('is-invalid');
    el.classList.remove('is-valid');
  } else {
    warning.hidden = true;
    el.classList.remove('is-invalid');
    el.classList.add('is-valid');
  }
}

document.getElementById('std-owasp')?.addEventListener('blur', () =>
  checkStdFormat('std-owasp', 'std-owasp-warning', OWASP_RE, 'LLM01:2025'));
document.getElementById('std-mitre')?.addEventListener('blur', () =>
  checkStdFormat('std-mitre', 'std-mitre-warning', MITRE_RE, 'AML.T0054'));

/* ── Tooltips ───────────────────────────────────────────────────────────── */
document.querySelectorAll('.tooltip-trigger').forEach(btn => {
  const tooltipId = btn.dataset.tooltip;
  const tooltip   = document.getElementById(tooltipId);
  if (!tooltip) return;

  btn.addEventListener('click', () => {
    const open    = tooltip.hidden;
    tooltip.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
  });

  document.addEventListener('click', (e) => {
    if (!btn.contains(e.target) && !tooltip.contains(e.target)) {
      tooltip.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !tooltip.hidden) {
      tooltip.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
      btn.focus();
    }
  });
});

/* ── Foco en el primer error ────────────────────────────────────────────── */
function focusFirstError() {
  const firstError = document.querySelector('.form-error:not([hidden])');
  if (!firstError) return;
  const group = firstError.closest('.form-group');
  const field = group?.querySelector('input, select, textarea');
  field?.focus();
  field?.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/* ── Init ───────────────────────────────────────────────────────────────── */
updateProgress();
