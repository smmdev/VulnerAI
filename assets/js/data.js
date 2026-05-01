import { supabase } from './supabase.js';

const BASE  = 'assets/data/';
const cache = {};

async function fetchJSON(name) {
  if (cache[name]) return cache[name];
  const res = await fetch(`${BASE}${name}.json`);
  if (!res.ok) throw new Error(`[data] Error cargando ${name}.json: ${res.status}`);
  cache[name] = await res.json();
  return cache[name];
}

function normalizeVuln(v) {
  // Supabase stores standards as [{framework, id}, ...]; normalize to {key: id} object
  if (Array.isArray(v.standards)) {
    const obj = {};
    v.standards.forEach(s => { if (s.framework && s.id) obj[s.framework] = s.id; });
    return { ...v, standards: obj };
  }
  return v;
}

export async function getVulnerabilities() {
  try {
    const { data, error } = await supabase
      .from('vulnerabilities')
      .select('*')
      .eq('is_published', true);
    if (!error && data?.length) return data.map(normalizeVuln);
  } catch (_) {}
  // Fallback to local JSON if Supabase is unavailable
  const json = await fetchJSON('vulnerabilities');
  return json.vulnerabilities;
}

export async function getVulnerabilityById(id) {
  try {
    const { data, error } = await supabase
      .from('vulnerabilities')
      .select('*')
      .eq('id', id)
      .single();
    if (!error && data) return normalizeVuln(data);
  } catch (_) {}
  const list = await getVulnerabilities();
  return list.find(v => v.id === id) ?? null;
}

export async function getVulnerabilityBySlug(slug) {
  try {
    const { data, error } = await supabase
      .from('vulnerabilities')
      .select('*')
      .eq('slug', slug)
      .single();
    if (!error && data) return normalizeVuln(data);
  } catch (_) {}
  const list = await getVulnerabilities();
  return list.find(v => v.slug === slug) ?? null;
}

export async function getSnippets() {
  const data = await fetchJSON('snippets');
  return data.snippets;
}

export async function getSnippetsByVulnId(vulnId) {
  const list = await getSnippets();
  return list.filter(s => s.vulnerability_id === vulnId);
}

export async function getModels() {
  // Supabase models table lacks vulnerability_profile, overall_risk_score, etc.
  // Always use JSON which has complete model data.
  const json = await fetchJSON('models');
  return json.models;
}

export async function getStandards() {
  // Supabase standards table has a flat structure incompatible with the nested
  // format expected by index.js and vulnerabilities.js. Always use local JSON.
  return fetchJSON('standards');
}

export async function submitContribution(payload) {
  const { data: { user } } = await supabase.auth.getUser();
  const { error } = await supabase
    .from('contributions')
    .insert({ ...payload, user_id: user?.id ?? null });
  if (error) throw error;
}

export async function getSession() {
  const { data: { session } } = await supabase.auth.getSession();
  return session;
}

export async function signInWithProvider(provider) {
  const { error } = await supabase.auth.signInWithOAuth({
    provider,
    options: { redirectTo: `${location.origin}/contribute.html` }
  });
  if (error) throw error;
}

export async function signOut() {
  await supabase.auth.signOut();
}
