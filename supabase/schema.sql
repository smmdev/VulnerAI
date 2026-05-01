-- ═══════════════════════════════════════════════════════════════════════════
-- VulnerAI — Esquema de base de datos (estado final)
-- Proyecto Supabase: kfmeqvzyqtcxqysipwam
-- Idempotente — puede ejecutarse desde cero para recrear la BD completa
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Tablas ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.vulnerabilities (
  id                      TEXT PRIMARY KEY,
  slug                    TEXT UNIQUE NOT NULL,
  title                   TEXT NOT NULL,
  short_description       TEXT,
  full_description        TEXT,
  category                TEXT,
  subcategory             TEXT,
  severity                TEXT CHECK (severity IN ('critical','high','medium','low','info')),
  cvss_score              NUMERIC(4,1) DEFAULT 0.0,
  cvss_vector             TEXT,
  standards               JSONB    DEFAULT '[]',
  affected_models         JSONB    DEFAULT '[]',
  attack_vector           TEXT,
  prerequisites           JSONB    DEFAULT '[]',
  impact                  JSONB    DEFAULT '{}',
  examples                JSONB    DEFAULT '[]',
  mitigations             JSONB    DEFAULT '[]',
  code_snippets           JSONB    DEFAULT '[]',
  related_vulnerabilities JSONB    DEFAULT '[]',
  "references"            JSONB    DEFAULT '[]',
  tags                    JSONB    DEFAULT '[]',
  linguistic_level        TEXT CHECK (linguistic_level IN ('lexico','sintactico','semantico')),
  performance_cost        TEXT CHECK (performance_cost IN ('low','medium','high')),
  ethical_risks           JSONB    DEFAULT '[]',
  cve_reference           TEXT,
  is_published            BOOLEAN  DEFAULT TRUE,
  created                 TIMESTAMPTZ DEFAULT NOW(),
  updated                 TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.contributions (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  threat_name         TEXT NOT NULL,
  affected_model      TEXT,
  severity            TEXT,
  attack_category     TEXT,
  attack_payload      TEXT,
  tech_description    TEXT,
  mitigation_proposal TEXT,
  cve_reference       TEXT,
  submitter_name      TEXT,
  submitter_email     TEXT,
  submitter_role      TEXT,
  status              TEXT DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  rejection_reason    TEXT,
  admin_notes         TEXT,
  extra_data          JSONB DEFAULT NULL,
  created_at          TIMESTAMPTZ DEFAULT NOW(),
  updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.standards (
  id            TEXT PRIMARY KEY,
  slug          TEXT UNIQUE,
  name          TEXT NOT NULL,
  full_name     TEXT,
  description   TEXT,
  url           TEXT,
  type          TEXT,
  last_reviewed DATE,
  logo_url      TEXT
);

CREATE TABLE IF NOT EXISTS public.models (
  id          TEXT PRIMARY KEY,
  slug        TEXT UNIQUE,
  name        TEXT NOT NULL,
  vendor      TEXT,
  type        TEXT,
  description TEXT
);

-- ── RLS ──────────────────────────────────────────────────────────────────────

-- vulnerabilities: RLS deshabilitado (datos públicos, acceso controlado por app)
ALTER TABLE public.vulnerabilities  DISABLE ROW LEVEL SECURITY;

-- contributions: solo usuarios autenticados
ALTER TABLE public.contributions    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.standards        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.models           ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN (
    SELECT schemaname, tablename, policyname FROM pg_policies
    WHERE tablename IN ('contributions','standards','models') AND schemaname = 'public'
  ) LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "contributions_insert"
  ON public.contributions FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "contributions_authenticated_access"
  ON public.contributions FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "standards_public_read"
  ON public.standards FOR SELECT USING (true);

CREATE POLICY "models_public_read"
  ON public.models FOR SELECT USING (true);

-- ── Grants ───────────────────────────────────────────────────────────────────

GRANT USAGE ON SCHEMA public TO anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON public.vulnerabilities TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.contributions   TO authenticated;
GRANT SELECT                         ON public.standards       TO anon, authenticated;
GRANT SELECT                         ON public.models          TO anon, authenticated;

-- ── Triggers ─────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_updated_at ON public.vulnerabilities;
CREATE TRIGGER set_updated_at
  BEFORE UPDATE ON public.vulnerabilities
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE OR REPLACE FUNCTION update_contributions_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_contributions_updated_at ON public.contributions;
CREATE TRIGGER set_contributions_updated_at
  BEFORE UPDATE ON public.contributions
  FOR EACH ROW EXECUTE FUNCTION update_contributions_updated_at();
