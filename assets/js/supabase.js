import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';

const SUPABASE_URL = 'https://kfmeqvzyqtcxqysipwam.supabase.co';
const SUPABASE_KEY = 'sb_publishable_pyPN4wPSEZI7f9P3ucqurw_Os2mleJn';

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
