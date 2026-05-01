import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const ADMIN_EMAILS = ['carb0003@red.ujaen.es', 'smm00156@red.ujaen.es', 'lina@ujaen.es']
const SITE_URL     = Deno.env.get('SITE_URL') ?? 'https://vulnerai.vercel.app'

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS })

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) return new Response('Unauthorized', { status: 401, headers: CORS })

    const token = authHeader.replace('Bearer ', '')
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
      { auth: { autoRefreshToken: false, persistSession: false } }
    )

    const { data: { user }, error: authErr } = await supabase.auth.getUser(token)
    if (authErr || !user || !ADMIN_EMAILS.includes(user.email ?? '')) {
      return new Response('Forbidden', { status: 403, headers: CORS })
    }

    const { to, name, threat_name, action, reason, vuln_id } = await req.json()

    if (!to || !threat_name || !action) {
      return new Response('Bad request — missing to, threat_name or action', { status: 400, headers: CORS })
    }

    const isApproved = action === 'approved'
    const subject    = isApproved
      ? `Contribucion aprobada: "${threat_name}"`
      : `Contribucion rechazada: "${threat_name}"`

    const html = buildEmail({ name, threat_name, action, reason, vuln_id })

    const senderEmail = Deno.env.get('BREVO_SENDER_EMAIL') ?? 'vulneraiproject@gmail.com'
    const senderName  = Deno.env.get('BREVO_SENDER_NAME')  ?? 'VulnerAI'

    const brevoRes = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key':      Deno.env.get('BREVO_API_KEY')!,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sender:      { name: senderName, email: senderEmail },
        to:          [{ email: to, name: name ?? '' }],
        subject,
        htmlContent: html,
      }),
    })

    if (!brevoRes.ok) {
      const errText = await brevoRes.text()
      throw new Error(`Brevo: ${errText}`)
    }

    const data = await brevoRes.json()
    return new Response(JSON.stringify({ ok: true, messageId: data.messageId }), {
      headers: { ...CORS, 'Content-Type': 'application/json' },
    })

  } catch (err) {
    console.error('[send-contribution-email]', err)
    return new Response(JSON.stringify({ ok: false, error: err.message }), {
      status: 500,
      headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }
})

/* ── Email templates ─────────────────────────────────────────────────────── */

function buildEmail({ name, threat_name, action, reason, vuln_id }: {
  name?: string; threat_name: string; action: string; reason?: string; vuln_id?: string
}) {
  const isApproved  = action === 'approved'
  const greeting    = name ? `Hola, ${esc(name)}` : 'Hola'
  const statusLabel = isApproved ? 'APROBADA' : 'RECHAZADA'
  const statusColor = isApproved ? '#22c55e' : '#ef4444'
  const ctaHref     = isApproved ? SITE_URL : `${SITE_URL}/contribute.html`
  const ctaLabel    = isApproved ? 'Ver en VulnerAI' : 'Enviar nueva contribucion'

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${statusLabel} — VulnerAI</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif">

  <!-- Wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f1f5f9" style="background:#f1f5f9;padding:40px 16px">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%">

        <!-- Header -->
        <tr>
          <td bgcolor="#1e2d42" style="background:#1e2d42;border-radius:12px 12px 0 0;padding:28px 40px;border-bottom:3px solid ${statusColor}">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td bgcolor="#1e2d42" style="background:#1e2d42">
                  <img src="${SITE_URL}/logo.png" alt="VulnerAI" height="36" style="display:block;height:36px;width:auto;border:0">
                </td>
                <td align="right" bgcolor="#1e2d42" style="background:#1e2d42">
                  <span style="display:inline-block;background:transparent;color:${statusColor};font-size:11px;font-weight:700;letter-spacing:0.12em;padding:5px 12px;border-radius:4px;border:1px solid ${statusColor}">${statusLabel}</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="background:#ffffff;padding:40px">

            <p style="margin:0 0 6px;font-size:14px;color:#64748b">${greeting},</p>
            <p style="margin:0 0 28px;font-size:16px;color:#0f172a;line-height:1.6">
              ${isApproved
                ? `tu contribucion <strong>"${esc(threat_name)}"</strong> ha sido revisada y <strong style="color:${statusColor}">aprobada</strong> por el equipo de VulnerAI.`
                : `tras revisar tu contribucion <strong>"${esc(threat_name)}"</strong>, el equipo de VulnerAI ha decidido <strong style="color:${statusColor}">no incorporarla</strong> en esta ocasion.`
              }
            </p>

            ${vuln_id ? `
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px">
              <tr>
                <td style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px 20px">
                  <p style="margin:0 0 4px;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:0.08em">Identificador de vulnerabilidad</p>
                  <p style="margin:0;font-size:16px;font-weight:700;color:#6366f1;font-family:monospace">${esc(vuln_id)}</p>
                </td>
              </tr>
            </table>` : ''}

            ${reason ? `
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px">
              <tr>
                <td style="background:#f8fafc;border:1px solid #e2e8f0;border-left:4px solid ${statusColor};border-radius:0 8px 8px 0;padding:16px 20px">
                  <p style="margin:0 0 6px;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:0.08em">${isApproved ? 'Nota del equipo' : 'Motivo'}</p>
                  <p style="margin:0;font-size:14px;color:#334155;line-height:1.6">${esc(reason)}</p>
                </td>
              </tr>
            </table>` : ''}

            ${!isApproved ? `<p style="margin:0 0 28px;font-size:14px;color:#64748b;line-height:1.6">Si consideras que puede mejorar, puedes enviar una nueva contribucion en cualquier momento.</p>` : ''}

            <!-- CTA -->
            <table cellpadding="0" cellspacing="0">
              <tr>
                <td style="background:#6366f1;border-radius:8px">
                  <a href="${ctaHref}" style="display:inline-block;padding:13px 28px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;letter-spacing:0.01em">${ctaLabel}</a>
                </td>
              </tr>
            </table>

          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f8fafc;border-radius:0 0 12px 12px;border-top:1px solid #e2e8f0;padding:20px 40px">
            <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.5">
              Este mensaje fue generado automaticamente por VulnerAI. Por favor, no respondas a este correo.<br>
              &copy; ${new Date().getFullYear()} VulnerAI — Plataforma de referencia en seguridad de LLMs.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>

</body>
</html>`
}

function esc(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
