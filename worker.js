// ========== EPSP Berriane – Gestion des Congés ==========
// Aucun import externe – compatible Cloudflare Workers (ES modules)

const JWT_SECRET = 'votre-clef-secrete-tres-longue'; // ⚠️ Passez par une variable d'environnement en production

// ========== SHA-256 (pour le mot de passe admin) ==========
async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ========== Helpers ==========
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

function getDB(env) {
  return env.DB; // Liaison D1
}

// ========== Authentification ==========
async function withAuth(request, env, role = null) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    if (role && payload.role !== role) return null;
    return payload;
  } catch {
    return null;
  }
}

// ========== JWT (sign / verify) ==========
async function signJWT(payload) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, exp: now + 86400 }; // 24 h

  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
  const encodedPayload = btoa(JSON.stringify(fullPayload)).replace(/=/g, '');
  const toSign = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(toSign));
  const sig = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '');
  return `${toSign}.${sig}`;
}

async function jwtVerify(token, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Token invalide');
  const [headerB64, payloadB64, sigB64] = parts;
  const toVerify = `${headerB64}.${payloadB64}`;
  const sigBytes = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(toVerify));
  if (!valid) throw new Error('Signature invalide');
  return { payload: JSON.parse(atob(payloadB64)) };
}

// ========== Gestion des routes ==========
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }

  try {
    // ---------- AUTH ----------
    if (path === '/api/auth/login' && method === 'POST') {
      const { code } = await request.json();
      if (!code) return json({ error: 'Code requis' }, 400);

      // Admin – on hache le code saisi avant de comparer
      const adminRow = await getDB(env).prepare('SELECT id, code_hash FROM admins WHERE username = ?').bind('admin').first();
      if (adminRow) {
        const hashedInput = await sha256(code);
        if (adminRow.code_hash === hashedInput) {
          const token = await signJWT({ id: adminRow.id, role: 'admin', code: 'admin' });
          return json({ token, role: 'admin' });
        }
      }

      // Employé – code en clair
      const emp = await getDB(env).prepare('SELECT id, code, first_name FROM employees WHERE code = ?').bind(code).first();
      if (emp) {
        const token = await signJWT({ id: emp.id, role: 'employee', code: emp.code });
        return json({
          token,
          role: 'employee',
          firstLogin: emp.first_name === '' || emp.first_name === null
        });
      }

      return json({ error: 'Code invalide' }, 401);
    }

    if (path === '/api/auth/register' && method === 'POST') {
      const user = await withAuth(request, env, 'employee');
      if (!user) return json({ error: 'Non autorisé' }, 401);
      const data = await request.json();
      const required = ['first_name','last_name','first_name_ar','last_name_ar','grade_id','degree_id','service_id','center_id','region'];
      for (const f of required) if (!data[f]) return json({ error: `Champ ${f} obligatoire` }, 400);
      const workPhone = data.work_phone || '';

      const update = await getDB(env).prepare(`
        UPDATE employees SET first_name=?, last_name=?, first_name_ar=?, last_name_ar=?,
        grade_id=?, degree_id=?, service_id=?, center_id=?, region=?, work_phone=?
        WHERE id=? AND first_name=''
      `).bind(data.first_name, data.last_name, data.first_name_ar, data.last_name_ar,
              data.grade_id, data.degree_id, data.service_id, data.center_id, data.region, workPhone, user.id).run();
      if (update.meta.changes === 0) return json({ error: 'Profil déjà complété ou introuvable' }, 400);
      await getDB(env).prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?,?,?)')
        .bind(user.id, 'complete_profile', JSON.stringify(data)).run();
      return json({ success: true });
    }

    // ---------- EMPLOYÉ ----------
    if (path === '/api/employee/profile' && method === 'GET') {
      const user = await withAuth(request, env, 'employee');
      if (!user) return json({ error: 'Non autorisé' }, 401);
      const emp = await getDB(env).prepare(`
        SELECT e.*, g.name grade, d.name degree, s.name service, c.name center
        FROM employees e
        JOIN grades g ON e.grade_id=g.id
        JOIN degrees d ON e.degree_id=d.id
        JOIN services s ON e.service_id=s.id
        JOIN centers c ON e.center_id=c.id
        WHERE e.id=?`).bind(user.id).first();
      return json(emp);
    }

    // ---------- RÉFÉRENTIELS (admin) ----------
    const refMatch = path.match(/^\/api\/referentials\/(grades|degrees|services|centers)$/);
    if (refMatch) {
      const user = await withAuth(request, env, 'admin');
      if (!user) return json({ error: 'Accès refusé' }, 403);
      const table = refMatch[1];
      if (method === 'GET') {
        const rows = await getDB(env).prepare(`SELECT * FROM ${table} ORDER BY name`).all();
        return json(rows.results);
      }
      if (method === 'POST') {
        const { name } = await request.json();
        if (!name) return json({ error: 'Nom requis' }, 400);
        const result = await getDB(env).prepare(`INSERT INTO ${table} (name) VALUES (?)`).bind(name).run();
        await getDB(env).prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?,?,?)')
          .bind(user.id, `create_${table}`, JSON.stringify({ name })).run();
        return json({ id: result.meta.last_row_id, name }, 201);
      }
    }

    const refIdMatch = path.match(/^\/api\/referentials\/(grades|degrees|services|centers)\/(\d+)$/);
    if (refIdMatch) {
      const user = await withAuth(request, env, 'admin');
      if (!user) return json({ error: 'Accès refusé' }, 403);
      const table = refIdMatch[1];
      const id = refIdMatch[2];
      if (method === 'PUT') {
        const { name } = await request.json();
        if (!name) return json({ error: 'Nom requis' }, 400);
        await getDB(env).prepare(`UPDATE ${table} SET name=? WHERE id=?`).bind(name, id).run();
        return json({ success: true });
      }
      if (method === 'DELETE') {
        await getDB(env).prepare(`DELETE FROM ${table} WHERE id=?`).bind(id).run();
        return json({ success: true });
      }
    }

    // ---------- DEMANDE DE CONGÉ ----------
    if (path === '/api/leaves/request' && method === 'POST') {
      const user = await withAuth(request, env, 'employee');
      if (!user) return json({ error: 'Non autorisé' }, 401);
      const { leave_type, start_date, end_date, duration: durInput, mode, observation } = await request.json();
      if (!leave_type || !start_date) return json({ error: 'Type et date début requis' }, 400);
      if (!['annuel','recuperation','maladie'].includes(leave_type)) return json({ error: 'Type invalide' }, 400);

      let start = new Date(start_date);
      if (isNaN(start.getTime())) return json({ error: 'Date début invalide' }, 400);
      let end, duration;

      if (mode === 'duration') {
        const days = parseInt(durInput);
        if (!days || days < 1) return json({ error: 'Nombre jours invalide' }, 400);
        duration = days;
        end = new Date(start);
        end.setDate(end.getDate() + days - 1);
      } else {
        if (!end_date) return json({ error: 'Date retour requise' }, 400);
        end = new Date(end_date);
        if (isNaN(end.getTime()) || end < start) return json({ error: 'Date retour invalide' }, 400);
        duration = Math.ceil((end - start) / 86400000) + 1;
      }

      // Chevauchment
      const overlap = await getDB(env).prepare(
        `SELECT COUNT(*) count FROM leave_requests WHERE employee_id=? AND status='Approuvé' AND start_date<=? AND end_date>=?`
      ).bind(user.id, end.toISOString().split('T')[0], start.toISOString().split('T')[0]).first();
      if (overlap.count > 0) return json({ error: 'Chevauchement avec un congé approuvé' }, 400);

      // Solde pour congé annuel
      if (leave_type === 'annuel') {
        const balances = await getDB(env).prepare('SELECT total_days, used_days FROM leave_balances WHERE employee_id=? ORDER BY year').bind(user.id).all();
        const available = balances.results.reduce((sum, b) => sum + (b.total_days - b.used_days), 0);
        if (available < duration) return json({ error: 'Solde insuffisant' }, 400);
      }

      const result = await getDB(env).prepare(
        `INSERT INTO leave_requests (employee_id, leave_type, start_date, end_date, duration, observation) VALUES (?,?,?,?,?,?)`
      ).bind(user.id, leave_type, start.toISOString().split('T')[0], end.toISOString().split('T')[0], duration, observation || '').run();

      await getDB(env).prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?,?,?)')
        .bind(user.id, 'create_request', JSON.stringify({ requestId: result.meta.last_row_id })).run();
      return json({ success: true, id: result.meta.last_row_id });
    }

    // ---------- HISTORIQUE / DÉTAIL DEMANDE ----------
    if (path === '/api/leaves/history' && method === 'GET') {
      const user = await withAuth(request, env, 'employee');
      if (!user) return json({ error: 'Non autorisé' }, 401);
      const rows = await getDB(env).prepare('SELECT * FROM leave_requests WHERE employee_id=? ORDER BY created_at DESC').bind(user.id).all();
      return json(rows.results);
    }

    const reqDetailMatch = path.match(/^\/api\/leaves\/requests\/(\d+)$/);
    if (reqDetailMatch && method === 'GET') {
      const user = await withAuth(request, env);
      if (!user) return json({ error: 'Non autorisé' }, 401);
      const id = reqDetailMatch[1];
      const reqData = await getDB(env).prepare('SELECT * FROM leave_requests WHERE id=?').bind(id).first();
      if (!reqData) return json({ error: 'Introuvable' }, 404);
      if (user.role === 'employee' && reqData.employee_id !== user.id) return json({ error: 'Accès refusé' }, 403);
      return json(reqData);
    }

    const validateMatch = path.match(/^\/api\/leaves\/requests\/(\d+)\/validate$/);
    if (validateMatch && method === 'PUT') {
      const user = await withAuth(request, env, 'admin');
      if (!user) return json({ error: 'Non autorisé' }, 401);
      const id = validateMatch[1];
      const { status } = await request.json();
      if (!['Approuvé','Refusé'].includes(status)) return json({ error: 'Statut invalide' }, 400);

      const reqData = await getDB(env).prepare('SELECT * FROM leave_requests WHERE id=?').bind(id).first();
      if (!reqData) return json({ error: 'Introuvable' }, 404);
      if (reqData.status !== 'En attente') return json({ error: 'Déjà traitée' }, 400);

      if (status === 'Approuvé' && reqData.leave_type === 'annuel') {
        const balances = await getDB(env).prepare('SELECT * FROM leave_balances WHERE employee_id=? ORDER BY year').bind(reqData.employee_id).all();
        let remaining = reqData.duration;
        for (const bal of balances.results) {
          const avail = bal.total_days - bal.used_days;
          if (avail > 0 && remaining > 0) {
            const deduct = Math.min(avail, remaining);
            await getDB(env).prepare('UPDATE leave_balances SET used_days = used_days + ? WHERE id=?').bind(deduct, bal.id).run();
            await getDB(env).prepare('INSERT INTO leave_transactions (employee_id, request_id, type, amount, balance_year, description) VALUES (?,?,?,?,?,?)')
              .bind(reqData.employee_id, id, 'debit', deduct, bal.year, `Congé ${reqData.leave_type} approuvé`).run();
            remaining -= deduct;
            if (remaining <= 0) break;
          }
        }
        const newStatus = reqData.leave_type === 'annuel' ? 'En congé' : (reqData.leave_type === 'recuperation' ? 'En récupération' : 'En maladie');
        await getDB(env).prepare('UPDATE employees SET status=? WHERE id=?').bind(newStatus, reqData.employee_id).run();
      }

      await getDB(env).prepare('UPDATE leave_requests SET status=?, validated_by=?, validated_at=CURRENT_TIMESTAMP WHERE id=?').bind(status, user.id, id).run();
      await getDB(env).prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?,?,?)').bind(user.id, 'validate_request', JSON.stringify({ requestId: id, status })).run();
      return json({ success: true });
    }

    // ---------- DASHBOARD ADMIN ----------
    if (path === '/api/admin/dashboard' && method === 'GET') {
      const user = await withAuth(request, env, 'admin');
      if (!user) return json({ error: 'Accès refusé' }, 403);
      const [absent, pending, total] = await Promise.all([
        getDB(env).prepare("SELECT COUNT(*) count FROM employees WHERE status != 'En travail'").first(),
        getDB(env).prepare("SELECT COUNT(*) count FROM leave_requests WHERE status = 'En attente'").first(),
        getDB(env).prepare('SELECT COUNT(*) count FROM employees').first()
      ]);
      return json({ absent: absent.count, pending: pending.count, totalEmployees: total.count });
    }

    // ---------- SOLDES EMPLOYÉ ----------
    if (path === '/api/leaves/balances' && method === 'GET') {
      const user = await withAuth(request, env, 'employee');
      if (!user) return json({ error: 'Non autorisé' }, 401);
      const rows = await getDB(env).prepare('SELECT year, total_days, used_days, (total_days-used_days) remaining FROM leave_balances WHERE employee_id=? ORDER BY year').bind(user.id).all();
      return json(rows.results);
    }

    // ---------- SAISIE INITIALE ----------
    if (path === '/api/leaves/initial' && method === 'POST') {
      const user = await withAuth(request, env, 'employee');
      if (!user) return json({ error: 'Non autorisé' }, 401);
      const { year, days } = await request.json();
      if (!year || !days || days <= 0) return json({ error: 'Année et jours valides requis' }, 400);
      const exist = await getDB(env).prepare('SELECT id FROM leave_balances WHERE employee_id=? AND year=?').bind(user.id, year).first();
      if (exist) return json({ error: 'Solde déjà existant' }, 400);
      await getDB(env).prepare('INSERT INTO leave_balances (employee_id, year, total_days, used_days) VALUES (?,?,?,0)').bind(user.id, year, days).run();
      await getDB(env).prepare('INSERT INTO leave_transactions (employee_id, type, amount, balance_year, description) VALUES (?,?,?,?,?)').bind(user.id, 'credit', days, year, 'Saisie initiale employé').run();
      return json({ success: true });
    }

    // 404
    return json({ error: 'Route non trouvée' }, 404);
  } catch (e) {
    return json({ error: 'Erreur serveur', details: e.message }, 500);
  }
}

// ========== CRON JOBS ==========
export async function scheduled(event, env, ctx) {
  // Remise à "En travail" chaque jour à minuit
  if (event.cron === '0 0 * * *') {
    const today = new Date().toISOString().split('T')[0];
    await getDB(env).prepare(`
      UPDATE employees SET status='En travail'
      WHERE status IN ('En congé','En récupération','En maladie')
      AND id IN (SELECT employee_id FROM leave_requests WHERE status='Approuvé' AND end_date < ?)
    `).bind(today).run();
  }

  // Attribution annuelle le 1er juin à minuit
  if (event.cron === '0 0 1 6 *') {
    const year = new Date().getFullYear();
    const emps = await getDB(env).prepare('SELECT id, region FROM employees').all();
    for (const e of emps.results) {
      const total = e.region === 'SUD_2' ? 50 : 30;
      await getDB(env).prepare('INSERT INTO leave_balances (employee_id, year, total_days, used_days) VALUES (?,?,?,0)').bind(e.id, year, total).run();
      await getDB(env).prepare('INSERT INTO leave_transactions (employee_id, type, amount, balance_year, description) VALUES (?,?,?,?,?)').bind(e.id, 'credit', total, year, 'Attribution annuelle').run();
    }
  }
}

// ========== EXPORT ==========
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  },
  scheduled
};