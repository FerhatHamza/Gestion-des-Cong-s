// Imports via URL – aucun npm nécessaire
import { Router } from 'https://esm.sh/itty-router@5.0.17';
import { SignJWT, jwtVerify } from 'https://esm.sh/jose@5.3.0';

const router = Router();

// Secret JWT (mettez une valeur longue et aléatoire – vous pouvez aussi la stocker dans une variable d’env.)
const JWT_SECRET = new TextEncoder().encode('votre-clef-secrete-tres-longue');

// Hash du mot de passe admin ("password" en SHA-256) – changez-le !
const ADMIN_HASH = '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8';

// ---------- Middleware ----------
async function withAuth(request, env, requiredRole = null) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.split(' ')[1];
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    if (requiredRole && payload.role !== requiredRole) return null;
    return payload;
  } catch {
    return null;
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

function getDB(env) {
  return env.DB; // Liaison D1 attendue nommée "DB"
}

// ---------- AUTH ----------
router.post('/api/auth/login', async (req, env) => {
  const { code } = await req.json();
  if (!code) return jsonResponse({ error: 'Code requis' }, 400);

  // Admin
  const adminRow = await getDB(env).prepare('SELECT id, code_hash FROM admins WHERE username = ?').bind('admin').first();
  if (adminRow && adminRow.code_hash === code) {
    const token = await new SignJWT({ id: adminRow.id, role: 'admin', code: 'admin' })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('24h')
      .sign(JWT_SECRET);
    return jsonResponse({ token, role: 'admin' });
  }

  // Employé
  const emp = await getDB(env).prepare('SELECT id, code, first_name FROM employees WHERE code = ?').bind(code).first();
  if (emp) {
    const token = await new SignJWT({ id: emp.id, role: 'employee', code: emp.code })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('24h')
      .sign(JWT_SECRET);
    return jsonResponse({
      token,
      role: 'employee',
      firstLogin: emp.first_name === '' || emp.first_name === null
    });
  }
  return jsonResponse({ error: 'Code invalide' }, 401);
});

router.post('/api/auth/register', async (req, env) => {
  const user = await withAuth(req, env, 'employee');
  if (!user) return jsonResponse({ error: 'Non autorisé' }, 401);

  const data = await req.json();
  const required = ['first_name', 'last_name', 'first_name_ar', 'last_name_ar', 'grade_id', 'degree_id', 'service_id', 'center_id', 'region'];
  for (const f of required) {
    if (!data[f]) return jsonResponse({ error: `Champ ${f} obligatoire` }, 400);
  }
  const workPhone = data.work_phone || '';

  const update = await getDB(env).prepare(`
    UPDATE employees 
    SET first_name = ?, last_name = ?, first_name_ar = ?, last_name_ar = ?, 
        grade_id = ?, degree_id = ?, service_id = ?, center_id = ?, region = ?, work_phone = ?
    WHERE id = ? AND first_name = ''
  `).bind(data.first_name, data.last_name, data.first_name_ar, data.last_name_ar,
          data.grade_id, data.degree_id, data.service_id, data.center_id, data.region, workPhone, user.id).run();

  if (update.meta.changes === 0) return jsonResponse({ error: 'Profil déjà complété ou introuvable' }, 400);

  await getDB(env).prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?,?,?)')
    .bind(user.id, 'complete_profile', JSON.stringify(data)).run();
  return jsonResponse({ success: true });
});

// ---------- EMPLOYÉ ----------
router.get('/api/employee/profile', async (req, env) => {
  const user = await withAuth(req, env, 'employee');
  if (!user) return jsonResponse({ error: 'Non autorisé' }, 401);
  const emp = await getDB(env).prepare(`
    SELECT e.id, e.code, e.first_name, e.last_name, e.first_name_ar, e.last_name_ar, 
           e.region, e.status, e.work_phone,
           g.name as grade, d.name as degree, s.name as service, c.name as center
    FROM employees e
    JOIN grades g ON e.grade_id = g.id
    JOIN degrees d ON e.degree_id = d.id
    JOIN services s ON e.service_id = s.id
    JOIN centers c ON e.center_id = c.id
    WHERE e.id = ?
  `).bind(user.id).first();
  return jsonResponse(emp);
});

// ---------- DEMANDE DE CONGÉ ----------
router.post('/api/leaves/request', async (req, env) => {
  const user = await withAuth(req, env, 'employee');
  if (!user) return jsonResponse({ error: 'Non autorisé' }, 401);

  const { leave_type, start_date, end_date, duration: durationInput, mode, observation } = await req.json();
  if (!leave_type || !start_date) return jsonResponse({ error: 'Type et date de début requis' }, 400);
  if (!['annuel','recuperation','maladie'].includes(leave_type)) return jsonResponse({ error: 'Type invalide' }, 400);

  let start = new Date(start_date);
  if (isNaN(start.getTime())) return jsonResponse({ error: 'Date de début invalide' }, 400);
  let end, duration;

  if (mode === 'duration') {
    const days = parseInt(durationInput);
    if (!days || days < 1) return jsonResponse({ error: 'Nombre de jours invalide' }, 400);
    duration = days;
    end = new Date(start);
    end.setDate(end.getDate() + days - 1);
  } else {
    if (!end_date) return jsonResponse({ error: 'Date de retour requise' }, 400);
    end = new Date(end_date);
    if (isNaN(end.getTime()) || end < start) return jsonResponse({ error: 'Date de retour invalide ou antérieure' }, 400);
    duration = Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1;
  }

  // Vérification chevauchement
  const overlap = await getDB(env).prepare(
    `SELECT COUNT(*) as count FROM leave_requests
     WHERE employee_id = ? AND status = 'Approuvé' AND start_date <= ? AND end_date >= ?`
  ).bind(user.id, end.toISOString().split('T')[0], start.toISOString().split('T')[0]).first();
  if (overlap.count > 0) return jsonResponse({ error: 'Chevauchement avec un congé approuvé' }, 400);

  // Solde annuel si type = annuel
  if (leave_type === 'annuel') {
    const balances = await getDB(env).prepare(
      'SELECT year, total_days, used_days FROM leave_balances WHERE employee_id = ? ORDER BY year'
    ).bind(user.id).all();
    let available = balances.results.reduce((sum, b) => sum + (b.total_days - b.used_days), 0);
    if (available < duration) return jsonResponse({ error: 'Solde annuel insuffisant' }, 400);
  }

  const result = await getDB(env).prepare(
    `INSERT INTO leave_requests (employee_id, leave_type, start_date, end_date, duration, observation)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(user.id, leave_type, start.toISOString().split('T')[0], end.toISOString().split('T')[0], duration, observation || '').run();

  await getDB(env).prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .bind(user.id, 'create_request', JSON.stringify({ requestId: result.meta.last_row_id })).run();

  return jsonResponse({ success: true, id: result.meta.last_row_id });
});

// ---------- HISTORIQUE ET DÉTAIL ----------
router.get('/api/leaves/history', async (req, env) => {
  const user = await withAuth(req, env, 'employee');
  if (!user) return jsonResponse({ error: 'Non autorisé' }, 401);
  const rows = await getDB(env).prepare('SELECT * FROM leave_requests WHERE employee_id = ? ORDER BY created_at DESC').bind(user.id).all();
  return jsonResponse(rows.results);
});

router.get('/api/leaves/requests/:id', async (req, env) => {
  const user = await withAuth(req, env);
  if (!user) return jsonResponse({ error: 'Non autorisé' }, 401);
  const reqData = await getDB(env).prepare('SELECT * FROM leave_requests WHERE id = ?').bind(req.params.id).first();
  if (!reqData) return jsonResponse({ error: 'Introuvable' }, 404);
  if (user.role === 'employee' && reqData.employee_id !== user.id) return jsonResponse({ error: 'Accès refusé' }, 403);
  return jsonResponse(reqData);
});

// ---------- VALIDATION ADMIN ----------
router.put('/api/leaves/requests/:id/validate', async (req, env) => {
  const user = await withAuth(req, env, 'admin');
  if (!user) return jsonResponse({ error: 'Non autorisé' }, 401);

  const requestId = req.params.id;
  const { status } = await req.json();
  if (!['Approuvé','Refusé'].includes(status)) return jsonResponse({ error: 'Statut invalide' }, 400);

  const reqData = await getDB(env).prepare('SELECT * FROM leave_requests WHERE id = ?').bind(requestId).first();
  if (!reqData) return jsonResponse({ error: 'Introuvable' }, 404);
  if (reqData.status !== 'En attente') return jsonResponse({ error: 'Déjà traitée' }, 400);

  if (status === 'Approuvé') {
    if (reqData.leave_type === 'annuel') {
      const balances = await getDB(env).prepare(
        'SELECT id, year, total_days, used_days FROM leave_balances WHERE employee_id = ? ORDER BY year'
      ).bind(reqData.employee_id).all();

      let remaining = reqData.duration;
      for (const bal of balances.results) {
        const available = bal.total_days - bal.used_days;
        if (available > 0 && remaining > 0) {
          const deduct = Math.min(available, remaining);
          await getDB(env).prepare('UPDATE leave_balances SET used_days = used_days + ? WHERE id = ?').bind(deduct, bal.id).run();
          await getDB(env).prepare(
            'INSERT INTO leave_transactions (employee_id, request_id, type, amount, balance_year, description) VALUES (?, ?, ?, ?, ?, ?)'
          ).bind(reqData.employee_id, requestId, 'debit', deduct, bal.year, `Congé ${reqData.leave_type} approuvé`).run();
          remaining -= deduct;
          if (remaining <= 0) break;
        }
      }
    }

    const newStatus = reqData.leave_type === 'annuel' ? 'En congé' :
                      reqData.leave_type === 'recuperation' ? 'En récupération' : 'En maladie';
    await getDB(env).prepare('UPDATE employees SET status = ? WHERE id = ?').bind(newStatus, reqData.employee_id).run();
  }

  await getDB(env).prepare(`
    UPDATE leave_requests SET status = ?, validated_by = ?, validated_at = CURRENT_TIMESTAMP WHERE id = ?
  `).bind(status, user.id, requestId).run();

  await getDB(env).prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .bind(user.id, 'validate_request', JSON.stringify({ requestId, status })).run();

  return jsonResponse({ success: true });
});

// ---------- RÉFÉRENTIELS ----------
const REF_TABLES = ['grades', 'degrees', 'services', 'centers'];

for (const table of REF_TABLES) {
  router.get(`/api/referentials/${table}`, async (req, env) => {
    const user = await withAuth(req, env, 'admin');
    if (!user) return jsonResponse({ error: 'Accès refusé' }, 403);
    const rows = await getDB(env).prepare(`SELECT * FROM ${table} ORDER BY name`).all();
    return jsonResponse(rows.results);
  });

  router.post(`/api/referentials/${table}`, async (req, env) => {
    const user = await withAuth(req, env, 'admin');
    if (!user) return jsonResponse({ error: 'Accès refusé' }, 403);
    const { name } = await req.json();
    if (!name) return jsonResponse({ error: 'Nom requis' }, 400);
    const result = await getDB(env).prepare(`INSERT INTO ${table} (name) VALUES (?)`).bind(name).run();
    await getDB(env).prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
      .bind(user.id, `create_${table}`, JSON.stringify({ name })).run();
    return jsonResponse({ id: result.meta.last_row_id, name }, 201);
  });

  router.put(`/api/referentials/${table}/:id`, async (req, env) => {
    const user = await withAuth(req, env, 'admin');
    if (!user) return jsonResponse({ error: 'Accès refusé' }, 403);
    const { name } = await req.json();
    if (!name) return jsonResponse({ error: 'Nom requis' }, 400);
    await getDB(env).prepare(`UPDATE ${table} SET name = ? WHERE id = ?`).bind(name, req.params.id).run();
    return jsonResponse({ success: true });
  });

  router.delete(`/api/referentials/${table}/:id`, async (req, env) => {
    const user = await withAuth(req, env, 'admin');
    if (!user) return jsonResponse({ error: 'Accès refusé' }, 403);
    await getDB(env).prepare(`DELETE FROM ${table} WHERE id = ?`).bind(req.params.id).run();
    return jsonResponse({ success: true });
  });
}

// ---------- DASHBOARD ADMIN ----------
router.get('/api/admin/dashboard', async (req, env) => {
  const user = await withAuth(req, env, 'admin');
  if (!user) return jsonResponse({ error: 'Accès refusé' }, 403);
  const absent = await getDB(env).prepare("SELECT COUNT(*) as count FROM employees WHERE status != 'En travail'").first();
  const pending = await getDB(env).prepare("SELECT COUNT(*) as count FROM leave_requests WHERE status = 'En attente'").first();
  const total = await getDB(env).prepare('SELECT COUNT(*) as count FROM employees').first();
  return jsonResponse({ absent: absent.count, pending: pending.count, totalEmployees: total.count });
});

// ---------- SOLDES ----------
router.get('/api/leaves/balances', async (req, env) => {
  const user = await withAuth(req, env, 'employee');
  if (!user) return jsonResponse({ error: 'Non autorisé' }, 401);
  const rows = await getDB(env).prepare('SELECT year, total_days, used_days, (total_days - used_days) as remaining FROM leave_balances WHERE employee_id = ? ORDER BY year').bind(user.id).all();
  return jsonResponse(rows.results);
});

// ---------- SAISIE INITIALE ----------
router.post('/api/leaves/initial', async (req, env) => {
  const user = await withAuth(req, env, 'employee');
  if (!user) return jsonResponse({ error: 'Non autorisé' }, 401);
  const { year, days } = await req.json();
  if (!year || !days || days <= 0) return jsonResponse({ error: 'Année et nombre de jours valides requis' }, 400);

  const exist = await getDB(env).prepare('SELECT id FROM leave_balances WHERE employee_id = ? AND year = ?').bind(user.id, year).first();
  if (exist) return jsonResponse({ error: 'Solde déjà existant' }, 400);

  await getDB(env).prepare('INSERT INTO leave_balances (employee_id, year, total_days, used_days) VALUES (?, ?, ?, 0)').bind(user.id, year, days).run();
  await getDB(env).prepare('INSERT INTO leave_transactions (employee_id, type, amount, balance_year, description) VALUES (?, ?, ?, ?, ?)').bind(user.id, 'credit', days, year, 'Saisie initiale employé').run();
  return jsonResponse({ success: true });
});

// ---------- GESTION DES CRONS ----------
export async function scheduled(event, env, ctx) {
  // Remise à "En travail" à minuit
  if (event.cron === '0 0 * * *') {
    const today = new Date().toISOString().split('T')[0];
    await getDB(env).prepare(`
      UPDATE employees SET status = 'En travail'
      WHERE status IN ('En congé', 'En récupération', 'En maladie')
      AND id IN (
        SELECT employee_id FROM leave_requests WHERE status = 'Approuvé' AND end_date < ?
      )
    `).bind(today).run();
  }

  // Attribution annuelle le 1er juin à minuit
  if (event.cron === '0 0 1 6 *') {
    const year = new Date().getFullYear();
    const emps = await getDB(env).prepare('SELECT id, region FROM employees').all();
    for (const e of emps.results) {
      const total = e.region === 'SUD_2' ? 50 : 30;
      await getDB(env).prepare('INSERT INTO leave_balances (employee_id, year, total_days, used_days) VALUES (?, ?, ?, 0)').bind(e.id, year, total).run();
      await getDB(env).prepare('INSERT INTO leave_transactions (employee_id, type, amount, balance_year, description) VALUES (?, ?, ?, ?, ?)').bind(e.id, 'credit', total, year, 'Attribution annuelle automatique').run();
    }
  }
}

// ---------- 404 / CORS ----------
router.all('*', async (req, env) => {
  const res = await router.handle(req, env);
  if (res) {
    res.headers.set('Access-Control-Allow-Origin', '*');
    return res;
  }
  return new Response('Not Found', { status: 404 });
});

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }
    return router.handle(request, env, ctx);
  },
  scheduled
};