const HEADERS = { 'content-type': 'application/json; charset=utf-8' };
const FICO_ROLES = new Set(['fico_admin', 'fico_inspector']);
const ALL_SEE_ROLES = new Set(['fico_admin', 'fico_inspector']);
const EDIT_ROLES = new Set(['fico_admin', 'company_admin', 'front_manager']);
const INSPECT_ROLES = new Set(['fico_admin', 'fico_inspector']);

function cors(request) {
  const origin = request.headers.get('origin');
  const allowed = !origin || origin === 'https://radarfico.github.io' || /^http:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?$/.test(origin);
  return { 'access-control-allow-origin': allowed && origin ? origin : 'https://radarfico.github.io', 'access-control-allow-methods': 'GET,POST,OPTIONS', 'access-control-allow-headers': 'authorization,content-type', vary: 'Origin' };
}

export const radarTestables = { effectiveStatus, normalizeSegments, normalizeEquipment, normalizeActivities, normalizeLdlRequirement, validUserCompany };
function reply(request, body, status = 200) { return new Response(JSON.stringify(body), { status, headers: { ...HEADERS, ...cors(request), 'cache-control': 'no-store' } }); }
function clean(value, max = 200) { return String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max); }
function code(value, max = 30) { const v = clean(value, max).toUpperCase(); return /^[A-Z0-9][A-Z0-9-]{1,29}$/.test(v) ? v : null; }
function iso(value) { if (value === null || value === undefined || String(value).trim() === '') return null; const d = new Date(value); return Number.isFinite(d.valueOf()) ? d.toISOString() : null; }
function num(value) { const n = Number(value); return Number.isFinite(n) ? n : null; }
function uuid() { return crypto.randomUUID(); }
function now() { return new Date().toISOString(); }
async function sha256(value) { const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)); return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
function random(bytes = 24) { const data = crypto.getRandomValues(new Uint8Array(bytes)); return [...data].map((b) => b.toString(16).padStart(2, '0')).join(''); }
function safeJson(value, fallback = null) { try { return JSON.parse(value || ''); } catch { return fallback; } }

function publicUser(row) { return { id: row.id, companyId: row.company_id, companyName: row.company_name, login: row.login, name: row.name, role: row.role, phone: row.phone }; }
function validUserCompany(role, companyId) { return FICO_ROLES.has(role) ? !companyId : Boolean(companyId); }
async function authenticate(request, env) {
  const bearer = request.headers.get('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!bearer) return null;
  return env.DB.prepare(`SELECT u.*,c.name AS company_name FROM radar_sessions s JOIN radar_users u ON u.id=s.user_id
    LEFT JOIN radar_companies c ON c.id=u.company_id WHERE s.token_hash=? AND s.expires_at>CURRENT_TIMESTAMP AND u.active=1`).bind(await sha256(bearer)).first();
}
async function login(request, env) {
  const body = await request.json().catch(() => ({})), loginCode = code(body.login), password = String(body.password || ''), companyId = code(body.companyId || '');
  if (!loginCode || password.length < 6) return reply(request, { ok: false, error: 'Informe empresa, usuário e senha.' }, 401);
  const user = await env.DB.prepare(`SELECT u.*,c.name AS company_name FROM radar_users u LEFT JOIN radar_companies c ON c.id=u.company_id
    WHERE u.login=? AND u.active=1`).bind(loginCode).first();
  if (!user || (user.company_id && user.company_id !== companyId)) return reply(request, { ok: false, error: 'Empresa, usuário ou senha inválidos.' }, 401);
  const isInitialAdmin = user.login === 'THYAGO' && user.role === 'fico_admin' && Boolean(env.RADAR_ADMIN_PASSWORD) && password === env.RADAR_ADMIN_PASSWORD;
  const validHash = user.password_salt && await sha256(`${user.password_salt}:${password}`) === user.password_hash;
  if (!isInitialAdmin && !validHash) return reply(request, { ok: false, error: 'Empresa, usuário ou senha inválidos.' }, 401);
  const token = random(), expiresAt = new Date(Date.now() + 12 * 3600000).toISOString();
  await env.DB.prepare('INSERT INTO radar_sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').bind(await sha256(token), user.id, expiresAt).run();
  return reply(request, { ok: true, token, expiresAt, user: publicUser(user) });
}
async function logout(request, env) { const bearer = request.headers.get('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1]; if (bearer) await env.DB.prepare('DELETE FROM radar_sessions WHERE token_hash=?').bind(await sha256(bearer)).run(); return reply(request, { ok: true }); }

function effectiveStatus(row, at = Date.now()) {
  if (!['scheduled', 'active'].includes(row.status)) return row.status;
  if (at > Date.parse(row.planned_end) + 30 * 60000) return 'awaiting_definition';
  if (at >= Date.parse(row.planned_start)) return 'active';
  return 'scheduled';
}
function group(rows, key, mapper) { const out = {}; for (const row of rows || []) (out[row[key]] ||= []).push(mapper(row)); return out; }
async function frontData(env, { from, to, companyId = null, includeAudit = false, limit = 5000 }) {
  const companyClause = companyId ? ' AND f.company_id=?' : '', bindings = [to, from, ...(companyId ? [companyId] : [])];
  const [fronts, activities, segments, equipment, risks, checkins, events] = await env.DB.batch([
    env.DB.prepare(`SELECT f.*,c.name AS company_name,c.icon_code,d.name AS discipline_name,a.name AS catalog_activity,
      i.name AS inspector_name,cu.name AS created_by_name,uu.name AS updated_by_name
      FROM radar_fronts f JOIN radar_companies c ON c.id=f.company_id JOIN radar_disciplines d ON d.id=f.discipline_id
      LEFT JOIN radar_activities a ON a.id=f.activity_id LEFT JOIN radar_users i ON i.id=f.inspector_user_id
      JOIN radar_users cu ON cu.id=f.created_by_user LEFT JOIN radar_users uu ON uu.id=f.updated_by_user
      WHERE f.planned_start<=? AND f.planned_end>=?${companyClause} ORDER BY f.planned_start DESC LIMIT ${Math.max(1, Math.min(10000, limit))}`).bind(to, from, ...(companyId ? [companyId] : [])),
    env.DB.prepare(`SELECT fa.* FROM radar_front_activities fa JOIN radar_fronts f ON f.id=fa.front_id
      WHERE f.planned_start<=? AND f.planned_end>=?${companyClause} ORDER BY fa.front_id,fa.sequence_order`).bind(...bindings),
    env.DB.prepare(`SELECT s.* FROM radar_front_segments s JOIN radar_fronts f ON f.id=s.front_id
      WHERE f.planned_start<=? AND f.planned_end>=?${companyClause} ORDER BY s.front_id,s.sequence_order`).bind(...bindings),
    env.DB.prepare(`SELECT e.* FROM radar_front_equipment e JOIN radar_fronts f ON f.id=e.front_id
      WHERE f.planned_start<=? AND f.planned_end>=?${companyClause} ORDER BY e.front_id,e.equipment_type`).bind(...bindings),
    env.DB.prepare(`SELECT fr.front_id,r.id AS risk_id,r.name FROM radar_front_risks fr JOIN radar_risks r ON r.id=fr.risk_id JOIN radar_fronts f ON f.id=fr.front_id
      WHERE f.planned_start<=? AND f.planned_end>=?${companyClause} ORDER BY fr.front_id,r.name`).bind(...bindings),
    env.DB.prepare(`SELECT ch.*,u.name AS inspector_name FROM radar_checkins ch JOIN radar_users u ON u.id=ch.inspector_user_id JOIN radar_fronts f ON f.id=ch.front_id
      WHERE f.planned_start<=? AND f.planned_end>=?${companyClause} ORDER BY ch.captured_at DESC LIMIT 10000`).bind(...bindings),
    includeAudit ? env.DB.prepare(`SELECT e.*,u.name AS user_name FROM radar_front_events e JOIN radar_users u ON u.id=e.user_id JOIN radar_fronts f ON f.id=e.front_id
      WHERE f.planned_start<=? AND f.planned_end>=?${companyClause} ORDER BY e.occurred_at DESC LIMIT 10000`).bind(...bindings) : env.DB.prepare('SELECT NULL AS id WHERE 0')
  ]);
  const byActivity = group(activities.results, 'front_id', (r) => ({ id: r.activity_id || null, name: r.activity_name }));
  const bySegment = group(segments.results, 'front_id', (r) => ({ id: r.id, kmStart: Number(r.km_start), kmEnd: Number(r.km_end) }));
  const byEquipment = group(equipment.results, 'front_id', (r) => ({ id: r.id, type: r.equipment_type, quantity: Number(r.quantity) }));
  const byRisk = group(risks.results, 'front_id', (r) => ({ id: r.risk_id, name: r.name }));
  const byCheckin = group(checkins.results, 'front_id', (r) => ({ ...r, foundEquipment: safeJson(r.found_equipment_json, []), foundRisks: safeJson(r.found_risks_json, []), corrections: safeJson(r.corrections_json, {}) }));
  const byEvent = group(events.results, 'front_id', (r) => ({ ...r, payload: safeJson(r.payload_json, {}) }));
  return (fronts.results || []).map((r) => { const frontActivities = byActivity[r.id] || [{ id: r.activity_id || null, name: r.activity_name }]; return { ...r, activity_name: frontActivities.map((x) => x.name).join(' + '), activities: frontActivities, effectiveStatus: effectiveStatus(r), segments: bySegment[r.id] || [], equipment: byEquipment[r.id] || [], risks: byRisk[r.id] || [], checkins: byCheckin[r.id] || [], events: byEvent[r.id] || [] }; });
}

async function catalogs(env, user = null) {
  const [companies, disciplines, activities, risks, inspectors, people] = await env.DB.batch([
    env.DB.prepare('SELECT id,name,icon_code,active FROM radar_companies WHERE active=1 ORDER BY name'),
    env.DB.prepare('SELECT id,name FROM radar_disciplines WHERE active=1 ORDER BY name'),
    env.DB.prepare('SELECT id,name,approved FROM radar_activities WHERE active=1 AND approved=1 ORDER BY name'),
    env.DB.prepare('SELECT id,name FROM radar_risks WHERE active=1 ORDER BY name'),
    env.DB.prepare("SELECT id,name,phone FROM radar_users WHERE role IN ('fico_admin','fico_inspector') AND active=1 ORDER BY name"),
    user?.company_id ? env.DB.prepare('SELECT id,name,kind,phone FROM radar_people WHERE company_id=? AND active=1 ORDER BY kind,name').bind(user.company_id) : env.DB.prepare('SELECT id,name,kind,phone,company_id FROM radar_people WHERE active=1 ORDER BY company_id,kind,name')
  ]);
  return { companies: companies.results, disciplines: disciplines.results, activities: activities.results, risks: risks.results, inspectors: inspectors.results, people: people.results };
}
async function publicState(request, env) {
  const url = new URL(request.url), from = iso(url.searchParams.get('from')) || new Date(Date.now() - 86400000).toISOString(), to = iso(url.searchParams.get('to')) || new Date(Date.now() + 86400000).toISOString();
  const fronts = await frontData(env, { from, to, limit: 2000 });
  return reply(request, { ok: true, serverTime: now(), fronts: fronts.map((f) => ({ id: f.id, permanent_code: f.permanent_code, company_id: f.company_id, company_name: f.company_name, icon_code: f.icon_code, manager_name: f.manager_name, discipline_name: f.discipline_name, activity_name: f.activity_name, activities: f.activities, ldl_requirement: f.ldl_requirement, workforce_count: f.workforce_count, risk_level: f.risk_level, planned_start: f.planned_start, planned_end: f.planned_end, status: f.status, effectiveStatus: f.effectiveStatus, verified: f.checkins.length > 0, segments: f.segments, equipment: f.equipment, risks: f.risks })) });
}
async function state(request, env, user) {
  const url = new URL(request.url), from = iso(url.searchParams.get('from')) || new Date(Date.now() - 31 * 86400000).toISOString(), to = iso(url.searchParams.get('to')) || new Date(Date.now() + 31 * 86400000).toISOString();
  const companyId = ALL_SEE_ROLES.has(user.role) ? null : user.company_id;
  return reply(request, { ok: true, serverTime: now(), user: publicUser(user), catalogs: await catalogs(env, user), fronts: await frontData(env, { from, to, companyId, includeAudit: true }) });
}

function normalizeSegments(value) {
  if (!Array.isArray(value) || !value.length || value.length > 20) return { error: 'Informe de 1 a 20 trechos da frente.' };
  const items = value.map((x) => ({ kmStart: num(x.kmStart), kmEnd: num(x.kmEnd) }));
  if (items.some((x) => x.kmStart === null || x.kmEnd === null || x.kmStart < 0 || x.kmEnd > 292000 || x.kmStart > x.kmEnd)) return { error: 'Revise os trechos. Os KMs devem estar entre 0+000 e 292+000.' };
  return { items };
}
function normalizeEquipment(value) {
  if (!Array.isArray(value) || value.length > 30) return { error: 'Informe uma lista válida de equipamentos.' };
  const items = value.map((x) => ({ type: clean(x.type, 80), quantity: Math.round(num(x.quantity) || 0) })).filter((x) => x.type || x.quantity);
  if (items.some((x) => x.type.length < 2 || x.quantity < 1 || x.quantity > 999)) return { error: 'Revise tipo e quantidade dos equipamentos.' };
  return { items };
}
function normalizeActivities(value, legacyName = '') {
  const source = Array.isArray(value) && value.length ? value : (legacyName ? [{ name: legacyName }] : []);
  if (!source.length || source.length > 12) return { error: 'Informe de 1 a 12 atividades.' };
  const seen = new Set(), items = [];
  for (const entry of source) {
    const name = clean(typeof entry === 'string' ? entry : entry?.name, 120), id = code(typeof entry === 'object' ? entry?.id || '' : '');
    const key = name.toLocaleLowerCase('pt-BR');
    if (name.length < 3) return { error: 'Revise as atividades. Cada atividade deve ter ao menos 3 caracteres.' };
    if (!seen.has(key)) { seen.add(key); items.push({ id, name }); }
  }
  return { items };
}
function normalizeLdlRequirement(value) {
  const normalized = clean(value, 20);
  return ['required', 'not_required'].includes(normalized) ? normalized : null;
}
async function validateFrontBody(env, body, user, existing = null) {
  const companyId = FICO_ROLES.has(user.role) ? code(body.companyId || existing?.company_id) : user.company_id;
  const segments = normalizeSegments(body.segments), equipment = normalizeEquipment(body.equipment), activities = normalizeActivities(body.activities, body.activityName);
  const riskIds = [...new Set((Array.isArray(body.riskIds) ? body.riskIds : []).map((x) => code(x)).filter(Boolean))];
  const start = iso(body.start), end = iso(body.end), workforce = Math.round(num(body.workforceCount) || 0), riskLevel = clean(body.riskLevel, 12), ldlRequirement = normalizeLdlRequirement(body.ldlRequirement);
  const disciplineId = code(body.disciplineId), managerName = clean(body.managerName, 100), managerPhone = clean(body.managerPhone, 30);
  if (!companyId || !disciplineId || activities.error || managerName.length < 3 || managerPhone.length < 8) return { error: activities.error || 'Preencha empresa, disciplina, atividade, responsável e telefone.' };
  if (!start || !end || Date.parse(start) >= Date.parse(end)) return { error: 'O período da atividade é inválido.' };
  if (workforce < 1 || workforce > 5000 || !['low', 'moderate', 'high', 'critical'].includes(riskLevel)) return { error: 'Revise efetivo e nível de risco.' };
  if (!ldlRequirement) return { error: 'Informe obrigatoriamente se a frente necessita ou não de LDL.' };
  if (segments.error || equipment.error) return { error: segments.error || equipment.error };
  if (!riskIds.length) return { error: 'Selecione ao menos um risco crítico aplicável.' };
  const [company, discipline, riskCount] = await Promise.all([
    env.DB.prepare('SELECT id FROM radar_companies WHERE id=? AND active=1').bind(companyId).first(),
    env.DB.prepare('SELECT id FROM radar_disciplines WHERE id=? AND active=1').bind(disciplineId).first(),
    env.DB.prepare(`SELECT COUNT(*) AS total FROM radar_risks WHERE active=1 AND id IN (${riskIds.map(() => '?').join(',')})`).bind(...riskIds).first()
  ]);
  if (!company || !discipline || Number(riskCount?.total) !== riskIds.length) return { error: 'Empresa, disciplina ou riscos inválidos.' };
  const catalogRows = (await env.DB.prepare('SELECT id,name FROM radar_activities WHERE active=1').all()).results || [];
  const catalogById = new Map(catalogRows.map((x) => [x.id, x])), catalogByName = new Map(catalogRows.map((x) => [x.name.toLocaleLowerCase('pt-BR'), x]));
  const resolvedActivities = activities.items.map((x) => { const match = (x.id && catalogById.get(x.id)) || catalogByName.get(x.name.toLocaleLowerCase('pt-BR')); return { id: match?.id || null, name: match?.name || x.name }; });
  if (activities.items.some((x) => x.id && !catalogById.has(x.id))) return { error: 'Uma das atividades selecionadas não existe mais no catálogo.' };
  const activityName = resolvedActivities.map((x) => x.name).join(' + ');
  return { data: { companyId, disciplineId, activityId: resolvedActivities[0].id, activityName, activities: resolvedActivities, ldlRequirement, description: clean(body.description, 500), subcontractor: clean(body.subcontractor, 100), managerName, managerPhone, safetyTechnician: clean(body.safetyTechnician, 100), inspectorUserId: clean(body.inspectorUserId, 80) || null, workforce, riskLevel, start, end, segments: segments.items, equipment: equipment.items, riskIds } };
}
async function replaceChildren(env, frontId, data) {
  const statements = [env.DB.prepare('DELETE FROM radar_front_activities WHERE front_id=?').bind(frontId), env.DB.prepare('DELETE FROM radar_front_segments WHERE front_id=?').bind(frontId), env.DB.prepare('DELETE FROM radar_front_equipment WHERE front_id=?').bind(frontId), env.DB.prepare('DELETE FROM radar_front_risks WHERE front_id=?').bind(frontId)];
  data.activities.forEach((x, i) => statements.push(env.DB.prepare('INSERT INTO radar_front_activities (front_id,activity_id,activity_name,sequence_order) VALUES (?,?,?,?)').bind(frontId, x.id, x.name, i)));
  data.segments.forEach((x, i) => statements.push(env.DB.prepare('INSERT INTO radar_front_segments (id,front_id,sequence_order,km_start,km_end) VALUES (?,?,?,?,?)').bind(uuid(), frontId, i, x.kmStart, x.kmEnd)));
  data.equipment.forEach((x) => statements.push(env.DB.prepare('INSERT INTO radar_front_equipment (id,front_id,equipment_type,quantity) VALUES (?,?,?,?)').bind(uuid(), frontId, x.type, x.quantity)));
  data.riskIds.forEach((id) => statements.push(env.DB.prepare('INSERT INTO radar_front_risks (front_id,risk_id) VALUES (?,?)').bind(frontId, id)));
  await env.DB.batch(statements);
}
async function createFront(request, env, user) {
  if (!EDIT_ROLES.has(user.role)) return reply(request, { ok: false, error: 'Seu perfil não pode cadastrar frentes.' }, 403);
  const body = await request.json().catch(() => ({})), valid = await validateFrontBody(env, body, user);
  if (valid.error) return reply(request, { ok: false, error: valid.error }, 400);
  const d = valid.data, id = uuid(), sequence = Number((await env.DB.prepare('SELECT COALESCE(MAX(sequence_number),0)+1 AS next FROM radar_fronts').first()).next), permanentCode = `RAD-${String(sequence).padStart(5, '0')}`, time = now(), revisionToken = random(12);
  await env.DB.prepare(`INSERT INTO radar_fronts (id,sequence_number,permanent_code,company_id,subcontractor,manager_name,manager_phone,safety_technician,inspector_user_id,discipline_id,activity_id,activity_name,ldl_requirement,description,workforce_count,risk_level,planned_start,planned_end,status,created_by_user,created_at,revision_token)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'scheduled',?,?,?)`).bind(id, sequence, permanentCode, d.companyId, d.subcontractor || null, d.managerName, d.managerPhone, d.safetyTechnician || null, d.inspectorUserId, d.disciplineId, d.activityId, d.activityName, d.ldlRequirement, d.description || null, d.workforce, d.riskLevel, d.start, d.end, user.id, time, revisionToken).run();
  await replaceChildren(env, id, d);
  await env.DB.prepare('INSERT INTO radar_front_events (id,front_id,event_type,user_id,occurred_at,payload_json) VALUES (?,?,?,?,?,?)').bind(uuid(), id, 'created', user.id, time, JSON.stringify({ after: d })).run();
  return reply(request, { ok: true, front: { id, permanentCode } });
}
async function updateFront(request, env, user) {
  const body = await request.json().catch(() => ({})), id = clean(body.id, 80), reason = clean(body.reason, 500);
  const current = await env.DB.prepare('SELECT * FROM radar_fronts WHERE id=?').bind(id).first();
  if (!current) return reply(request, { ok: false, error: 'Frente não encontrada.' }, 404);
  const canEdit = FICO_ROLES.has(user.role) || (EDIT_ROLES.has(user.role) && user.company_id === current.company_id);
  if (!canEdit) return reply(request, { ok: false, error: 'Você não pode alterar esta frente.' }, 403);
  if (reason.length < 5) return reply(request, { ok: false, error: 'Informe a justificativa da alteração.' }, 400);
  if (Number(body.expectedRevision) !== Number(current.revision)) return reply(request, { ok: false, error: 'A frente foi alterada por outro usuário. Atualize antes de continuar.' }, 409);
  const valid = await validateFrontBody(env, body, user, current); if (valid.error) return reply(request, { ok: false, error: valid.error }, 400);
  const beforeData = await frontData(env, { from: current.planned_start, to: current.planned_end, companyId: current.company_id, includeAudit: false });
  const d = valid.data, revision = Number(current.revision) + 1, time = now(), revisionToken = random(12);
  await env.DB.prepare(`UPDATE radar_fronts SET company_id=?,subcontractor=?,manager_name=?,manager_phone=?,safety_technician=?,inspector_user_id=?,discipline_id=?,activity_id=?,activity_name=?,ldl_requirement=?,description=?,workforce_count=?,risk_level=?,planned_start=?,planned_end=?,updated_by_user=?,updated_at=?,revision=?,revision_token=? WHERE id=? AND revision=?`)
    .bind(d.companyId, d.subcontractor || null, d.managerName, d.managerPhone, d.safetyTechnician || null, d.inspectorUserId, d.disciplineId, d.activityId, d.activityName, d.ldlRequirement, d.description || null, d.workforce, d.riskLevel, d.start, d.end, user.id, time, revision, revisionToken, id, current.revision).run();
  await replaceChildren(env, id, d);
  await env.DB.prepare('INSERT INTO radar_front_events (id,front_id,event_type,user_id,occurred_at,payload_json) VALUES (?,?,?,?,?,?)').bind(uuid(), id, FICO_ROLES.has(user.role) ? 'corrected_by_fico' : 'updated', user.id, time, JSON.stringify({ reason, before: beforeData.find((x) => x.id === id), after: d, revision })).run();
  return reply(request, { ok: true, front: { id, revision } });
}
async function actionFront(request, env, user) {
  const body = await request.json().catch(() => ({})), id = clean(body.id, 80), action = clean(body.action, 30), note = clean(body.note, 500), current = await env.DB.prepare('SELECT * FROM radar_fronts WHERE id=?').bind(id).first();
  if (!current) return reply(request, { ok: false, error: 'Frente não encontrada.' }, 404);
  const companyOwns = EDIT_ROLES.has(user.role) && user.company_id === current.company_id, inspector = INSPECT_ROLES.has(user.role);
  const map = { close: 'closed', cancel: 'cancelled', pause: 'paused', resume: 'active', stop: 'stopped', not_located: 'not_located' }, status = map[action];
  if (!status || (['stop', 'not_located'].includes(action) && !inspector) || (!['stop', 'not_located'].includes(action) && !companyOwns && !inspector)) return reply(request, { ok: false, error: 'Ação não autorizada.' }, 403);
  if (note.length < 5) return reply(request, { ok: false, error: 'Informe uma justificativa com pelo menos 5 caracteres.' }, 400);
  const time = now();
  await env.DB.prepare(`UPDATE radar_fronts SET status=?,updated_by_user=?,updated_at=?,closed_by_user=?,closed_at=?,close_note=?,revision=revision+1,revision_token=? WHERE id=?`).bind(status, user.id, time, ['closed', 'cancelled'].includes(status) ? user.id : null, ['closed', 'cancelled'].includes(status) ? time : null, note, random(12), id).run();
  await env.DB.prepare('INSERT INTO radar_front_events (id,front_id,event_type,user_id,occurred_at,payload_json) VALUES (?,?,?,?,?,?)').bind(uuid(), id, action, user.id, time, JSON.stringify({ note, beforeStatus: current.status, afterStatus: status })).run();
  return reply(request, { ok: true, status });
}

async function checkin(request, env, user) {
  if (!INSPECT_ROLES.has(user.role)) return reply(request, { ok: false, error: 'Somente a fiscalização FICO pode registrar check-in.' }, 403);
  const body = await request.json().catch(() => ({})), clientId = clean(body.clientId, 80), frontId = clean(body.frontId, 80), capturedAt = iso(body.capturedAt), latitude = num(body.latitude), longitude = num(body.longitude), accuracy = num(body.accuracyM), distance = num(body.distanceToFrontM), result = clean(body.result, 30), comment = clean(body.comment, 1000), outside = distance !== null && distance > 500, distanceJustification = clean(body.distanceJustification, 500);
  if (!clientId || !frontId || !capturedAt || latitude === null || longitude === null || !['conforming', 'divergence', 'not_located', 'not_started', 'different_activity', 'stopped'].includes(result)) return reply(request, { ok: false, error: 'Check-in incompleto ou inválido.' }, 400);
  if (outside && distanceJustification.length < 5) return reply(request, { ok: false, error: 'O GPS está a mais de 500 m. Informe a justificativa para continuar.' }, 400);
  const front = await env.DB.prepare('SELECT id,workforce_count FROM radar_fronts WHERE id=?').bind(frontId).first(); if (!front) return reply(request, { ok: false, error: 'Frente não encontrada.' }, 404);
  const foundWorkforce = body.foundWorkforce === '' || body.foundWorkforce === null ? null : Math.round(num(body.foundWorkforce) || 0), corrections = body.corrections && typeof body.corrections === 'object' ? body.corrections : {};
  await env.DB.prepare(`INSERT OR IGNORE INTO radar_checkins (id,client_id,front_id,inspector_user_id,result,captured_at,latitude,longitude,accuracy_m,distance_to_front_m,outside_tolerance,distance_justification,found_workforce,found_equipment_json,found_risks_json,comment,corrections_json)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(uuid(), clientId, frontId, user.id, result, capturedAt, latitude, longitude, accuracy, distance, outside ? 1 : 0, distanceJustification || null, foundWorkforce, JSON.stringify(body.foundEquipment || []), JSON.stringify(body.foundRisks || []), comment || null, JSON.stringify(corrections)).run();
  if (result !== 'conforming') await env.DB.prepare('INSERT INTO radar_front_events (id,front_id,event_type,user_id,occurred_at,payload_json) VALUES (?,?,?,?,?,?)').bind(uuid(), frontId, 'inspection_divergence', user.id, capturedAt, JSON.stringify({ result, comment, foundWorkforce, foundEquipment: body.foundEquipment || [], foundRisks: body.foundRisks || [], outsideTolerance: outside, corrections })).run();
  if (result === 'stopped') await env.DB.prepare("UPDATE radar_fronts SET status='stopped',updated_by_user=?,updated_at=?,revision=revision+1,revision_token=? WHERE id=?").bind(user.id, now(), random(12), frontId).run();
  return reply(request, { ok: true, clientId, syncedAt: now() });
}

async function adminList(request, env, user) {
  if (!['fico_admin', 'company_admin'].includes(user.role)) return reply(request, { ok: false, error: 'Acesso administrativo necessário.' }, 403);
  const companyClause = user.role === 'company_admin' ? ' WHERE u.company_id=?' : '', users = await (user.role === 'company_admin' ? env.DB.prepare(`SELECT u.id,u.company_id,c.name AS company_name,u.login,u.name,u.role,u.phone,u.active,u.created_at,u.updated_at FROM radar_users u LEFT JOIN radar_companies c ON c.id=u.company_id${companyClause} ORDER BY u.active DESC,u.name`).bind(user.company_id).all() : env.DB.prepare('SELECT u.id,u.company_id,c.name AS company_name,u.login,u.name,u.role,u.phone,u.active,u.created_at,u.updated_at FROM radar_users u LEFT JOIN radar_companies c ON c.id=u.company_id ORDER BY u.active DESC,u.name').all());
  const pendingActivities = user.role === 'fico_admin' ? (await env.DB.prepare('SELECT id,name,created_at FROM radar_activities WHERE active=1 AND approved=0 ORDER BY created_at').all()).results : [];
  return reply(request, { ok: true, user: publicUser(user), catalogs: await catalogs(env, user), users: users.results, pendingActivities });
}
async function adminSaveUser(request, env, user) {
  if (!['fico_admin', 'company_admin'].includes(user.role)) return reply(request, { ok: false, error: 'Acesso administrativo necessário.' }, 403);
  const body = await request.json().catch(() => ({})), id = clean(body.id, 80) || uuid(), loginCode = code(body.login), name = clean(body.name, 100), role = clean(body.role, 30), phone = clean(body.phone, 30), password = String(body.password || ''), companyId = user.role === 'company_admin' ? user.company_id : (code(body.companyId || '') || null);
  const allowedRoles = user.role === 'company_admin' ? ['company_admin', 'front_manager', 'viewer'] : ['fico_admin', 'fico_inspector', 'company_admin', 'front_manager', 'viewer'];
  if (!loginCode || name.length < 3 || !allowedRoles.includes(role) || !validUserCompany(role, companyId)) return reply(request, { ok: false, error: 'Selecione obrigatoriamente a contratada para perfis da empresa. Perfis FICO não podem ser vinculados a contratadas.' }, 400);
  if (companyId && !await env.DB.prepare('SELECT id FROM radar_companies WHERE id=? AND active=1').bind(companyId).first()) return reply(request, { ok: false, error: 'A contratada selecionada não existe ou está inativa.' }, 400);
  const existing = await env.DB.prepare('SELECT id,company_id FROM radar_users WHERE id=?').bind(id).first();
  if (existing && user.role === 'company_admin' && existing.company_id !== user.company_id) return reply(request, { ok: false, error: 'Você não pode editar este usuário.' }, 403);
  if (!existing && password.length < 8) return reply(request, { ok: false, error: 'A senha inicial deve ter pelo menos 8 caracteres.' }, 400);
  let salt = null, hash = null; if (password) { salt = random(12); hash = await sha256(`${salt}:${password}`); }
  if (existing) await env.DB.prepare(`UPDATE radar_users SET company_id=?,login=?,name=?,role=?,phone=?,password_salt=COALESCE(?,password_salt),password_hash=COALESCE(?,password_hash),updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(companyId, loginCode, name, role, phone || null, salt, hash, id).run();
  else await env.DB.prepare('INSERT INTO radar_users (id,company_id,login,name,role,phone,password_salt,password_hash) VALUES (?,?,?,?,?,?,?,?)').bind(id, companyId, loginCode, name, role, phone || null, salt, hash).run();
  return reply(request, { ok: true, id });
}
async function adminStatusUser(request, env, user) {
  if (!['fico_admin', 'company_admin'].includes(user.role)) return reply(request, { ok: false, error: 'Acesso administrativo necessário.' }, 403);
  const body = await request.json().catch(() => ({})), target = await env.DB.prepare('SELECT id,company_id FROM radar_users WHERE id=?').bind(clean(body.id, 80)).first();
  if (!target || (user.role === 'company_admin' && target.company_id !== user.company_id) || target.id === user.id) return reply(request, { ok: false, error: 'Usuário inválido para esta ação.' }, 400);
  await env.DB.prepare('UPDATE radar_users SET active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(body.active ? 1 : 0, target.id).run(); if (!body.active) await env.DB.prepare('DELETE FROM radar_sessions WHERE user_id=?').bind(target.id).run();
  return reply(request, { ok: true });
}
async function adminSaveCatalog(request, env, user) {
  if (!['fico_admin', 'company_admin'].includes(user.role)) return reply(request, { ok: false, error: 'Acesso administrativo necessário.' }, 403);
  const body = await request.json().catch(() => ({})), kind = clean(body.kind, 20), name = clean(body.name, 100), id = code(body.id || name.normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^A-Za-z0-9]+/g, '-'));
  if (!id || name.length < 3) return reply(request, { ok: false, error: 'Informe um nome válido.' }, 400);
  if (kind === 'activity') await env.DB.prepare(`INSERT INTO radar_activities (id,name,approved,suggested_by_user) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,active=1`).bind(id, name, user.role === 'fico_admin' ? 1 : 0, user.id).run();
  else if (kind === 'risk' && user.role === 'fico_admin') await env.DB.prepare('INSERT INTO radar_risks (id,name) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,active=1').bind(id, name).run();
  else return reply(request, { ok: false, error: kind === 'risk' ? 'Somente a administração FICO cadastra riscos.' : 'Catálogo inválido.' }, 403);
  return reply(request, { ok: true, id, pendingApproval: kind === 'activity' && user.role !== 'fico_admin' });
}
async function adminApproveActivity(request, env, user) {
  if (user.role !== 'fico_admin') return reply(request, { ok: false, error: 'Somente a administração FICO aprova atividades.' }, 403);
  const body = await request.json().catch(() => ({})), id = code(body.id);
  const row = id && await env.DB.prepare('SELECT id FROM radar_activities WHERE id=? AND active=1').bind(id).first();
  if (!row) return reply(request, { ok: false, error: 'Atividade não encontrada.' }, 404);
  await env.DB.prepare('UPDATE radar_activities SET approved=1 WHERE id=?').bind(id).run();
  return reply(request, { ok: true, id });
}
async function adminSavePerson(request, env, user) {
  if (!['fico_admin', 'company_admin'].includes(user.role)) return reply(request, { ok: false, error: 'Acesso administrativo necessário.' }, 403);
  const body = await request.json().catch(() => ({})), companyId = user.role === 'company_admin' ? user.company_id : code(body.companyId), id = clean(body.id, 80) || uuid(), name = clean(body.name, 100), kind = clean(body.kind, 30), phone = clean(body.phone, 30);
  if (!companyId || name.length < 3 || !['manager', 'safety_technician', 'subcontractor'].includes(kind)) return reply(request, { ok: false, error: 'Revise empresa, nome e tipo de cadastro.' }, 400);
  await env.DB.prepare(`INSERT INTO radar_people (id,company_id,name,kind,phone) VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,phone=excluded.phone,updated_at=CURRENT_TIMESTAMP`).bind(id, companyId, name, kind, phone || null).run();
  return reply(request, { ok: true, id });
}

async function history(request, env, user) {
  const url = new URL(request.url), from = iso(url.searchParams.get('from')) || new Date(Date.now() - 90 * 86400000).toISOString(), to = iso(url.searchParams.get('to')) || now();
  if (Date.parse(to) - Date.parse(from) > 91 * 86400000) return reply(request, { ok: false, error: 'O histórico permite consultar até 90 dias por vez.' }, 400);
  const companyId = ALL_SEE_ROLES.has(user.role) ? null : user.company_id;
  return reply(request, { ok: true, serverTime: now(), user: publicUser(user), fronts: await frontData(env, { from, to, companyId, includeAudit: true, limit: 10000 }) });
}

async function publicCcoOperations(request, env) {
  try {
    const ldls = await env.DB.prepare(`SELECT l.id,l.permanent_code,l.km_start,l.km_end,l.work_description,l.requested_start,l.requested_end,r.name AS requester_name,r.company
      FROM ldl l JOIN requesters r ON r.code=l.requester_code WHERE l.status='active' ORDER BY l.km_start,l.created_at`).all();
    const ldlLines = await env.DB.prepare(`SELECT ll.ldl_id,ll.line_id FROM ldl_lines ll JOIN ldl l ON l.id=ll.ldl_id WHERE l.status='active'`).all();
    const circulations = await env.DB.prepare(`SELECT c.id,c.permanent_code,c.km_start,c.km_end,c.line_id,c.direction,c.planned_start,c.planned_end,e.name AS equipment_name
      FROM circulations c JOIN equipment e ON e.id=c.equipment_id WHERE c.status='authorized' ORDER BY c.km_start,c.authorized_at`).all();
    const linesByLdl = {};
    for (const row of ldlLines.results || []) (linesByLdl[row.ldl_id] ||= []).push(row.line_id);
    return reply(request, {
      ok: true, updatedAt: now(), refreshSeconds: 15,
      ldls: (ldls.results || []).map((item) => ({ ...item, lines: linesByLdl[item.id] || [] })),
      circulations: circulations.results || []
    });
  } catch {
    return reply(request, { ok: false, error: 'Dados operacionais CCO indisponíveis.' }, 502);
  }
}

function weatherReply(request, body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...HEADERS, ...cors(request), 'cache-control': 'public, max-age=900' } });
}
function forecastGrid() {
  const points = [], step = 0.12;
  for (let lat = -14.62; lat <= -13.86; lat += step) for (let lng = -51.62; lng <= -49.02; lng += step) points.push([Number(lat.toFixed(3)), Number(lng.toFixed(3))]);
  return { step, points };
}
async function weatherForecast(request) {
  const hourBucket = Math.floor(Date.now() / (15 * 60 * 1000));
  const cacheKey = new Request(`https://radarfico-weather-cache.local/today/${hourBucket}`);
  const cached = await caches.default.match(cacheKey); if (cached) return cached;
  try {
    const { step, points } = forecastGrid(), latitude = points.map((p) => p[0]).join(','), longitude = points.map((p) => p[1]).join(',');
    const upstream = await fetch(`https://api.open-meteo.com/v1/ecmwf?latitude=${latitude}&longitude=${longitude}&hourly=precipitation&forecast_days=1&timezone=America%2FFortaleza`);
    if (!upstream.ok) throw new Error('forecast upstream');
    const rows = await upstream.json(), list = Array.isArray(rows) ? rows : [rows], first = list[0]?.hourly || {};
    const body = { ok: true, provider: 'ECMWF IFS HRES via Open-Meteo', updatedAt: now(), refreshSeconds: 900, step, times: first.time || [], points: list.map((row) => ({ latitude: row.latitude, longitude: row.longitude, precipitation: row.hourly?.precipitation || [] })) };
    const response = weatherReply(request, body); await caches.default.put(cacheKey, response.clone()); return response;
  } catch {
    return reply(request, { ok: false, error: 'Previsão de chuva indisponível no momento.' }, 502);
  }
}

export async function routeRadar(request, env) {
  const path = new URL(request.url).pathname;
  if (!path.startsWith('/api/v1/radar/') && !path.startsWith('/api/v2/admin/radar/')) return null;
  if (request.method === 'POST' && path === '/api/v1/radar/login') return login(request, env);
  if (request.method === 'GET' && path === '/api/v1/radar/public/state') return publicState(request, env);
  if (request.method === 'GET' && path === '/api/v1/radar/public/cco-operations') return publicCcoOperations(request, env);
  if (request.method === 'GET' && path === '/api/v1/radar/public/weather-forecast') return weatherForecast(request);
  const user = await authenticate(request, env); if (!user) return reply(request, { ok: false, error: 'Sessão do Radar FICO inválida ou expirada.' }, 401);
  if (request.method === 'POST' && path === '/api/v1/radar/logout') return logout(request, env);
  if (request.method === 'GET' && path === '/api/v1/radar/state') return state(request, env, user);
  if (request.method === 'GET' && path === '/api/v1/radar/history') return history(request, env, user);
  if (request.method === 'POST' && path === '/api/v1/radar/front/create') return createFront(request, env, user);
  if (request.method === 'POST' && path === '/api/v1/radar/front/update') return updateFront(request, env, user);
  if (request.method === 'POST' && path === '/api/v1/radar/front/action') return actionFront(request, env, user);
  if (request.method === 'POST' && path === '/api/v1/radar/checkin') return checkin(request, env, user);
  if (request.method === 'GET' && path === '/api/v2/admin/radar/state') return adminList(request, env, user);
  if (request.method === 'POST' && path === '/api/v2/admin/radar/user/save') return adminSaveUser(request, env, user);
  if (request.method === 'POST' && path === '/api/v2/admin/radar/user/status') return adminStatusUser(request, env, user);
  if (request.method === 'POST' && path === '/api/v2/admin/radar/catalog/save') return adminSaveCatalog(request, env, user);
  if (request.method === 'POST' && path === '/api/v2/admin/radar/catalog/approve') return adminApproveActivity(request, env, user);
  if (request.method === 'POST' && path === '/api/v2/admin/radar/person/save') return adminSavePerson(request, env, user);
  return reply(request, { ok: false, error: 'Rota do Radar FICO não encontrada.' }, 404);
}
