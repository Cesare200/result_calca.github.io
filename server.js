'use strict';
// Servidor sin dependencias. Uso: node server.js
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';          // 0.0.0.0 para exponerlo en red
const SECURE = process.env.HTTPS === '1';              // 1 si está detrás de HTTPS (cookie Secure)
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const DATA = path.join(__dirname, 'data.json');
const CRED = path.join(__dirname, 'admin.json');
const AUDIT = path.join(__dirname, 'audit.log');
const HTML = path.join(__dirname, 'index.html');
const DIST = ['Calca (capital)', 'Coya', 'Lamay', 'Lares', 'Pisac', 'San Salvador', 'Taray', 'Yanatile'];
const NP = 10, MAXV = 10_000_000, SESSION_MS = 2 * 3600e3, MAX_FAILS = 5, LOCK_MS = 15 * 60e3;

/* ---------- archivos JSON (escritura atómica + respaldo) ---------- */
function writeJSON(f, o, mode) {
  const t = f + '.tmp';
  fs.writeFileSync(t, JSON.stringify(o, null, 2), mode ? { mode } : undefined);
  if (fs.existsSync(f) && f === DATA) fs.copyFileSync(f, f + '.bak');
  fs.renameSync(t, f);
}
function freshData() {
  const votes = {}; DIST.forEach(d => votes[d] = Array(NP).fill(0));
  return { version: 1, updatedAt: new Date().toISOString(), votes };
}
let db;
try { db = JSON.parse(fs.readFileSync(DATA, 'utf8')); } catch { db = freshData(); writeJSON(DATA, db); }
DIST.forEach(d => { if (!Array.isArray(db.votes[d]) || db.votes[d].length !== NP) db.votes[d] = Array(NP).fill(0); });

/* ---------- credenciales: scrypt + salt, nunca en texto plano ---------- */
const scrypt = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
function setCred(user, pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  writeJSON(CRED, { user, salt, hash: scrypt(pw, salt) }, 0o600);
}
if (!fs.existsSync(CRED)) {
  const pw = process.env.ADMIN_PASS || crypto.randomBytes(12).toString('base64url');
  const user = process.env.ADMIN_USER || 'admin';
  setCred(user, pw);
  console.log('\n=== PRIMER INICIO ===\nUsuario   : ' + user + '\nContraseña: ' + pw + '\n(se muestra una sola vez; cámbiala desde el panel)\n');
}
const readCred = () => JSON.parse(fs.readFileSync(CRED, 'utf8'));
const h256 = s => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(h256(a), h256(b));
function checkLogin(user, pass) {
  const c = readCred();
  const u = safeEq(user, c.user);
  const p = crypto.timingSafeEqual(Buffer.from(scrypt(String(pass), c.salt), 'hex'), Buffer.from(c.hash, 'hex'));
  return u && p;
}

/* ---------- sesiones, intentos y auditoría ---------- */
const sessions = new Map(), attempts = new Map();
setInterval(() => { const n = Date.now(); for (const [k, s] of sessions) if (s.exp < n) sessions.delete(k); }, 60e3).unref();
const ipOf = req => (TRUST_PROXY && req.headers['x-forwarded-for']?.split(',')[0].trim()) || req.socket.remoteAddress;
const audit = (req, msg) => fs.appendFile(AUDIT, `${new Date().toISOString()} ${ipOf(req)} ${msg}\n`, () => {});
function getSession(req) {
  const m = /(?:^|;\s*)sid=([\w-]+)/.exec(req.headers.cookie || '');
  const s = m && sessions.get(m[1]);
  if (!s || s.exp < Date.now()) return null;
  s.exp = Date.now() + SESSION_MS; s.id = m[1]; return s;
}
const cookie = (v, age) => `sid=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${SECURE ? '; Secure' : ''}`;

/* ---------- utilidades HTTP ---------- */
function headers(extra = {}, nonce = '') {
  return {
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin', 'Cache-Control': 'no-store',
    ...(SECURE ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}),
    'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; style-src-attr 'unsafe-inline'; img-src 'self' https://stovotoinformadodev.blob.core.windows.net data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    ...extra
  };
}
const send = (res, code, obj, extra) => { res.writeHead(code, headers({ 'Content-Type': 'application/json', ...extra })); res.end(JSON.stringify(obj)); };
function body(req) {
  return new Promise((ok, no) => {
    let n = 0, s = '';
    req.on('data', c => { n += c.length; if (n > 8192) { no(Object.assign(new Error('big'), { code: 413 })); req.destroy(); } else s += c; });
    req.on('end', () => { try { ok(s ? JSON.parse(s) : {}); } catch { no(Object.assign(new Error('json'), { code: 400 })); } });
  });
}
const wait = ms => new Promise(r => setTimeout(r, ms));

/* ---------- rutas ---------- */
http.createServer(async (req, res) => {
  try {
    const url = req.url.split('?')[0];
    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
      const nonce = crypto.randomBytes(16).toString('base64');
      const html = fs.readFileSync(HTML, 'utf8').replaceAll('__NONCE__', nonce);
      res.writeHead(200, headers({ 'Content-Type': 'text/html; charset=utf-8' }, nonce)); return res.end(html);
    }
    if (req.method === 'GET' && url === '/api/results')
      return send(res, 200, { version: db.version, updatedAt: db.updatedAt, votes: db.votes });
    const sess = getSession(req);
    if (req.method === 'GET' && url === '/api/session')
      return send(res, 200, sess ? { auth: true, csrf: sess.csrf } : { auth: false });

    if (req.method === 'POST' && url === '/api/login') {
      const ip = ipOf(req), a = attempts.get(ip) || { n: 0, until: 0 };
      if (a.until > Date.now()) return send(res, 429, { error: `Demasiados intentos. Reintenta en ${Math.ceil((a.until - Date.now()) / 60000)} min.` });
      const b = await body(req);
      if (checkLogin(b.user ?? '', b.pass ?? '')) {
        attempts.delete(ip);
        const id = crypto.randomBytes(32).toString('base64url'), csrf = crypto.randomBytes(24).toString('base64url');
        sessions.set(id, { csrf, exp: Date.now() + SESSION_MS });
        audit(req, 'login ok');
        return send(res, 200, { auth: true, csrf }, { 'Set-Cookie': cookie(id, SESSION_MS / 1000) });
      }
      if (++a.n >= MAX_FAILS) { a.n = 0; a.until = Date.now() + LOCK_MS; }
      attempts.set(ip, a); audit(req, 'login FAIL');
      await wait(600);
      return send(res, 401, { error: 'Usuario o contraseña incorrectos' });
    }

    if (!url.startsWith('/api/')) return send(res, 404, { error: 'No encontrado' });
    // Todo lo siguiente exige sesión + token CSRF
    if (!sess) return send(res, 401, { error: 'Sesión no válida' });
    if (req.headers['x-csrf'] !== sess.csrf) return send(res, 403, { error: 'CSRF inválido' });

    if (req.method === 'POST' && url === '/api/logout') {
      sessions.delete(sess.id); audit(req, 'logout');
      return send(res, 200, { ok: true }, { 'Set-Cookie': cookie('', 0) });
    }
    if (req.method === 'PUT' && url === '/api/votes') {
      const b = await body(req);
      if (!DIST.includes(b.district) || !Array.isArray(b.votes) || b.votes.length !== NP ||
          !b.votes.every(x => Number.isInteger(x) && x >= 0 && x <= MAXV))
        return send(res, 400, { error: 'Datos no válidos' });
      db.votes[b.district] = b.votes; db.version++; db.updatedAt = new Date().toISOString();
      writeJSON(DATA, db); audit(req, `votes ${b.district} [${b.votes}]`);
      return send(res, 200, { ok: true, version: db.version });
    }
    if (req.method === 'POST' && url === '/api/reset') {
      db = { ...freshData(), version: db.version + 1 }; writeJSON(DATA, db); audit(req, 'RESET');
      return send(res, 200, { ok: true, version: db.version });
    }
    if (req.method === 'POST' && url === '/api/password') {
      const b = await body(req), c = readCred();
      if (!checkLogin(c.user, b.current ?? '')) { await wait(600); return send(res, 400, { error: 'La contraseña actual no es correcta' }); }
      const n = String(b.next ?? '');
      if (n.length < 10 || n.length > 128 || /^(admin|password|12345)/i.test(n) || n === c.user)
        return send(res, 400, { error: 'La nueva contraseña debe tener al menos 10 caracteres y no ser trivial' });
      setCred(c.user, n);
      for (const k of sessions.keys()) if (k !== sess.id) sessions.delete(k);   // cierra otras sesiones
      audit(req, 'password changed');
      return send(res, 200, { ok: true });
    }
    send(res, 404, { error: 'No encontrado' });
  } catch (e) {
    send(res, e.code === 413 || e.code === 400 ? e.code : 500, { error: e.code ? 'Solicitud no válida' : 'Error interno' });
  }
}).listen(PORT, HOST, () => console.log(`Resultados Calca en http://${HOST}:${PORT}`));
