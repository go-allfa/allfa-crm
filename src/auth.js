'use strict';

const crypto = require('node:crypto');

const SESSION_COOKIE = 'crm_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const KEY_LEN = 64;

// ---------- Senhas (scrypt, embutido no Node) ----------

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, KEY_LEN, SCRYPT_PARAMS);
  return `scrypt$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(password, stored) {
  const [scheme, saltB64, hashB64] = String(stored).split('$');
  if (scheme !== 'scrypt' || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = crypto.scryptSync(password, Buffer.from(saltB64, 'base64'), expected.length, SCRYPT_PARAMS);
  return crypto.timingSafeEqual(expected, actual);
}

// Hash usado quando o e-mail não existe, para o tempo de resposta não revelar quais contas existem.
const DUMMY_HASH = hashPassword(crypto.randomBytes(16).toString('hex'));

function validatePasswordStrength(password) {
  if (typeof password !== 'string' || password.length < 10) return 'A senha precisa ter pelo menos 10 caracteres.';
  if (password.length > 200) return 'Senha muito longa.';
  return null;
}

// ---------- Sessões ----------

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

function createSession(db, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(32).toString('base64url');
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
  db.prepare('INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)')
    .run(sha256(token), userId, csrf, Date.now() + SESSION_TTL_MS);
  return token;
}

function destroySession(db, token) {
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
}

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    if (key) out[key] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function sessionCookie(token, { secure, maxAgeMs }) {
  const attrs = [
    `${SESSION_COOKIE}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
  ];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

// Carrega o usuário da sessão (se houver) em req.user / req.session.
function loadSession(db) {
  const stmt = db.prepare(`
    SELECT s.csrf_token, s.expires_at, u.id, u.email, u.name, u.is_admin
      FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND u.active = 1
  `);
  return (req, _res, next) => {
    const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    req.sessionToken = token;
    if (token) {
      const row = stmt.get(sha256(token));
      if (row && row.expires_at > Date.now()) {
        req.user = { id: row.id, email: row.email, name: row.name, isAdmin: !!row.is_admin };
        req.csrfToken = row.csrf_token;
      }
    }
    next();
  };
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Não autenticado.' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Acesso restrito a administradores.' });
  next();
}

// Toda requisição que altera dados precisa enviar o token CSRF da sessão no header.
function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const sent = req.get('x-csrf-token') || '';
  const expected = req.csrfToken || '';
  const ok = sent.length === expected.length && expected.length > 0 &&
    crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected));
  if (!ok) return res.status(403).json({ error: 'Token CSRF inválido. Recarregue a página.' });
  next();
}

// ---------- Limite de tentativas de login (em memória) ----------

function createLoginLimiter({ maxAttempts = 5, windowMs = 15 * 60 * 1000 } = {}) {
  const attempts = new Map();
  const keyFor = (ip, email) => `${ip}|${String(email).toLowerCase()}`;

  return {
    isBlocked(ip, email) {
      const entry = attempts.get(keyFor(ip, email));
      if (!entry) return false;
      if (Date.now() - entry.first > windowMs) {
        attempts.delete(keyFor(ip, email));
        return false;
      }
      return entry.count >= maxAttempts;
    },
    fail(ip, email) {
      const key = keyFor(ip, email);
      const entry = attempts.get(key);
      if (!entry || Date.now() - entry.first > windowMs) attempts.set(key, { count: 1, first: Date.now() });
      else entry.count += 1;
      if (attempts.size > 10000) attempts.clear(); // proteção simples contra crescimento ilimitado
    },
    reset(ip, email) {
      attempts.delete(keyFor(ip, email));
    },
  };
}

module.exports = {
  SESSION_COOKIE,
  SESSION_TTL_MS,
  DUMMY_HASH,
  hashPassword,
  verifyPassword,
  validatePasswordStrength,
  createSession,
  destroySession,
  sessionCookie,
  loadSession,
  requireAuth,
  requireAdmin,
  requireCsrf,
  createLoginLimiter,
};
