'use strict';

const path = require('node:path');
const express = require('express');
const { openDatabase } = require('./db');
const auth = require('./auth');
const { leadsRouter } = require('./leads');

function securityHeaders(secure) {
  return (_req, res, next) => {
    res.set({
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "object-src 'none'",
      ].join('; '),
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
    });
    if (secure) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  };
}

function createApp(db, { secureCookies = false, trustProxy = false } = {}) {
  const app = express();
  app.disable('x-powered-by');
  if (trustProxy) app.set('trust proxy', trustProxy);

  app.use(securityHeaders(secureCookies));
  app.use(express.json({ limit: '32kb' }));
  app.use(auth.loadSession(db));

  const limiter = auth.createLoginLimiter();
  const cookieOpts = { secure: secureCookies, maxAgeMs: auth.SESSION_TTL_MS };

  // ---------- Autenticação ----------

  app.post('/api/login', (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!email || !password || password.length > 200) {
      return res.status(400).json({ error: 'Informe e-mail e senha.' });
    }
    if (limiter.isBlocked(req.ip, email)) {
      return res.status(429).json({ error: 'Muitas tentativas. Aguarde 15 minutos e tente novamente.' });
    }
    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ? AND active = 1').get(email);
    const valid = auth.verifyPassword(password, user ? user.password_hash : auth.DUMMY_HASH) && !!user;
    if (!valid) {
      limiter.fail(req.ip, email);
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }
    limiter.reset(req.ip, email);
    auth.destroySession(db, req.sessionToken);
    const token = auth.createSession(db, user.id);
    res.set('Set-Cookie', auth.sessionCookie(token, cookieOpts));
    res.json({ ok: true });
  });

  app.use('/api', auth.requireAuth, auth.requireCsrf);

  app.post('/api/logout', (req, res) => {
    auth.destroySession(db, req.sessionToken);
    res.set('Set-Cookie', auth.sessionCookie('', { ...cookieOpts, maxAgeMs: 0 }));
    res.json({ ok: true });
  });

  app.get('/api/me', (req, res) => {
    res.json({ ...req.user, csrfToken: req.csrfToken });
  });

  app.post('/api/me/password', (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
    if (typeof currentPassword !== 'string' || !auth.verifyPassword(currentPassword, row.password_hash)) {
      return res.status(400).json({ error: 'Senha atual incorreta.' });
    }
    const problem = auth.validatePasswordStrength(newPassword);
    if (problem) return res.status(400).json({ error: problem });
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(auth.hashPassword(newPassword), req.user.id);
    // Encerra as outras sessões do usuário.
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND csrf_token != ?').run(req.user.id, req.csrfToken);
    res.json({ ok: true });
  });

  // ---------- Usuários (somente admin) ----------

  app.get('/api/users', auth.requireAdmin, (_req, res) => {
    res.json(db.prepare('SELECT id, email, name, is_admin, active, created_at FROM users ORDER BY name').all());
  });

  app.post('/api/users', auth.requireAdmin, (req, res) => {
    const { email, name, password, isAdmin } = req.body || {};
    if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || email.length > 200) {
      return res.status(400).json({ error: 'E-mail inválido.' });
    }
    if (typeof name !== 'string' || !name.trim() || name.length > 120) {
      return res.status(400).json({ error: 'Nome inválido.' });
    }
    const problem = auth.validatePasswordStrength(password);
    if (problem) return res.status(400).json({ error: problem });
    try {
      const r = db.prepare('INSERT INTO users (email, name, password_hash, is_admin) VALUES (?, ?, ?, ?)')
        .run(email.trim(), name.trim(), auth.hashPassword(password), isAdmin ? 1 : 0);
      res.status(201).json({ id: Number(r.lastInsertRowid) });
    } catch (err) {
      if (/UNIQUE/.test(err.message)) return res.status(409).json({ error: 'Já existe um usuário com esse e-mail.' });
      throw err;
    }
  });

  app.patch('/api/users/:id', auth.requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    if (id === req.user.id) return res.status(400).json({ error: 'Você não pode desativar a própria conta.' });
    if (typeof req.body?.active !== 'boolean') return res.status(400).json({ error: 'Informe "active".' });
    const r = db.prepare('UPDATE users SET active = ? WHERE id = ?').run(req.body.active ? 1 : 0, id);
    if (!r.changes) return res.status(404).json({ error: 'Usuário não encontrado.' });
    if (!req.body.active) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
    res.json({ ok: true });
  });

  // ---------- Contatos ----------

  app.use('/api/leads', leadsRouter(db));

  app.use('/api', (_req, res) => res.status(404).json({ error: 'Rota não encontrada.' }));

  // ---------- Front-end ----------

  app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
      return res.status(400).json({ error: 'Requisição inválida.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Erro interno.' });
  });

  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  const secureCookies = process.env.COOKIE_SECURE !== 'false';
  const rawProxy = process.env.TRUST_PROXY;
  const trustProxy = !rawProxy ? false : /^\d+$/.test(rawProxy) ? Number(rawProxy) : rawProxy;
  const db = openDatabase();

  const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (count === 0) {
    console.warn('Nenhum usuário cadastrado. Crie o primeiro administrador com: npm run create-user -- --admin');
  }
  if (!secureCookies) {
    console.warn('ATENÇÃO: COOKIE_SECURE=false — use apenas em desenvolvimento local (sem HTTPS).');
  }

  createApp(db, { secureCookies, trustProxy }).listen(port, host, () => {
    console.log(`Allfa CRM rodando em http://${host}:${port}`);
  });
}

module.exports = { createApp };
