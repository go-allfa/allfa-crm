'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/db');
const { createApp } = require('../src/server');
const { hashPassword } = require('../src/auth');

let server;
let base;

before(async () => {
  const db = openDatabase(':memory:');
  db.prepare('INSERT INTO users (email, name, password_hash, is_admin) VALUES (?, ?, ?, 1)')
    .run('admin@allfa.test', 'Admin', hashPassword('senha-super-forte'));
  server = createApp(db).listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

async function login(email = 'admin@allfa.test', password = 'senha-super-forte') {
  const res = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  return { res, cookie };
}

async function session() {
  const { cookie } = await login();
  const me = await (await fetch(`${base}/api/me`, { headers: { cookie } })).json();
  const call = (path, { method = 'GET', body, csrf = me.csrfToken } = {}) => fetch(`${base}/api${path}`, {
    method,
    headers: { cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { cookie, me, call };
}

test('bloqueia acesso sem login', async () => {
  const res = await fetch(`${base}/api/leads`);
  assert.equal(res.status, 401);
});

test('rejeita senha errada e define cookie seguro no login correto', async () => {
  assert.equal((await login('admin@allfa.test', 'errada-errada')).res.status, 401);
  const res = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'admin@allfa.test', password: 'senha-super-forte' }),
  });
  assert.equal(res.status, 200);
  const cookie = res.headers.get('set-cookie');
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
});

test('bloqueia após muitas tentativas de login', async () => {
  for (let i = 0; i < 5; i++) await login('ninguem@allfa.test', 'qualquer-coisa');
  assert.equal((await login('ninguem@allfa.test', 'qualquer-coisa')).res.status, 429);
});

test('exige token CSRF para alterar dados', async () => {
  const { call } = await session();
  const res = await call('/leads', { method: 'POST', csrf: 'falso', body: { name: 'X', contact_method: 'LinkedIn' } });
  assert.equal(res.status, 403);
});

test('CRUD de contatos e mudança de status', async () => {
  const { call } = await session();
  let res = await call('/leads', {
    method: 'POST',
    body: {
      name: 'Maria Souza',
      phone: '(11) 98888-7777',
      linkedin: 'linkedin.com/in/maria',
      store: 'Loja Centro',
      contact_method: 'WhatsApp',
    },
  });
  assert.equal(res.status, 201);
  const lead = await res.json();
  assert.equal(lead.status, 'novo');
  assert.equal(lead.linkedin, 'https://linkedin.com/in/maria');
  assert.equal(lead.created_by_name, 'Admin');

  res = await call(`/leads/${lead.id}`, { method: 'PATCH', body: { status: 'proposta' } });
  assert.equal((await res.json()).status, 'proposta');

  const history = await (await call(`/leads/${lead.id}/history`)).json();
  assert.equal(history[0].action, 'status');

  res = await call(`/leads/${lead.id}`, { method: 'DELETE' });
  assert.equal(res.status, 204);
});

test('valida campos', async () => {
  const { call } = await session();
  const cases = [
    { name: '', contact_method: 'LinkedIn' },
    { name: 'A', contact_method: 'Pombo-correio' },
    { name: 'A', contact_method: 'LinkedIn', linkedin: 'javascript:alert(1)' },
    { name: 'A', contact_method: 'LinkedIn', linkedin: 'https://evil.com/linkedin.com' },
    { name: 'A', contact_method: 'LinkedIn', phone: 'abc' },
    { name: 'A', contact_method: 'LinkedIn', status: 'inexistente' },
  ];
  for (const body of cases) {
    const res = await call('/leads', { method: 'POST', body });
    assert.equal(res.status, 400, JSON.stringify(body));
  }
});

test('envia cabeçalhos de segurança', async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('admin cria usuário; usuário comum não acessa gestão', async () => {
  const { call } = await session();
  let res = await call('/users', {
    method: 'POST',
    body: { name: 'Vendedor', email: 'vendas@allfa.test', password: 'outra-senha-forte' },
  });
  assert.equal(res.status, 201);

  const { cookie } = await login('vendas@allfa.test', 'outra-senha-forte');
  res = await fetch(`${base}/api/users`, { headers: { cookie } });
  assert.equal(res.status, 403);
});
