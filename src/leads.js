'use strict';

const express = require('express');
const { STATUSES, CONTACT_METHODS } = require('./db');

const STATUS_IDS = new Set(STATUSES.map((s) => s.id));
const STATUS_LABEL = Object.fromEntries(STATUSES.map((s) => [s.id, s.label]));

const LIMITS = { name: 120, phone: 30, linkedin: 300, store: 120, notes: 2000 };

function cleanText(value, max) {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string') throw new Error('Formato inválido.');
  const text = value.trim();
  if (text.length > max) throw new Error(`Campo excede ${max} caracteres.`);
  return text;
}

function cleanLinkedin(value) {
  const text = cleanText(value, LIMITS.linkedin);
  if (!text) return '';
  let url;
  try {
    url = new URL(/^https?:\/\//i.test(text) ? text : `https://${text}`);
  } catch {
    throw new Error('LinkedIn deve ser uma URL válida.');
  }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || !(host === 'linkedin.com' || host.endsWith('.linkedin.com'))) {
    throw new Error('LinkedIn deve ser um endereço https://linkedin.com/...');
  }
  return url.toString();
}

function cleanPhone(value) {
  const text = cleanText(value, LIMITS.phone);
  if (text && !/^[0-9+()\-.\s]{8,30}$/.test(text)) throw new Error('Telefone inválido.');
  return text;
}

// Valida o corpo da requisição. Em "partial" só os campos enviados são validados (para PATCH).
function parseLead(body, { partial = false } = {}) {
  if (!body || typeof body !== 'object') throw new Error('Corpo inválido.');
  const out = {};
  const has = (k) => Object.prototype.hasOwnProperty.call(body, k);

  if (!partial || has('name')) {
    out.name = cleanText(body.name, LIMITS.name);
    if (!out.name) throw new Error('Nome é obrigatório.');
  }
  if (!partial || has('phone')) out.phone = cleanPhone(body.phone);
  if (!partial || has('linkedin')) out.linkedin = cleanLinkedin(body.linkedin);
  if (!partial || has('store')) out.store = cleanText(body.store, LIMITS.store);
  if (!partial || has('notes')) out.notes = cleanText(body.notes, LIMITS.notes);
  if (!partial || has('contact_method')) {
    if (!CONTACT_METHODS.includes(body.contact_method)) throw new Error('Forma de contato inválida.');
    out.contact_method = body.contact_method;
  }
  if (has('status') || !partial) {
    const status = body.status ?? 'novo';
    if (!STATUS_IDS.has(status)) throw new Error('Status inválido.');
    out.status = status;
  }
  if (has('position')) {
    const pos = Number(body.position);
    if (!Number.isFinite(pos)) throw new Error('Posição inválida.');
    out.position = pos;
  }
  return out;
}

const LEAD_COLUMNS = `
  l.id, l.name, l.phone, l.linkedin, l.store, l.contact_method, l.notes, l.status, l.position,
  l.created_at, l.updated_at, cu.name AS created_by_name, uu.name AS updated_by_name
`;

function leadsRouter(db) {
  const router = express.Router();

  const listStmt = db.prepare(`
    SELECT ${LEAD_COLUMNS}
      FROM leads l
      LEFT JOIN users cu ON cu.id = l.created_by
      LEFT JOIN users uu ON uu.id = l.updated_by
     ORDER BY l.status, l.position, l.id
  `);
  const getStmt = db.prepare(`
    SELECT ${LEAD_COLUMNS}
      FROM leads l
      LEFT JOIN users cu ON cu.id = l.created_by
      LEFT JOIN users uu ON uu.id = l.updated_by
     WHERE l.id = ?
  `);
  const maxPosStmt = db.prepare('SELECT COALESCE(MAX(position), 0) AS pos FROM leads WHERE status = ?');
  const historyStmt = db.prepare('INSERT INTO lead_history (lead_id, user_id, action, detail) VALUES (?, ?, ?, ?)');

  const parseId = (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      res.status(400).json({ error: 'ID inválido.' });
      return null;
    }
    return id;
  };

  router.get('/meta', (_req, res) => {
    res.json({ statuses: STATUSES, contactMethods: CONTACT_METHODS });
  });

  router.get('/', (_req, res) => {
    res.json(listStmt.all());
  });

  router.post('/', (req, res) => {
    let data;
    try {
      data = parseLead(req.body);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    const position = data.position ?? maxPosStmt.get(data.status).pos + 1;
    const result = db.prepare(`
      INSERT INTO leads (name, phone, linkedin, store, contact_method, notes, status, position, created_by, updated_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(data.name, data.phone, data.linkedin, data.store, data.contact_method, data.notes,
      data.status, position, req.user.id, req.user.id);
    const id = Number(result.lastInsertRowid);
    historyStmt.run(id, req.user.id, 'criado', `Status: ${STATUS_LABEL[data.status]}`);
    res.status(201).json(getStmt.get(id));
  });

  router.patch('/:id', (req, res) => {
    const id = parseId(req, res);
    if (id === null) return;
    const current = getStmt.get(id);
    if (!current) return res.status(404).json({ error: 'Contato não encontrado.' });

    let data;
    try {
      data = parseLead(req.body, { partial: true });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    const fields = Object.keys(data);
    if (!fields.length) return res.json(current);

    if (data.status && data.status !== current.status && data.position === undefined) {
      data.position = maxPosStmt.get(data.status).pos + 1;
      fields.push('position');
    }

    // Nomes de colunas vêm da whitelist de parseLead, nunca do usuário.
    const sets = [...new Set(fields)].map((f) => `${f} = ?`);
    const values = [...new Set(fields)].map((f) => data[f]);
    db.prepare(`UPDATE leads SET ${sets.join(', ')}, updated_by = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(...values, req.user.id, id);

    if (data.status && data.status !== current.status) {
      historyStmt.run(id, req.user.id, 'status', `${STATUS_LABEL[current.status]} → ${STATUS_LABEL[data.status]}`);
    } else if (fields.some((f) => f !== 'position')) {
      historyStmt.run(id, req.user.id, 'editado', '');
    }
    res.json(getStmt.get(id));
  });

  router.delete('/:id', (req, res) => {
    const id = parseId(req, res);
    if (id === null) return;
    const result = db.prepare('DELETE FROM leads WHERE id = ?').run(id);
    if (!result.changes) return res.status(404).json({ error: 'Contato não encontrado.' });
    res.status(204).end();
  });

  router.get('/:id/history', (req, res) => {
    const id = parseId(req, res);
    if (id === null) return;
    res.json(db.prepare(`
      SELECT h.action, h.detail, h.created_at, u.name AS user_name
        FROM lead_history h LEFT JOIN users u ON u.id = h.user_id
       WHERE h.lead_id = ? ORDER BY h.id DESC LIMIT 50
    `).all(id));
  });

  return router;
}

module.exports = { leadsRouter, parseLead };
