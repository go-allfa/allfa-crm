'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const STATUSES = [
  { id: 'novo', label: 'Novo contato' },
  { id: 'qualificacao', label: 'Em qualificação' },
  { id: 'proposta', label: 'Proposta enviada' },
  { id: 'negociacao', label: 'Em negociação' },
  { id: 'ganho', label: 'Fechado (ganho)' },
  { id: 'perdido', label: 'Perdido' },
];

const CONTACT_METHODS = [
  'LinkedIn',
  'WhatsApp',
  'Telefone',
  'E-mail',
  'Indicação',
  'Visita presencial',
  'Evento',
  'Outro',
];

function openDatabase(file = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'crm.sqlite')) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });

  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
      name          TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin      INTEGER NOT NULL DEFAULT 0,
      active        INTEGER NOT NULL DEFAULT 1,
      created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf_token TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS leads (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      name           TEXT NOT NULL,
      phone          TEXT NOT NULL DEFAULT '',
      linkedin       TEXT NOT NULL DEFAULT '',
      store          TEXT NOT NULL DEFAULT '',
      contact_method TEXT NOT NULL,
      notes          TEXT NOT NULL DEFAULT '',
      status         TEXT NOT NULL DEFAULT 'novo',
      position       REAL NOT NULL DEFAULT 0,
      created_by     INTEGER REFERENCES users(id),
      updated_by     INTEGER REFERENCES users(id),
      created_at     TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS lead_history (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      lead_id    INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
      user_id    INTEGER REFERENCES users(id),
      action     TEXT NOT NULL,
      detail     TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status, position);
    CREATE INDEX IF NOT EXISTS idx_history_lead ON lead_history(lead_id);
  `);
  return db;
}

module.exports = { openDatabase, STATUSES, CONTACT_METHODS };
