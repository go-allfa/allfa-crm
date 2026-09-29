'use strict';

// Uso: npm run create-user -- [--admin] [--email x@y.com] [--name "Nome"]
// A senha é sempre pedida no terminal (sem eco) para não ficar no histórico do shell.

const readline = require('node:readline');
const { openDatabase } = require('../src/db');
const { hashPassword, validatePasswordStrength } = require('../src/auth');

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

function ask(question, { hidden = false } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) {
      rl._writeToOutput = (s) => {
        if (s.includes(question)) rl.output.write(s);
      };
    }
    rl.question(question, (answer) => {
      rl.close();
      if (hidden) process.stdout.write('\n');
      resolve(answer.trim());
    });
  });
}

(async () => {
  const isAdmin = process.argv.includes('--admin');
  const email = arg('email') || await ask('E-mail: ');
  const name = arg('name') || await ask('Nome: ');
  const password = await ask('Senha (mín. 10 caracteres): ', { hidden: true });
  const confirm = await ask('Confirme a senha: ', { hidden: true });

  if (!email || !name) throw new Error('E-mail e nome são obrigatórios.');
  if (password !== confirm) throw new Error('As senhas não conferem.');
  const problem = validatePasswordStrength(password);
  if (problem) throw new Error(problem);

  const db = openDatabase();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    db.prepare('UPDATE users SET name = ?, password_hash = ?, is_admin = ?, active = 1 WHERE id = ?')
      .run(name, hashPassword(password), isAdmin ? 1 : 0, existing.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(existing.id);
    console.log(`Usuário ${email} atualizado${isAdmin ? ' (admin)' : ''}.`);
  } else {
    db.prepare('INSERT INTO users (email, name, password_hash, is_admin) VALUES (?, ?, ?, ?)')
      .run(email, name, hashPassword(password), isAdmin ? 1 : 0);
    console.log(`Usuário ${email} criado${isAdmin ? ' (admin)' : ''}.`);
  }
})().catch((err) => {
  console.error(`Erro: ${err.message}`);
  process.exit(1);
});
