'use strict';

// Todo conteúdo vindo do usuário é inserido com textContent (nunca innerHTML) para evitar XSS.

const state = { me: null, meta: null, leads: [], editing: null };
const $ = (sel) => document.querySelector(sel);

// ---------- API ----------

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && state.me) headers['X-CSRF-Token'] = state.me.csrfToken;
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  if (res.status === 401 && path !== '/login') {
    showLogin();
    throw new Error('Sessão expirada. Entre novamente.');
  }
  const data = res.status === 204 ? null : await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || 'Erro inesperado.');
  return data;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function formatDate(sqlDate) {
  const d = new Date(`${sqlDate.replace(' ', 'T')}Z`);
  return d.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
}

// ---------- Views ----------

function showLogin() {
  state.me = null;
  $('#app-view').hidden = true;
  $('#login-view').hidden = false;
  $('#login-form [name=email]').focus();
}

async function showApp() {
  state.me = await api('/me');
  if (!state.meta) state.meta = await api('/leads/meta');
  $('#login-view').hidden = true;
  $('#app-view').hidden = false;
  $('#user-name').textContent = state.me.name;
  $('#open-users').hidden = !state.me.isAdmin;
  fillSelects();
  await loadLeads();
}

function fillSelects() {
  const methodSelect = $('#lead-form [name=contact_method]');
  const statusSelect = $('#lead-form [name=status]');
  const filter = $('#filter-method');
  if (methodSelect.options.length) return;
  for (const m of state.meta.contactMethods) {
    methodSelect.append(el('option', { value: m }, m));
    filter.append(el('option', { value: m }, m));
  }
  for (const s of state.meta.statuses) statusSelect.append(el('option', { value: s.id }, s.label));
}

async function loadLeads() {
  state.leads = await api('/leads');
  renderBoard();
}

function matchesFilters(lead) {
  const q = $('#search').value.trim().toLowerCase();
  const method = $('#filter-method').value;
  if (method && lead.contact_method !== method) return false;
  if (!q) return true;
  return [lead.name, lead.store, lead.phone, lead.notes, lead.linkedin]
    .some((v) => v && v.toLowerCase().includes(q));
}

function renderBoard() {
  const board = $('#board');
  board.replaceChildren();
  for (const status of state.meta.statuses) {
    const leads = state.leads
      .filter((l) => l.status === status.id && matchesFilters(l))
      .sort((a, b) => a.position - b.position || a.id - b.id);

    const cards = el('div', { class: 'cards' }, ...leads.map(renderCard));
    const column = el('section', { class: 'column', dataset: { status: status.id } },
      el('header', {}, el('span', {}, status.label), el('span', { class: 'count' }, leads.length)),
      cards,
    );
    setupDropZone(column, cards, status.id);
    board.append(column);
  }
}

function renderCard(lead) {
  const meta = el('div', { class: 'meta' }, el('span', { class: 'tag' }, lead.contact_method));
  if (lead.phone) {
    meta.append(el('a', { href: `tel:${lead.phone.replace(/[^0-9+]/g, '')}` }, lead.phone));
  }
  if (lead.linkedin) {
    meta.append(el('a', { href: lead.linkedin, target: '_blank', rel: 'noopener noreferrer' }, 'LinkedIn'));
  }
  const card = el('article', { class: 'card', draggable: 'true', tabindex: '0', dataset: { id: lead.id } },
    el('div', { class: 'name' }, lead.name),
    lead.store ? el('div', { class: 'store' }, lead.store) : null,
    meta,
    el('div', { class: 'footer' }, `Atualizado ${formatDate(lead.updated_at)}${lead.updated_by_name ? ` por ${lead.updated_by_name}` : ''}`),
  );
  card.addEventListener('click', (e) => {
    if (e.target.closest('a')) return;
    openLead(lead);
  });
  card.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') openLead(lead);
  });
  card.addEventListener('dragstart', (e) => {
    e.dataTransfer.setData('text/plain', String(lead.id));
    e.dataTransfer.effectAllowed = 'move';
    card.classList.add('dragging');
  });
  card.addEventListener('dragend', () => card.classList.remove('dragging'));
  return card;
}

// ---------- Drag and drop ----------

function setupDropZone(column, cardsEl, statusId) {
  column.addEventListener('dragover', (e) => {
    e.preventDefault();
    column.classList.add('drag-over');
  });
  column.addEventListener('dragleave', (e) => {
    if (!column.contains(e.relatedTarget)) column.classList.remove('drag-over');
  });
  column.addEventListener('drop', async (e) => {
    e.preventDefault();
    column.classList.remove('drag-over');
    const id = Number(e.dataTransfer.getData('text/plain'));
    const lead = state.leads.find((l) => l.id === id);
    if (!lead) return;

    // Calcula a posição entre os cartões vizinhos onde foi solto.
    const siblings = [...cardsEl.querySelectorAll('.card')].filter((c) => Number(c.dataset.id) !== id);
    const after = siblings.find((c) => {
      const r = c.getBoundingClientRect();
      return e.clientY < r.top + r.height / 2;
    });
    const posOf = (c) => state.leads.find((l) => l.id === Number(c.dataset.id)).position;
    const idx = after ? siblings.indexOf(after) : siblings.length;
    const prev = idx > 0 ? posOf(siblings[idx - 1]) : null;
    const next = after ? posOf(after) : null;
    let position;
    if (prev === null && next === null) position = 1;
    else if (prev === null) position = next - 1;
    else if (next === null) position = prev + 1;
    else position = (prev + next) / 2;

    if (lead.status === statusId && lead.position === position) return;
    const previous = { ...lead };
    Object.assign(lead, { status: statusId, position });
    renderBoard();
    try {
      Object.assign(lead, await api(`/leads/${id}`, { method: 'PATCH', body: { status: statusId, position } }));
      renderBoard();
    } catch (err) {
      Object.assign(lead, previous);
      renderBoard();
      alert(err.message);
    }
  });
}

// ---------- Modal de contato ----------

async function openLead(lead) {
  state.editing = lead || null;
  const form = $('#lead-form');
  form.reset();
  $('#lead-error').textContent = '';
  $('#lead-title').textContent = lead ? 'Editar contato' : 'Novo contato';
  $('#delete-lead').hidden = !lead;
  const history = $('#lead-history');
  history.hidden = !lead;
  history.open = false;
  history.querySelector('ul').replaceChildren();

  if (lead) {
    for (const f of ['name', 'phone', 'linkedin', 'store', 'contact_method', 'status', 'notes']) {
      form.elements[f].value = lead[f] ?? '';
    }
  } else {
    form.elements.status.value = 'novo';
  }
  $('#lead-dialog').showModal();
  form.elements.name.focus();

  if (lead) {
    try {
      const items = await api(`/leads/${lead.id}/history`);
      history.querySelector('ul').replaceChildren(...items.map((h) =>
        el('li', {}, `${formatDate(h.created_at)} · ${h.user_name || '—'} · ${h.action}${h.detail ? `: ${h.detail}` : ''}`)));
    } catch { /* histórico é opcional */ }
  }
}

$('#lead-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const body = Object.fromEntries(new FormData(form));
  try {
    if (state.editing) {
      await api(`/leads/${state.editing.id}`, { method: 'PATCH', body });
    } else {
      await api('/leads', { method: 'POST', body });
    }
    $('#lead-dialog').close();
    await loadLeads();
  } catch (err) {
    $('#lead-error').textContent = err.message;
  }
});

$('#delete-lead').addEventListener('click', async () => {
  if (!state.editing || !confirm(`Excluir o contato "${state.editing.name}"?`)) return;
  try {
    await api(`/leads/${state.editing.id}`, { method: 'DELETE' });
    $('#lead-dialog').close();
    await loadLeads();
  } catch (err) {
    $('#lead-error').textContent = err.message;
  }
});

// ---------- Login / logout / senha ----------

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  $('#login-error').textContent = '';
  try {
    await api('/login', { method: 'POST', body: Object.fromEntries(new FormData(form)) });
    form.reset();
    await showApp();
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});

$('#logout').addEventListener('click', async () => {
  try { await api('/logout', { method: 'POST' }); } catch { /* ignora */ }
  showLogin();
});

$('#open-password').addEventListener('click', () => {
  const form = $('#password-form');
  form.reset();
  form.querySelector('.error').textContent = '';
  $('#password-dialog').showModal();
});

$('#password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  try {
    await api('/me/password', { method: 'POST', body: Object.fromEntries(new FormData(form)) });
    $('#password-dialog').close();
    alert('Senha alterada com sucesso.');
  } catch (err) {
    form.querySelector('.error').textContent = err.message;
  }
});

// ---------- Usuários (admin) ----------

async function loadUsers() {
  const users = await api('/users');
  $('#users-list').replaceChildren(...users.map((u) => {
    const toggle = el('button', { type: 'button', class: 'link' }, u.active ? 'Desativar' : 'Reativar');
    toggle.hidden = u.id === state.me.id;
    toggle.addEventListener('click', async () => {
      try {
        await api(`/users/${u.id}`, { method: 'PATCH', body: { active: !u.active } });
        await loadUsers();
      } catch (err) {
        alert(err.message);
      }
    });
    return el('tr', {},
      el('td', { class: u.active ? '' : 'inactive' }, u.name),
      el('td', {}, u.email),
      el('td', {}, u.is_admin ? 'Admin' : 'Vendas'),
      el('td', {}, toggle));
  }));
}

$('#open-users').addEventListener('click', async () => {
  const form = $('#user-form');
  form.reset();
  form.querySelector('.error').textContent = '';
  $('#users-dialog').showModal();
  await loadUsers();
});

$('#user-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  data.isAdmin = form.elements.isAdmin.checked;
  try {
    await api('/users', { method: 'POST', body: data });
    form.reset();
    form.querySelector('.error').textContent = '';
    await loadUsers();
  } catch (err) {
    form.querySelector('.error').textContent = err.message;
  }
});

// ---------- Geral ----------

document.querySelectorAll('[data-close]').forEach((btn) =>
  btn.addEventListener('click', () => btn.closest('dialog').close()));

$('#new-lead').addEventListener('click', () => openLead(null));
$('#search').addEventListener('input', renderBoard);
$('#filter-method').addEventListener('change', renderBoard);

showApp().catch(showLogin);
