/* Вебморда фаервола. Один файл, без сборки и без зависимостей: приложение,
   которое стоит между агентом и деньгами, не должно тянуть npm-дерево, чтобы
   нарисовать восемь таблиц. */

const api = {
  async get(url) { const r = await fetch(url); if (!r.ok) throw new Error(await r.text()); return r.json(); },
  async post(url, body) {
    const r = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'},
                               body: JSON.stringify(body || {})});
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },
  async del(url) { const r = await fetch(url, {method: 'DELETE'}); return r.json(); },
};

const esc = (s) => String(s === null || s === undefined ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const DECISION_RU = {allow: 'разрешено', deny: 'заблокировано', hitl: 'подтверждение'};
const money = (v) => (v === null || v === undefined || v === '') ? '' : Number(v).toFixed(2) + ' ₽';

let META = null;
async function meta() { if (!META) META = await api.get('/api/v1/meta'); return META; }

const page = document.body.dataset.page;

/* ── значок «ждут подтверждения» во всех страницах ─────────────────────── */
async function refreshBadge() {
  try {
    const {pending} = await api.get('/api/v1/pending');
    const el = document.getElementById('pendingBadge');
    if (!el) return;
    el.hidden = pending.length === 0;
    el.textContent = pending.length;
  } catch (e) { /* морда не должна умирать из-за одного опроса */ }
}
refreshBadge();
setInterval(refreshBadge, 5000);

/* ── демон входа ────────────────────────────────────────────────────────
   Браузер ходит к нему НАПРЯМУЮ, мимо фаервола: пароль не должен проходить
   через контейнер, который потом показывает журнал. Поэтому здесь свой
   мини-клиент, а не api.* выше. */
const authd = {
  base: () => (window.AUTHD_URL || 'http://127.0.0.1:8765').replace(/\/$/, ''),
  async get(path) {
    const r = await fetch(authd.base() + path, {mode: 'cors'});
    return r.json();
  },
  async post(path, body) {
    const r = await fetch(authd.base() + path, {
      method: 'POST', mode: 'cors',
      headers: {'Content-Type': 'application/json'},   // форсирует preflight
      body: JSON.stringify(body || {}),
    });
    return r.json();
  },
};

const SESSION_STATE_RU = {
  active: ['Сессия активна', 'ok'],
  stale: ['Сессия устарела — банк попросит обновить', 'warn'],
  none: ['Входа нет', 'off'],
  broken: ['Файл сессии повреждён', 'bad'],
};

async function sessionDot() {
  const el = document.getElementById('sessionDot');
  if (!el) return null;
  try {
    const s = await authd.get('/api/auth/status');
    el.className = 'dot ' + (SESSION_STATE_RU[s.state] || ['', 'off'])[1];
    el.title = (SESSION_STATE_RU[s.state] || ['неизвестно'])[0];
    return s;
  } catch (e) {
    el.className = 'dot down';
    el.title = 'демон входа не запущен';
    return null;
  }
}
sessionDot();
setInterval(sessionDot, 15000);

/* ── лента ─────────────────────────────────────────────────────────────── */
function feedTable(rows) {
  if (!rows.length) return '<div class="empty">Пока ничего. Запустите агента — вызовы появятся здесь.</div>';
  return `<table><thead><tr>
      <th style="width:96px">Время</th><th>Операция</th><th style="width:110px">Сумма</th>
      <th style="width:135px">Решение</th><th>Причина</th></tr></thead><tbody>` +
    rows.map(r => `<tr class="clickable" onclick="location.href='/requests/${esc(r.id)}'">
      <td class="nowrap mono muted">${esc(r.time)}</td>
      <td><b>${esc(r.title)}</b><br><span class="mono muted">${esc(r.tool)}</span>
          ${r.recipient ? `<br><span class="muted">→ ${esc(r.recipient)}</span>` : ''}</td>
      <td class="nowrap"><b>${esc(money(r.amount))}</b></td>
      <td><span class="tag ${esc(r.decision)}">${esc(DECISION_RU[r.decision] || r.decision)}</span></td>
      <td class="muted">${esc(r.reason)}</td></tr>`).join('') + '</tbody></table>';
}

async function loadFeed(container, params) {
  const qs = new URLSearchParams(params || {}).toString();
  const {feed} = await api.get('/api/v1/feed?' + qs);
  container.innerHTML = feedTable(feed);
}

/* ── страница: обзор ───────────────────────────────────────────────────── */
if (page === 'index') {
  const feedEl = document.getElementById('feed');
  const tick = async () => {
    await loadFeed(feedEl, {limit: 60});
    const {pending} = await api.get('/api/v1/pending');
    const card = document.getElementById('pendingCard');
    card.hidden = pending.length === 0;
    document.getElementById('pendingList').innerHTML = pending.map(p => `
      <div class="row" style="padding:10px 0;border-bottom:1px solid var(--line)">
        <div><b>${esc(p.tool)}</b> ${p.amount ? '· <b>' + esc(money(p.amount)) + '</b>' : ''}
             ${p.recipient ? '→ ' + esc(p.recipient) : ''}
             <br><span class="muted">${esc(p.reason)}</span></div>
        <div class="spacer"></div>
        <a class="btn" href="/hitl/${esc(p.request_id)}">Решить</a>
      </div>`).join('');
  };
  tick(); setInterval(tick, 3000);
}

/* ── страница: журнал ──────────────────────────────────────────────────── */
if (page === 'requests') {
  const feedEl = document.getElementById('feed');
  const dec = document.getElementById('fltDecision');
  const tool = document.getElementById('fltTool');
  const reload = () => loadFeed(feedEl, {limit: 200, decision: dec.value, tool: tool.value});
  dec.onchange = reload;
  tool.oninput = reload;
  document.getElementById('fltClear').onclick = () => { dec.value = ''; tool.value = ''; reload(); };
  reload(); setInterval(reload, 5000);
}

/* ── страница: подтверждения ───────────────────────────────────────────── */
if (page === 'hitl') {
  const tick = async () => {
    const {pending} = await api.get('/api/v1/pending');
    document.getElementById('hitlList').innerHTML = pending.length ? pending.map(p => `
      <div class="row" style="padding:12px 0;border-bottom:1px solid var(--line)">
        <div>
          <b style="font-size:16px">${esc(p.tool)}</b>
          ${p.amount ? ' · <b>' + esc(money(p.amount)) + '</b>' : ''}
          ${p.recipient ? ' → <span class="mono">' + esc(p.recipient) + '</span>' : ''}
          <br><span class="muted">${esc(p.reason)} · истекает через ${Math.max(0, Math.floor(p.expires_in_sec / 60))} мин</span>
        </div>
        <div class="spacer"></div>
        <a class="btn" href="/hitl/${esc(p.request_id)}">Открыть</a>
      </div>`).join('') : '<div class="empty">Ничего не ждёт вашего решения.</div>';

    const {feed} = await api.get('/api/v1/feed?limit=40&decision=hitl');
    const done = feed.filter(r => r.status !== 'pending');
    document.getElementById('hitlDone').innerHTML = done.length ? feedTable(done)
      : '<div class="empty">Пока пусто.</div>';
  };
  tick(); setInterval(tick, 4000);
}

if (page === 'hitl_one') {
  const card = document.getElementById('decisionCard');
  const rid = card.dataset.req;
  const note = () => (document.getElementById('hitlNote') || {}).value || '';
  const decide = async (what) => {
    const res = await api.post(`/api/v1/hitl/${rid}/${what}`, {note: note()});
    if (!res.ok) { alert(res.error || 'не удалось'); }
    location.reload();
  };
  const approve = document.getElementById('btnApprove');
  const deny = document.getElementById('btnDeny');
  if (approve) approve.onclick = () => decide('approve');
  if (deny) deny.onclick = () => decide('deny');
  // Если человек ушёл со страницы открытой, а срок истёк — покажем это без F5.
  if (card.dataset.state === 'pending') {
    setInterval(async () => {
      const s = await api.get('/api/v1/requests/' + rid);
      if (s.hitl_state !== 'pending') location.reload();
    }, 5000);
  }
}

/* ── редактор фильтра (общий для правил и лимитов) ─────────────────────── */
function conditionRow(cond, m) {
  const fields = m.fields.map(([v, t]) =>
    `<option value="${esc(v)}" ${cond.field === v ? 'selected' : ''}>${esc(t)}</option>`).join('');
  const ops = m.ops.map(([v, t]) =>
    `<option value="${esc(v)}" ${cond.op === v ? 'selected' : ''}>${esc(t)}</option>`).join('');
  const listOpts = m.lists.map(l =>
    `<option value="${esc(l.name)}" ${String(cond.value) === l.name ? 'selected' : ''}>${esc(l.name)}</option>`).join('');
  const isList = cond.op === 'in_list' || cond.op === 'not_in_list';
  const valueInput = isList
    ? `<select class="c-value">${listOpts}</select>`
    : `<input type="text" class="c-value" value="${esc(cond.value)}" placeholder="значение">`;
  return `<div class="cond">
    <select class="c-field">${fields}</select>
    <select class="c-op">${ops}</select>
    ${valueInput}
    <button type="button" class="ghost sm c-del">✕</button>
  </div>`;
}

function bindConditions(root, m) {
  root.querySelectorAll('.c-del').forEach(b => b.onclick = () => b.closest('.cond').remove());
  // Смена операции на «входит в список» подменяет поле ввода на выпадашку со
  // списками: иначе человек пишет туда имя списка руками и опечатывается.
  root.querySelectorAll('.c-op').forEach(sel => sel.onchange = () => {
    const row = sel.closest('.cond');
    const cur = readCondition(row);
    row.outerHTML = conditionRow({...cur, value: ''}, m);
    bindConditions(root, m);
  });
}

function readCondition(row) {
  return {
    field: row.querySelector('.c-field').value,
    op: row.querySelector('.c-op').value,
    value: row.querySelector('.c-value').value,
  };
}

function matchEditor(match, m) {
  const conds = (match.conditions || []);
  return `
    <label>Туллы (через запятую, можно с *, пусто = любые)</label>
    <input type="text" id="mTools" value="${esc((match.tools || []).join(', '))}" placeholder="transfer, grocery_*">
    <label>Типы операций</label>
    <div class="row">
      ${['read', 'write', 'money'].map(k => `<span class="check">
        <input type="checkbox" class="mKind" value="${k}" ${(match.kinds || []).includes(k) ? 'checked' : ''}>
        <label>${esc(m.kind_titles[k])}</label></span>`).join('')}
    </div>
    <label>Категории (пусто = любые)</label>
    <select id="mCats" multiple size="6">
      ${Object.entries(m.categories).map(([v, t]) =>
        `<option value="${esc(v)}" ${(match.categories || []).includes(v) ? 'selected' : ''}>${esc(t)}</option>`).join('')}
    </select>
    <label>Условия</label>
    <div class="row" style="margin-bottom:8px">
      <select id="mCondMode" style="width:auto">
        <option value="all" ${match.conditions_mode !== 'any' ? 'selected' : ''}>должны выполниться все</option>
        <option value="any" ${match.conditions_mode === 'any' ? 'selected' : ''}>достаточно любого</option>
      </select>
      <button type="button" class="ghost sm" id="mAddCond">+ условие</button>
    </div>
    <div id="mConds">${conds.map(c => conditionRow(c, m)).join('')}</div>`;
}

function readMatch(root) {
  const tools = root.querySelector('#mTools').value.split(',').map(s => s.trim()).filter(Boolean);
  const kinds = [...root.querySelectorAll('.mKind:checked')].map(i => i.value);
  const cats = [...root.querySelector('#mCats').selectedOptions].map(o => o.value);
  const conditions = [...root.querySelectorAll('#mConds .cond')].map(readCondition)
    .filter(c => c.field);
  return {tools, kinds, categories: cats, conditions_mode: root.querySelector('#mCondMode').value,
          conditions};
}

function modal(html, onMount) {
  const root = document.getElementById('modalRoot');
  root.innerHTML = `<div class="modal-bg"><div class="modal">${html}</div></div>`;
  const bg = root.querySelector('.modal-bg');
  bg.onclick = (e) => { if (e.target === bg) root.innerHTML = ''; };
  if (onMount) onMount(root);
  return root;
}
const closeModal = () => { document.getElementById('modalRoot').innerHTML = ''; };

function describeMatch(match, m) {
  const bits = [];
  if ((match.tools || []).length) bits.push('тулы: ' + match.tools.join(', '));
  if ((match.kinds || []).length) bits.push('тип: ' + match.kinds.map(k => m.kind_titles[k]).join(', '));
  if ((match.categories || []).length)
    bits.push('категории: ' + match.categories.map(c => m.categories[c] || c).join(', '));
  (match.conditions || []).forEach(c => {
    const f = (m.fields.find(x => x[0] === c.field) || [c.field, c.field])[1];
    const o = (m.ops.find(x => x[0] === c.op) || [c.op, c.op])[1];
    bits.push(`${f} ${o} ${c.value === '' ? '' : c.value}`.trim());
  });
  return bits.length ? bits.join(' · ') : 'любой вызов';
}

/* Норма правила и сколько от неё осталось — иначе квота есть, а понять,
   сколько её израсходовано, можно только по журналу. */
const QUOTA_WINDOW_RU = {hour: 'в час', day: 'в сутки', week: 'в неделю', month: 'в месяц'};

function quotaBadge(r) {
  if (!r.quota_window) return '';
  const used = r.quota_used || {count: 0, amount: 0};
  const parts = [];
  if (r.quota_max_count !== null && r.quota_max_count !== undefined)
    parts.push(`${used.count} из ${r.quota_max_count} раз`);
  if (r.quota_max_amount !== null && r.quota_max_amount !== undefined)
    parts.push(`${money(used.amount)} из ${money(r.quota_max_amount)}`);
  if (!parts.length) return '';
  const over = (r.quota_max_count != null && used.count >= r.quota_max_count) ||
               (r.quota_max_amount != null && used.amount >= r.quota_max_amount);
  const then = r.quota_on_exceed === 'deny' ? 'дальше запрет' : 'дальше подтверждение';
  return `<br><span class="tag ${over ? 'hitl' : 'read'}">без подтверждения
    ${esc(QUOTA_WINDOW_RU[r.quota_window] || r.quota_window)}:
    ${esc(parts.join(', '))} · ${esc(then)}</span>`;
}

/* ── страница: правила ─────────────────────────────────────────────────── */
if (page === 'rules') {
  const m0 = meta();

  async function render() {
    const m = await m0;
    const {rules} = await api.get('/api/v1/rules');
    document.getElementById('rulesList').innerHTML = `<table><thead><tr>
        <th style="width:60px">№</th><th>Правило</th><th style="width:130px">Решение</th>
        <th style="width:150px"></th></tr></thead><tbody>` +
      rules.map(r => `<tr style="${r.enabled ? '' : 'opacity:.5'}">
        <td class="mono muted">${r.priority}</td>
        <td><b>${esc(r.name)}</b><br><span class="muted">${esc(describeMatch(r.match, m))}</span>
            ${r.skip_limits ? '<br><span class="tag off">обходит лимиты</span>' : ''}
            ${quotaBadge(r)}</td>
        <td><span class="tag ${esc(r.action)}">${esc(DECISION_RU[r.action])}</span></td>
        <td class="nowrap">
          <button class="ghost sm" data-edit="${r.id}">Изменить</button>
          <button class="ghost sm" data-toggle="${r.id}">${r.enabled ? 'Выкл' : 'Вкл'}</button>
          <button class="ghost sm" data-del="${r.id}">✕</button>
        </td></tr>`).join('') + '</tbody></table>';

    document.querySelectorAll('[data-edit]').forEach(b => b.onclick =
      () => edit(rules.find(r => r.id == b.dataset.edit)));
    document.querySelectorAll('[data-toggle]').forEach(b => b.onclick = async () => {
      const r = rules.find(x => x.id == b.dataset.toggle);
      await api.post('/api/v1/rules', {...r, enabled: !r.enabled});
      render();
    });
    document.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => {
      if (!confirm('Удалить правило?')) return;
      await api.del('/api/v1/rules/' + b.dataset.del);
      render();
    });
  }

  async function edit(rule) {
    const m = await m0;
    rule = rule || {name: '', priority: 100, action: 'hitl', enabled: true, match: {},
                    reason: '', hitl_mode: '', skip_limits: false};
    modal(`
      <h2>${rule.id ? 'Правило' : 'Новое правило'}</h2>
      <p class="muted" style="margin-top:0">Первое совпавшее правило решает — приоритет
      это порядок разбора, меньше = раньше.</p>
      <div class="inline">
        <div><label>Название</label><input type="text" id="rName" value="${esc(rule.name)}"></div>
        <div><label>Приоритет</label><input type="number" id="rPrio" value="${rule.priority}"></div>
        <div><label>Решение</label><select id="rAction">
          <option value="allow" ${rule.action === 'allow' ? 'selected' : ''}>Разрешить</option>
          <option value="hitl"  ${rule.action === 'hitl' ? 'selected' : ''}>Спросить человека</option>
          <option value="deny"  ${rule.action === 'deny' ? 'selected' : ''}>Запретить</option>
        </select></div>
      </div>
      <label>Причина (её увидит агент и вы в журнале)</label>
      <input type="text" id="rReason" value="${esc(rule.reason)}">
      <div class="check"><input type="checkbox" id="rEnabled" ${rule.enabled ? 'checked' : ''}>
        <label for="rEnabled">Правило включено</label></div>
      <div class="check"><input type="checkbox" id="rSkip" ${rule.skip_limits ? 'checked' : ''}>
        <label for="rSkip">Обходить лимиты (осторожно: снимает потолки для совпавших вызовов)</label></div>
      <hr style="border:none;border-top:1px solid var(--line);margin:18px 0">
      <h2>Норма без подтверждения</h2>
      <p class="muted" style="margin-top:0">Сколько раз и на какую сумму это правило
      пропускает <b>молча</b>. Когда норма исчерпана — операция не запрещается, а идёт
      на подтверждение. Например: до 3 000 ₽ три раза в сутки без вопросов, четвёртый
      раз — спросить. Считается только то, что прошло по этому правилу; операции,
      которые вы подтвердили руками, норму не расходуют. Имеет смысл у разрешающего
      правила.</p>
      <div class="inline">
        <div><label>Окно</label><select id="rqWindow">
          ${Object.entries({'': 'нормы нет', hour: 'в час', day: 'в сутки',
                            week: 'в неделю', month: 'в месяц'}).map(([v, t]) =>
            `<option value="${v}" ${(rule.quota_window || '') === v ? 'selected' : ''}>${esc(t)}</option>`).join('')}
        </select></div>
        <div><label>Не больше раз</label>
          <input type="number" id="rqCount" min="1" value="${rule.quota_max_count ?? ''}"></div>
        <div><label>Не больше, ₽</label>
          <input type="number" id="rqAmount" step="0.01" value="${rule.quota_max_amount ?? ''}"></div>
        <div><label>Когда норма исчерпана</label><select id="rqExceed">
          <option value="hitl" ${(rule.quota_on_exceed || 'hitl') === 'hitl' ? 'selected' : ''}>Спросить человека</option>
          <option value="deny" ${rule.quota_on_exceed === 'deny' ? 'selected' : ''}>Запретить</option>
        </select></div>
      </div>
      ${rule.quota_used ? `<p class="hint">Сейчас израсходовано:
        <b>${rule.quota_used.count}</b> операций${rule.quota_used.amount
          ? ' на <b>' + esc(money(rule.quota_used.amount)) + '</b>' : ''}.</p>` : ''}
      <hr style="border:none;border-top:1px solid var(--line);margin:18px 0">
      <h2>Когда срабатывает</h2>
      ${matchEditor(rule.match || {}, m)}
      <div class="row end" style="margin-top:20px">
        <button class="ghost" id="rCancel">Отмена</button>
        <button id="rSave">Сохранить</button>
      </div>`, (root) => {
      bindConditions(root, m);
      root.querySelector('#mAddCond').onclick = () => {
        root.querySelector('#mConds').insertAdjacentHTML('beforeend',
          conditionRow({field: 'amount', op: 'gt', value: ''}, m));
        bindConditions(root, m);
      };
      root.querySelector('#rCancel').onclick = closeModal;
      root.querySelector('#rSave').onclick = async () => {
        await api.post('/api/v1/rules', {
          id: rule.id, name: root.querySelector('#rName').value,
          priority: Number(root.querySelector('#rPrio').value),
          action: root.querySelector('#rAction').value,
          reason: root.querySelector('#rReason').value,
          enabled: root.querySelector('#rEnabled').checked,
          skip_limits: root.querySelector('#rSkip').checked,
          quota_window: root.querySelector('#rqWindow').value,
          quota_max_count: root.querySelector('#rqCount').value,
          quota_max_amount: root.querySelector('#rqAmount').value,
          quota_on_exceed: root.querySelector('#rqExceed').value,
          match: readMatch(root),
        });
        closeModal(); render();
      };
    });
  }

  document.getElementById('btnNewRule').onclick = () => edit(null);

  (async () => {
    const m = await m0;
    document.getElementById('simTool').innerHTML = Object.entries(m.tools)
      .map(([t, info]) => `<option value="${esc(t)}" ${t === 'transfer' ? 'selected' : ''}>${esc(info[0])} — ${esc(t)}</option>`).join('');
  })();

  document.getElementById('btnSimulate').onclick = async () => {
    const tool = document.getElementById('simTool').value;
    const amount = document.getElementById('simAmount').value;
    const recipient = document.getElementById('simRecipient').value;
    const text = document.getElementById('simText').value;
    // Имена аргументов у каждого тула свои — здесь отправляются самые ходовые
    // синонимы сразу, а разложит их по фактам сам фаервол.
    const args = {amount: Number(amount), to_account: recipient, phone: recipient,
                  expected_sum: Number(amount), description: text, text: text, query: text};
    const res = await api.post('/api/v1/simulate', {tool, args, agent: 'simulator'});
    document.getElementById('simResult').innerHTML = `
      <div class="card" style="margin:0">
        <span class="tag ${esc(res.decision)}">${esc(DECISION_RU[res.decision])}</span>
        <p style="margin:10px 0 0"><b>Причина:</b> ${esc(res.reason)}</p>
        ${res.rule ? `<p style="margin:4px 0 0"><b>Правило:</b> ${esc(res.rule)}</p>` : ''}
      </div>`;
  };

  render();
}

/* ── страница: списки ──────────────────────────────────────────────────── */
if (page === 'lists') {
  const MATCHES = {exact: 'точное совпадение', substring: 'подстрока',
                   prefix: 'начинается с', regex: 'регулярка'};

  function entryRow(e) {
    return `<div class="entry">
      <select class="e-match">${Object.entries(MATCHES).map(([v, t]) =>
        `<option value="${v}" ${e.match === v ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select>
      <input type="text" class="e-value mono" value="${esc(e.value)}" placeholder="значение">
      <input type="text" class="e-note" value="${esc(e.note || '')}" placeholder="комментарий">
      <button type="button" class="ghost sm e-del">✕</button></div>`;
  }

  async function render() {
    const {lists} = await api.get('/api/v1/lists');
    document.getElementById('listsRoot').innerHTML = lists.map(l => `
      <div class="card" data-list="${l.id}">
        <div class="row">
          <div><h2 style="margin:0">${esc(l.name)}</h2>
            <span class="muted">${esc(l.note)}</span></div>
          <div class="spacer"></div>
          <span class="tag off">${esc(l.kind)}</span>
          <button class="ghost sm" data-del-list="${l.id}">Удалить список</button>
        </div>
        <div class="entries" style="margin-top:14px">${(l.entries || []).map(entryRow).join('')}</div>
        <div class="row" style="margin-top:6px">
          <button class="ghost sm" data-add="${l.id}">+ строка</button>
          <div class="spacer"></div>
          <button data-save="${l.id}">Сохранить список</button>
        </div>
      </div>`).join('') || '<div class="card"><div class="empty">Списков пока нет.</div></div>';

    const bindEntries = (card) => card.querySelectorAll('.e-del').forEach(
      b => b.onclick = () => b.closest('.entry').remove());
    document.querySelectorAll('[data-list]').forEach(bindEntries);

    document.querySelectorAll('[data-add]').forEach(b => b.onclick = () => {
      const card = b.closest('[data-list]');
      card.querySelector('.entries').insertAdjacentHTML('beforeend',
        entryRow({match: 'exact', value: '', note: ''}));
      bindEntries(card);
    });
    document.querySelectorAll('[data-save]').forEach(b => b.onclick = async () => {
      const card = b.closest('[data-list]');
      const l = lists.find(x => x.id == b.dataset.save);
      const entries = [...card.querySelectorAll('.entry')].map(row => ({
        match: row.querySelector('.e-match').value,
        value: row.querySelector('.e-value').value,
        note: row.querySelector('.e-note').value,
      })).filter(e => e.value);
      await api.post('/api/v1/lists', {...l, entries});
      render();
    });
    document.querySelectorAll('[data-del-list]').forEach(b => b.onclick = async () => {
      if (!confirm('Удалить список? Правила, которые на него ссылаются, перестанут совпадать.')) return;
      await api.del('/api/v1/lists/' + b.dataset.delList);
      render();
    });
  }

  document.getElementById('btnNewList').onclick = async () => {
    const name = prompt('Название списка');
    if (!name) return;
    const kind = prompt('Тип: recipients, orgs, cards, text', 'recipients') || 'recipients';
    await api.post('/api/v1/lists', {name, kind, entries: [], note: ''});
    render();
  };

  render();
}

/* ── страница: лимиты ──────────────────────────────────────────────────── */
if (page === 'limits') {
  const m0 = meta();
  const WINDOWS = {tx: 'одна операция', hour: 'в час', day: 'в сутки',
                   week: 'в неделю', month: 'в месяц'};

  async function render() {
    const m = await m0;
    const {limits} = await api.get('/api/v1/limits');
    document.getElementById('limitsList').innerHTML = limits.length ? `<table><thead><tr>
        <th>Лимит</th><th style="width:150px">Окно</th><th style="width:190px">Потолок</th>
        <th style="width:140px">При превышении</th><th style="width:150px"></th>
        </tr></thead><tbody>` + limits.map(l => `<tr style="${l.enabled ? '' : 'opacity:.5'}">
        <td><b>${esc(l.name)}</b><br><span class="muted">${esc(describeMatch(l.match, m))}</span></td>
        <td>${esc(WINDOWS[l.window] || l.window)}</td>
        <td>${l.max_amount !== null ? '<b>' + esc(money(l.max_amount)) + '</b>' : ''}
            ${l.max_count !== null ? (l.max_amount !== null ? '<br>' : '') + esc(l.max_count) + ' операций' : ''}</td>
        <td><span class="tag ${esc(l.on_exceed)}">${esc(DECISION_RU[l.on_exceed])}</span></td>
        <td class="nowrap">
          <button class="ghost sm" data-edit="${l.id}">Изменить</button>
          <button class="ghost sm" data-toggle="${l.id}">${l.enabled ? 'Выкл' : 'Вкл'}</button>
          <button class="ghost sm" data-del="${l.id}">✕</button></td>
        </tr>`).join('') + '</tbody></table>'
      : '<div class="empty">Лимитов нет — потолков по сумме сейчас не существует.</div>';

    document.querySelectorAll('[data-edit]').forEach(b => b.onclick =
      () => edit(limits.find(l => l.id == b.dataset.edit)));
    document.querySelectorAll('[data-toggle]').forEach(b => b.onclick = async () => {
      const l = limits.find(x => x.id == b.dataset.toggle);
      await api.post('/api/v1/limits', {...l, enabled: !l.enabled});
      render();
    });
    document.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => {
      if (!confirm('Удалить лимит?')) return;
      await api.del('/api/v1/limits/' + b.dataset.del);
      render();
    });
  }

  async function edit(limit) {
    const m = await m0;
    limit = limit || {name: '', enabled: true, match: {kinds: ['money']}, window: 'day',
                      max_amount: null, max_count: null, on_exceed: 'deny'};
    modal(`
      <h2>${limit.id ? 'Лимит' : 'Новый лимит'}</h2>
      <div class="inline">
        <div><label>Название</label><input type="text" id="lName" value="${esc(limit.name)}"></div>
        <div><label>Окно</label><select id="lWindow">${Object.entries(WINDOWS).map(([v, t]) =>
          `<option value="${v}" ${limit.window === v ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></div>
        <div><label>При превышении</label><select id="lExceed">
          <option value="deny" ${limit.on_exceed === 'deny' ? 'selected' : ''}>Запретить</option>
          <option value="hitl" ${limit.on_exceed === 'hitl' ? 'selected' : ''}>Спросить человека</option>
        </select></div>
      </div>
      <div class="inline">
        <div><label>Потолок суммы, ₽ (пусто = без ограничения)</label>
          <input type="number" id="lAmount" step="0.01" value="${limit.max_amount ?? ''}"></div>
        <div><label>Потолок числа операций (пусто = без ограничения)</label>
          <input type="number" id="lCount" value="${limit.max_count ?? ''}"></div>
      </div>
      <div class="check"><input type="checkbox" id="lEnabled" ${limit.enabled ? 'checked' : ''}>
        <label for="lEnabled">Лимит включён</label></div>
      <hr style="border:none;border-top:1px solid var(--line);margin:18px 0">
      <h2>На что распространяется</h2>
      ${matchEditor(limit.match || {}, m)}
      <div class="row end" style="margin-top:20px">
        <button class="ghost" id="lCancel">Отмена</button>
        <button id="lSave">Сохранить</button>
      </div>`, (root) => {
      bindConditions(root, m);
      root.querySelector('#mAddCond').onclick = () => {
        root.querySelector('#mConds').insertAdjacentHTML('beforeend',
          conditionRow({field: 'recipient', op: 'in_list', value: ''}, m));
        bindConditions(root, m);
      };
      root.querySelector('#lCancel').onclick = closeModal;
      root.querySelector('#lSave').onclick = async () => {
        await api.post('/api/v1/limits', {
          id: limit.id, name: root.querySelector('#lName').value,
          enabled: root.querySelector('#lEnabled').checked,
          window: root.querySelector('#lWindow').value,
          on_exceed: root.querySelector('#lExceed').value,
          max_amount: root.querySelector('#lAmount').value,
          max_count: root.querySelector('#lCount').value,
          match: readMatch(root),
        });
        closeModal(); render();
      };
    });
  }

  document.getElementById('btnNewLimit').onclick = () => edit(null);
  render();
}

/* ── страница: видимость ───────────────────────────────────────────────── */
if (page === 'visibility') {
  document.querySelectorAll('.toolMode').forEach(sel => sel.onchange = async () => {
    await api.post(`/api/v1/tools/${sel.dataset.tool}/mode`, {mode: sel.value});
    sel.style.outline = '2px solid var(--green)';
    setTimeout(() => sel.style.outline = '', 900);
  });
}

/* ── страница: вход ────────────────────────────────────────────────────── */
if (page === 'auth') {
  const $ = (id) => document.getElementById(id);
  const say = (html, cls) => $('authMsg').innerHTML =
    `<div class="${cls || 'hint'}">${html}</div>`;
  $('authdUrl').textContent = authd.base();
  $('authdUrl2').textContent = authd.base();

  const STEPS = ['stepPhone', 'stepOtp', 'stepPassword', 'stepPin'];
  const showStep = (id) => STEPS.forEach(s => $(s).hidden = s !== id);
  const stepOf = {otp: 'stepOtp', password: 'stepPassword', pin: 'stepPin'};

  const human = (sec) => {
    if (sec === null || sec === undefined) return '—';
    if (sec < 60) return sec + ' с назад';
    if (sec < 3600) return Math.floor(sec / 60) + ' мин назад';
    return Math.floor(sec / 3600) + ' ч назад';
  };

  async function loadStatus(live) {
    let s;
    try {
      s = await authd.get('/api/auth/status' + (live ? '?live=1' : ''));
    } catch (e) {
      $('daemonHelp').hidden = false;
      $('loginCard').hidden = true;
      $('statusBody').innerHTML =
        '<span class="tag deny">демон входа недоступен</span>';
      return null;
    }
    $('daemonHelp').hidden = true;
    $('loginCard').hidden = false;
    const [label, cls] = SESSION_STATE_RU[s.state] || [s.state, 'off'];
    const tagCls = {ok: 'allow', warn: 'hitl', off: 'off', bad: 'deny'}[cls] || 'off';
    let rows = `<dl class="kv">
      <dt>Состояние</dt><dd><span class="tag ${tagCls}">${esc(label)}</span></dd>
      <dt>Файл сессии</dt><dd class="mono">${esc(s.session_file)}${s.mode ? ' · ' + esc(s.mode) : ''}</dd>`;
    if (s.exists) {
      rows += `<dt>Получена</dt><dd>${esc(human(s.age_sec))}</dd>
        <dt>Молчаливое продление</dt><dd>${s.can_silent_relogin
          ? 'доступно — повторный вход не понадобится'
          : '<b>недоступно</b> — когда токен истечёт, нужен полный вход'}</dd>`;
    }
    if (s.live) {
      rows += s.live.ok
        ? `<dt>Проверка в банке</dt><dd><span class="tag allow">отвечает</span>
             ${s.live.access_level ? ' · уровень доступа ' + esc(s.live.access_level) : ''}</dd>`
        : `<dt>Проверка в банке</dt><dd><span class="tag deny">не отвечает</span>
             <br><span class="muted mono">${esc(s.live.error)}</span></dd>`;
    }
    rows += '</dl>';
    if (s.exists) {
      rows += `<div class="row" style="margin-top:14px">
        <button class="danger sm" id="btnLogout">Удалить сессию</button></div>`;
    }
    $('statusBody').innerHTML = rows;
    $('sessFile').textContent = s.session_file;
    const lo = $('btnLogout');
    if (lo) lo.onclick = async () => {
      if (!confirm('Удалить session.json? Агент потеряет доступ к банку, потребуется вход заново.')) return;
      await authd.post('/api/auth/logout');
      showStep('stepPhone');
      say('Сессия удалена.');
      loadStatus();
    };

    // Незавершённый вход переживает перезагрузку страницы — демон помнит шаг.
    if (s.pending && s.pending.next) {
      showStep(stepOf[s.pending.next] || 'stepPhone');
      $('phoneShown').textContent = s.pending.phone || '';
    }
    sessionDot();
    return s;
  }

  const handle = (res) => {
    if (res.error && !res.ok) {
      say('❌ ' + esc(res.error), 'warn');
      if (res.restart) showStep('stepPhone');
      return false;
    }
    if (res.done) {
      showStep('stepPhone');
      say('✅ ' + esc(res.message || 'Готово.'));
      loadStatus();
      return true;
    }
    if (res.next) {
      showStep(stepOf[res.next] || 'stepPhone');
      say(esc(res.message || ''));
      return true;
    }
    say(esc(JSON.stringify(res)));
    return false;
  };

  const busy = async (btn, fn) => {
    btn.disabled = true;
    const was = btn.textContent;
    btn.textContent = '…';
    try { await fn(); } catch (e) { say('❌ ' + esc(e.message || e), 'warn'); }
    btn.disabled = false;
    btn.textContent = was;
  };

  $('btnPhone').onclick = () => busy($('btnPhone'), async () => {
    const phone = $('inPhone').value.trim();
    if (!phone) return say('Введите номер телефона.', 'warn');
    const res = await authd.post('/api/auth/login', {phone});
    $('phoneShown').textContent = res.phone || phone;
    handle(res);
  });

  const send = (kind, inputId, btnId) => busy($(btnId), async () => {
    const el = $(inputId);
    const value = el.value;
    if (!value) return say('Пустое значение.', 'warn');
    el.value = '';                       // не оставляем введённое в DOM
    handle(await authd.post('/api/auth/step', {kind, value}));
  });

  $('btnOtp').onclick = () => send('otp', 'inOtp', 'btnOtp');
  $('btnPassword').onclick = () => send('password', 'inPassword', 'btnPassword');
  $('btnPin').onclick = () => send('pin', 'inPin', 'btnPin');

  ['btnCancel', 'btnCancel2', 'btnCancel3'].forEach(id => {
    const b = $(id);
    if (b) b.onclick = async () => {
      await authd.post('/api/auth/cancel');
      showStep('stepPhone');
      say('Вход отменён.');
    };
  });

  ['inPhone', 'inOtp', 'inPassword', 'inPin'].forEach((id, i) => {
    $(id).addEventListener('keydown', (e) => {
      if (e.key === 'Enter') $(['btnPhone', 'btnOtp', 'btnPassword', 'btnPin'][i]).click();
    });
  });

  $('btnRefresh').onclick = () => loadStatus();
  $('btnCheck').onclick = () => busy($('btnCheck'), () => loadStatus(true));
  loadStatus();
}

/* ── страница: выбор банка ─────────────────────────────────────────────── */
if (page === 'choice') {
  const card = document.getElementById('choiceCard');
  const cid = card.dataset.choice;

  const send = async (body) => {
    const res = await api.post(`/api/v1/choice/${cid}/pick`, body);
    if (!res.ok) { alert(res.error || 'не удалось'); return; }
    location.reload();
  };

  document.querySelectorAll('button.bank').forEach(b => b.onclick = () => {
    b.disabled = true;
    send({index: Number(b.dataset.index)});
  });

  const cancel = document.getElementById('btnCancelChoice');
  if (cancel) cancel.onclick = () => {
    if (!confirm('Отменить перевод?')) return;
    send({cancel: true});
  };

  // Если выбор сделали с другого устройства — обновимся сами, чтобы страница
  // не показывала кнопки, которые уже ничего не решают.
  if (card.dataset.state === 'pending') {
    setInterval(async () => {
      const s = await api.get('/api/v1/choice/' + cid);
      if (s.state !== 'pending') location.reload();
    }, 5000);
  }
}

/* ── страница: настройки ───────────────────────────────────────────────── */
if (page === 'settings') {
  (async () => {
    const s = await api.get('/api/v1/settings');
    document.querySelectorAll('[data-setting]').forEach(el => {
      if (s[el.id] !== undefined) el.value = s[el.id];
    });
    document.querySelectorAll('[data-setting-check]').forEach(el => {
      el.checked = s[el.id] === '1';
    });
  })();

  document.getElementById('btnSaveSettings').onclick = async () => {
    const payload = {};
    document.querySelectorAll('[data-setting]').forEach(el => payload[el.id] = el.value);
    document.querySelectorAll('[data-setting-check]').forEach(el => payload[el.id] = el.checked ? '1' : '0');
    await api.post('/api/v1/settings', payload);
    const note = document.getElementById('settingsSaved');
    note.textContent = 'Сохранено';
    setTimeout(() => note.textContent = '', 2500);
  };
}
