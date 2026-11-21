'use strict';
// VpnGuard для Linux — веб-интерфейс. Страницы модулей строятся из описания, которое присылает сам модуль
// (поля, действия, таблицы), поэтому новый модуль появляется в меню без правок этого файла.
let DIAGNEW = true, S = null, PAGE = location.hash.slice(1) || 'home', DRAG = null, WIRE = null, SELP = '', SELC = '', OPENX = '', LASTKEY = '', MODAL = null;
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rate = b => b >= 1e6 ? (b / 1e6).toFixed(1).replace('.', ',') + ' Мбит/с' : Math.round((b || 0) / 1e3) + ' кбит/с';
const FIXED = [['home', 'Главная'], ['routes', 'Маршруты']], TAIL = [['mon', 'Мониторинг'], ['diag', 'Диагностика'], ['logs', 'Журнал'], ['updates', 'Обновления']];
let TT = 0;
function toast(t, bad) { const el = $('toast'); el.textContent = t; el.style.display = 'block'; el.style.color = bad ? 'var(--bad)' : ''; clearTimeout(TT); TT = setTimeout(() => { el.style.display = 'none'; }, bad ? 6000 : 2800); }
async function get(path) { const r = await fetch('/api/' + path, { cache: 'no-store' }); if (r.status === 401) { login(); throw new Error('нужен пароль'); } const j = await r.json(); if (j.error) throw new Error(j.error); return j.result; }
async function post(path, body, quiet) {
  try {
    const r = await fetch('/api/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-VG': '1', 'X-VG-Route-Confirm':'1' }, body: JSON.stringify(body || {}) });
    const j = await r.json(); if (j.error) throw new Error(j.error);
    if (!quiet && typeof j.result === 'string' && j.result) toast(j.result);
    await refresh(true); return j.result === undefined ? true : j.result;
  } catch (e) { toast(e.message, true); return null; }
}
function login() {
  if (MODAL) return;
  modal(`<div class="sec">Вход</div><form id="lf"><div class="field"><label for="lt">Пароль веб-интерфейса (web.token)</label><input type="password" id="lt"></div><div class="row" style="margin-top:12px"><button class="p" type="submit">Войти</button><span class="err" id="le"></span></div></form>`);
  $('lf').onsubmit = async ev => { ev.preventDefault(); const r = await fetch('/api/login', { method: 'POST', body: new URLSearchParams({ token: $('lt').value }) }); if (r.ok) { closeModal(); refresh(true); } else $('le').textContent = 'Неверный пароль'; };
}
function modal(html) { MODAL = true; $('mbody').innerHTML = html; $('modal').style.display = 'flex'; const f = $('mbody').querySelector('input,textarea,select,button'); if (f) f.focus(); }
function closeModal() { MODAL = null; $('modal').style.display = 'none'; }
$('modal').addEventListener('click', ev => { if (ev.target === $('modal')) closeModal(); });
document.addEventListener('keydown', ev => { if (ev.key === 'Escape' && MODAL) closeModal(); });
function ask(text, yes) { return new Promise(res => { modal(`<p>${esc(text)}</p><div class="row"><button class="p" id="my">${esc(yes || 'Да')}</button><button id="mn">Отмена</button></div>`); $('my').onclick = () => { closeModal(); res(true); }; $('mn').onclick = () => { closeModal(); res(false); }; }); }
function fieldHtml(f, id) {
  const v = f.value == null ? '' : f.value, o = f.options || [];
  const ctl = f.type === 'bool' ? `<select id="${id}"><option value="true"${v === 'true' ? ' selected' : ''}>да</option><option value="false"${v !== 'true' ? ' selected' : ''}>нет</option></select>`
    : f.type === 'select' ? `<select id="${id}">${(o.some(x => x.V === v) ? o : o.concat([{ V: v, T: v || '—' }])).map(x => `<option value="${esc(x.V)}"${x.V === v ? ' selected' : ''}>${esc(x.T)}</option>`).join('')}</select>`
    : f.type === 'textarea' ? `<textarea id="${id}">${esc(v)}</textarea>`
    : f.type === 'code' ? `<textarea id="${id}" class="log" spellcheck="false">${esc(v)}</textarea>`
    : f.type === 'password' ? `<input type="password" id="${id}" autocomplete="off">`
    : `<input type="text" id="${id}" value="${esc(v)}"${f.type === 'number' ? ' inputmode="numeric"' : ''}>`;
  return `<div class="field"><label for="${id}">${esc(f.title)}</label>${ctl}${f.help ? `<span class="help">${esc(f.help)}</span>` : ''}</div>`;
}
// действие модуля: подтверждение и/или форма с аргументами, затем запрос
async function runAction(modId, a, row) {
  if (modId === 'meduza' && a.id === 'locations') {
    try {
      toast('Загружаю доступные локации MeduzaVPN…');
      const action = await get('meduzalocations');
      await runAction(modId, action);
    } catch (e) { toast(e.message, true); }
    return;
  }
  const args = row ? { row: row } : {};
  if (a.args && a.args.length) {
    // форма остаётся открытой, пока действие не выполнено: при ошибке (например, в конфигурации) правки не теряются
    modal(`<div class="sec">${esc(a.title)}</div>${a.confirm ? `<p class="sub">${esc(a.confirm)}</p>` : ''}<form id="af"${a.args.some(f => f.type === 'code') ? ' class="wide"' : ''}><div class="form" style="grid-template-columns:1fr">${a.args.map((f, i) => fieldHtml(f, 'aa' + i)).join('')}</div><div class="row" style="margin-top:12px"><button class="p" type="submit">Выполнить</button><button type="button" id="ac">Отмена</button><span class="err" id="ae"></span></div></form>`);
    $('ac').onclick = () => closeModal();
    $('af').onsubmit = async ev => {
      ev.preventDefault(); a.args.forEach((f, i) => { args[f.key] = $('aa' + i).value; });
      const b = $('af').querySelector('button[type=submit]'); b.disabled = true; $('ae').textContent = 'Выполняется…';
      const r = await post('do', { module: modId, action: a.id, args: args });
      if (r === null) { b.disabled = false; $('ae').textContent = document.getElementById('toast').textContent; return; }
      closeModal(); refresh(true);
    };
    return;
  } else if (a.confirm && !(await ask(a.confirm, a.title))) return;
  await post('do', { module: modId, action: a.id, args: args });
}
const M = id => S.modules.find(m => m.id === id);
function busyUI() { const a = document.activeElement, selection = window.getSelection(); return MODAL || DRAG || WIRE || (selection && !selection.isCollapsed) || (a && $('page').contains(a) && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)); }
async function refresh(force) {
  try { S = await get('state'); } catch (e) { $('agent').textContent = 'нет связи с агентом'; $('adot').className = 'dot l2'; return; }
  const pending = S.routes.pending;
  if (pending && pending.status === 'awaiting_confirmation' && pending.requester === S.clientIP) {
    try {
      const ack = await fetch('/api/routeconfirm', {method:'POST',headers:{'Content-Type':'application/json','X-VG':'1'},body:JSON.stringify({id:pending.id})});
      const result = await ack.json();
      if (result.ok) S.routes.pending = null;
    } catch (_) { /* Без отдельного ответа таймер восстановит прежние маршруты. */ }
  }
  $('ver').textContent = 'Linux · ' + S.version; $('simnote').hidden = !S.sim;
  $('adot').className = 'dot l' + S.hero.level; $('agent').textContent = 'агент на связи · ' + S.time;
  const items = FIXED.concat(S.modules.filter(m => m.page).map(m => [m.id, m.name, m.status.level])).concat([null]).concat(TAIL);
  const navHtml = items.map(x => x ? `<a href="#${x[0]}" class="${x[0] === PAGE ? 'sel' : ''}">${esc(x[1])}${x[0] === 'routes' ? ' <span class="new">новое</span>' : x.length > 2 ? ` <span class="dot ${x[2] >= 0 ? 'l' + x[2] : ''}"></span>` : ''}</a>` : '<hr>').join('');
  if ($('navitems').dataset.html !== navHtml && (force || !busyUI())) { $('navitems').innerHTML = navHtml; $('navitems').dataset.html = navHtml; }
  if (force || !busyUI()) render();
}
window.addEventListener('hashchange', () => { PAGE = location.hash.slice(1) || 'home'; LASTKEY = ''; LASTPAGE = ''; DIAGNEW = true; $('nav').classList.remove('open'); if (S) refresh(true); });
function render() {
  if (!S) return;
  const all = FIXED.concat(TAIL).concat(S.modules.map(m => [m.id, m.name]));
  $('title').textContent = (all.find(x => x[0] === PAGE) || ['', 'Главная'])[1];
  const fn = { home: pHome, routes: pRoutes, mon: pMon, diag: pDiag, logs: pLogs, updates: pUpdates }[PAGE] || (M(PAGE) ? pModule : pHome);
  fn();
}
const hero = (lvl, title, text, extra) => `<div class="card hero st${lvl}"><div class="hero"><div><div class="big st${lvl}"><span class="dot ${lvl >= 0 ? 'l' + lvl : ''}"></span>${esc(title)}</div><div class="sub" style="margin-top:6px">${esc(text || '')}</div></div>${extra || ''}</div></div>`;
const decisions = n => `<pre class="lgv" style="margin:0">${S.decisions.slice(-n).reverse().map(l => `<span class="${l.lvl === 'ERROR' ? 'le' : l.lvl === 'WARN' ? 'lw' : 'li'}">${l.t}  ${esc(l.text)}</span>`).join('') || '<span class="li">Решений пока нет</span>'}</pre>`;
let LASTHTML = '', LASTPAGE = '';
function setHtml(html, key) {
  if ((key && key === LASTKEY) || (LASTPAGE === PAGE && LASTHTML === html)) return false;
  const open = new Map(Array.from($('page').querySelectorAll('details[data-details-key]'), el => [el.dataset.detailsKey, el.open]));
  LASTKEY = key || ''; LASTHTML = html; LASTPAGE = PAGE;
  $('page').innerHTML = html;
  $('page').querySelectorAll('details[data-details-key]').forEach(el => { if (open.has(el.dataset.detailsKey)) el.open = open.get(el.dataset.detailsKey); });
  return true;
}

// ---------------------------------------------------------------- главная
function pHome() {
  const cl = S.routes.clients, on = cl.filter(c => c.on).length, inet = M('inet');
  const prov = inet ? `<div class="card row"><span class="dot l${inet.status.level}"></span><b>Провайдер: ${esc(inet.status.state)}</b>${inet.status.kv.map(k => `<span class="sub">${esc(k[0])}: ${esc(k[1])}</span>`).join('')}${inet.status.why ? `<span class="sub">${esc(inet.status.why)}</span>` : ''}<a href="#diag" class="sub" style="margin-left:auto">проверки системы →</a></div>` : '';
  setHtml(hero(S.hero.level, S.hero.title, S.hero.text || `Клиентов на связи: ${on} из ${cl.length} · профилей: ${S.routes.profiles.length}`) + prov +
    `<div class="grid">${S.modules.filter(m => m.id !== 'inet' && !m.aux).map(m => `<div class="tile" onclick="location.hash='${m.page ? m.id : 'routes'}'" tabindex="0"><div class="t"><span class="dot ${m.status.level >= 0 ? 'l' + m.status.level : ''}"></span>${esc(m.name)}</div><div class="s">${esc(m.status.busy ? '⟳ ' + m.status.busy : m.status.state)}</div><div class="d">${esc(m.status.why || (m.metrics.rx ? '↓ ' + rate(m.metrics.rx) : ''))}</div></div>`).join('')}</div>
    <div class="sec">Клиенты WG-Server</div><div class="card"><table><tr><th>Клиент</th><th>Адрес</th><th>Профиль</th><th>Состояние</th><th>Скорость ↓</th></tr>
    ${cl.map(c => `<tr><td>${esc(c.name)}</td><td>${c.ip}</td><td>${esc((S.routes.profiles.find(p => p.id === c.profile) || {}).name)}${c.overrides.length ? ' + свои правила: ' + c.overrides.length : ''}</td><td class="${c.on ? 'c0' : 'c-1'}">${c.off ? 'отключён' : c.on ? 'на связи' : esc(c.seen)}</td><td>${c.on ? rate(c.tx) : '—'}</td></tr>`).join('')}</table></div>
    <div class="sec">Журнал решений</div><div class="card">${decisions(12)}</div>`);
}
// ---------------------------------------------------------------- страница модуля (строится из описания модуля)
// блок модуля: таблица, текст (конфигурация, журнал) и/или картинка (QR-код); ti — номер блока в m.tables
function blockHtml(t, ti) {
  const note = t.note ? `<p class="sub" style="margin:0 0 8px">${esc(t.note)}</p>` : '';
  let body;
  if (t.text || t.img) body = `<div class="row" style="align-items:flex-start;gap:16px">${t.img ? `<img class="qr" src="${esc(t.img)}" alt="QR-код">` : ''}<div class="grow" style="min-width:260px">${t.text ? `<pre style="margin:0" id="bt${ti}">${esc(t.text)}</pre>` : ''}${t.file ? `<div class="row" style="margin-top:8px"><button type="button" data-copy="${ti}">Скопировать</button><button type="button" data-dl="${ti}">Скачать ${esc(t.file)}</button></div>` : ''}</div></div>`;
  else if (!t.rows || !t.rows.length) body = `<span class="muted">${esc(t.empty || 'Пусто')}</span>`;
  else body = `<table><tr>${t.cols.map(c => `<th>${esc(c)}</th>`).join('')}${t.actions ? '<th></th>' : ''}</tr>${t.rows.map(r => `<tr>${r.map((c, ci) => `<td class="${String(c).length > 60 ? 'wrap' : ''}">${ci === 0 ? '<b>' + esc(c) + '</b>' : esc(c)}</td>`).join('')}${t.actions ? `<td class="act">${t.actions.map((a, ai) => `<button type="button" class="sq${a.danger ? ' bad' : ''}" data-ta="${ti}:${ai}" data-row="${esc(r[0])}">${esc(a.title)}</button>`).join('')}</td>` : ''}</tr>`).join('')}</table>`;
  return `<div class="sec">${esc(t.title)}</div><div class="card">${note}${body}</div>`;
}
// настройки модуля: поля одной группы — отдельный блок с заголовком группы
function fieldsHtml(m, pre, title) {
  const groups = [];
  (m.fields || []).forEach((f, i) => { const g = f.group || title || 'Настройки'; let x = groups.find(y => y.g === g); if (!x) groups.push(x = { g, h: [] }); x.h.push(fieldHtml(f, (pre || 'mf') + i)); });
  return groups.map(x => `<div class="sec">${esc(x.g)}</div><div class="card"><div class="form">${x.h.join('')}</div></div>`).join('');
}
// кнопки, таблицы, копирование, скачивание и поля модуля внутри root (страница модуля или его блок на другой странице)
function bindModule(m, root, pre) {
  root = root || $('page'); pre = pre || 'mf';
  root.querySelectorAll('[data-ma]').forEach(b => { b.onclick = () => runAction(m.id, m.actions[+b.dataset.ma]); });
  root.querySelectorAll('[data-ta]').forEach(b => { b.onclick = () => { const [ti, ai] = b.dataset.ta.split(':'); runAction(m.id, m.tables[+ti].actions[+ai], b.dataset.row); }; });
  root.querySelectorAll('[data-copy]').forEach(b => { b.onclick = () => navigator.clipboard.writeText(m.tables[+b.dataset.copy].text).then(() => toast('Скопировано'), () => toast('Браузер не дал скопировать — выделите текст вручную', true)); });
  root.querySelectorAll('[data-dl]').forEach(b => { b.onclick = () => { const t = m.tables[+b.dataset.dl], a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([t.text], { type: 'text/plain' })); a.download = t.file; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000); }; });
  (m.fields || []).forEach((f, i) => { const el = $(pre + i); if (el) el.onchange = ev => { ev.target.blur(); post('set', { module: m.id, key: f.key, value: ev.target.value }); }; });
}
// модуль без своей вкладки — блоком на другой странице: состояние, кнопки, блоки, настройки
function moduleBlock(m) {
  const st = m.status, pre = 'x' + m.id;
  return `<div data-mod="${m.id}"><div class="sec">${esc(m.name)}</div><div class="card"><div class="row"><span class="dot ${st.level >= 0 ? 'l' + st.level : ''}"></span><b>${esc(st.state)}</b>${st.why ? `<span class="sub">${esc(st.why)}</span>` : ''}</div>` +
    (st.kv.length ? `<table class="kv" style="margin-top:8px">${st.kv.map(k => `<tr><td>${esc(k[0])}</td><td>${esc(k[1])}</td></tr>`).join('')}</table>` : '') +
    (m.actions && m.actions.length ? `<div class="row" style="margin-top:10px">${m.actions.map((a, i) => `<button type="button" class="${a.danger ? 'bad' : ''}" data-ma="${i}">${esc(a.title)}</button>`).join('')}</div>` : '') + '</div>' +
    (m.tables || []).map((t, ti) => blockHtml(t, ti)).join('') + fieldsHtml(m, pre, 'Настройки: ' + m.name) + '</div>';
}
function pModule() {
  const m = M(PAGE), st = m.status, tb = (m.tables || []).map((t, ti) => [t, ti]);
  const top = tb.filter(x => x[0].top).map(x => blockHtml(x[0], x[1])).join(''), rest = tb.filter(x => !x[0].top).map(x => blockHtml(x[0], x[1])).join('');
  const html = hero(st.level, st.busy ? 'Выполняется: ' + st.busy : st.state, st.why) +
    (st.kv.length ? `<div class="card"><table class="kv">${st.kv.map(k => `<tr><td>${esc(k[0])}</td><td>${esc(k[1])}</td></tr>`).join('')}</table></div>` : '') + top +
    (m.actions && m.actions.length ? `<div class="sec">Управление</div><div class="row">${m.actions.map((a, i) => `<button type="button" class="${a.danger ? 'bad' : ''}" data-ma="${i}">${esc(a.title)}</button>`).join('')}</div>` : '') +
    (m.fieldsTop ? fieldsHtml(m) + rest : rest + fieldsHtml(m));
  if (!setHtml(html, PAGE + JSON.stringify([st, m.tables, m.fields, m.actions]))) return;
  bindModule(m);
}
// ---------------------------------------------------------------- маршруты
function RT() { // рабочая копия маршрутов в том виде, в каком её принимает сервер
  const r = S.routes, strip = x => ({ id: x.id, title: x.title, preset: x.preset || '', match: x.match || '', exit: x.exit, last: !!x.last });
  const out = { profiles: r.profiles.map(p => ({ id: p.id, name: p.name, rules: p.rules.map(strip) })), clients: {}, overrides: {}, policy: {} };
  r.clients.forEach(c => { out.clients[c.ip] = c.profile; if (c.overrides.length) out.overrides[c.ip] = c.overrides.map(strip); });
  r.exits.forEach(e => { if (e.policy) out.policy[e.id] = { reserve: e.reserve || '', ifDown: e.ifDown || 'block' }; });
  return out;
}
const saveRT = (rt, quiet) => post('routes', { routes: rt }, quiet);
const uid = p => p + Date.now().toString(36) + Math.floor(Math.random() * 99);
const xopts = (cur, skip, none) => (none ? `<option value=""${cur ? '' : ' selected'}>нет</option>` : '') + S.routes.exits.filter(e => e.id !== skip).map(e => `<option value="${e.id}"${e.id === cur ? ' selected' : ''}>${esc(e.name)}</option>`).join('');
function ruleList() { // правила клиента (если выбран) стоят выше правил профиля
  const P = S.routes.profiles.find(p => p.id === SELP) || S.routes.profiles[0], c = S.routes.clients.find(x => x.ip === SELC && x.profile === P.id);
  return { P, c, list: (c ? c.overrides.map((r, i) => ({ r, sc: 'o', i })) : []).concat(P.rules.map((r, i) => ({ r, sc: 'p', i }))) };
}
function pRoutes() {
  const R = S.routes; if (!R.profiles.some(p => p.id === SELP)) SELP = R.profiles[0].id;
  const { P, c, list } = ruleList(), mine = R.clients.filter(x => x.profile === P.id);
  if (!c) SELC = '';
  const whys = [...new Set(R.profiles.flatMap(p => R.clients.some(x => x.profile === p.id) ? p.rules.filter(r => r.why).map(r => p.name + ': ' + r.why) : []))];
  const lvl = whys.length ? (R.profiles.some(p => p.rules.some(r => r.state === 'bad')) ? 2 : 1) : 0;
  const tiles = R.profiles.map(p => `<div class="tile${p.id === P.id ? ' sel' : ''}" data-selp="${p.id}" data-drop="${p.id}" tabindex="0" role="button"><div class="t">Профиль · правил: ${p.rules.length}</div><div class="s">${esc(p.name)}</div>
    <div class="chips">${R.clients.filter(x => x.profile === p.id).map(x => `<span class="chip${x.on ? '' : ' off'}${x.ip === SELC ? ' sel' : ''}" draggable="true" data-drag="client" data-ip="${x.ip}" title="${x.ip} · перетащите в другой профиль; щелчок — свои правила клиента"><span class="dot ${x.on ? 'l0' : ''}"></span>${esc(x.name)}${x.overrides.length ? ' ●' : ''}</span>`).join('') || '<span class="n3">нет клиентов — перетащите сюда</span>'}</div></div>`).join('');
  const rules = list.map((x, k) => { const r = x.r, n = list.filter(y => y.sc === x.sc).length, fixed = r.last;
    return `<div class="fnode rule${x.sc === 'o' ? ' ov' : ''}" data-rule="${k}"><div class="row rhead">${fixed ? '' : `<span class="grip" draggable="true" data-drag="rule" data-k="${k}" title="Перетащите, чтобы изменить порядок">⠿</span>`}<span class="num">${k + 1}</span>
      <div class="grow"><div class="n1">${esc(r.title)}</div><div class="n3">${x.sc === 'o' ? 'только ' + esc(c.name) + ' · ' : ''}${r.last ? 'правило по умолчанию' : esc(r.preset ? (R.presets.find(p => p.id === r.preset) || {}).match : r.match)}</div></div>
      ${fixed ? '' : `<button type="button" class="sq" data-mv="${k}:-1" aria-label="Поднять"${x.i === 0 ? ' disabled' : ''}>↑</button><button type="button" class="sq" data-mv="${k}:1" aria-label="Опустить"${x.i >= n - (x.sc === 'p' ? 2 : 1) ? ' disabled' : ''}>↓</button><button type="button" class="sq bad" data-del="${k}" aria-label="Удалить правило">×</button>`}</div>
      <div class="row"><label class="lbl" for="rx${k}">Выход</label><select id="rx${k}" data-rx="${k}">${xopts(r.exit)}</select></div>${r.why ? `<div class="note ${r.state}">${esc(r.why)}</div>` : ''}<span class="port" data-port="${k}" title="Потяните к узлу справа, чтобы сменить выход"></span></div>`; }).join('');
  const exits = R.exits.map(e => `<div class="fnode xnode${e.up ? '' : ' down'}" data-exit="${e.id}" style="--xc:${e.color}"><div class="row"><span class="dot ${e.level >= 0 ? 'l' + e.level : ''}"></span><span class="n1 grow">${esc(e.name)}</span>
    ${e.policy ? `<button type="button" class="sq" data-xedit="${e.id}" title="Резерв и поведение при сбое" aria-label="Настройки выхода">✎</button>${M(e.id)?.page ? `<a href="#${e.id}" class="n3" title="Открыть страницу модуля">модуль →</a>` : ''}` : ''}</div>
    <div class="n3">${esc(e.state)}${e.why ? ' · ' + esc(e.why) : ''}</div>${e.policy ? `<div class="n3">резерв: ${esc((R.exits.find(x => x.id === e.reserve) || { name: 'нет' }).name)} · если всё упало: ${e.ifDown === 'direct' ? 'напрямую' : 'блокировать'}</div>` : ''}
    ${OPENX === e.id ? `<div class="row"><div class="field"><label for="xr">Резерв</label><select id="xr" data-pol="${e.id}:reserve">${xopts(e.reserve, e.id, true)}</select></div><div class="field"><label for="xd">Если всё упало</label><select id="xd" data-pol="${e.id}:ifDown"><option value="block"${e.ifDown !== 'direct' ? ' selected' : ''}>блокировать</option><option value="direct"${e.ifDown === 'direct' ? ' selected' : ''}>напрямую</option></select></div></div>` : ''}</div>`).join('');
  const extra = (S.routeResources || []).filter(r => r.priority && Number(r.table) >= 103 && Number(r.table) <= 199);
  const assignments = extra.length ? '<div class="card"><div class="sec">Назначения дополнительных VPN</div><table><tr><th>Выход</th><th>Метка</th><th>Таблица</th><th>Приоритет</th></tr>' +
    extra.map(r => `<tr><td>${esc(M(r.owner)?.name || r.owner)}</td><td>0x${r.mark.toString(16)}</td><td>${esc(r.table)}</td><td>${r.priority}</td></tr>`).join('') + '</table></div>' : '';
  const key = 'routes' + JSON.stringify([extra, S.routeResourceError, R.profiles, R.clients.map(x => [x.ip, x.name, x.on, x.profile, x.overrides]), R.exits, SELP, SELC, OPENX, R.canRollback]);
  const done = setHtml(hero(lvl, ['Все маршруты работают', 'Есть предупреждения', 'Часть трафика заблокирована'][lvl], whys.join(' · ') || 'Последнее применение правил: ' + (R.applyInfo || 'ещё не применялись'),
      `<div class="row"><button type="button" id="bnft">Показать правила nftables</button>${R.canRollback ? '<button type="button" id="brb">Откатить последнее изменение</button>' : ''}</div>`) +
    (S.routeResourceError ? '<div class="card err">' + esc(S.routeResourceError) + '</div>' : '') + assignments +
    `<div class="sec">Профили и клиенты</div><div class="profiles">${tiles}</div>
    <form class="row" id="fprof" style="margin-top:10px"><label class="lbl" for="npn">Новый профиль</label><input type="text" id="npn" placeholder="Гости"><button type="submit">+ Создать профиль</button></form>
    <div class="sec">Схема профиля</div><div class="card"><div class="row" style="margin-bottom:12px"><div class="field"><label for="pname">Название профиля</label><input type="text" id="pname" value="${esc(P.name)}"></div>
      <span class="sub grow">Правила проверяются сверху вниз, срабатывает первое подходящее. ⠿ — порядок, кружок справа — выход. Щёлкните клиента, чтобы задать ему свои правила поверх профиля.</span>
      <button type="button" id="bdelp"${R.profiles.length < 2 ? ' disabled' : ''}>Удалить профиль</button></div>
      <div id="flowhost"><div class="scheme" id="scheme"><svg id="wires" aria-hidden="true"></svg>
        <div class="col"><div class="fglh">Откуда</div><div class="fnode" id="me" style="margin-top:30px"><div class="n1">${esc(c ? c.name : P.name)}</div><div class="n3">${c ? c.ip + ' · свои правила + профиль' : 'клиентов: ' + mine.length + ' · на связи: ' + mine.filter(x => x.on).length}</div>
          <div class="chips">${mine.map(x => `<span class="chip${x.ip === SELC ? ' sel' : ''}" data-selc="${x.ip}" role="button" tabindex="0"><span class="dot ${x.on ? 'l0' : ''}"></span>${esc(x.name)}</span>`).join('') || '<span class="n3">пока никого</span>'}</div></div></div>
        <div class="col"><div class="fglh">Правила</div>${rules}
          <form class="fnode add" id="frule"><div class="row"><div class="field"><label for="nrw">Какой трафик</label><select id="nrw">${R.presets.map(p => `<option value="${p.id}">${esc(p.title)}</option>`).join('')}<option value="">Свой список</option></select></div>
            <div class="field"><label for="nrx">Куда</label><select id="nrx">${xopts('meduza')}</select></div>
            <div class="field"><label for="nrs">Для кого</label><select id="nrs"><option value="p">весь профиль</option>${c ? `<option value="o" selected>только ${esc(c.name)}</option>` : ''}</select></div></div>
            <div class="row" id="nrbox" hidden><div class="field"><label for="nrt">Название</label><input type="text" id="nrt" placeholder="Мои сайты"></div><div class="field grow"><label for="nrm">Домены, адреса, сети, порты через запятую</label><input type="text" id="nrm" placeholder="example.org, 203.0.113.0/24, udp:27000-27100" style="width:100%"></div></div>
            <div class="row"><button type="submit" class="p">+ Добавить правило</button><span class="err" id="nre"></span></div></form></div>
        <div class="col"><div class="fglh">Куда · узлы-выходы</div>${exits}</div></div></div></div>
    <div class="sec">Журнал решений</div><div class="card">${decisions(8)}</div>`, key);
  if (!done) return;
  requestAnimationFrame(wires);
  const pg = $('page'), q = (s, f) => pg.querySelectorAll(s).forEach(f);
  $('bnft').onclick = async () => { const r = await get('nft'); modal(`<div class="sec">Правила nftables и маршруты</div><pre>${esc(r.script)}\n# ip:\n${esc((r.ip || []).map(x => 'ip ' + x.join(' ')).join('\n'))}</pre><button type="button" onclick="closeModal()">Закрыть</button>`); };
  if ($('brb')) $('brb').onclick = () => post('rollback');
  q('[data-selp]', t => { t.onclick = ev => { const ch = ev.target.closest('.chip'); SELP = t.dataset.selp; SELC = ch ? (SELC === ch.dataset.ip ? '' : ch.dataset.ip) : ''; LASTKEY = ''; render(); }; });
  q('[data-selc]', t => { t.onclick = () => { SELC = SELC === t.dataset.selc ? '' : t.dataset.selc; render(); }; });
  q('[data-xedit]', b => { b.onclick = () => { OPENX = OPENX === b.dataset.xedit ? '' : b.dataset.xedit; render(); }; });
  q('[data-pol]', s => { s.onchange = () => { const [id, k] = s.dataset.pol.split(':'), rt = RT(); rt.policy[id][k] = s.value; s.blur(); saveRT(rt); }; });
  const at = (rt, k) => { const x = list[k]; return x.sc === 'o' ? rt.overrides[SELC] : rt.profiles.find(p => p.id === P.id).rules; };
  q('[data-rx]', s => { s.onchange = () => { const k = +s.dataset.rx, rt = RT(); at(rt, k)[list[k].i].exit = s.value; s.blur(); saveRT(rt); }; });
  q('[data-del]', b => { b.onclick = () => { const k = +b.dataset.del, rt = RT(); at(rt, k).splice(list[k].i, 1); if (rt.overrides[SELC] && !rt.overrides[SELC].length) delete rt.overrides[SELC]; saveRT(rt); }; });
  q('[data-mv]', b => { b.onclick = () => { const [k, d] = b.dataset.mv.split(':').map(Number), rt = RT(), a = at(rt, k), i = list[k].i; a.splice(i + d, 0, a.splice(i, 1)[0]); saveRT(rt, true); }; });
  $('pname').onchange = ev => { const rt = RT(); rt.profiles.find(p => p.id === P.id).name = ev.target.value.trim(); ev.target.blur(); saveRT(rt); };
  $('bdelp').onclick = async () => { if (!(await ask(`Удалить профиль «${P.name}»? Его клиенты перейдут в первый из оставшихся профилей.`, 'Удалить'))) return; const rt = RT(); rt.profiles = rt.profiles.filter(p => p.id !== P.id); Object.keys(rt.clients).forEach(ip => { if (rt.clients[ip] === P.id) rt.clients[ip] = rt.profiles[0].id; }); SELP = ''; saveRT(rt); };
  $('fprof').onsubmit = ev => { ev.preventDefault(); const name = $('npn').value.trim(); if (!name) return toast('Введите название профиля', true); const rt = RT(), id = uid('p'); rt.profiles.push({ id: id, name: name, rules: [{ id: uid('r'), title: 'Всё остальное', exit: 'meduza', last: true }] }); SELP = id; document.activeElement.blur(); saveRT(rt); };
  $('nrw').onchange = () => { $('nrbox').hidden = $('nrw').value !== ''; };
  $('frule').onsubmit = ev => { ev.preventDefault(); const pre = $('nrw').value, rt = RT(), sc = $('nrs').value;
    const rule = { id: uid('r'), exit: $('nrx').value, preset: pre, title: pre ? R.presets.find(p => p.id === pre).title : ($('nrt').value.trim() || 'Свой список'), match: pre ? '' : $('nrm').value.trim() };
    if (!pre && !rule.match) { $('nre').textContent = 'Введите хотя бы один домен, адрес или порт'; return; }
    if (sc === 'o') (rt.overrides[SELC] = rt.overrides[SELC] || []).push(rule); else { const a = rt.profiles.find(p => p.id === P.id).rules; a.splice(a.length - 1, 0, rule); }
    document.activeElement.blur(); saveRT(rt); };
}
function curve(x1, y1, x2, y2) { const m = (x1 + x2) / 2; return `M${x1} ${y1} C${m} ${y1} ${m} ${y2} ${x2} ${y2}`; }
function wires() {
  const svg = $('wires'); if (!svg || PAGE !== 'routes') return;
  const box = $('scheme').getBoundingClientRect(), me = $('me').getBoundingClientRect(), { P, list } = ruleList();
  const live = S.routes.clients.some(x => x.profile === P.id && x.on); let out = '';
  list.forEach((x, k) => {
    const re = document.querySelector(`[data-rule="${k}"]`), port = document.querySelector(`[data-port="${k}"]`), xe = document.querySelector(`[data-exit="${x.r.eff}"]`); if (!re || !port || !xe) return;
    const a = re.getBoundingClientRect(), pt = port.getBoundingClientRect(), b = xe.getBoundingClientRect(), col = (S.routes.exits.find(e => e.id === x.r.eff) || {}).color;
    const px = pt.left + pt.width / 2 - box.left, py = pt.top + pt.height / 2 - box.top;
    out += `<path d="${curve(me.right - box.left, me.top + 24 - box.top, a.left - box.left, a.top + a.height / 2 - box.top)}" fill="none" stroke="var(--border)" stroke-width="1.5"/>`;
    if (x.r.eff !== x.r.exit) { const o = document.querySelector(`[data-exit="${x.r.exit}"]`); if (o) { const ob = o.getBoundingClientRect(); out += `<path d="${curve(px, py, ob.left - box.left, ob.top + 20 - box.top)}" fill="none" stroke="var(--bad)" stroke-width="1" stroke-dasharray="4 5" opacity=".7"/>`; } }
    const d = curve(px, py, b.left - box.left, b.top + 20 - box.top);
    out += `<path d="${d}" fill="none" stroke="${col}" stroke-width="${x.r.state === 'ok' ? 1.5 : 2.5}" opacity=".45"/>` + (x.r.eff !== 'block' && live ? `<path class="flowline" d="${d}" fill="none" stroke="${col}" stroke-width="3"/>` : '');
  });
  svg.innerHTML = out + '<path id="tmpw" fill="none" stroke="var(--ok)" stroke-width="2" stroke-dasharray="6 4"/>';
}
window.addEventListener('resize', wires);
document.addEventListener('dragstart', ev => { const d = ev.target.closest && ev.target.closest('[data-drag]'); if (!d) return; DRAG = { type: d.dataset.drag, ip: d.dataset.ip, k: +d.dataset.k }; ev.dataTransfer.effectAllowed = 'move'; try { ev.dataTransfer.setData('text/plain', 'vg'); if (DRAG.type === 'rule') ev.dataTransfer.setDragImage(d.closest('.rule'), 20, 20); } catch (e) {} });
function dropTarget(ev) { if (!DRAG) return null; if (DRAG.type === 'client') return ev.target.closest('[data-drop]'); const r = ev.target.closest('[data-rule]'), l = ruleList().list; return r && +r.dataset.rule !== DRAG.k && l[+r.dataset.rule].sc === l[DRAG.k].sc ? r : null; }
document.addEventListener('dragover', ev => { const t = dropTarget(ev); document.querySelectorAll('.over').forEach(e => { if (e !== t) e.classList.remove('over'); }); if (t) { ev.preventDefault(); t.classList.add('over'); } });
document.addEventListener('drop', ev => {
  const t = dropTarget(ev); if (!t) return; ev.preventDefault(); const rt = RT(), d = DRAG; DRAG = null;
  if (d.type === 'client') { if (rt.clients[d.ip] === t.dataset.drop) return; rt.clients[d.ip] = t.dataset.drop; SELP = t.dataset.drop; SELC = ''; saveRT(rt); return; }
  const { P, list } = ruleList(), x = list[d.k], a = x.sc === 'o' ? rt.overrides[SELC] : rt.profiles.find(p => p.id === P.id).rules; let to = list[+t.dataset.rule].i; const r = a.splice(x.i, 1)[0];
  if (x.i < to) to--; if (x.sc === 'p') to = Math.min(to, a.length - 1); a.splice(to, 0, r); saveRT(rt, true);
});
document.addEventListener('dragend', () => { DRAG = null; document.querySelectorAll('.over').forEach(e => e.classList.remove('over')); });
document.addEventListener('pointerdown', ev => { const p = ev.target.closest && ev.target.closest('.port'); if (!p) return; ev.preventDefault(); const b = p.getBoundingClientRect(); WIRE = { k: +p.dataset.port, x: b.left + b.width / 2, y: b.top + b.height / 2 }; });
document.addEventListener('pointermove', ev => {
  if (!WIRE) return; const box = $('scheme').getBoundingClientRect(), tmp = $('tmpw'); if (tmp) tmp.setAttribute('d', curve(WIRE.x - box.left, WIRE.y - box.top, ev.clientX - box.left, ev.clientY - box.top));
  const el = document.elementFromPoint(ev.clientX, ev.clientY), x = el && el.closest('[data-exit]'); document.querySelectorAll('.hot').forEach(e => { if (e !== x) e.classList.remove('hot'); }); if (x) x.classList.add('hot');
});
document.addEventListener('pointerup', ev => {
  if (!WIRE) return; const el = document.elementFromPoint(ev.clientX, ev.clientY), x = el && el.closest('[data-exit]'), k = WIRE.k; WIRE = null;
  const { P, list } = ruleList(), it = list[k]; if (!x || !it || it.r.exit === x.dataset.exit) { LASTKEY = ''; render(); return; }
  const rt = RT(); (it.sc === 'o' ? rt.overrides[SELC] : rt.profiles.find(p => p.id === P.id).rules)[it.i].exit = x.dataset.exit; saveRT(rt);
});
// ---------------------------------------------------------------- мониторинг
function networkTelemetryHtml() {
  const n = S.networkTelemetry; if (!n) return '';
  const ms = v => typeof v === 'number' && Number.isFinite(v) ? v.toFixed(1).replace('.', ',') : '—';
  const count = v => v == null ? '—' : Number(v).toLocaleString('ru-RU');
  const stamp = at => at ? new Date(at * 1000).toLocaleTimeString('ru-RU') : 'ожидается';
  const now = Date.now() / 1000, c = n.counters || {}, fresh = c.at && now - c.at <= 20 && n.countersCurrent !== false && !c.error;
  return `<div class="sec">Качество соединений</div><div class="card"><p class="sub">Пять ICMP-пакетов примерно раз в 30 с. RTT — среднее время ответа, ΔRTT — среднее абсолютное изменение между соседними ответами. Потери относятся к ICMP до указанного адреса и не доказывают сбой приложений.</p>${n.qualityEnabled === false ? '<p class="sub">ICMP-измерения выключены в настройках диагностики.</p>' : `<table><tr><th>Путь / адрес</th><th>RTT, мс</th><th>ΔRTT, мс</th><th>Потери</th><th>Ответы</th><th>Измерено</th></tr>${(n.quality || []).map(q => { const fresh = now - q.at <= 45; return `<tr><td>${esc(q.title)}<div class="sub">${esc(q.iface)} → ${esc(q.target)}</div>${q.error ? `<div class="sub">${esc(q.error)}</div>` : ''}</td><td>${fresh ? ms(q.rtt) : '—'}</td><td>${fresh ? ms(q.jitter) : '—'}</td><td>${fresh && q.loss != null ? ms(q.loss) + '%' : '—'}</td><td>${q.loss != null ? count(q.received) + ' / ' + count(q.sent) : '—'}</td><td>${esc(stamp(q.at))}${fresh ? '' : '<div class="sub">устарело</div>'}</td></tr>`; }).join('') || '<tr><td colspan="6" class="sub">Ожидается первая серия измерений.</td></tr>'}</table>`}</div>` +
    `<div class="sec">Счётчики правил</div><div class="card"><details class="dev-stage" data-details-key="rule-counters"><summary>Срабатывания правил · ${esc(stamp(c.at))}</summary><p class="sub">Пакеты и байты с момента применения правил. Это счётчики классификации: закреплённые соединения проходят до неё. При новом применении счётчики могут сбрасываться. Отсутствующий счётчик показан прочерком.</p>${c.applied ? `<p class="sub">Применение: ${esc(c.applied)}</p>` : ''}${c.error ? `<p class="c2">${esc(c.error)}</p>` : ''}${!fresh ? '<p class="sub">Ожидаются свежие счётчики.</p>' : ''}<table><tr><th>Правило</th><th>Пакеты</th><th>Байты</th></tr>${(c.rows || []).map(r => `<tr><td>${esc(r.title)}</td><td>${fresh ? count(r.packets) : '—'}</td><td>${fresh ? count(r.bytes) : '—'}</td></tr>`).join('')}</table>${c.truncated ? '<p class="sub">Показаны первые 256 правил.</p>' : ''}</details></div>`;
}
async function pMon() {
  let h; try { h = await get('history'); } catch (e) { return; } if (PAGE !== 'mon' || busyUI()) return;
  const n = h.t.length, span = n ? Math.round((h.t[n - 1] - h.t[0]) / 60) : 0, sr = k => h.series[k] || [];
  const avail = k => { const a = sr(k + '.level').filter(v => typeof v === 'number' && v >= 0); return a.length ? Math.round(100 * a.filter(v => v === 0 || v === 1).length / a.length) + '%' : '—'; };
  const mods = S.modules.filter(m => m.id !== 'block' && !m.aux), cl = S.routes.clients;
  const storage = h.storage || {}, saved = storage.savedAt ? new Date(storage.savedAt * 1000).toLocaleTimeString('ru-RU') : 'ожидается';
  setHtml(`<div class="card"><p class="sub">История за последние ${span} мин, шаг 5 с. Полоса — состояние (зелёный норма, жёлтый предупреждение, красный сбой), линия — скорость. Пробелы означают отсутствие измерений.</p><span class="sub">Сохраняется до часа истории и 200 решений, максимум 4 МиБ. Запись каждые 30 с; последняя: ${esc(saved)}.${storage.error ? ` <b class="c2">Ошибка сохранения: ${esc(storage.error)}</b>` : ''}</span></div>` + networkTelemetryHtml() + `
    <div class="sec">Узлы</div><div class="card">${mods.map(m => `<div class="chartrow"><div><b>${esc(m.name)}</b><div class="sub">${esc(m.status.state)}</div></div><div><div class="tl" data-tl="${m.id}"></div><canvas class="chart" data-ch="${m.id}.rx" style="height:${sr(m.id + '.rx').length ? 70 : 0}px"></canvas></div><div class="kpi"><div class="v">${avail(m.id)}</div><div class="sub">доступность</div></div></div>`).join('')}</div>
    <div class="sec">Клиенты</div><div class="card">${cl.map(c => `<div class="chartrow"><div><b>${esc(c.name)}</b><div class="sub">${c.ip}</div></div><canvas class="chart" data-ch="client.${c.ip}" style="height:60px"></canvas><div class="kpi"><div class="v" style="font-size:16px">${c.on ? rate(c.tx) : '—'}</div><div class="sub">сейчас ↓</div></div></div>`).join('')}</div>`);
  document.querySelectorAll('[data-tl]').forEach(el => { const a = sr(el.dataset.tl + '.level'), step = Math.max(1, Math.floor(a.length / 240)); let s = ''; for (let i = 0; i < a.length; i += step) { const bucket = a.slice(i, i + step); s += `<i class="l${bucket.some(v => v == null) ? -1 : Math.max(...bucket)}"></i>`; } el.innerHTML = s; });
  document.querySelectorAll('[data-ch]').forEach(cv => {
    const a = sr(cv.dataset.ch); if (!a.length || !cv.clientHeight) return; const w = cv.width = cv.clientWidth * 2, hh = cv.height = cv.clientHeight * 2, g = cv.getContext('2d'), mx = Math.max(...a.filter(v => typeof v === 'number'), 1);
    const css = getComputedStyle(document.documentElement); g.strokeStyle = css.getPropertyValue('--grid'); g.lineWidth = 1; for (let i = 1; i < 4; i++) { g.beginPath(); g.moveTo(0, hh * i / 4); g.lineTo(w, hh * i / 4); g.stroke(); }
    const x = i => a.length > 1 ? i * w / (a.length - 1) : 0;
    g.strokeStyle = css.getPropertyValue('--accent'); g.lineWidth = 3; g.fillStyle = 'rgba(57,208,255,.12)';
    let start = -1;
    for (let i = 0; i <= a.length; i++) {
      const v = a[i];
      if (typeof v === 'number') { const y = hh - 4 - v / mx * (hh - 12); if (start < 0) { g.beginPath(); g.moveTo(x(i), y); start = i; } else g.lineTo(x(i), y); }
      else if (start >= 0) { g.stroke(); g.lineTo(x(i - 1), hh); g.lineTo(x(start), hh); g.closePath(); g.fill(); start = -1; }
    }
    g.fillStyle = css.getPropertyValue('--dim'); g.font = '20px Segoe UI, sans-serif'; g.fillText('макс. ' + rate(mx), 8, 22);
  });
}
// ---------------------------------------------------------------- диагностика
function downloadDiagnosticReport(checks, state) {
  const now = new Date().toISOString();
  const failed = checks.filter(check => !check.ok).length;
  const updates = state.updates || [];
  const last = updates[updates.length - 1];
  // Only export check labels, outcomes and explicit shareable details. Raw findings and logs can contain local addresses or credentials.
  const lines = [
    'VpnGuard Linux · Отчёт диагностики',
    'Создан (UTC): ' + now,
    'Версия: ' + state.version,
    'Режим: ' + (state.sim ? 'имитация' : 'шлюз'),
    'Маршрутизация готова: ' + (state.routingReady ? 'да' : 'нет'),
    'Последнее обновление: ' + (last ? last.version + ' · ' + last.status + ' · ' + last.at : 'записей нет'),
    'Проверок: ' + checks.length + ', пройдено: ' + (checks.length - failed) + ', проблем: ' + failed,
    '',
    ...checks.flatMap(check => [[check.ok ? 'OK' : 'СБОЙ', check.at, check.module, check.id, check.title].join(' | '),
      ...(check.report || []).map(line => '  ' + line)])
  ];
  const url = URL.createObjectURL(new Blob(['\uFEFF', lines.join('\r\n') + '\r\n'], {type: 'text/plain;charset=utf-8'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'vpnguard-report-' + now.replace(/[:.]/g, '-') + '.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

let providerBusy = false;
async function requestDiagnosticAdvice() {
  if (providerBusy) return;
  providerBusy = true;
  try {
    const r = await post('diag/recommendation', {}, true);
    if (!r || PAGE !== 'diag') return;
    const reasons = {disabled:'Провайдер выключен.', busy:'Другой запрос уже выполняется.', invalid_endpoint:'Проверьте адрес провайдера.', unavailable:'Провайдер недоступен.', invalid_response:'Ответ провайдера не соответствует формату.'};
    const confidence = {low:'низкая', medium:'средняя', high:'высокая'};
    const advice = r.advice ? `<p>${esc(r.advice.recommendation)}</p><p class="sub">Уверенность по оценке провайдера — ${esc(confidence[r.advice.confidence])}.</p>` : `<p>${esc(reasons[r.status])}</p>`;
    modal(`<div class="sec">Рекомендация провайдера</div>${advice}<b>Локальный анализ</b><p>${esc(r.local.summary)}</p><ul>${r.local.observations.map(o => `<li>${esc(o)}</li>`).join('')}</ul><button type="button" onclick="closeModal()">Закрыть</button>`);
  } finally { providerBusy = false; }
}
async function pDiag(run) {
  if (DIAGNEW) { run = true; DIAGNEW = false; } // при входе на страницу проверки выполняются заново
  let res; try { res = run ? await post('diagrun', {}, true) : await get('diag'); } catch (e) { return; } if (PAGE !== 'diag' || !res) return;
  let explanation;
  try { explanation = await get('diag/explanation'); } catch (e) { /* Keep the checks available. */ }
  if (PAGE !== 'diag') return;
  const analysis = explanation ? `<div class="card"><div class="sec">Объяснение состояния</div><p>${esc(explanation.summary)}</p>${explanation.observations.length ? `<ul>${explanation.observations.map(text => `<li>${esc(text)}</li>`).join('')}</ul>` : ''}</div>` : '';
  const bad = res.filter(r => !r.ok);
  $('page').innerHTML = hero(bad.length ? 1 : 0, bad.length ? 'Найдено проблем: ' + bad.length : 'Проблем не найдено', `Проверок: ${res.length}. Модули чинят себя сами по лестнице восстановления; здесь видно, что именно не так и что делать руками.`, '<div class="row"><button type="button" class="p" id="drun">⟳ Проверить сейчас</button><button type="button" id="dreport">Скачать отчёт проверки</button></div>') +
    analysis + `<div class="card"><table><tr><th></th><th>Модуль</th><th>Проверка</th><th>Что проверено</th><th>Что делать</th><th></th></tr>${res.map(r => `<tr><td><span class="dot ${r.ok ? 'l0' : 'l2'}"></span></td><td>${esc(r.module)}</td><td>${esc(r.title)}</td><td class="muted">${esc(r.text)}</td><td>${esc(r.hint || '')}</td><td class="act">${r.fixTitle ? `<button type="button" class="sq" data-fix="${r.id}">${esc(r.fixTitle)}</button>` : ''}</td></tr>`).join('')}</table></div>` +
    (S.faults ? `<div class="sec">Имитация сбоев</div><div class="card"><div class="sub" style="margin-bottom:8px">Включите сбой и посмотрите, как агент его находит и что делает. Проверки идут раз в 10–30 секунд.</div>${S.faults.map(f => `<div class="row" style="padding:4px 0"><button type="button" class="sq${f.on ? ' bad' : ''}" data-fault="${f.id}" data-on="${f.on ? '' : '1'}">${f.on ? 'Убрать сбой' : 'Включить'}</button><span class="${f.on ? 'c2' : ''}">${esc(f.title)}</span></div>`).join('')}</div>` : '') +
    S.modules.filter(m => !m.page && !m.exit && ((m.fields && m.fields.length) || (m.actions && m.actions.length))).map(moduleBlock).join('') +
    (S.routes.pending ? `<div class="card"><b>Проверяется связь после изменения маршрутов</b><p class="sub">Если отдельный запрос подтверждения не придёт, прежние настройки будут восстановлены автоматически.</p></div>` : '') +
    `<div class="sec">Изменения маршрутов</div><div class="card">${(S.routes.events || []).length ? `<table><tr><th>Время</th><th>Операция</th><th>Результат</th></tr>${S.routes.events.slice(-10).reverse().map(e => `<tr><td style="white-space:nowrap">${esc(new Date(e.at).toLocaleString('ru-RU'))}</td><td>${esc(e.reason)}</td><td>${esc(({committed:'Применено',aborted:'Возвращены прежние настройки',recovered:'Восстановлено после сбоя',recovery_failed:'Ошибка восстановления'})[e.status] || e.status)}</td></tr>`).join('')}</table>` : '<p class="sub">Операций пока нет.</p>'}</div>` +
    `<div class="sec">Журнал решений</div><div class="card">${decisions(30)}</div>`;
  document.querySelectorAll('[data-mod]').forEach(el => bindModule(M(el.dataset.mod), el, 'x' + el.dataset.mod));
  $('drun').onclick = () => pDiag(true);
  const reportState = S;
  $('dreport').onclick = () => downloadDiagnosticReport(res, reportState);
  document.querySelectorAll('[data-fix]').forEach(b => { b.onclick = async () => { await post('fix', { id: b.dataset.fix }); pDiag(true); }; });
  document.querySelectorAll('[data-fault]').forEach(b => { b.onclick = async () => { await post('sim', { id: b.dataset.fault, on: !!b.dataset.on }); setTimeout(() => pDiag(true), 2500); }; });
}
function developmentHtml() {
  const stages = S.development || [];
  if (!stages.length) return '';
  const completed = stages.filter(s => !(s.remaining || []).length).length;
  const active = stages.filter(s => (s.done || []).length && (s.remaining || []).length).length;
  return `<div class="sec">Прогресс разработки</div><div class="card"><div class="row"><b>Завершено этапов: ${completed} из ${stages.length}</b><span class="sub">В работе: ${active} · Запланировано: ${stages.length - completed - active}</span></div><p class="sub">Полосы показывают выполненные пункты плана. Раскройте этап, чтобы увидеть проверки и оставшиеся задачи.</p>${stages.map(s => {
    const done = s.done || [], remaining = s.remaining || [], total = done.length + remaining.length;
    const status = !remaining.length ? 'Завершён' : done.length ? 'В работе' : 'Запланирован';
    return `<details class="dev-stage" data-details-key="stage-${s.id}"><summary><div class="row"><b style="flex:1">${s.id}. ${esc(s.title)}</b><span class="sub">${status} · ${done.length} из ${total}</span></div><progress value="${done.length}" max="${total || 1}" aria-label="${esc(s.title)}: ${done.length} из ${total}"></progress></summary><p class="sub">${esc(s.evidence)}</p><div class="dev-lists">${done.length ? `<div><b>Выполнено</b><ul>${done.map(item => `<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}${remaining.length ? `<div><b>Осталось</b><ul>${remaining.map(item => `<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}</div></details>`;
  }).join('')}</div>`;
}
let repositoryRelease = null, repositoryBusy = false, repositoryError = '';
function pUpdates() {
  const statuses = { prepared: 'Подготовлено', installed: 'Ожидает проверки', confirmed: 'Установлено и проверено', rolled_back: 'Выполнен откат', rollback_failed: 'Ошибка отката' };
  const job = S.repositoryInstall || {};
  const jobStatus = {...statuses, downloading: 'Скачивание и установка', failed: 'Не удалось установить'};
  const disabled = repositoryBusy ? ' disabled' : '';
  const actions = `<div class="card"><div class="sec">Обновление из репозитория</div>
    <div class="row"><button id="rcheck"${disabled}>Проверить обновления</button>
    ${!S.sim && repositoryRelease?.available && repositoryRelease.version !== S.version && !['downloading','installed','prepared'].includes(job.status) ? `<button class="p" id="rinstall"${disabled}>Установить ${esc(repositoryRelease.version)}</button>` : ''}
    ${job.canConfirm ? `<button class="p" id="rconfirm"${disabled}>Проверить связь и подтвердить</button>` : ''}</div>
    ${repositoryRelease ? `<p>Последний выпуск: ${esc(repositoryRelease.version)} · установлен: ${esc(S.version)}</p>` : ''}
    ${job.status ? `<p>${esc(job.version)} · ${esc(jobStatus[job.status] || job.status)} ${esc(job.message || '')}</p>` : ''}
    ${repositoryError ? `<p class="err">${esc(repositoryError)}</p>` : ''}</div>`;
  setHtml(`<div class="card"><div class="sec">Linux · ${esc(S.version)}</div><p class="sub">Для первого перехода со старой версии можно использовать Windows.</p><div class="row"><a href="Update-VpnGuard.ps1" download>Скачать скрипт для Windows</a><a href="https://github.com/Fogiku/VpnGuard_linux#обновление-шлюза-из-windows">Инструкция по обновлению</a></div></div>` + actions + developmentHtml() +
    (S.releases || []).map(r => `<div class="card"><div class="sec">${esc(r.version)} · ${esc(r.date)}</div><ul>${r.changes.map(c => `<li>${esc(c)}</li>`).join('')}</ul></div>`).join('') +
    `<div class="sec">История установки</div><div class="card">${(S.updates || []).length ? `<table><tr><th>Время</th><th>Версия</th><th>Результат</th><th>Описание</th></tr>${S.updates.slice().reverse().map(e => `<tr><td style="white-space:nowrap">${esc(new Date(e.at).toLocaleString('ru-RU'))}</td><td>${esc(e.version)}</td><td>${esc(statuses[e.status] || e.status)}</td><td>${esc(e.description)}</td></tr>`).join('')}</table>` : '<p class="sub">Установки с журналированием ещё не выполнялись.</p>'}</div>`);
  async function request(action) {
    repositoryBusy = true;
    repositoryError = '';
    pUpdates();
    try {
      if (action === 'check') repositoryRelease = await get('repository/check');
      else {
        const body = action === 'install' ? {version: repositoryRelease.version} : {job: job.job};
        const result = await post('repository/' + action, body, true);
        if (result === null) throw new Error($('toast').textContent);
        toast(result);
      }
    } catch (err) { repositoryError = err.message; }
    finally { repositoryBusy = false; if (PAGE === 'updates') pUpdates(); }
  }
  $('rcheck').onclick = () => request('check');
  if ($('rinstall')) $('rinstall').onclick = async () => {
    if (await ask('Агент перезапустится. После восстановления страницы подтвердите обновление в течение четырёх минут, иначе шлюз вернёт прежнюю версию.', 'Установить обновление')) request('install');
  };
  if ($('rconfirm')) $('rconfirm').onclick = () => request('confirm');
}
async function pLogs() {
  let l; try { l = await get('log'); } catch (e) { return; } if (PAGE !== 'logs' || busyUI()) return;
  $('page').innerHTML = `<pre class="log lgv">${l.slice().reverse().map(x => `<span class="${x.lvl === 'ERROR' ? 'le' : x.lvl === 'WARN' ? 'lw' : ''}">${x.t} [${x.lvl}] ${esc(x.text)}</span>`).join('')}</pre>`;
}
refresh(true); setInterval(refresh, 3000);
