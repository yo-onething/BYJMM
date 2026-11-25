'use strict';

/* =========================================================================
   Qsecret 前端
   约束：无内联事件、无外部资源、所有用户数据渲染前转义。
   ========================================================================= */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const CATS = {
  login: { label: '登录账号', short: '登', icon: 'M12 3.2a4 4 0 1 1 0 8 4 4 0 0 1 0-8ZM4.8 20.4c0-3.4 3.2-5.6 7.2-5.6s7.2 2.2 7.2 5.6' },
  card: { label: '银行卡', short: '卡', icon: 'M3.6 7.6h16.8v9.2a1.6 1.6 0 0 1-1.6 1.6H5.2a1.6 1.6 0 0 1-1.6-1.6V7.6Zm0 3.4h16.8M3.6 8.8V6.4c0-.9.7-1.6 1.6-1.6h13.6c.9 0 1.6.7 1.6 1.6v2.4' },
  server: { label: '服务器 / 密钥', short: '服', icon: 'M4 6.2h16v4.6H4V6.2Zm0 7h16v4.6H4v-4.6ZM7 8.5h.01M7 15.5h.01' },
  note: { label: '安全笔记', short: '记', icon: 'M6.4 3.6h8.2l4 4v12.8H6.4V3.6Zm8.2 0v4h4M9 12h6M9 15.4h6' },
  other: { label: '其他', short: '其', icon: 'M5 12h.01M12 12h.01M19 12h.01' },
};

const state = {
  csrf: null,
  entries: [],
  stats: { total: 0, weak: 0, reused: 0, categories: {} },
  filter: { category: 'all', tag: null, q: '' },
  selectedId: null,
  idleMinutes: 5,
  desktop: false,
  platform: '',
  mode: 'unlock', // unlock | create
  lastActivity: Date.now(),
  revealed: new Map(),
  editingId: null,
  genTarget: null,
  genValue: '',
};

/* -------------------------------------------------------------- 基础工具 */

function esc(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function toast(message, kind = 'ok') {
  const box = $('#toasts');
  // 同一条提示连续触发时替换上一条，避免快速操作堆成一列
  const last = box.lastElementChild;
  if (last && last.dataset.msg === message && last.dataset.kind === kind) last.remove();
  while (box.children.length >= 2) box.firstElementChild.remove();
  const el = document.createElement('div');
  el.className = `toast${kind === 'error' ? ' error' : ''}`;
  el.dataset.msg = message;
  el.dataset.kind = kind;
  el.textContent = message;
  box.appendChild(el);
  setTimeout(() => {
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 220);
  }, 2600);
}

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function scoreToBars(score) {
  if (score >= 85) return 4;
  if (score >= 65) return 3;
  if (score >= 40) return 2;
  if (score > 0) return 1;
  return 0;
}

function strengthLabel(score) {
  if (score >= 85) return '很强';
  if (score >= 65) return '较强';
  if (score >= 40) return '一般';
  if (score > 0) return '偏弱';
  return '未设置';
}

function scorePassword(pw) {
  const s = String(pw || '');
  if (!s) return 0;
  let score = Math.min(60, s.length * 4);
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(s)).length;
  score += classes * 10;
  if (/^(.)\1+$/.test(s)) score -= 40;
  if (/^[0-9]+$/.test(s)) score -= 25;
  if (/^(password|qwerty|admin|123456|letmein|iloveyou)/i.test(s)) score -= 40;
  return Math.max(0, Math.min(100, score));
}

/* -------------------------------------------------------------- API */

class ApiError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && state.csrf) headers['X-CSRF-Token'] = state.csrf;

  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (res.status === 401) {
    const data = await res.json().catch(() => ({}));
    if (data && data.error && data.error.code === 'LOCKED') {
      lockToAuth('会话已结束，请重新解锁');
      throw new ApiError('LOCKED', '请先解锁');
    }
    throw new ApiError(data?.error?.code || 'UNAUTHORIZED', data?.error?.message || '未授权');
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(data?.error?.code || 'ERROR', data?.error?.message || '请求失败');
  }
  return data;
}

/* -------------------------------------------------------------- 解锁页 */

const authEls = {
  section: $('#auth'),
  title: $('#authTitle'),
  desc: $('#authDesc'),
  form: $('#authForm'),
  password: $('#authPassword'),
  confirmWrap: $('#authConfirmWrap'),
  confirm: $('#authConfirm'),
  error: $('#authError'),
  submit: $('#authSubmit'),
  hint: $('#authHint'),
  strength: $('#authStrength'),
  note: $('#authNote'),
};

function showAuth(mode, note = '') {
  state.mode = mode;
  $('#app').classList.add('hidden');
  authEls.section.classList.remove('hidden');
  authEls.error.textContent = '';
  authEls.note.textContent = note;
  authEls.password.value = '';
  authEls.confirm.value = '';
  authEls.section.querySelector('.brand').classList.remove('hidden');

  if (mode === 'create') {
    authEls.title.textContent = '创建本地保险库';
    authEls.desc.textContent = '设置一个主密码。它不会被保存，也无法找回——忘记就等于永久失去全部数据。';
    authEls.confirmWrap.classList.remove('hidden');
    authEls.submit.textContent = '创建保险库';
    authEls.hint.textContent = '至少 12 位，建议 4 个以上不相关单词组合；不要与任何网站密码相同。';
    authEls.note.textContent = state.desktop ? '首次使用：数据将以密文保存在本机，不上传、不同步。' : '首次使用：数据将加密保存在本机应用目录。';
  } else {
    authEls.title.textContent = '解锁保险库';
    authEls.desc.textContent = '输入主密码。它只在本机内存中用于派生密钥，不会被保存或发送。';
    authEls.confirmWrap.classList.add('hidden');
    authEls.submit.textContent = '解锁';
    authEls.note.textContent = note;
  }
  setTimeout(() => authEls.password.focus(), 60);
}

function updateAuthStrength() {
  const score = scorePassword(authEls.confirm.value || authEls.password.value);
  authEls.strength.dataset.score = String(scoreToBars(score));
}

authEls.password.addEventListener('input', () => {
  authEls.error.textContent = '';
  if (state.mode === 'create') updateAuthStrength();
});
authEls.confirm.addEventListener('input', () => {
  authEls.error.textContent = '';
  updateAuthStrength();
});

authEls.form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = authEls.password.value;
  authEls.error.textContent = '';

  if (state.mode === 'create') {
    if (pw.length < 12) {
      authEls.error.textContent = '主密码至少 12 位';
      return;
    }
    if (pw !== authEls.confirm.value) {
      authEls.error.textContent = '两次输入的主密码不一致';
      return;
    }
  } else if (!pw) {
    authEls.error.textContent = '请输入主密码';
    return;
  }

  authEls.submit.disabled = true;
  const original = authEls.submit.textContent;
  authEls.submit.textContent = state.mode === 'create' ? '正在创建…' : '正在派生密钥…';

  try {
    const path = state.mode === 'create' ? '/api/vault/create' : '/api/vault/unlock';
    const body = state.mode === 'create' ? { password: pw, confirm: authEls.confirm.value } : { password: pw };
    const data = await api(path, { method: 'POST', body });
    authEls.password.value = '';
    authEls.confirm.value = '';
    await enterApp(data.csrf, 5);
  } catch (err) {
    if (err.code === 'RATE_LIMITED') {
      authEls.error.textContent = err.message;
    } else if (err.code === 'TAMPERED') {
      authEls.error.textContent = '文件完整性校验失败：保险库可能被篡改，已拒绝打开。';
    } else {
      authEls.error.textContent = err.message || '操作失败';
    }
    authEls.password.select();
  } finally {
    authEls.submit.disabled = false;
    authEls.submit.textContent = original;
  }
});

function lockToAuth(note = '') {
  state.csrf = null;
  state.entries = [];
  state.selectedId = null;
  state.revealed.forEach((v) => clearTimeout(v.timer));
  state.revealed.clear();
  $('#detail').classList.remove('open');
  showAuth('unlock', note);
}

/* -------------------------------------------------------------- 主界面 */

async function enterApp(csrf, idleMinutes, dataDir) {
  state.csrf = csrf;
  if (!idleMinutes) {
    try {
      const s = await api('/api/session');
      idleMinutes = s.idleMinutes;
      state.csrf = s.csrf || csrf;
      dataDir = dataDir || s.dataDir;
    } catch {
      idleMinutes = 5;
    }
  }
  // 桌面应用里保险库不在应用目录：显示真实位置
  if (state.desktop && dataDir) setVaultLocation(dataDir);
  state.idleMinutes = idleMinutes || 5;
  state.lastActivity = Date.now();
  $('#auth').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#search').value = '';
  state.filter = { category: 'all', tag: null, q: '' };
  await refreshEntries(true);
}

async function refreshEntries(selectFirst = false) {
  const data = await api('/api/entries');
  state.entries = data.entries;
  state.stats = data.stats;

  if (state.selectedId && !state.entries.some((e) => e.id === state.selectedId)) {
    state.selectedId = null;
  }
  if (!state.selectedId && selectFirst && state.entries.length > 0) {
    state.selectedId = state.entries[0].id;
  }
  renderAll();
}

function visibleEntries() {
  const { category, tag, q } = state.filter;
  const needle = q.trim().toLowerCase();
  return state.entries.filter((e) => {
    if (category !== 'all' && e.category !== category) return false;
    if (tag && !(e.tags || []).includes(tag)) return false;
    if (!needle) return true;
    const hay = [e.title, e.username, e.url, e.notes, (e.tags || []).join(' ')].join('\n').toLowerCase();
    return hay.includes(needle);
  });
}

function renderAll() {
  renderSidebar();
  renderList();
  renderDetail();
  renderStats();
}

function renderSidebar() {
  const all = state.entries.length;
  const counts = state.stats.categories || {};
  const rows = [
    `<button class="cat ${state.filter.category === 'all' ? 'active' : ''}" data-cat="all">
       <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 6.5h16M4 12h16M4 17.5h16" stroke-linecap="round"/></svg>
       <span>全部条目</span><span class="n">${all}</span>
     </button>`,
  ];
  for (const [key, meta] of Object.entries(CATS)) {
    rows.push(`<button class="cat ${state.filter.category === key ? 'active' : ''}" data-cat="${key}">
      <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="${meta.icon}"/></svg>
      <span>${esc(meta.label)}</span><span class="n">${counts[key] || 0}</span>
    </button>`);
  }
  $('#catList').innerHTML = rows.join('');

  const tags = new Map();
  for (const e of state.entries) for (const t of e.tags || []) tags.set(t, (tags.get(t) || 0) + 1);
  const sorted = Array.from(tags.entries()).sort((a, b) => b[1] - a[1]).slice(0, 30);
  $('#tagBlock').classList.toggle('hidden', sorted.length === 0);
  $('#tagList').innerHTML = sorted
    .map(([t, n]) => `<button class="tag-chip ${state.filter.tag === t ? 'active' : ''}" data-tag="${esc(t)}">#${esc(t)} <span class="n">${n}</span></button>`)
    .join('');
}

function renderStats() {
  const { weak, reused, total } = state.stats;
  $('#statWeak').textContent = String(weak);
  $('#statWeak').classList.toggle('warn', weak > 0);
  $('#statReused').textContent = String(reused);
  $('#statReused').classList.toggle('warn', reused > 0);
  const healthy = total === 0 ? 100 : Math.round(((total - Math.max(weak, reused)) / total) * 100);
  $('#statBar').style.width = `${Math.max(4, healthy)}%`;
  $('#statBar').style.background = healthy >= 70 ? 'var(--accent)' : healthy >= 40 ? 'var(--warn)' : 'var(--danger)';
  $('#statNote').textContent = total === 0 ? '尚无条目' : `健康度 ${healthy}% · 共 ${total} 条`;
}

function renderList() {
  const items = visibleEntries();
  const title = state.filter.category === 'all' ? '全部条目' : CATS[state.filter.category].label;
  $('#listTitle').textContent = state.filter.tag ? `#${state.filter.tag}` : title;
  $('#listCount').textContent = String(items.length);

  $('#entryList').innerHTML = items
    .map((e) => {
      const meta = CATS[e.category] || CATS.other;
      const sub = e.username || e.url || fmtTime(e.updatedAt);
      const flags = [
        e.strength < 60 ? '<span class="flag" title="密码强度偏弱"></span>' : '',
        e.reused ? '<span class="flag reused" title="与其他条目重复使用"></span>' : '',
      ].join('');
      return `<button class="entry ${state.selectedId === e.id ? 'active' : ''}" data-id="${e.id}" role="listitem">
        <span class="avatar" data-cat="${e.category}">${esc((e.title || '?').trim().slice(0, 1))}</span>
        <span class="entry-main">
          <span class="entry-title">${esc(e.title)}</span>
          <span class="entry-sub">${esc(sub)}</span>
        </span>
        <span class="entry-flags">${flags}</span>
      </button>`;
    })
    .join('');

  $('#listEmpty').classList.toggle('hidden', items.length > 0);
  $('#listEmptyText').textContent = state.entries.length === 0 ? '保险库还是空的，先添加第一条' : '没有匹配的条目';
  $('#entryList').classList.toggle('hidden', items.length === 0);
}

function renderDetail() {
  const pane = $('#detail');
  const entry = state.entries.find((e) => e.id === state.selectedId);

  if (!entry) {
    pane.innerHTML = `<div class="detail-empty">
      <span class="empty-mark">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4">
          <rect x="4" y="3.5" width="16" height="17" rx="2.5"/>
          <path d="M8 8h8M8 12h8M8 16h5" stroke-linecap="round"/>
        </svg>
      </span>
      <h3>选择左侧条目查看详情</h3>
      <p>密码默认隐藏，点击眼睛按钮才会向本地服务请求明文；复制记录不会被保存。</p>
    </div>`;
    return;
  }

  const meta = CATS[entry.category] || CATS.other;
  const revealed = state.revealed.get(entry.id);
  const pwValue = revealed ? revealed.password : '';
  const strength = entry.strength;
  const level = scoreToBars(strength);
  const initial = (entry.title || '?').trim().slice(0, 1);

  pane.innerHTML = `
    <div class="detail-inner">
      <button class="btn ghost sm detail-back" data-action="back">← 返回列表</button>

      <header class="detail-head">
        <span class="avatar lg" data-cat="${esc(entry.category)}" aria-hidden="true">${esc(initial)}</span>
        <div class="detail-head-text">
          <h1 class="detail-title">${esc(entry.title)}</h1>
          <div class="detail-meta">
            <span class="chip">${esc(meta.label)}</span>
            <span class="meta-dot" aria-hidden="true"></span>
            <span>更新于 ${esc(fmtTime(entry.updatedAt))}</span>
            ${entry.reused ? '<span class="chip danger">密码重复</span>' : ''}
          </div>
        </div>
        <div class="detail-actions">
          <button class="btn sm" data-action="edit">编辑</button>
          <button class="btn ghost sm danger-ghost" data-action="delete">删除</button>
        </div>
      </header>

      <section class="detail-card" aria-label="条目字段">
        <div class="drow">
          <span class="dk">账号</span>
          <span class="dv ${entry.username ? '' : 'empty'}">${entry.username ? esc(entry.username) : '未填写'}</span>
          <span class="da">${entry.username ? '<button class="copy-btn" data-copy="username" aria-label="复制账号" title="复制账号"></button>' : ''}</span>
        </div>

        <div class="drow">
          <span class="dk">密码</span>
          <span class="dv mono">${revealed ? esc(pwValue) : '<span class="dots" aria-label="密码已隐藏">••••••••••••</span>'}</span>
          <span class="da">
            <button class="icon-btn eye" data-action="toggle-reveal" aria-label="${revealed ? '隐藏密码' : '显示密码'}" title="${revealed ? '隐藏密码' : '显示密码'}"></button>
            <button class="copy-btn" data-copy="password" aria-label="复制密码" title="复制密码"></button>
          </span>
        </div>

        <div class="drow">
          <span class="dk">强度</span>
          <span class="dv">
            <span class="strength" data-level="${level}">
              <span class="seg" aria-hidden="true"><i></i><i></i><i></i><i></i></span>
              <span class="strength-text">${esc(strengthLabel(strength))} · ${strength}/100</span>
            </span>
          </span>
          <span class="da"></span>
        </div>

        <div class="drow">
          <span class="dk">网址</span>
          <span class="dv ${entry.url ? '' : 'empty'}">${entry.url ? esc(entry.url) : '未填写'}</span>
          <span class="da">${entry.url ? '<button class="copy-btn" data-copy="url" aria-label="复制网址" title="复制网址"></button>' : ''}</span>
        </div>
      </section>

      ${entry.notes ? `<div class="detail-label">备注</div><div class="detail-notes-body">${esc(entry.notes)}</div>` : ''}
      ${(entry.tags || []).length ? `<div class="tag-row">${entry.tags.map((t) => `<span class="chip">#${esc(t)}</span>`).join('')}</div>` : ''}
    </div>
  `;

  paintEye(pane.querySelector('[data-action="toggle-reveal"]'), !!revealed);

  // 详情内的操作按钮
  $$('[data-action]', pane).forEach((btn) => {
    btn.addEventListener('click', () => {
      const action = btn.dataset.action;
      if (action === 'edit') openEntryDialog(entry);
      if (action === 'delete') deleteEntry(entry);
      if (action === 'toggle-reveal') toggleReveal(entry);
      if (action === 'back') {
        $('#detail').classList.remove('open');
        renderList();
      }
    });
  });

  $$('[data-copy]', pane).forEach((btn) => {
    btn.addEventListener('click', async () => {
      const field = btn.dataset.copy;
      try {
        let text = '';
        if (field === 'password') {
          const data = await api(`/api/entries/${entry.id}/reveal`, { method: 'POST' });
          text = data.password;
        } else {
          text = entry[field] || '';
        }
        if (!text) return;
        await copyText(text, field === 'password' ? '密码' : field === 'url' ? '网址' : '账号');
        btn.classList.add('copied');
        setTimeout(() => btn.classList.remove('copied'), 1200);
      } catch (err) {
        toast(err.message || '复制失败', 'error');
      }
    });
  });
}

async function toggleReveal(entry) {
  const existing = state.revealed.get(entry.id);
  if (existing) {
    clearTimeout(existing.timer);
    state.revealed.delete(entry.id);
    renderDetail();
    return;
  }
  try {
    const data = await api(`/api/entries/${entry.id}/reveal`, { method: 'POST' });
    const timer = setTimeout(() => {
      state.revealed.delete(entry.id);
      if (state.selectedId === entry.id) renderDetail();
    }, 30000);
    state.revealed.set(entry.id, { password: data.password, timer });
    renderDetail();
    toast('明文将在 30 秒后自动隐藏');
  } catch (err) {
    toast(err.message || '无法读取密码', 'error');
  }
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast('浏览器拒绝了剪贴板访问，请手动选择复制', 'error');
    return;
  }
  toast(`${label}已复制，45 秒后尝试清除剪贴板`);
  setTimeout(async () => {
    try {
      const current = await navigator.clipboard.readText();
      if (current === text) await navigator.clipboard.writeText('');
    } catch {
      /* 无权限则不处理 */
    }
  }, 45000);
}

/* -------------------------------------------------------------- 列表交互 */

$('#entryList').addEventListener('click', (e) => {
  const btn = e.target.closest('.entry');
  if (!btn) return;
  state.selectedId = btn.dataset.id;
  renderList();
  renderDetail();
  $('#detail').classList.add('open');
  if (window.matchMedia('(max-width: 760px)').matches) {
    // 移动端：详情全屏显示
  }
});

$('#catList').addEventListener('click', (e) => {
  const btn = e.target.closest('.cat');
  if (!btn) return;
  state.filter.category = btn.dataset.cat;
  state.filter.tag = null;
  renderSidebar();
  renderList();
});

$('#tagList').addEventListener('click', (e) => {
  const btn = e.target.closest('.tag-chip');
  if (!btn) return;
  const tag = btn.dataset.tag;
  state.filter.tag = state.filter.tag === tag ? null : tag;
  state.filter.category = 'all';
  renderSidebar();
  renderList();
});

$('#search').addEventListener('input', debounce((e) => {
  state.filter.q = e.target.value;
  renderList();
}, 90));

$('#search').addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    $('#search').value = '';
    state.filter.q = '';
    renderList();
  }
});

/* -------------------------------------------------------------- 顶部操作 */

$('#btnNew').addEventListener('click', () => openEntryDialog(null));
$('#btnEmptyNew').addEventListener('click', () => openEntryDialog(null));

$('#btnGenerate').addEventListener('click', () => {
  state.genTarget = null;
  openGenerator();
});

$('#btnLock').addEventListener('click', async () => {
  try {
    await api('/api/vault/lock', { method: 'POST' });
  } catch {
    /* 即使请求失败也回到解锁页 */
  }
  lockToAuth('已锁定。密钥已从内存中抹除。');
});

document.addEventListener('keydown', (e) => {
  const meta = e.metaKey || e.ctrlKey;
  if (meta && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (!$('#app').classList.contains('hidden')) $('#search').focus();
  }
  if (meta && e.shiftKey && e.key.toLowerCase() === 'l') {
    e.preventDefault();
    if (!$('#app').classList.contains('hidden')) $('#btnLock').click();
  }
});

/* -------------------------------------------------------------- 条目编辑 */

const entryDialog = $('#entryDialog');
const entryForm = $('#entryForm');

function openEntryDialog(entry) {
  state.editingId = entry ? entry.id : null;
  $('#entryDialogTitle').textContent = entry ? '编辑条目' : '新建条目';
  $('#fTitle').value = entry ? entry.title : '';
  $('#fCategory').value = entry ? entry.category : 'login';
  $('#fUsername').value = entry ? entry.username : '';
  $('#fPassword').value = '';
  $('#fPassword').type = 'password';
  $('#fUrl').value = entry ? entry.url : '';
  $('#fNotes').value = entry ? entry.notes : '';
  $('#fTags').value = entry ? (entry.tags || []).join(', ') : '';
  $('#entryError').textContent = '';
  $('#entrySave').textContent = '保存';
  updateFormStrength();
  entryDialog.showModal();
  setTimeout(() => $('#fTitle').focus(), 50);

  // 编辑时必须回填密码，否则保存会把原密码清空
  if (entry) {
    const editingId = entry.id;
    const saveBtn = $('#entrySave');
    saveBtn.disabled = true;
    saveBtn.textContent = '读取中…';
    api(`/api/entries/${entry.id}/reveal`, { method: 'POST' })
      .then((data) => {
        if (state.editingId !== editingId) return;
        if ($('#fPassword').value !== '') return; // 用户已开始输入，不覆盖
        $('#fPassword').value = data.password;
        updateFormStrength();
      })
      .catch(() => {
        $('#entryError').textContent = '读取原密码失败，为避免误清空请直接取消';
      })
      .finally(() => {
        saveBtn.disabled = false;
        saveBtn.textContent = '保存';
      });
  }
}

function updateFormStrength() {
  const score = scorePassword($('#fPassword').value);
  $('#fStrength').dataset.score = String(scoreToBars(score));
}

$('#fPassword').addEventListener('input', updateFormStrength);

$('#fGenerate').addEventListener('click', () => {
  state.genTarget = 'entry';
  openGenerator();
});

entryForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const tags = $('#fTags').value
    .split(/[,，]/)
    .map((t) => t.trim())
    .filter(Boolean);

  const payload = {
    title: $('#fTitle').value.trim(),
    category: $('#fCategory').value,
    username: $('#fUsername').value,
    password: $('#fPassword').value,
    url: $('#fUrl').value.trim(),
    notes: $('#fNotes').value,
    tags,
  };

  if (!payload.title) {
    $('#entryError').textContent = '标题不能为空';
    return;
  }

  const saveBtn = $('#entrySave');
  saveBtn.disabled = true;
  saveBtn.textContent = '保存中…';
  try {
    if (state.editingId) {
      await api(`/api/entries/${state.editingId}`, { method: 'PUT', body: payload });
      toast('条目已更新');
    } else {
      const data = await api('/api/entries', { method: 'POST', body: payload });
      state.selectedId = data.entry.id;
      toast('条目已加密保存');
    }
    entryDialog.close();
    await refreshEntries();
  } catch (err) {
    $('#entryError').textContent = err.message || '保存失败';
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = '保存';
  }
});

async function deleteEntry(entry) {
  const ok = await askConfirm('删除条目', `确定删除「${entry.title}」吗？该操作不可撤销。`, '删除');
  if (!ok) return;
  try {
    await api(`/api/entries/${entry.id}`, { method: 'DELETE' });
    if (state.selectedId === entry.id) state.selectedId = null;
    toast('条目已删除');
    await refreshEntries();
  } catch (err) {
    toast(err.message || '删除失败', 'error');
  }
}

/* -------------------------------------------------------------- 生成器 */

const genDialog = $('#genDialog');

function openGenerator() {
  genDialog.showModal();
  regenerate();
}

async function regenerate() {
  const body = {
    length: Number($('#genLength').value),
    upper: $('#genUpper').checked,
    lower: $('#genLower').checked,
    digits: $('#genDigits').checked,
    symbols: $('#genSymbols').checked,
    avoidAmbiguous: $('#genAvoid').checked,
  };
  try {
    const data = await api('/api/generate', { method: 'POST', body });
    state.genValue = data.password;
    $('#genValue').textContent = data.password;
    const score = scorePassword(data.password);
    $('#genBar').style.width = `${Math.max(10, score)}%`;
    $('#genBar').style.background = score >= 80 ? 'var(--accent)' : score >= 55 ? 'var(--warn)' : 'var(--danger)';
  } catch (err) {
    $('#genValue').textContent = '生成失败';
  }
}

$('#genLength').addEventListener('input', (e) => {
  $('#genLenLabel').textContent = e.target.value;
  regenerate();
});
['#genUpper', '#genLower', '#genDigits', '#genSymbols', '#genAvoid'].forEach((sel) => {
  $(sel).addEventListener('change', regenerate);
});
$('#genRefresh').addEventListener('click', regenerate);

$('#genCopy').addEventListener('click', async (e) => {
  if (!state.genValue) return;
  await copyText(state.genValue, '密码');
  e.currentTarget.classList.add('copied');
  setTimeout(() => e.currentTarget.classList.remove('copied'), 1200);
});

$('#genUse').addEventListener('click', () => {
  if (state.genTarget === 'entry') {
    $('#fPassword').value = state.genValue;
    $('#fPassword').type = 'text';
    updateFormStrength();
    genDialog.close();
    toast('已填入密码字段');
  } else {
    copyText(state.genValue, '密码');
    genDialog.close();
  }
  state.genTarget = null;
});

/* -------------------------------------------------------------- 主题 */

function syncThemeUI(pref) {
  const sel = $('#setTheme');
  if (sel) sel.value = pref;
  const btn = $('#btnTheme');
  if (btn) btn.title = document.documentElement.dataset.theme === 'light' ? '切换到深色' : '切换到浅色';
}

$('#btnTheme').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  try { localStorage.setItem(QsecretTheme.KEY, next); } catch { /* 存不了就只影响本次 */ }
  QsecretTheme.apply(next);
});

$('#setTheme').addEventListener('change', (e) => {
  try { localStorage.setItem(QsecretTheme.KEY, e.target.value); } catch { /* 同上 */ }
  QsecretTheme.apply(e.target.value);
});

window.addEventListener('qsecret:theme', (e) => syncThemeUI(e.detail.pref));
syncThemeUI(QsecretTheme.pref());

/* -------------------------------------------------------------- 设置 */

const settingsDialog = $('#settingsDialog');

$('#btnSettings').addEventListener('click', async () => {
  try {
    const data = await api('/api/settings');
    $('#setIdle').value = String(data.settings.idleMinutes);
    state.idleMinutes = data.settings.idleMinutes;
  } catch {
    /* 使用当前值 */
  }
  if (state.desktop) await refreshAutostart();
  $('#setOldPw').value = '';
  $('#setNewPw').value = '';
  $('#setError').textContent = '';
  $('#restoreFile').value = '';
  settingsDialog.showModal();
});

/* ------------------------------------------------- 登录时自动启动（仅桌面应用） */

const AUTOSTART_HINT = '登录后在后台待命并保持锁定，需要输入主密码才能查看。关闭后每次要手动打开 Qsecret。';

async function refreshAutostart() {
  try {
    const info = await api('/api/app/autostart');
    $('#setAutostart').checked = !!info.autoStart;
    $('#autostartHint').textContent = info.reason || AUTOSTART_HINT;
  } catch {
    $('#setAutostart').disabled = true;
    $('#autostartHint').textContent = '当前无法读取系统的登录项设置。';
  }
}

$('#setAutostart').addEventListener('change', async (e) => {
  const enable = e.target.checked;
  e.target.disabled = true;
  try {
    const info = await api('/api/app/autostart', { method: 'PUT', body: { enabled: enable } });
    e.target.checked = !!info.autoStart;
    toast(enable ? '已开启：登录系统时自动启动' : '已关闭：登录系统时自动启动');
  } catch (err) {
    e.target.checked = !enable;
    toast(err.message || '设置失败', 'error');
  } finally {
    e.target.disabled = false;
  }
});

$('#setIdle').addEventListener('change', async (e) => {
  try {
    const data = await api('/api/settings', { method: 'PUT', body: { idleMinutes: Number(e.target.value) } });
    state.idleMinutes = data.settings.idleMinutes;
    state.lastActivity = Date.now();
    toast('自动锁定时间已更新');
  } catch (err) {
    toast(err.message || '保存失败', 'error');
  }
});

$('#setChangePw').addEventListener('click', async () => {
  const oldPw = $('#setOldPw').value;
  const newPw = $('#setNewPw').value;
  const errEl = $('#setError');
  errEl.textContent = '';

  if (!oldPw) { errEl.textContent = '请输入当前主密码'; return; }
  if (newPw.length < 12) { errEl.textContent = '新主密码至少 12 位'; return; }

  const ok = await askConfirm('更新主密码', '全部条目会用新密钥重新加密，旧主密码立即失效。请确认已记住新密码。', '更新');
  if (!ok) return;

  const btn = $('#setChangePw');
  btn.disabled = true;
  try {
    const data = await api('/api/master/change', { method: 'POST', body: { currentPassword: oldPw, newPassword: newPw } });
    state.csrf = data.csrf;
    $('#setOldPw').value = '';
    $('#setNewPw').value = '';
    toast('主密码已更新，条目已重新加密');
  } catch (err) {
    errEl.textContent = err.message || '更新失败';
  } finally {
    btn.disabled = false;
  }
});

$('#btnBackup').addEventListener('click', () => {
  // 备份内容本身是密文，直接由浏览器下载
  const a = document.createElement('a');
  a.href = '/api/backup';
  a.download = '';
  document.body.appendChild(a);
  a.click();
  a.remove();
  toast('已开始下载加密备份');
});

$('#restoreFile').addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const password = $('#restorePassword').value;
  if (!password) {
    toast('请先填写备份文件的主密码', 'error');
    e.target.value = '';
    return;
  }
  if (file.size > 32 * 1024 * 1024) {
    toast('文件过大，不像是有效的备份', 'error');
    return;
  }
  const ok = await askConfirm(
    '从备份恢复',
    '当前保险库将被备份文件覆盖。确认后无法撤销（系统会保留一份 .bak）。',
    '恢复'
  );
  if (!ok) {
    e.target.value = '';
    return;
  }

  try {
    const buf = await file.arrayBuffer();
    let binary = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    const data = await api('/api/backup/restore', {
      method: 'POST',
      body: { data: btoa(binary), password },
    });
    state.csrf = data.csrf;
    $('#restoreFile').value = '';
    $('#restorePassword').value = '';
    settingsDialog.close();
    await refreshEntries(true);
    toast('已从备份恢复');
  } catch (err) {
    toast(err.message || '恢复失败', 'error');
    e.target.value = '';
  }
});

/** 把保险库所在目录同步到手册和设置页（桌面应用的数据目录不在应用里）。 */
function setVaultLocation(dir) {
  const file = `${dir.replace(/[\\/]+$/, '')}${state.platform === 'win32' ? '\\' : '/'}vault.qvault`;
  $$('.vault-dir').forEach((el) => { el.textContent = dir; });
  $$('.vault-path').forEach((el) => { el.textContent = file; });
  $('#vaultPathHint').textContent = `数据文件：${file}（权限 0600）`;
}

/* -------------------------------------------------------------- 使用手册 */

const helpDialog = $('#helpDialog');
const helpBody = $('#helpBody');
const helpToc = $('#helpToc');

function setHelpActive(id) {
  $$('button', helpToc).forEach((b) => b.classList.toggle('active', b.dataset.target === id));
}

(function buildHelpToc() {
  const sections = $$('.help-section', helpBody);
  helpToc.innerHTML = sections
    .map((s, i) => `<button type="button" data-target="${s.id}"><span>${i + 1}</span>${esc(s.dataset.title)}</button>`)
    .join('');

  helpToc.addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    const el = document.getElementById(btn.dataset.target);
    if (!el) return;
    // 直接定位而非平滑滚动：长距离动画途中目录会依次闪过中间章节
    helpBody.scrollTo({ top: Math.max(0, el.offsetTop - 4) });
    setHelpActive(el.id);
  });

  // 滚动时高亮当前所在章节；滚到底时末节可能不够高，直接高亮最后一节
  helpBody.addEventListener('scroll', debounce(() => {
    let current = sections[0];
    for (const s of sections) {
      if (s.offsetTop - 24 <= helpBody.scrollTop) current = s;
    }
    if (helpBody.scrollTop + helpBody.clientHeight >= helpBody.scrollHeight - 2) current = sections[sections.length - 1];
    setHelpActive(current.id);
  }, 40));
})();

function openHelp(targetId) {
  if (!helpDialog.open) helpDialog.showModal();
  const el = targetId ? document.getElementById(targetId) : helpBody.querySelector('.help-section');
  if (!el) return;
  helpBody.scrollTo({ top: Math.max(0, el.offsetTop - 4) });
  setHelpActive(el.id);
}

['#btnHelp', '#btnHelpAuth', '#btnHelpSettings'].forEach((sel) => {
  $(sel).addEventListener('click', () => openHelp());
});

/** 把当前运行方式（桌面应用 / 后台服务 / 手动启动）同步到手册和设置页。 */
function setRunMode(st) {
  const desktop = !!st.desktop;
  const service = !!st.service;
  state.desktop = desktop;
  state.platform = st.platform || '';

  const kbd = $('.search kbd');
  if (kbd) kbd.textContent = state.platform === 'win32' ? 'Ctrl K' : '⌘K';

  $('#helpMode').textContent = desktop ? '桌面应用' : service ? '后台服务 · 登录后自启' : '手动启动';
  $('#helpMode').classList.toggle('on', desktop || service);
  $('#serviceHint').textContent = desktop
    ? '当前运行方式：桌面应用。数据保存在本机的用户数据目录，只监听 127.0.0.1，不上传、不同步。'
    : service
      ? '当前运行方式：后台服务（已随系统登录自动启动，意外退出会自动拉起）。'
      : '当前运行方式：手动启动（未安装后台服务，关闭启动窗口即停止）。';
  $('#helpServiceStatus').textContent = service
    ? '当前状态：已安装为后台服务，正在以服务模式运行。'
    : '当前状态：未安装后台服务，本次为手动启动。需要开机自启，按下方说明安装即可。';

  // 只显示与当前运行方式相关的说明
  $('#helpServiceDesktop').classList.toggle('hidden', !desktop);
  $('#helpServiceWeb').classList.toggle('hidden', desktop);
  $$('.desktop-only').forEach((el) => el.classList.toggle('hidden', !desktop));
  $$('.web-only').forEach((el) => el.classList.toggle('hidden', desktop));

  if (desktop) {
    // 实际目录要等解锁后才由接口返回；这里先给出该系统的默认位置
    setVaultLocation(
      st.platform === 'win32' ? '%APPDATA%\\Qsecret\\data' : '~/Library/Application Support/Qsecret/data'
    );
  }
}

/* -------------------------------------------------------------- 确认框 */

const confirmDialog = $('#confirmDialog');
let confirmResolve = null;

function askConfirm(title, text, okLabel = '确认') {
  $('#confirmTitle').textContent = title;
  $('#confirmText').textContent = text;
  $('#confirmOk').textContent = okLabel;
  confirmDialog.showModal();
  return new Promise((resolve) => { confirmResolve = resolve; });
}

$('#confirmOk').addEventListener('click', () => {
  confirmDialog.close();
  if (confirmResolve) confirmResolve(true);
  confirmResolve = null;
});
$('#confirmCancel').addEventListener('click', () => {
  confirmDialog.close();
  if (confirmResolve) confirmResolve(false);
  confirmResolve = null;
});
confirmDialog.addEventListener('cancel', () => {
  if (confirmResolve) confirmResolve(false);
  confirmResolve = null;
});

/* -------------------------------------------------------------- 弹窗通用 */

$$('[data-close]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const el = document.getElementById(btn.dataset.close);
    if (el) el.close();
  });
});

$$('dialog').forEach((dlg) => {
  dlg.addEventListener('click', (e) => {
    if (e.target === dlg) dlg.close();
  });
});

/* -------------------------------------------------------------- 眼睛按钮 */

function paintEye(btn, visible) {
  if (!btn) return;
  btn.classList.toggle('off', !!visible);
}

$$('[data-toggle-pw]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.togglePw);
    if (!input) return;
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    paintEye(btn, show);
  });
});

// 详情页的眼睛按钮同样使用图标
const detailObserver = new MutationObserver(() => {
  $$('#detail [data-action="toggle-reveal"]').forEach((btn) => {
    const visible = !!state.revealed.get(state.selectedId);
    paintEye(btn, visible);
  });
});
detailObserver.observe($('#detail'), { childList: true, subtree: true });

/* -------------------------------------------------------------- 空闲计时 */

setInterval(() => {
  const appVisible = !$('#app').classList.contains('hidden');
  if (!appVisible) return;
  const idleMs = state.idleMinutes * 60 * 1000;
  const left = Math.max(0, idleMs - (Date.now() - state.lastActivity));
  const m = Math.floor(left / 60000);
  const s = Math.floor((left % 60000) / 1000);
  $('#idleTimer').textContent = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  if (left <= 0) {
    api('/api/vault/lock', { method: 'POST' }).catch(() => {});
    lockToAuth('空闲超时，已自动锁定');
  }
}, 1000);

['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach((evt) => {
  document.addEventListener(evt, () => { state.lastActivity = Date.now(); }, { passive: true });
});

/* -------------------------------------------------------------- 启动 */

(async function boot() {
  try {
    const res = await fetch('/api/state', { credentials: 'same-origin' });
    const st = await res.json();
    setRunMode(st);
    $('#boot').classList.add('hidden');

    if (!st.hasVault) {
      showAuth('create');
      return;
    }

    if (st.unlocked) {
      // 页面刷新后尝试沿用现有会话
      try {
        const s = await fetch('/api/session', { credentials: 'same-origin' });
        const data = await s.json();
        if (s.ok && data.unlocked) {
          await enterApp(data.csrf, data.idleMinutes, data.dataDir);
          return;
        }
      } catch {
        /* fallthrough */
      }
    }

    const lockMsg = st.lockoutSeconds > 0 ? `尝试次数过多，请等待 ${st.lockoutSeconds} 秒` : '';
    showAuth('unlock', lockMsg);
  } catch (err) {
    $('#boot').classList.add('hidden');
    showAuth('unlock', '无法连接本地服务，请确认 Qsecret 正在运行');
  }
})();