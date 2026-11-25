'use strict';
/**
 * 接口与安全边界自检：会真实启动一个临时服务（独立数据目录、随机端口），
 * 验证鉴权、CSRF、跨站拦截、限速与静态资源策略。
 * 运行：node test/api.test.js
 */

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const { spawn } = require('node:child_process');

const PW = 'correct horse battery staple 42';
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qsecret-api-'));
const dataDir = path.join(root, 'data');

let passed = 0;
let failed = 0;
const queue = [];

function test(name, fn) {
  queue.push({ name, fn });
}

let child;
let port;
let cookie = '';
let csrf = '';

function request(method, urlPath, { body, headers = {}, useCookie = true } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body), 'utf8');
    const h = { ...headers };
    if (payload) {
      h['Content-Type'] = 'application/json';
      h['Content-Length'] = payload.length;
    }
    if (useCookie && cookie) h.Cookie = cookie;

    const req = http.request(
      { host: '127.0.0.1', port, path: urlPath, method, headers: h },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          const setCookie = res.headers['set-cookie'];
          if (setCookie && setCookie[0]) cookie = setCookie[0].split(';')[0];
          let json = null;
          const type = res.headers['content-type'] || '';
          if (type.includes('application/json')) {
            try {
              json = JSON.parse(buf.toString('utf8'));
            } catch {
              json = null;
            }
          }
          resolve({ status: res.statusCode, headers: res.headers, body: buf, json });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
}

async function waitReady() {
  for (let i = 0; i < 120; i++) {
    try {
      const res = await request('GET', '/api/state', { useCookie: false });
      if (res.status === 200) return;
    } catch {
      /* not yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('服务未能在预期时间内启动');
}

/* ------------------------------------------------------------------ 用例 */

test('未创建保险库时 /api/state 返回 hasVault=false', async () => {
  const res = await request('GET', '/api/state', { useCookie: false });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.hasVault, false);
  assert.strictEqual(res.json.unlocked, false);
});

test('手动启动时 /api/state 标明非服务模式', async () => {
  const res = await request('GET', '/api/state', { useCookie: false });
  assert.strictEqual(res.json.service, false);
});

test('首页返回严格 CSP 与安全响应头', async () => {
  const res = await request('GET', '/', { useCookie: false });
  assert.strictEqual(res.status, 200);
  const csp = res.headers['content-security-policy'] || '';
  assert.ok(csp.includes("default-src 'none'"), 'CSP 应默认拒绝');
  assert.ok(csp.includes("script-src 'self'"), '脚本仅允许同源');
  assert.ok(!csp.includes('unsafe-inline'), 'CSP 不应允许内联');
  assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
  assert.strictEqual(res.headers['x-frame-options'], 'DENY');
});

test('目录穿越访问源文件被拒绝', async () => {
  const res = await request('GET', '/../server.js', { useCookie: false });
  assert.strictEqual(res.status, 404);
  const res2 = await request('GET', '/data/vault.qvault', { useCookie: false });
  assert.strictEqual(res2.status, 404);
});

test('伪造 Host 头被拒绝（防 DNS rebinding）', async () => {
  const res = await request('GET', '/api/state', {
    useCookie: false,
    headers: { Host: 'evil.example.com' },
  });
  assert.strictEqual(res.status, 400);
});

test('跨站 Origin 被拒绝', async () => {
  const res = await request('GET', '/api/state', {
    useCookie: false,
    headers: { Origin: 'https://evil.example.com' },
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.json.error.code, 'VALIDATION');
});

test('未解锁时读取条目返回 401', async () => {
  const res = await request('GET', '/api/entries');
  assert.strictEqual(res.status, 401);
  assert.strictEqual(res.json.error.code, 'LOCKED');
});

test('弱主密码无法创建保险库', async () => {
  const res = await request('POST', '/api/vault/create', {
    body: { password: 'short', confirm: 'short' },
    useCookie: false,
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.json.error.code, 'WEAK_MASTER');
});

test('创建保险库并下发 HttpOnly + SameSite 会话 Cookie', async () => {
  const res = await request('POST', '/api/vault/create', {
    body: { password: PW, confirm: PW },
    useCookie: false,
  });
  assert.strictEqual(res.status, 201);
  assert.ok(res.json.csrf && res.json.csrf.length > 30, '应返回 CSRF 令牌');
  const setCookie = (res.headers['set-cookie'] || []).join(';');
  assert.ok(setCookie.includes('HttpOnly'), 'Cookie 必须 HttpOnly');
  assert.ok(setCookie.includes('SameSite=Strict'), 'Cookie 必须 SameSite=Strict');
  assert.ok(cookie.startsWith('qsid='), '应记录会话 Cookie');
  csrf = res.json.csrf;
});

test('重复创建保险库返回 409', async () => {
  const res = await request('POST', '/api/vault/create', { body: { password: PW, confirm: PW } });
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.error.code, 'ALREADY_EXISTS');
});

test('不带 CSRF 令牌的写操作被拒绝', async () => {
  const res = await request('POST', '/api/entries', {
    body: { title: 'no-csrf', password: 'p' },
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.json.error.code, 'VALIDATION');
});

test('创建条目并在列表接口隐藏密码明文', async () => {
  const res = await request('POST', '/api/entries', {
    headers: { 'X-CSRF-Token': csrf },
    body: {
      title: 'GitHub',
      username: 'alice@example.com',
      password: 'S3cret-Value-For-Test!',
      url: 'https://github.com',
      category: 'login',
      tags: ['工作'],
      notes: '备注内容',
    },
  });
  assert.strictEqual(res.status, 201);

  const list = await request('GET', '/api/entries');
  assert.strictEqual(list.status, 200);
  assert.strictEqual(list.json.entries.length, 1);
  const entry = list.json.entries[0];
  assert.strictEqual(entry.title, 'GitHub');
  assert.strictEqual(entry.password, undefined, '列表不得返回密码');
  assert.strictEqual(list.json.stats.total, 1);
});

test('落盘文件不含明文（接口层复验）', async () => {
  const raw = fs.readFileSync(path.join(dataDir, 'vault.qvault'), 'utf8');
  for (const needle of ['GitHub', 'alice@example.com', 'S3cret-Value-For-Test', '备注内容']) {
    assert.ok(!raw.includes(needle), `文件中出现明文：${needle}`);
  }
  assert.strictEqual(fs.statSync(path.join(dataDir, 'vault.qvault')).mode & 0o777, 0o600);
});

test('按需读取密码需要 CSRF 且返回正确明文', async () => {
  const list = await request('GET', '/api/entries');
  const id = list.json.entries[0].id;

  const denied = await request('POST', `/api/entries/${id}/reveal`);
  assert.strictEqual(denied.status, 400);

  const ok = await request('POST', `/api/entries/${id}/reveal`, {
    headers: { 'X-CSRF-Token': csrf },
  });
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(ok.json.password, 'S3cret-Value-For-Test!');
});

test('编辑与删除条目', async () => {
  const list = await request('GET', '/api/entries');
  const id = list.json.entries[0].id;

  const upd = await request('PUT', `/api/entries/${id}`, {
    headers: { 'X-CSRF-Token': csrf },
    body: { title: 'GitHub 工作号', category: 'login' },
  });
  assert.strictEqual(upd.status, 200);
  assert.strictEqual(upd.json.entry.title, 'GitHub 工作号');

  const del = await request('DELETE', `/api/entries/${id}`, {
    headers: { 'X-CSRF-Token': csrf },
  });
  assert.strictEqual(del.status, 200);

  const after = await request('GET', '/api/entries');
  assert.strictEqual(after.json.entries.length, 0);
});

test('生成器返回指定长度且字符集符合选择', async () => {
  const res = await request('POST', '/api/generate', {
    headers: { 'X-CSRF-Token': csrf },
    body: { length: 24, upper: true, lower: true, digits: true, symbols: false, avoidAmbiguous: true },
  });
  assert.strictEqual(res.status, 200);
  const pw = res.json.password;
  assert.strictEqual(pw.length, 24);
  assert.ok(/^[A-Za-z0-9]+$/.test(pw), '关闭符号后不应出现符号');
  assert.ok(/[A-Z]/.test(pw) && /[a-z]/.test(pw) && /[0-9]/.test(pw), '每类至少一个');
  assert.ok(!/[0O1lI]/.test(pw), '排除易混淆字符');
});

test('设置自动锁定时间', async () => {
  const put = await request('PUT', '/api/settings', {
    headers: { 'X-CSRF-Token': csrf },
    body: { idleMinutes: 15 },
  });
  assert.strictEqual(put.status, 200);
  assert.strictEqual(put.json.settings.idleMinutes, 15);

  const get = await request('GET', '/api/settings');
  assert.strictEqual(get.json.settings.idleMinutes, 15);
});

test('备份下载为加密文件', async () => {
  const res = await request('GET', '/api/backup');
  assert.strictEqual(res.status, 200);
  assert.ok(String(res.headers['content-type']).includes('application/octet-stream'));
  const parsed = JSON.parse(res.body.toString('utf8'));
  assert.strictEqual(parsed.format, 'qsecret-vault');
  assert.ok(!res.body.toString('utf8').includes('S3cret'), '备份中不应有明文');
});

test('从备份恢复成功并刷新会话', async () => {
  const backup = await request('GET', '/api/backup');
  const b64 = backup.body.toString('base64');

  const wrong = await request('POST', '/api/backup/restore', {
    headers: { 'X-CSRF-Token': csrf },
    body: { data: b64, password: 'not-the-password' },
  });
  assert.strictEqual(wrong.status, 401);

  const ok = await request('POST', '/api/backup/restore', {
    headers: { 'X-CSRF-Token': csrf },
    body: { data: b64, password: PW },
  });
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(ok.json.restored, true);
  csrf = ok.json.csrf;

  const list = await request('GET', '/api/entries');
  assert.strictEqual(list.status, 200, '恢复后会话应立即可用');
});

test('修改主密码：旧密码校验、换钥后会话仍可用', async () => {
  const tmpPw = 'temporary master password 77';

  const wrong = await request('POST', '/api/master/change', {
    headers: { 'X-CSRF-Token': csrf },
    body: { currentPassword: 'wrong-old-password', newPassword: tmpPw },
  });
  assert.strictEqual(wrong.status, 401);

  const first = await request('POST', '/api/master/change', {
    headers: { 'X-CSRF-Token': csrf },
    body: { currentPassword: PW, newPassword: tmpPw },
  });
  assert.strictEqual(first.status, 200);
  csrf = first.json.csrf;

  const afterFirst = await request('GET', '/api/entries');
  assert.strictEqual(afterFirst.status, 200, '换钥后会话应仍然可用');

  const second = await request('POST', '/api/master/change', {
    headers: { 'X-CSRF-Token': csrf },
    body: { currentPassword: tmpPw, newPassword: PW },
  });
  assert.strictEqual(second.status, 200);
  csrf = second.json.csrf;
});

test('锁定后会话立即失效', async () => {
  const lock = await request('POST', '/api/vault/lock', { headers: { 'X-CSRF-Token': csrf } });
  assert.strictEqual(lock.status, 200);
  const res = await request('GET', '/api/entries');
  assert.strictEqual(res.status, 401);
});

test('重新解锁需要正确主密码', async () => {
  const wrong = await request('POST', '/api/vault/unlock', { body: { password: 'wrong-password-xxxx' } });
  assert.strictEqual(wrong.status, 401);
  assert.strictEqual(wrong.json.error.code, 'BAD_PASSWORD');

  const ok = await request('POST', '/api/vault/unlock', { body: { password: PW } });
  assert.strictEqual(ok.status, 200);
  assert.ok(ok.json.csrf);
  csrf = ok.json.csrf;
});

test('连续失败触发指数退避（429 + Retry-After）', async () => {
  await request('POST', '/api/vault/lock', { headers: { 'X-CSRF-Token': csrf } });
  // 成功解锁会清零计数，因此这里需要连续失败 5 次才进入锁定
  for (let i = 0; i < 5; i++) {
    const res = await request('POST', '/api/vault/unlock', {
      body: { password: `wrong-${i}-xxxxxxxx` },
    });
    assert.strictEqual(res.status, 401, `第 ${i + 1} 次失败应为 401`);
  }
  const limited = await request('POST', '/api/vault/unlock', { body: { password: PW } });
  assert.strictEqual(limited.status, 429, '锁定期间即使密码正确也应拒绝');
  assert.ok(Number(limited.headers['retry-after']) > 0);
});

test('限速状态落盘，重启也无法绕过', async () => {
  const stateFile = path.join(dataDir, 'auth-state.json');
  assert.ok(fs.existsSync(stateFile), '应存在 auth-state.json');
  const st = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  assert.ok(st.fails >= 5);
  assert.ok(st.lockUntil > Date.now());
});

test('服务模式：端口被占不退出，原实例退出后自动接管', async () => {
  const svcPort = await freePort();
  const svcData = path.join(root, 'svc-data');

  // 先用一个占位服务占住端口，模拟"手动启动的实例还在运行"
  const blocker = net.createServer();
  await new Promise((r) => blocker.listen(svcPort, '127.0.0.1', r));

  const svc = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, QSECRET_DATA: svcData, QSECRET_PORT: String(svcPort), QSECRET_SERVICE: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let exited = false;
  svc.on('exit', () => { exited = true; });
  svc.stdout.on('data', () => {});
  svc.stderr.on('data', (d) => process.stderr.write(`[service] ${d}`));

  try {
    await new Promise((r) => setTimeout(r, 1500));
    assert.strictEqual(exited, false, '端口被占时服务模式不应退出');
    assert.strictEqual(fs.existsSync(svcData), false, '尚未监听成功不应创建数据目录');

    blocker.close();
    let state = null;
    for (let i = 0; i < 100; i++) {
      state = await new Promise((resolve) => {
        const req = http.get({ host: '127.0.0.1', port: svcPort, path: '/api/state' }, (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
        });
        req.on('error', () => resolve(null));
      });
      if (state) break;
      await new Promise((r) => setTimeout(r, 200));
    }
    assert.ok(state, '原实例退出后服务应自动接管端口');
    assert.strictEqual(state.service, true);
    assert.strictEqual(exited, false);
  } finally {
    svc.kill('SIGTERM');
  }
});

/* ------------------------------------------------------------------ 执行 */

(async () => {
  port = await freePort();
  child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, QSECRET_DATA: dataDir, QSECRET_PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', () => {});
  child.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));

  try {
    await waitReady();
    for (const item of queue) {
      try {
        await item.fn();
        console.log(`  \u2713 ${item.name}`);
        passed++;
      } catch (err) {
        console.error(`  \u2717 ${item.name}\n      ${err && err.message}`);
        failed++;
      }
    }
  } catch (err) {
    console.error('启动失败：', err.message);
    failed++;
  } finally {
    if (child) child.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 300));
    if (root.startsWith(os.tmpdir()) && path.basename(root).startsWith('qsecret-api-')) {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }

  console.log(`\n结果：${passed} 通过 / ${failed} 失败\n`);
  process.exit(failed === 0 ? 0 : 1);
})();