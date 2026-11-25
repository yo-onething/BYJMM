'use strict';
/**
 * startServer() 模块级自检：桌面应用（Electron）就是以库的方式加载 server.js 的。
 * 验证以库加载时不会自动监听、桌面模式接口、自启钩子的校验顺序，以及 close() 可完整关闭。
 * 运行：node test/server.unit.test.js
 */

const assert = require('node:assert');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const { startServer } = require('../server.js');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qsecret-unit-'));
const PW = 'correct horse battery staple 42';

let passed = 0;
let failed = 0;
const queue = [];
const test = (name, fn) => queue.push({ name, fn });

let app = null;
let cookie = '';
let csrf = '';

const hook = { enabled: false, reason: null, calls: [] };
const autostart = {
  get: () => hook.enabled,
  set: (value) => {
    hook.calls.push(value);
    hook.enabled = value;
  },
  unavailableReason: () => hook.reason,
};

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
      { host: '127.0.0.1', port: app.port, path: urlPath, method, headers: h },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          const setCookie = res.headers['set-cookie'];
          if (setCookie && setCookie[0]) cookie = setCookie[0].split(';')[0];
          let json = null;
          if ((res.headers['content-type'] || '').includes('application/json')) {
            try {
              json = JSON.parse(buf.toString('utf8'));
            } catch {
              json = null;
            }
          }
          resolve({ status: res.statusCode, body: buf, json });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

test('以库方式加载后不会自动监听 7878，由调用方决定端口', async () => {
  assert.ok(typeof startServer === 'function');
  app = startServer({
    dataDir: path.join(root, 'data'),
    port: 0,
    desktop: true,
    autostart,
    log: () => {},
    standalone: false,
  });
  await app.ready;
  assert.ok(app.port > 0, '应拿到系统分配的端口');
  assert.notStrictEqual(app.port, 7878);
  assert.ok(app.server.listening);
});

test('随机端口下 Host 校验使用真实端口', async () => {
  const res = await request('GET', '/api/state');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.desktop, true);
  assert.strictEqual(res.json.service, false);
  assert.strictEqual(res.json.autoStart, false);
  assert.strictEqual(res.json.platform, process.platform);
});

test('未解锁时自启接口返回 401', async () => {
  const res = await request('GET', '/api/app/autostart');
  assert.strictEqual(res.status, 401);
});

test('创建保险库并拿到会话', async () => {
  const res = await request('POST', '/api/vault/create', { body: { password: PW, confirm: PW } });
  assert.strictEqual(res.status, 201);
  csrf = res.json.csrf;
  assert.ok(cookie.includes('qsid='));
});

test('会话接口返回真实数据目录（桌面模式）', async () => {
  const res = await request('GET', '/api/session');
  assert.strictEqual(res.json.unlocked, true);
  assert.strictEqual(res.json.dataDir, path.resolve(path.join(root, 'data')));
});

test('改自启必须带 CSRF 令牌', async () => {
  const res = await request('PUT', '/api/app/autostart', { body: { enabled: true } });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.json.error.code, 'VALIDATION');
  assert.deepStrictEqual(hook.calls, []);
});

test('开启自启：钩子被调用一次，读回为 true', async () => {
  const put = await request('PUT', '/api/app/autostart', {
    body: { enabled: true },
    headers: { 'X-CSRF-Token': csrf },
  });
  assert.strictEqual(put.status, 200);
  assert.deepStrictEqual(put.json, { autoStart: true, reason: null });
  const get = await request('GET', '/api/app/autostart');
  assert.strictEqual(get.json.autoStart, true);
  assert.deepStrictEqual(hook.calls, [true]);
});

test('enabled 不是布尔值时拒绝', async () => {
  const res = await request('PUT', '/api/app/autostart', {
    body: { enabled: 'yes' },
    headers: { 'X-CSRF-Token': csrf },
  });
  assert.strictEqual(res.status, 400);
  assert.deepStrictEqual(hook.calls, [true]);
});

test('应用位置不满足条件时返回 409，且不调用钩子', async () => {
  hook.reason = '请先把 Qsecret 拖进「应用程序」文件夹';
  const res = await request('PUT', '/api/app/autostart', {
    body: { enabled: false },
    headers: { 'X-CSRF-Token': csrf },
  });
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.error.code, 'AUTOSTART_UNAVAILABLE');
  assert.ok(res.json.error.message.includes('应用程序'));
  assert.deepStrictEqual(hook.calls, [true]);
  hook.reason = null;
});

test('关闭自启', async () => {
  const res = await request('PUT', '/api/app/autostart', {
    body: { enabled: false },
    headers: { 'X-CSRF-Token': csrf },
  });
  assert.strictEqual(res.json.autoStart, false);
  assert.deepStrictEqual(hook.calls, [true, false]);
});

test('lock() 让会话立即失效', async () => {
  app.lock();
  const res = await request('GET', '/api/session');
  assert.strictEqual(res.json.unlocked, false);
});

test('同一进程不能重复启动', () => {
  assert.throws(() => startServer({ dataDir: root, port: 0 }), /已经启动/);
});

test('close() 完整关闭监听', async () => {
  await app.close();
  assert.strictEqual(app.server.listening, false);
});

test('非桌面模式：没有自启接口，状态里不带桌面字段', async () => {
  app = startServer({ dataDir: path.join(root, 'data'), port: 0, log: () => {}, standalone: false });
  await app.ready;
  const state = await request('GET', '/api/state');
  assert.strictEqual(state.json.desktop, false);
  assert.strictEqual(state.json.autoStart, null);
  assert.strictEqual(state.json.platform, undefined);
  // 未解锁时一律 401，不泄露接口是否存在；解锁后才能确认该接口不存在
  const locked = await request('GET', '/api/app/autostart');
  assert.strictEqual(locked.status, 401);
  const unlock = await request('POST', '/api/vault/unlock', { body: { password: PW } });
  assert.strictEqual(unlock.status, 200);
  const autostartRoute = await request('GET', '/api/app/autostart');
  assert.strictEqual(autostartRoute.status, 404);
  const session = await request('GET', '/api/session');
  assert.strictEqual(session.json.dataDir, undefined);
  await app.close();
});

(async () => {
  for (const { name, fn } of queue) {
    try {
      await fn();
      passed += 1;
      console.log(`  ✓ ${name}`);
    } catch (err) {
      failed += 1;
      console.log(`  ✗ ${name}`);
      console.log(`      ${err && err.message ? err.message.split('\n').join('\n      ') : err}`);
    }
  }
  if (app && app.server.listening) await app.close().catch(() => {});
  console.log(`\n结果：${passed} 通过 / ${failed} 失败\n`);
  process.exit(failed ? 1 : 0);
})();
